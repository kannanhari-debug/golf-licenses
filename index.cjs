// =====================================
// FINAL License + Tracking Server (CJS)
// =====================================

const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const crypto = require("crypto");

// ---------- ENV ----------
const PORT = process.env.PORT || 8080;
const DATABASE_URL = process.env.DATABASE_URL;
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || ""; // set this in Railway Variables

if (!DATABASE_URL) {
  console.error("❌ DATABASE_URL missing");
  process.exit(1);
}

// ---------- DB ----------
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

// ---------- APP ----------
const app = express();
app.use(cors());
app.use(express.json({ limit: "256kb" }));

// ---------- UTIL ----------
function nowIso() {
  return new Date().toISOString();
}

function getMeta(req) {
  const ip =
    (req.headers["x-forwarded-for"] || "")
      .toString()
      .split(",")[0]
      .trim() ||
    req.socket?.remoteAddress ||
    null;

  const user_agent = (req.headers["user-agent"] || "").toString() || null;
  return { ip, user_agent };
}

function cleanText(v, max = 200) {
  if (v === undefined || v === null) return "";
  const s = String(v).trim();
  return s.length > max ? s.slice(0, max) : s;
}

function toInt(v) {
  const n = Number(v);
  if (!Number.isFinite(n)) return null;
  const i = Math.floor(n);
  return i < 0 ? 0 : i;
}

function randomId() {
  return crypto.randomBytes(10).toString("hex"); // 20 chars
}

// ---------- RATE LIMIT (simple, in-memory) ----------
const RL_WINDOW_MS = 60_000;
const RL_MAX_REQ = 120; // per IP per minute
const rateMap = new Map();

function rateLimit(req, res, next) {
  const ip =
    (req.headers["x-forwarded-for"] || "")
      .toString()
      .split(",")[0]
      .trim() ||
    req.socket?.remoteAddress ||
    "unknown";

  const now = Date.now();
  const entry = rateMap.get(ip) || { n: 0, t: now };

  if (now - entry.t > RL_WINDOW_MS) {
    entry.n = 0;
    entry.t = now;
  }

  entry.n += 1;
  rateMap.set(ip, entry);

  if (entry.n > RL_MAX_REQ) {
    return res.status(429).json({ error: "rate_limited" });
  }
  return next();
}

app.use(rateLimit);

// ---------- DB HELPERS ----------
async function logEvent(device_id, event, result, req, data = null) {
  const meta = getMeta(req);
  await pool.query(
    `INSERT INTO public.events (device_id, event, result, ip, user_agent, data)
     VALUES ($1,$2,$3,$4,$5,$6::jsonb)`,
    [
      cleanText(device_id, 200) || "unknown",
      cleanText(event, 50) || "event",
      cleanText(result, 50) || "ok",
      cleanText(meta.ip, 64),
      cleanText(meta.user_agent, 300),
      data ? JSON.stringify(data) : null,
    ]
  );
}

// Treat DATE expiry as valid until end-of-day UTC
function isExpired(expiryDateStr /* YYYY-MM-DD */) {
  if (!expiryDateStr) return true;
  const end = new Date(String(expiryDateStr) + "T23:59:59.999Z");
  return end.getTime() < Date.now();
}

async function getLicense(device_id) {
  const r = await pool.query(
    `SELECT device_id, username, level, expiry, status
     FROM public.licenses
     WHERE device_id = $1
     LIMIT 1`,
    [device_id]
  );
  return r.rows[0] || null;
}

async function validate(device_id) {
  const lic = await getLicense(device_id);

  if (!lic) return { status: "unauthorised" };

  const st = (lic.status || "").toString().toLowerCase();
  if (st !== "active") {
    return { status: "inactive", username: lic.username, level: lic.level, expiry: lic.expiry };
  }

  if (isExpired(lic.expiry)) {
    return { status: "expired", username: lic.username, level: lic.level, expiry: lic.expiry };
  }

  return { status: "valid", username: lic.username, level: lic.level, expiry: lic.expiry };
}

async function abortRunningSession(device_id) {
  // mark latest running session aborted (crash/unknown)
  await pool.query(
    `UPDATE public.sessions
       SET end_time = now(),
           status = 'aborted',
           duration_sec = GREATEST(EXTRACT(EPOCH FROM (now() - start_time))::int, 0)
     WHERE id = (
       SELECT id FROM public.sessions
        WHERE device_id = $1 AND status = 'running' AND end_time IS NULL
        ORDER BY start_time DESC
        LIMIT 1
     )`,
    [device_id]
  );
}

async function startSession(device_id, level, req, session_id_from_client = null) {
  // abort any previous running session for this device
  await abortRunningSession(device_id);

  const meta = getMeta(req);
  const sid = session_id_from_client || randomId();

  await pool.query(
    `INSERT INTO public.sessions (session_id, device_id, level, start_time, status, ip, user_agent)
     VALUES ($1,$2,$3,now(),'running',$4,$5)
     ON CONFLICT (session_id) DO NOTHING`,
    [
      sid,
      device_id,
      cleanText(level, 20) || "unknown",
      cleanText(meta.ip, 64),
      cleanText(meta.user_agent, 300),
    ]
  );

  return sid;
}

async function endSession(device_id, durationSec, session_id_from_client = null) {
  const dur = durationSec == null ? null : Math.max(0, durationSec);

  if (session_id_from_client) {
    await pool.query(
      `UPDATE public.sessions
          SET end_time = now(),
              status = 'ended',
              duration_sec = COALESCE($3, GREATEST(EXTRACT(EPOCH FROM (now() - start_time))::int, 0))
        WHERE device_id = $1
          AND session_id = $2`,
      [device_id, session_id_from_client, dur]
    );
    return { ended: true, session_id: session_id_from_client };
  }

  // best-effort: close the latest running session
  const r = await pool.query(
    `SELECT session_id FROM public.sessions
      WHERE device_id = $1 AND status = 'running' AND end_time IS NULL
      ORDER BY start_time DESC
      LIMIT 1`,
    [device_id]
  );

  if (r.rows.length === 0) return { ended: false };

  const sid = r.rows[0].session_id;

  await pool.query(
    `UPDATE public.sessions
        SET end_time = now(),
            status = 'ended',
            duration_sec = COALESCE($2, GREATEST(EXTRACT(EPOCH FROM (now() - start_time))::int, 0))
      WHERE device_id = $1
        AND session_id = $3`,
    [device_id, dur, sid]
  );

  return { ended: true, session_id: sid };
}

// ---------- ROUTES ----------
app.get("/", (req, res) => {
  res.json({ status: "ok", service: "license-server", time: nowIso() });
});

// GET /check?device_id=...
app.get("/check", async (req, res) => {
  try {
    const device_id = cleanText(req.query.device_id, 200);
    if (!device_id) return res.status(400).json({ error: "device_id required" });

    const v = await validate(device_id);
    await logEvent(device_id, "check", v.status, req);

    return res.json(v);
  } catch (err) {
    console.error("❌ /check error:", err);
    return res.status(500).json({ error: "server_error" });
  }
});

// GET /event?device_id=...&event=start|end|ping|...&script=...&duration=...&session_id=...
app.get("/event", async (req, res) => {
  try {
    const device_id = cleanText(req.query.device_id, 200);
    const event = cleanText(req.query.event, 50).toLowerCase() || "event";
    const script = cleanText(req.query.script, 20).toLowerCase() || null;
    const duration = req.query.duration !== undefined ? toInt(req.query.duration) : null;
    const session_id = cleanText(req.query.session_id, 60) || null;

    if (!device_id) return res.status(400).json({ error: "device_id required" });

    // Always log event (audit trail)
    await logEvent(device_id, event, "ok", req, { script, duration, session_id });

    // Only VALID licenses can create/update sessions (prevents FK crash + keeps clean data)
    const v = await validate(device_id);

    if (event === "start") {
      if (v.status === "valid") {
        const sid = await startSession(device_id, script || v.level || "unknown", req, session_id);
        return res.json({ status: "ok", session: "started", session_id: sid });
      }
      return res.json({ status: "ok", session: "not_started", reason: v.status });
    }

    if (event === "end") {
      if (v.status === "valid") {
        const out = await endSession(device_id, duration, session_id);
        return res.json({ status: "ok", session: out.ended ? "ended" : "not_found", session_id: out.session_id || null });
      }
      return res.json({ status: "ok", session: "not_ended", reason: v.status });
    }

    return res.json({ status: "ok" });
  } catch (err) {
    console.error("❌ /event error:", err);
    return res.status(500).json({ error: "server_error" });
  }
});

// ---------- ADMIN VIEWS (browser) ----------
// /admin/licenses (GET list/filter, POST add, PUT update, DELETE remove) [requires ADMIN_TOKEN]
app.get("/admin/licenses", async (req, res) => {
  try {
    const token = cleanText(req.query.token, 500);
    if (!ADMIN_TOKEN || token !== ADMIN_TOKEN) return res.status(401).json({ error: "unauthorised" });

    const device_id = cleanText(req.query.device_id, 200);
    const limit = device_id ? 1 : Math.min(Math.max(toInt(req.query.limit) || 1000, 1), 1000);

    const r = device_id
      ? await pool.query(
          `SELECT device_id, username, level, expiry, status
             FROM public.licenses
            WHERE device_id = $1
            LIMIT $2`,
          [device_id, limit]
        )
      : await pool.query(
          `SELECT device_id, username, level, expiry, status
             FROM public.licenses
            ORDER BY username ASC
            LIMIT $1`,
          [limit]
        );
    res.json(r.rows);
  } catch (err) {
    console.error("❌ /admin/licenses GET error:", err);
    res.status(500).json({ error: "server_error" });
  }
});

app.post("/admin/licenses", async (req, res) => {
  try {
    const token = cleanText(req.query.token, 500);
    if (!ADMIN_TOKEN || token !== ADMIN_TOKEN) return res.status(401).json({ error: "unauthorised" });

    const device_id = cleanText(req.body.device_id, 200);
    const username = cleanText(req.body.username, 200);
    const level = cleanText(req.body.level, 20);
    const expiry = cleanText(req.body.expiry, 100);
    const status = cleanText(req.body.status, 10);

    if (!device_id) return res.status(400).json({ error: "device_id required" });
    if (!username) return res.status(400).json({ error: "username required" });
    if (!level) return res.status(400).json({ error: "level required" });
    if (!expiry) return res.status(400).json({ error: "expiry required" });
    if (!status) return res.status(400).json({ error: "status required" });

    const levelLower = level.toLowerCase();
    if (levelLower !== "lite" && levelLower !== "premium") {
      return res.status(400).json({ error: "level invalid" });
    }
    const statusLower = status.toLowerCase();
    if (statusLower !== "active" && statusLower !== "inactive") {
      return res.status(400).json({ error: "status invalid" });
    }
    const datePattern = /^\d{4}-\d{2}-\d{2}$/;
    if (!datePattern.test(expiry)) {
      return res.status(400).json({ error: "expiry invalid" });
    }
    const d = new Date(expiry + "T00:00:00Z");
    if (isNaN(d.getTime()) || d.toISOString().slice(0, 10) !== expiry) {
      return res.status(400).json({ error: "expiry invalid" });
    }

    const r = await pool.query(
      `INSERT INTO public.licenses (device_id, username, level, expiry, status)
       VALUES ($1,$2,$3,$4,$5)
       RETURNING device_id, username, level, expiry, status`,
      [device_id, username, levelLower, expiry, statusLower]
    );
    res.json(r.rows[0]);
  } catch (err) {
    console.error("❌ /admin/licenses POST error:", err);
    if (err.code === "23505") {
      return res.status(400).json({ error: "device_id exists" });
    }
    res.status(500).json({ error: "server_error" });
  }
});

app.put("/admin/licenses", async (req, res) => {
  try {
    const token = cleanText(req.query.token, 500);
    if (!ADMIN_TOKEN || token !== ADMIN_TOKEN) return res.status(401).json({ error: "unauthorised" });

    const device_id = cleanText(req.query.device_id || req.body.device_id, 200);
    if (!device_id) return res.status(400).json({ error: "device_id required" });

    const updates = [];
    const values = [];
    let idx = 1;
    if (req.body.username !== undefined) {
      const username = cleanText(req.body.username, 200);
      if (!username) return res.status(400).json({ error: "username required" });
      updates.push(`username = $${idx++}`);
      values.push(username);
    }
    if (req.body.level !== undefined) {
      const level = cleanText(req.body.level, 20);
      if (!level) return res.status(400).json({ error: "level required" });
      const levelLower = level.toLowerCase();
      if (levelLower !== "lite" && levelLower !== "premium") {
        return res.status(400).json({ error: "level invalid" });
      }
      updates.push(`level = $${idx++}`);
      values.push(levelLower);
    }
    if (req.body.expiry !== undefined) {
      const expiry = cleanText(req.body.expiry, 100);
      if (!expiry) return res.status(400).json({ error: "expiry required" });
      const datePattern = /^\d{4}-\d{2}-\d{2}$/;
      if (!datePattern.test(expiry)) {
        return res.status(400).json({ error: "expiry invalid" });
      }
      const d = new Date(expiry + "T00:00:00Z");
      if (isNaN(d.getTime()) || d.toISOString().slice(0, 10) !== expiry) {
        return res.status(400).json({ error: "expiry invalid" });
      }
      updates.push("expiry = $" + idx++);
      values.push(expiry);
    }
    if (req.body.status !== undefined) {
      const status = cleanText(req.body.status, 10);
      if (!status) return res.status(400).json({ error: "status required" });
      const statusLower = status.toLowerCase();
      if (statusLower !== "active" && statusLower !== "inactive") {
        return res.status(400).json({ error: "status invalid" });
      }
      updates.push("status = $" + idx++);
      values.push(statusLower);
    }
    if (updates.length === 0) {
      return res.status(400).json({ error: "no_fields_to_update" });
    }
    values.push(device_id);
    const query = `UPDATE public.licenses SET ${updates.join(", ")} WHERE device_id = $${idx} RETURNING device_id, username, level, expiry, status`;
    const r = await pool.query(query, values);
    if (r.rows.length === 0) {
      return res.status(404).json({ error: "not_found" });
    }
    res.json(r.rows[0]);
  } catch (err) {
    console.error("❌ /admin/licenses PUT error:", err);
    res.status(500).json({ error: "server_error" });
  }
});

app.delete("/admin/licenses", async (req, res) => {
  try {
    const token = cleanText(req.query.token, 500);
    if (!ADMIN_TOKEN || token !== ADMIN_TOKEN) return res.status(401).json({ error: "unauthorised" });

    const device_id = cleanText(req.query.device_id || req.body.device_id, 200);
    if (!device_id) return res.status(400).json({ error: "device_id required" });

    const r = await pool.query(
      `DELETE FROM public.licenses
       WHERE device_id = $1`,
      [device_id]
    );
    if (r.rowCount === 0) {
      return res.status(404).json({ error: "not_found" });
    }
    res.json({ device_id: device_id, deleted: true });
  } catch (err) {
    console.error("❌ /admin/licenses DELETE error:", err);
    if (err.code === "23503") {
      return res.status(400).json({ error: "license_delete_failed" });
    }
    res.status(500).json({ error: "server_error" });
  }
});

// /admin/events?token=...&device_id=...&date=YYYY-MM-DD&limit=200
app.get("/admin/events", async (req, res) => {
  try {
    const token = cleanText(req.query.token, 500);
    if (!ADMIN_TOKEN || token !== ADMIN_TOKEN) return res.status(401).json({ error: "unauthorised" });

    const device_id = cleanText(req.query.device_id, 200);
    const dateStr = cleanText(req.query.date, 20);
    if (dateStr) {
      const datePattern = /^\d{4}-\d{2}-\d{2}$/;
      if (!datePattern.test(dateStr)) {
        return res.status(400).json({ error: "date invalid" });
      }
      const d = new Date(dateStr + "T00:00:00Z");
      if (isNaN(d.getTime()) || d.toISOString().slice(0, 10) !== dateStr) {
        return res.status(400).json({ error: "date invalid" });
      }
    }

    const limit = Math.min(Math.max(toInt(req.query.limit) || 200, 1), 1000);
    let r;
    if (device_id && dateStr) {
      r = await pool.query(
        `SELECT id, device_id, event, result, created_at
           FROM public.events
          WHERE device_id = $1
            AND created_at::date = $2
          ORDER BY created_at DESC
          LIMIT $3`,
        [device_id, dateStr, limit]
      );
    } else if (device_id) {
      r = await pool.query(
        `SELECT id, device_id, event, result, created_at
           FROM public.events
          WHERE device_id = $1
          ORDER BY created_at DESC
          LIMIT $2`,
        [device_id, limit]
      );
    } else if (dateStr) {
      r = await pool.query(
        `SELECT id, device_id, event, result, created_at
           FROM public.events
          WHERE created_at::date = $1
          ORDER BY created_at DESC
          LIMIT $2`,
        [dateStr, limit]
      );
    } else {
      r = await pool.query(
        `SELECT id, device_id, event, result, created_at
           FROM public.events
          ORDER BY created_at DESC
          LIMIT $1`,
        [limit]
      );
    }

    res.json(r.rows);
  } catch (err) {
    console.error("❌ /admin/events error:", err);
    res.status(500).json({ error: "server_error" });
  }
});

// /admin/sessions?token=...&device_id=...&limit=200
app.get("/admin/sessions", async (req, res) => {
  try {
    const token = cleanText(req.query.token, 500);
    if (!ADMIN_TOKEN || token !== ADMIN_TOKEN) return res.status(401).json({ error: "unauthorised" });

    const device_id = cleanText(req.query.device_id, 200);
    const limit = Math.min(Math.max(toInt(req.query.limit) || 200, 1), 1000);

    const r = device_id
      ? await pool.query(
          `SELECT session_id, device_id, level, start_time, end_time, status, duration_sec
             FROM public.sessions
            WHERE device_id = $1
            ORDER BY start_time DESC
            LIMIT $2`,
          [device_id, limit]
        )
      : await pool.query(
          `SELECT session_id, device_id, level, start_time, end_time, status, duration_sec
             FROM public.sessions
            ORDER BY start_time DESC
            LIMIT $1`,
          [limit]
        );

    res.json(r.rows);
  } catch (err) {
    console.error("❌ /admin/sessions error:", err);
    res.status(500).json({ error: "server_error" });
  }
});

// /admin/stats?token=...
app.get("/admin/stats", async (req, res) => {
  try {
    const token = cleanText(req.query.token, 500);
    if (!ADMIN_TOKEN || token !== ADMIN_TOKEN) return res.status(401).json({ error: "unauthorised" });

    const r = await pool.query(
      `SELECT
         COUNT(*)::text AS total,
         COUNT(*) FILTER (WHERE status = 'active' AND expiry >= CURRENT_DATE)::text AS active,
         COUNT(*) FILTER (WHERE status = 'active' AND expiry < CURRENT_DATE)::text AS expired,
         COUNT(*) FILTER (WHERE LOWER(level) = 'lite')::text AS lite,
         COUNT(*) FILTER (WHERE LOWER(level) = 'premium')::text AS premium
       FROM public.licenses`
    );
    const row = r.rows[0];
    const stats = {
      total: parseInt(row.total, 10) || 0,
      active: parseInt(row.active, 10) || 0,
      expired: parseInt(row.expired, 10) || 0,
      lite: parseInt(row.lite, 10) || 0,
      premium: parseInt(row.premium, 10) || 0
    };
    res.json(stats);
  } catch (err) {
    console.error("❌ /admin/stats error:", err);
    res.status(500).json({ error: "server_error" });
  }
});

// /admin/unauthorised?token=...&limit=200
app.get("/admin/unauthorised", async (req, res) => {
  try {
    const token = cleanText(req.query.token, 500);
    if (!ADMIN_TOKEN || token !== ADMIN_TOKEN) return res.status(401).json({ error: "unauthorised" });

    const limit = Math.min(Math.max(toInt(req.query.limit) || 200, 1), 1000);
    const r = await pool.query(
      `SELECT device_id, event, result, created_at
         FROM public.events
        WHERE event = 'check' AND result IN ('unauthorised','expired')
        ORDER BY created_at DESC
        LIMIT $1`,
      [limit]
    );
    res.json(r.rows);
  } catch (err) {
    console.error("❌ /admin/unauthorised error:", err);
    res.status(500).json({ error: "server_error" });
  }
});

// ---------- START ----------
app.listen(PORT, () => {
  console.log("✅ Server listening on port", PORT);
});
