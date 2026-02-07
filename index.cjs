// =====================================
// FINAL License + Tracking Server (CJS)
// + Admin API (licenses CRUD + stats endpoints)
// =====================================

const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const crypto = require("crypto");

// ---------- ENV ----------
const PORT = process.env.PORT || 8080;
const DATABASE_URL = process.env.DATABASE_URL;
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || ""; // set in Railway Variables

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

// ---------- ADMIN GUARD ----------
function adminGuard(req, res) {
  const token = cleanText(req.query.token, 500);
  if (!ADMIN_TOKEN || token !== ADMIN_TOKEN) {
    res.status(401).json({ error: "unauthorised" });
    return false;
  }
  return true;
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

    // Only VALID licenses can create/update sessions
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
        return res.json({
          status: "ok",
          session: out.ended ? "ended" : "not_found",
          session_id: out.session_id || null,
        });
      }
      return res.json({ status: "ok", session: "not_ended", reason: v.status });
    }

    return res.json({ status: "ok" });
  } catch (err) {
    console.error("❌ /event error:", err);
    return res.status(500).json({ error: "server_error" });
  }
});

// ---------- ADMIN: RAW VIEWS (browser JSON) ----------
app.get("/admin/events", async (req, res) => {
  try {
    if (!adminGuard(req, res)) return;

    const device_id = cleanText(req.query.device_id, 200);
    const limit = Math.min(Math.max(toInt(req.query.limit) || 200, 1), 1000);

    const r = device_id
      ? await pool.query(
          `SELECT id, device_id, event, result, created_at
             FROM public.events
            WHERE device_id = $1
            ORDER BY created_at DESC
            LIMIT $2`,
          [device_id, limit]
        )
      : await pool.query(
          `SELECT id, device_id, event, result, created_at
             FROM public.events
            ORDER BY created_at DESC
            LIMIT $1`,
          [limit]
        );

    res.json(r.rows);
  } catch (err) {
    console.error("❌ /admin/events error:", err);
    res.status(500).json({ error: "server_error" });
  }
});

app.get("/admin/sessions", async (req, res) => {
  try {
    if (!adminGuard(req, res)) return;

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

// ---------- ADMIN: LICENSES CRUD ----------
// List all licenses
app.get("/admin/licenses", async (req, res) => {
  try {
    if (!adminGuard(req, res)) return;

    const { rows } = await pool.query(
      `SELECT device_id, username, level, expiry, status, created_at, updated_at
       FROM public.licenses
       ORDER BY updated_at DESC NULLS LAST, created_at DESC NULLS LAST`
    );
    res.json(rows);
  } catch (err) {
    console.error("❌ /admin/licenses error:", err);
    res.status(500).json({ error: "server_error" });
  }
});

// Add/Edit license (UPSERT)
app.post("/admin/license", async (req, res) => {
  try {
    if (!adminGuard(req, res)) return;

    const body = req.body || {};
    const device_id = cleanText(body.device_id, 200);
    const username = body.username == null ? null : cleanText(body.username, 200);
    const level = body.level == null ? null : cleanText(body.level, 20);
    const expiry = body.expiry == null ? null : cleanText(body.expiry, 20); // YYYY-MM-DD
    const status = body.status == null ? "active" : cleanText(body.status, 20);

    if (!device_id) return res.status(400).json({ error: "device_id required" });

    await pool.query(
      `INSERT INTO public.licenses (device_id, username, level, expiry, status, updated_at)
       VALUES ($1,$2,$3,$4,$5, now())
       ON CONFLICT (device_id) DO UPDATE SET
         username = EXCLUDED.username,
         level = EXCLUDED.level,
         expiry = EXCLUDED.expiry,
         status = EXCLUDED.status,
         updated_at = now()`,
      [device_id, username, level, expiry, status]
    );

    res.json({ status: "ok" });
  } catch (err) {
    console.error("❌ /admin/license POST error:", err);
    res.status(500).json({ error: "server_error" });
  }
});

// Delete license
app.delete("/admin/license", async (req, res) => {
  try {
    if (!adminGuard(req, res)) return;

    const device_id = cleanText(req.query.device_id, 200);
    if (!device_id) return res.status(400).json({ error: "device_id required" });

    await pool.query(`DELETE FROM public.licenses WHERE device_id = $1`, [device_id]);
    res.json({ status: "ok" });
  } catch (err) {
    console.error("❌ /admin/license DELETE error:", err);
    res.status(500).json({ error: "server_error" });
  }
});

// ---------- ADMIN: STATS (requires the views you already created) ----------
// /admin/daily-usage?token=...&from=YYYY-MM-DD&to=YYYY-MM-DD
app.get("/admin/daily-usage", async (req, res) => {
  try {
    if (!adminGuard(req, res)) return;

    const from = cleanText(req.query.from, 20);
    const to = cleanText(req.query.to, 20);
    if (!from || !to) return res.status(400).json({ error: "from and to required (YYYY-MM-DD)" });

    const { rows } = await pool.query(
      `SELECT *
       FROM public.daily_usage_named
       WHERE day BETWEEN $1 AND $2
       ORDER BY day DESC, total_duration_sec DESC`,
      [from, to]
    );

    res.json(rows);
  } catch (err) {
    console.error("❌ /admin/daily-usage error:", err);
    res.status(500).json({ error: "server_error" });
  }
});

// /admin/daily-attempts?token=...&from=YYYY-MM-DD&to=YYYY-MM-DD
app.get("/admin/daily-attempts", async (req, res) => {
  try {
    if (!adminGuard(req, res)) return;

    const from = cleanText(req.query.from, 20);
    const to = cleanText(req.query.to, 20);
    if (!from || !to) return res.status(400).json({ error: "from and to required (YYYY-MM-DD)" });

    const { rows } = await pool.query(
      `SELECT *
       FROM public.daily_attempts_named
       WHERE day BETWEEN $1 AND $2
       ORDER BY day DESC, attempts DESC`,
      [from, to]
    );

    res.json(rows);
  } catch (err) {
    console.error("❌ /admin/daily-attempts error:", err);
    res.status(500).json({ error: "server_error" });
  }
});

// ---------- START ----------
app.listen(PORT, () => {
  console.log("✅ Server listening on port", PORT);
});
