// ================================
// License Server (CommonJS)
// Old GameGuardian compatible (GET /check + GET /event)
// Keep POST endpoints for future admin/tools
// ================================

const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const { Pool } = require("pg");

// ----------------
// ENV CHECK
// ----------------
if (!process.env.DATABASE_URL) {
  console.error("❌ DATABASE_URL is missing");
  process.exit(1);
}

// ----------------
// DB CONNECTION
// ----------------
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 5,
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 10_000,
});

// ----------------
// APP SETUP
// ----------------
const app = express();
app.use(cors());
app.use(express.json({ limit: "256kb" }));

// ----------------
// HELPERS
// ----------------
function safeText(v, max = 200) {
  if (v === undefined || v === null) return null;
  const s = String(v);
  return s.length > max ? s.slice(0, max) : s;
}

function getRequestMeta(req) {
  const ip =
    (req.headers["x-forwarded-for"] && req.headers["x-forwarded-for"].toString().split(",")[0].trim()) ||
    req.socket?.remoteAddress ||
    null;

  const user_agent = req.headers["user-agent"] || null;
  return { ip, user_agent };
}

function toJsonbParam(obj) {
  // pg will send JS object as JSON if we stringify; we cast to jsonb in SQL
  if (obj === undefined) return null;
  if (obj === null) return null;
  return JSON.stringify(obj);
}

async function logEvent(device_id, event, result, extra = {}) {
  try {
    const ip = (extra && extra.ip) || null;
    const user_agent = (extra && extra.user_agent) || null;
    const data = extra && extra.data ? extra.data : null;

    await pool.query(
      `INSERT INTO events (device_id, event, result, ip, user_agent, data)
       VALUES ($1, $2, $3, $4, $5, $6::jsonb)`,
      [
        safeText(device_id, 200),
        safeText(event, 50),
        safeText(result, 50),
        safeText(ip, 64),
        safeText(user_agent, 300),
        toJsonbParam(data),
      ]
    );
  } catch (e) {
    console.error("⚠️ logEvent failed:", e.message);
  }
}

// Treat DATE expiry as valid through end-of-day UTC
function isExpired(dateString /* YYYY-MM-DD */) {
  if (!dateString) return true;
  const exp = new Date(String(dateString) + "T23:59:59Z");
  return exp.getTime() < Date.now();
}

async function checkLicenseByDeviceId(device_id, meta) {
  if (!device_id) {
    await logEvent(null, "check", "error_missing_device", meta);
    return { status: "unauthorised" };
  }

  const result = await pool.query(
    `SELECT device_id, username, level, expiry, status
     FROM licenses
     WHERE device_id = $1
     LIMIT 1`,
    [device_id]
  );

  if (result.rows.length === 0) {
    await logEvent(device_id, "check", "unauthorised", meta);
    return { status: "unauthorised" };
  }

  const lic = result.rows[0];

  if (String(lic.status || "").toLowerCase() !== "active") {
    await logEvent(device_id, "check", "inactive", meta);
    // for GG you wanted "no access" style; we can still return inactive if you want.
    return {
      status: "inactive",
      username: lic.username,
      level: lic.level,
      expiry: lic.expiry,
    };
  }

  if (isExpired(lic.expiry)) {
    await logEvent(device_id, "check", "expired", meta);
    return {
      status: "expired",
      username: lic.username,
      level: lic.level,
      expiry: lic.expiry,
    };
  }

  await logEvent(device_id, "check", "valid", meta);
  return {
    status: "valid",
    username: lic.username,
    level: lic.level,
    expiry: lic.expiry,
  };
}

// ----------------
// HEALTH CHECK
// ----------------
app.get("/", async (req, res) => {
  res.json({
    status: "ok",
    service: "license-server",
    time: new Date().toISOString(),
  });
});

// ----------------
// LICENSE CHECK (GET for OLD GG)
// Example: /check?device_id=123
// ----------------
app.get("/check", async (req, res) => {
  const { ip, user_agent } = getRequestMeta(req);
  const device_id = safeText(req.query.device_id, 200);

  try {
    const out = await checkLicenseByDeviceId(device_id, { ip, user_agent });
    res.json(out);
  } catch (err) {
    console.error("❌ GET /check error:", err.message);
    // fail closed = unauthorised
    res.json({ status: "unauthorised" });
  }
});

// ----------------
// LICENSE CHECK (POST for future tools)
// body: { device_id: "..." }
// ----------------
app.post("/check", async (req, res) => {
  const { ip, user_agent } = getRequestMeta(req);
  const device_id = safeText(req.body?.device_id, 200);

  try {
    const out = await checkLicenseByDeviceId(device_id, { ip, user_agent });
    res.json(out);
  } catch (err) {
    console.error("❌ POST /check error:", err.message);
    res.status(500).json({ error: "server_error" });
  }
});

// ----------------
// EVENT LOGGING (GET for OLD GG)
// Example:
// /event?device_id=123&event=start&script=lite
// /event?device_id=123&event=end&duration=55&script=premium
// ----------------
app.get("/event", async (req, res) => {
  const { ip, user_agent } = getRequestMeta(req);

  const device_id = safeText(req.query.device_id, 200);
  const event = safeText(req.query.event || "event", 50);
  const duration = req.query.duration !== undefined ? Number(req.query.duration) : null;
  const script = safeText(req.query.script, 20);

  if (!device_id) return res.json({ ok: false });

  const data = {
    duration: Number.isFinite(duration) ? Math.max(0, Math.floor(duration)) : null,
    script: script || null,
  };

  await logEvent(device_id, event, "ok", { ip, user_agent, data });
  return res.json({ ok: true });
});

// ----------------
// GENERIC EVENT (POST for future tools)
// body: { device_id, event, result, data }
// ----------------
app.post("/event", async (req, res) => {
  const { ip, user_agent } = getRequestMeta(req);

  try {
    const device_id = safeText(req.body?.device_id, 200);
    const event = safeText(req.body?.event || "event", 50);
    const result = safeText(req.body?.result || "ok", 50);
    const data = req.body?.data ?? null;

    if (!device_id) return res.status(400).json({ error: "device_id required" });

    await logEvent(device_id, event, result, { ip, user_agent, data });
    res.json({ status: "logged" });
  } catch (err) {
    console.error("❌ POST /event error:", err.message);
    res.status(500).json({ error: "server_error" });
  }
});

// ----------------
// SESSION START (POST)
// body: { session_id?, device_id, level }
// (Not required for your old GG wrapper; you are using /event start/end.)
// Keeping it for future.
// ----------------
app.post("/start", async (req, res) => {
  const { ip, user_agent } = getRequestMeta(req);

  try {
    const device_id = safeText(req.body?.device_id, 200);
    const level = safeText(req.body?.level, 20);

    if (!device_id) return res.status(400).json({ error: "device_id required" });

    const sid =
      req.body?.session_id && String(req.body.session_id).trim()
        ? String(req.body.session_id).trim()
        : crypto.randomUUID();

    await pool.query(
      `INSERT INTO sessions (session_id, device_id, level, start_time, status, ip, user_agent)
       VALUES ($1, $2, $3, now(), 'running', $4, $5)`,
      [sid, device_id, level, safeText(ip, 64), safeText(user_agent, 300)]
    );

    await logEvent(device_id, "start", "ok", { ip, user_agent, data: { session_id: sid, level } });
    res.json({ status: "started", session_id: sid });
  } catch (err) {
    console.error("❌ /start error:", err.message);
    res.status(500).json({ error: "server_error" });
  }
});

// ----------------
// SESSION END (POST)
// body: { session_id, device_id }
// ----------------
app.post("/end", async (req, res) => {
  const { ip, user_agent } = getRequestMeta(req);

  try {
    const device_id = safeText(req.body?.device_id, 200);
    const session_id = safeText(req.body?.session_id, 200);

    if (!device_id) return res.status(400).json({ error: "device_id required" });
    if (!session_id) return res.status(400).json({ error: "session_id required" });

    const r = await pool.query(
      `UPDATE sessions
       SET end_time = now(),
           status = 'ended',
           duration_sec = EXTRACT(EPOCH FROM (now() - start_time))::int
       WHERE session_id = $1 AND device_id = $2 AND status = 'running'
       RETURNING duration_sec`,
      [session_id, device_id]
    );

    const duration = r.rows[0]?.duration_sec ?? null;

    await logEvent(device_id, "end", "ok", { ip, user_agent, data: { session_id, duration_sec: duration } });
    res.json({ status: "ended", duration_sec: duration });
  } catch (err) {
    console.error("❌ /end error:", err.message);
    res.status(500).json({ error: "server_error" });
  }
});

// ----------------
// QUICK VIEW (for testing in browser)
// ----------------
app.get("/recent", async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT id, device_id, event, result, created_at
       FROM events
       ORDER BY id DESC
       LIMIT 50`
    );
    res.json(r.rows);
  } catch (err) {
    res.status(500).json({ error: "server_error" });
  }
});

// ----------------
// START SERVER
// ----------------
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log("✅ Server listening on port", PORT);
});
