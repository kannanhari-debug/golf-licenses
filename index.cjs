// ================================
// License Server (CommonJS)
// Works with Railway when filename is index.cjs
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
  // Supabase usually requires SSL from external hosts.
  ssl: { rejectUnauthorized: false },
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

async function logEvent(device_id, event, result, extra = {}) {
  try {
    const ip =
      (extra && extra.ip) ||
      null;
    const user_agent =
      (extra && extra.user_agent) ||
      null;

    const data = extra && extra.data ? extra.data : null;

    await pool.query(
      `INSERT INTO events (device_id, event, result, ip, user_agent, data)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [
        safeText(device_id, 200),
        safeText(event, 50),
        safeText(result, 50),
        safeText(ip, 64),
        safeText(user_agent, 300),
        data ? JSON.stringify(data) : null,
      ]
    );
  } catch (e) {
    // Never crash the API because logging failed
    console.error("⚠️ logEvent failed:", e.message);
  }
}

function getRequestMeta(req) {
  const ip =
    req.headers["x-forwarded-for"]?.toString().split(",")[0].trim() ||
    req.socket?.remoteAddress ||
    null;

  const user_agent = req.headers["user-agent"] || null;
  return { ip, user_agent };
}

// ----------------
// HEALTH CHECK
// ----------------
app.get("/", async (req, res) => {
  try {
    await pool.query(
      `INSERT INTO events (device_id, event, result, created_at)
       VALUES ($1, $2, $3, now())`,
      ["BROWSER_TEST", "ping", "ok"]
    );
  } catch (e) {
    console.log("log failed:", e.message);
  }

  res.json({
    status: "ok",
    service: "license-server",
    time: new Date().toISOString(),
  });
});

// ----------------
// LICENSE CHECK
// ----------------
app.post("/check", async (req, res) => {
  const { ip, user_agent } = getRequestMeta(req);

  try {
    const { device_id } = req.body || {};

    if (!device_id) {
      await logEvent(null, "check", "error_missing_device", {
        ip,
        user_agent,
      });
      return res.status(400).json({ error: "device_id required" });
    }

    const result = await pool.query(
      `SELECT device_id, username, level, expiry, status
       FROM licenses
       WHERE device_id = $1
       LIMIT 1`,
      [device_id]
    );

    if (result.rows.length === 0) {
      await logEvent(device_id, "check", "unauthorised", { ip, user_agent });
      return res.json({ status: "unauthorised" });
    }

    const lic = result.rows[0];

    if (lic.status !== "active") {
      await logEvent(device_id, "check", "inactive", { ip, user_agent });
      return res.json({
        status: "inactive",
        username: lic.username,
        level: lic.level,
        expiry: lic.expiry,
      });
    }

    // expiry in DB is DATE; compare as end-of-day
    const expiryDate = new Date(lic.expiry + "T23:59:59Z");
    const now = new Date();

    if (expiryDate < now) {
      await logEvent(device_id, "check", "expired", { ip, user_agent });
      return res.json({
        status: "expired",
        username: lic.username,
        level: lic.level,
        expiry: lic.expiry,
      });
    }

    await logEvent(device_id, "check", "valid", { ip, user_agent });

    return res.json({
      status: "valid",
      username: lic.username,
      level: lic.level,
      expiry: lic.expiry,
    });
  } catch (err) {
    console.error("❌ /check error:", err);
    await logEvent(req.body?.device_id || null, "check", "server_error", {
      ip,
      user_agent,
      data: { msg: err.message },
    });
    res.status(500).json({ error: "server_error" });
  }
});

// ----------------
// SESSION START
// ----------------
app.post("/start", async (req, res) => {
  const { ip, user_agent } = getRequestMeta(req);

  try {
    const { session_id, device_id, level } = req.body || {};

    if (!device_id) return res.status(400).json({ error: "device_id required" });

    // If client didn't send session_id, generate one
    const sid = session_id && String(session_id).trim()
      ? String(session_id).trim()
      : crypto.randomUUID();

    await pool.query(
      `INSERT INTO sessions (session_id, device_id, level, start_time, status, ip, user_agent)
       VALUES ($1, $2, $3, now(), 'running', $4, $5)`,
      [sid, device_id, safeText(level, 20), safeText(ip, 64), safeText(user_agent, 300)]
    );

    await logEvent(device_id, "start", "ok", {
      ip,
      user_agent,
      data: { session_id: sid, level },
    });

    res.json({ status: "started", session_id: sid });
  } catch (err) {
    console.error("❌ /start error:", err);
    await logEvent(req.body?.device_id || null, "start", "server_error", {
      ip,
      user_agent,
      data: { msg: err.message },
    });
    res.status(500).json({ error: "server_error" });
  }
});

// ----------------
// SESSION END
// ----------------
app.post("/end", async (req, res) => {
  const { ip, user_agent } = getRequestMeta(req);

  try {
    const { session_id, device_id } = req.body || {};
    if (!device_id) return res.status(400).json({ error: "device_id required" });
    if (!session_id) return res.status(400).json({ error: "session_id required" });

    // Update end_time + duration
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

    await logEvent(device_id, "end", "ok", {
      ip,
      user_agent,
      data: { session_id, duration_sec: duration },
    });

    res.json({ status: "ended", duration_sec: duration });
  } catch (err) {
    console.error("❌ /end error:", err);
    await logEvent(req.body?.device_id || null, "end", "server_error", {
      ip,
      user_agent,
      data: { msg: err.message },
    });
    res.status(500).json({ error: "server_error" });
  }
});

// ----------------
// GENERIC EVENT (optional)
// ----------------
app.post("/event", async (req, res) => {
  const { ip, user_agent } = getRequestMeta(req);

  try {
    const { device_id, event, result, data } = req.body || {};
    if (!device_id) return res.status(400).json({ error: "device_id required" });

    await logEvent(device_id, event || "event", result || "ok", {
      ip,
      user_agent,
      data: data || null,
    });

    res.json({ status: "logged" });
  } catch (err) {
    console.error("❌ /event error:", err);
    res.status(500).json({ error: "server_error" });
  }
});

// ----------------
// QUICK VIEW (for testing in browser)
// DO NOT leave this public forever in real production.
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
