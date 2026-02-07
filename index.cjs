// ================================
// Golf License Server (EVENT->SESSION MAPPING)
// CommonJS (.cjs) – SAFE FOR Railway
// ================================

const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const crypto = require("crypto");

// ----------------
// ENV CHECK
// ----------------
if (!process.env.DATABASE_URL) {
  console.error("❌ DATABASE_URL is missing in Railway variables");
  process.exit(1);
}

// ----------------
// DB CONNECTION
// ----------------
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

// ----------------
// APP SETUP
// ----------------
const app = express();
app.use(cors());
app.use(express.json());

function nowIso() {
  return new Date().toISOString();
}

function safeInt(v) {
  const n = parseInt(v, 10);
  return Number.isFinite(n) && n >= 0 ? n : null;
}

function newSessionId() {
  return crypto.randomBytes(9).toString("hex"); // 18 chars
}

// ----------------
// EVENT LOGGER
// ----------------
async function logEvent(device_id, event, result, req, data = null) {
  const ip =
    (req.headers["x-forwarded-for"] || "").split(",")[0].trim() ||
    req.socket?.remoteAddress ||
    null;

  const ua = req.headers["user-agent"] || null;

  await pool.query(
    `INSERT INTO events (device_id, event, result, ip, user_agent, data)
     VALUES ($1,$2,$3,$4,$5,$6)`,
    [device_id, event, result, ip, ua, data]
  );
}

// ----------------
// SESSION HELPERS (event=start/end -> sessions table)
// ----------------
async function abortRunningSessions(device_id, reason = "aborted") {
  // Close any running sessions for this device (crash/unknown)
  // duration_sec = now - start_time
  await pool.query(
    `UPDATE sessions
       SET end_time = now(),
           status = $2,
           duration_sec = EXTRACT(EPOCH FROM (now() - start_time))::int
     WHERE device_id = $1
       AND status = 'running'
       AND end_time IS NULL`,
    [device_id, reason]
  );
}

async function startSessionFromEvent(device_id, level) {
  // mark old running sessions as aborted (if any)
  await abortRunningSessions(device_id, "aborted");

  const sid = newSessionId();

  await pool.query(
    `INSERT INTO sessions (session_id, device_id, level, start_time, status)
     VALUES ($1,$2,$3, now(), 'running')`,
    [sid, device_id, level || "unknown"]
  );

  return sid;
}

async function endSessionFromEvent(device_id, durationSec) {
  // Close the latest running session
  // If durationSec provided, trust it; else compute from timestamps
  const q = await pool.query(
    `SELECT id, start_time
       FROM sessions
      WHERE device_id = $1
        AND status = 'running'
        AND end_time IS NULL
   ORDER BY start_time DESC
      LIMIT 1`,
    [device_id]
  );

  if (q.rows.length === 0) return { closed: false };

  const row = q.rows[0];

  if (durationSec == null) {
    // compute duration on server
    await pool.query(
      `UPDATE sessions
          SET end_time = now(),
              status = 'ended',
              duration_sec = EXTRACT(EPOCH FROM (now() - start_time))::int
        WHERE id = $1`,
      [row.id]
    );
  } else {
    await pool.query(
      `UPDATE sessions
          SET end_time = now(),
              status = 'ended',
              duration_sec = $2
        WHERE id = $1`,
      [row.id, durationSec]
    );
  }

  return { closed: true };
}

// ----------------
// HEALTH CHECK
// ----------------
app.get("/", (req, res) => {
  res.json({
    status: "ok",
    service: "license-server",
    time: nowIso(),
  });
});

// ----------------
// LICENSE CHECK (GET for old GG)
// /check?device_id=123
// ----------------
app.get("/check", async (req, res) => {
  try {
    const device_id = (req.query.device_id || "").toString().trim();
    if (!device_id) return res.status(400).json({ error: "device_id required" });

    const result = await pool.query(
      `SELECT device_id, username, level, expiry, status
         FROM licenses
        WHERE device_id = $1
        LIMIT 1`,
      [device_id]
    );

    if (result.rows.length === 0) {
      await logEvent(device_id, "check", "unauthorised", req);
      return res.json({ status: "unauthorised" });
    }

    const lic = result.rows[0];
    const today = new Date();

    if (lic.status !== "active") {
      await logEvent(device_id, "check", "inactive", req, { lic_status: lic.status });
      return res.json({ status: "inactive" });
    }

    if (lic.expiry && new Date(lic.expiry) < today) {
      await logEvent(device_id, "check", "expired", req, { expiry: lic.expiry });
      return res.json({
        status: "expired",
        username: lic.username,
        level: lic.level,
        expiry: lic.expiry,
      });
    }

    await logEvent(device_id, "check", "valid", req, { level: lic.level, expiry: lic.expiry });

    return res.json({
      status: "valid",
      username: lic.username,
      level: lic.level,
      expiry: lic.expiry,
    });
  } catch (err) {
    console.error("❌ /check error:", err);
    return res.status(500).json({ error: "server_error" });
  }
});

// ----------------
// EVENT ENDPOINT (GET for old GG)
// /event?device_id=123&event=start&script=premium
// /event?device_id=123&event=end&duration=25&script=premium
// ----------------
app.get("/event", async (req, res) => {
  try {
    const device_id = (req.query.device_id || "").toString().trim();
    const event = (req.query.event || "").toString().trim().toLowerCase();
    const script = (req.query.script || "").toString().trim() || null;
    const duration = safeInt(req.query.duration);

    if (!device_id || !event) {
      return res.status(400).json({ error: "device_id and event required" });
    }

    // Log ALL events
    await logEvent(device_id, event, "ok", req, { script, duration });

    // Map start/end into sessions automatically
    if (event === "start") {
      const sid = await startSessionFromEvent(device_id, script || "unknown");
      return res.json({ status: "ok", mapped: "session_start", session_id: sid });
    }

    if (event === "end") {
      const out = await endSessionFromEvent(device_id, duration);
      return res.json({ status: "ok", mapped: "session_end", closed: out.closed });
    }

    // other events just logged
    return res.json({ status: "ok" });
  } catch (err) {
    console.error("❌ /event error:", err);
    return res.status(500).json({ error: "server_error" });
  }
});

// ----------------
// VIEW LOGS IN BROWSER (simple)
// /events?device_id=123
// /sessions?device_id=123
// ----------------
app.get("/events", async (req, res) => {
  try {
    const device_id = (req.query.device_id || "").toString().trim();
    const limit = Math.min(safeInt(req.query.limit) || 200, 1000);

    const q = device_id
      ? await pool.query(
          `SELECT id, device_id, event, result, created_at
             FROM events
            WHERE device_id = $1
         ORDER BY created_at DESC
            LIMIT $2`,
          [device_id, limit]
        )
      : await pool.query(
          `SELECT id, device_id, event, result, created_at
             FROM events
         ORDER BY created_at DESC
            LIMIT $1`,
          [limit]
        );

    res.json(q.rows);
  } catch (err) {
    console.error("❌ /events error:", err);
    res.status(500).json({ error: "server_error" });
  }
});

app.get("/sessions", async (req, res) => {
  try {
    const device_id = (req.query.device_id || "").toString().trim();
    const limit = Math.min(safeInt(req.query.limit) || 200, 1000);

    const q = device_id
      ? await pool.query(
          `SELECT session_id, device_id, level, start_time, end_time, status, duration_sec
             FROM sessions
            WHERE device_id = $1
         ORDER BY start_time DESC
            LIMIT $2`,
          [device_id, limit]
        )
      : await pool.query(
          `SELECT session_id, device_id, level, start_time, end_time, status, duration_sec
             FROM sessions
         ORDER BY start_time DESC
            LIMIT $1`,
          [limit]
        );

    res.json(q.rows);
  } catch (err) {
    console.error("❌ /sessions error:", err);
    res.status(500).json({ error: "server_error" });
  }
});

// ----------------
// PORT + START
// ----------------
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`✅ Server listening on port ${PORT}`);
});
