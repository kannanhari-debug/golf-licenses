// ================================
// Golf License Server (FULL TEST VERSION)
// CommonJS – SAFE FOR RAILWAY
// ================================

const express = require("express");
const cors = require("cors");
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
  ssl: { rejectUnauthorized: false }
});

// ----------------
// APP SETUP
// ----------------
const app = express();
app.use(cors());
app.use(express.json());

// ----------------
// HEALTH CHECK
// ----------------
app.get("/", (req, res) => {
  res.json({
    status: "ok",
    service: "golf-license-server",
    time: new Date().toISOString()
  });
});

// ----------------
// LICENSE CHECK
// ----------------
app.post("/check", async (req, res) => {
  try {
    const { device_id } = req.body;

    if (!device_id) {
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
      await logEvent(device_id, "check", "unauthorised");
      return res.json({ status: "unauthorised" });
    }

    const lic = result.rows[0];
    const today = new Date();

    if (lic.status !== "active") {
      await logEvent(device_id, "check", "inactive");
      return res.json({ status: "inactive" });
    }

    if (new Date(lic.expiry) < today) {
      await logEvent(device_id, "check", "expired");
      return res.json({
        status: "expired",
        username: lic.username,
        expiry: lic.expiry
      });
    }

    await logEvent(device_id, "check", "valid");

    res.json({
      status: "valid",
      username: lic.username,
      level: lic.level,
      expiry: lic.expiry
    });

  } catch (err) {
    console.error("❌ /check error:", err);
    res.status(500).json({ error: "server_error" });
  }
});

// ----------------
// SESSION START
// ----------------
app.post("/start", async (req, res) => {
  try {
    const { session_id, device_id, level } = req.body;

    await pool.query(
      `INSERT INTO sessions (session_id, device_id, level, start_time, status)
       VALUES ($1, $2, $3, now(), 'running')`,
      [session_id, device_id, level]
    );

    await logEvent(device_id, "start", "ok");

    res.json({ status: "started" });
  } catch (err) {
    console.error("❌ /start error:", err);
    res.status(500).json({ error: "server_error" });
  }
});

// ----------------
// SESSION END
// ----------------
app.post("/end", async (req, res) => {
  try {
    const { session_id } = req.body;

    const result = await pool.query(
      `UPDATE sessions
       SET end_time = now(),
           status = 'ended',
           duration_sec = EXTRACT(EPOCH FROM (now() - start_time))
       WHERE session_id = $1
       RETURNING device_id`,
      [session_id]
    );

    if (result.rowCount > 0) {
      await logEvent(result.rows[0].device_id, "end", "ok");
    }

    res.json({ status: "ended" });
  } catch (err) {
    console.error("❌ /end error:", err);
    res.status(500).json({ error: "server_error" });
  }
});

// ----------------
// LOG HELPER
// ----------------
async function logEvent(device_id, event, result) {
  try {
    await pool.query(
      `INSERT INTO events (device_id, event, result, created_at)
       VALUES ($1, $2, $3, now())`,
      [device_id, event, result]
    );
  } catch (e) {
    console.error("⚠ logEvent failed:", e.message);
  }
}

// ----------------
// START SERVER
// ----------------
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log("✅ Server running on port", PORT);
});
