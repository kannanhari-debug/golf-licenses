/**
 * index.js - Railway + Supabase (Postgres) backend
 * Beginner-friendly: includes /health so Railway doesn’t stop immediately
 *
 * Required env vars on Railway:
 * - DATABASE_URL  (Supabase "Session pooler" or "Direct connection" URI)
 * - DB_PASSWORD   (your Supabase DB password)
 *
 * Optional:
 * - PORT (Railway sets this automatically)
 */

const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const { Pool } = require("pg");

const app = express();
app.use(cors());
app.use(express.json({ limit: "512kb" }));

// --- Build DATABASE_URL safely (supports [YOUR-PASSWORD] placeholder) ---
function getDatabaseUrl() {
  let url = process.env.DATABASE_URL || "";
  const pw = process.env.DB_PASSWORD || "";

  if (!url) return "";

  // Supabase UI often shows [YOUR-PASSWORD] placeholder in the connection string
  if (url.includes("[YOUR-PASSWORD]")) {
    if (!pw) {
      // leave placeholder; we’ll fail fast with a helpful error
      return url;
    }
    url = url.replace("[YOUR-PASSWORD]", encodeURIComponent(pw));
  }

  return url;
}

const DATABASE_URL = getDatabaseUrl();
if (!DATABASE_URL || DATABASE_URL.includes("[YOUR-PASSWORD]")) {
  console.log("❌ DATABASE_URL is missing or still contains [YOUR-PASSWORD].");
  console.log("   Fix Railway Variables:");
  console.log("   - set DB_PASSWORD");
  console.log("   - set DATABASE_URL from Supabase connection string");
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 5,
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 10_000,
});

// --- Helpers ---
function nowIso() {
  return new Date().toISOString();
}

function getClientIp(req) {
  const xf = req.headers["x-forwarded-for"];
  if (typeof xf === "string" && xf.length > 0) {
    return xf.split(",")[0].trim();
  }
  return req.socket?.remoteAddress || null;
}

function newSessionId() {
  return crypto.randomBytes(12).toString("hex"); // 24 chars
}

// --- Health route (CRITICAL for Railway testing) ---
app.get("/health", async (req, res) => {
  try {
    // quick DB ping (optional but useful)
    await pool.query("select 1 as ok");
    res.status(200).send("OK");
  } catch (e) {
    res.status(500).send("DB_NOT_OK");
  }
});

app.get("/", (req, res) => {
  res.status(200).send("OK");
});

// --- Validate license by device_id ---
app.get("/validate", async (req, res) => {
  const device_id = String(req.query.device_id || "").trim();

  if (!device_id) {
    return res.status(400).json({ status: "error", message: "device_id required" });
  }

  try {
    const q = `
      select device_id, username, level, expiry, status
      from public.licenses
      where device_id = $1
      limit 1
    `;
    const r = await pool.query(q, [device_id]);

    if (r.rowCount === 0) {
      await pool.query(
        `insert into public.events(device_id, event, result, ip, user_agent, data)
         values ($1, 'validate', 'unauthorised', $2, $3, $4)`,
        [device_id, getClientIp(req), req.headers["user-agent"] || null, { time: nowIso() }]
      );

      return res.json({
        status: "unauthorised",
        device_id,
      });
    }

    const lic = r.rows[0];
    const expiryDate = lic.expiry ? new Date(lic.expiry) : null;
    const today = new Date();
    today.setHours(0, 0, 0, 0);

    let result = "valid";
    if (lic.status && String(lic.status).toLowerCase() !== "active") result = "unauthorised";
    if (expiryDate && expiryDate < today) result = "expired";

    await pool.query(
      `insert into public.events(device_id, event, result, ip, user_agent, data)
       values ($1, 'validate', $2, $3, $4, $5)`,
      [
        device_id,
        result,
        getClientIp(req),
        req.headers["user-agent"] || null,
        { time: nowIso(), level: lic.level, username: lic.username, expiry: lic.expiry },
      ]
    );

    return res.json({
      status: result,
      device_id: lic.device_id,
      username: result === "valid" ? lic.username : undefined,
      level: result === "valid" ? lic.level : undefined,
      expiry: lic.expiry,
    });
  } catch (e) {
    console.log("validate error:", e.message);
    return res.status(500).json({ status: "error", message: "server error" });
  }
});

// --- Start/end events + sessions (simple version for testing) ---
// POST /event
// body: { device_id, event: "start"|"end", level?: "lite"|"premium", session_id?: "..." }
app.post("/event", async (req, res) => {
  const device_id = String(req.body?.device_id || "").trim();
  const event = String(req.body?.event || "").trim().toLowerCase();
  const level = req.body?.level ? String(req.body.level).trim().toLowerCase() : null;
  let session_id = req.body?.session_id ? String(req.body.session_id).trim() : null;

  if (!device_id || !event) {
    return res.status(400).json({ status: "error", message: "device_id and event required" });
  }

  if (event !== "start" && event !== "end") {
    return res.status(400).json({ status: "error", message: "event must be start or end" });
  }

  try {
    // log event row always
    await pool.query(
      `insert into public.events(device_id, event, result, ip, user_agent, data)
       values ($1, $2, 'ok', $3, $4, $5)`,
      [
        device_id,
        event,
        getClientIp(req),
        req.headers["user-agent"] || null,
        { time: nowIso(), level, session_id },
      ]
    );

    // session handling (optional but useful)
    if (event === "start") {
      session_id = newSessionId();
      await pool.query(
        `insert into public.sessions(session_id, device_id, level, start_time, status, ip, user_agent)
         values ($1, $2, $3, now(), 'running', $4, $5)`,
        [session_id, device_id, level, getClientIp(req), req.headers["user-agent"] || null]
      );
      return res.json({ status: "ok", session_id });
    }

    // event === "end"
    if (!session_id) {
      // If client didn’t send a session_id, end the latest running session
      const find = await pool.query(
        `select id, session_id, start_time
         from public.sessions
         where device_id = $1 and status = 'running'
         order by start_time desc
         limit 1`,
        [device_id]
      );
      if (find.rowCount > 0) session_id = find.rows[0].session_id;
    }

    if (session_id) {
      await pool.query(
        `update public.sessions
         set end_time = now(),
             status = 'ended',
             duration_sec = greatest(0, extract(epoch from (now() - start_time))::int)
         where session_id = $1 and device_id = $2 and status = 'running'`,
        [session_id, device_id]
      );
    }

    return res.json({ status: "ok", session_id: session_id || null });
  } catch (e) {
    console.log("event error:", e.message);
    return res.status(500).json({ status: "error", message: "server error" });
  }
});

// --- Start server ---
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log("Server listening on port", PORT);
});

// Graceful shutdown (helps Railway)
process.on("SIGTERM", async () => {
  try {
    console.log("SIGTERM received, shutting down...");
    await pool.end();
  } catch {}
  process.exit(0);
});
