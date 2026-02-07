import express from "express";
import fs from "fs";
import path from "path";
import crypto from "crypto";

const app = express();
app.use(express.json());

// Railway provides PORT
const PORT = process.env.PORT || 3000;

// Files (these exist in your repo)
const LICENSES_PATH = path.join(process.cwd(), "licenses.json");
const LOGS_PATH = path.join(process.cwd(), "logs.json");

// In-memory last start time (helps compute duration if you want)
const lastStart = new Map();

/* --------------------------
   Helpers
-------------------------- */
function safeReadJson(filePath, fallback) {
  try {
    if (!fs.existsSync(filePath)) return fallback;
    const txt = fs.readFileSync(filePath, "utf8");
    if (!txt.trim()) return fallback;
    return JSON.parse(txt);
  } catch {
    return fallback;
  }
}

function safeWriteJson(filePath, data) {
  // Write atomically: write temp then rename
  const tmp = filePath + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2), "utf8");
  fs.renameSync(tmp, filePath);
}

function nowIso() {
  return new Date().toISOString();
}

function getIp(req) {
  // Railway / proxies may send x-forwarded-for
  const xf = req.headers["x-forwarded-for"];
  if (typeof xf === "string" && xf.length) return xf.split(",")[0].trim();
  return req.socket?.remoteAddress || "unknown";
}

function isExpired(expiryYYYYMMDD) {
  // expiry stored like "2026-12-31"
  const exp = new Date(expiryYYYYMMDD + "T23:59:59Z");
  return Number.isFinite(exp.getTime()) ? exp < new Date() : true;
}

// Optional: hash device id in logs (privacy). If you want raw, set to false.
const HASH_DEVICE_IN_LOGS = false;
function deviceForLog(deviceId) {
  if (!HASH_DEVICE_IN_LOGS) return deviceId;
  return crypto.createHash("sha256").update(deviceId).digest("hex");
}

/* --------------------------
   Core license check
-------------------------- */
function checkLicense(device_id) {
  const licenses = safeReadJson(LICENSES_PATH, []);
  const lic = licenses.find((l) => String(l.device_id) === String(device_id));

  if (!lic) {
    return {
      status: "unauthorised" // no username/level/expiry
    };
  }

  const expired = isExpired(lic.expiry);

  return {
    status: expired ? "expired" : "valid",
    username: lic.username,
    level: lic.level, // "lite" or "premium"
    expiry: lic.expiry
  };
}

/* --------------------------
   Routes
-------------------------- */

// Health
app.get("/", (req, res) => {
  res.type("text/plain").send("GG License backend is running");
});
// QUICK TEST (browser-friendly)
// Example:
// https://golf-licenses-production.up.railway.app/check?device_id=739414467890316
app.get("/check", (req, res) => {
  const device_id = (req.query.device_id || "").toString().trim();
  if (!device_id) return res.status(400).json({ status: "error", message: "device_id required" });

  const result = checkLicense(device_id);

  // Log check attempt
  const logs = safeReadJson(LOGS_PATH, []);
  logs.push({
    type: "check",
    device_id: deviceForLog(device_id),
    result: result.status,
    time: nowIso(),
    ip: getIp(req)
  });
  safeWriteJson(LOGS_PATH, logs);

  return res.json(result);
});

/**
 * POST /check
 * Body: { device_id: "..." }
 * Returns:
 *  - {status:"valid", username, level, expiry}
 *  - {status:"expired", username, level, expiry}
 *  - {status:"unauthorised"}
 */
app.post("/check", (req, res) => {
  const device_id = (req.body?.device_id || "").toString().trim();
  if (!device_id) return res.status(400).json({ status: "error", message: "device_id required" });

  const result = checkLicense(device_id);

  // Log check attempt (time + device + result)
  const logs = safeReadJson(LOGS_PATH, []);
  logs.push({
    type: "check",
    device_id: deviceForLog(device_id),
    result: result.status,
    time: nowIso(),
    ip: getIp(req)
  });
  safeWriteJson(LOGS_PATH, logs);

  return res.json(result);
});

/**
 * POST /event
 * Body examples:
 *  START: { device_id:"...", event:"start", script:"lite"|"premium" }
 *  END:   { device_id:"...", event:"end", duration: 17 }
 *
 * Rules you wanted:
 * - valid users: start + end + duration
 * - expired/unauthorised: log device_id + time (and result)
 */
app.post("/event", (req, res) => {
  const device_id = (req.body?.device_id || "").toString().trim();
  const event = (req.body?.event || "").toString().trim().toLowerCase();
  const script = (req.body?.script || "").toString().trim().toLowerCase(); // optional
  const duration = Number(req.body?.duration); // optional

  if (!device_id) return res.status(400).json({ status: "error", message: "device_id required" });
  if (event !== "start" && event !== "end") {
    return res.status(400).json({ status: "error", message: "event must be start or end" });
  }

  const lic = checkLicense(device_id);
  const ip = getIp(req);

  // session helpers
  if (event === "start") {
    lastStart.set(device_id, Date.now());
  }

  let duration_final = null;
  if (event === "end") {
    if (Number.isFinite(duration) && duration >= 0) {
      duration_final = duration;
    } else {
      // If client didn't send duration, try compute from last start
      const st = lastStart.get(device_id);
      if (st) {
        duration_final = Math.round((Date.now() - st) / 60000); // minutes
      }
    }
    lastStart.delete(device_id);
  }

  // Build log record
  const logRecord = {
    type: "event",
    event,
    result: lic.status,
    device_id: deviceForLog(device_id),
    time: nowIso(),
    ip
  };

  // Only attach username/level/expiry if licensed (valid OR expired)
  if (lic.status === "valid" || lic.status === "expired") {
    logRecord.username = lic.username;
    logRecord.level = lic.level;
    logRecord.expiry = lic.expiry;
  }

  // For valid users, include script + duration when relevant
  if (lic.status === "valid") {
    if (script) logRecord.script = script;
    if (event === "end") logRecord.duration = duration_final ?? 0;
  } else {
    // For expired/unauthorised: you asked only device id + time.
    // We still store "result" and "event" so you can filter later.
    if (event === "end") logRecord.duration = duration_final ?? null;
  }

  const logs = safeReadJson(LOGS_PATH, []);
  logs.push(logRecord);
  safeWriteJson(LOGS_PATH, logs);

  return res.json({ status: "ok", logged: { event, result: lic.status } });
});

app.listen(PORT, () => {
  console.log("Server listening on port", PORT);
});
