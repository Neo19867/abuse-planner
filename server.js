const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const express = require("express");
const cookieParser = require("cookie-parser");

const PORT = Number(process.env.PORT || 8080);
const BOT_TOKEN = process.env.TG_BOT_TOKEN || "";
const ADMIN_USERNAME = String(process.env.ADMIN_TG_USERNAME || "Neo19867").replace(/^@/, "").toLowerCase();
const SESSION_COOKIE = "planner_sid";
const SESSION_TTL_MS = 1000 * 60 * 60 * 24 * 7;
const AUTH_MAX_AGE_SEC = 60 * 60 * 24;
const DB_PATH = path.join(__dirname, "auth-db.json");

if (!BOT_TOKEN) {
  console.error("Missing TG_BOT_TOKEN env variable.");
  process.exit(1);
}

const app = express();
const sessions = new Map();

app.use(express.json());
app.use(cookieParser());

function nowIso() {
  return new Date().toISOString();
}

function loadDb() {
  try {
    const raw = fs.readFileSync(DB_PATH, "utf8");
    const data = JSON.parse(raw);
    return {
      users: data.users && typeof data.users === "object" ? data.users : {},
      logins: Array.isArray(data.logins) ? data.logins : [],
    };
  } catch {
    return { users: {}, logins: [] };
  }
}

function saveDb(db) {
  fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2), "utf8");
}

function verifyTelegramAuth(payload) {
  const hash = payload.hash;
  const authDate = Number(payload.auth_date || 0);
  if (!hash || !authDate || !payload.id) return false;
  const age = Math.floor(Date.now() / 1000) - authDate;
  if (age > AUTH_MAX_AGE_SEC) return false;

  const checkString = Object.keys(payload)
    .filter((k) => k !== "hash" && payload[k] !== undefined && payload[k] !== null)
    .sort()
    .map((k) => `${k}=${payload[k]}`)
    .join("\n");

  const secretKey = crypto.createHash("sha256").update(BOT_TOKEN).digest();
  const expected = crypto.createHmac("sha256", secretKey).update(checkString).digest("hex");
  const a = Buffer.from(expected, "hex");
  const b = Buffer.from(String(hash), "hex");
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

function getSession(req) {
  const sid = req.cookies[SESSION_COOKIE];
  if (!sid) return null;
  const s = sessions.get(sid);
  if (!s) return null;
  if (Date.now() > s.expires_at) {
    sessions.delete(sid);
    return null;
  }
  return s;
}

function createSession(res, user) {
  const sid = crypto.randomBytes(32).toString("hex");
  const username = String(user.username || "").replace(/^@/, "").toLowerCase();
  const isAdmin = username === ADMIN_USERNAME;
  sessions.set(sid, {
    id: Number(user.id),
    username: user.username || "",
    first_name: user.first_name || "",
    is_admin: isAdmin,
    expires_at: Date.now() + SESSION_TTL_MS,
  });
  res.cookie(SESSION_COOKIE, sid, {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: SESSION_TTL_MS,
    path: "/",
  });
  return sessions.get(sid);
}

function sessionResponse(session) {
  return {
    authenticated: true,
    is_admin: !!session.is_admin,
    user: {
      id: session.id,
      username: session.username,
      first_name: session.first_name,
    },
  };
}

app.post("/api/auth/telegram", (req, res) => {
  const payload = req.body || {};
  if (!verifyTelegramAuth(payload)) {
    return res.status(401).json({ authenticated: false, error: "Invalid Telegram auth payload" });
  }

  const db = loadDb();
  const uid = String(payload.id);
  const prev = db.users[uid] || {};
  db.users[uid] = {
    id: Number(payload.id),
    username: payload.username || "",
    first_name: payload.first_name || "",
    last_name: payload.last_name || "",
    photo_url: payload.photo_url || "",
    registered_at: prev.registered_at || nowIso(),
    last_login_at: nowIso(),
    login_count: Number(prev.login_count || 0) + 1,
  };
  db.logins.push({ id: Number(payload.id), at: nowIso() });
  if (db.logins.length > 10000) db.logins = db.logins.slice(-10000);
  saveDb(db);

  const session = createSession(res, payload);
  return res.json(sessionResponse(session));
});

app.get("/api/session", (req, res) => {
  const session = getSession(req);
  if (!session) return res.json({ authenticated: false });
  return res.json(sessionResponse(session));
});

app.post("/api/logout", (req, res) => {
  const sid = req.cookies[SESSION_COOKIE];
  if (sid) sessions.delete(sid);
  res.clearCookie(SESSION_COOKIE, { path: "/" });
  return res.json({ ok: true });
});

app.get("/api/admin/stats", (req, res) => {
  const session = getSession(req);
  if (!session || !session.is_admin) {
    return res.status(403).json({ error: "Forbidden" });
  }
  const db = loadDb();
  const users = Object.values(db.users).sort((a, b) => {
    const ta = new Date(a.last_login_at || 0).getTime();
    const tb = new Date(b.last_login_at || 0).getTime();
    return tb - ta;
  });

  const today = new Date().toISOString().slice(0, 10);
  const todayLogins = db.logins.filter((x) => String(x.at || "").startsWith(today)).length;

  return res.json({
    total_users: users.length,
    total_logins: db.logins.length,
    today_logins: todayLogins,
    recent_users: users.slice(0, 30).map((u) => ({
      id: u.id,
      username: u.username,
      first_name: u.first_name,
      last_login_at: u.last_login_at,
      login_count: u.login_count,
    })),
  });
});

app.use(express.static(__dirname, { extensions: ["html"] }));

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

app.listen(PORT, () => {
  console.log(`Planner server listening on http://localhost:${PORT}`);
});
