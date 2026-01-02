 
// server.js — STAK Webinar + Admin Dashboard (glass) + RBAC + Live metrics + QoS
//
// install:
//   npm i express ws bcrypt jsonwebtoken
//
// run:
//   node server.js
//
// env optional:
//   set PORT=3000
//   set JWT_SECRET=change_me
//   set SUPERADMIN_USER=Admin
//   set SUPERADMIN_PASS=StrongPass123!
//   set SUPERADMIN_EMAIL=admin@corp.local
//   set SUPERADMIN_NICK=Administrator
//
// open:
//   http://localhost:3000          (login/menu)
//   http://localhost:3000/admin    (admin dashboard, only admin roles)

const express = require("express");
const fs = require("fs");
const path = require("path");
const http = require("http");
const WebSocket = require("ws");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json({ limit: "2mb" }));

const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET || "CHANGE_ME_SUPER_SECRET";
const DB_FILE = path.join(__dirname, "database.json");

// ---------------- DB ----------------
function initDB() {
  if (!fs.existsSync(DB_FILE)) {
    fs.writeFileSync(
      DB_FILE,
      JSON.stringify(
        {
          users: [],
          logs: [],
          meetings: [], // history
          chat: [], // {meetingId, time, from, text, deletedAt, deletedBy}
        },
        null,
        2
      )
    );
  }
}
initDB();

const db = {
  read: () => JSON.parse(fs.readFileSync(DB_FILE, "utf-8")),
  write: (data) => fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2)),
  log: (actor, action, meta = {}) => {
    const data = db.read();
    data.logs.push({ time: new Date().toISOString(), actor, action, meta });
    if (data.logs.length > 5000) data.logs = data.logs.slice(-4000);
    db.write(data);
  },
};

// ---------------- RBAC ----------------
// roles: superadmin > dept_admin > moderator > employee > guest
const ROLE_LEVEL = {
  guest: 1,
  employee: 2,
  moderator: 3,
  dept_admin: 4,
  superadmin: 5,
};

function canAtLeast(role, required) {
  return (ROLE_LEVEL[role] || 0) >= (ROLE_LEVEL[required] || 0);
}

// ---------------- AUTH helpers ----------------
function signToken(user) {
  return jwt.sign(
    {
      username: user.username,
      role: user.role,
      nickname: user.nickname || "",
      email: user.email || "",
      deptId: user.deptId || "",
      twofa: !!user.twofaEnabled,
    },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}
function verifyToken(token) {
  return jwt.verify(token, JWT_SECRET);
}
function authMiddleware(req, res, next) {
  const hdr = req.headers.authorization || "";
  const token = hdr.startsWith("Bearer ") ? hdr.slice(7) : "";
  if (!token) return res.status(401).json({ error: "Unauthorized" });
  try {
    req.user = verifyToken(token);
    next();
  } catch {
    return res.status(401).json({ error: "Unauthorized" });
  }
}
function requireRole(minRole) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: "Unauthorized" });
    if (!canAtLeast(req.user.role, minRole)) return res.status(403).json({ error: "Access Denied" });
    next();
  };
}

function normalizeEmail(e) {
  return String(e || "").trim().toLowerCase();
}
function normalizeUsername(u) {
  return String(u || "").trim();
}
function normalizeNickname(n) {
  return String(n || "").trim();
}
function isEmailValid(e) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);
}
function genRoomId() {
  return "WEB-" + Math.random().toString(36).slice(2, 8).toUpperCase();
}

// ---------------- Default SUPERADMIN ----------------
async function ensureSuperadmin() {
  const SU = normalizeUsername(process.env.SUPERADMIN_USER || "Borat1");
  const SP = String(process.env.SUPERADMIN_PASS || "Admin@2026!");
  const SE = normalizeEmail(process.env.SUPERADMIN_EMAIL || "admin@local");
  const SN = normalizeNickname(process.env.SUPERADMIN_NICK || "Administrator");

  const data = db.read();
  const exists = data.users.find((u) => u.username === SU);
  if (!exists) {
    const passwordHash = await bcrypt.hash(SP, 12);
    data.users.push({
      username: SU,
      passwordHash,
      role: "superadmin",
      email: SE,
      nickname: SN,
      deptId: "HQ",
      created: new Date().toISOString(),
      twofaEnabled: false,
    });
    db.write(data);
    db.log(SU, "Superadmin created", { username: SU, email: SE });
    console.log(`[SUPERADMIN CREATED] login=${SU} password=${SP}`);
  }
}
ensureSuperadmin().catch(() => {});

// ---------------- Meetings runtime state ----------------
// rooms map: roomId -> roomState
// roomState: {createdAt, type, deptId, flags, members Map, qosAgg}
const rooms = new Map();
let sockSeq = 0;

function getRoom(roomId) {
  if (!rooms.has(roomId)) {
    rooms.set(roomId, {
      roomId,
      createdAt: new Date().toISOString(),
      type: "webinar", // default, can be edited later
      deptId: "HQ",
      flags: {
        locked: false,
        quiet: false,
        chatEnabled: true,
        micPolicy: "free", // free | moderator_only
        camPolicy: "free", // free | off_by_default
      },
      members: new Map(), // socketId -> member
      // qos aggregated buckets (rolling)
      qosAgg: {
        lastUpdate: 0,
        rttSum: 0,
        rttN: 0,
        lossSum: 0,
        lossN: 0,
      },
      // meeting start/stop tracking
      startedAt: null, // when participants>=2 first time
      endedAt: null,
    });
  }
  return rooms.get(roomId);
}

function safeSend(ws, obj) {
  if (!ws || ws.readyState !== WebSocket.OPEN) return;
  ws.send(JSON.stringify(obj));
}

function snapshotMembers(roomId) {
  const room = rooms.get(roomId);
  if (!room) return [];
  return Array.from(room.members.entries()).map(([socketId, m]) => ({
    socketId,
    username: m.username,
    nickname: m.nickname,
    role: m.role,
    deptId: m.deptId || "",
    mic: !!m.mic,
    cam: !!m.cam,
    screen: !!m.screen,
    joinedAt: m.joinedAt,
  }));
}

function broadcastRoom(roomId, payload, exceptSocketId = null) {
  const room = rooms.get(roomId);
  if (!room) return;
  for (const [sid, m] of room.members.entries()) {
    if (exceptSocketId && sid === exceptSocketId) continue;
    safeSend(m.ws, payload);
  }
}

function roomsSnapshot() {
  const out = [];
  for (const [roomId, room] of rooms.entries()) {
    out.push({
      roomId,
      createdAt: room.createdAt,
      type: room.type,
      deptId: room.deptId,
      flags: room.flags,
      count: room.members.size,
      startedAt: room.startedAt,
      qos: getRoomQos(room),
      members: snapshotMembers(roomId),
    });
  }
  out.sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)));
  return out;
}

function getRoomQos(room) {
  const rtt = room.qosAgg.rttN ? room.qosAgg.rttSum / room.qosAgg.rttN : null;
  const loss = room.qosAgg.lossN ? room.qosAgg.lossSum / room.qosAgg.lossN : null;
  return { avgRtt: rtt, avgLoss: loss };
}

function isLiveMeeting(room) {
  // считаем "meeting live" когда >=2 участника
  return room.members.size >= 2;
}

function updateMeetingStartStop(room) {
  // start
  if (!room.startedAt && room.members.size >= 2) {
    room.startedAt = new Date().toISOString();
    db.log("system", "Meeting started", { roomId: room.roomId });
  }
  // end (when 0 members)
  if (room.startedAt && room.members.size === 0) {
    room.endedAt = new Date().toISOString();
    // persist to history
    const data = db.read();
    data.meetings.push({
      roomId: room.roomId,
      type: room.type,
      deptId: room.deptId,
      createdAt: room.createdAt,
      startedAt: room.startedAt,
      endedAt: room.endedAt,
      flags: room.flags,
    });
    // trim meetings history
    if (data.meetings.length > 5000) data.meetings = data.meetings.slice(-4000);
    db.write(data);
    db.log("system", "Meeting ended", { roomId: room.roomId });
  }
}

// ---------------- API: AUTH ----------------
app.post("/api/auth", async (req, res) => {
  const { type } = req.body || {};

  if (type === "login") {
    const username = normalizeUsername(req.body.username);
    const password = String(req.body.password || "");

    if (username.length < 2) return res.status(400).json({ error: "Invalid username" });
    if (password.length < 2) return res.status(400).json({ error: "Invalid password" });

    const data = db.read();
    const user = data.users.find((x) => x.username === username);
    if (!user) return res.status(401).json({ error: "Invalid Credentials" });

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ error: "Invalid Credentials" });

    db.log(username, "Login success");
    return res.json({
      username: user.username,
      role: user.role,
      email: user.email || "",
      nickname: user.nickname || "",
      deptId: user.deptId || "",
      token: signToken(user),
    });
  }

  if (type === "signup") {
    const email = normalizeEmail(req.body.email);
    const nickname = normalizeNickname(req.body.nickname);
    const username = normalizeUsername(req.body.username);
    const password = String(req.body.password || "");
    const deptId = String(req.body.deptId || "HQ").trim();

    if (!isEmailValid(email)) return res.status(400).json({ error: "Invalid email" });
    if (nickname.length < 2) return res.status(400).json({ error: "Invalid nickname" });
    if (username.length < 2) return res.status(400).json({ error: "Invalid username" });
    if (password.length < 6) return res.status(400).json({ error: "Password must be at least 6 chars" });

    const data = db.read();
    if (data.users.find((u) => normalizeEmail(u.email) === email)) return res.status(400).json({ error: "Email already used" });
    if (data.users.find((u) => u.username === username)) return res.status(400).json({ error: "Username already used" });

    const passwordHash = await bcrypt.hash(password, 12);
    const user = {
      username,
      passwordHash,
      role: "employee",
      email,
      nickname,
      deptId,
      created: new Date().toISOString(),
      twofaEnabled: false,
    };
    data.users.push(user);
    db.write(data);

    db.log(username, "Signup success", { email, deptId });

    return res.json({
      username: user.username,
      role: user.role,
      email: user.email,
      nickname: user.nickname,
      deptId: user.deptId,
      token: signToken(user),
    });
  }

  return res.status(400).json({ error: "Unknown auth type" });
});

// ---------------- API: ADMIN USERS ----------------
app.get("/api/admin/users", authMiddleware, requireRole("dept_admin"), (req, res) => {
  const data = db.read();
  // dept_admin видит свой dept, superadmin видит всех
  const mineDept = req.user.deptId || "";
  const users = data.users
    .filter((u) => canAtLeast(req.user.role, "superadmin") || (u.deptId || "") === mineDept)
    .map((u) => ({
      username: u.username,
      email: u.email || "",
      nickname: u.nickname || "",
      role: u.role,
      deptId: u.deptId || "",
      created: u.created,
      twofaEnabled: !!u.twofaEnabled,
    }));
  res.json(users);
});

app.post("/api/admin/users", authMiddleware, requireRole("dept_admin"), async (req, res) => {
  const email = normalizeEmail(req.body.email);
  const nickname = normalizeNickname(req.body.nickname);
  const username = normalizeUsername(req.body.username);
  const password = String(req.body.password || "");
  let role = String(req.body.role || "employee");
  let deptId = String(req.body.deptId || req.user.deptId || "HQ").trim();

  if (!isEmailValid(email)) return res.status(400).json({ error: "Invalid email" });
  if (nickname.length < 2) return res.status(400).json({ error: "Invalid nickname" });
  if (username.length < 2) return res.status(400).json({ error: "Invalid username" });
  if (password.length < 6) return res.status(400).json({ error: "Password must be at least 6 chars" });

  // dept_admin не может создавать superadmin
  if (!["guest", "employee", "moderator", "dept_admin", "superadmin", "administrator"].includes(role)) role = "employee";
  if (!canAtLeast(req.user.role, "superadmin") && role === "superadmin") role = "dept_admin";

  // dept_admin создаёт только в своём dept
  if (!canAtLeast(req.user.role, "superadmin")) deptId = req.user.deptId || "HQ";

  // normalize "administrator" -> dept_admin (чтоб было красиво)
  if (role === "administrator") role = "dept_admin";

  const data = db.read();
  if (data.users.find((u) => normalizeEmail(u.email) === email)) return res.status(400).json({ error: "Email already used" });
  if (data.users.find((u) => u.username === username)) return res.status(400).json({ error: "Username already used" });

  const passwordHash = await bcrypt.hash(password, 12);
  data.users.push({
    username,
    passwordHash,
    role,
    email,
    nickname,
    deptId,
    created: new Date().toISOString(),
    twofaEnabled: false,
  });
  db.write(data);
  db.log(req.user.username, "Admin created user", { username, email, role, deptId });
  res.json({ ok: true });
});

app.patch("/api/admin/users/:username", authMiddleware, requireRole("dept_admin"), async (req, res) => {
  const uname = String(req.params.username || "").trim();
  const data = db.read();
  const u = data.users.find((x) => x.username === uname);
  if (!u) return res.status(404).json({ error: "User not found" });

  // dept_admin может править только свой dept (кроме superadmin)
  if (!canAtLeast(req.user.role, "superadmin") && (u.deptId || "") !== (req.user.deptId || "")) {
    return res.status(403).json({ error: "Access Denied" });
  }

  if (typeof req.body.role === "string") {
    let role = String(req.body.role);
    if (role === "administrator") role = "dept_admin";
    if (!["guest", "employee", "moderator", "dept_admin", "superadmin"].includes(role)) {
      return res.status(400).json({ error: "Invalid role" });
    }
    if (!canAtLeast(req.user.role, "superadmin") && role === "superadmin") role = u.role; // forbid
    u.role = role;
  }

  if (typeof req.body.nickname === "string") {
    const nn = normalizeNickname(req.body.nickname);
    if (nn.length < 2) return res.status(400).json({ error: "Invalid nickname" });
    u.nickname = nn;
  }

  if (typeof req.body.email === "string") {
    const em = normalizeEmail(req.body.email);
    if (!isEmailValid(em)) return res.status(400).json({ error: "Invalid email" });
    if (data.users.find((x) => x.username !== uname && normalizeEmail(x.email) === em)) {
      return res.status(400).json({ error: "Email already used" });
    }
    u.email = em;
  }

  if (typeof req.body.deptId === "string" && canAtLeast(req.user.role, "superadmin")) {
    u.deptId = String(req.body.deptId).trim() || "HQ";
  }

  if (typeof req.body.newPassword === "string" && req.body.newPassword.length) {
    const np = String(req.body.newPassword);
    if (np.length < 6) return res.status(400).json({ error: "Password must be at least 6 chars" });
    u.passwordHash = await bcrypt.hash(np, 12);
  }

  db.write(data);
  db.log(req.user.username, "Admin updated user", { username: uname });
  res.json({ ok: true });
});

app.delete("/api/admin/users/:username", authMiddleware, requireRole("dept_admin"), (req, res) => {
  const uname = String(req.params.username || "").trim();
  const data = db.read();
  const idx = data.users.findIndex((x) => x.username === uname);
  if (idx === -1) return res.status(404).json({ error: "User not found" });

  const target = data.users[idx];

  if (req.user.username === uname) return res.status(400).json({ error: "You cannot delete yourself" });

  // dept_admin only in own dept, superadmin all
  if (!canAtLeast(req.user.role, "superadmin") && (target.deptId || "") !== (req.user.deptId || "")) {
    return res.status(403).json({ error: "Access Denied" });
  }

  data.users.splice(idx, 1);
  db.write(data);
  db.log(req.user.username, "Admin deleted user", { username: uname });
  res.json({ ok: true });
});

// ---------------- API: ADMIN Logs / Meetings / Summary ----------------
app.get("/api/admin/logs", authMiddleware, requireRole("dept_admin"), (req, res) => {
  // dept_admin can see logs but you can filter by dept if needed
  res.json(db.read().logs);
});

app.get("/api/admin/meetings/history", authMiddleware, requireRole("dept_admin"), (req, res) => {
  const data = db.read();
  const mineDept = req.user.deptId || "";
  const items = data.meetings
    .filter((m) => canAtLeast(req.user.role, "superadmin") || (m.deptId || "") === mineDept)
    .slice()
    .reverse()
    .slice(0, 500);
  res.json(items);
});

app.get("/api/admin/meetings/active", authMiddleware, requireRole("dept_admin"), (req, res) => {
  const mineDept = req.user.deptId || "";
  const items = roomsSnapshot().filter((r) => (canAtLeast(req.user.role, "superadmin") || r.deptId === mineDept));
  res.json(items);
});

function computeSummaryForRole(reqUser) {
  const mineDept = reqUser.deptId || "";
  const allRooms = roomsSnapshot().filter((r) => canAtLeast(reqUser.role, "superadmin") || r.deptId === mineDept);

  // online users (unique usernames currently connected)
  const onlineUsersSet = new Set();
  let onlineEmployees = 0;
  let onlineGuests = 0;

  let activeRooms = 0;
  let liveMeetings = 0;

  const now = Date.now();
  const hourBuckets = Array(24).fill(0); // simplistic "load by hour": current members count aggregated by hour of day

  let rttSum = 0, rttN = 0;
  let lossSum = 0, lossN = 0;

  const liveList = [];

  for (const r of allRooms) {
    if (r.count > 0) activeRooms++;
    if (r.count >= 2) liveMeetings++;

    for (const m of r.members) {
      onlineUsersSet.add(m.username);
      const role = (m.role || "employee");
      if (role === "guest") onlineGuests++;
      else onlineEmployees++;
    }

    // peak buckets: add current member count into current hour (rough MVP)
    const h = new Date().getHours();
    hourBuckets[h] += r.count;

    // qos
    if (r.qos && typeof r.qos.avgRtt === "number") { rttSum += r.qos.avgRtt; rttN++; }
    if (r.qos && typeof r.qos.avgLoss === "number") { lossSum += r.qos.avgLoss; lossN++; }

    // live list
    if (r.count >= 2) {
      const durSec = r.startedAt ? Math.max(0, Math.floor((Date.parse(new Date().toISOString()) - Date.parse(r.startedAt)) / 1000)) : 0;
      liveList.push({
        roomId: r.roomId,
        type: r.type,
        deptId: r.deptId,
        count: r.count,
        startedAt: r.startedAt,
        durationSec: durSec,
        flags: r.flags,
        qos: r.qos,
      });
    }
  }

  // average duration last 24h from history
  const data = db.read();
  const since = now - 24 * 3600 * 1000;
  const hist = data.meetings
    .filter((m) => (canAtLeast(reqUser.role, "superadmin") || (m.deptId || "") === mineDept))
    .filter((m) => m.endedAt && Date.parse(m.endedAt) >= since);

  let durSum = 0, durCount = 0;
  for (const m of hist) {
    const s = Date.parse(m.startedAt || m.createdAt || m.endedAt);
    const e = Date.parse(m.endedAt);
    if (Number.isFinite(s) && Number.isFinite(e) && e > s) { durSum += (e - s); durCount++; }
  }
  const avgDurationSec = durCount ? Math.round((durSum / durCount) / 1000) : 0;

  // peak hour (max bucket)
  let peakHour = 0, peakValue = -1;
  for (let i = 0; i < 24; i++) {
    if (hourBuckets[i] > peakValue) { peakValue = hourBuckets[i]; peakHour = i; }
  }

  return {
    onlineNow: onlineUsersSet.size,
    onlineEmployees,
    onlineGuests,
    activeRooms,
    liveMeetings,
    avgDurationSec24h: avgDurationSec,
    peakHour,
    peakValue,
    qos: {
      avgRtt: rttN ? (rttSum / rttN) : null,
      avgLoss: lossN ? (lossSum / lossN) : null,
    },
    liveList: liveList.sort((a, b) => (b.count - a.count)).slice(0, 20),
    hourBuckets,
  };
}

app.get("/api/admin/summary", authMiddleware, requireRole("dept_admin"), (req, res) => {
  res.json(computeSummaryForRole(req.user));
});

// ---------------- ROUTES (UI) ----------------
app.get("/", (req, res) => res.send(renderHomeHTML()));
app.get("/room/:id", (req, res) => {
  const roomId = String(req.params.id || "").toUpperCase().replace(/[^A-Z0-9-]/g, "");
  res.send(renderRoomHTML(roomId));
});
app.get("/admin", (req, res) => res.send(renderAdminHTML()));

// ---------------- WS signaling + control + QoS ----------------
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

function broadcastAdmins(payload) {
  // send to all online dept_admin/superadmin
  for (const [roomId, room] of rooms.entries()) {
    for (const [sid, m] of room.members.entries()) {
      if (canAtLeast(m.role, "dept_admin")) safeSend(m.ws, payload);
    }
  }
}

wss.on("connection", (ws, req) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const roomId = String(url.searchParams.get("room") || "").toUpperCase();
  const token = String(url.searchParams.get("token") || "");
  const as = String(url.searchParams.get("as") || "room"); // room | admin

  if (!token) return ws.close(1008, "Auth required");

  let user;
  try {
    user = verifyToken(token);
  } catch {
    return ws.close(1008, "Invalid token");
  }

  // admin socket can connect without roomId (for dashboard live updates)
  if (as === "admin") {
    if (!canAtLeast(user.role, "dept_admin")) return ws.close(1008, "Access denied");
    // send periodic admin snapshots
    safeSend(ws, { t: "admin-hello", you: user });
    const tick = setInterval(() => {
      safeSend(ws, { t: "admin-live", summary: computeSummaryForRole(user), rooms: roomsSnapshot() });
    }, 2000);

    ws.on("close", () => clearInterval(tick));
    ws.on("message", (buf) => {
      let msg; try { msg = JSON.parse(buf.toString("utf-8")); } catch { return; }
      // allow admin actions from dashboard too
      if (msg.t === "admin-action") {
        // reuse action handler below by creating a faux call
        handleAdminAction(user, msg);
      }
    });
    return;
  }

  // room socket requires roomId
  if (!roomId) return ws.close(1008, "Room required");

  const socketId = "S" + (++sockSeq).toString(36).toUpperCase();
  const room = getRoom(roomId);

  // apply dept restrictions for dept_admin (optional strict policy)
  // in MVP we allow joining any room; you can enforce dept later

  room.members.set(socketId, {
    ws,
    username: user.username,
    nickname: user.nickname || user.username,
    role: user.role,
    deptId: user.deptId || "",
    mic: true,
    cam: true,
    screen: false,
    joinedAt: new Date().toISOString(),
  });

  updateMeetingStartStop(room);

  db.log(user.username, "WS join", { roomId, socketId });

  safeSend(ws, {
    t: "welcome",
    socketId,
    roomId,
    you: { username: user.username, nickname: user.nickname || user.username, role: user.role, deptId: user.deptId || "" },
    roomFlags: room.flags,
    members: snapshotMembers(roomId),
  });

  broadcastRoom(
    roomId,
    {
      t: "peer-joined",
      peer: {
        socketId,
        username: user.username,
        nickname: user.nickname || user.username,
        role: user.role,
        deptId: user.deptId || "",
        mic: true,
        cam: true,
        screen: false,
      },
    },
    socketId
  );

  // update admins
  broadcastAdmins({ t: "admin-rooms", rooms: roomsSnapshot() });

  ws.on("message", (buf) => {
    let msg;
    try { msg = JSON.parse(buf.toString("utf-8")); } catch { return; }

    // Presence updates
    if (msg.t === "presence") {
      const me = room.members.get(socketId);
      if (!me) return;
      if (typeof msg.mic === "boolean") me.mic = msg.mic;
      if (typeof msg.cam === "boolean") me.cam = msg.cam;
      if (typeof msg.screen === "boolean") me.screen = msg.screen;

      broadcastRoom(roomId, { t: "peer-presence", socketId, mic: me.mic, cam: me.cam, screen: me.screen }, socketId);
      broadcastAdmins({ t: "admin-rooms", rooms: roomsSnapshot() });
      return;
    }

    // QoS: {t:"qos", rttMs, lossPct}
    if (msg.t === "qos") {
      const rttMs = Number(msg.rttMs);
      const lossPct = Number(msg.lossPct);
      if (Number.isFinite(rttMs) && rttMs >= 0 && rttMs < 5000) {
        room.qosAgg.rttSum += rttMs;
        room.qosAgg.rttN += 1;
      }
      if (Number.isFinite(lossPct) && lossPct >= 0 && lossPct <= 100) {
        room.qosAgg.lossSum += lossPct;
        room.qosAgg.lossN += 1;
      }
      room.qosAgg.lastUpdate = Date.now();
      return;
    }

    // Chat: respect room flag
    if (msg.t === "chat") {
      if (!room.flags.chatEnabled) return;
      const text = String(msg.text || "").slice(0, 4000).trim();
      if (!text) return;
      broadcastRoom(roomId, {
        t: "chat",
        from: { socketId, username: user.username, nickname: user.nickname || user.username },
        time: new Date().toISOString(),
        text,
      });

      // persist
      const data = db.read();
      data.chat.push({ meetingId: roomId, time: new Date().toISOString(), from: user.username, text });
      if (data.chat.length > 20000) data.chat = data.chat.slice(-15000);
      db.write(data);
      return;
    }

    // WebRTC signaling
    if (msg.t === "signal") {
      const to = String(msg.to || "");
      const target = room.members.get(to);
      if (!target) return;
      safeSend(target.ws, { t: "signal", from: socketId, data: msg.data });
      return;
    }

    // Admin actions from inside room (moderator+)
    if (msg.t === "admin-action") {
      handleAdminAction(user, { ...msg, roomId: msg.roomId || roomId, fromSocketId: socketId });
      return;
    }
  });

  ws.on("close", () => {
    const r = rooms.get(roomId);
    if (!r) return;
    const m = r.members.get(socketId);
    r.members.delete(socketId);

    if (m) db.log(m.username, "WS leave", { roomId, socketId });

    broadcastRoom(roomId, { t: "peer-left", socketId });
    updateMeetingStartStop(r);

    if (r.members.size === 0) rooms.delete(roomId);

    broadcastAdmins({ t: "admin-rooms", rooms: roomsSnapshot() });
  });
});

function handleAdminAction(user, msg) {
  // allowed: moderator+ within room, dept_admin+ cross-room, superadmin all
  const action = String(msg.action || "");
  const anyRoomId = String(msg.roomId || "").toUpperCase();
  const targetRoom = rooms.get(anyRoomId);

  // dashboard refresh
  if (action === "refresh-rooms") {
    broadcastAdmins({ t: "admin-rooms", rooms: roomsSnapshot() });
    return;
  }
  if (!targetRoom) return;

  // room-level controls require moderator+ if it's same room; dept_admin+ for cross-room
  const crossRoom = (msg.fromRoomId && msg.fromRoomId !== anyRoomId);
  if (crossRoom && !canAtLeast(user.role, "dept_admin")) return;

  // end room (dept_admin+)
  if (action === "end-room") {
    if (!canAtLeast(user.role, "dept_admin")) return;
    for (const [sid, m] of targetRoom.members.entries()) {
      safeSend(m.ws, { t: "room-ended", by: user.username });
      try { m.ws.close(4002, "Room ended"); } catch {}
    }
    rooms.delete(anyRoomId);
    db.log(user.username, "Admin end room", { roomId: anyRoomId });
    broadcastAdmins({ t: "admin-rooms", rooms: roomsSnapshot() });
    return;
  }

  // flags
  if (action === "toggle-chat") {
    if (!canAtLeast(user.role, "moderator")) return;
    targetRoom.flags.chatEnabled = !!msg.value;
    broadcastRoom(anyRoomId, { t: "room-flags", flags: targetRoom.flags, by: user.username });
    db.log(user.username, "Room flag chat", { roomId: anyRoomId, value: targetRoom.flags.chatEnabled });
    broadcastAdmins({ t: "admin-rooms", rooms: roomsSnapshot() });
    return;
  }
  if (action === "toggle-lock") {
    if (!canAtLeast(user.role, "moderator")) return;
    targetRoom.flags.locked = !!msg.value;
    broadcastRoom(anyRoomId, { t: "room-flags", flags: targetRoom.flags, by: user.username });
    db.log(user.username, "Room flag lock", { roomId: anyRoomId, value: targetRoom.flags.locked });
    broadcastAdmins({ t: "admin-rooms", rooms: roomsSnapshot() });
    return;
  }
  if (action === "toggle-quiet") {
    if (!canAtLeast(user.role, "moderator")) return;
    targetRoom.flags.quiet = !!msg.value;
    // if quiet on -> force mute all
    if (targetRoom.flags.quiet) {
      for (const [sid, m] of targetRoom.members.entries()) {
        m.mic = false;
        safeSend(m.ws, { t: "force", what: "mic", value: false, by: user.username });
        broadcastRoom(anyRoomId, { t: "peer-presence", socketId: sid, mic: false, cam: m.cam, screen: m.screen });
      }
    }
    broadcastRoom(anyRoomId, { t: "room-flags", flags: targetRoom.flags, by: user.username });
    db.log(user.username, "Room flag quiet", { roomId: anyRoomId, value: targetRoom.flags.quiet });
    broadcastAdmins({ t: "admin-rooms", rooms: roomsSnapshot() });
    return;
  }

  const targetId = String(msg.targetSocketId || "");
  if (!targetId) return;
  const tMember = targetRoom.members.get(targetId);
  if (!tMember) return;

  // kick / force mute / force camoff require moderator+
  if (!canAtLeast(user.role, "moderator")) return;

  if (action === "kick") {
    safeSend(tMember.ws, { t: "kicked", by: user.username });
    try { tMember.ws.close(4001, "Kicked"); } catch {}
    db.log(user.username, "Kick", { roomId: anyRoomId, target: targetId });
    broadcastAdmins({ t: "admin-rooms", rooms: roomsSnapshot() });
    return;
  }
  if (action === "force-mute") {
    tMember.mic = false;
    safeSend(tMember.ws, { t: "force", what: "mic", value: false, by: user.username });
    broadcastRoom(anyRoomId, { t: "peer-presence", socketId: targetId, mic: false, cam: tMember.cam, screen: tMember.screen });
    db.log(user.username, "Force mute", { roomId: anyRoomId, target: targetId });
    broadcastAdmins({ t: "admin-rooms", rooms: roomsSnapshot() });
    return;
  }
  if (action === "force-camoff") {
    tMember.cam = false;
    safeSend(tMember.ws, { t: "force", what: "cam", value: false, by: user.username });
    broadcastRoom(anyRoomId, { t: "peer-presence", socketId: targetId, mic: tMember.mic, cam: false, screen: tMember.screen });
    db.log(user.username, "Force camoff", { roomId: anyRoomId, target: targetId });
    broadcastAdmins({ t: "admin-rooms", rooms: roomsSnapshot() });
    return;
  }
}

// ---------------- HOME UI ----------------
function renderHomeHTML() {
  return `<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no"/>
<title>STAK Webinar</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@200;300;400;500&display=swap" rel="stylesheet">
<style>
:root{--bg:#050505;--panel:rgba(255,255,255,.05);--border:rgba(255,255,255,.12);--txt:rgba(255,255,255,.92);--dim:rgba(255,255,255,.55);--r:18px;--shadow:0 20px 60px rgba(0,0,0,.45);--danger:#ff3b3b}
*{margin:0;padding:0;box-sizing:border-box;-webkit-font-smoothing:antialiased}
body{height:100vh;background:var(--bg);color:var(--txt);font-family:Inter,system-ui,Arial;overflow:hidden}
canvas{position:fixed;inset:0;z-index:-1;pointer-events:none}
.glass{background:var(--panel);border:1px solid var(--border);backdrop-filter:blur(18px);-webkit-backdrop-filter:blur(18px);border-radius:var(--r);box-shadow:var(--shadow)}
.wrap{position:fixed;inset:0;display:flex;align-items:center;justify-content:center;padding:16px}
.card{width:min(560px,94vw);padding:18px}
.head{display:flex;align-items:center;justify-content:space-between;margin-bottom:14px}
.logo{letter-spacing:.35em;font-weight:300}
.pill{border:1px solid var(--border);border-radius:999px;padding:8px 10px;font-size:11px;color:var(--dim);letter-spacing:.12em;text-transform:uppercase}
.btn{background:transparent;border:1px solid var(--border);color:var(--txt);padding:14px 14px;border-radius:14px;cursor:pointer;transition:.18s;user-select:none;touch-action:manipulation}
.btn:hover{border-color:rgba(255,255,255,.24);transform:translateY(-1px)}
.btn:active{transform:translateY(0);opacity:.92}
.btn.primary{border-color:rgba(255,255,255,.35)}
.btn.danger{border-color:rgba(255,59,59,.7);color:var(--danger)}
.input{width:100%;padding:14px;border-radius:14px;border:1px solid var(--border);background:rgba(0,0,0,.25);color:var(--txt);outline:none}
.input:focus{border-color:rgba(255,255,255,.25)}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.sep{height:1px;background:rgba(255,255,255,.08);margin:14px 0}
.small{font-size:12px;color:var(--dim);margin-top:10px}
.menu{display:none}
.form{display:none}
.row{margin-top:10px}
@media(max-width:520px){.grid2{grid-template-columns:1fr}}
</style>
</head>
<body>
<canvas id="stars"></canvas>

<div class="wrap">
  <div class="card glass">
    <div class="head">
      <div class="logo">STAK WEBINAR</div>
      <div class="pill" id="statusP">READY</div>
    </div>

    <div id="authView">
      <div class="grid2">
        <input id="loginUser" class="input" placeholder="Логин" autocomplete="username"/>
        <input id="loginPass" class="input" placeholder="Пароль" type="password" autocomplete="current-password"/>
      </div>
      <div class="grid2" style="margin-top:10px">
        <button class="btn primary" onclick="doLogin()">Войти</button>
        <button class="btn" onclick="showRegister()">Регистрация</button>
      </div>
      <div class="small" style="opacity:.7">Админ-панель: <span style="color:rgba(255,255,255,.85)">/admin</span> (доступ только ролям dept_admin/superadmin)</div>
    </div>

    <div id="registerView" class="form">
      <div class="grid2">
        <input id="regEmail" class="input" placeholder="Email"/>
        <input id="regNick" class="input" placeholder="Nickname"/>
      </div>
      <div class="grid2" style="margin-top:10px">
        <input id="regDept" class="input" placeholder="Отдел (например HQ)"/>
        <input id="regUser" class="input" placeholder="Username (логин)"/>
      </div>
      <div class="row">
        <input id="regPass" class="input" placeholder="Password (мин 6)" type="password"/>
      </div>
      <div class="grid2" style="margin-top:10px">
        <button class="btn primary" onclick="doRegister()">Создать</button>
        <button class="btn" onclick="backToLogin()">Назад</button>
      </div>
    </div>

    <div class="sep"></div>

    <div id="menuView" class="menu">
      <div class="pill" id="meP">/ USER</div>
      <div class="row" style="margin-top:12px">
        <button class="btn primary" style="width:100%" onclick="createWebinar()">Создать вебинар</button>
      </div>
      <div class="row">
        <button class="btn" style="width:100%" onclick="joinWebinar()">Присоединиться к вебинару</button>
      </div>
      <div class="row" id="adminRow" style="display:none">
        <button class="btn" style="width:100%" onclick="location.href='/admin'">Админ-панель</button>
      </div>
      <div class="row">
        <button class="btn danger" style="width:100%" onclick="logout()">Выйти</button>
      </div>
    </div>

  </div>
</div>

<script>
let session=null;
function setStatus(s){document.getElementById("statusP").textContent=s;}

function showRegister(){
  document.getElementById("authView").style.display="none";
  document.getElementById("registerView").style.display="block";
  document.getElementById("menuView").style.display="none";
}
function backToLogin(){
  document.getElementById("authView").style.display="block";
  document.getElementById("registerView").style.display="none";
  document.getElementById("menuView").style.display="none";
}

async function doLogin(){
  const username=(document.getElementById("loginUser").value||"").trim();
  const password=(document.getElementById("loginPass").value||"");
  if(!username||!password) return alert("Заполни логин и пароль");
  setStatus("LOGIN...");
  const r=await fetch("/api/auth",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({type:"login",username,password})});
  const data=await r.json();
  if(!r.ok){setStatus("READY"); return alert(data.error||"Ошибка");}
  session=data;
  localStorage.setItem("stak_token", session.token);
  localStorage.setItem("stak_role", session.role);
  showMenu();
}

async function doRegister(){
  const email=(document.getElementById("regEmail").value||"").trim();
  const nickname=(document.getElementById("regNick").value||"").trim();
  const deptId=(document.getElementById("regDept").value||"HQ").trim();
  const username=(document.getElementById("regUser").value||"").trim();
  const password=(document.getElementById("regPass").value||"");
  if(!email||!nickname||!username||!password) return alert("Заполни все поля");
  setStatus("SIGNUP...");
  const r=await fetch("/api/auth",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({type:"signup",email,nickname,deptId,username,password})});
  const data=await r.json();
  if(!r.ok){setStatus("READY"); return alert(data.error||"Ошибка");}
  session=data;
  localStorage.setItem("stak_token", session.token);
  localStorage.setItem("stak_role", session.role);
  showMenu();
}

function showMenu(){
  setStatus("ONLINE");
  document.getElementById("authView").style.display="none";
  document.getElementById("registerView").style.display="none";
  document.getElementById("menuView").style.display="block";
  document.getElementById("meP").textContent="/ "+(session.nickname||session.username)+" • "+(session.role||"").toUpperCase();
  const role=(session.role||"");
  document.getElementById("adminRow").style.display = (role==="dept_admin"||role==="superadmin") ? "block":"none";
}

function createWebinar(){
  const id="WEB-"+Math.random().toString(36).slice(2,8).toUpperCase();
  localStorage.setItem("last_room", id);
  location.href="/room/"+encodeURIComponent(id);
}
function joinWebinar(){
  const last=localStorage.getItem("last_room")||"";
  const id=prompt("Введите ID вебинара", last);
  if(!id) return;
  const clean=String(id).toUpperCase().replace(/[^A-Z0-9-]/g,"");
  localStorage.setItem("last_room", clean);
  location.href="/room/"+encodeURIComponent(clean);
}
function logout(){
  localStorage.removeItem("stak_token");
  localStorage.removeItem("stak_role");
  session=null;
  backToLogin();
  setStatus("READY");
}

// stars
const canvas=document.getElementById("stars");
const ctx=canvas.getContext("2d");
let stars=[];
function initStars(){canvas.width=innerWidth;canvas.height=innerHeight;stars=Array(200).fill().map(()=>({x:Math.random()*canvas.width,y:Math.random()*canvas.height,z:Math.random()*canvas.width,o:Math.random()}));}
function drawStars(){ctx.clearRect(0,0,canvas.width,canvas.height);for(const s of stars){const x=(s.x-canvas.width/2)*(canvas.width/s.z)+canvas.width/2;const y=(s.y-canvas.height/2)*(canvas.width/s.z)+canvas.height/2;const size=(1-s.z/canvas.width)*2.2;ctx.fillStyle=\`rgba(255,255,255,\${s.o*(1-s.z/canvas.width)})\`;ctx.beginPath();ctx.arc(x,y,size,0,Math.PI*2);ctx.fill();s.z-=0.55;if(s.z<=0)s.z=canvas.width;}requestAnimationFrame(drawStars);}
addEventListener("resize",initStars);initStars();drawStars();
</script>
</body>
</html>`;
}

// ---------------- ROOM UI (WebRTC + QoS + moderator controls) ----------------
function renderRoomHTML(roomId) {
  roomId = String(roomId || "").toUpperCase().replace(/[^A-Z0-9-]/g, "");
  const ROOM_ID = roomId;

  return `<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no"/>
<title>Room ${roomId}</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@200;300;400;500&display=swap" rel="stylesheet">
<style>
:root{--bg:#050505;--panel:rgba(255,255,255,0.04);--panel2:rgba(0,0,0,0.35);--border:rgba(255,255,255,0.10);--txt:rgba(255,255,255,0.92);--dim:rgba(255,255,255,0.55);--danger:#ff3b3b;--ok:rgba(120,255,170,0.9);--shadow:0 20px 60px rgba(0,0,0,0.45);--r:18px}
*{margin:0;padding:0;box-sizing:border-box;-webkit-font-smoothing:antialiased}
body{height:100vh;background:var(--bg);color:var(--txt);font-family:Inter,system-ui,Arial;overflow:hidden}
canvas{position:fixed;inset:0;z-index:-1;pointer-events:none}
.glass{background:var(--panel);border:1px solid var(--border);backdrop-filter:blur(18px);-webkit-backdrop-filter:blur(18px);border-radius:var(--r);box-shadow:var(--shadow)}
.btn{background:transparent;border:1px solid var(--border);color:var(--txt);padding:12px 14px;border-radius:14px;cursor:pointer;transition:.18s;user-select:none;touch-action:manipulation}
.btn:hover{transform:translateY(-1px);border-color:rgba(255,255,255,.22)}
.btn:active{transform:translateY(0);opacity:.9}
.btn.primary{border-color:rgba(255,255,255,.35)}
.btn.danger{border-color:rgba(255,59,59,.7);color:var(--danger)}
.btn.ok{border-color:rgba(120,255,170,.55);color:var(--ok)}
.btn.muted{opacity:.55}
.pill{border:1px solid var(--border);border-radius:999px;padding:8px 10px;font-size:11px;color:var(--dim);letter-spacing:.12em;text-transform:uppercase;white-space:nowrap}
.pill strong{color:var(--txt);font-weight:500}
#gate{position:fixed;inset:0;display:flex;align-items:center;justify-content:center;padding:18px}
.gateCard{width:min(560px,94vw);padding:18px}
.sep{height:1px;background:rgba(255,255,255,.08);margin:14px 0}
.small{font-size:12px;color:var(--dim);margin-top:10px}
#app{display:none;height:100vh}
.topbar{height:56px;display:flex;align-items:center;justify-content:space-between;padding:10px 12px;border-bottom:1px solid var(--border);background:var(--panel2)}
.topLeft{display:flex;gap:8px;align-items:center;overflow:hidden}
.topRight{display:flex;gap:8px;align-items:center}
#grid{height:calc(100vh - 56px - 74px);display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:2px;padding:2px;background:#000}
.tile{position:relative;background:#0b0b0b;border-radius:16px;overflow:hidden}
.tile video{width:100%;height:100%;object-fit:cover;background:#000}
.tag{position:absolute;left:10px;bottom:10px;padding:6px 10px;border-radius:999px;border:1px solid rgba(255,255,255,0.08);background:rgba(0,0,0,0.38);color:rgba(255,255,255,0.85);font-size:11px;letter-spacing:.12em;text-transform:uppercase}
.status{position:absolute;right:10px;top:10px;padding:6px 10px;border-radius:999px;border:1px solid rgba(255,255,255,0.08);background:rgba(0,0,0,0.38);color:var(--dim);font-size:11px;letter-spacing:.10em;text-transform:uppercase}
.bottom{height:74px;display:flex;align-items:center;justify-content:center;gap:10px;padding:10px 12px;border-top:1px solid var(--border);background:rgba(0,0,0,0.55)}
.drawer{position:fixed;top:0;right:0;height:100vh;width:min(380px,100vw);transform:translateX(110%);transition:transform .22s ease;z-index:50;border-radius:0}
.drawer.open{transform:translateX(0)}
.drawerHead{height:56px;display:flex;align-items:center;justify-content:space-between;padding:10px 12px;border-bottom:1px solid var(--border);background:rgba(0,0,0,0.35)}
.drawerBody{height:calc(100vh - 56px - 58px);overflow:auto;padding:12px}
.drawerFoot{height:58px;border-top:1px solid var(--border);display:flex;gap:8px;padding:10px;background:rgba(0,0,0,0.35)}
.input{width:100%;padding:14px;border-radius:14px;border:1px solid var(--border);background:rgba(0,0,0,.25);color:var(--txt);outline:none}
.input:focus{border-color:rgba(255,255,255,.25)}
.item{border-bottom:1px solid rgba(255,255,255,0.08);padding:10px 0;font-size:13px;color:var(--dim);display:flex;align-items:flex-start;justify-content:space-between;gap:10px}
.item strong{color:var(--txt);font-weight:500}
.actions{display:flex;gap:8px;flex-wrap:wrap;justify-content:flex-end}
.msg{border:1px solid rgba(255,255,255,0.08);border-radius:14px;padding:10px;background:rgba(255,255,255,0.02);margin-bottom:10px}
.msg .m1{display:flex;justify-content:space-between;font-size:11px;color:rgba(255,255,255,0.35);letter-spacing:.10em;text-transform:uppercase}
.msg .m2{margin-top:6px;font-size:13px;color:rgba(255,255,255,0.86);white-space:pre-wrap}
@media (max-width:520px){.topRight .pill{display:none} #grid{grid-template-columns:1fr} .bottom{gap:8px}}
</style>
</head>
<body>
<canvas id="stars"></canvas>

<section id="gate">
  <div class="gateCard glass">
    <div style="display:flex;justify-content:space-between;align-items:center">
      <div class="pill">ROOM <strong>${roomId}</strong></div>
      <button class="btn" onclick="location.href='/'">Меню</button>
    </div>
    <div class="sep"></div>
    <div class="small">Для входа нужен токен (логин на главной).</div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:10px">
      <button class="btn primary" onclick="enterRoom()">Войти</button>
      <button class="btn" onclick="location.href='/'">Авторизация</button>
    </div>
  </div>
</section>

<section id="app">
  <div class="topbar">
    <div class="topLeft">
      <div class="pill">ROOM <strong>${roomId}</strong></div>
      <div class="pill" id="meP">/ INIT</div>
      <div class="pill" id="netP">NET <strong>—</strong></div>
      <div class="pill" id="qosP">QOS <strong>—</strong></div>
    </div>
    <div class="topRight">
      <button class="btn" onclick="copyLink()">Link</button>
      <button class="btn" onclick="toggleDrawer()">Panel</button>
      <button class="btn" id="modBtn" style="display:none" onclick="toggleModeration()">Moderation</button>
      <div class="pill">USERS <strong id="cntP">1</strong></div>
    </div>
  </div>

  <div id="grid">
    <div class="tile" id="tile-local">
      <video id="v-local" muted autoplay playsinline></video>
      <div class="tag" id="tag-local">YOU</div>
      <div class="status" id="st-local">—</div>
    </div>
  </div>

  <div class="bottom">
    <button class="btn" id="b-mic" onclick="toggleMic()">Mic</button>
    <button class="btn" id="b-cam" onclick="toggleCam()">Cam</button>
    <button class="btn ok" id="b-screen" onclick="toggleScreen()">Screen</button>
    <button class="btn" onclick="openChat()">Chat</button>
    <button class="btn danger" onclick="leave()">Leave</button>
  </div>
</section>

<aside id="drawer" class="drawer glass">
  <div class="drawerHead">
    <div class="pill">PANEL</div>
    <button class="btn" onclick="toggleDrawer()">Close</button>
  </div>

  <div class="drawerBody">
    <div class="pill" id="flagsP">FLAGS <strong>—</strong></div>
    <div style="height:10px"></div>
    <div id="peoplePane"></div>

    <div style="height:14px"></div>
    <div class="pill">CHAT</div>
    <div style="height:10px"></div>
    <div id="chatBox"></div>
  </div>

  <div class="drawerFoot">
    <input class="input" id="chatText" placeholder="Сообщение..." />
    <button class="btn primary" onclick="sendChat()">Send</button>
  </div>
</aside>

<script>
const ROOM_ID = "${ROOM_ID}";
let session=null;
let ws=null;
let myId=null;

let localStream=null, camStream=null, screenStream=null;
let micEnabled=true, camEnabled=true, screenEnabled=false;

const peers = new Map();

// TURN/STUN
const ICE_SERVERS = [{ urls: "stun:stun.l.google.com:19302" }];

function parseJWT(token){
  try{
    const p=token.split(".")[1];
    const json=atob(p.replace(/-/g,'+').replace(/_/g,'/'));
    return JSON.parse(json);
  }catch{ return null; }
}

async function enterRoom(){
  const token=localStorage.getItem("stak_token")||"";
  if(!token) return alert("Нет токена. Авторизуйся на главной.");
  const payload=parseJWT(token);
  if(!payload) return alert("Токен некорректный.");

  session={ username:payload.username, role:payload.role, nickname:payload.nickname||payload.username, deptId:payload.deptId||"", token };

  document.getElementById("gate").style.display="none";
  document.getElementById("app").style.display="block";
  document.getElementById("meP").innerHTML="/ <strong>"+(session.nickname||session.username).toUpperCase()+"</strong> • "+(session.role||"").toUpperCase();
  document.getElementById("tag-local").textContent=(session.nickname||session.username).toUpperCase();

  // show moderation button for moderator+
  const r=session.role||"";
  if (["moderator","dept_admin","superadmin"].includes(r)) document.getElementById("modBtn").style.display="inline-block";

  await startMedia();
  connectWS();
}

async function startMedia(){
  localStream = await navigator.mediaDevices.getUserMedia({ video:true, audio:true });
  camStream = localStream;
  const v=document.getElementById("v-local");
  v.srcObject=localStream;
  v.play().catch(()=>{});
  updateLocalUI();
}

function updateLocalUI(){
  document.getElementById("st-local").textContent =
    (micEnabled ? "MIC ON":"MIC OFF") + " • " + (camEnabled ? "CAM ON":"CAM OFF") + (screenEnabled ? " • SCREEN":"");
  document.getElementById("b-mic").classList.toggle("muted", !micEnabled);
  document.getElementById("b-cam").classList.toggle("muted", !camEnabled);
  document.getElementById("b-screen").classList.toggle("muted", !screenEnabled);
}

function setNet(s){ document.getElementById("netP").innerHTML="NET <strong>"+s+"</strong>"; }

function toggleMic(){
  micEnabled=!micEnabled;
  localStream.getAudioTracks().forEach(t=>t.enabled=micEnabled);
  updateLocalUI(); sendPresence();
}
function toggleCam(){
  camEnabled=!camEnabled;
  localStream.getVideoTracks().forEach(t=>t.enabled=camEnabled);
  updateLocalUI(); sendPresence();
}
async function toggleScreen(){
  if(!screenEnabled){
    try{ screenStream=await navigator.mediaDevices.getDisplayMedia({video:true,audio:false}); }
    catch{ return; }
    screenEnabled=true;
    const screenTrack=screenStream.getVideoTracks()[0];
    replaceVideoTrack(screenTrack);
    document.getElementById("v-local").srcObject = new MediaStream([screenTrack, ...localStream.getAudioTracks()]);
    screenTrack.onended=()=>{ if(screenEnabled) toggleScreen(); };
    updateLocalUI(); sendPresence();
  } else {
    screenEnabled=false;
    if(screenStream){ screenStream.getTracks().forEach(t=>t.stop()); screenStream=null; }
    const camTrack=camStream.getVideoTracks()[0];
    replaceVideoTrack(camTrack);
    document.getElementById("v-local").srcObject = localStream;
    updateLocalUI(); sendPresence();
  }
}
function replaceVideoTrack(newTrack){
  const old=localStream.getVideoTracks()[0];
  if(old) localStream.removeTrack(old);
  localStream.addTrack(newTrack);
  for(const {pc} of peers.values()){
    const sender=pc.getSenders().find(s=>s.track && s.track.kind==="video");
    if(sender) sender.replaceTrack(newTrack);
  }
}

function toggleDrawer(){
  const d=document.getElementById("drawer");
  d.classList.toggle("open");
}
function openChat(){
  document.getElementById("drawer").classList.add("open");
  setTimeout(()=>document.getElementById("chatText").focus(),60);
}

function connectWS(){
  const proto = location.protocol==="https:" ? "wss":"ws";
  ws = new WebSocket(\`\${proto}://\${location.host}/?room=\${encodeURIComponent(ROOM_ID)}&token=\${encodeURIComponent(session.token)}\`);
  ws.onopen = ()=> setNet("ONLINE");
  ws.onclose = ()=> setNet("OFFLINE");

  ws.onmessage = async (ev)=>{
    const msg = JSON.parse(ev.data);

    if(msg.t==="welcome"){
      myId = msg.socketId;
      setCount(msg.members.length);
      renderFlags(msg.roomFlags);
      renderPeople(msg.members);

      // lock policy: if room locked and you are not already in - server should enforce (MVP just UI)
      // initiate offers deterministically
      for(const m of msg.members){
        if(m.socketId===myId) continue;
        ensurePeer(m.socketId, m.nickname||m.username);
        if(shouldInitiate(myId, m.socketId)) await makeOffer(m.socketId);
      }

      sendPresence();
      startQoSLoop();
      return;
    }

    if(msg.t==="room-flags"){
      renderFlags(msg.flags);
      return;
    }

    if(msg.t==="peer-joined"){
      ensurePeer(msg.peer.socketId, msg.peer.nickname||msg.peer.username);
      addOrUpdatePerson(msg.peer);
      setCount(document.querySelectorAll("[data-person]").length);
      if(shouldInitiate(myId, msg.peer.socketId)) await makeOffer(msg.peer.socketId);
      return;
    }

    if(msg.t==="peer-left"){
      removePeer(msg.socketId);
      removePerson(msg.socketId);
      setCount(document.querySelectorAll("[data-person]").length);
      return;
    }

    if(msg.t==="peer-presence"){
      updatePersonPresence(msg.socketId, msg.mic, msg.cam, msg.screen);
      const st=document.getElementById("st_"+msg.socketId);
      if(st) st.textContent=statusText(msg.mic,msg.cam,msg.screen);
      return;
    }

    if(msg.t==="signal"){
      ensurePeer(msg.from, "REMOTE");
      await handleSignal(msg.from, msg.data);
      return;
    }

    if(msg.t==="chat"){ addChat(msg); return; }

    if(msg.t==="force"){
      if(msg.what==="mic"){
        micEnabled=!!msg.value;
        localStream.getAudioTracks().forEach(t=>t.enabled=micEnabled);
      }
      if(msg.what==="cam"){
        camEnabled=!!msg.value;
        localStream.getVideoTracks().forEach(t=>t.enabled=camEnabled);
      }
      updateLocalUI(); sendPresence();
      alert("Модератор ограничил: "+msg.what.toUpperCase());
      return;
    }

    if(msg.t==="kicked"){ alert("Вас исключили"); leave(); return; }
    if(msg.t==="room-ended"){ alert("Комната завершена"); leave(); return; }
  };
}

function sendPresence(){
  if(!ws || ws.readyState!==1) return;
  ws.send(JSON.stringify({t:"presence",mic:micEnabled,cam:camEnabled,screen:screenEnabled}));
}

function shouldInitiate(a,b){ return String(a) > String(b); }

// WebRTC
function ensurePeer(peerId,label){
  if(peers.has(peerId)) return;
  const pc = new RTCPeerConnection({ iceServers: ICE_SERVERS });
  localStream.getTracks().forEach(track=>pc.addTrack(track, localStream));
  pc.onicecandidate = (e)=>{ if(e.candidate) sendSignal(peerId,{type:"ice",candidate:e.candidate}); };
  pc.ontrack = (e)=>{ attachRemote(peerId, label, e.streams[0]); };
  peers.set(peerId,{pc,label,videoEl:null});
}
async function makeOffer(peerId){
  const p=peers.get(peerId); if(!p) return;
  const offer = await p.pc.createOffer({offerToReceiveAudio:true,offerToReceiveVideo:true});
  await p.pc.setLocalDescription(offer);
  sendSignal(peerId,{type:"offer",sdp:offer.sdp});
}
async function handleSignal(from,data){
  const p=peers.get(from); if(!p) return;
  const pc=p.pc;
  if(data.type==="offer"){
    await pc.setRemoteDescription({type:"offer",sdp:data.sdp});
    const ans=await pc.createAnswer();
    await pc.setLocalDescription(ans);
    sendSignal(from,{type:"answer",sdp:ans.sdp});
    return;
  }
  if(data.type==="answer"){
    await pc.setRemoteDescription({type:"answer",sdp:data.sdp});
    return;
  }
  if(data.type==="ice"){
    try{ await pc.addIceCandidate(data.candidate); }catch{}
  }
}
function sendSignal(to,data){
  if(!ws || ws.readyState!==1) return;
  ws.send(JSON.stringify({t:"signal",to,data}));
}
function attachRemote(peerId,label,stream){
  const existing=document.getElementById("v_"+peerId);
  if(existing){ existing.srcObject=stream; return; }
  const tile=document.createElement("div");
  tile.className="tile"; tile.id="tile_"+peerId;

  const v=document.createElement("video");
  v.id="v_"+peerId; v.autoplay=true; v.playsInline=true; v.srcObject=stream;

  const tag=document.createElement("div");
  tag.className="tag"; tag.textContent=(label||"REMOTE").toUpperCase();

  const st=document.createElement("div");
  st.className="status"; st.id="st_"+peerId; st.textContent="CONNECTED";

  tile.appendChild(v); tile.appendChild(tag); tile.appendChild(st);
  document.getElementById("grid").appendChild(tile);
}
function removePeer(peerId){
  const p=peers.get(peerId);
  if(p){ try{ p.pc.close(); }catch{} peers.delete(peerId); }
  const tile=document.getElementById("tile_"+peerId);
  if(tile) tile.remove();
}

// People + moderator buttons
function statusText(mic,cam,screen){
  const a = mic?"MIC":"MUTED";
  const b = cam?"CAM":"NO-CAM";
  const c = screen?"SCREEN":"";
  return a+" • "+b+(c?" • "+c:"");
}
function renderPeople(members){
  const pane=document.getElementById("peoplePane"); pane.innerHTML="";
  for(const m of members) addOrUpdatePerson(m);
}
function addOrUpdatePerson(m){
  const id=m.socketId;
  const pane=document.getElementById("peoplePane");
  const me=(id===myId);
  const name=(m.nickname||m.username||"USER");
  const role=String(m.role||"employee").toUpperCase();
  const pres=statusText(m.mic!==false,m.cam!==false,!!m.screen);

  const myRole=session.role||"";
  const canMod = ["moderator","dept_admin","superadmin"].includes(myRole);

  const modBtns = (canMod && !me) ? \`
    <div class="actions">
      <button class="btn danger" onclick="adminKick('\${id}','\${ROOM_ID}')">Kick</button>
      <button class="btn" onclick="adminForceMute('\${id}','\${ROOM_ID}')">Mute</button>
      <button class="btn" onclick="adminForceCamOff('\${id}','\${ROOM_ID}')">CamOff</button>
    </div>\` : "";

  const html=\`
    <div class="item" id="person_\${id}" data-person="1">
      <div>
        <div><strong>\${name}</strong> \${me?'<span style="opacity:.4">(YOU)</span>':''}</div>
        <div class="small" id="pres_\${id}" style="margin-top:4px">\${pres} • \${role}</div>
      </div>
      \${modBtns}
    </div>\`;

  const old=document.getElementById("person_"+id);
  if(old) old.outerHTML=html; else pane.insertAdjacentHTML("beforeend",html);
}
function removePerson(id){ const el=document.getElementById("person_"+id); if(el) el.remove(); }
function updatePersonPresence(id,mic,cam,screen){
  const el=document.getElementById("pres_"+id);
  if(el){
    const parts=el.textContent.split("•");
    const role=parts[parts.length-1].trim();
    el.textContent=statusText(mic,cam,screen)+" • "+role;
  }
}
function setCount(n){ document.getElementById("cntP").textContent=String(n); }

function renderFlags(flags){
  const f = flags || {};
  document.getElementById("flagsP").innerHTML = "FLAGS <strong>"+
    (f.locked ? "LOCK ":"")+
    (f.quiet ? "QUIET ":"")+
    (!f.chatEnabled ? "CHAT_OFF ":"")+
    "</strong>";
}

function sendChat(){
  const inp=document.getElementById("chatText");
  const text=(inp.value||"").trim();
  if(!text) return;
  inp.value="";
  if(!ws||ws.readyState!==1) return;
  ws.send(JSON.stringify({t:"chat",text}));
}
document.addEventListener("keydown",(e)=>{
  if(e.key==="Enter"){
    if(document.activeElement && document.activeElement.id==="chatText") sendChat();
  }
});
function addChat(msg){
  const box=document.getElementById("chatBox");
  const time=new Date(msg.time).toLocaleTimeString();
  const who=(msg.from && (msg.from.nickname||msg.from.username)) ? (msg.from.nickname||msg.from.username) : "USER";
  const d=document.createElement("div");
  d.className="msg";
  d.innerHTML=\`<div class="m1"><span>\${who}</span><span>\${time}</span></div><div class="m2"></div>\`;
  d.querySelector(".m2").textContent=msg.text;
  box.appendChild(d);
  box.scrollTop=box.scrollHeight;
}

// Moderator actions (room flags)
let moderationOpen=false;
function toggleModeration(){
  moderationOpen=!moderationOpen;
  if(!moderationOpen){
    alert("Модерация: используйте кнопки напротив участников (Kick/Mute/CamOff).");
    return;
  }
  const v = prompt("Команды модерации:\\n1) lock on/off\\n2) quiet on/off\\n3) chat on/off\\nВведите: lock on");
  if(!v) return;
  const parts=v.trim().toLowerCase().split(/\\s+/);
  if(parts.length<2) return;
  const cmd=parts[0], val=parts[1]==="on";
  if(cmd==="lock") adminToggleLock(val);
  if(cmd==="quiet") adminToggleQuiet(val);
  if(cmd==="chat") adminToggleChat(val);
}

// send admin-action
function adminSend(action,payload){
  if(!ws||ws.readyState!==1) return;
  ws.send(JSON.stringify({t:"admin-action",action,...payload}));
}
function adminKick(targetSocketId,roomId){ adminSend("kick",{targetSocketId,roomId}); }
function adminForceMute(targetSocketId,roomId){ adminSend("force-mute",{targetSocketId,roomId}); }
function adminForceCamOff(targetSocketId,roomId){ adminSend("force-camoff",{targetSocketId,roomId}); }
function adminToggleChat(value){ adminSend("toggle-chat",{roomId:ROOM_ID,value}); }
function adminToggleLock(value){ adminSend("toggle-lock",{roomId:ROOM_ID,value}); }
function adminToggleQuiet(value){ adminSend("toggle-quiet",{roomId:ROOM_ID,value}); }

async function copyLink(){
  const link=location.origin+"/room/"+encodeURIComponent(ROOM_ID);
  try{ await navigator.clipboard.writeText(link); alert("Ссылка скопирована"); }
  catch{ prompt("Скопируй ссылку:", link); }
}
function leave(){
  try{ if(ws) ws.close(); }catch{}
  try{ if(localStream) localStream.getTracks().forEach(t=>t.stop()); }catch{}
  try{ if(screenStream) screenStream.getTracks().forEach(t=>t.stop()); }catch{}
  for(const [id,p] of peers){ try{ p.pc.close(); }catch{} }
  peers.clear();
  location.href="/";
}

// QoS loop (RTT + packet loss)
let qosTimer=null;
async function startQoSLoop(){
  if(qosTimer) clearInterval(qosTimer);
  qosTimer=setInterval(async ()=>{
    try{
      // pick one peer connection (any) to read candidate stats
      let anyPC=null;
      for(const {pc} of peers.values()){ anyPC=pc; break; }
      if(!anyPC) return;

      const stats = await anyPC.getStats();
      let rttMs=null;
      let packetsLost=0, packetsRecv=0;

      stats.forEach(report=>{
        if(report.type==="candidate-pair" && report.state==="succeeded" && report.currentRoundTripTime!=null){
          rttMs = Math.round(report.currentRoundTripTime * 1000);
        }
        if(report.type==="inbound-rtp" && report.kind==="video"){
          packetsLost += report.packetsLost || 0;
          packetsRecv += report.packetsReceived || 0;
        }
      });

      let lossPct=null;
      if((packetsLost+packetsRecv)>0) lossPct = Math.round((packetsLost/(packetsLost+packetsRecv))*1000)/10;

      if(rttMs!=null || lossPct!=null){
        document.getElementById("qosP").innerHTML = "QOS <strong>"+(rttMs!=null?("RTT "+rttMs+"ms"):"")+(lossPct!=null?(" • LOSS "+lossPct+"%"):"")+"</strong>";
        if(ws && ws.readyState===1){
          ws.send(JSON.stringify({t:"qos", rttMs: rttMs!=null?rttMs:undefined, lossPct: lossPct!=null?lossPct:undefined}));
        }
      }
    }catch{}
  }, 4000);
}

// stars
const canvas=document.getElementById("stars");
const ctx=canvas.getContext("2d");
let stars=[];
function initStars(){canvas.width=innerWidth;canvas.height=innerHeight;stars=Array(220).fill().map(()=>({x:Math.random()*canvas.width,y:Math.random()*canvas.height,z:Math.random()*canvas.width,o:Math.random()}));}
function drawStars(){ctx.clearRect(0,0,canvas.width,canvas.height);for(const s of stars){const x=(s.x-canvas.width/2)*(canvas.width/s.z)+canvas.width/2;const y=(s.y-canvas.height/2)*(canvas.width/s.z)+canvas.height/2;const size=(1-s.z/canvas.width)*2.2;ctx.fillStyle=\`rgba(255,255,255,\${s.o*(1-s.z/canvas.width)})\`;ctx.beginPath();ctx.arc(x,y,size,0,Math.PI*2);ctx.fill();s.z-=0.55;if(s.z<=0)s.z=canvas.width;}requestAnimationFrame(drawStars);}
addEventListener("resize",initStars);initStars();drawStars();
</script>
</body>
</html>`;
}

// ---------------- ADMIN DASHBOARD UI ----------------
function renderAdminHTML() {
  // This page connects as WS admin client + calls REST /api/admin/*
  return `<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no"/>
<title>Admin Dashboard</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@200;300;400;600&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#050505;
  --card:rgba(255,255,255,0.05);
  --border:rgba(255,255,255,0.12);
  --txt:rgba(255,255,255,0.92);
  --dim:rgba(255,255,255,0.55);
  --shadow:0 20px 60px rgba(0,0,0,0.45);
  --r:18px;
  --danger:#ff3b3b;
  --ok:rgba(120,255,170,0.9);
}
*{margin:0;padding:0;box-sizing:border-box;-webkit-font-smoothing:antialiased}
body{min-height:100vh;background:var(--bg);color:var(--txt);font-family:Inter,system-ui,Arial}
canvas{position:fixed;inset:0;z-index:-1;pointer-events:none}
.wrap{padding:14px;max-width:1280px;margin:0 auto}
.top{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;padding:12px 0}
.title{letter-spacing:.26em;font-weight:300}
.pill{border:1px solid var(--border);border-radius:999px;padding:8px 10px;font-size:11px;color:var(--dim);letter-spacing:.12em;text-transform:uppercase}
.glass{background:var(--card);border:1px solid var(--border);backdrop-filter:blur(18px);-webkit-backdrop-filter:blur(18px);border-radius:var(--r);box-shadow:var(--shadow)}
.grid{display:grid;grid-template-columns:repeat(12,1fr);gap:10px}
.card{padding:12px}
.h{font-size:11px;color:var(--dim);letter-spacing:.14em;text-transform:uppercase}
.big{font-size:34px;font-weight:300;letter-spacing:.02em;margin-top:8px}
.row{margin-top:10px;color:var(--dim);font-size:12px;display:flex;gap:10px;flex-wrap:wrap}
.liveDot{display:inline-flex;align-items:center;gap:8px}
.dot{width:10px;height:10px;border-radius:999px;background:var(--ok);box-shadow:0 0 18px rgba(120,255,170,.35);animation:pulse 1.2s infinite}
@keyframes pulse{0%{transform:scale(1);opacity:.85}50%{transform:scale(1.4);opacity:.35}100%{transform:scale(1);opacity:.85}}
.btn{background:transparent;border:1px solid var(--border);color:var(--txt);padding:10px 12px;border-radius:14px;cursor:pointer;transition:.18s;user-select:none}
.btn:hover{transform:translateY(-1px);border-color:rgba(255,255,255,.22)}
.btn:active{transform:translateY(0);opacity:.9}
.btn.danger{border-color:rgba(255,59,59,.7);color:var(--danger)}
.input{width:100%;padding:12px;border-radius:14px;border:1px solid var(--border);background:rgba(0,0,0,.25);color:var(--txt);outline:none}
.input:focus{border-color:rgba(255,255,255,.25)}
.table{margin-top:10px}
.tr{display:grid;grid-template-columns:2.2fr 1fr 1fr 2fr;gap:10px;padding:10px 0;border-bottom:1px solid rgba(255,255,255,.08);font-size:12px;color:var(--dim)}
.tr strong{color:var(--txt);font-weight:500}
.badge{border:1px solid rgba(255,255,255,.12);border-radius:999px;padding:6px 10px;font-size:11px;color:var(--dim);text-transform:uppercase;letter-spacing:.12em}
.kpi{display:flex;align-items:baseline;justify-content:space-between;gap:10px}
.spark{height:40px;width:100%;border:1px solid rgba(255,255,255,.08);border-radius:12px;background:rgba(0,0,0,.18);overflow:hidden}
.spark canvas{position:static;inset:auto;z-index:auto}
.section{margin-top:10px}
@media(max-width:900px){.grid{grid-template-columns:repeat(6,1fr)}}
@media(max-width:520px){.grid{grid-template-columns:repeat(2,1fr)} .big{font-size:28px}}
</style>
</head>
<body>
<canvas id="stars"></canvas>
<div class="wrap">

  <div class="top">
    <div>
      <div class="title">EXECUTIVE DASHBOARD</div>
      <div class="row">
        <span class="pill liveDot"><span class="dot"></span> LIVE</span>
        <span class="pill" id="whoP">/ —</span>
        <span class="pill" id="netP">NET —</span>
      </div>
    </div>
    <div style="display:flex;gap:10px;flex-wrap:wrap">
      <button class="btn" onclick="location.href='/'">Меню</button>
      <button class="btn" onclick="refreshAll()">Refresh</button>
      <button class="btn danger" onclick="logout()">Logout</button>
    </div>
  </div>

  <!-- KPI ROW -->
  <div class="grid">
    <div class="glass card" style="grid-column:span 3">
      <div class="h">Онлайн сейчас</div>
      <div class="big" id="k_online">—</div>
      <div class="row"><span class="badge" id="k_emp">EMP —</span><span class="badge" id="k_guest">GUEST —</span></div>
    </div>

    <div class="glass card" style="grid-column:span 3">
      <div class="h">Активные комнаты</div>
      <div class="big" id="k_rooms">—</div>
      <div class="row"><span class="badge" id="k_live">LIVE —</span></div>
    </div>

    <div class="glass card" style="grid-column:span 3">
      <div class="h">Средняя длительность (24ч)</div>
      <div class="big" id="k_avgdur">—</div>
      <div class="row"><span class="badge" id="k_peak">PEAK —</span></div>
    </div>

    <div class="glass card" style="grid-column:span 3">
      <div class="h">Качество связи</div>
      <div class="big" id="k_qos">—</div>
      <div class="row"><span class="badge" id="k_loss">LOSS —</span></div>
    </div>

    <div class="glass card" style="grid-column:span 12">
      <div class="h">Пиковая нагрузка по времени (сейчас: грубый MVP)</div>
      <div class="section">
        <div class="spark"><canvas id="spark"></canvas></div>
      </div>
    </div>

    <div class="glass card" style="grid-column:span 12">
      <div style="display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap">
        <div class="h">Идут встречи (LIVE)</div>
        <div style="display:flex;gap:10px;flex-wrap:wrap">
          <button class="btn" onclick="loadUsers()">Users</button>
          <button class="btn" onclick="loadLogs()">Logs</button>
        </div>
      </div>
      <div class="table" id="liveTable"></div>
    </div>

    <div class="glass card" style="grid-column:span 12">
      <div class="h">Пользователи</div>
      <div style="display:grid;grid-template-columns:1fr 1fr 1fr 1fr;gap:10px;margin-top:10px">
        <input class="input" id="u_email" placeholder="Email">
        <input class="input" id="u_nick" placeholder="Nickname">
        <input class="input" id="u_user" placeholder="Username">
        <input class="input" id="u_pass" placeholder="Password" type="password">
      </div>
      <div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:10px">
        <select class="input" id="u_role" style="max-width:260px">
          <option value="employee">employee</option>
          <option value="moderator">moderator</option>
          <option value="dept_admin">dept_admin</option>
          <option value="superadmin">superadmin</option>
          <option value="guest">guest</option>
        </select>
        <input class="input" id="u_dept" placeholder="Dept (например HQ)" style="max-width:260px">
        <button class="btn" onclick="createUser()">Create user</button>
      </div>
      <div class="table" id="usersTable"></div>
    </div>

    <div class="glass card" style="grid-column:span 12">
      <div class="h">Логи (последние 120)</div>
      <div class="table" id="logsTable"></div>
    </div>
  </div>
</div>

<script>
let token = localStorage.getItem("stak_token") || "";
let ws = null;
let myRole = localStorage.getItem("stak_role") || "";

function fmtSec(sec){
  if(!sec) return "0m";
  const m=Math.floor(sec/60);
  const h=Math.floor(m/60);
  const mm=m%60;
  if(h>0) return h+"h "+mm+"m";
  return mm+"m";
}
function logout(){
  localStorage.removeItem("stak_token");
  localStorage.removeItem("stak_role");
  location.href="/";
}

async function refreshAll(){
  await loadSummary();
  await loadUsers();
  await loadLogs();
}

async function loadSummary(){
  if(!token) return location.href="/";
  const r = await fetch("/api/admin/summary",{ headers:{ "Authorization":"Bearer "+token }});
  const data = await r.json();
  if(!r.ok) return alert(data.error||"Access denied");

  document.getElementById("k_online").textContent = data.onlineNow;
  document.getElementById("k_emp").textContent = "EMP " + data.onlineEmployees;
  document.getElementById("k_guest").textContent = "GUEST " + data.onlineGuests;

  document.getElementById("k_rooms").textContent = data.activeRooms;
  document.getElementById("k_live").textContent = "LIVE " + data.liveMeetings;

  document.getElementById("k_avgdur").textContent = fmtSec(data.avgDurationSec24h);
  document.getElementById("k_peak").textContent = "PEAK " + String(data.peakHour).padStart(2,"0") + ":00";

  const rtt = (data.qos && data.qos.avgRtt!=null) ? Math.round(data.qos.avgRtt) : null;
  const loss = (data.qos && data.qos.avgLoss!=null) ? (Math.round(data.qos.avgLoss*10)/10) : null;
  document.getElementById("k_qos").textContent = rtt!=null ? (rtt+"ms") : "—";
  document.getElementById("k_loss").textContent = "LOSS " + (loss!=null ? (loss+"%") : "—");

  renderLive(data.liveList||[]);
  drawSpark(data.hourBuckets||[]);
}

function renderLive(list){
  const root=document.getElementById("liveTable");
  if(!list.length){
    root.innerHTML = '<div class="tr"><strong>Сейчас нет активных встреч</strong><span></span><span></span><span></span></div>';
    return;
  }
  root.innerHTML = '<div class="tr" style="color:rgba(255,255,255,.35)"><span>ROOM</span><span>USERS</span><span>DURATION</span><span>ACTIONS</span></div>';
  for(const m of list){
    const locked = m.flags && m.flags.locked;
    const quiet = m.flags && m.flags.quiet;
    const chatOn = m.flags && m.flags.chatEnabled;
    const qos = m.qos && m.qos.avgRtt!=null ? ("RTT "+Math.round(m.qos.avgRtt)+"ms") : "RTT —";
    const loss = m.qos && m.qos.avgLoss!=null ? ("LOSS "+(Math.round(m.qos.avgLoss*10)/10)+"%") : "LOSS —";
    root.innerHTML += \`
      <div class="tr">
        <span><strong>\${m.roomId}</strong> <span class="badge">\${(m.type||"webinar")}</span> <span class="badge">\${m.deptId||""}</span></span>
        <span><strong>\${m.count}</strong></span>
        <span><strong>\${fmtSec(m.durationSec||0)}</strong><div style="font-size:11px;color:rgba(255,255,255,.35);margin-top:4px">\${qos} • \${loss}</div></span>
        <span style="display:flex;gap:8px;flex-wrap:wrap">
          <button class="btn danger" onclick="endRoom('\${m.roomId}')">End</button>
          <button class="btn" onclick=">(_=>0)()"> </button>
          <button class="btn" onclick="toggleLock('\${m.roomId}', \${!locked})">\${locked?"Unlock":"Lock"}</button>
          <button class="btn" onclick="toggleQuiet('\${m.roomId}', \${!quiet})">\${quiet?"Unquiet":"Quiet"}</button>
          <button class="btn" onclick="toggleChat('\${m.roomId}', \${!chatOn})">\${chatOn?"ChatOff":"ChatOn"}</button>
        </span>
      </div>\`;
  }
}

// Admin WS live (optional) — обновляет summary каждые 2 сек
function connectAdminWS(){
  const proto = location.protocol==="https:" ? "wss":"ws";
  ws = new WebSocket(\`\${proto}://\${location.host}/?as=admin&token=\${encodeURIComponent(token)}\`);
  ws.onopen = ()=> document.getElementById("netP").textContent="NET ONLINE";
  ws.onclose = ()=> document.getElementById("netP").textContent="NET OFFLINE";
  ws.onmessage = (ev)=>{
    const msg = JSON.parse(ev.data);
    if(msg.t==="admin-hello"){
      document.getElementById("whoP").textContent = "/ " + (msg.you.username||"") + " • " + (msg.you.role||"").toUpperCase();
      return;
    }
    if(msg.t==="admin-live"){
      // use the server-prepared summary
      const data = msg.summary;
      if(!data) return;

      document.getElementById("k_online").textContent = data.onlineNow;
      document.getElementById("k_emp").textContent = "EMP " + data.onlineEmployees;
      document.getElementById("k_guest").textContent = "GUEST " + data.onlineGuests;

      document.getElementById("k_rooms").textContent = data.activeRooms;
      document.getElementById("k_live").textContent = "LIVE " + data.liveMeetings;

      document.getElementById("k_avgdur").textContent = fmtSec(data.avgDurationSec24h);
      document.getElementById("k_peak").textContent = "PEAK " + String(data.peakHour).padStart(2,"0") + ":00";

      const rtt = (data.qos && data.qos.avgRtt!=null) ? Math.round(data.qos.avgRtt) : null;
      const loss = (data.qos && data.qos.avgLoss!=null) ? (Math.round(data.qos.avgLoss*10)/10) : null;
      document.getElementById("k_qos").textContent = rtt!=null ? (rtt+"ms") : "—";
      document.getElementById("k_loss").textContent = "LOSS " + (loss!=null ? (loss+"%") : "—");

      renderLive(data.liveList||[]);
      drawSpark(data.hourBuckets||[]);
    }
  };
}

function adminSend(action, payload){
  if(!ws || ws.readyState!==1) return alert("Admin WS offline");
  ws.send(JSON.stringify({t:"admin-action", action, ...payload}));
}
function endRoom(roomId){
  if(!confirm("Завершить комнату "+roomId+"?")) return;
  adminSend("end-room",{roomId});
}
function toggleLock(roomId, val){ adminSend("toggle-lock",{roomId, value: !!val}); }
function toggleQuiet(roomId, val){ adminSend("toggle-quiet",{roomId, value: !!val}); }
function toggleChat(roomId, val){ adminSend("toggle-chat",{roomId, value: !!val}); }

async function loadUsers(){
  if(!token) return;
  const r = await fetch("/api/admin/users",{ headers:{ "Authorization":"Bearer "+token }});
  const data = await r.json();
  if(!r.ok) return;
  const root=document.getElementById("usersTable");
  root.innerHTML = '<div class="tr" style="color:rgba(255,255,255,.35)"><span>USER</span><span>ROLE</span><span>DEPT</span><span>ACTIONS</span></div>';
  for(const u of data){
    root.innerHTML += \`
      <div class="tr">
        <span><strong>\${u.username}</strong><div style="margin-top:4px;font-size:11px;color:rgba(255,255,255,.35)">\${u.nickname} • \${u.email}</div></span>
        <span><span class="badge">\${u.role}</span></span>
        <span><span class="badge">\${u.deptId||""}</span></span>
        <span style="display:flex;gap:8px;flex-wrap:wrap">
          <button class="btn" onclick="changeRole('\${u.username}','\${u.role}')">Role</button>
          <button class="btn" onclick="resetPass('\${u.username}')">Reset</button>
          <button class="btn danger" onclick="delUser('\${u.username}')">Del</button>
        </span>
      </div>\`;
  }
}
async function createUser(){
  const email=(document.getElementById("u_email").value||"").trim();
  const nickname=(document.getElementById("u_nick").value||"").trim();
  const username=(document.getElementById("u_user").value||"").trim();
  const password=(document.getElementById("u_pass").value||"");
  const role=document.getElementById("u_role").value;
  const deptId=(document.getElementById("u_dept").value||"HQ").trim();

  const r = await fetch("/api/admin/users",{
    method:"POST",
    headers:{ "Content-Type":"application/json", "Authorization":"Bearer "+token },
    body: JSON.stringify({ email,nickname,username,password,role,deptId })
  });
  const data = await r.json();
  if(!r.ok) return alert(data.error||"Ошибка");
  alert("Создано");
  loadUsers();
}
async function changeRole(username,currentRole){
  const next = prompt("Новая роль для "+username+" (guest/employee/moderator/dept_admin/superadmin):", currentRole);
  if(!next) return;
  const r = await fetch("/api/admin/users/"+encodeURIComponent(username),{
    method:"PATCH",
    headers:{ "Content-Type":"application/json", "Authorization":"Bearer "+token },
    body: JSON.stringify({ role: next })
  });
  const data = await r.json();
  if(!r.ok) return alert(data.error||"Ошибка");
  loadUsers();
}
async function resetPass(username){
  const np = prompt("Новый пароль для "+username+" (мин 6):");
  if(!np) return;
  const r = await fetch("/api/admin/users/"+encodeURIComponent(username),{
    method:"PATCH",
    headers:{ "Content-Type":"application/json", "Authorization":"Bearer "+token },
    body: JSON.stringify({ newPassword: np })
  });
  const data = await r.json();
  if(!r.ok) return alert(data.error||"Ошибка");
  alert("Пароль обновлён");
}
async function delUser(username){
  if(!confirm("Удалить пользователя "+username+"?")) return;
  const r = await fetch("/api/admin/users/"+encodeURIComponent(username),{
    method:"DELETE",
    headers:{ "Authorization":"Bearer "+token }
  });
  const data = await r.json();
  if(!r.ok) return alert(data.error||"Ошибка");
  loadUsers();
}

async function loadLogs(){
  if(!token) return;
  const r = await fetch("/api/admin/logs",{ headers:{ "Authorization":"Bearer "+token }});
  const data = await r.json();
  if(!r.ok) return;
  const list = data.slice().reverse().slice(0,120);
  const root=document.getElementById("logsTable");
  root.innerHTML = '<div class="tr" style="color:rgba(255,255,255,.35)"><span>TIME</span><span>ACTOR</span><span>ACTION</span><span>META</span></div>';
  for(const l of list){
    root.innerHTML += \`
      <div class="tr">
        <span><strong>\${new Date(l.time).toLocaleString()}</strong></span>
        <span><strong>\${l.actor}</strong></span>
        <span><strong>\${l.action}</strong></span>
        <span style="opacity:.6">\${escapeHtml(JSON.stringify(l.meta||{})).slice(0,140)}</span>
      </div>\`;
  }
}
function escapeHtml(s){return String(s).replace(/[&<>"']/g,m=>({ "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;" }[m]));}

// sparkline (hour buckets)
function drawSpark(arr){
  const c=document.getElementById("spark");
  const ctx=c.getContext("2d");
  const w=c.parentElement.clientWidth;
  const h=c.parentElement.clientHeight;
  c.width=w; c.height=h;
  ctx.clearRect(0,0,w,h);
  if(!arr || !arr.length) return;

  const max = Math.max(...arr, 1);
  const pad=8;
  const n=arr.length;
  const step=(w-2*pad)/(n-1);

  ctx.globalAlpha=0.9;
  ctx.beginPath();
  for(let i=0;i<n;i++){
    const x=pad+i*step;
    const y=h-pad - (arr[i]/max)*(h-2*pad);
    if(i===0) ctx.moveTo(x,y); else ctx.lineTo(x,y);
  }
  ctx.strokeStyle="rgba(255,255,255,0.75)";
  ctx.lineWidth=2;
  ctx.stroke();

  ctx.globalAlpha=0.18;
  ctx.lineTo(w-pad,h-pad);
  ctx.lineTo(pad,h-pad);
  ctx.closePath();
  ctx.fillStyle="rgba(255,255,255,0.45)";
  ctx.fill();
  ctx.globalAlpha=1;
}

function boot(){
  if(!token) return location.href="/";
  connectAdminWS();
  refreshAll();
}
boot();

// stars
const canvas=document.getElementById("stars");
const ctx=canvas.getContext("2d");
let stars=[];
function initStars(){canvas.width=innerWidth;canvas.height=innerHeight;stars=Array(220).fill().map(()=>({x:Math.random()*canvas.width,y:Math.random()*canvas.height,z:Math.random()*canvas.width,o:Math.random()}));}
function drawStars(){ctx.clearRect(0,0,canvas.width,canvas.height);for(const s of stars){const x=(s.x-canvas.width/2)*(canvas.width/s.z)+canvas.width/2;const y=(s.y-canvas.height/2)*(canvas.width/s.z)+canvas.height/2;const size=(1-s.z/canvas.width)*2.2;ctx.fillStyle=\`rgba(255,255,255,\${s.o*(1-s.z/canvas.width)})\`;ctx.beginPath();ctx.arc(x,y,size,0,Math.PI*2);ctx.fill();s.z-=0.55;if(s.z<=0)s.z=canvas.width;}requestAnimationFrame(drawStars);}
addEventListener("resize",initStars);initStars();drawStars();
</script>
</body>
</html>`;
}

// ---------------- START (EADDRINUSE friendly) ----------------
server.listen(PORT, () => {
  console.log(`STAK: http://localhost:${PORT}`);
  console.log(`Admin: http://localhost:${PORT}/admin`);
});
server.on("error", (err) => {
  if (err && err.code === "EADDRINUSE") {
    console.error(`PORT ${PORT} is busy. Change port via env:`);
    console.error(`  PowerShell: $env:PORT=3001; node server.js`);
    console.error(`  CMD: set PORT=3001 && node server.js`);
    process.exit(1);
  }
  console.error("Server error:", err);
  process.exit(1);
});


