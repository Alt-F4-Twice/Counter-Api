
// server.js
// Full long-form version with Owner/Admin panel, leaderboard, VPN detection, AES passwords

const { Client, GatewayIntentBits } = require('discord.js');
const express = require("express");
const fs = require("fs");
const crypto = require("crypto");
const https = require("https");
const bcrypt = require("bcrypt");
const cookieParser = require("cookie-parser");
const rateLimit = require("express-rate-limit");

// ==================== ENV VARIABLES ====================
const BOT_TOKEN = process.env.BOT_TOKEN;         // your Discord bot token
const CHANNEL_ID = process.env.CHANNEL_ID;       // your Discord channel ID
const OWNER_MASTER_PASSWORD = process.env.OWNER_MASTER_PASSWORD;
const REVEAL_MASTER_PASSWORD = process.env.REVEAL_MASTER_PASSWORD;
const OWNER_INIT_PASSWORD = process.env.OWNER_INIT_PASSWORD;

if (!BOT_TOKEN) throw new Error("BOT_TOKEN not set in environment!");
if (!CHANNEL_ID) throw new Error("CHANNEL_ID not set in environment!");
if (!OWNER_MASTER_PASSWORD) throw new Error("OWNER_MASTER_PASSWORD not set in environment!");
if (!REVEAL_MASTER_PASSWORD) throw new Error("REVEAL_MASTER_PASSWORD not set in environment!");

// ==================== DISCORD BOT ====================
const bot = new Client({ intents: [GatewayIntentBits.Guilds, GatewayIntentBits.GuildMessages, GatewayIntentBits.MessageContent] });
bot.once('ready', () => console.log(`Logged in as ${bot.user.tag}`));
bot.login(BOT_TOKEN);

// ==================== APP SETUP ====================

const app = express();

app.set('trust proxy', 1); // ✅ FIXED

app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// ==================== CONFIG =======================

const PORT = process.env.PORT || 3000;
const DATA_FILE = "./data.json";
const ADMINS_FILE = "./admins.json";
const SESSION_TTL = 1000 * 60 * 60 * 6; // 6 hours

// Create AES key for encryption
const ENCRYPTION_KEY = crypto
  .createHash("sha256")
  .update(REVEAL_MASTER_PASSWORD)
  .digest();

// ==================== STORAGE ======================

let data = { counter: 0, users: {} };
let admins = {};
let sessions = {};

function invalidateSession(username) {
  for (const token in sessions) {
    if (sessions[token].username === username) {
      delete sessions[token];
    }
  }
}

let ipCache = {};
let leaderboardCache = null;
let leaderboardTime = 0;

// ==================== FILE LOAD ====================

if (fs.existsSync(DATA_FILE)) {
  data = JSON.parse(fs.readFileSync(DATA_FILE));
}

if (fs.existsSync(ADMINS_FILE)) {
  admins = JSON.parse(fs.readFileSync(ADMINS_FILE));
}


// ==================== ENCRYPTION ===================

function encrypt(text) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv("aes-256-cbc", ENCRYPTION_KEY, iv);

  let encrypted = cipher.update(text, "utf8", "hex");
  encrypted += cipher.final("hex");

  return iv.toString("hex") + ":" + encrypted;
}

function decrypt(text) {
  const parts = text.split(":");
  const iv = Buffer.from(parts.shift(), "hex");
  const encryptedText = parts.join(":");

  const decipher = crypto.createDecipheriv("aes-256-cbc", ENCRYPTION_KEY, iv);

  let decrypted = decipher.update(encryptedText, "hex", "utf8");
  decrypted += decipher.final("utf8");

  return decrypted;
}

// ==================== SAVE FUNCTIONS ===================

function saveData() {
  fs.promises.writeFile(DATA_FILE, JSON.stringify(data, null, 2));
}

function saveAdmins() {
  fs.promises.writeFile(ADMINS_FILE, JSON.stringify(admins, null, 2));
}

// ==================== INITIALIZE OWNER ===================

async function initOwner() {
  if (!admins.Owner) {
    const pass = "Luckyme2309!";
    const hash = await bcrypt.hash(pass, 10);

    admins.Owner = {
      role: "owner",
      passwordHash: hash,
      passwordEncrypted: encrypt(pass),
    };

    saveAdmins();
  }
}

// ==================== SESSION FUNCTIONS ===================

function createSession(username) {
  const token = crypto.randomBytes(32).toString("hex");

  sessions[token] = {
    username,
    created: Date.now(),
  };

  return token;
}

function requireLogin(req, res, next) {
  const token = req.cookies.session;
  const session = sessions[token];

  if (!session || Date.now() - session.created > SESSION_TTL) {
    return res.redirect("/login");
  }

  req.admin = session.username;

  next();
}

function requireOwner(req, res, next) {
  if (!admins[req.admin] || admins[req.admin].role !== "owner") {
    return res.send("Owner only");
  }

  next();
}

// ==================== RATE LIMIT LOGIN ===================

app.use(
  "/login-submit",
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 20,
  })
);

// ==================== HELPER ===================

function fetchJSON(url) {
  return new Promise((resolve) => {
    https
      .get(url, (res) => {
        let raw = "";

        res.on("data", (d) => (raw += d));

        res.on("end", () => {
          try {
            resolve(JSON.parse(raw));
          } catch {
            resolve(null);
          }
        });
      })
      .on("error", () => resolve(null));
  });
}

// ==================== DISCORD ALERT ===================

function sendDiscord(msg) {
  const channel = bot.channels.cache.get(CHANNEL_ID);
  if (!channel) return console.error('Discord channel not found!');
  channel.send(msg).catch(console.error);
}

// ==================== VPN / PROXY / TOR DETECTION ===================

async function checkVPN(ip) {
  if (ipCache[ip]) return ipCache[ip].vpn;

  try {
    const [ipapi, ipwho, ipstack] = await Promise.all([
      fetchJSON(`https://ipapi.co/${ip}/json/`),
      fetchJSON(`https://ipwho.is/${ip}`),
      fetchJSON(`https://api.ipstack.com/${ip}?access_key=YOUR_ACCESS_KEY`),
    ]);

    let vpn = false;
    let country = "Unknown";

    if (ipapi) {
      if (ipapi.proxy || ipapi.vpn || ipapi.tor) vpn = true;
      if (ipapi.country_name) country = ipapi.country_name;
    }

    if (ipwho) {
      if (ipwho.proxy || ipwho.vpn || ipwho.tor) vpn = true;
      if (ipwho.country) country = ipwho.country;
    }

    if (ipstack) {
      if (ipstack.proxy || ipstack.vpn) vpn = true;
      if (ipstack.country_name) country = ipstack.country_name;
    }

    ipCache[ip] = { vpn, country };

    return vpn;
  } catch {
    return true;
  }
}

// ==================== LEADERBOARD ===================

function getLeaderboard(limit = Infinity) {
  const now = Date.now();

  if (leaderboardCache && now - leaderboardTime < 10000) {
    return leaderboardCache.slice(0, limit);
  }

  leaderboardCache = Object.values(data.users).sort(
    (a, b) => a.position - b.position
  );

  leaderboardTime = now;

  return leaderboardCache.slice(0, limit);
}

// ==================== COUNTER ===================

app.get("/counter", async (req, res) => {
  // Get real client IP
  let ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress;
  if (ip.includes(",")) ip = ip.split(",")[0].trim(); // first IP if behind proxy
  if (ip === "::1") ip = "127.0.0.1"; // localhost

  const device = req.headers["user-agent"] || "Unknown";

  if (await checkVPN(ip)) {
    res.setHeader("Content-Type", "application/json");
    return res.send(JSON.stringify({ error: "VPN detected" }, null, 2));
  }

  let id = req.query.id;

  if (id && data.users[id]) {
    if (data.users[id].device !== device) {
      res.setHeader("Content-Type", "application/json");
      return res.send(JSON.stringify({ error: "Device mismatch" }, null, 2));
    }

    res.setHeader("Content-Type", "application/json");
    return res.send(JSON.stringify(data.users[id], null, 2));
  }

  do {
    id = crypto.randomUUID();
  } while (data.users[id]);

  data.counter++;

  data.users[id] = {
    id,
    name: "User",
    position: data.counter,
    joined: new Date().toISOString(),
    device,
    ip, // now stores real client IP
  };

  saveData();

  res.setHeader("Content-Type", "application/json");
  res.send(JSON.stringify(data.users[id], null, 2));
});

// ==================== LOGIN ===================

app.get("/login", (req, res) => {
  const msg = req.query.error || "";

  res.send(`
<h2>Admin Login</h2>

<form action="/login-submit">
<input name="username" placeholder="Username"><br><br>
<input name="password" type="password" placeholder="Password"><br><br>
<button>Login</button>
</form>

<span style="color:red">${msg}</span>
`);
});

app.get("/login-submit", async (req, res) => {
  const { username, password } = req.query;

  if (!admins[username]) {
    return res.redirect(
      "/login?error=Wrong username or password, please try again"
    );
  }

  const ok = await bcrypt.compare(password, admins[username].passwordHash);

  if (!ok) {
    return res.redirect(
      "/login?error=Wrong username or password, please try again"
    );
  }

  // ==================== DISCORD ALERT ===================

let ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress;
if (ip.includes(",")) ip = ip.split(",")[0].trim();
if (ip === "::1") ip = "127.0.0.1";
  
sendDiscord(`🔐 ADMIN LOGIN
User: ${username}
IP: ${ip}
Time: ${new Date().toISOString()}`);

  const session = createSession(username);

  res.cookie("session", session, { httpOnly: true });

  res.redirect("/admin");
});

// ==================== ADMIN PANEL ===================
// (unchanged — kept exactly same)

app.get("/admin", requireLogin, (req, res) => {
  const currentUsers = Object.keys(data.users).length;

  const usersHTML = getLeaderboard()
    .map(
      (u) => `
<tr>
<td><input type="checkbox" class="delete-user" value="${u.id}"></td>
<td>${u.position}</td>
<td>${u.id}</td>
<td>${u.ip}</td>
</tr>`
    )
    .join("");

  const adminsHTML = Object.keys(admins)
    .map((a) => {
      const role = admins[a].role;

      let buttons = "";

      // Only Owner can reveal or delete other admins
      if (req.admin === "Owner") {
        buttons = `<button onclick="reveal('${a}')">Reveal</button>`;
        if (a !== "Owner") {
          buttons += ` <button onclick="deleteAdmin('${a}')">Delete</button>`;
        }
      }

      return `<div>${a} (${role}) ${buttons}</div>`;
    })
    .join("");

  res.send(`
<h1>${req.admin === "Owner" ? "Owner Panel" : "Admin Panel"}</h1>
<p>Current users created: ${currentUsers}</p>

<h2>Leaderboard</h2>
<button onclick="loadLeaderboard()">Refresh</button>
<button onclick="resetLeaderboard()">Reset Leaderboard</button>

<label><input type="checkbox" id="autoRefresh"> Auto Refresh: Off</label>

<table border="1">
<tr><th>Select</th><th>Position</th><th>ID</th><th>IP</th></tr>
<tbody id="leaderboard">
${usersHTML}
</tbody>
</table>

${req.admin === "Owner" ? '<button onclick="deleteSelected()">Delete Selected Users</button>' : ''}

${req.admin === "Owner" ? `
<h2>Create Admin</h2>
<form id="createAdminForm">
<input name="username" placeholder="Username">
<input name="password" placeholder="Password">
<button>Create Admin</button>
<span id="createAdminMsg"></span>
</form>

<h2>Admins & Owner</h2>
${adminsHTML}
` : ''}

<script>
let autoRefresh = false;

const checkbox = document.getElementById('autoRefresh');
const label = checkbox.parentElement;

checkbox.addEventListener('change', () => {
  autoRefresh = checkbox.checked;
  label.lastChild.textContent = " Auto Refresh: " + (autoRefresh ? "On" : "Off");
});

async function loadLeaderboard() {
  const res = await fetch('/leaderboard?limit=50');
  const users = await res.json();

  const tbody = document.getElementById('leaderboard');
  tbody.innerHTML='';

  users.forEach(u=>{
    const tr=document.createElement('tr');
    tr.innerHTML='<td><input type="checkbox" class="delete-user" value="'+u.id+'"></td><td>'+u.position+'</td><td>'+u.id+'</td><td>'+u.ip+'</td>';
    tbody.appendChild(tr);
  });
}

setInterval(()=>{ if(autoRefresh) loadLeaderboard(); }, 5000);

function deleteSelected() {
  const selected = Array.from(document.querySelectorAll('.delete-user:checked')).map(i=>i.value);
  selected.forEach(id => fetch('/delete-user?id='+id));
  setTimeout(loadLeaderboard, 500);
}

function resetLeaderboard() {
  fetch('/reset-leaderboard').then(()=>loadLeaderboard());
}

document.getElementById('createAdminForm').onsubmit = async e => {
  e.preventDefault();
  const f = e.target;
  const username = f.username.value;
  const password = f.password.value;

  await fetch('/create-admin?username=' + encodeURIComponent(username) + '&password=' + encodeURIComponent(password));

  f.querySelector('#createAdminMsg').innerText='Admin created';
  f.reset();
  loadLeaderboard();
}

function reveal(admin) {
  const pwd = prompt("Enter Owner Special Password","");
  if(!pwd) return;

  fetch('/reveal-password?username=' + admin + '&master=' + pwd)
    .then(r=>r.text())
    .then(t=>alert(t));
}

function deleteAdmin(admin) {
  if(!confirm("Delete "+admin+"?")) return;
  fetch('/delete-admin?username=' + admin).then(()=>location.reload());
}
</script>
`);
});

// ==================== API ROUTES ===================

app.get("/leaderboard", requireLogin, (req, res) =>
  res.json(getLeaderboard())
);

app.get("/delete-user", requireLogin, requireOwner, (req, res) => {
  let ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress;
  if (ip.includes(",")) ip = ip.split(",")[0].trim();
  if (ip === "::1") ip = "127.0.0.1";

  const id = req.query.id;

  if (!id || !data.users[id]) {
    return res.send("User not found");
  }

  delete data.users[id];

  const users = Object.values(data.users).sort((a, b) => a.position - b.position);
  users.forEach((u, i) => (u.position = i + 1));
  data.counter = users.length;

  saveData();

  // DISCORD ALERT
  sendDiscord(
    "🗑 USER DELETED\n" +
    "User ID: " + id +
    "\nDeleted By: " + req.admin +
    "\nIP: " + ip +
    "\nTime: " + new Date().toISOString()
  );

  res.send("ok");
});

app.get("/reset-leaderboard", requireLogin, requireOwner, (req, res) => {
  data = { counter: 0, users: {} };

  saveData();

  res.send("ok");
});

app.get("/create-admin", requireLogin, requireOwner, async (req, res) => {
  let ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress;
  if (ip.includes(",")) ip = ip.split(",")[0].trim();
  if (ip === "::1") ip = "127.0.0.1";

  const { username, password } = req.query;

  if (!username || !password) return res.send("Missing");
  if (admins[username]) return res.send("Exists");

  admins[username] = {
    role: "admin",
    passwordHash: await bcrypt.hash(password, 10),
    passwordEncrypted: encrypt(password),
  };

  saveAdmins();

  // DISCORD ALERT
  sendDiscord(
    "🆕 ADMIN CREATED\n" +
    "Admin: " + username +
    "\nCreated By: " + req.admin +
    "\nIP: " + ip +
    "\nTime: " + new Date().toISOString()
  );

  res.send("ok");
});

app.get("/reveal-password", requireLogin, requireOwner, (req, res) => {
  const { username, master } = req.query;

  if (master !== OWNER_MASTER_PASSWORD)
    return res.send("Wrong master password");

  if (!admins[username]) return res.send("Admin not found");

  const pass = decrypt(admins[username].passwordEncrypted);

  res.send("Password for " + username + ": " + pass);
});

app.get("/delete-admin", requireLogin, requireOwner, (req, res) => {
  let ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress;
  if (ip.includes(",")) ip = ip.split(",")[0].trim();
  if (ip === "::1") ip = "127.0.0.1";

  const { username } = req.query;

  if (username === "Owner") return res.send("Cannot delete Owner");

delete admins[username];
invalidateSession(username); // <-- Add this line
  
  saveAdmins();

  // DISCORD ALERT
  sendDiscord(
    "❌ ADMIN DELETED\n" +
    "Admin: " + username +
    "\nDeleted By: " + req.admin +
    "\nIP: " + ip +
    "\nTime: " + new Date().toISOString()
  );

  res.send("ok");
});

// ==================== NEW ROUTE (ID ↔ POSITION LOOKUP) ===================

app.get("/:value", (req, res) => {
  const value = req.params.value;

  if (!isNaN(value)) {
    const pos = parseInt(value);

    const user = Object.values(data.users).find((u) => u.position === pos);
    if (!user) return res.send("error");

    return res.send(user.id);
  }

  const user = data.users[value];
  if (!user) return res.send("error");

  res.send(String(user.position));
});


// ==================== SESSION CLEANUP ===================

setInterval(() => {
  const now = Date.now();

  for (const s in sessions) {
    if (now - sessions[s].created > SESSION_TTL) delete sessions[s];
  }
}, 3600000);

// ==================== START SERVER ===================

initOwner().then(() =>
  app.listen(PORT, () => console.log("Server running on port " + PORT))
);
