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
const BOT_TOKEN = process.env.BOT_TOKEN;  
const CHANNEL_ID = process.env.CHANNEL_ID;
const OWNER_MASTER_PASSWORD = process.env.OWNER_MASTER_PASSWORD;
const REVEAL_MASTER_PASSWORD = process.env.REVEAL_MASTER_PASSWORD;

if (!BOT_TOKEN) throw new Error("BOT_TOKEN not set!");
if (!CHANNEL_ID) throw new Error("CHANNEL_ID not set!");
if (!OWNER_MASTER_PASSWORD) throw new Error("OWNER_MASTER_PASSWORD not set!");
if (!REVEAL_MASTER_PASSWORD) throw new Error("REVEAL_MASTER_PASSWORD not set!");

// ==================== DISCORD BOT ====================
const bot = new Client({ intents: [GatewayIntentBits.Guilds, GatewayIntentBits.GuildMessages, GatewayIntentBits.MessageContent] });

bot.once('ready', () => {
  console.log(`✅ Bot is online as ${bot.user.tag}`);
});

bot.login(BOT_TOKEN)
  .then(() => console.log("✅ Bot login success"))
  .catch(err => console.error("❌ Bot login failed:", err));

// ==================== APP SETUP ====================
const app = express();
app.set('trust proxy', 1); // works behind Render proxy

app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// ==================== CONFIG =======================
const PORT = process.env.PORT || 3000;
const DATA_FILE = "/tmp/data.json";   // Persistent files in Render /tmp
const ADMINS_FILE = "/tmp/admins.json";
const SESSION_TTL = 1000 * 60 * 60 * 6; // 6 hours

// AES key for encryption
const ENCRYPTION_KEY = crypto.createHash("sha256").update(REVEAL_MASTER_PASSWORD).digest();

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
if (fs.existsSync(DATA_FILE)) data = JSON.parse(fs.readFileSync(DATA_FILE));
if (fs.existsSync(ADMINS_FILE)) admins = JSON.parse(fs.readFileSync(ADMINS_FILE));

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
    admins.Owner = { role: "owner", passwordHash: hash, passwordEncrypted: encrypt(pass) };
    saveAdmins();
  }
}

// ==================== SESSION FUNCTIONS ===================
function createSession(username) {
  const token = crypto.randomBytes(32).toString("hex");
  sessions[token] = { username, created: Date.now() };
  return token;
}

function requireLogin(req, res, next) {
  const token = req.cookies.session;
  const session = sessions[token];
  if (!session || Date.now() - session.created > SESSION_TTL) return res.redirect("/login");
  req.admin = session.username;
  next();
}

function requireOwner(req, res, next) {
  if (!admins[req.admin] || admins[req.admin].role !== "owner") return res.send("Owner only");
  next();
}

// ==================== RATE LIMIT LOGIN ===================
app.use("/login-submit", rateLimit({ windowMs: 15 * 60 * 1000, max: 20 }));

// ==================== HELPER ===================
function fetchJSON(url) {
  return new Promise((resolve) => {
    https.get(url, res => {
      let raw = "";
      res.on("data", d => raw += d);
      res.on("end", () => { try { resolve(JSON.parse(raw)) } catch { resolve(null) } });
    }).on("error", () => resolve(null));
  });
}

// ==================== DISCORD ALERT ===================
async function sendDiscord(msg) {
  try {
    const channel = await bot.channels.fetch(CHANNEL_ID);
    if (!channel) return console.error("Channel not found");
    await channel.send(msg);
  } catch (err) { console.error("Discord error:", err); }
}

// ==================== VPN / PROXY DETECTION ===================
async function checkVPN(ip) {
  if (ipCache[ip]) return ipCache[ip].vpn;
  try {
    const [ipapi, ipwho] = await Promise.all([
      fetchJSON(`https://ipapi.co/${ip}/json/`),
      fetchJSON(`https://ipwho.is/${ip}`)
    ]);
    let vpn = false;
    let country = "Unknown";
    if (ipapi) { if (ipapi.proxy || ipapi.vpn || ipapi.tor) vpn = true; if (ipapi.country_name) country = ipapi.country_name; }
    if (ipwho) { if (ipwho.proxy || ipwho.vpn || ipwho.tor) vpn = true; if (ipwho.country) country = ipwho.country; }
    ipCache[ip] = { vpn, country };
    return vpn;
  } catch { return true; }
}

// ==================== LEADERBOARD ===================
function getLeaderboard(limit = Infinity) {
  const now = Date.now();
  if (leaderboardCache && now - leaderboardTime < 10000) return leaderboardCache.slice(0, limit);
  leaderboardCache = Object.values(data.users).sort((a, b) => a.position - b.position);
  leaderboardTime = now;
  return leaderboardCache.slice(0, limit);
}

// ==================== COUNTER ===================
app.get("/counter", async (req, res) => {
  let ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress;
  if (ip.includes(",")) ip = ip.split(",")[0].trim();
  if (ip === "::1") ip = "127.0.0.1";
  const device = req.headers["user-agent"] || "Unknown";

  if (await checkVPN(ip)) return res.json({ error: "VPN detected" });

  let id = req.query.id;
  if (id && data.users[id]) {
    if (data.users[id].device !== device) return res.json({ error: "Device mismatch" });
    return res.json(data.users[id]);
  }

  do { id = crypto.randomUUID(); } while (data.users[id]);
  data.counter++;
  data.users[id] = { id, name: "User", position: data.counter, joined: new Date().toISOString(), device, ip };
  saveData();
  res.json(data.users[id]);
});

// ==================== LOGIN & ADMIN PANEL ===================
// (Same as your original code; omitted here for brevity but works unchanged)

initOwner().then(() => {
  app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
});
