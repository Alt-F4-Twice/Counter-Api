const express = require("express");
const axios = require("axios");
const { v4: uuidv4 } = require("uuid");
const ADMIN_KEY = process.env.ADMIN_KEY;

const app = express();
const PORT = process.env.PORT || 3000;

// In-memory storage (replace with DB for production)
let users = new Map();
let positionCounter = 1;

// Generate 16-character ID
function generateId() {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let id = "";
  for (let i = 0; i < 16; i++) {
    id += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return id;
}

//Generate 20-character Key
function generateKey(length = 20) {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let key = "";
  for (let i = 0; i < length; i++) {
    key += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return key;
}

// Ensure unique ID
function getUniqueId() {
  let id;
  do {
    id = generateId();
  } while ([...users.values()].some(u => u.id === id));
  return id;
}

// Get real IP
function getIP(req) {
  return req.headers["x-forwarded-for"] || req.socket.remoteAddress;
}

// VPN / Proxy check (basic)
async function isVPN(ip) {
  try {
    const res = await axios.get(`http://ip-api.com/json/${ip}?fields=proxy,hosting`);
    return res.data.proxy || res.data.hosting;
  } catch {
    return false;
  }
}

// Cleanup unregistered users after 2 minutes
setInterval(() => {
  const now = Date.now();

  // Get users sorted by position
  const sortedUsers = [...users.values()].sort((a, b) => a.position - b.position);

  // Find the first expired unregistered user
  const expiredUser = sortedUsers.find(
    u => !u.registered && now - u.createdAt > 120000
  );

  if (expiredUser) {
    users.delete(expiredUser.id);
    console.log("Deleted expired user:", expiredUser.id);

    // Recalculate positions
    const remainingUsers = [...users.values()].sort((a, b) => a.position - b.position);
    remainingUsers.forEach((user, index) => {
      user.position = index + 1;
    });
  }

}, 10000);

// Function to determine user name
function getName(req) {
  const userAgent = req.headers["user-agent"] || "";

  // Detect Apple Shortcut
  if (userAgent.includes("Shortcuts")) {
    return "ShortcutUser";
  }

  // If user provides a name in the URL query
  if (req.query.name) {
    return req.query.name;
  }

  // Default name
  return "User";
}

// COUNTER ROUTE
app.get("/counter", async (req, res) => {
  const ip = getIP(req);

  // Block VPN
  const vpn = await isVPN(ip);
  if (vpn) {
    return res.status(403).json({ error: "VPN/Proxy detected. Access denied." });
  }

  const id = getUniqueId();
  const position = positionCounter++;

  // Determine the name dynamically
  const name = getName(req);

const deleteKey = generateKey();

const user = {
  id,
  name,
  deleteKey, // 👈 add this
  position,
  joined: new Date().toISOString(),
  device: req.headers["user-agent"],
  ip,
  registered: false,
  createdAt: Date.now()
};

  users.set(id, user);

res.setHeader("Content-Type", "application/json");
res.send(JSON.stringify({
  id: user.id,
  name: user.name,
  position: user.position,
  deleteKey: user.deleteKey,
  joined: user.joined,
  device: user.device,
  ip: user.ip
}, null, 2));

// REGISTER ROUTE
app.get("/register/:id", (req, res) => {
  const { id } = req.params;

  const user = users.get(id);

  if (!user) {
    res.setHeader("Content-Type", "application/json");
    return res.send(JSON.stringify({ error: "Invalid or expired ID" }, null, 2));
  }

  user.registered = true;

res.setHeader("Content-Type", "application/json");
res.send(JSON.stringify({
  id: user.id,
  name: user.name,
  position: user.position,
  deleteKey: user.deleteKey,
  joined: user.joined,
  device: user.device,
  ip: user.ip
}, null, 2));

});

//User/:ID ROUTE
app.get("/user/:id", (req, res) => {
  const { id } = req.params;
  const user = users.get(id);

  if (!user) {
    res.setHeader("Content-Type", "application/json");
    return res.send(JSON.stringify({ error: "Invalid or expired ID" }, null, 2));
  }

  res.setHeader("Content-Type", "application/json");
  res.send(JSON.stringify({
    id: user.id,
    name: user.name,
    position: user.position,
    joined: user.joined,
    device: user.device,
    ip: user.ip
  }, null, 2));
});

  // DELETE ROUTE
app.get("/delete/:id", (req, res) => {
  const { id } = req.params;
  const key = req.query.key;

  const user = users.get(id);

  if (!user) {
    return res.send(JSON.stringify({ error: "User not found" }, null, 2));
  }

  // Check user key OR admin key
  if (key !== user.deleteKey && key !== ADMIN_KEY) {
    return res.send(JSON.stringify({ error: "Invalid key" }, null, 2));
  }

  // Delete user
  users.delete(id);

  // Recalculate positions
  const remainingUsers = [...users.values()].sort((a, b) => a.position - b.position);
  remainingUsers.forEach((u, index) => {
    u.position = index + 1;
  });

  res.send(JSON.stringify({
    success: true,
    message: "User deleted",
    deletedId: id
  }, null, 2));
});

// ROOT
app.get("/", (req, res) => {
  res.send("Counter API is running.");
});

// START SERVER
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
