const express = require("express");
const axios = require("axios");
const { v4: uuidv4 } = require("uuid");

const app = express();
const PORT = process.env.PORT || 3000;

// In-memory storage (replace with DB for production)
let users = new Map();
let positionCounter = 1;

// Generate 14-character ID
function generateId() {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let id = "";
  for (let i = 0; i < 14; i++) {
    id += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return id;
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
  for (let [key, user] of users) {
    if (!user.registered && now - user.createdAt > 120000) {
      users.delete(key);
      console.log("Deleted expired user:", user.id);
    }
  }
}, 10000);

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

  const user = {
    id,
    name: "User",
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
    joined: user.joined,
    device: user.device,
    ip: user.ip
  }, null, 2));
});

// REGISTER ROUTE
app.get("/register/:id", (req, res) => {
  const { id } = req.params;

  const user = users.get(id);

  if (!user) {
    return res.status(404).json({ error: "Invalid or expired ID" });
  }

  user.registered = true;

  res.json({
    success: true,
    message: "User registered successfully",
    user: {
      id: user.id,
      position: user.position
    }
  });
});

// ROOT
app.get("/", (req, res) => {
  res.send("Counter API is running.");
});

// START SERVER
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
