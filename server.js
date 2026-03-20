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
  for (let i = 0; i < 16; i++) {
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
  let deletedAny = false;

  // Delete unregistered users older than 2 minutes
  for (let [key, user] of users) {
    if (!user.registered && now - user.createdAt > 120000) {
      users.delete(key);
      deletedAny = true;
      console.log("Deleted expired user:", user.id);
    }
  }

  // If anyone was deleted, recalc positions for remaining users
  if (deletedAny) {
    // Sort by original position
    const sortedUsers = [...users.values()].sort((a, b) => a.position - b.position);
    sortedUsers.forEach((user, index) => {
      user.position = index + 1; // new positions start at 1
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

  const user = {
    id,
    name, // dynamic name
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
