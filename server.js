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
