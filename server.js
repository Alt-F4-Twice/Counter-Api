const express = require("express");
const axios = require("axios");
const cookieParser = require("cookie-parser");
const store = require("./store");

const ADMIN_KEY = process.env.ADMIN_KEY;
const STAFF_DELETE_KEY = process.env.STAFF_DELETE_KEY;

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cookieParser());

const ipCountryCache = new Map();

function isRankedUser(user) {
  return (
    user.position != null &&
    !user.admin &&
    !user.test &&
    user.ip !== "TEST" &&
    user.ip !== "ADMIN"
  );
}

function isSpecialUser(user) {
  return user.admin || user.test || user.ip === "TEST" || user.ip === "ADMIN";
}

async function recalculatePositions() {
  const all = await store.getAllUsers();
  const ranked = all.filter(isRankedUser).sort((a, b) => a.position - b.position);

  for (let index = 0; index < ranked.length; index++) {
    ranked[index].position = index + 1;
    await store.saveUser(ranked[index]);
  }

  await store.setPositionCounter(ranked.length + 1);
}

function generateId() {
  const chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let id = "";
  for (let i = 0; i < 16; i++) {
    id += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return id;
}

function generateKey(length = 20) {
  const chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let key = "";
  for (let i = 0; i < length; i++) {
    key += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return key;
}

async function getUniqueId() {
  let id;
  do {
    id = generateId();
  } while (await store.idExists(id));
  return id;
}

function getIP(req) {
  let ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress;
  if (!ip) return null;
  if (ip.includes(",")) ip = ip.split(",")[0].trim();
  if (ip === "::1") return "127.0.0.1";
  if (ip.startsWith("::ffff:")) ip = ip.replace("::ffff:", "");
  return ip;
}

function sendJson(res, data, status = 200) {
  res.status(status);
  res.setHeader("Content-Type", "application/json");
  res.send(JSON.stringify(data, null, 2));
}

async function getCountryCode(ip) {
  if (!ip || ip === "TEST" || ip === "ADMIN" || ip === "127.0.0.1") {
    return null;
  }
  if (ipCountryCache.has(ip)) return ipCountryCache.get(ip);

  try {
    const res = await axios.get(
      `http://ip-api.com/json/${ip}?fields=status,countryCode`,
      { timeout: 3000 }
    );
    const code = res.data.status === "success" ? res.data.countryCode : null;
    ipCountryCache.set(ip, code);
    return code;
  } catch {
    ipCountryCache.set(ip, null);
    return null;
  }
}

function displayCountryCode(code) {
  if (code === "GB") return "UK";
  if (code === "US") return "USA";
  return code;
}

function formatIpDisplay(ip) {
  if (!ip || ip === "TEST" || ip === "ADMIN") return ip;
  const country = ipCountryCache.get(ip);
  return country ? `${ip} (${displayCountryCode(country)})` : ip;
}

async function prefetchCountries(userList) {
  const ips = [
    ...new Set(
      userList
        .map((u) => u.ip)
        .filter((ip) => ip && ip !== "TEST" && ip !== "ADMIN")
    ),
  ];
  await Promise.all(ips.map((ip) => getCountryCode(ip)));
}

/** Who may delete targetId with this key? */
async function canDelete(targetId, key) {
  const user = await store.getUser(targetId);
  if (!user) return { ok: false, status: 404, error: "User not found" };

  if (key === ADMIN_KEY) {
    return { ok: true, user, mode: "admin" };
  }

  if (key === STAFF_DELETE_KEY) {
    if (key === user.deleteKey) {
      return {
        ok: false,
        status: 403,
        error:
          "Use your personal deleteKey to remove your own account, not the staff key",
      };
    }
    if (user.admin) {
      return {
        ok: false,
        status: 403,
        error: "Staff key cannot delete admin accounts",
      };
    }
    if (!user.registered) {
      return {
        ok: false,
        status: 403,
        error: "Can only delete registered accounts with the staff key",
      };
    }
    return { ok: true, user, mode: "staff" };
  }

  if (key === user.deleteKey) {
    if (!user.registered) {
      return {
        ok: false,
        status: 403,
        error: "Must register before deleting your account",
      };
    }
    return { ok: true, user, mode: "self" };
  }

  return { ok: false, status: 403, error: "Invalid key" };
}

async function performDelete(targetId) {
  await store.deleteUser(targetId);
  await recalculatePositions();
}

function publicUserSummary(user) {
  return {
    id: user.id,
    name: user.name,
    position: user.position,
    joined: user.joined,
    ip: user.ip,
    ipDisplay: formatIpDisplay(user.ip),
    registered: user.registered,
  };
}

function adminUserSummary(user) {
  const summary = {
    id: user.id,
    name: user.name,
    joined: user.joined,
    ip: user.ip,
    ipDisplay: formatIpDisplay(user.ip),
    registered: user.registered,
    viewKey: user.viewKey,
    deleteKey: user.deleteKey,
  };
  if (user.position != null) summary.position = user.position;
  if (user.admin) summary.admin = true;
  if (user.test) summary.test = true;
  return summary;
}

async function getRemainingRankedUsers() {
  const all = await store.getAllUsers();
  return all
    .filter(isRankedUser)
    .sort((a, b) => a.position - b.position)
    .map(publicUserSummary);
}

setInterval(async () => {
  const now = Date.now();
  let deleted = false;
  const all = await store.getAllUsers();

  for (const user of all) {
    if (
      !user.registered &&
      now - new Date(user.joined).getTime() > 180000
    ) {
      await store.deleteUser(user.id);
      deleted = true;
      console.log(`Deleted expired user: ${user.id}`);
    }
  }

  if (deleted) await recalculatePositions();
}, 10000);

function getName(req) {
  const userAgent = req.headers["user-agent"] || "";
  if (userAgent.includes("Shortcuts")) return "ShortcutUser";
  if (req.query.name) return req.query.name;
  return "User";
}

function requireAdminKey(req, res) {
  if (req.query.key !== ADMIN_KEY) {
    res.status(403).json({ error: "Unauthorized" });
    return false;
  }
  return true;
}

app.get("/counter", async (req, res) => {
  const ip = getIP(req);
  if (!ip) return res.status(400).json({ error: "Could not determine IP" });

  const userToken = req.cookies?.userToken;
  if (userToken) {
    const existingUser = await store.getUser(userToken);
    if (existingUser) {
      res.cookie("userToken", existingUser.id);
      res.setHeader("Content-Type", "application/json");
      return res.send(JSON.stringify(existingUser, null, 2));
    }
  }

  const all = await store.getAllUsers();
  const existingUser = all
    .filter((u) => u.ip === ip && isRankedUser(u))
    .sort((a, b) => new Date(a.joined) - new Date(b.joined))[0];

  if (existingUser) {
    res.cookie("userToken", existingUser.id);
    res.setHeader("Content-Type", "application/json");
    return res.send(JSON.stringify(existingUser, null, 2));
  }

  const id = await getUniqueId();
  let positionCounter = await store.getPositionCounter();
  const position = positionCounter++;
  await store.setPositionCounter(positionCounter);

  const user = {
    id,
    name: getName(req),
    position,
    viewKey: generateKey(16),
    deleteKey: generateKey(),
    joined: new Date().toISOString(),
    device: req.headers["user-agent"],
    ip,
    registered: false,
  };

  await store.saveUser(user);
  res.cookie("userToken", id);
  res.setHeader("Content-Type", "application/json");
  res.send(JSON.stringify(user, null, 2));
});

app.get("/test", async (req, res) => {
  if (!requireAdminKey(req, res)) return;

  const user = {
    id: await getUniqueId(),
    name: getName(req),
    position: null,
    viewKey: generateKey(16),
    deleteKey: generateKey(),
    joined: new Date().toISOString(),
    device: req.headers["user-agent"],
    ip: "TEST",
    registered: false,
    test: true,
  };

  await store.saveUser(user);
  res.setHeader("Content-Type", "application/json");
  res.send(JSON.stringify(user, null, 2));
});

app.get("/admin", async (req, res) => {
  if (!requireAdminKey(req, res)) return;

  const user = {
    id: await getUniqueId(),
    name: req.query.name || "Admin",
    position: null,
    viewKey: generateKey(16),
    deleteKey: generateKey(),
    joined: new Date().toISOString(),
    device: req.headers["user-agent"],
    ip: "ADMIN",
    registered: false,
    admin: true,
  };

  await store.saveUser(user);
  res.setHeader("Content-Type", "application/json");
  res.send(JSON.stringify(user, null, 2));
});

// Admin panel — JSON leaderboard (Shortcuts-friendly)
app.get("/leaderboard", async (req, res) => {
  if (req.query.key !== ADMIN_KEY) {
    return sendJson(res, { error: "Unauthorized" }, 403);
  }

  const all = await store.getAllUsers();
  const rankedUsers = all.filter(isRankedUser).sort((a, b) => a.position - b.position);
  const specialUsers = all
    .filter(isSpecialUser)
    .sort((a, b) => new Date(a.joined) - new Date(b.joined));

  await prefetchCountries([...rankedUsers, ...specialUsers]);

  sendJson(res, {
    people: rankedUsers.map((u) => adminUserSummary(u)),
    special: specialUsers.map((u) => adminUserSummary(u)),
    counts: { people: rankedUsers.length, special: specialUsers.length },
  });
});

// Delete info — JSON (use /delete/:id or /delete/position/N to actually delete)
app.get("/delete", async (req, res) => {
  const key = req.query.key;
  if (!key) {
    return sendJson(res, { error: "Missing ?key= (your deleteKey or STAFF_DELETE_KEY)" }, 400);
  }

  if (key === STAFF_DELETE_KEY) {
    if (!STAFF_DELETE_KEY) {
      return sendJson(res, { error: "STAFF_DELETE_KEY is not configured" }, 500);
    }

    const all = await store.getAllUsers();
    const targets = all
      .filter((u) => u.registered && !u.admin)
      .sort((a, b) => new Date(a.joined) - new Date(b.joined));

    return sendJson(res, {
      mode: "staff",
      message: "Call /delete/{id}?key=STAFF_DELETE_KEY or /delete/position/{n}?key=STAFF_DELETE_KEY to delete",
      deletable: targets.map((u) => ({
        id: u.id,
        name: u.name,
        position: u.position,
        ip: u.ip,
        registered: u.registered,
      })),
    });
  }

  const owner = await store.getUserByDeleteKey(key);
  if (!owner) {
    return sendJson(res, { error: "Invalid delete key" }, 403);
  }

  sendJson(res, {
    mode: "self",
    account: {
      id: owner.id,
      name: owner.name,
      position: owner.position,
      registered: owner.registered,
      admin: owner.admin || false,
      test: owner.test || false,
    },
    canDelete: owner.registered,
    message: owner.registered
      ? `Call /delete/${owner.id}?key=${key} to delete your account`
      : `Register first: /register/${owner.id}`,
  });
});

async function findRankedUserByPosition(positionParam) {
  const position = parseInt(positionParam, 10);
  if (!Number.isFinite(position) || position < 1) {
    return { ok: false, status: 400, error: "Invalid position number" };
  }

  const all = await store.getAllUsers();
  const user = all.find((u) => isRankedUser(u) && u.position === position);

  if (!user) {
    return { ok: false, status: 404, error: "No user at that position" };
  }

  return { ok: true, user };
}

// Admin only — look up ranked /counter user by position number
app.get("/user/position/:position", async (req, res) => {
  const key = req.query.key;
  if (key !== ADMIN_KEY) {
    return res.status(403).json({ error: "Unauthorized" });
  }

  const lookup = await findRankedUserByPosition(req.params.position);
  if (!lookup.ok) {
    return res.status(lookup.status).json({ error: lookup.error });
  }

  const user = lookup.user;

  res.setHeader("Content-Type", "application/json");
  res.setHeader("Refresh", "5");
  res.send(JSON.stringify(user, null, 2));
});

app.get("/user/:id", async (req, res) => {
  const { id } = req.params;
  const key = req.query.key;
  const user = await store.getUser(id);
  if (!user) return res.status(404).json({ error: "Invalid or expired ID" });
  if (key !== user.viewKey && key !== ADMIN_KEY) {
    return res.status(403).json({ error: "Invalid key" });
  }

  res.setHeader("Content-Type", "application/json");
  res.setHeader("Refresh", "5");
  res.send(JSON.stringify(user, null, 2));
});

app.get("/register/:id", async (req, res) => {
  const { id } = req.params;
  const user = await store.getUser(id);
  if (!user) return res.status(404).json({ error: "Invalid or expired ID" });

  user.registered = true;
  await store.saveUser(user);
  res.setHeader("Content-Type", "application/json");
  res.send(JSON.stringify(user, null, 2));
});

// Delete ranked user by position (same key rules as /delete/:id)
app.get("/delete/position/:position", async (req, res) => {
  const key = req.query.key;

  const lookup = await findRankedUserByPosition(req.params.position);
  if (!lookup.ok) {
    return sendJson(res, { error: lookup.error }, lookup.status);
  }

  const id = lookup.user.id;
  const check = await canDelete(id, key);
  if (!check.ok) {
    return sendJson(res, { error: check.error }, check.status);
  }

  await performDelete(id);

  sendJson(res, {
    success: true,
    deletedId: id,
    position: lookup.user.position,
    users: await getRemainingRankedUsers(),
  });
});

app.get("/delete/:id", async (req, res) => {
  const { id } = req.params;
  const key = req.query.key;

  const check = await canDelete(id, key);
  if (!check.ok) {
    return sendJson(res, { error: check.error }, check.status);
  }

  await performDelete(id);

  sendJson(res, {
    success: true,
    deletedId: id,
    users: await getRemainingRankedUsers(),
  });
});

app.get("/", (req, res) => {
  res.send("Counter API is running.");
});

async function start() {
  if (!ADMIN_KEY) {
    console.error("ADMIN_KEY environment variable is required");
    process.exit(1);
  }

  await store.initStore();
  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
}

start().catch((err) => {
  console.error("Failed to start:", err);
  process.exit(1);
});
