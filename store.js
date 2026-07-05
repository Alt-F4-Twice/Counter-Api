const memoryUsers = new Map();
const memoryDeleteKeys = new Map();
let memoryPositionCounter = 1;

async function initStore() {}

async function getAllUsers() {
  return [...memoryUsers.values()];
}

async function getUser(id) {
  return memoryUsers.get(id) || null;
}

async function getUserByDeleteKey(key) {
  if (!key) return null;
  const id = memoryDeleteKeys.get(key);
  return id ? memoryUsers.get(id) || null : null;
}

async function saveUser(user) {
  memoryUsers.set(user.id, user);
  memoryDeleteKeys.set(user.deleteKey, user.id);
}

async function deleteUser(id) {
  const user = memoryUsers.get(id);
  if (!user) return false;

  memoryUsers.delete(id);
  memoryDeleteKeys.delete(user.deleteKey);
  return true;
}

async function idExists(id) {
  return memoryUsers.has(id);
}

async function getPositionCounter() {
  return memoryPositionCounter;
}

async function setPositionCounter(value) {
  memoryPositionCounter = value;
}

module.exports = {
  initStore,
  getAllUsers,
  getUser,
  getUserByDeleteKey,
  saveUser,
  deleteUser,
  idExists,
  getPositionCounter,
  setPositionCounter,
};
