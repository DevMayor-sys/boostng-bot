/**
 * BoostNG Data Store
 * Persistent JSON storage for blacklist, owners, blocked users
 * © 2026 Mayor Tech Inc
 */

'use strict';

const fs   = require('fs');
const path = require('path');

const DATA_DIR  = path.join(__dirname, 'data');
const FILES = {
  owners    : path.join(DATA_DIR, 'owners.json'),
  blacklist : path.join(DATA_DIR, 'blacklist.json'),
  threats   : path.join(DATA_DIR, 'threats.json'),
};

// Ensure data directory exists
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

function readJSON(file, fallback) {
  try {
    if (fs.existsSync(file)) return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch(e) {}
  return fallback;
}

function writeJSON(file, data) {
  try { fs.writeFileSync(file, JSON.stringify(data, null, 2), 'utf8'); return true; }
  catch(e) { console.error('[Store] Write error:', e.message); return false; }
}

// ─── Owners ───────────────────────────────────────────────────────────────────
function loadOwners(mainOwner) {
  var stored = readJSON(FILES.owners, { owners: [] });
  var set = new Set(stored.owners || []);
  if (mainOwner) set.add(String(mainOwner).replace(/[^0-9]/g, ''));
  return set;
}

function saveOwners(ownerSet) {
  return writeJSON(FILES.owners, { owners: Array.from(ownerSet) });
}

function addOwner(ownerSet, number) {
  var num = String(number).replace(/[^0-9]/g, '');
  if (!num || num.length < 7 || num.length > 15) return { ok: false, reason: 'Invalid number format' };
  if (ownerSet.has(num)) return { ok: false, reason: 'Already an owner' };
  ownerSet.add(num);
  saveOwners(ownerSet);
  return { ok: true, number: num };
}

function removeOwner(ownerSet, number, mainOwner) {
  var num = String(number).replace(/[^0-9]/g, '');
  var main = String(mainOwner || '').replace(/[^0-9]/g, '');
  if (num === main) return { ok: false, reason: 'Cannot remove main owner' };
  if (!ownerSet.has(num)) return { ok: false, reason: 'Not an owner' };
  ownerSet.delete(num);
  saveOwners(ownerSet);
  return { ok: true, number: num };
}

// ─── Blacklist ────────────────────────────────────────────────────────────────
function loadBlacklist() {
  var stored = readJSON(FILES.blacklist, { entries: {} });
  return new Map(Object.entries(stored.entries || {}));
}

function saveBlacklist(map) {
  var obj = {};
  map.forEach(function(v, k) { obj[k] = v; });
  return writeJSON(FILES.blacklist, { entries: obj });
}

function blacklistAdd(map, jid, reason, level) {
  var entry = map.get(jid) || { reason, level, count: 0, firstSeen: Date.now() };
  entry.count++;
  entry.reason  = reason;
  entry.level   = level;
  entry.lastSeen = Date.now();
  map.set(jid, entry);
  saveBlacklist(map);
  return entry;
}

// ─── Threat log ───────────────────────────────────────────────────────────────
function logThreat(jid, threat, context) {
  var threats = readJSON(FILES.threats, { log: [] });
  threats.log.unshift({
    jid, threat, context,
    time: new Date().toISOString(),
    ts  : Date.now(),
  });
  // Keep last 500 entries
  if (threats.log.length > 500) threats.log = threats.log.slice(0, 500);
  writeJSON(FILES.threats, threats);
}

module.exports = { loadOwners, saveOwners, addOwner, removeOwner, loadBlacklist, saveBlacklist, blacklistAdd, logThreat };
