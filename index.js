/**
 * BoostNG Assistant Bot — Enterprise Hardened Edition
 * By Mayor Tech Inc © 2026
 *
 * HARDENING CHANGES:
 * - Global uncaughtException + unhandledRejection handlers
 * - Exponential backoff reconnection (no reconnect storms)
 * - safeSend() wrapper — never crashes on send failure
 * - safeAsync() wrapper — catches all async errors
 * - All fs operations made async / cached
 * - Bounded Maps with auto-cleanup (no memory leaks)
 * - Per-user rate limiting with cooldowns
 * - AI request timeout + retry limit
 * - Defensive null checks everywhere (Baileys payloads)
 * - CPU-safe regex (no catastrophic backtracking)
 * - Memory usage monitor (logs warning at 80% heap)
 * - Groq API timeout + circuit breaker
 * - Session corruption detection + auto-recovery
 * - HTTP server with /health endpoint
 * - All blocking fs.readFileSync replaced with cached async reads
 */

'use strict';
require('dotenv').config();

// ═══════════════════════════════════════════════════════════════════════════════
// 1. GLOBAL PROCESS PROTECTION — must be first
//    Prevents crashes from uncaught errors anywhere in the codebase
// ═══════════════════════════════════════════════════════════════════════════════
process.on('uncaughtException', function(err) {
  console.error('[FATAL] Uncaught Exception:', err.message);
  console.error(err.stack);
  // Don't exit — log and continue (Railway will restart if truly dead)
});

process.on('unhandledRejection', function(reason, promise) {
  console.error('[FATAL] Unhandled Promise Rejection:', reason && reason.message || reason);
  // Don't exit — prevents bot restart loops from minor async errors
});

process.on('warning', function(warning) {
  console.warn('[WARN]', warning.name, warning.message);
});

process.on('SIGTERM', function() {
  console.log('[BOT] SIGTERM received — graceful shutdown');
  process.exit(0);
});

process.on('SIGINT', function() {
  console.log('[BOT] SIGINT received — graceful shutdown');
  process.exit(0);
});

// ═══════════════════════════════════════════════════════════════════════════════
// 2. IMPORTS
// ═══════════════════════════════════════════════════════════════════════════════
const {
  default: makeWASocket,
  useMultiFileAuthState,
  DisconnectReason,
  fetchLatestBaileysVersion,
  makeCacheableSignalKeyStore,
} = require('@whiskeysockets/baileys');

const pino   = require('pino');
const qrcode = require('qrcode-terminal');
const QRCode = require('qrcode');
const Groq   = require('groq-sdk');
const http   = require('http');
const fs     = require('fs');
const fsp    = require('fs').promises;
const path   = require('path');

// Security engine
const SEC = require('./security');
// Protocol-level runtime hardening
const H = require('./hardening');

// ═══════════════════════════════════════════════════════════════════════════════
// 3. CONFIG
// ═══════════════════════════════════════════════════════════════════════════════
const CONFIG = {
  WA_CHANNEL   : 'https://whatsapp.com/channel/0029Vb84NAUFXUui0ueD3H1O',
  TELEGRAM_GC  : 'https://t.me/mayor_d_dev',
  WEBSITE      : 'https://boosthubng.pages.dev',
  RAILWAY_URL  : process.env.RAILWAY_URL || 'https://web-production-94012.up.railway.app',
  WATERMARK    : '\n\n━━━━━━━━━━━━━━━━━━━━━\n        \ud83c\udfc6 MAYOR TECH INC\n\u00a9 2026 \u2014 ALL RIGHTS RESERVED\n━━━━━━━━━━━━━━━━━━━━━',
  GROQ_KEY     : process.env.GROQ_API_KEY || '',
  JOIN_KEYWORD : 'JOINED',
  PORT         : parseInt(process.env.PORT || '3000', 10),
  LOGO_PATH    : path.join(__dirname, 'logo.jpg'),
  BOT_MODE     : process.env.BOT_MODE || 'public',
  // Reconnection — exponential backoff
  RECONNECT_BASE : 3000,
  RECONNECT_MAX  : 60000,
  // Rate limits
  RATE_LIMIT_WINDOW : 60000,  // 1 min
  RATE_LIMIT_MAX    : 15,     // messages per min per user
  AI_COOLDOWN_MS    : 3000,   // min 3s between AI calls per user
  AI_TIMEOUT_MS     : 8000,   // max 8s per AI request
  AI_MAX_RETRIES    : 1,
  // Memory
  CACHE_MAX         : 1000,   // max entries in any Map
  CLEANUP_INTERVAL  : 300000, // 5 min cleanup
  MEM_WARN_RATIO    : 0.80,   // warn at 80% heap
};

const MAIN_OWNER = (process.env.OWNER_NUMBER || '').replace(/[^0-9]/g, '');
const BOT_MODE_CURRENT = { value: CONFIG.BOT_MODE };

const STAFF = [
  { name: process.env.STAFF1_NAME || 'Staff 1', number: process.env.STAFF1_NUMBER || '', online: false },
  { name: process.env.STAFF2_NAME || 'Staff 2', number: process.env.STAFF2_NUMBER || '', online: false },
  { name: process.env.STAFF3_NAME || 'Staff 3', number: process.env.STAFF3_NUMBER || '', online: false },
  { name: process.env.STAFF4_NAME || 'Staff 4', number: process.env.STAFF4_NUMBER || '', online: false },
  { name: process.env.STAFF5_NAME || 'Staff 5', number: process.env.STAFF5_NUMBER || '', online: false },
];

// ═══════════════════════════════════════════════════════════════════════════════
// 4. PERSISTENT STORE — async, cached, safe
// ═══════════════════════════════════════════════════════════════════════════════
const DATA_DIR = path.join(__dirname, 'data');
const DATA_FILES = {
  owners    : path.join(DATA_DIR, 'owners.json'),
  blacklist : path.join(DATA_DIR, 'blacklist.json'),
  threats   : path.join(DATA_DIR, 'threats.json'),
};

// Ensure data dir exists synchronously ONCE at startup (acceptable at boot)
try { if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true }); } catch(e) {}

// Safe async JSON read with fallback
async function readJSONAsync(file, fallback) {
  try {
    var data = await fsp.readFile(file, 'utf8');
    return JSON.parse(data);
  } catch(e) { return fallback; }
}

// Safe async JSON write — non-blocking
async function writeJSONAsync(file, data) {
  try { await fsp.writeFile(file, JSON.stringify(data, null, 2), 'utf8'); return true; }
  catch(e) { console.error('[Store] Write error:', e.message); return false; }
}

// In-memory owner set — loaded async at startup
var OWNERS = new Set();
if (MAIN_OWNER) OWNERS.add(MAIN_OWNER);

// In-memory blacklist
var BLACKLIST = new Map();

// Load persistent data at startup
async function loadPersistentData() {
  try {
    var ownerData = await readJSONAsync(DATA_FILES.owners, { owners: [] });
    (ownerData.owners || []).forEach(function(n) { OWNERS.add(String(n)); });
    var blData = await readJSONAsync(DATA_FILES.blacklist, { entries: {} });
    Object.entries(blData.entries || {}).forEach(function(e) { BLACKLIST.set(e[0], e[1]); });
    console.log('[Store] Loaded ' + OWNERS.size + ' owners, ' + BLACKLIST.size + ' blacklisted');
  } catch(e) { console.error('[Store] Load error:', e.message); }
}

async function saveOwners() {
  await writeJSONAsync(DATA_FILES.owners, { owners: Array.from(OWNERS) });
}

async function saveBlacklist() {
  var obj = {};
  BLACKLIST.forEach(function(v, k) { obj[k] = v; });
  await writeJSONAsync(DATA_FILES.blacklist, { entries: obj });
}

// ═══════════════════════════════════════════════════════════════════════════════
// 5. BOUNDED CACHE — prevents unbounded memory growth
//    Auto-evicts oldest entry when limit reached
// ═══════════════════════════════════════════════════════════════════════════════
function boundedSet(map) {
  if (map.size >= CONFIG.CACHE_MAX) {
    map.delete(map.keys().next().value);
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 6. RUNTIME STATE — all bounded
// ═══════════════════════════════════════════════════════════════════════════════
var verifiedUsers  = new Set();
var userSessions   = new H.BoundedMap(1000, 7200000);  // TTL 2hr, max 1000
var rateLimiter    = new H.BoundedMap(2000, 60000);    // TTL 1min, max 2000
var tempBlocked    = new H.BoundedMap(2000, 600000);   // TTL 10min, max 2000
var latestQR       = null;
var globalSock     = null;
var reconnectCount = 0;
var reconnectDelay = CONFIG.RECONNECT_BASE;

// Logo buffer — cached in memory after first read (avoids repeated disk I/O)
var logoBuf = null;
async function getLogoBuf() {
  if (logoBuf) return logoBuf;
  try { logoBuf = await fsp.readFile(CONFIG.LOGO_PATH); } catch(e) { logoBuf = null; }
  return logoBuf;
}

// ═══════════════════════════════════════════════════════════════════════════════
// 7. STATS + MONITORING
// ═══════════════════════════════════════════════════════════════════════════════
var STATS = {
  startTime  : Date.now(),
  scanned    : 0,
  blocked    : 0,
  aiReplies  : 0,
  pairings   : 0,
  reconnects : 0,
  errors     : 0,
  memWarnings: 0,
};

function getUptime() {
  var ms = Date.now() - STATS.startTime;
  var d = Math.floor(ms / 86400000);
  var h = Math.floor((ms % 86400000) / 3600000);
  var m = Math.floor((ms % 3600000) / 60000);
  var s = Math.floor((ms % 60000) / 1000);
  if (d > 0) return d + 'd ' + h + 'h ' + m + 'm';
  if (h > 0) return h + 'h ' + m + 'm ' + s + 's';
  return m + 'm ' + s + 's';
}

function getMemStats() {
  var mem = process.memoryUsage();
  return {
    heapUsed  : Math.round(mem.heapUsed / 1024 / 1024) + 'MB',
    heapTotal : Math.round(mem.heapTotal / 1024 / 1024) + 'MB',
    rss       : Math.round(mem.rss / 1024 / 1024) + 'MB',
    ratio     : mem.heapUsed / mem.heapTotal,
  };
}

// checkMemory delegated to H.checkMemory

// ═══════════════════════════════════════════════════════════════════════════════
// 8. PERMISSION HELPERS
// ═══════════════════════════════════════════════════════════════════════════════
function numOf(jid) {
  return ((jid || '').split('@')[0] || '').replace(/[^0-9]/g, '');
}

function isOwner(jid) {
  var num = numOf(jid);
  if (!num) return false;
  if (OWNERS.has(num)) return true;
  if (MAIN_OWNER && num === MAIN_OWNER) return true;
  var env = (process.env.OWNER_NUMBER || '').replace(/[^0-9]/g, '');
  return !!env && num === env;
}

function isOfficer(jid) {
  if (isOwner(jid)) return true;
  var num = numOf(jid);
  var officers = (process.env.OFFICER_NUMBERS || '').split(',')
    .map(function(n) { return n.replace(/[^0-9]/g, '').trim(); })
    .filter(Boolean);
  return officers.includes(num);
}

// ═══════════════════════════════════════════════════════════════════════════════
// 9. RATE LIMITER — per-user message rate limiting
//    Prevents spam floods from any single user
// ═══════════════════════════════════════════════════════════════════════════════
function isRateLimited(jid) {
  var now = Date.now();
  var r = rateLimiter.get(jid);
  if (!r || now > r.resetAt) {
    boundedSet(rateLimiter);
    rateLimiter.set(jid, { count: 1, resetAt: now + CONFIG.RATE_LIMIT_WINDOW });
    return false;
  }
  r.count++;
  if (r.count > CONFIG.RATE_LIMIT_MAX) return true;
  return false;
}

// ═══════════════════════════════════════════════════════════════════════════════
// 10. SAFE WRAPPERS — never crash on send/async failures
// ═══════════════════════════════════════════════════════════════════════════════

var safeAsync = H.safeAsync;

// safeSend provided by hardening engine (with timeout + retry)
async function safeSend(sock, jid, content, opts) { return H.safeSend(sock, jid, content, opts); }

// safeDelete provided by hardening engine
async function safeDelete(sock, msg) { return H.safeDelete(sock, msg); }

var safeJSON = H.safeJsonParse;

// withTimeout, safeAsync, safeSend, safeDelete provided by hardening engine
var withTimeout = H.withTimeout;

// ═══════════════════════════════════════════════════════════════════════════════
// 11. WATERMARK
// ═══════════════════════════════════════════════════════════════════════════════
function wm(t) { return (t || '') + CONFIG.WATERMARK; }

// ═══════════════════════════════════════════════════════════════════════════════
// 12. SAFE SEND HELPERS
// ═══════════════════════════════════════════════════════════════════════════════
async function send(sock, jid, text, q) {
  return safeSend(sock, jid, { text: String(text || '') }, q ? { quoted: q } : undefined);
}

async function sendMenu(sock, jid, caption, isGroup) {
  var buf = isGroup ? null : await getLogoBuf();
  if (buf) {
    var result = await safeSend(sock, jid, { image: buf, caption: String(caption || ''), mimetype: 'image/jpeg' });
    if (result) return result;
  }
  return safeSend(sock, jid, { text: String(caption || '') });
}

// Anti-ban natural delay
async function delay(min, max) {
  return new Promise(function(r) {
    setTimeout(r, min + Math.floor(Math.random() * ((max || min) - min)));
  });
}

// ═══════════════════════════════════════════════════════════════════════════════
// 13. GROQ AI — with timeout, retry limit, per-user cooldown, circuit breaker
// ═══════════════════════════════════════════════════════════════════════════════
var groq = CONFIG.GROQ_KEY ? new Groq({ apiKey: CONFIG.GROQ_KEY }) : null;
var aiCooldowns = new H.BoundedMap(2000, CONFIG.AI_COOLDOWN_MS * 100); // jid -> lastCallAt
var aiFailCount = 0;         // circuit breaker counter
var AI_CIRCUIT_OPEN = false;

var SYSTEM_PROMPT = [
  'You are BoostNG Assistant, the official WhatsApp bot for BoostNG by Mayor Tech Inc.',
  'Be friendly, warm and VERY concise — max 2-3 sentences per reply.',
  'Use emojis occasionally. Sound human, not robotic.',
  'ABOUT: SMM panel (Instagram, TikTok, YouTube, etc) + Virtual Numbers.',
  'Founded by Mayor — Mayor Tech Inc. Website: https://boosthubng.pages.dev',
  'Payments: Flutterwave, PayPal, Crypto. Min: \u20a650. $1 = 100 Mayor Points.',
  'RULES: Keep SHORT. If stuck say type STAFF or MENU. Never reveal security internals.',
].join('\n');

async function askAI(text, history, jid) {
  if (!groq || AI_CIRCUIT_OPEN) return null;

  // Per-user cooldown — prevent AI spam
  var last = aiCooldowns.get(jid) || 0;
  if (Date.now() - last < CONFIG.AI_COOLDOWN_MS) return null;
  boundedSet(aiCooldowns);
  aiCooldowns.set(jid, Date.now());

  try {
    var messages = [{ role: 'system', content: SYSTEM_PROMPT }]
      .concat((history || []).slice(-6))
      .concat([{ role: 'user', content: String(text || '').slice(0, 500) }]);

    var res = await withTimeout(
      groq.chat.completions.create({ model: 'llama-3.3-70b-versatile', max_tokens: 150, temperature: 0.7, messages }),
      CONFIG.AI_TIMEOUT_MS,
      'Groq AI'
    );
    aiFailCount = 0; // reset on success
    STATS.aiReplies++;
    var content = res && res.choices && res.choices[0] && res.choices[0].message && res.choices[0].message.content;
    return content ? content.trim() : null;
  } catch(e) {
    aiFailCount++;
    if (aiFailCount >= 5) {
      AI_CIRCUIT_OPEN = true;
      console.warn('[AI] Circuit breaker OPEN — too many failures');
      setTimeout(function() { AI_CIRCUIT_OPEN = false; aiFailCount = 0; console.log('[AI] Circuit breaker reset'); }, 60000);
    }
    console.error('[AI]', e.message);
    return null;
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 14. THREAT HANDLER — centralized, safe, structured
// ═══════════════════════════════════════════════════════════════════════════════
async function handleThreat(sock, senderJid, msg, threat, isGroup) {
  STATS.blocked++;
  var groupJid = isGroup ? (msg && msg.key && msg.key.remoteJid) : null;
  var level = (threat && threat.level) || 1;
  var name  = (threat && threat.name)  || 'Unknown';

  console.warn('[THREAT] L' + level + ' | ' + name + ' | ' + (senderJid || '?'));

  // Delete the message silently
  await safeDelete(sock, msg);

  if (level >= 3) {
    // HIGH — permanent blacklist + WA block + kick
    var entry = BLACKLIST.get(senderJid) || { reason: name, count: 0, firstSeen: Date.now() };
    entry.count++; entry.lastSeen = Date.now(); entry.reason = name;
    boundedSet(BLACKLIST);
    BLACKLIST.set(senderJid, entry);
    await saveBlacklist();

    // Real WhatsApp block
    await safeAsync(function() { return sock.updateBlockStatus(senderJid, 'block'); }, 'WA block');

    // Kick from group
    if (isGroup && groupJid) {
      await safeAsync(function() { return sock.groupParticipantsUpdate(groupJid, [senderJid], 'remove'); }, 'kick');
    }

    // Alert Mayor
    if (MAIN_OWNER) {
      var alertText = '\ud83d\udea8 HIGH THREAT\n\n+' + numOf(senderJid) + '\nType: ' + name + '\nOffense #' + entry.count + CONFIG.WATERMARK;
      await safeAsync(function() { return safeSend(sock, MAIN_OWNER + '@s.whatsapp.net', { text: alertText }); }, 'alert');
    }

    // Warn attacker
    await safeAsync(function() {
      return safeSend(sock, senderJid, { text: '\u26d4 Your account has been permanently blocked and reported for sending malicious content.' + CONFIG.WATERMARK });
    }, 'warn attacker');

  } else if (level === 2) {
    // MEDIUM — temp block 10 min + kick
    boundedSet(tempBlocked);
    tempBlocked.set(senderJid, Date.now() + 600000);
    if (isGroup && groupJid) {
      await safeAsync(function() { return sock.groupParticipantsUpdate(groupJid, [senderJid], 'remove'); }, 'kick medium');
    }
  }

  // Notify group
  if (isGroup && groupJid && level >= 2) {
    await safeAsync(function() {
      return safeSend(sock, groupJid, { text: '\ud83d\udee1\ufe0f A malicious message was detected and the sender has been removed.' + CONFIG.WATERMARK });
    }, 'notify group');
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 15. OWNER COMMAND HANDLER — flexible prefix, persistent
// ═══════════════════════════════════════════════════════════════════════════════
async function handleOwnerCmd(sock, jid, text, msg) {
  var clean = (text || '').trim().replace(/^[./!\s]+/, '');

  // .pair / pair any number
  var pairM = clean.match(/pair\s+\+?(\d{7,15})/i);
  if (pairM) {
    return safeAsync(async function() {
      var code = await withTimeout(sock.requestPairingCode(pairM[1] + '@s.whatsapp.net'), 10000, 'pairCode');
      STATS.pairings++;
      await send(sock, jid, wm('\ud83d\udd17 *Pairing Code*\n\n\ud83d\udcf1 +' + pairM[1] + '\n\ud83d\udd11 Code: *' + code + '*\n\n1. WhatsApp \u2192 Linked Devices\n2. Link a Device\n3. Link with phone number\n4. Enter code \u2705\n\n\u23f0 Expires in 60s!'), msg);
    }, 'pair');
  }

  // mode
  if (/mode\s+(public|private)/i.test(clean)) {
    BOT_MODE_CURRENT.value = clean.toLowerCase().includes('private') ? 'private' : 'public';
    return send(sock, jid, wm('\ud83c\udf10 Mode: *' + BOT_MODE_CURRENT.value.toUpperCase() + '*'), msg);
  }

  // Add_owner
  var addM = clean.match(/add.?owner\s+\+?(\d{7,15})/i);
  if (addM) {
    var num = addM[1].replace(/[^0-9]/g, '');
    if (OWNERS.has(num)) return send(sock, jid, wm('\u274c Already an owner'), msg);
    OWNERS.add(num);
    await saveOwners();
    console.log('[Owner] Added: +' + num);
    return send(sock, jid, wm('\u2705 *+' + num + '* added as owner!'), msg);
  }

  // Remove_owner
  var rmM = clean.match(/remove.?owner\s+\+?(\d{7,15})/i);
  if (rmM) {
    var rnum = rmM[1].replace(/[^0-9]/g, '');
    if (rnum === MAIN_OWNER) return send(sock, jid, wm('\u274c Cannot remove main owner'), msg);
    if (!OWNERS.has(rnum)) return send(sock, jid, wm('\u274c Not an owner'), msg);
    OWNERS.delete(rnum);
    await saveOwners();
    return send(sock, jid, wm('\u2705 *+' + rnum + '* removed from owners.'), msg);
  }

  // List_owners
  if (/list.?owners?/i.test(clean)) {
    var list = Array.from(OWNERS).map(function(n, i) { return (i+1) + '. +' + n + (n === MAIN_OWNER ? ' (Main)' : ''); }).join('\n');
    return send(sock, jid, wm('\ud83d\udc51 *Owners (' + OWNERS.size + ')*\n\n' + (list || 'None')), msg);
  }

  return false;
}

// ═══════════════════════════════════════════════════════════════════════════════
// 16. GROUP ADMIN COMMANDS
// ═══════════════════════════════════════════════════════════════════════════════
async function isGroupAdmin(sock, jid, senderJid) {
  return safeAsync(async function() {
    var meta = await sock.groupMetadata(jid);
    return meta.participants.filter(function(p) { return p.admin; }).map(function(p) { return p.id; }).includes(senderJid);
  }, 'isGroupAdmin') || false;
}

function getMentioned(msg) {
  try {
    var ext = msg && msg.message && msg.message.extendedTextMessage;
    return (ext && ext.contextInfo && ext.contextInfo.mentionedJid) || [];
  } catch(e) { return []; }
}

async function handleGC(sock, jid, text, msg) {
  var raw  = (text || '').trim();
  var cmd  = raw.toLowerCase();
  var args = raw.split(/\s+/);
  var senderJid = (msg && msg.key && msg.key.participant) || jid;
  var mentioned  = getMentioned(msg);

  // Owner commands work in GC too
  if (isOwner(senderJid) || isOfficer(senderJid)) {
    var ownerResult = await handleOwnerCmd(sock, jid, raw, msg);
    if (ownerResult !== false) return;
  }

  // Info commands — anyone
  var BORDER_TOP = '\u2554\u2550\u254b\u254b\u254b\u2500\u2500\u2500 \u2022 \u2500\u2500\u2500\u254b\u254b\u254b\u2550\u2557';
  var BORDER_BOT = '\u255a\u2550\u254b\u254b\u254b\u2500\u2500\u2500 \u2022 \u2500\u2500\u2500\u254b\u254b\u254b\u2550\u255d';

  if (cmd === '!menu' || cmd === '!help') {
    return send(sock, jid, BORDER_TOP + '\n     \u2022 BOOST NG \u2022\n' + BORDER_BOT + '\n\n\ud83d\udd39 *USER COMMANDS*\n  !menu !ping !uptime !status !info !link !staff\n\n\ud83d\udc51 *ADMIN COMMANDS*\n  !add [num] !kick [@] !promote [@] !demote [@]\n  !setname !setdesc !setpic !everyone !revoke\n\n\ud83d\udee1\ufe0f Security: 72 layers active\n\n' + BORDER_TOP + '\n  POWERED BY MAYOR TECH INC\n' + BORDER_BOT, msg);
  }
  if (cmd === '!ping') {
    var t0 = Date.now();
    return send(sock, jid, wm('\ud83c\udfd3 Pong! ' + (Date.now()-t0) + 'ms | Uptime: ' + getUptime()), msg);
  }
  if (cmd === '!uptime') return send(sock, jid, wm('\u23f1\ufe0f *' + getUptime() + '* | Scanned: ' + STATS.scanned + ' | Blocked: ' + STATS.blocked), msg);
  if (cmd === '!status') return send(sock, jid, wm('\ud83d\udee1\ufe0f 72-layer security ACTIVE\n\ud83d\udcec Scanned: ' + STATS.scanned + '\n\ud83d\udee1\ufe0f Blocked: ' + STATS.blocked + '\n\u23f1\ufe0f Uptime: ' + getUptime()), msg);
  if (cmd === '!staff') {
    var onStaff = STAFF.filter(function(s) { return s.online && s.number; });
    return send(sock, jid, wm(onStaff.length ? '\ud83d\udc68\u200d\ud83d\udcbc Online:\n' + onStaff.map(function(s) { return '\u2022 ' + s.name + ': wa.me/' + s.number; }).join('\n') : '\ud83d\udd34 All staff offline\n\n' + CONFIG.TELEGRAM_GC), msg);
  }
  if (cmd === '!protect' || cmd === '!unprotect') return send(sock, jid, wm('\ud83d\udee1\ufe0f Protection always *ACTIVE* \u2014 cannot be disabled!'), msg);

  if (cmd === '!info') {
    var meta = await safeAsync(function() { return sock.groupMetadata(jid); }, 'groupMeta');
    if (!meta) return send(sock, jid, wm('\u274c Could not fetch group info'), msg);
    return send(sock, jid, wm('\u2139\ufe0f *' + (meta.subject||'?') + '*\n\ud83d\udc65 Members: ' + meta.participants.length + '\n\ud83d\udc51 Admins: ' + meta.participants.filter(function(p){return p.admin;}).length), msg);
  }

  if (cmd === '!link') {
    var inv = await safeAsync(function() { return sock.groupInviteCode(jid); }, 'inviteCode');
    return send(sock, jid, inv ? wm('\ud83d\udd17 https://chat.whatsapp.com/' + inv) : wm('\u274c Need bot to be admin'), msg);
  }

  // Admin-only commands
  var adminCmds = ['!add','!kick','!promote','!demote','!setname','!setdesc','!setpic','!everyone','!tagall','!revoke'];
  if (adminCmds.some(function(c) { return cmd.startsWith(c); })) {
    var adminOk = await isGroupAdmin(sock, jid, senderJid);
    if (!adminOk) return send(sock, jid, wm('\u26d4 Admins only'), msg);
  }

  if (args[0] && args[0].toLowerCase() === '!add') {
    var addNum = (args[1] || '').replace(/[^0-9]/g, '');
    if (!addNum) return send(sock, jid, wm('\u274c !add +234...'), msg);
    var addRes = await safeAsync(function() { return sock.groupParticipantsUpdate(jid, [addNum + '@s.whatsapp.net'], 'add'); }, 'add');
    var st = addRes && addRes[0] && addRes[0].status;
    return send(sock, jid, wm(st === '200' ? '\u2705 +' + addNum + ' added!' : '\u274c Could not add (code: ' + st + ')'), msg);
  }
  if (args[0] && args[0].toLowerCase() === '!kick') {
    if (!mentioned.length) return send(sock, jid, wm('\u274c !kick @person'), msg);
    await safeAsync(function() { return sock.groupParticipantsUpdate(jid, mentioned, 'remove'); }, 'kick');
    return send(sock, jid, wm('\u2705 Member removed'), msg);
  }
  if (args[0] && args[0].toLowerCase() === '!promote') {
    if (!mentioned.length) return send(sock, jid, wm('\u274c !promote @person'), msg);
    await safeAsync(function() { return sock.groupParticipantsUpdate(jid, mentioned, 'promote'); }, 'promote');
    return send(sock, jid, wm('\u2705 Promoted! \ud83d\udc51'), msg);
  }
  if (args[0] && args[0].toLowerCase() === '!demote') {
    if (!mentioned.length) return send(sock, jid, wm('\u274c !demote @person'), msg);
    await safeAsync(function() { return sock.groupParticipantsUpdate(jid, mentioned, 'demote'); }, 'demote');
    return send(sock, jid, wm('\u2705 Admin removed'), msg);
  }
  if (args[0] && args[0].toLowerCase() === '!setname') {
    var n = args.slice(1).join(' ');
    if (!n) return send(sock, jid, wm('\u274c !setname Name'), msg);
    await safeAsync(function() { return sock.groupUpdateSubject(jid, n); }, 'setname');
    return send(sock, jid, wm('\u2705 Renamed to *' + n + '*'), msg);
  }
  if (args[0] && args[0].toLowerCase() === '!setdesc') {
    var d = args.slice(1).join(' ');
    if (!d) return send(sock, jid, wm('\u274c !setdesc Description'), msg);
    await safeAsync(function() { return sock.groupUpdateDescription(jid, d); }, 'setdesc');
    return send(sock, jid, wm('\u2705 Description updated'), msg);
  }
  if (args[0] && args[0].toLowerCase() === '!setpic') {
    var ctx = msg && msg.message && msg.message.extendedTextMessage && msg.message.extendedTextMessage.contextInfo;
    if (!ctx || !ctx.quotedMessage || !ctx.quotedMessage.imageMessage) return send(sock, jid, wm('\u274c Reply to an image with !setpic'), msg);
    var picBuf = await safeAsync(function() { return sock.downloadMediaMessage({ message: { imageMessage: ctx.quotedMessage.imageMessage }, key: { remoteJid: jid } }); }, 'downloadPic');
    if (!picBuf) return send(sock, jid, wm('\u274c Could not download image'), msg);
    await safeAsync(function() { return sock.updateProfilePicture(jid, picBuf); }, 'setPic');
    return send(sock, jid, wm('\u2705 Group picture updated!'), msg);
  }
  if (cmd === '!everyone' || cmd === '!tagall') {
    var meta2 = await safeAsync(function() { return sock.groupMetadata(jid); }, 'meta2');
    if (!meta2) return send(sock, jid, wm('\u274c Could not fetch members'), msg);
    var members = meta2.participants.map(function(p) { return p.id; });
    var tagText = '\ud83d\udce2 *Attention!*\n' + members.map(function(m) { return '@' + m.split('@')[0]; }).join(' ') + CONFIG.WATERMARK;
    await safeAsync(function() { return sock.sendMessage(jid, { text: tagText, mentions: members }); }, 'tagAll');
    return;
  }
  if (cmd === '!revoke') {
    await safeAsync(function() { return sock.groupRevokeInvite(jid); }, 'revoke');
    var nc = await safeAsync(function() { return sock.groupInviteCode(jid); }, 'newCode');
    return send(sock, jid, nc ? wm('\u2705 Link reset!\nhttps://chat.whatsapp.com/' + nc) : wm('\u274c Could not reset'), msg);
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 17. DM MENU HANDLER
// ═══════════════════════════════════════════════════════════════════════════════
var BORDER_TOP = '\u2554\u2550\u254b\u254b\u254b\u2500\u2500\u2500 \u2022 \u2500\u2500\u2500\u254b\u254b\u254b\u2550\u2557';
var BORDER_BOT = '\u255a\u2550\u254b\u254b\u254b\u2500\u2500\u2500 \u2022 \u2500\u2500\u2500\u254b\u254b\u254b\u2550\u255d';
var POWERED    = '  POWERED BY MAYOR TECH INC';

function T_menu() {
  return BORDER_TOP + '\n     \u2022 BOOST NG \u2022\n' + BORDER_BOT + '\n\n\ud83d\udd39 *MAIN MENU*\n\n' +
    '  1\ufe0f\u20e3  \ud83d\udce6 SMM Services\n  2\ufe0f\u20e3  \ud83d\udd0d Order Status\n' +
    '  3\ufe0f\u20e3  \ud83d\udcb3 Top Up Wallet\n  4\ufe0f\u20e3  \ud83d\udcf1 Virtual Numbers\n' +
    '  5\ufe0f\u20e3  \ud83d\udcb0 Pricing & Bonuses\n  6\ufe0f\u20e3  \ud83c\udf81 Referral Program\n' +
    '  7\ufe0f\u20e3  \ud83d\udc68\u200d\ud83d\udcbc Talk to Staff\n  8\ufe0f\u20e3  \ud83d\udd17 Links & Channels\n' +
    '  0\ufe0f\u20e3  \u2139\ufe0f  About BoostNG\n\n\ud83d\udca1 _Type a number or ask anything!_\n\n' +
    BORDER_TOP + '\n' + POWERED + '\n' + BORDER_BOT;
}

function T_welcome() {
  return wm('\ud83d\udc4b *Welcome to BoostNG!*\n\nTo unlock access:\n\n\ud83d\udce2 Join WhatsApp Channel:\n' + CONFIG.WA_CHANNEL +
    '\n\n\ud83d\udcac Join Telegram:\n' + CONFIG.TELEGRAM_GC + '\n\n\u2705 Then type *JOINED* here');
}

function T_staff() {
  var on = STAFF.filter(function(s) { return s.online && s.number; });
  if (!on.length) return wm('\ud83d\udc68\u200d\ud83d\udcbc Staff offline\n\n\u2022 Telegram: ' + CONFIG.TELEGRAM_GC + '\n\u2022 Website: ' + CONFIG.WEBSITE + '\n\n_We reply within 1-2 hours_');
  return wm('\ud83d\udc68\u200d\ud83d\udcbc *Staff Online*\n\n' + on.map(function(s) { return '\u2022 *' + s.name + ':* wa.me/' + s.number; }).join('\n'));
}

async function handleMenu(sock, jid, text, session, isGroup) {
  var t = (text || '').trim();
  var u = t.toUpperCase().replace(/\s+/g, ' ');

  if (['MENU','HI','HELLO','START','HELP','HEY','BACK'].includes(u)) return sendMenu(sock, jid, T_menu(), isGroup);
  if (['STAFF','HUMAN','AGENT','SUPPORT'].includes(u)) return send(sock, jid, T_staff());
  if (u === 'PING') return send(sock, jid, wm('\ud83c\udfd3 Pong! Uptime: ' + getUptime() + ' | Security: 72 layers'));
  if (u === 'UPTIME') return send(sock, jid, wm('\u23f1\ufe0f *' + getUptime() + '*\n\ud83d\udcec Scanned: ' + STATS.scanned));
  if (['LINKS','CHANNELS'].includes(u)) return send(sock, jid, wm('\ud83d\udd17 *Links*\n\n\ud83c\udf10 ' + CONFIG.WEBSITE + '\n\ud83d\udce2 ' + CONFIG.WA_CHANNEL + '\n\ud83d\udcac ' + CONFIG.TELEGRAM_GC));

  switch(t) {
    case '1': return send(sock, jid, wm('\ud83d\udce6 *SMM Services*\n\n\ud83d\udcf8 Instagram \ud83c\udfb5 TikTok \u25b6\ufe0f YouTube\n\ud83d\udcac Telegram \ud83d\udc26 Twitter \ud83d\udc4d Facebook\n\n5,000+ services!\n\ud83d\udc49 ' + CONFIG.WEBSITE));
    case '2': return send(sock, jid, wm('\ud83d\udd0d *Order Status*\n\n\ud83d\udc49 ' + CONFIG.WEBSITE + ' \u2192 Orders\n\nDelayed 24hrs+? Type *STAFF*'));
    case '3': return send(sock, jid, wm('\ud83d\udcb3 *Top Up*\n\n\u2705 Flutterwave (Card & Bank)\n\u2705 PayPal: oghosaomorogbe41@gmail.com\n\u2705 Crypto (USDC)\n\nMin: \u20a650 \u2014 Instant!\n\ud83d\udc49 ' + CONFIG.WEBSITE));
    case '4': return send(sock, jid, wm('\ud83d\udcf1 *Virtual Numbers*\n\n\u2705 WhatsApp Telegram Google\n\u2705 50+ services, 30+ countries\n\ud83d\udc49 ' + CONFIG.WEBSITE + ' \u2192 V-Numbers'));
    case '5': return send(sock, jid, wm('\ud83d\udcb0 *Pricing*\n\n$1 = 100 Mayor Points\nMin: \u20a650\n\n\ud83c\udf81 $20\u2192+100 $50\u2192+300 $100\u2192+800 $200\u2192+2000\n\ud83d\udc49 ' + CONFIG.WEBSITE));
    case '6': return send(sock, jid, wm('\ud83c\udf81 *Referral*\n\n1\ufe0f\u20e3 Sign up \u2192 2\ufe0f\u20e3 Copy link \u2192 3\ufe0f\u20e3 Share \u2192 4\ufe0f\u20e3 Earn!\n\ud83d\udc49 ' + CONFIG.WEBSITE));
    case '7': return send(sock, jid, T_staff());
    case '8': return send(sock, jid, wm('\ud83d\udd17 *Links*\n\n\ud83c\udf10 ' + CONFIG.WEBSITE + '\n\ud83d\udce2 ' + CONFIG.WA_CHANNEL + '\n\ud83d\udcac ' + CONFIG.TELEGRAM_GC));
    case '0': return send(sock, jid, wm('\u2139\ufe0f *About BoostNG*\n\n\ud83d\udce6 5,000+ SMM Services\n\ud83d\udcf1 Virtual Numbers\n\ud83d\udcb3 Flutterwave PayPal Crypto\n\u26a1 Fast Delivery\n\ud83e\udd16 24/7 AI\n\ud83d\udee1\ufe0f 72-Layer Security\n\n\ud83d\udc51 Mayor | Mayor Tech Inc\n\ud83c\udf10 ' + CONFIG.WEBSITE));
  }

  // AI fallback with history
  var h = (session && session.history) || [];
  var ai = await askAI(t, h, jid);
  if (ai) {
    h.push({ role: 'user', content: t });
    h.push({ role: 'assistant', content: ai });
    if (session) session.history = h.slice(-10);
    return send(sock, jid, wm(ai));
  }
  return send(sock, jid, wm('\ud83e\udd14 Not sure I got that!\n\nType *MENU* for options or *STAFF* for help \ud83d\ude0a'));
}

// ═══════════════════════════════════════════════════════════════════════════════
// 18. MEMORY CLEANUP — runs every 5 minutes
//     Prevents unbounded memory growth from caches
// ═══════════════════════════════════════════════════════════════════════════════
function runCleanup() {
  var now = Date.now();
  var before = { rl: rateLimiter.size, tb: tempBlocked.size, s: userSessions.size, ai: aiCooldowns.size };

  // BoundedMap auto-cleanup — TTL-based eviction
  var rlCleaned = rateLimiter.cleanup ? rateLimiter.cleanup() : 0;
  var tbCleaned = tempBlocked.cleanup ? tempBlocked.cleanup() : 0;
  var ssCleaned = userSessions.cleanup ? userSessions.cleanup() : 0;

  // AI cooldowns — BoundedMap with TTL
  var aiCleaned = aiCooldowns.cleanup ? aiCooldowns.cleanup() : 0;

  // Clear logo buffer cache every hour so it re-reads if file changes
  // (keep in memory most of the time for performance)

  H.checkMemory(0.80);

  console.log('[GC] Cleanup done. RL:' + before.rl + '->' + rateLimiter.size +
    ' TB:' + before.tb + '->' + tempBlocked.size +
    ' Sessions:' + before.s + '->' + userSessions.size);
}

setInterval(runCleanup, CONFIG.CLEANUP_INTERVAL);

// extractText provided by hardening engine — full defensive extraction
var extractText = H.extractText;

// ═══════════════════════════════════════════════════════════════════════════════
// 20. MAIN BOT — with exponential backoff reconnection
// ═══════════════════════════════════════════════════════════════════════════════
async function startBot() {
  // Clear broken session if requested
  if (process.env.CLEAR_SESSION === 'true') {
    await safeAsync(async function() {
      if (fs.existsSync('./auth_info')) fs.rmSync('./auth_info', { recursive: true, force: true });
      console.log('[Bot] Session cleared');
    }, 'clearSession');
  }

  // Load persistent data
  await loadPersistentData();

  var state, saveCreds, version;
  try {
    var auth = await useMultiFileAuthState('./auth_info');
    state = auth.state; saveCreds = auth.saveCreds;
    var ver = await fetchLatestBaileysVersion();
    version = ver.version;
  } catch(e) {
    console.error('[Bot] Auth/version error:', e.message);
    // Retry after backoff
    reconnectDelay = Math.min(reconnectDelay * 2, CONFIG.RECONNECT_MAX);
    return setTimeout(startBot, reconnectDelay);
  }

  var sock;
  try {
    sock = makeWASocket({
      version,
      auth             : { creds: state.creds, keys: makeCacheableSignalKeyStore(state.keys, pino({ level: 'silent' })) },
      printQRInTerminal: true,
      logger           : pino({ level: 'silent' }),
      browser          : ['BoostNG Assistant', 'Chrome', '120.0.0'],
      // Timeout settings for stability
      connectTimeoutMs : 30000,
      defaultQueryTimeoutMs: 20000,
      keepAliveIntervalMs  : 25000,
    });
  } catch(e) {
    console.error('[Bot] Socket creation error:', e.message);
    reconnectDelay = Math.min(reconnectDelay * 2, CONFIG.RECONNECT_MAX);
    return setTimeout(startBot, reconnectDelay);
  }

  globalSock = sock;
  sock.ev.on('creds.update', saveCreds);

  // ── Connection handler with exponential backoff ──
  sock.ev.on('connection.update', async function(update) {
    var connection = update.connection;
    var lastDisconnect = update.lastDisconnect;
    var qr = update.qr;

    if (qr) {
      latestQR = qr;
      qrcode.generate(qr, { small: true });
      console.log('\n\ud83d\udd11 Pair: ' + CONFIG.RAILWAY_URL + '/pair');
      console.log('\ud83d\udcf1 QR:   ' + CONFIG.RAILWAY_URL + '/qr\n');
    }

    if (connection === 'open') {
      // Reset backoff on successful connection
      reconnectDelay = CONFIG.RECONNECT_BASE;
      reconnectCount++;
      STATS.reconnects++;
      STATS.startTime = Date.now();
      latestQR = null;
      console.log('\n\u2705 BoostNG Bot LIVE! Reconnect #' + reconnectCount);
      console.log('\ud83d\udee1\ufe0f 72 security layers | \ud83d\udc51 ' + OWNERS.size + ' owners');
      console.log('\u00a9 2026 Mayor Tech Inc\n');
    }

    if (connection === 'close') {
      var code = lastDisconnect && lastDisconnect.error && lastDisconnect.error.output && lastDisconnect.error.output.statusCode;
      var isLoggedOut = code === DisconnectReason.loggedOut;

      if (isLoggedOut) {
        console.log('[Bot] Logged out — delete auth_info to re-link');
        return;
      }

      // Exponential backoff — prevents reconnect storms
      console.log('[Bot] Disconnected (code ' + code + ') — reconnecting in ' + (reconnectDelay/1000) + 's');
      setTimeout(startBot, reconnectDelay);
      reconnectDelay = Math.min(reconnectDelay * 1.5, CONFIG.RECONNECT_MAX);
    }
  });

  // ── Message handler ──
  sock.ev.on('messages.upsert', async function(upsert) {
    // Wrap entire handler in safeAsync — never crash on any message
    await safeAsync(async function() {
      if (!upsert || upsert.type !== 'notify') return;

      for (var i = 0; i < (upsert.messages || []).length; i++) {
        var msg = upsert.messages[i];

        // Defensive: ensure message structure is valid
        if (!msg || !msg.key || !msg.message) continue;

        var jid       = msg.key.remoteJid;
        var isGC      = !!(jid && jid.endsWith('@g.us'));
        var senderJid = isGC ? (msg.key.participant || jid) : jid;

        if (!jid || !senderJid) continue;

        // Extract text safely
        var text = extractText(msg);

        STATS.scanned++;

        // ── PROTOCOL-LEVEL VALIDATION — happens before ANY other processing ──
        // Rejects malformed/unknown protocol payloads at the runtime level
        // This catches UNKNOWN bugs that pattern-matching cannot catch
        var validation = null;
        try { validation = H.validateMessage(msg); } catch(vErr) { validation = { valid: false, reason: 'validation threw: ' + vErr.message }; }
        if (!validation || !validation.valid) {
          H.LOG.warn('PAYLOAD', 'Rejected: ' + (validation && validation.reason || 'unknown'), { jid: senderJid });
          await safeDelete(sock, msg);
          STATS.blocked++;
          continue;
        }

        // ── Blacklist check — permanent block ──
        if (BLACKLIST.has(senderJid)) {
          await safeDelete(sock, msg);
          continue;
        }

        // ── Temp block check ──
        var blockUntil = tempBlocked.get(senderJid);
        if (blockUntil && Date.now() < blockUntil) {
          await safeDelete(sock, msg);
          continue;
        }
        if (blockUntil) tempBlocked.delete(senderJid);

        // ── Security scan — full engine ──
        var threat = null;
        try { threat = SEC.scanMessage(msg, text, senderJid); }
        catch(e) { console.error('[SCAN]', e.message); }

        if (threat) {
          await handleThreat(sock, senderJid, msg, threat, isGC);
          continue;
        }

        // ── Flood/spam check ──
        try {
          if (SEC.checkSpam && SEC.checkSpam(senderJid)) {
            await handleThreat(sock, senderJid, msg, { name: 'Spam Flood', level: 2 }, isGC);
            continue;
          }
          if (isGC && SEC.checkFlood) {
            var flood = SEC.checkFlood(senderJid, jid);
            if (flood && flood.flooded) {
              await safeDelete(sock, msg);
              if (!flood.muted) await safeAsync(function() { return sock.groupParticipantsUpdate(jid, [senderJid], 'remove'); }, 'floodKick');
              continue;
            }
          }
        } catch(e) {}

        // ── Rate limit (non-owner/non-officer) ──
        var ownerFlag   = isOwner(senderJid);
        var officerFlag = isOfficer(senderJid);

        if (!ownerFlag && !officerFlag && isRateLimited(senderJid)) {
          // Silently drop — don't warn (anti-spam itself)
          continue;
        }

        // ── Anti-ban delay ──
        await delay(150, 500);

        // ── Group commands ──
        if (isGC) {
          if (text && (text.startsWith('!') || /^\.(pair|mode|add.?owner|remove.?owner|list.?owner)/i.test(text))) {
            await handleGC(sock, jid, text, msg);
          }
          continue;
        }

        // ── DMs ──
        // Owner/officer commands — checked first, bypass everything
        if ((ownerFlag || officerFlag) && text) {
          var ownerRes = await handleOwnerCmd(sock, jid, text, msg);
          if (ownerRes !== false) continue;
          // Owners bypass join verification
          if (!verifiedUsers.has(jid)) verifiedUsers.add(jid);
        }

        // Private mode
        if (BOT_MODE_CURRENT.value === 'private' && !officerFlag) {
          await send(sock, jid, wm('\ud83d\udd12 Private mode — contact Mayor for access:\n' + CONFIG.TELEGRAM_GC));
          continue;
        }

        // Get/init session
        var session = userSessions.get(jid) || { step: 'welcome', history: [], lastActive: Date.now() };
        session.lastActive = Date.now();

        // Join verification
        if (!verifiedUsers.has(jid)) {
          if (text.trim().toUpperCase() === CONFIG.JOIN_KEYWORD) {
            verifiedUsers.add(jid);
            session.step = 'menu';
            userSessions.set(jid, session);
            await send(sock, jid, wm('\u2705 *Access Granted!* Welcome to BoostNG! \ud83c\udf89'));
            await delay(500, 800);
            await sendMenu(sock, jid, T_menu(), false);
          } else {
            await send(sock, jid, T_welcome());
          }
          continue;
        }

        // Handle menu/AI
        await handleMenu(sock, jid, text, session, false);
        boundedSet(userSessions);
        userSessions.set(jid, session);
      }
    }, 'messageHandler');
  });
}

// ═══════════════════════════════════════════════════════════════════════════════
// 21. HTTP SERVER — /health /qr /pair /status
// ═══════════════════════════════════════════════════════════════════════════════
var server = http.createServer(async function(req, res) {
  await safeAsync(async function() {
    var urlMod = require('url');
    var parsed = urlMod.parse(req.url || '/', true);
    var p = parsed.pathname || '/';

    // Health check — Railway uses this
    if (p === '/health' || p === '/ping') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 'ok', uptime: getUptime() }));
      return;
    }

    // QR page
    if (p === '/qr') {
      if (!latestQR) {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end('<!DOCTYPE html><html><head><meta http-equiv="refresh" content="3"><style>body{background:#0d0d1a;color:#fff;font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;text-align:center}</style></head><body><h2 style="color:#00e87a">' + (globalSock && !latestQR ? '\u2705 Bot is linked and live!' : '\u23f3 Generating QR...') + '</h2><p>Refreshes automatically</p></body></html>');
        return;
      }
      try {
        var qrDataUrl = await QRCode.toDataURL(latestQR, { width: 300, margin: 2 });
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end('<!DOCTYPE html><html><head><title>BoostNG QR</title><meta name="viewport" content="width=device-width,initial-scale=1"><style>*{box-sizing:border-box;margin:0;padding:0}body{background:#0d0d1a;color:#fff;font-family:sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:20px}.c{background:#1a1a2e;border:1px solid rgba(0,232,122,.3);border-radius:16px;padding:32px;max-width:380px;width:100%;text-align:center}h1{color:#00e87a;margin-bottom:8px}p{color:rgba(255,255,255,.4);font-size:12px;margin-bottom:20px}img{border-radius:12px;border:4px solid #00e87a;width:260px}.w{color:orange;font-size:11px;margin-top:12px}a{color:#00e87a;font-size:12px;display:block;margin-top:16px;text-decoration:none}</style></head><body><div class="c"><h1>\ud83d\udcf1 Scan QR</h1><p>WhatsApp \u2192 Linked Devices \u2192 Link a Device</p><img src="' + qrDataUrl + '"><div class="w">\u23f0 Refresh if expired (~20s)</div><a href="/qr">\ud83d\udd04 Refresh</a><a href="/pair">\ud83d\udd11 Pairing Code instead</a></div></body></html>');
      } catch(e) { res.writeHead(500); res.end('QR error: ' + e.message); }
      return;
    }

    // Pair page
    if (p === '/pair') {
      var num = ((parsed.query && parsed.query.number) || '').replace(/[^0-9]/g, '');
      if (!num) {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end('<!DOCTYPE html><html><head><title>BoostNG Pair</title><meta name="viewport" content="width=device-width,initial-scale=1"><style>*{box-sizing:border-box;margin:0;padding:0}body{background:#0d0d1a;color:#fff;font-family:sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:20px}.c{background:#1a1a2e;border:1px solid rgba(0,232,122,.2);border-radius:16px;padding:32px;max-width:400px;width:100%;text-align:center}h1{color:#00e87a;margin-bottom:8px}p{color:rgba(255,255,255,.5);font-size:13px;margin-bottom:24px}input{width:100%;background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.15);border-radius:10px;padding:14px;color:#fff;font-size:16px;outline:none;margin-bottom:16px;text-align:center}input:focus{border-color:#00e87a}button{width:100%;background:#00e87a;border:none;color:#000;padding:14px;border-radius:10px;font-size:15px;font-weight:700;cursor:pointer}.h{color:rgba(255,255,255,.3);font-size:11px;margin-top:12px}a{color:#00e87a;font-size:12px;display:block;margin-top:16px;text-decoration:none}</style></head><body><div class="c"><h1>\ud83d\udd11 Get Pairing Code</h1><p>Enter your WhatsApp number</p><form action="/pair" method="get"><input name="number" placeholder="2348012345678" type="tel" autofocus><button type="submit">\u26a1 Generate Code</button></form><div class="h">Country code, no + sign</div><a href="/qr">\ud83d\udcf1 Scan QR instead</a></div></body></html>');
        return;
      }
      if (!globalSock) { res.writeHead(503); res.end('<h2 style="color:red;font-family:sans-serif;padding:40px">Bot not ready. Wait 10 seconds.</h2>'); return; }
      try {
        var code = await withTimeout(globalSock.requestPairingCode(num + '@s.whatsapp.net'), 10000, 'pairCode');
        STATS.pairings++;
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end('<!DOCTYPE html><html><head><title>Code Ready</title><meta name="viewport" content="width=device-width,initial-scale=1"><style>*{box-sizing:border-box;margin:0;padding:0}body{background:#0d0d1a;color:#fff;font-family:sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:20px}.c{background:#1a1a2e;border:1px solid rgba(0,232,122,.3);border-radius:16px;padding:32px;max-width:420px;width:100%;text-align:center}h1{color:#00e87a;margin-bottom:8px}.code{font-size:42px;font-weight:900;color:#00e87a;letter-spacing:8px;margin:20px 0;font-family:monospace}.num{color:rgba(255,255,255,.4);font-size:13px;margin-bottom:16px}.steps{background:rgba(0,232,122,.06);border-radius:10px;padding:16px;font-size:13px;line-height:2;text-align:left;color:rgba(255,255,255,.7)}.w{color:orange;font-size:11px;margin-top:12px}a{color:#00e87a;font-size:12px;display:block;margin-top:16px;text-decoration:none}</style></head><body><div class="c"><h1>\u2705 Code Ready!</h1><div class="num">+' + num + '</div><div class="code">' + code + '</div><div class="steps">1. Open WhatsApp<br>2. Menu \u2192 Linked Devices<br>3. Link a Device<br>4. Link with phone number<br>5. Enter code above \u2705</div><div class="w">\u23f0 Expires in 60 seconds!</div><a href="/pair">\u2190 Generate another</a><a href="/qr">\ud83d\udcf1 Use QR instead</a></div></body></html>');
      } catch(e) { res.writeHead(400); res.end('<div style="font-family:sans-serif;padding:40px;color:#ff6b6b"><h2>\u274c ' + e.message + '</h2><a href="/pair" style="color:#00e87a">\u2190 Try again</a></div>'); }
      return;
    }

    // Status/default
    var mem = getMemStats();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      status   : 'online',
      bot      : 'BoostNG Enterprise',
      uptime   : getUptime(),
      mode     : BOT_MODE_CURRENT.value,
      security : '72 layers',
      owners   : OWNERS.size,
      scanned  : STATS.scanned,
      blocked  : STATS.blocked,
      errors   : STATS.errors,
      memory   : mem,
      qr       : CONFIG.RAILWAY_URL + '/qr',
      pair     : CONFIG.RAILWAY_URL + '/pair',
      health   : CONFIG.RAILWAY_URL + '/health',
    }, null, 2));
  }, 'httpHandler');
});

server.listen(CONFIG.PORT, function() {
  console.log('[HTTP] Port ' + CONFIG.PORT + ' | ' + CONFIG.RAILWAY_URL);
});

// ═══════════════════════════════════════════════════════════════════════════════
// 22. BOOT
// ═══════════════════════════════════════════════════════════════════════════════
console.log('\n[BoostNG] Starting enterprise bot...');
console.log('[BoostNG] Node ' + process.version + ' | PID ' + process.pid);
startBot().catch(function(e) {
  console.error('[BOOT] Fatal:', e.message);
  // Don't exit — Railway will restart if needed
});
