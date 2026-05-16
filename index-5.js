/**
 * BoostNG Assistant Bot v2 — Enterprise Edition
 * By Mayor Tech Inc © 2026
 *
 * Features:
 * - Enterprise security engine (30+ threat patterns)
 * - Structured scanner: scanText / scanMedia / scanInteractive
 * - Threat levels: LOW / MEDIUM / HIGH
 * - Real WhatsApp blocking (sock.updateBlockStatus)
 * - Auto-delete + auto-kick in groups
 * - Persistent blacklist & owner management
 * - All groups protected by default (no toggle)
 * - Owner management: Add_owner / Remove_owner / List_owners
 * - .pair works from DM or GC (owner/officer only)
 * - AI replies (Groq), menus, group admin commands
 * - HTTP server with /qr and /pair pages
 * - Anti-ban natural delays
 * - Watermark on every message
 */

'use strict';
require('dotenv').config();

const {
  default: makeWASocket,
  useMultiFileAuthState,
  DisconnectReason,
  fetchLatestBaileysVersion,
  makeCacheableSignalKeyStore,
} = require('@whiskeysockets/baileys');

const pino    = require('pino');
const qrcode  = require('qrcode-terminal');
const QRCode  = require('qrcode');
const Groq    = require('groq-sdk');
const http    = require('http');
const fs      = require('fs');
const path    = require('path');

const { scanText, scanMedia, scanInteractive, scanMessage, THREAT } = require('./security');
const Store = require('./store');

// ─── Config ───────────────────────────────────────────────────────────────────
const MAIN_OWNER = (process.env.OWNER_NUMBER || '').replace(/[^0-9]/g, '');

const CONFIG = {
  WA_CHANNEL   : 'https://whatsapp.com/channel/0029Vb84NAUFXUui0ueD3H1O',
  TELEGRAM_GC  : 'https://t.me/mayor_d_dev',
  WEBSITE      : 'https://boosthubng.pages.dev',
  WATERMARK    : '\n\n━━━━━━━━━━━━━━━━━━━━━\n        🏆 MAYOR TECH INC\n© 2026 — ALL RIGHTS RESERVED\n━━━━━━━━━━━━━━━━━━━━━',
  GROQ_KEY     : process.env.GROQ_API_KEY    || '',
  JOIN_KEYWORD : 'JOINED',
  PORT         : process.env.PORT            || 3000,
  LOGO_PATH    : path.join(__dirname, 'logo.jpg'),
  RAILWAY_URL  : process.env.RAILWAY_URL     || 'https://web-production-94012.up.railway.app',
};

const STAFF = [
  { name: process.env.STAFF1_NAME || 'Staff 1', number: process.env.STAFF1_NUMBER || '', online: false },
  { name: process.env.STAFF2_NAME || 'Staff 2', number: process.env.STAFF2_NUMBER || '', online: false },
  { name: process.env.STAFF3_NAME || 'Staff 3', number: process.env.STAFF3_NUMBER || '', online: false },
  { name: process.env.STAFF4_NAME || 'Staff 4', number: process.env.STAFF4_NUMBER || '', online: false },
  { name: process.env.STAFF5_NAME || 'Staff 5', number: process.env.STAFF5_NUMBER || '', online: false },
];

// ─── Persistent data ──────────────────────────────────────────────────────────
var OWNERS    = Store.loadOwners(MAIN_OWNER);
var BLACKLIST = Store.loadBlacklist();
var BOT_MODE  = process.env.BOT_MODE || 'public';

// ─── Runtime state ────────────────────────────────────────────────────────────
var verifiedUsers = new Set();
var userSessions  = new Map();
var spamTracker   = new Map();
var tempBlocked   = new Map(); // jid → unblock timestamp
var latestQR      = null;
var globalSock    = null;

// ─── Stats ────────────────────────────────────────────────────────────────────
var STATS = { startTime: Date.now(), scanned: 0, blocked: 0, aiReplies: 0, pairings: 0 };

function getUptime() {
  var ms = Date.now() - STATS.startTime;
  var d = Math.floor(ms/86400000), h = Math.floor((ms%86400000)/3600000);
  var m = Math.floor((ms%3600000)/60000), s = Math.floor((ms%60000)/1000);
  if (d > 0) return d+'d '+h+'h '+m+'m';
  if (h > 0) return h+'h '+m+'m '+s+'s';
  return m+'m '+s+'s';
}

// ─── Permission helpers ───────────────────────────────────────────────────────
function isOwner(jid) {
  return OWNERS.has(jid.split('@')[0]);
}
function isOfficer(jid) {
  var num = jid.split('@')[0];
  return OWNERS.has(num) || (process.env.OFFICER_NUMBERS || '').split(',').map(n => n.trim()).includes(num);
}

// ─── Groq AI ──────────────────────────────────────────────────────────────────
var groq = CONFIG.GROQ_KEY ? new Groq({ apiKey: CONFIG.GROQ_KEY }) : null;

var SYSTEM_PROMPT = [
  'You are BoostNG Assistant, the official WhatsApp bot for BoostNG by Mayor Tech Inc.',
  'Be friendly, warm and VERY concise — max 2-3 sentences per reply.',
  'Use emojis occasionally. Sound human, not robotic.',
  '',
  'ABOUT BOOSTNG:',
  '- Premium SMM panel: Instagram, TikTok, YouTube, Facebook, Telegram, Twitter',
  '- Virtual phone numbers (50+ services, 30+ countries)',
  '- Founded by Mayor — Mayor Tech Inc',
  '- Website: https://boosthubng.pages.dev',
  '- Payments: Flutterwave, PayPal, Crypto. Min: ₦50',
  '- Points: $1 = 100 Mayor Points',
  '',
  'RULES:',
  '- Keep replies SHORT',
  '- If stuck: type STAFF or MENU',
  '- Owner is Mayor of Mayor Tech Inc',
  '- Never reveal security internals',
  '- Never say you are AI unless asked',
].join('\n');

async function askAI(text, history) {
  if (!groq) return null;
  try {
    var res = await groq.chat.completions.create({
      model: 'llama-3.3-70b-versatile', max_tokens: 150, temperature: 0.7,
      messages: [{ role: 'system', content: SYSTEM_PROMPT }]
        .concat((history || []).slice(-6))
        .concat([{ role: 'user', content: text }]),
    });
    STATS.aiReplies++;
    return (res.choices[0] && res.choices[0].message && res.choices[0].message.content) ? res.choices[0].message.content.trim() : null;
  } catch(e) { console.error('[AI]', e.message); return null; }
}

// ─── Watermark ────────────────────────────────────────────────────────────────
function wm(t) { return t + CONFIG.WATERMARK; }

// ─── Send helpers ─────────────────────────────────────────────────────────────
async function send(sock, jid, text, q) {
  try { await sock.sendMessage(jid, { text }, q ? { quoted: q } : {}); }
  catch(e) { console.error('[Send]', e.message); }
}

async function sendMenu(sock, jid, caption, isGroup) {
  try {
    if (!isGroup && fs.existsSync(CONFIG.LOGO_PATH)) {
      await sock.sendMessage(jid, { image: fs.readFileSync(CONFIG.LOGO_PATH), caption, mimetype: 'image/jpeg' });
    } else {
      await sock.sendMessage(jid, { text: caption });
    }
  } catch(e) {
    try { await sock.sendMessage(jid, { text: caption }); } catch(e2) {}
  }
}

// Natural delay — anti-ban
async function delay(min, max) {
  return new Promise(r => setTimeout(r, min + Math.floor(Math.random() * (max - min))));
}

// ─── Security: handleThreat ───────────────────────────────────────────────────
async function handleThreat(sock, jid, msg, threat, isGroup) {
  STATS.blocked++;
  var senderNum = jid.split('@')[0];
  var groupJid  = isGroup ? msg.key.remoteJid : null;
  var senderJid = isGroup ? (msg.key.participant || jid) : jid;

  console.warn('[THREAT] L' + threat.level + ' | ' + threat.name + ' | ' + senderJid);

  // Log to file
  Store.logThreat(senderJid, threat.name, { level: threat.level, category: threat.category, group: groupJid });

  // ── Step 1: Delete the message ──
  try { await sock.sendMessage(msg.key.remoteJid, { delete: msg.key }); } catch(e) {}

  // ── Step 2: Punish based on threat level ──
  if (threat.level === THREAT.HIGH) {
    // Permanent blacklist
    Store.blacklistAdd(BLACKLIST, senderJid, threat.name, threat.level);

    // Real WhatsApp block
    try { await sock.updateBlockStatus(senderJid, 'block'); } catch(e) {}

    // Kick from group
    if (isGroup) {
      try { await sock.groupParticipantsUpdate(groupJid, [senderJid], 'remove'); } catch(e) {}
    }

    // Alert Mayor
    if (MAIN_OWNER) {
      var num = senderJid.split('@')[0];
      var alertText = '🚨 HIGH THREAT BLOCKED\n\n' +
        'Number: +' + num + '\n' +
        'Threat: ' + threat.name + '\n' +
        'Action: Blocked + kicked + WA blocked\n' +
        'Context: ' + (isGroup ? 'Group' : 'DM') + CONFIG.WATERMARK;
      try { await sock.sendMessage(MAIN_OWNER + '@s.whatsapp.net', { text: alertText }); } catch(e) {}
    }

    // Tell attacker
    try {
      await sock.sendMessage(senderJid, {
        text: '⛔ Your account has been permanently blocked and reported for sending malicious content.' + CONFIG.WATERMARK
      });
    } catch(e) {}

  } else if (threat.level === THREAT.MEDIUM) {
    // Temp block 10 min
    tempBlocked.set(senderJid, Date.now() + 600000);
    if (isGroup) {
      try { await sock.groupParticipantsUpdate(groupJid, [senderJid], 'remove'); } catch(e) {}
    }
    try {
      await sock.sendMessage(senderJid, {
        text: '⚠️ You have been temporarily blocked for 10 minutes for sending suspicious content.' + CONFIG.WATERMARK
      });
    } catch(e) {}

  } else {
    // LOW — just warn
    try {
      await sock.sendMessage(isGroup ? groupJid : senderJid, {
        text: '⚠️ A suspicious message was blocked.' + CONFIG.WATERMARK
      });
    } catch(e) {}
  }

  // Notify group
  if (isGroup && threat.level >= THREAT.MEDIUM) {
    try {
      await sock.sendMessage(groupJid, {
        text: '🛡️ *Security Alert*\n\nA malicious message was detected and removed.\nThe sender has been ' + (threat.level === THREAT.HIGH ? 'permanently removed.' : 'temporarily removed.') + CONFIG.WATERMARK
      });
    } catch(e) {}
  }
}

// ─── Spam check ───────────────────────────────────────────────────────────────
function checkSpam(jid) {
  var now  = Date.now();
  var s    = spamTracker.get(jid) || { count: 0, last: now };
  if (now - s.last > 60000) { s = { count: 1, last: now }; }
  else { s.count++; }
  spamTracker.set(jid, s);
  if (s.count > 10) return true;
  return false;
}

// ─── Message templates ────────────────────────────────────────────────────────
var BORDER_TOP = '\u2554\u2550\u254b\u254b\u254b\u2500\u2500\u2500 \u2022 \u2500\u2500\u2500\u254b\u254b\u254b\u2550\u2557';
var BORDER_BOT = '\u255a\u2550\u254b\u254b\u254b\u2500\u2500\u2500 \u2022 \u2500\u2500\u2500\u254b\u254b\u254b\u2550\u255d';
var POWERED    = '  POWERED BY MAYOR TECH INC';

function T_menu() {
  return BORDER_TOP + '\n     \u2022 BOOST NG \u2022\n' + BORDER_BOT + '\n\n' +
    '\ud83d\udd39 *MAIN MENU*\n\n' +
    '  1\ufe0f\u20e3  \ud83d\udce6 SMM Services\n' +
    '  2\ufe0f\u20e3  \ud83d\udd0d Order Status\n' +
    '  3\ufe0f\u20e3  \ud83d\udcb3 Top Up Wallet\n' +
    '  4\ufe0f\u20e3  \ud83d\udcf1 Virtual Numbers\n' +
    '  5\ufe0f\u20e3  \ud83d\udcb0 Pricing & Bonuses\n' +
    '  6\ufe0f\u20e3  \ud83c\udf81 Referral Program\n' +
    '  7\ufe0f\u20e3  \ud83d\udc68\u200d\ud83d\udcbc Talk to Staff\n' +
    '  8\ufe0f\u20e3  \ud83d\udd17 Links & Channels\n' +
    '  0\ufe0f\u20e3  \u2139\ufe0f  About BoostNG\n\n' +
    '\ud83d\udca1 _Type a number or ask anything!_\n\n' +
    BORDER_TOP + '\n' + POWERED + '\n' + BORDER_BOT;
}

function T_gchelp() {
  return BORDER_TOP + '\n     \u2022 BOOST NG \u2022\n' + BORDER_BOT + '\n\n' +
    '\ud83d\udd39 *USER COMMANDS*\n' +
    '  !menu    \u2022 Open Menu\n' +
    '  !ping    \u2022 Check Speed\n' +
    '  !uptime  \u2022 Bot Runtime\n' +
    '  !status  \u2022 Bot Status\n' +
    '  !info    \u2022 Group Info\n' +
    '  !link    \u2022 Group Link\n' +
    '  !staff   \u2022 Online Staff\n\n' +
    '\ud83d\udc51 *ADMIN COMMANDS*\n' +
    '  !add [num]   \u2022 Add User\n' +
    '  !kick [@]    \u2022 Remove User\n' +
    '  !promote [@] \u2022 Give Admin\n' +
    '  !demote [@]  \u2022 Remove Admin\n' +
    '  !setname     \u2022 Rename Group\n' +
    '  !setdesc     \u2022 Set Description\n' +
    '  !setpic      \u2022 Change Picture\n' +
    '  !everyone    \u2022 Mention All\n' +
    '  !revoke      \u2022 Reset Link\n\n' +
    '\ud83d\udee1\ufe0f *SECURITY*\n' +
    '  \u2713 Anti-Crash  \u2713 Anti-Spam\n' +
    '  \u2713 Anti-Hack   \u2713 Auto-Block\n\n' +
    BORDER_TOP + '\n' + POWERED + '\n' + BORDER_BOT;
}

function T_status() {
  return wm('\ud83d\udee1\ufe0f *BOOSTNG SECURITY STATUS*\n\n' +
    '\u2501\u2501\u2501\u2501 Protection Active \u2501\u2501\u2501\u2501\n\n' +
    '\u2705 Invisible Char Filter\n' +
    '\u2705 RTL Override Block\n' +
    '\u2705 Zalgo/Combining Scanner\n' +
    '\u2705 Character Bomb Detector\n' +
    '\u2705 Null Byte Filter\n' +
    '\u2705 Braille Spam Block\n' +
    '\u2705 Surrogate Pair Filter\n' +
    '\u2705 Emoji Bomb Detector\n' +
    '\u2705 Tag Character Block\n' +
    '\u2705 Script Injection Filter\n' +
    '\u2705 Media Size Scanner\n' +
    '\u2705 vCard Exploit Block\n' +
    '\u2705 ViewOnce Scanner\n' +
    '\u2705 Button/Poll Scanner\n' +
    '\u2705 Quoted Message Scanner\n' +
    '\u2705 Phishing Detector\n' +
    '\u2705 Spam Rate Limiter\n' +
    '\u2705 Persistent Blacklist\n' +
    '\u2705 Real WhatsApp Blocker\n' +
    '\u2705 Auto-Kick Threat Senders\n\n' +
    '\u2501\u2501\u2501\u2501 Live Stats \u2501\u2501\u2501\u2501\n\n' +
    '\ud83d\udce8 Scanned: *' + STATS.scanned + '*\n' +
    '\ud83d\udee1\ufe0f Blocked: *' + STATS.blocked + '*\n' +
    '\ud83e\udd16 AI replies: *' + STATS.aiReplies + '*\n' +
    '\ud83d\udd11 Pairings: *' + STATS.pairings + '*\n' +
    '\u23f1\ufe0f Uptime: *' + getUptime() + '*\n' +
    '\ud83c\udf10 Mode: *' + BOT_MODE.toUpperCase() + '*\n\n' +
    '\ud83d\udfe2 *ONLINE — All 20 layers active*');
}

function T_ping(ms) {
  return wm('\ud83c\udfd3 *Pong!*\n\n\u26a1 Response: *' + ms + 'ms*\n\ud83d\udfe2 Status: *ONLINE*\n\u23f1\ufe0f Uptime: *' + getUptime() + '*\n\ud83d\udee1\ufe0f Security: *20 layers active*');
}

function T_staff() {
  var on = STAFF.filter(s => s.online && s.number);
  if (!on.length) return wm('\ud83d\udc68\u200d\ud83d\udcbc *Staff Status*\n\n\ud83d\udd34 All staff *offline*\n\n\u2022 Leave your message\n\u2022 Telegram: ' + CONFIG.TELEGRAM_GC + '\n\u2022 Website: ' + CONFIG.WEBSITE + '\n\n_We reply within 1-2 hours_ \u23f0');
  return wm('\ud83d\udc68\u200d\ud83d\udcbc *Staff Online* \ud83d\udfe2\n\n' + on.map(s => '\u2022 *' + s.name + ':* wa.me/' + s.number).join('\n') + '\n\n_Tap to chat!_ \ud83d\udcac');
}

function T_links()    { return wm('\ud83d\udd17 *Links*\n\n\ud83c\udf10 ' + CONFIG.WEBSITE + '\n\ud83d\udce2 ' + CONFIG.WA_CHANNEL + '\n\ud83d\udcac ' + CONFIG.TELEGRAM_GC); }
function T_about()    { return wm('\u2139\ufe0f *About BoostNG*\n\n\ud83d\udce6 5,000+ SMM Services\n\ud83d\udcf1 Virtual Numbers\n\ud83d\udcb3 Flutterwave, PayPal, Crypto\n\u26a1 Fast Delivery\n\ud83e\udd16 24/7 AI Support\n\ud83d\udee1\ufe0f Enterprise Security\n\n\ud83d\udc51 Founded by *Mayor*\n\ud83c\udfe2 Mayor Tech Inc\n\ud83c\udf10 ' + CONFIG.WEBSITE); }
function T_pricing()  { return wm('\ud83d\udcb0 *Pricing*\n\n$1 = 100 Mayor Points\nMin: \u20a650\n\n\ud83c\udf81 Bonuses:\n\u2022 $20 \u2192 +100 pts\n\u2022 $50 \u2192 +300 pts\n\u2022 $100 \u2192 +800 pts\n\u2022 $200 \u2192 +2,000 pts\n\n\u{1F4B3} Flutterwave, PayPal, Crypto\n\ud83d\udc49 ' + CONFIG.WEBSITE); }
function T_topup()    { return wm('\ud83d\udcb3 *Top Up*\n\n\ud83d\udc49 *' + CONFIG.WEBSITE + '*\n\n\u2705 Flutterwave (Card & Bank)\n\u2705 PayPal: oghosaomorogbe41@gmail.com\n\u2705 Crypto (USDC)\n\nMin: \u20a650 \u2014 Instant! \u26a1'); }
function T_smm()      { return wm('\ud83d\udce6 *SMM Services*\n\n\ud83d\udcf8 Instagram\n\ud83c\udfb5 TikTok\n\u25b6\ufe0f YouTube\n\ud83d\udcac Telegram\n\ud83d\udc26 Twitter/X\n\ud83d\udc4d Facebook\n\n5,000+ services!\n\ud83d\udc49 ' + CONFIG.WEBSITE); }
function T_vnum()     { return wm('\ud83d\udcf1 *Virtual Numbers*\n\n\u2705 WhatsApp, Telegram, Google\n\u2705 50+ services, 30+ countries\n\ud83d\udc49 ' + CONFIG.WEBSITE + ' \u2192 V-Numbers'); }
function T_referral() { return wm('\ud83c\udf81 *Referral Program*\n\n1\ufe0f\u20e3 Sign up on website\n2\ufe0f\u20e3 Copy referral link\n3\ufe0f\u20e3 Share with friends\n4\ufe0f\u20e3 Earn when they top up!\n\ud83d\udc49 ' + CONFIG.WEBSITE); }
function T_order()    { return wm('\ud83d\udd0d *Order Status*\n\n\ud83d\udc49 ' + CONFIG.WEBSITE + ' \u2192 Orders\n\nDelayed 24hrs+? Type *STAFF*'); }
function T_private()  { return wm('\ud83d\udd12 *Private Mode*\n\nContact *Mayor* for access:\n\ud83d\udcac ' + CONFIG.TELEGRAM_GC + '\n\ud83c\udf10 ' + CONFIG.WEBSITE); }
function T_welcome()  { return wm('\ud83d\udc4b *Welcome to BoostNG!*\n_Your #1 SMM Platform_ \ud83d\ude80\n\n\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\n\nTo unlock access:\n\n\ud83d\udce2 *Step 1* \u2014 Join WhatsApp Channel:\n' + CONFIG.WA_CHANNEL + '\n\n\ud83d\udcac *Step 2* \u2014 Join Telegram:\n' + CONFIG.TELEGRAM_GC + '\n\n\u2705 *Step 3* \u2014 Type *JOINED* here\n\n\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501'); }

// ─── DM Menu handler ──────────────────────────────────────────────────────────
async function handleMenu(sock, jid, text, session, isGrp) {
  var t = text.trim(), u = t.toUpperCase().replace(/\s+/g, ' ');

  // Quick keywords
  if (['MENU','HI','HELLO','START','HELP','HEY','BACK'].includes(u)) return sendMenu(sock, jid, T_menu(), isGrp);
  if (['STAFF','HUMAN','AGENT','SUPPORT'].includes(u)) return send(sock, jid, T_staff());
  if (['STATUS','SECURITY','PROTECTION'].includes(u)) return send(sock, jid, T_status());
  if (u === 'PING') { var t0 = Date.now(); return send(sock, jid, T_ping(Date.now()-t0)); }
  if (u === 'UPTIME') return send(sock, jid, wm('\u23f1\ufe0f Uptime: *'+getUptime()+'*\n\ud83d\udcec Scanned: *'+STATS.scanned+'*\n\ud83d\udee1\ufe0f Blocked: *'+STATS.blocked+'*'));
  if (['LINKS','CHANNELS'].includes(u)) return send(sock, jid, T_links());

  // Number menu
  switch(t) {
    case '1': return send(sock, jid, T_smm());
    case '2': return send(sock, jid, T_order());
    case '3': return send(sock, jid, T_topup());
    case '4': return send(sock, jid, T_vnum());
    case '5': return send(sock, jid, T_pricing());
    case '6': return send(sock, jid, T_referral());
    case '7': return send(sock, jid, T_staff());
    case '8': return send(sock, jid, T_links());
    case '0': return send(sock, jid, T_about());
  }

  // AI fallback
  var h = session.history || [];
  var ai = await askAI(t, h);
  if (ai) {
    h.push({ role:'user', content:t });
    h.push({ role:'assistant', content:ai });
    session.history = h.slice(-10);
    return send(sock, jid, wm(ai));
  }
  return send(sock, jid, wm('\ud83e\udd14 Not sure I got that!\n\nType *MENU* for options or *STAFF* for human help \ud83d\ude0a'));
}

// ─── Owner commands ───────────────────────────────────────────────────────────
async function handleOwnerCmd(sock, jid, text, msg) {
  var t = text.trim();
  var upper = t.toUpperCase();

  // .pair command — owner/officer only, works from anywhere
  if (/^\.pair\s+\+?(\d{7,15})/i.test(t)) {
    var m = t.match(/\.pair\s+\+?(\d{7,15})/i);
    try {
      var code = await sock.requestPairingCode(m[1] + '@s.whatsapp.net');
      STATS.pairings++;
      return send(sock, jid, wm('\ud83d\udd17 *Pairing Code*\n\n\ud83d\udcf1 Number: *+' + m[1] + '*\n\ud83d\udd11 Code: *' + code + '*\n\n1. Open WhatsApp\n2. Linked Devices \u2192 Link a Device\n3. Link with phone number\n4. Enter code above \u2705\n\n\u23f0 _Expires in 60 seconds!_'), msg);
    } catch(e) { return send(sock, jid, wm('\u274c Could not generate code for +' + m[1]), msg); }
  }

  // .mode public/private
  if (/^\.mode\s+(public|private)/i.test(t)) {
    BOT_MODE = t.toLowerCase().includes('private') ? 'private' : 'public';
    return send(sock, jid, wm('\ud83c\udf10 Bot switched to *' + BOT_MODE.toUpperCase() + ' MODE*'), msg);
  }

  // Add_owner
  if (/^add_owner\s+\+?(\d{7,15})/i.test(t)) {
    var am = t.match(/add_owner\s+\+?(\d{7,15})/i);
    var res = Store.addOwner(OWNERS, am[1]);
    if (res.ok) {
      console.log('[Owner] Added: +' + res.number + ' by ' + jid);
      if (MAIN_OWNER) {
        try { await sock.sendMessage(MAIN_OWNER+'@s.whatsapp.net', { text: '\ud83d\udc51 New owner added: +' + res.number + CONFIG.WATERMARK }); } catch(e) {}
      }
      return send(sock, jid, wm('\u2705 *+' + res.number + '* has been added as owner!\n\nThey now have full owner permissions.'), msg);
    }
    return send(sock, jid, wm('\u274c ' + res.reason), msg);
  }

  // Remove_owner
  if (/^remove_owner\s+\+?(\d{7,15})/i.test(t)) {
    var rm = t.match(/remove_owner\s+\+?(\d{7,15})/i);
    var rres = Store.removeOwner(OWNERS, rm[1], MAIN_OWNER);
    if (rres.ok) {
      console.log('[Owner] Removed: +' + rres.number + ' by ' + jid);
      return send(sock, jid, wm('\u2705 *+' + rres.number + '* removed from owners.'), msg);
    }
    return send(sock, jid, wm('\u274c ' + rres.reason), msg);
  }

  // List_owners
  if (/^list_owners$/i.test(t)) {
    var list = Array.from(OWNERS).map((n,i) => (i+1)+'. +'+n+(n===MAIN_OWNER?' (Main)':'')).join('\n');
    return send(sock, jid, wm('\ud83d\udc51 *Owners (' + OWNERS.size + ')*\n\n' + (list || 'None')), msg);
  }

  return false; // not an owner command
}

// ─── Group admin commands ─────────────────────────────────────────────────────
async function isGroupAdmin(sock, jid, senderJid) {
  try {
    var meta = await sock.groupMetadata(jid);
    return meta.participants.filter(p => p.admin).map(p => p.id).includes(senderJid);
  } catch(e) { return false; }
}

function getMentioned(msg) {
  try {
    var ext = msg.message && msg.message.extendedTextMessage;
    if (ext && ext.contextInfo && ext.contextInfo.mentionedJid) return ext.contextInfo.mentionedJid;
  } catch(e) {}
  return [];
}

async function handleGC(sock, jid, text, msg) {
  var raw = text.trim(), cmd = raw.toLowerCase();
  var args = raw.split(/\s+/);
  var senderJid = msg.key.participant || msg.key.remoteJid;
  var mentioned = getMentioned(msg);

  // Owner commands in GC
  if (isOwner(senderJid) || isOfficer(senderJid)) {
    var ownerResult = await handleOwnerCmd(sock, jid, raw, msg);
    if (ownerResult !== false) return;
  }

  // Info commands — anyone
  if (cmd === '!menu' || cmd === '!help') return send(sock, jid, T_gchelp(), msg);
  if (cmd === '!ping') { var t0 = Date.now(); return send(sock, jid, T_ping(Date.now()-t0), msg); }
  if (cmd === '!status') return send(sock, jid, T_status(), msg);
  if (cmd === '!uptime') return send(sock, jid, wm('\u23f1\ufe0f Uptime: *'+getUptime()+'*'), msg);
  if (cmd === '!staff') return send(sock, jid, T_staff(), msg);
  if (cmd === '!links') return send(sock, jid, T_links(), msg);
  if (cmd === '!protect' || cmd === '!unprotect') return send(sock, jid, wm('\ud83d\udee1\ufe0f Protection is always *ACTIVE* \u2014 cannot be disabled!'), msg);

  if (cmd === '!info') {
    try {
      var meta = await sock.groupMetadata(jid);
      return send(sock, jid, wm('\u2139\ufe0f *Group Info*\n\n\ud83d\udcdb Name: *' + meta.subject + '*\n\ud83d\udc65 Members: *' + meta.participants.length + '*\n\ud83d\udc51 Admins: *' + meta.participants.filter(p=>p.admin).length + '*\n\ud83d\udcdd Desc: ' + (meta.desc||'None')), msg);
    } catch(e) { return send(sock, jid, wm('\u274c Could not fetch group info.'), msg); }
  }

  if (cmd === '!link') {
    try { var inv = await sock.groupInviteCode(jid); return send(sock, jid, wm('\ud83d\udd17 https://chat.whatsapp.com/'+inv), msg); }
    catch(e) { return send(sock, jid, wm('\u274c Need bot to be admin.'), msg); }
  }

  // Admin only
  var adminCmds = ['!add','!kick','!promote','!demote','!setname','!setdesc','!setpic','!everyone','!tagall','!revoke'];
  if (adminCmds.some(c => cmd.startsWith(c))) {
    var isAdmin = await isGroupAdmin(sock, jid, senderJid);
    if (!isAdmin) return send(sock, jid, wm('\u26d4 *Admins Only*'), msg);
  }

  if (args[0].toLowerCase() === '!add') {
    var num = (args[1]||'').replace(/[^0-9]/g,'');
    if (!num) return send(sock, jid, wm('\u274c Format: *!add +2348012345678*'), msg);
    try {
      var r = await sock.groupParticipantsUpdate(jid, [num+'@s.whatsapp.net'], 'add');
      var st = r && r[0] && r[0].status;
      if (st==='200') return send(sock, jid, wm('\u2705 *+'+num+'* added!'), msg);
      if (st==='403') return send(sock, jid, wm('\u274c +'+num+' has privacy settings blocking group adds.'), msg);
      if (st==='404') return send(sock, jid, wm('\u274c +'+num+' not on WhatsApp.'), msg);
      return send(sock, jid, wm('\u274c Could not add (code: '+st+')'), msg);
    } catch(e) { return send(sock, jid, wm('\u274c Add failed: '+e.message), msg); }
  }
  if (args[0].toLowerCase()==='!kick') {
    if (!mentioned.length) return send(sock, jid, wm('\u274c Format: *!kick @person*'), msg);
    try { await sock.groupParticipantsUpdate(jid, mentioned, 'remove'); return send(sock, jid, wm('\u2705 Member removed.'), msg); }
    catch(e) { return send(sock, jid, wm('\u274c Kick failed: '+e.message), msg); }
  }
  if (args[0].toLowerCase()==='!promote') {
    if (!mentioned.length) return send(sock, jid, wm('\u274c Format: *!promote @person*'), msg);
    try { await sock.groupParticipantsUpdate(jid, mentioned, 'promote'); return send(sock, jid, wm('\u2705 Promoted to Admin! \ud83d\udc51'), msg); }
    catch(e) { return send(sock, jid, wm('\u274c Promote failed.'), msg); }
  }
  if (args[0].toLowerCase()==='!demote') {
    if (!mentioned.length) return send(sock, jid, wm('\u274c Format: *!demote @person*'), msg);
    try { await sock.groupParticipantsUpdate(jid, mentioned, 'demote'); return send(sock, jid, wm('\u2705 Admin removed.'), msg); }
    catch(e) { return send(sock, jid, wm('\u274c Demote failed.'), msg); }
  }
  if (args[0].toLowerCase()==='!setname') {
    var n = args.slice(1).join(' ');
    if (!n) return send(sock, jid, wm('\u274c Format: *!setname New Name*'), msg);
    try { await sock.groupUpdateSubject(jid, n); return send(sock, jid, wm('\u2705 Group renamed to *'+n+'*'), msg); }
    catch(e) { return send(sock, jid, wm('\u274c Could not rename.'), msg); }
  }
  if (args[0].toLowerCase()==='!setdesc') {
    var d = args.slice(1).join(' ');
    if (!d) return send(sock, jid, wm('\u274c Format: *!setdesc Description*'), msg);
    try { await sock.groupUpdateDescription(jid, d); return send(sock, jid, wm('\u2705 Description updated!'), msg); }
    catch(e) { return send(sock, jid, wm('\u274c Could not update.'), msg); }
  }
  if (args[0].toLowerCase()==='!setpic') {
    var ctx = msg.message && msg.message.extendedTextMessage && msg.message.extendedTextMessage.contextInfo;
    if (!ctx || !ctx.quotedMessage || !ctx.quotedMessage.imageMessage) return send(sock, jid, wm('\u274c *Reply to an image* with !setpic'), msg);
    try {
      var buf = await sock.downloadMediaMessage({ message:{ imageMessage:ctx.quotedMessage.imageMessage }, key:{ remoteJid:jid } });
      await sock.updateProfilePicture(jid, buf);
      return send(sock, jid, wm('\u2705 Group picture updated!'), msg);
    } catch(e) { return send(sock, jid, wm('\u274c Could not set picture.'), msg); }
  }
  if (cmd==='!everyone'||cmd==='!tagall') {
    try {
      var meta2 = await sock.groupMetadata(jid);
      var members = meta2.participants.map(p=>p.id);
      var tagText = '\ud83d\udce2 *Attention!*\n' + members.map(m=>'@'+m.split('@')[0]).join(' ') + CONFIG.WATERMARK;
      await sock.sendMessage(jid, { text: tagText, mentions: members });
    } catch(e) { return send(sock, jid, wm('\u274c Could not tag all.'), msg); }
    return;
  }
  if (cmd==='!revoke') {
    try {
      await sock.groupRevokeInvite(jid);
      var nc = await sock.groupInviteCode(jid);
      return send(sock, jid, wm('\u2705 Link reset!\n\nhttps://chat.whatsapp.com/'+nc), msg);
    } catch(e) { return send(sock, jid, wm('\u274c Could not reset link.'), msg); }
  }
}

// ─── Main bot ─────────────────────────────────────────────────────────────────
async function startBot() {
  // Clear session if requested
  if (process.env.CLEAR_SESSION === 'true') {
    if (fs.existsSync('./auth_info')) { fs.rmSync('./auth_info', { recursive:true, force:true }); console.log('[Bot] Session cleared.'); }
  }

  const { state, saveCreds } = await useMultiFileAuthState('./auth_info');
  const { version }          = await fetchLatestBaileysVersion();

  const sock = makeWASocket({
    version,
    auth             : { creds:state.creds, keys:makeCacheableSignalKeyStore(state.keys, pino({ level:'silent' })) },
    printQRInTerminal: true,
    logger           : pino({ level:'silent' }),
    browser          : ['BoostNG Assistant', 'Chrome', '120.0.0'],
  });

  globalSock = sock;
  sock.ev.on('creds.update', saveCreds);

  sock.ev.on('connection.update', async ({ connection, lastDisconnect, qr }) => {
    if (qr) {
      latestQR = qr;
      qrcode.generate(qr, { small: true });
      console.log('\n\ud83d\udd11 Or visit: ' + CONFIG.RAILWAY_URL + '/qr\n\ud83d\udcf1 Or visit: ' + CONFIG.RAILWAY_URL + '/pair\n');
    }
    if (connection === 'close') {
      var code = lastDisconnect?.error?.output?.statusCode;
      if (code !== DisconnectReason.loggedOut) { console.log('[Bot] Reconnecting...'); setTimeout(startBot, 5000); }
      else { console.log('[Bot] Logged out. Delete auth_info and restart.'); }
    } else if (connection === 'open') {
      STATS.startTime = Date.now();
      latestQR = null;
      console.log('\n\u2705 BoostNG Bot LIVE!\n\ud83d\udee1\ufe0f 20 security layers active\n\ud83d\udc51 ' + OWNERS.size + ' owners loaded\n\u00a9 2026 Mayor Tech Inc\n');
    }
  });

  sock.ev.on('messages.upsert', async ({ messages, type }) => {
    if (type !== 'notify') return;
    for (var msg of messages) {
      try {
        if (msg.key.fromMe || !msg.message) continue;
        var jid   = msg.key.remoteJid;
        var isGC  = jid && jid.endsWith('@g.us');
        var senderJid = isGC ? (msg.key.participant || jid) : jid;
        var text  = msg.message?.conversation
          || msg.message?.extendedTextMessage?.text
          || msg.message?.imageMessage?.caption || '';

        STATS.scanned++;

        // ── Blacklist check ──
        if (BLACKLIST.has(senderJid)) {
          try { await sock.sendMessage(msg.key.remoteJid, { delete: msg.key }); } catch(e) {}
          continue;
        }

        // ── Temp block check ──
        var blockUntil = tempBlocked.get(senderJid);
        if (blockUntil) {
          if (Date.now() < blockUntil) {
            try { await sock.sendMessage(msg.key.remoteJid, { delete: msg.key }); } catch(e) {}
            continue;
          }
          tempBlocked.delete(senderJid);
        }

        // ── Full security scan ──
        var threat = scanMessage(msg, text);
        if (threat) {
          await handleThreat(sock, senderJid, msg, threat, isGC);
          continue;
        }

        // ── Spam check ──
        if (checkSpam(senderJid)) {
          await handleThreat(sock, senderJid, msg, { name:'Spam Flood', level:THREAT.MEDIUM, category:'spam' }, isGC);
          continue;
        }

        // ── Anti-ban delay ──
        await delay(200, 600);

        // ── Groups ──
        if (isGC) {
          if (text && (text.startsWith('!') || /^\.(pair|mode)/i.test(text))) {
            await handleGC(sock, jid, text, msg);
          }
          continue;
        }

        // ── DMs ──
        console.log('[DM] ' + (isOwner(senderJid)?'\ud83d\udc51 ':'') + senderJid.split('@')[0] + ': ' + text.slice(0,50));

        // Owner/Officer commands
        if (isOwner(senderJid) || isOfficer(senderJid)) {
          if (text && (/^\.(pair|mode)/i.test(text) || /^(add_owner|remove_owner|list_owners)/i.test(text))) {
            await handleOwnerCmd(sock, jid, text, msg);
            continue;
          }
        }

        // Private mode check
        if (BOT_MODE === 'private' && !isOfficer(senderJid)) {
          await send(sock, jid, T_private());
          continue;
        }

        // Session
        var session = userSessions.get(jid) || { step:'welcome', history:[] };

        // Join verification
        if (!verifiedUsers.has(jid) && !isOfficer(senderJid)) {
          if (text.trim().toUpperCase() === 'JOINED') {
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

        await handleMenu(sock, jid, text, session, false);
        userSessions.set(jid, session);

      } catch(e) { console.error('[Handler]', e.message); }
    }
  });
}

// ─── HTTP Server ──────────────────────────────────────────────────────────────
http.createServer(async (req, res) => {
  var urlMod = require('url');
  var parsed = urlMod.parse(req.url, true);
  var p      = parsed.pathname;

  // /debug
  if (p === '/debug') {
    var files = fs.readdirSync('/app').filter(f => !f.startsWith('.') && f !== 'node_modules');
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ files, logoExists: fs.existsSync(CONFIG.LOGO_PATH), owners: Array.from(OWNERS) }, null, 2));
    return;
  }

  // /qr
  if (p === '/qr') {
    if (!latestQR) {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end('<!DOCTYPE html><html><head><meta http-equiv="refresh" content="3"><style>body{background:#0d0d1a;color:#fff;font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;text-align:center}</style></head><body><h2 style="color:#00e87a">' + (latestQR===null && globalSock ? '✅ Already linked! Bot is live.' : '⏳ Waiting for QR...') + '</h2><p>Page refreshes automatically</p></body></html>');
      return;
    }
    try {
      var qrDataUrl = await QRCode.toDataURL(latestQR, { width:300, margin:2 });
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end('<!DOCTYPE html><html><head><title>BoostNG QR</title><meta name="viewport" content="width=device-width,initial-scale=1"><style>*{box-sizing:border-box;margin:0;padding:0}body{background:#0d0d1a;color:#fff;font-family:sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:20px}.card{background:#1a1a2e;border:1px solid rgba(0,232,122,0.3);border-radius:16px;padding:32px;max-width:380px;width:100%;text-align:center}h1{color:#00e87a;margin-bottom:8px}p{color:rgba(255,255,255,0.4);font-size:12px;margin-bottom:20px}img{border-radius:12px;border:4px solid #00e87a;width:260px}a{color:#00e87a;font-size:12px;display:block;margin-top:16px;text-decoration:none}.warn{color:orange;font-size:11px;margin-top:12px}</style></head><body><div class="card"><h1>📱 Scan QR</h1><p>WhatsApp → Linked Devices → Link a Device</p><img src="'+qrDataUrl+'" alt="QR"><div class="warn">⏰ Refresh if expired (~20 seconds)</div><a href="/qr">🔄 Refresh</a><a href="/pair">🔑 Use Pairing Code instead</a></div></body></html>');
    } catch(e) { res.writeHead(500); res.end('QR error: '+e.message); }
    return;
  }

  // /pair
  if (p === '/pair') {
    var num = (parsed.query.number || '').replace(/[^0-9]/g, '');
    if (!num) {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end('<!DOCTYPE html><html><head><title>BoostNG Pair</title><meta name="viewport" content="width=device-width,initial-scale=1"><style>*{box-sizing:border-box;margin:0;padding:0}body{background:#0d0d1a;color:#fff;font-family:sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:20px}.card{background:#1a1a2e;border:1px solid rgba(0,232,122,0.2);border-radius:16px;padding:32px;max-width:400px;width:100%;text-align:center}h1{color:#00e87a;margin-bottom:8px}p{color:rgba(255,255,255,0.5);font-size:13px;margin-bottom:24px}input{width:100%;background:rgba(255,255,255,0.06);border:1px solid rgba(255,255,255,0.15);border-radius:10px;padding:14px;color:#fff;font-size:16px;outline:none;margin-bottom:16px;text-align:center}input:focus{border-color:#00e87a}button{width:100%;background:#00e87a;border:none;color:#000;padding:14px;border-radius:10px;font-size:15px;font-weight:700;cursor:pointer}.hint{color:rgba(255,255,255,0.3);font-size:11px;margin-top:12px}a{color:#00e87a;font-size:12px;display:block;margin-top:16px;text-decoration:none}</style></head><body><div class="card"><h1>🔑 Get Pairing Code</h1><p>Enter your WhatsApp number</p><form action="/pair" method="get"><input name="number" placeholder="2348012345678" type="tel" autofocus><button type="submit">⚡ Generate Code</button></form><div class="hint">Country code, no + sign</div><a href="/qr">📱 Scan QR instead</a></div></body></html>');
      return;
    }
    if (!globalSock) { res.writeHead(503); res.end('<h2 style="color:red;font-family:sans-serif;padding:40px">Bot not ready. Try again in 10 seconds.</h2>'); return; }
    try {
      var code = await globalSock.requestPairingCode(num + '@s.whatsapp.net');
      STATS.pairings++;
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end('<!DOCTYPE html><html><head><title>Pairing Code</title><meta name="viewport" content="width=device-width,initial-scale=1"><style>*{box-sizing:border-box;margin:0;padding:0}body{background:#0d0d1a;color:#fff;font-family:sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:20px}.card{background:#1a1a2e;border:1px solid rgba(0,232,122,0.3);border-radius:16px;padding:32px;max-width:420px;width:100%;text-align:center}h1{color:#00e87a;margin-bottom:8px}.code{font-size:42px;font-weight:900;color:#00e87a;letter-spacing:8px;margin:20px 0;font-family:monospace}.num{color:rgba(255,255,255,0.4);font-size:13px;margin-bottom:16px}.steps{background:rgba(0,232,122,0.06);border-radius:10px;padding:16px;font-size:13px;line-height:2;text-align:left;color:rgba(255,255,255,0.7)}.warn{color:orange;font-size:11px;margin-top:12px}a{color:#00e87a;font-size:12px;display:block;margin-top:16px;text-decoration:none}</style></head><body><div class="card"><h1>✅ Code Ready!</h1><div class="num">+'+num+'</div><div class="code">'+code+'</div><div class="steps">1. Open WhatsApp<br>2. Menu → Linked Devices<br>3. Link a Device<br>4. Link with phone number<br>5. Enter code above ✅</div><div class="warn">⏰ Expires in 60 seconds!</div><a href="/pair">← Generate another</a><a href="/qr">📱 Use QR instead</a></div></body></html>');
    } catch(e) { res.writeHead(400); res.end('<div style="font-family:sans-serif;padding:40px;color:#ff6b6b"><h2>❌ '+e.message+'</h2><a href="/pair" style="color:#00e87a">← Try again</a></div>'); }
    return;
  }

  // / status
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({
    status:'online', bot:'BoostNG Assistant v2', mode:BOT_MODE,
    uptime:getUptime(), security:'20 layers', owners:OWNERS.size,
    scanned:STATS.scanned, blocked:STATS.blocked, ai:STATS.aiReplies,
    qr: CONFIG.RAILWAY_URL+'/qr', pair: CONFIG.RAILWAY_URL+'/pair',
    copy:'© 2026 Mayor Tech Inc',
  }));
}).listen(CONFIG.PORT, () => {
  console.log('[HTTP] Port', CONFIG.PORT);
  console.log('[HTTP] QR page:', CONFIG.RAILWAY_URL + '/qr');
  console.log('[HTTP] Pair page:', CONFIG.RAILWAY_URL + '/pair');
});

startBot().catch(console.error);
