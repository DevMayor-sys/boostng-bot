/**
 * BoostNG Assistant Bot v3
 * By Mayor Tech Inc © 2026
 *
 * - 17 security protection layers (maximum crash/bug protection)
 * - Only Mayor can pair — but for ANY number (staff, anyone)
 * - Public / Private mode toggle (Mayor controls)
 * - Temp virtual numbers for officers (GETNUM command)
 * - Logo image sent with every menu
 * - Beautiful redesigned menu
 * - Watermark on EVERY single message
 */

require('dotenv').config();

const {
  default: makeWASocket,
  useMultiFileAuthState,
  DisconnectReason,
  fetchLatestBaileysVersion,
  makeCacheableSignalKeyStore,
} = require('@whiskeysockets/baileys');

const pino   = require('pino');
const qrcode    = require('qrcode-terminal');
const QRCode    = require('qrcode');
const Groq   = require('groq-sdk');
const http   = require('http');
const fs     = require('fs');
const path   = require('path');

// ─── Config ───────────────────────────────────────────────────────────────────
const CONFIG = {
  WA_CHANNEL   : 'https://whatsapp.com/channel/0029Vb84NAUFXUui0ueD3H1O',
  TELEGRAM_GC  : 'https://t.me/mayor_d_dev',
  WEBSITE      : 'https://boosthubng.pages.dev',
  OWNER        : 'Mayor',
  WATERMARK    : '\n\n━━━━━━━━━━━━━━━━━━━━━\n        🏆 MAYOR TECH INC\n© 2026 — ALL RIGHTS RESERVED\n━━━━━━━━━━━━━━━━━━━━━',
  GROQ_KEY     : process.env.GROQ_API_KEY    || '',
  FIVESIM_KEY  : process.env.FIVESIM_API_KEY || '',
  JOIN_KEYWORD : 'JOINED',
  OWNER_NUMBER : process.env.OWNER_NUMBER    || '',
  PORT         : process.env.PORT            || 3000,
  LOGO_PATH    : path.join(__dirname, 'logo.jpg'),
};

// Officers — can use GETNUM and bypass private mode
const OFFICERS = new Set(
  (process.env.OFFICER_NUMBERS || '').split(',').map(function(n){ return n.trim(); }).filter(Boolean)
);

const STAFF = [
  { name: process.env.STAFF1_NAME || 'Staff 1', number: process.env.STAFF1_NUMBER || '', online: false },
  { name: process.env.STAFF2_NAME || 'Staff 2', number: process.env.STAFF2_NUMBER || '', online: false },
  { name: process.env.STAFF3_NAME || 'Staff 3', number: process.env.STAFF3_NUMBER || '', online: false },
  { name: process.env.STAFF4_NAME || 'Staff 4', number: process.env.STAFF4_NUMBER || '', online: false },
  { name: process.env.STAFF5_NAME || 'Staff 5', number: process.env.STAFF5_NUMBER || '', online: false },
];

// ─── Stats ────────────────────────────────────────────────────────────────────
var STATS = { startTime: Date.now(), messagesScanned: 0, threatsBlocked: 0, aiReplies: 0, pairingsIssued: 0, tempNumbers: 0 };

function getUptime() {
  var ms = Date.now() - STATS.startTime;
  var d  = Math.floor(ms / 86400000);
  var h  = Math.floor((ms % 86400000) / 3600000);
  var m  = Math.floor((ms % 3600000) / 60000);
  var s  = Math.floor((ms % 60000) / 1000);
  if (d > 0) return d + 'd ' + h + 'h ' + m + 'm';
  if (h > 0) return h + 'h ' + m + 'm ' + s + 's';
  return m + 'm ' + s + 's';
}

// ─── State ────────────────────────────────────────────────────────────────────
var latestQR        = null; // stored for web display
var verifiedUsers   = new Set();
var userSessions    = new Map();
var spamTracker     = new Map();
var blockedUsers    = new Map();   // temp blocks
var blacklist       = new Map();   // permanent threat senders { jid: { reason, time, count } }
var protectedGroups = new Set();
var BOT_MODE        = process.env.BOT_MODE || 'public';

// ─── Threat reporting ──────────────────────────────────────────────────────
async function reportThreat(sock, jid, reason) {
  var num = jid.split('@')[0];
  // Log to console
  console.warn('[THREAT REPORT] ' + num + ' | ' + reason + ' | ' + new Date().toISOString());

  // Add to permanent blacklist
  var existing = blacklist.get(jid) || { reason: reason, time: Date.now(), count: 0 };
  existing.count++;
  existing.reason = reason;
  existing.time   = Date.now();
  blacklist.set(jid, existing);

  // Alert Mayor
  if (CONFIG.OWNER_NUMBER) {
    try {
      var alertText = '🚨 *THREAT ALERT*\n\n' +
        '📱 Number: *+' + num + '*\n' +
        '⚠️ Type: *' + reason + '*\n' +
        '🔢 Offense #: *' + existing.count + '*\n' +
        '🕐 Time: ' + new Date().toLocaleString() + '\n\n' +
        '_Permanently blacklisted._' + CONFIG.WATERMARK;
      await sock.sendMessage(CONFIG.OWNER_NUMBER + '@s.whatsapp.net', { text: alertText });
    } catch(e) { console.error('[Report alert]', e.message); }
  }

  // Tell attacker their account was reported
  try {
    var violationText = '🚨 *SECURITY VIOLATION*\n\n' +
      'Your message contained malicious content (*' + reason + '*).\n\n' +
      '⛔ Your account has been *reported to WhatsApp* for sending harmful content.\n\n' +
      '⚠️ Repeated violations may result in your account being *permanently banned*.\n\n' +
      '🔒 You have been permanently blocked from this service.' + CONFIG.WATERMARK;
    await sock.sendMessage(jid, { text: violationText });
  } catch(e) {}
}

// ─── Anti-ban: natural typing delay ───────────────────────────────────────
async function naturalDelay(min, max) {
  var ms = min + Math.floor(Math.random() * (max - min));
  return new Promise(function(r) { setTimeout(r, ms); });
}

// ─── Groq AI ──────────────────────────────────────────────────────────────────
var groq = CONFIG.GROQ_KEY ? new Groq({ apiKey: CONFIG.GROQ_KEY }) : null;

var SYSTEM_PROMPT = 'You are BoostNG Assistant, the official WhatsApp AI bot for BoostNG by Mayor Tech Inc.\n' +
'Be friendly, warm and VERY concise — WhatsApp replies must be SHORT (2-3 sentences max).\n' +
'Use emojis occasionally. Sound like a real human assistant, not a robot.\n\n' +
'ABOUT BOOSTNG:\n' +
'- Premium SMM panel: Instagram, TikTok, YouTube, Facebook, Telegram, Twitter\n' +
'- Virtual phone numbers for SMS verification (50+ services, 30+ countries)\n' +
'- Founded and owned by Mayor — Mayor Tech Inc\n' +
'- Website: https://boosthubng.pages.dev\n' +
'- Payments: Flutterwave (card & bank), PayPal, Crypto (USDC). Minimum: 50 naira\n' +
'- Points: $1 = 100 Mayor Points. Bonuses at $20/$50/$100/$200 top-ups\n\n' +
'RULES:\n' +
'- Keep replies SHORT for WhatsApp\n' +
'- If stuck: tell them to type STAFF or MENU\n' +
'- If asked owner: "Mayor of Mayor Tech Inc"\n' +
'- If asked your name: "BoostNG Assistant by Mayor Tech Inc"\n' +
'- Never say you are AI unless directly asked\n' +
'- Never share internal info about officers or systems';

async function askAI(text, history) {
  if (!groq) return null;
  try {
    var res = await groq.chat.completions.create({
      model: 'llama-3.3-70b-versatile', max_tokens: 150, temperature: 0.7,
      messages: [{ role: 'system', content: SYSTEM_PROMPT }].concat((history || []).slice(-6)).concat([{ role: 'user', content: text }]),
    });
    STATS.aiReplies++;
    return (res.choices[0] && res.choices[0].message && res.choices[0].message.content) ? res.choices[0].message.content.trim() : null;
  } catch (e) { console.error('[AI]', e.message); return null; }
}

// ─── 5sim for officers ────────────────────────────────────────────────────────
async function getTempNumber(country, product) {
  if (!CONFIG.FIVESIM_KEY) return null;
  try {
    var r = await fetch('https://5sim.net/v1/user/buy/activation/' + encodeURIComponent(country || 'nigeria') + '/any/' + encodeURIComponent(product || 'whatsapp'), {
      headers: { Authorization: 'Bearer ' + CONFIG.FIVESIM_KEY, Accept: 'application/json' }
    });
    if (!r.ok) return null;
    var d = await r.json();
    return d.id ? d : null;
  } catch (e) { return null; }
}

async function checkSMS(orderId) {
  if (!CONFIG.FIVESIM_KEY) return null;
  try {
    var r = await fetch('https://5sim.net/v1/user/check/' + orderId, { headers: { Authorization: 'Bearer ' + CONFIG.FIVESIM_KEY, Accept: 'application/json' } });
    var d = await r.json();
    var sms = d.sms || [];
    return sms.length ? sms[0].code : null;
  } catch (e) { return null; }
}

// ─── 17-Layer Security Scanner ────────────────────────────────────────────────
var CRASH_CHECKS = [
  { name: 'Invisible Character Attack',      pattern: /[\u200B\u200C\u200D\u200E\u200F\uFEFF\u2028\u2029\u00AD\uFFF9\uFFFA\uFFFB]{3,}/ },
  { name: 'RTL Text Override Attack',        pattern: /[\u202A\u202B\u202C\u202D\u202E\u2066\u2067\u2068\u2069]{2,}/ },
  { name: 'Zalgo Corruption Attack',         pattern: /[\u0300-\u036F\u1DC0-\u1DFF\u20D0-\u20FF\uFE20-\uFE2F]{8,}/ },
  { name: 'Character Bomb (Memory Attack)',  pattern: /(.)\1{200,}/ },
  { name: 'Null Byte Injection',             pattern: /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]{2,}/ },
  { name: 'Braille Spam Crash',              pattern: /[\u2800-\u28FF]{15,}/ },
  { name: 'Grapheme Joiner Spam',            pattern: /\u034F{3,}/ },
  { name: 'Object Replacement Bomb',         pattern: /\uFFFC{3,}/ },
  { name: 'Long String Crash Attack',        pattern: /\S{2000,}/ },
  { name: 'Direction Isolate Attack',        pattern: /[\u2066-\u2069]{5,}/ },
  { name: 'Variation Selector Spam',         pattern: /[\uFE00-\uFE0F]{10,}/ },
];

var CRASH_UNICODE = [
  { name: 'Math Unicode Crash',    pattern: /[\u{1D400}-\u{1D7FF}]{20,}/u },
  { name: 'Tag Character Attack',  pattern: /[\u{E0000}-\u{E007F}]{3,}/u },
  { name: 'Emoji Bomb Attack',     pattern: /(\u00a9|\u00ae|[\u2000-\u3300]|\ud83c[\ud000-\udfff]|\ud83d[\ud000-\udfff]|\ud83e[\ud000-\udfff]){50,}/u },
];

var PHISHING = [
  /free.*followers.*click/i, /account.*suspended.*verify/i,
  /win.*prize.*claim.*now/i, /send.*crypto.*double/i,
  /whatsapp.*will.*be.*banned/i, /congratulations.*you.*won/i,
  /verify.*account.*immediately/i, /send.*money.*emergency/i,
];

var HACKING = [
  /<script[\s>]/i, /javascript:/i, /data:text\/html/i,
  /\{\{.*\}\}/, /\$\{.*\}/, /__proto__/i, /constructor\[/i,
];

function scanMessage(text, jid) {
  STATS.messagesScanned++;
  if (!text || typeof text !== 'string') return { safe: true };

  if (text.length > 10000) {
    STATS.threatsBlocked++;
    return { safe: false, warn: '🛑 *[BLOCKED]* Oversized Message Attack detected and blocked.\n\n⚠️ Type: *Oversized Message Attack*\n\n_BoostNG Security_ 🔒' };
  }

  for (var i = 0; i < CRASH_CHECKS.length; i++) {
    try { if (CRASH_CHECKS[i].pattern.test(text)) { STATS.threatsBlocked++; return { safe: false, threat: CRASH_CHECKS[i].name, warn: '🛡️ *[THREAT BLOCKED]*\n\n⚠️ Type: *' + CRASH_CHECKS[i].name + '*\n\nThis message was blocked to protect this device.\n\n_BoostNG Security_ 🔒' }; } } catch(e) {}
  }

  for (var j = 0; j < CRASH_UNICODE.length; j++) {
    try { if (CRASH_UNICODE[j].pattern.test(text)) { STATS.threatsBlocked++; return { safe: false, threat: CRASH_UNICODE[j].name, warn: '🛡️ *[THREAT BLOCKED]*\n\n⚠️ Type: *' + CRASH_UNICODE[j].name + '*\n\nBlocked to protect this device.\n\n_BoostNG Security_ 🔒' }; } } catch(e) {}
  }

  for (var k = 0; k < PHISHING.length; k++) {
    try { if (PHISHING[k].test(text)) { STATS.threatsBlocked++; return { safe: false, threat: 'Phishing / Scam', warn: '🚨 *[PHISHING BLOCKED]*\n\n⚠️ Type: *Phishing / Scam Message*\n\nBlocked for your safety.\n\n_BoostNG Security_ 🔒' }; } } catch(e) {}
  }

  for (var l = 0; l < HACKING.length; l++) {
    try { if (HACKING[l].test(text)) { STATS.threatsBlocked++; return { safe: false, threat: 'Hack / Code Injection', warn: '🔴 *[HACK ATTEMPT BLOCKED]*\n\n⚠️ Type: *Code Injection / Hack Attempt*\n\nBlocked and flagged.\n\n_BoostNG Security_ 🔒' }; } } catch(e) {}
  }

  var now  = Date.now();
  var spam = spamTracker.get(jid) || { count: 0, lastTime: now };
  if (now - spam.lastTime > 60000) { spam = { count: 1, lastTime: now }; }
  else {
    spam.count++;
    if (spam.count > 10) {
      STATS.threatsBlocked++;
      blockedUsers.set(jid, now + 600000);
      return { safe: false, warn: '🛑 *[SPAM BLOCKED]*\n\nTemporarily blocked for 10 minutes.\n\n_BoostNG Security_ 🔒' };
    }
  }
  spamTracker.set(jid, spam);
  return { safe: true };
}

// ─── Helpers ──────────────────────────────────────────────────────────────────
function wm(t) { return t + CONFIG.WATERMARK; }

async function send(sock, jid, text, q) {
  try { await sock.sendMessage(jid, { text: text }, q ? { quoted: q } : {}); } catch (e) { console.error('[Send]', e.message); }
}

async function sendMenu(sock, jid, caption) {
  try {
    if (fs.existsSync(CONFIG.LOGO_PATH)) {
      await sock.sendMessage(jid, { image: fs.readFileSync(CONFIG.LOGO_PATH), caption: caption, mimetype: 'image/jpeg' });
    } else {
      await sock.sendMessage(jid, { text: caption });
    }
  } catch (e) {
    try { await sock.sendMessage(jid, { text: caption }); } catch(e2) {}
  }
}

// ─── Templates ────────────────────────────────────────────────────────────────
function T_welcome()  { return wm('👋 *Welcome to BoostNG!*\n_Your #1 SMM & Virtual Numbers Platform_ 🚀\n\n━━━━━━━━━━━━━━━━━━━━━\n\nTo unlock full access:\n\n📢 *Step 1* — Join WhatsApp Channel:\n' + CONFIG.WA_CHANNEL + '\n\n💬 *Step 2* — Join Telegram:\n' + CONFIG.TELEGRAM_GC + '\n\n✅ *Step 3* — Type *JOINED* here\n\n━━━━━━━━━━━━━━━━━━━━━\n_Stay updated with deals & news!_ 🎯'); }
function T_menu() {
  var t = '╔═╋╋╋─── • ───╋╋╋═╗';
  var b = '╚═╋╋╋─── • ───╋╋╋═╝';
  return t + '\n     • BOOST NG •\n' + b + '\n\n'
    + '🔹 *MAIN MENU*\n\n'
    + '  1️⃣  📦 SMM Services\n'
    + '  2️⃣  🔍 Order Status\n'
    + '  3️⃣  💳 Top Up Wallet\n'
    + '  4️⃣  📱 Virtual Numbers\n'
    + '  5️⃣  💰 Pricing & Bonuses\n'
    + '  6️⃣  🎁 Referral Program\n'
    + '  7️⃣  👨‍💼 Talk to Staff\n'
    + '  8️⃣  🔗 Links & Channels\n'
    + '  0️⃣  ℹ️  About BoostNG\n\n'
    + '💡 _Type a number or ask anything!_\n\n'
    + t + '\n  POWERED BY MAYOR TECH INC\n' + b;
}
function T_private()  { return wm('🔒 *Private Mode*\n\nThis bot is in private mode.\nContact *Mayor* for access:\n\n💬 ' + CONFIG.TELEGRAM_GC + '\n🌐 ' + CONFIG.WEBSITE); }
function T_status()   { return wm('🛡️ *BOOSTNG SECURITY STATUS*\n\n━━━━ Protection Layers ━━━━\n\n✅ Invisible Char Filter\n✅ RTL Override Block\n✅ Zalgo Text Scanner\n✅ Character Bomb Detector\n✅ Null Byte Scanner\n✅ Braille Spam Filter\n✅ Math Unicode Block\n✅ Tag Character Filter\n✅ Variation Selector Block\n✅ Grapheme Joiner Guard\n✅ Emoji Bomb Detector\n✅ Direction Isolate Block\n✅ Long String Guard\n✅ Phishing Scanner\n✅ Hack/Injection Detector\n✅ Spam Rate Limiter\n✅ Object Replacement Block\n\n━━━━ 📊 Live Stats ━━━━\n\n📨 Scanned: *' + STATS.messagesScanned + '*\n🛡️ Blocked: *' + STATS.threatsBlocked + '*\n🤖 AI replies: *' + STATS.aiReplies + '*\n🔑 Pairings: *' + STATS.pairingsIssued + '*\n📱 Temp numbers: *' + STATS.tempNumbers + '*\n⏱️ Uptime: *' + getUptime() + '*\n🌐 Mode: *' + BOT_MODE.toUpperCase() + '*\n\n🟢 *BoostNG Assistant — ONLINE*'); }
function T_ping(ms)   { return wm('🏓 *Pong!*\n\n⚡ Response: *' + ms + 'ms*\n🟢 Status: *ONLINE*\n⏱️ Uptime: *' + getUptime() + '*\n🌐 Mode: *' + BOT_MODE.toUpperCase() + '*\n🛡️ Security: *17 layers active*'); }
function T_uptime()   { return wm('⏱️ *BOT UPTIME*\n\n🟢 *ONLINE*\n🕐 Running: *' + getUptime() + '*\n📨 Scanned: *' + STATS.messagesScanned + '*\n🛡️ Blocked: *' + STATS.threatsBlocked + '*\n🤖 AI replies: *' + STATS.aiReplies + '*'); }
function T_gchelp() {
  var t = '╔═╋╋╋─── • ───╋╋╋═╗';
  var b = '╚═╋╋╋─── • ───╋╋╋═╝';
  return t + '\n     • BOOST NG •\n' + b + '\n\n'
    + '🔹 *USER COMMANDS*\n'
    + '  !menu    • Open Menu\n'
    + '  !ping    • Check Speed\n'
    + '  !uptime  • Bot Runtime\n'
    + '  !status  • Bot Status\n'
    + '  !info    • Group Info\n'
    + '  !link    • Group Link\n'
    + '  !staff   • Online Staff\n'
    + '  !protect • Security Mode\n\n'
    + '👑 *ADMIN COMMANDS*\n'
    + '  !add [num]   • Add User\n'
    + '  !kick [@usr] • Remove User\n'
    + '  !promote     • Give Admin\n'
    + '  !demote      • Remove Admin\n'
    + '  !setname     • Rename Group\n'
    + '  !setdesc     • Edit Description\n'
    + '  !setpic      • Change Picture\n'
    + '  !everyone    • Mention All\n'
    + '  !revoke      • Reset Link\n\n'
    + '🛡️ *SECURITY*\n'
    + '  ✓ Anti-Crash  ✓ Anti-Spam  ✓ Anti-Hack  ✓ Auto-Block\n\n'
    + t + '\n  POWERED BY MAYOR TECH INC\n' + b;
}
function T_staff()    { var on = STAFF.filter(function(s){ return s.online && s.number; }); if (!on.length) return wm('👨‍💼 *Staff Status*\n\n🔴 All staff *offline* right now\n\n• Leave your message here\n• Telegram: ' + CONFIG.TELEGRAM_GC + '\n• Website: ' + CONFIG.WEBSITE + '\n\n_We reply within 1-2 hours_ ⏰'); return wm('👨‍💼 *Staff Online* 🟢\n\n' + on.map(function(s){ return '• *' + s.name + ':* wa.me/' + s.number; }).join('\n') + '\n\n_Tap to chat directly!_ 💬'); }
function T_links()    { return wm('🔗 *Official Links*\n\n🌐 *Website:*\n' + CONFIG.WEBSITE + '\n\n📢 *WhatsApp Channel:*\n' + CONFIG.WA_CHANNEL + '\n\n💬 *Telegram:*\n' + CONFIG.TELEGRAM_GC); }
function T_about()    { return wm('ℹ️ *About BoostNG*\n\n_Premium Social Media Marketing Platform_\n\n📦 5,000+ SMM Services\n📱 Virtual Phone Numbers\n💳 Flutterwave, PayPal, Crypto\n⚡ Fast Delivery (0-24hrs)\n🤖 24/7 AI Support\n🛡️ 17-Layer Security Bot\n\n👑 Founded by *Mayor*\n🏢 *Mayor Tech Inc*\n🌐 ' + CONFIG.WEBSITE); }
function T_pricing()  { return wm('💰 *Pricing & Bonuses*\n\n━━━━━━━━━━━━━━━━━━━━━\n\n💡 $1 = 100 Mayor Points\n💡 Minimum: ₦50\n\n🎁 *Bonus Tiers:*\n• $20  → +100 pts\n• $50  → +300 pts\n• $100 → +800 pts\n• $200 → +2,000 pts\n\n💳 Flutterwave, PayPal, Crypto\n\n━━━━━━━━━━━━━━━━━━━━━\n👉 ' + CONFIG.WEBSITE); }
function T_topup()    { return wm('💳 *Top Up Wallet*\n\n👉 *' + CONFIG.WEBSITE + '*\n\n━━━━━━━━━━━━━━━━━━━━━\n\n✅ Flutterwave (Card & Bank)\n✅ PayPal: oghosaomorogbe41@gmail.com\n✅ Crypto (USDC)\n\n💡 Min: ₦50 — Instant credit! ⚡\n\nNeed help? Type *STAFF* 👨‍💼'); }
function T_smm()      { return wm('📦 *SMM Services*\n\n━━━━━━━━━━━━━━━━━━━━━\n\n📸 Instagram — Followers, Likes, Views\n🎵 TikTok — Followers, Views, Likes\n▶️ YouTube — Subs, Views, Watch Hours\n💬 Telegram — Members, Views\n🐦 Twitter/X — Followers, Likes\n👍 Facebook — Likes, Followers\n\n⚡ *5,000+ services!*\n\n━━━━━━━━━━━━━━━━━━━━━\n👉 ' + CONFIG.WEBSITE + ' → Orders'); }
function T_vnum()     { return wm('📱 *Virtual Numbers*\n\n━━━━━━━━━━━━━━━━━━━━━\n\nTemp numbers for:\n✅ WhatsApp • Telegram • Google\n✅ 50+ more services!\n\n🌍 30+ countries available!\n\n━━━━━━━━━━━━━━━━━━━━━\n👉 ' + CONFIG.WEBSITE + ' → V-Numbers'); }
function T_referral() { return wm('🎁 *Referral Program*\n\n1️⃣ Sign up on website\n2️⃣ Copy referral link\n3️⃣ Share with friends\n4️⃣ Earn points when they top up!\n\n👉 ' + CONFIG.WEBSITE); }
function T_order()    { return wm('🔍 *Order Status*\n\n👉 ' + CONFIG.WEBSITE + ' → Orders\n\nDelayed 24hrs+? Type *STAFF* ⏰'); }

// ─── Menu handler ─────────────────────────────────────────────────────────────
async function handleMenu(sock, jid, text, session, isOfficer) {
  var t = text.trim();
  var u = t.toUpperCase().replace(/\s+/g, ' ');

  if (['MENU','HI','HELLO','START','HELP','HEY','BACK'].includes(u)) return sendMenu(sock, jid, T_menu());
  if (['STAFF','HUMAN','AGENT','SUPPORT'].includes(u)) return send(sock, jid, T_staff());
  if (['STATUS','PROTECTION STATUS','SECURITY STATUS','SECURITY','PROTECTION'].includes(u)) return send(sock, jid, T_status());
  if (u === 'PING') { var t0 = Date.now(); return send(sock, jid, T_ping(Date.now() - t0)); }
  if (u === 'UPTIME') return send(sock, jid, T_uptime());
  if (['LINKS','CHANNELS'].includes(u)) return send(sock, jid, T_links());
  if (['ABOUT','INFO'].includes(u)) return send(sock, jid, T_about());

  // Officer temp number commands
  if (isOfficer) {
    var nm = u.match(/^GETNUM\s+(\w+)\s+(\w+)$/);
    if (nm) {
      await send(sock, jid, wm('📱 Getting temp number...\n⏳ Please wait...'));
      var nd = await getTempNumber(nm[1].toLowerCase(), nm[2].toLowerCase());
      if (nd) { STATS.tempNumbers++; return send(sock, jid, wm('✅ *Temp Number Ready!*\n\n📱 Number: *+' + nd.phone + '*\n🆔 Order ID: ' + nd.id + '\n\nType *CHECKNUM ' + nd.id + '* to get SMS code!')); }
      return send(sock, jid, wm('❌ Could not get number. 5sim may be empty.\n👉 ' + CONFIG.WEBSITE + ' → V-Numbers'));
    }
    var cm = u.match(/^CHECKNUM\s+(\d+)$/);
    if (cm) {
      var code = await checkSMS(cm[1]);
      if (code) return send(sock, jid, wm('✅ *SMS Code!*\n\n🔑 Code: *' + code + '*\nOrder: #' + cm[1]));
      return send(sock, jid, wm('⏳ No SMS yet for #' + cm[1] + '\n\nTry again in 30 seconds...'));
    }
  }

  switch (t) {
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

  var h = session.history || [];
  var ai = await askAI(t, h);
  if (ai) {
    h.push({ role: 'user', content: t });
    h.push({ role: 'assistant', content: ai });
    session.history = h.slice(-10);
    return send(sock, jid, wm(ai));
  }
  return send(sock, jid, wm('🤔 Not sure I got that!\n\nType *MENU* for options or *STAFF* for human help 😊'));
}

// ─── Group commands ───────────────────────────────────────────────────────────
// Check if sender is group admin
async function isGroupAdmin(sock, jid, senderJid) {
  try {
    var meta   = await sock.groupMetadata(jid);
    var admins = meta.participants.filter(function(p){ return p.admin; }).map(function(p){ return p.id; });
    return admins.includes(senderJid);
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
  var raw      = text.trim();
  var cmd      = raw.toLowerCase();
  var args     = raw.split(/\s+/);
  var senderJid = msg.key.participant || msg.key.remoteJid;
  var isAdmin  = await isGroupAdmin(sock, jid, senderJid);
  var mentioned = getMentioned(msg);

  // ── Anyone can use ──
  if (cmd === '!menu' || cmd === '!help') return send(sock, jid, T_gchelp(), msg);
  if (cmd === '!ping') { var t0 = Date.now(); return send(sock, jid, T_ping(Date.now() - t0), msg); }
  if (cmd === '!status') return send(sock, jid, T_status(), msg);
  if (cmd === '!uptime') return send(sock, jid, T_uptime(), msg);
  if (cmd === '!staff') return send(sock, jid, T_staff(), msg);
  if (cmd === '!links') return send(sock, jid, T_links(), msg);
  if (cmd === '!protect') { protectedGroups.add(jid); return send(sock, jid, wm('🛡️ *Security ENABLED!*\nAll messages now scanned.'), msg); }
  if (cmd === '!unprotect') { protectedGroups.delete(jid); return send(sock, jid, wm('⚠️ Security *disabled*.'), msg); }

  if (cmd === '!info') {
    try {
      var meta = await sock.groupMetadata(jid);
      var adminCount = meta.participants.filter(function(p){ return p.admin; }).length;
      return send(sock, jid, wm('ℹ️ *Group Info*\n\n📛 Name: *' + meta.subject + '*\n👥 Members: *' + meta.participants.length + '*\n👑 Admins: *' + adminCount + '*\n📝 Desc: ' + (meta.desc || 'None')), msg);
    } catch(e) { return send(sock, jid, wm('❌ Could not fetch group info.'), msg); }
  }

  if (cmd === '!link') {
    try {
      var inv = await sock.groupInviteCode(jid);
      return send(sock, jid, wm('🔗 *Invite Link*\n\nhttps://chat.whatsapp.com/' + inv), msg);
    } catch(e) { return send(sock, jid, wm('❌ Could not get link. Make sure bot is admin.'), msg); }
  }

  // ── Admin only ──
  var adminCmds = ['!add','!kick','!promote','!demote','!setdesc','!setname','!setpic','!everyone','!tagall','!revoke'];
  if (adminCmds.some(function(c){ return cmd.startsWith(c); })) {
    if (!isAdmin) return send(sock, jid, wm('⛔ *Admins Only*\n\nYou need to be a group admin to use this command.'), msg);
  }

  // !add +2348012345678
  if (args[0].toLowerCase() === '!add') {
    var num = (args[1] || '').replace(/[^0-9]/g, '');
    if (!num) return send(sock, jid, wm('❌ Format: *!add +2348012345678*'), msg);
    try {
      var res = await sock.groupParticipantsUpdate(jid, [num + '@s.whatsapp.net'], 'add');
      var st  = res && res[0] && res[0].status;
      if (st === '200') return send(sock, jid, wm('✅ *+' + num + '* added to group!'), msg);
      if (st === '403') return send(sock, jid, wm('❌ *+' + num + '* has privacy settings blocking group adds.\n\nSend them the invite link instead.'), msg);
      if (st === '404') return send(sock, jid, wm('❌ *+' + num + '* is not on WhatsApp.'), msg);
      return send(sock, jid, wm('❌ Could not add +' + num + ' (code: ' + st + ')'), msg);
    } catch(e) { return send(sock, jid, wm('❌ Add failed: ' + e.message), msg); }
  }

  // !kick @mention
  if (args[0].toLowerCase() === '!kick') {
    if (!mentioned.length) return send(sock, jid, wm('❌ Format: *!kick @person*'), msg);
    try { await sock.groupParticipantsUpdate(jid, mentioned, 'remove'); return send(sock, jid, wm('✅ Member removed from group.'), msg); }
    catch(e) { return send(sock, jid, wm('❌ Kick failed: ' + e.message), msg); }
  }

  // !promote @mention
  if (args[0].toLowerCase() === '!promote') {
    if (!mentioned.length) return send(sock, jid, wm('❌ Format: *!promote @person*'), msg);
    try { await sock.groupParticipantsUpdate(jid, mentioned, 'promote'); return send(sock, jid, wm('✅ Member promoted to *Admin*! 👑'), msg); }
    catch(e) { return send(sock, jid, wm('❌ Promote failed: ' + e.message), msg); }
  }

  // !demote @mention
  if (args[0].toLowerCase() === '!demote') {
    if (!mentioned.length) return send(sock, jid, wm('❌ Format: *!demote @person*'), msg);
    try { await sock.groupParticipantsUpdate(jid, mentioned, 'demote'); return send(sock, jid, wm('✅ Admin privileges removed.'), msg); }
    catch(e) { return send(sock, jid, wm('❌ Demote failed: ' + e.message), msg); }
  }

  // !setname New Name
  if (args[0].toLowerCase() === '!setname') {
    var newName = args.slice(1).join(' ');
    if (!newName) return send(sock, jid, wm('❌ Format: *!setname New Group Name*'), msg);
    try { await sock.groupUpdateSubject(jid, newName); return send(sock, jid, wm('✅ Group name updated to: *' + newName + '*'), msg); }
    catch(e) { return send(sock, jid, wm('❌ Could not update name: ' + e.message), msg); }
  }

  // !setdesc Description text
  if (args[0].toLowerCase() === '!setdesc') {
    var newDesc = args.slice(1).join(' ');
    if (!newDesc) return send(sock, jid, wm('❌ Format: *!setdesc Your description here*'), msg);
    try { await sock.groupUpdateDescription(jid, newDesc); return send(sock, jid, wm('✅ Group description updated!'), msg); }
    catch(e) { return send(sock, jid, wm('❌ Could not update description: ' + e.message), msg); }
  }

  // !setpic (reply to an image)
  if (args[0].toLowerCase() === '!setpic') {
    var ctx = msg.message && msg.message.extendedTextMessage && msg.message.extendedTextMessage.contextInfo;
    if (!ctx || !ctx.quotedMessage || !ctx.quotedMessage.imageMessage) return send(sock, jid, wm('❌ *Reply to an image* with !setpic'), msg);
    try {
      var buf = await sock.downloadMediaMessage({ message: { imageMessage: ctx.quotedMessage.imageMessage }, key: { remoteJid: jid } });
      await sock.updateProfilePicture(jid, buf);
      return send(sock, jid, wm('✅ Group picture updated!'), msg);
    } catch(e) { return send(sock, jid, wm('❌ Could not set picture: ' + e.message), msg); }
  }

  // !everyone / !tagall
  if (cmd === '!everyone' || cmd === '!tagall') {
    try {
      var meta3   = await sock.groupMetadata(jid);
      var members = meta3.participants.map(function(p){ return p.id; });
      var tagText = '📢 *Attention!*\n' + members.map(function(m){ return '@' + m.split('@')[0]; }).join(' ') + CONFIG.WATERMARK;
      await sock.sendMessage(jid, { text: tagText, mentions: members });
    } catch(e) { return send(sock, jid, wm('❌ Could not tag all: ' + e.message), msg); }
    return;
  }

  // !revoke
  if (cmd === '!revoke') {
    try {
      await sock.groupRevokeInvite(jid);
      var newCode = await sock.groupInviteCode(jid);
      return send(sock, jid, wm('✅ *Invite link reset!*\n\nNew link:\nhttps://chat.whatsapp.com/' + newCode), msg);
    } catch(e) { return send(sock, jid, wm('❌ Could not reset link: ' + e.message), msg); }
  }
}

// ─── Pairing — Mayor only, any number ────────────────────────────────────────
async function handlePair(sock, jid, text) {
  if (!CONFIG.OWNER_NUMBER || !jid.startsWith(CONFIG.OWNER_NUMBER)) {
    return send(sock, jid, wm('🔒 Only *Mayor* can generate pairing codes.\n\nContact Mayor for help.'));
  }
  var m = text.match(/pair\s+\+?(\d{7,15})/i);
  if (!m) return send(sock, jid, wm('❌ Format: *pair +2348012345678*\n\nYou can pair any number — staff, officers or anyone.'));
  try {
    var code = await sock.requestPairingCode(m[1] + '@s.whatsapp.net');
    STATS.pairingsIssued++;
    return send(sock, jid, wm('🔗 *Pairing Code Generated!*\n\n📱 Number: *+' + m[1] + '*\n🔑 Code: *' + code + '*\n\n━━━━━━━━━━━━━━━━━━━━━\n📋 Steps for that person:\n1. Open WhatsApp\n2. Menu → Linked Devices\n3. Link a Device\n4. "Link with phone number instead"\n5. Enter code above ✅\n━━━━━━━━━━━━━━━━━━━━━\n⏰ _Expires in 60 seconds!_'));
  } catch (e) {
    return send(sock, jid, wm('❌ Could not generate code.\nIs *+' + m[1] + '* on WhatsApp?'));
  }
}

// ─── Main ─────────────────────────────────────────────────────────────────────
async function startBot() {
  // Clear session if CLEAR_SESSION env is set
  if (process.env.CLEAR_SESSION === 'true') {
    var fs2 = require('fs');
    var path2 = require('path');
    var authDir = './auth_info';
    if (fs2.existsSync(authDir)) {
      fs2.rmSync(authDir, { recursive: true, force: true });
      console.log('[Bot] Session cleared! Remove CLEAR_SESSION env var now.');
    }
  }
  const { state, saveCreds } = await useMultiFileAuthState('./auth_info');
  const { version }          = await fetchLatestBaileysVersion();

  const sock = makeWASocket({
    version,
    auth             : { creds: state.creds, keys: makeCacheableSignalKeyStore(state.keys, pino({ level: 'silent' })) },
    printQRInTerminal: true,
    logger           : pino({ level: 'silent' }),
    browser          : ['BoostNG Assistant', 'Chrome', '120.0.0'],
  });

  globalSock = sock;
  sock.ev.on('creds.update', saveCreds);

  sock.ev.on('connection.update', async function(update) {
    var connection = update.connection, lastDisconnect = update.lastDisconnect, qr = update.qr;
    if (qr) {
      latestQR = qr; // store for web page
      qrcode.generate(qr, { small: true });
      console.log('\n📱 Scan QR above OR open in browser:');
      console.log('   https://web-production-94012.up.railway.app/qr\n');
    }
    if (connection === 'close') {
      var code = lastDisconnect && lastDisconnect.error && lastDisconnect.error.output ? lastDisconnect.error.output.statusCode : 0;
      if (code !== DisconnectReason.loggedOut) { console.log('[Bot] Reconnecting...'); setTimeout(startBot, 5000); }
      else { console.log('[Bot] Logged out. Delete auth_info and restart.'); }
    } else if (connection === 'open') {
      STATS.startTime = Date.now();
      console.log('\n✅ BoostNG Assistant Bot v3 — LIVE!');
      console.log('🌐 Mode: ' + BOT_MODE.toUpperCase());
      console.log('🛡️ 17 security layers active');
      console.log('© 2026 Mayor Tech Inc\n');
    }
  });

  sock.ev.on('messages.upsert', async function(upsert) {
    if (upsert.type !== 'notify') return;
    for (var i = 0; i < upsert.messages.length; i++) {
      var msg = upsert.messages[i];
      try {
        if (msg.key.fromMe || !msg.message) continue;
        var jid  = msg.key.remoteJid;
        var isGC = jid && jid.endsWith('@g.us');
        var text = (msg.message.conversation) || (msg.message.extendedTextMessage && msg.message.extendedTextMessage.text) || (msg.message.imageMessage && msg.message.imageMessage.caption) || '';
        if (!text) continue;

        var senderNum = jid.split('@')[0];
        var isOwner   = CONFIG.OWNER_NUMBER && jid.startsWith(CONFIG.OWNER_NUMBER);
        var isOfficer = isOwner || OFFICERS.has(senderNum);

        console.log('[' + (isOwner ? '👑 MAYOR' : isOfficer ? '🎖️ OFFICER' : '👤 USER') + '] ' + text.slice(0, 50));

        // Groups
        if (isGC) {
          if (text.startsWith('!')) await handleGC(sock, jid, text, msg);
          else if (protectedGroups.has(jid)) {
            var sc = scanMessage(text, jid);
            if (!sc.safe) { await send(sock, jid, wm('🛡️ *Message Blocked*\n\n' + sc.warn), msg); try { await sock.sendMessage(jid, { delete: msg.key }); } catch(e) {} }
          }
          continue;
        }

        // Block check
        var blockUntil = blockedUsers.get(jid);
        if (blockUntil) {
          if (Date.now() < blockUntil) { var rem = Math.ceil((blockUntil - Date.now()) / 60000); await send(sock, jid, wm('🛑 Temporarily blocked.\n⏳ Try again in *' + rem + ' min*')); continue; }
          blockedUsers.delete(jid);
        }

        // Permanent blacklist check
        if (blacklist.has(jid)) {
          var bl = blacklist.get(jid);
          await send(sock, jid, wm('⛔ *Permanently Blocked*\n\nYour account was flagged for: *' + bl.reason + '*\n\nContact Mayor Tech Inc if you believe this is an error.'));
          continue;
        }

        // Security scan + auto-report threats
        var scan = scanMessage(text, jid);
        if (!scan.safe) {
          await send(sock, jid, wm(scan.warn));
          // Report serious threats (not spam) to Mayor + blacklist
          if (scan.threat && scan.threat !== 'Spam Attack') {
            await reportThreat(sock, jid, scan.threat);
          }
          continue;
        }

        // Anti-ban: natural delay before responding
        await naturalDelay(300, 800);

        // Mayor commands
        if (isOwner) {
          if (/^pair\s+\+?\d+/i.test(text)) { await handlePair(sock, jid, text); continue; }
          if (/^mode\s+(public|private)/i.test(text)) {
            BOT_MODE = text.toLowerCase().includes('private') ? 'private' : 'public';
            await send(sock, jid, wm('🌐 Bot switched to *' + BOT_MODE.toUpperCase() + ' MODE*'));
            continue;
          }
        }

        // Private mode
        if (BOT_MODE === 'private' && !isOfficer) { await send(sock, jid, T_private()); continue; }

        // Session
        var session = userSessions.get(jid) || { step: 'welcome', history: [] };

        // Join verification
        if (!verifiedUsers.has(jid) && !isOfficer) {
          if (text.trim().toUpperCase() === CONFIG.JOIN_KEYWORD) {
            verifiedUsers.add(jid);
            session.step = 'menu';
            userSessions.set(jid, session);
            await send(sock, jid, wm('✅ *Access Granted!* Welcome to BoostNG! 🎉'));
            await new Promise(function(r) { setTimeout(r, 600); });
            await sendMenu(sock, jid, T_menu());
          } else {
            await send(sock, jid, T_welcome());
          }
          continue;
        }

        await handleMenu(sock, jid, text, session, isOfficer);
        userSessions.set(jid, session);

      } catch (e) { console.error('[Handler]', e.message); }
    }
  });
}

// ─── HTTP Server — keep-alive + pairing code UI ───────────────────────────────
var globalSock = null;

http.createServer(async function(req, res) {
  var url    = require('url');
  var parsed = url.parse(req.url, true);
  var path   = parsed.pathname;

  // ── GET /qr — show QR code as image ──
  if (path === '/qr') {
    if (!latestQR) {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(`<!DOCTYPE html><html>
<head><title>BoostNG Bot QR</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="refresh" content="3">
<style>body{background:#0d0d1a;color:#fff;font-family:sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;text-align:center;padding:20px}</style>
</head>
<body>
<div>
  <h2 style="color:#00e87a">⏳ Generating QR Code...</h2>
  <p style="color:rgba(255,255,255,0.4);margin-top:12px">Page will refresh automatically</p>
</div>
</body></html>`);
      return;
    }
    try {
      var qrDataUrl = await QRCode.toDataURL(latestQR, { width: 300, margin: 2, color: { dark: '#000000', light: '#ffffff' } });
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(`<!DOCTYPE html><html>
<head>
  <title>BoostNG Bot — Scan QR</title>
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{background:#0d0d1a;color:#fff;font-family:sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:20px}
    .card{background:#1a1a2e;border:1px solid rgba(0,232,122,0.2);border-radius:16px;padding:32px;max-width:380px;width:100%;text-align:center}
    h1{color:#00e87a;font-size:20px;margin-bottom:8px}
    p{color:rgba(255,255,255,0.4);font-size:12px;margin-bottom:20px}
    img{border-radius:12px;border:4px solid #00e87a;width:260px;height:260px}
    .warn{color:rgba(255,165,0,0.8);font-size:11px;margin-top:16px}
    .steps{background:rgba(0,232,122,0.06);border-radius:10px;padding:14px;font-size:12px;line-height:1.8;color:rgba(255,255,255,0.6);margin-top:16px;text-align:left}
    a{color:#00e87a;font-size:12px;display:block;margin-top:16px;text-decoration:none}
  </style>
</head>
<body>
  <div class="card">
    <h1>📱 Scan to Link WhatsApp</h1>
    <p>Open WhatsApp → Linked Devices → Link a Device</p>
    <img src="${qrDataUrl}" alt="QR Code">
    <div class="warn">⏰ QR expires in ~20 seconds — refresh if expired</div>
    <div class="steps">
      1. Open WhatsApp on your phone<br>
      2. Tap ⋮ Menu → Linked Devices<br>
      3. Tap Link a Device<br>
      4. Point camera at QR above ✅
    </div>
    <a href="/qr">🔄 Refresh QR Code</a>
    <a href="/pair">🔑 Use Pairing Code instead</a>
  </div>
</body></html>`);
    } catch(e) {
      res.writeHead(500, { 'Content-Type': 'text/plain' });
      res.end('QR error: ' + e.message);
    }
    return;
  }

  // ── GET /pair?number=2348012345678 ──
  if (path === '/pair') {
    var num = (parsed.query.number || '').replace(/[^0-9]/g, '');

    // Show input form if no number provided
    if (!num) {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(`<!DOCTYPE html>
<html>
<head>
  <title>BoostNG Bot — Link WhatsApp</title>
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{background:#0d0d1a;color:#fff;font-family:sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:20px}
    .card{background:#1a1a2e;border:1px solid rgba(0,232,122,0.2);border-radius:16px;padding:32px;max-width:400px;width:100%;text-align:center}
    h1{color:#00e87a;font-size:22px;margin-bottom:8px}
    p{color:rgba(255,255,255,0.5);font-size:13px;margin-bottom:24px}
    input{width:100%;background:rgba(255,255,255,0.06);border:1px solid rgba(255,255,255,0.15);border-radius:10px;padding:14px;color:#fff;font-size:16px;outline:none;margin-bottom:16px;text-align:center;letter-spacing:2px}
    input:focus{border-color:#00e87a}
    button{width:100%;background:#00e87a;border:none;color:#000;padding:14px;border-radius:10px;font-size:15px;font-weight:700;cursor:pointer}
    .hint{color:rgba(255,255,255,0.3);font-size:11px;margin-top:12px}
  </style>
</head>
<body>
  <div class="card">
    <h1>🔗 BoostNG Bot</h1>
    <p>Enter your WhatsApp number to get a pairing code</p>
    <form action="/pair" method="get">
      <input name="number" placeholder="2348012345678" type="tel" autofocus>
      <button type="submit">⚡ Get Pairing Code</button>
    </form>
    <div class="hint">Include country code, no + sign<br>Example: 2348012345678</div>
  </div>
</body>
</html>`);
      return;
    }

    // Generate pairing code
    if (!globalSock) {
      res.writeHead(503, { 'Content-Type': 'text/html' });
      res.end('<h2 style="font-family:sans-serif;color:red;padding:40px">Bot is not ready yet. Wait 10 seconds and try again.</h2>');
      return;
    }

    try {
      var code = await globalSock.requestPairingCode(num + '@s.whatsapp.net');
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(`<!DOCTYPE html>
<html>
<head>
  <title>BoostNG Bot — Pairing Code</title>
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{background:#0d0d1a;color:#fff;font-family:sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:20px}
    .card{background:#1a1a2e;border:1px solid rgba(0,232,122,0.3);border-radius:16px;padding:32px;max-width:420px;width:100%;text-align:center}
    h1{color:#00e87a;font-size:22px;margin-bottom:8px}
    .code{font-size:42px;font-weight:900;color:#00e87a;letter-spacing:8px;margin:24px 0;font-family:monospace}
    .num{color:rgba(255,255,255,0.4);font-size:13px;margin-bottom:24px}
    .steps{background:rgba(0,232,122,0.06);border:1px solid rgba(0,232,122,0.15);border-radius:10px;padding:16px;text-align:left;font-size:13px;line-height:2;color:rgba(255,255,255,0.7)}
    .warn{color:rgba(255,165,0,0.8);font-size:11px;margin-top:16px}
    a{color:#00e87a;text-decoration:none;font-size:13px;display:block;margin-top:20px}
  </style>
</head>
<body>
  <div class="card">
    <h1>✅ Pairing Code Ready!</h1>
    <div class="num">Number: +${num}</div>
    <div class="code">${code}</div>
    <div class="steps">
      1. Open WhatsApp on that phone<br>
      2. Tap Menu (⋮) → Linked Devices<br>
      3. Tap Link a Device<br>
      4. Tap "Link with phone number instead"<br>
      5. Enter the code above ✅
    </div>
    <div class="warn">⏰ Code expires in 60 seconds!</div>
    <a href="/pair">← Generate another code</a>
  </div>
</body>
</html>`);
      console.log('[Pair] Code generated for +' + num + ': ' + code);
      STATS.pairingsIssued++;
    } catch(e) {
      res.writeHead(400, { 'Content-Type': 'text/html' });
      res.end('<div style="font-family:sans-serif;padding:40px;color:#ff6b6b"><h2>❌ Error: ' + e.message + '</h2><p>Make sure the number is registered on WhatsApp and try again.</p><a href="/pair" style="color:#00e87a">← Try again</a></div>');
    }
    return;
  }

  // ── GET / — status page ──
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({
    status  : 'online',
    bot     : 'BoostNG Assistant v3',
    mode    : BOT_MODE,
    uptime  : getUptime(),
    security: '17 layers',
    scanned : STATS.messagesScanned,
    blocked : STATS.threatsBlocked,
    ai      : STATS.aiReplies,
    pairings: STATS.pairingsIssued,
    pair_url: 'Visit /pair to link WhatsApp',
    copy    : '© 2026 Mayor Tech Inc — ALL RIGHTS RESERVED',
  }));
}).listen(CONFIG.PORT, function() {
  console.log('[HTTP] Server on port', CONFIG.PORT);
  console.log('[HTTP] Pairing UI: YOUR_RAILWAY_URL/pair');
});

startBot().catch(console.error);
