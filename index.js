/**
 * BoostNG Assistant Bot v2
 * By Mayor Tech Inc © 2026
 *
 * Features:
 * - Pairing code system (no QR needed for staff)
 * - Security scanning (crash, zalgo, phishing, spam, RTL, braille)
 * - Protection status + uptime + ping commands
 * - Group chat commands (!menu !protect !ping !status !uptime !staff)
 * - Channel join verification (type JOINED)
 * - AI powered replies (Groq Llama 3.3)
 * - Interactive menu system
 * - Staff online/offline routing
 * - Watermark on EVERY message
 * - HTTP keep-alive for Railway/Render
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
const qrcode = require('qrcode-terminal');
const Groq   = require('groq-sdk');
const http   = require('http');

// ─── Config ──────────────────────────────────────────────────────────────────
const CONFIG = {
  WA_CHANNEL   : 'https://whatsapp.com/channel/0029Vb84NAUFXUui0ueD3H1O',
  TELEGRAM_GC  : 'https://t.me/mayor_d_dev',
  WEBSITE      : 'https://boosthubng.pages.dev',
  OWNER        : 'Mayor',
  COMPANY      : 'Mayor Tech Inc',
  BOT_NAME     : 'BoostNG Assistant',
  WATERMARK    : '\n\n─────────────────────\n© 2026 MAYOR TECH INC\n─────────────────────',
  GROQ_KEY     : process.env.GROQ_API_KEY || '',
  JOIN_KEYWORD : 'JOINED',
  OWNER_NUMBER : process.env.OWNER_NUMBER || '',
  PORT         : process.env.PORT || 3000,
};

// Staff — set names and numbers in .env
const STAFF = [
  { id: 'staff1', name: process.env.STAFF1_NAME || 'Staff 1', number: process.env.STAFF1_NUMBER || '', online: false },
  { id: 'staff2', name: process.env.STAFF2_NAME || 'Staff 2', number: process.env.STAFF2_NUMBER || '', online: false },
  { id: 'staff3', name: process.env.STAFF3_NAME || 'Staff 3', number: process.env.STAFF3_NUMBER || '', online: false },
  { id: 'staff4', name: process.env.STAFF4_NAME || 'Staff 4', number: process.env.STAFF4_NUMBER || '', online: false },
  { id: 'staff5', name: process.env.STAFF5_NAME || 'Staff 5', number: process.env.STAFF5_NUMBER || '', online: false },
];

// ─── Stats ────────────────────────────────────────────────────────────────────
const STATS = { startTime: Date.now(), messagesScanned: 0, threatsBlocked: 0, aiReplies: 0 };

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
const verifiedUsers   = new Set();
const userSessions    = new Map();
const spamTracker     = new Map();
const blockedUsers    = new Set();
const protectedGroups = new Set();

// ─── Groq AI ──────────────────────────────────────────────────────────────────
const groq = CONFIG.GROQ_KEY ? new Groq({ apiKey: CONFIG.GROQ_KEY }) : null;

const SYSTEM_PROMPT = `You are BoostNG Assistant, the official WhatsApp bot for BoostNG by Mayor Tech Inc.
Be friendly, helpful and concise. WhatsApp messages must be SHORT — max 3 sentences.
Use emojis occasionally. Sound like a real human assistant, not a robot.

ABOUT BOOSTNG:
- SMM panel: Instagram, TikTok, YouTube, Facebook, Telegram, Twitter
- Virtual phone numbers for SMS verification
- Founded by Mayor — Mayor Tech Inc
- Website: https://boosthubng.pages.dev
- Payments: Flutterwave, PayPal, Crypto. Min top up: ₦50
- Points: $1 = 100 Mayor Points

RULES:
- Keep replies SHORT for WhatsApp
- If stuck: tell them to type STAFF or MENU
- If asked owner: "Mayor of Mayor Tech Inc 👑"
- If asked your name: "BoostNG Assistant 🤖"
- Never say you are AI unless directly asked`;

async function askAI(text, history) {
  if (!groq) return null;
  try {
    var res = await groq.chat.completions.create({
      model      : 'llama-3.3-70b-versatile',
      max_tokens : 150,
      temperature: 0.7,
      messages   : [
        { role: 'system', content: SYSTEM_PROMPT },
        ...(history || []).slice(-6),
        { role: 'user', content: text },
      ],
    });
    STATS.aiReplies++;
    return res.choices[0]?.message?.content || null;
  } catch (e) {
    console.error('[AI]', e.message);
    return null;
  }
}

// ─── Security ─────────────────────────────────────────────────────────────────
var CRASH = [
  /[\u200B-\u200F\uFEFF\u202A-\u202E]{5,}/,
  /(.)\1{100,}/,
  /[\u0300-\u036F]{10,}/,
  /\u0000{3,}/,
  /[\uD800-\uDFFF]{10,}/,
  /[\u2800-\u28FF]{20,}/,
  /\u034F{5,}/,
];

var PHISH = [
  /free.*followers.*click/i,
  /account.*suspended.*verify/i,
  /win.*prize.*claim.*now/i,
  /send.*crypto.*double/i,
  /your.*whatsapp.*banned/i,
];

function scanMessage(text, jid) {
  STATS.messagesScanned++;
  if (!text) return { safe: true };
  if (text.length > 5000) { STATS.threatsBlocked++; return { safe: false, reason: 'oversized', warn: '⚠️ Message too large. Keep messages under 5000 characters.' }; }
  for (var p of CRASH) { if (p.test(text)) { STATS.threatsBlocked++; return { safe: false, reason: 'crash', warn: '⚠️ Your message contains characters that may cause issues. Please send plain text.' }; } }
  for (var ph of PHISH) { if (ph.test(text)) { STATS.threatsBlocked++; return { safe: false, reason: 'phishing', warn: '🚨 Suspicious content detected and blocked for your safety.' }; } }
  var now  = Date.now();
  var spam = spamTracker.get(jid) || { count: 0, lastTime: now };
  if (now - spam.lastTime > 60000) { spam = { count: 1, lastTime: now }; }
  else { spam.count++; if (spam.count > 8) { STATS.threatsBlocked++; blockedUsers.add(jid); setTimeout(function() { blockedUsers.delete(jid); }, 300000); return { safe: false, reason: 'spam', warn: '🛑 Temporarily blocked for sending too many messages. Wait 5 minutes.' }; } }
  spamTracker.set(jid, spam);
  return { safe: true };
}

// ─── Watermark ────────────────────────────────────────────────────────────────
function wm(t) { return t + CONFIG.WATERMARK; }

// ─── Send ─────────────────────────────────────────────────────────────────────
async function send(sock, jid, text, q) {
  try { await sock.sendMessage(jid, { text }, q ? { quoted: q } : {}); }
  catch (e) { console.error('[Send]', e.message); }
}

// ─── Message templates ────────────────────────────────────────────────────────
var T = {
  welcome: function() {
    return wm('👋 *Welcome to BoostNG Assistant!*\n_Powered by Mayor Tech Inc_ 🚀\n\nTo access our services:\n\n1️⃣ Join our *WhatsApp Channel:*\n' + CONFIG.WA_CHANNEL + '\n\n2️⃣ Join our *Telegram:*\n' + CONFIG.TELEGRAM_GC + '\n\n3️⃣ Type *JOINED* after joining ✅');
  },
  menu: function() {
    return wm('🤖 *BoostNG Assistant*\n\n━━━━━ *MAIN MENU* ━━━━━\n\n1️⃣ SMM Services\n2️⃣ Order Status\n3️⃣ Top Up Wallet\n4️⃣ Virtual Numbers\n5️⃣ Pricing & Bonuses\n6️⃣ Referral Program\n7️⃣ Talk to Staff 👨‍💼\n8️⃣ Links & Channels\n0️⃣ About BoostNG\n\n💡 _Or just type your question!_\n━━━━━━━━━━━━━━━━━━━━━');
  },
  status: function() {
    return wm('🛡️ *BOOSTNG SECURITY STATUS*\n\n*Protection Layers:*\n✅ Crash Text Filter — ACTIVE\n✅ Zalgo Scanner — ACTIVE\n✅ Phishing Blocker — ACTIVE\n✅ Spam Guard (8/min) — ACTIVE\n✅ RTL Attack Block — ACTIVE\n✅ Oversized Msg Filter — ACTIVE\n✅ Braille Spam Block — ACTIVE\n✅ Null Byte Scanner — ACTIVE\n\n*📊 Live Stats:*\n• Messages scanned: ' + STATS.messagesScanned.toLocaleString() + '\n• Threats blocked: ' + STATS.threatsBlocked + '\n• AI replies: ' + STATS.aiReplies + '\n• Uptime: ' + getUptime() + '\n\n🤖 *BoostNG Assistant — ONLINE* ✅');
  },
  ping: function(ms) {
    return wm('🏓 *Pong!*\n\n⚡ Response: *' + ms + 'ms*\n🟢 Status: *ONLINE*\n🕐 Uptime: *' + getUptime() + '*');
  },
  uptime: function() {
    return wm('⏱️ *BOT UPTIME*\n\n🟢 Status: *ONLINE*\n🕐 Running: *' + getUptime() + '*\n📨 Scanned: *' + STATS.messagesScanned + '*\n🛡️ Blocked: *' + STATS.threatsBlocked + '*\n🤖 AI replies: *' + STATS.aiReplies + '*');
  },
  gchelp: function() {
    return wm('🤖 *BoostNG Bot — Commands*\n\n!ping — Check bot online\n!status — Protection status\n!uptime — Bot uptime\n!protect — Enable security scan\n!unprotect — Disable security scan\n!staff — Available staff\n!links — Official links\n!menu — This help\n\n🛡️ _Security scanning blocks crash msgs, phishing & spam_');
  },
  staff: function() {
    var online = STAFF.filter(function(s) { return s.online && s.number; });
    if (!online.length) return wm('👨‍💼 *Staff Status*\n\nAll staff currently *offline* 😴\n\n• Leave your message — we reply ASAP\n• Telegram: ' + CONFIG.TELEGRAM_GC + '\n• Website: ' + CONFIG.WEBSITE + '\n\n_We reply within 1-2 hours_ ⏰');
    return wm('👨‍💼 *Staff Online* 🟢\n\n' + online.map(function(s) { return '• *' + s.name + ':* wa.me/' + s.number; }).join('\n') + '\n\n_Tap to chat directly!_ 💬');
  },
  links: function() { return wm('🔗 *Official Links*\n\n🌐 ' + CONFIG.WEBSITE + '\n📢 ' + CONFIG.WA_CHANNEL + '\n💬 ' + CONFIG.TELEGRAM_GC); },
  about: function() { return wm('ℹ️ *About BoostNG*\n\n📦 5,000+ SMM Services\n📱 Virtual Phone Numbers\n💳 Flutterwave, PayPal, Crypto\n⚡ Fast Delivery\n🤖 24/7 AI Support\n\nFounded by *Mayor* 👑\nCompany: *Mayor Tech Inc*\n👉 ' + CONFIG.WEBSITE); },
  pricing: function() { return wm('💰 *Pricing & Bonuses*\n\n$1 = 100 Mayor Points\nMin top up: ₦50\n\n*Bonuses:*\n• $20 → +100 pts\n• $50 → +300 pts\n• $100 → +800 pts\n• $200 → +2,000 pts\n\n*Payments:* Flutterwave, PayPal, Crypto\n👉 ' + CONFIG.WEBSITE); },
  topup: function() { return wm('💳 *Top Up Wallet*\n\n👉 ' + CONFIG.WEBSITE + '\n\n✅ Flutterwave (Card & Bank)\n✅ PayPal: oghosaomorogbe41@gmail.com\n✅ Crypto (USDC)\n\nMin: ₦50 — Instant credit! ⚡'); },
  smm: function() { return wm('📦 *SMM Services*\n\n📸 Instagram\n🎵 TikTok\n▶️ YouTube\n💬 Telegram\n🐦 Twitter/X\n👍 Facebook\n\n5,000+ services!\n👉 ' + CONFIG.WEBSITE + ' → Orders'); },
  vnum: function() { return wm('📱 *Virtual Numbers*\n\n✅ WhatsApp • Telegram • Google\n✅ 50+ services • 30+ countries\n\n👉 ' + CONFIG.WEBSITE + ' → V-Numbers'); },
  referral: function() { return wm('🎁 *Referral Program*\n\n1️⃣ Sign up on website\n2️⃣ Copy referral link\n3️⃣ Share with friends\n4️⃣ Earn points when they top up!\n\n👉 ' + CONFIG.WEBSITE); },
  orderstatus: function() { return wm('🔍 *Order Status*\n\n👉 ' + CONFIG.WEBSITE + ' → Orders tab\n\nDelayed 24hrs+? Type *STAFF* ⏰'); },
};

// ─── Menu handler ─────────────────────────────────────────────────────────────
async function handleMenu(sock, jid, text, session) {
  var t = text.trim();
  var u = t.toUpperCase();

  if (['MENU','HI','HELLO','START','HELP','HEY'].includes(u)) return send(sock, jid, T.menu());
  if (['STAFF','HUMAN','AGENT','SUPPORT'].includes(u)) return send(sock, jid, T.staff());
  if (['STATUS','PROTECTION STATUS','SECURITY STATUS','PROTECTION'].includes(u)) return send(sock, jid, T.status());
  if (u === 'PING') { var t0 = Date.now(); return send(sock, jid, T.ping(Date.now() - t0)); }
  if (u === 'UPTIME') return send(sock, jid, T.uptime());
  if (['LINKS','CHANNELS'].includes(u)) return send(sock, jid, T.links());

  switch (t) {
    case '1': return send(sock, jid, T.smm());
    case '2': return send(sock, jid, T.orderstatus());
    case '3': return send(sock, jid, T.topup());
    case '4': return send(sock, jid, T.vnum());
    case '5': return send(sock, jid, T.pricing());
    case '6': return send(sock, jid, T.referral());
    case '7': return send(sock, jid, T.staff());
    case '8': return send(sock, jid, T.links());
    case '0': return send(sock, jid, T.about());
  }

  var h       = session.history || [];
  var aiReply = await askAI(t, h);
  if (aiReply) {
    h.push({ role: 'user', content: t });
    h.push({ role: 'assistant', content: aiReply });
    session.history = h.slice(-10);
    return send(sock, jid, wm(aiReply));
  }
  return send(sock, jid, wm('🤔 Not sure I got that!\n\nType *MENU* for options or *STAFF* to speak with a human 😊'));
}

// ─── Group commands ───────────────────────────────────────────────────────────
async function handleGC(sock, jid, text, msg) {
  var cmd = text.trim().toLowerCase();
  if (cmd === '!menu' || cmd === '!help') return send(sock, jid, T.gchelp(), msg);
  if (cmd === '!ping') { var t0 = Date.now(); return send(sock, jid, T.ping(Date.now() - t0), msg); }
  if (cmd === '!status' || cmd === '!protection') return send(sock, jid, T.status(), msg);
  if (cmd === '!uptime') return send(sock, jid, T.uptime(), msg);
  if (cmd === '!staff') return send(sock, jid, T.staff(), msg);
  if (cmd === '!links') return send(sock, jid, T.links(), msg);
  if (cmd === '!protect') { protectedGroups.add(jid); return send(sock, jid, wm('🛡️ *Security Protection ENABLED!*\nAll messages now scanned for threats.'), msg); }
  if (cmd === '!unprotect') { protectedGroups.delete(jid); return send(sock, jid, wm('⚠️ Security protection *disabled* for this group.'), msg); }
}

// ─── Pairing code ─────────────────────────────────────────────────────────────
async function handlePair(sock, jid, text) {
  var m = text.match(/pair\s+\+?(\d{7,15})/i);
  if (!m) return send(sock, jid, wm('❌ Format: *pair +2348012345678*'));
  try {
    var code = await sock.requestPairingCode(m[1] + '@s.whatsapp.net');
    return send(sock, jid, wm('🔗 *Pairing Code*\n\n📱 Number: +' + m[1] + '\n🔑 Code: *' + code + '*\n\n*Steps:*\n1. Open WhatsApp on that phone\n2. Menu → Linked Devices\n3. Link with phone number\n4. Enter code above ✅\n\n_Expires in 60 seconds!_ ⏰'));
  } catch (e) {
    return send(sock, jid, wm('❌ Could not generate code. Is that number on WhatsApp?'));
  }
}

// ─── Main bot ─────────────────────────────────────────────────────────────────
async function startBot() {
  const { state, saveCreds } = await useMultiFileAuthState('./auth_info');
  const { version }          = await fetchLatestBaileysVersion();

  const sock = makeWASocket({
    version,
    auth             : { creds: state.creds, keys: makeCacheableSignalKeyStore(state.keys, pino({ level: 'silent' })) },
    printQRInTerminal: true,
    logger           : pino({ level: 'silent' }),
    browser          : ['BoostNG Assistant', 'Chrome', '120.0.0'],
  });

  sock.ev.on('creds.update', saveCreds);

  sock.ev.on('connection.update', async function({ connection, lastDisconnect, qr }) {
    if (qr) { console.log('\n📱 Scan QR Code:\n'); qrcode.generate(qr, { small: true }); }
    if (connection === 'close') {
      var code = lastDisconnect?.error?.output?.statusCode;
      if (code !== DisconnectReason.loggedOut) { console.log('[Bot] Reconnecting...'); setTimeout(startBot, 3000); }
      else { console.log('[Bot] Logged out. Delete auth_info and restart.'); }
    } else if (connection === 'open') {
      STATS.startTime = Date.now();
      console.log('\n✅ BoostNG Assistant Bot LIVE!\n© 2026 Mayor Tech Inc\n');
    }
  });

  sock.ev.on('messages.upsert', async function({ messages, type }) {
    if (type !== 'notify') return;
    for (var msg of messages) {
      try {
        if (msg.key.fromMe || !msg.message) continue;
        var jid  = msg.key.remoteJid;
        var isGC = jid?.endsWith('@g.us');
        var text = msg.message?.conversation || msg.message?.extendedTextMessage?.text || '';
        if (!text) continue;

        // ── Groups ──
        if (isGC) {
          if (text.startsWith('!')) { await handleGC(sock, jid, text, msg); }
          else if (protectedGroups.has(jid)) {
            var sc = scanMessage(text, jid);
            if (!sc.safe) {
              await send(sock, jid, wm('🛡️ *Threat Blocked*\n\n' + sc.warn), msg);
              try { await sock.sendMessage(jid, { delete: msg.key }); } catch(e) {}
            }
          }
          continue;
        }

        // ── DMs ──
        console.log('[DM] ' + jid + ': ' + text.slice(0, 60));
        if (blockedUsers.has(jid)) { await send(sock, jid, wm('🛑 Temporarily blocked. Wait 5 minutes.')); continue; }

        var sc = scanMessage(text, jid);
        if (!sc.safe) { await send(sock, jid, wm(sc.warn)); continue; }

        // Owner pairing command
        if (CONFIG.OWNER_NUMBER && jid.startsWith(CONFIG.OWNER_NUMBER) && /^pair\s+\+?\d+/i.test(text)) {
          await handlePair(sock, jid, text); continue;
        }

        // Session
        var session = userSessions.get(jid) || { step: 'welcome', history: [] };

        // Join verification
        if (!verifiedUsers.has(jid)) {
          if (text.trim().toUpperCase() === CONFIG.JOIN_KEYWORD) {
            verifiedUsers.add(jid);
            session.step = 'menu';
            userSessions.set(jid, session);
            await send(sock, jid, wm('✅ *Access Granted!* Welcome to BoostNG! 🎉'));
            await new Promise(function(r) { setTimeout(r, 800); });
            await send(sock, jid, T.menu());
          } else {
            await send(sock, jid, T.welcome());
          }
          continue;
        }

        await handleMenu(sock, jid, text, session);
        userSessions.set(jid, session);

      } catch (e) { console.error('[Handler]', e.message); }
    }
  });
}

// ─── Keep-alive server ────────────────────────────────────────────────────────
http.createServer(function(req, res) {
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({
    status : 'online',
    bot    : 'BoostNG Assistant',
    uptime : getUptime(),
    scanned: STATS.messagesScanned,
    blocked: STATS.threatsBlocked,
    ai     : STATS.aiReplies,
    copy   : '© 2026 Mayor Tech Inc',
  }));
}).listen(CONFIG.PORT, function() {
  console.log('[HTTP] Keep-alive on port', CONFIG.PORT);
});

startBot().catch(console.error);
