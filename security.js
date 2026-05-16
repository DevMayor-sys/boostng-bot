/**
 * BoostNG Security Engine v2 — Enterprise Advanced Edition
 * © 2026 Mayor Tech Inc
 */
'use strict';

const THREAT = { LOW: 1, MEDIUM: 2, HIGH: 3 };

const CFG = {
  MAX_TEXT_LEN      : 10000,
  MAX_PAYLOAD_BYTES : 512 * 1024,
  MAX_DEPTH         : 10,
  MAX_QUOTED_DEPTH  : 5,
  ENTROPY_THRESHOLD : 4.8,
  ENTROPY_MIN_LEN   : 50,
  FLOOD_WINDOW_MS   : 30000,
  FLOOD_LIMIT       : 8,
  SCORE_DECAY_MS    : 3600000,
  CACHE_MAX         : 2000,
  MEDIA_IMG_MAX     : 15 * 1024 * 1024,
  MEDIA_VID_MAX     : 64 * 1024 * 1024,
  MEDIA_AUD_MAX     : 10 * 1024 * 1024,
  MEDIA_DOC_MAX     : 50 * 1024 * 1024,
};

const DANGEROUS_EXT = new Set([
  '.exe','.bat','.cmd','.sh','.apk','.vbs','.ps1','.msi',
  '.scr','.jar','.hta','.pif','.com','.reg','.lnk','.dll',
  '.so','.dylib','.elf','.bin','.run',
]);

// ─── Structured logger ────────────────────────────────────────────────────────
const logger = {
  log: [],
  MAX: 1000,
  write(level, sender, threat, action, extra) {
    var entry = Object.assign({ ts: Date.now(), time: new Date().toISOString(), level, sender, threat, action }, extra || {});
    this.log.unshift(entry);
    if (this.log.length > this.MAX) this.log.length = this.MAX;
    var icon = level === THREAT.HIGH ? '🔴' : level === THREAT.MEDIUM ? '🟡' : '🟢';
    console.warn('[SEC] ' + icon + ' L' + level + ' | ' + threat + ' | ' + (sender||'?') + ' | ' + action);
    return entry;
  },
  recent(n) { return this.log.slice(0, n || 20); },
};

// ─── Adaptive threat scoring ──────────────────────────────────────────────────
var threatScores = new Map();

function getScore(jid) {
  var s = threatScores.get(jid);
  if (!s) return 0;
  if (Date.now() - s.lastUpdate > CFG.SCORE_DECAY_MS) { threatScores.delete(jid); return 0; }
  return s.score;
}

function addScore(jid, points) {
  var s = threatScores.get(jid) || { score: 0, lastUpdate: Date.now(), offenses: 0 };
  s.score += points; s.offenses += 1; s.lastUpdate = Date.now();
  threatScores.set(jid, s);
  if (threatScores.size > CFG.CACHE_MAX) threatScores.delete(threatScores.keys().next().value);
  return s;
}

function escalateLevel(threat, jid) {
  if (!jid) return threat;
  var s = addScore(jid, threat.level * 10);
  var level = threat.level;
  if (s.offenses >= 3 && level < THREAT.HIGH)    level = THREAT.HIGH;
  else if (s.offenses >= 2 && level < THREAT.MEDIUM) level = THREAT.MEDIUM;
  return Object.assign({}, threat, { level: level, score: s.score, offenses: s.offenses });
}

// ─── Group flood protection ───────────────────────────────────────────────────
var floodMap = new Map();

function checkFlood(senderJid, groupJid) {
  var key = senderJid + ':' + (groupJid || '');
  var now = Date.now();
  var data = floodMap.get(key) || { msgs: [], muted: false, muteUntil: 0 };
  if (data.muted && now > data.muteUntil) { data.muted = false; data.msgs = []; }
  if (data.muted) return { flooded: true, muted: true };
  data.msgs = data.msgs.filter(function(t){ return now - t < CFG.FLOOD_WINDOW_MS; });
  data.msgs.push(now);
  if (data.msgs.length >= CFG.FLOOD_LIMIT) {
    data.muted = true; data.muteUntil = now + 600000;
    floodMap.set(key, data);
    return { flooded: true, muted: false };
  }
  floodMap.set(key, data);
  if (floodMap.size > CFG.CACHE_MAX) floodMap.delete(floodMap.keys().next().value);
  return { flooded: false };
}

// ─── Spam tracker ─────────────────────────────────────────────────────────────
var spamTracker = new Map();

function checkSpam(jid) {
  var now = Date.now();
  var s = spamTracker.get(jid) || { count: 0, last: now };
  if (now - s.last > 60000) s = { count: 1, last: now }; else s.count++;
  spamTracker.set(jid, s);
  if (spamTracker.size > CFG.CACHE_MAX) spamTracker.delete(spamTracker.keys().next().value);
  return s.count > 10;
}

// ─── Utilities ────────────────────────────────────────────────────────────────
function safeSlice(text, max) {
  if (!text || typeof text !== 'string') return '';
  return text.length > max ? text.slice(0, max) : text;
}

function checkDepth(obj, maxDepth, current, seen) {
  if (!obj || typeof obj !== 'object') return false;
  if ((current || 0) >= maxDepth) return true;
  seen = seen || new WeakSet();
  if (seen.has(obj)) return false;
  seen.add(obj);
  var keys = Object.keys(obj);
  for (var i = 0; i < keys.length; i++) {
    var v = obj[keys[i]];
    if (v && typeof v === 'object') { if (checkDepth(v, maxDepth, (current||0)+1, seen)) return true; }
  }
  return false;
}

function estimateSize(obj, depth) {
  if (!obj || typeof obj !== 'object') return String(obj).length;
  if ((depth||0) > 8) return CFG.MAX_PAYLOAD_BYTES + 1;
  var size = 2;
  var keys = Object.keys(obj);
  for (var i = 0; i < keys.length; i++) {
    size += keys[i].length + 3;
    var v = obj[keys[i]];
    if (typeof v === 'string') size += v.length + 2;
    else if (typeof v === 'number') size += 10;
    else if (typeof v === 'boolean') size += 5;
    else if (v && typeof v === 'object') size += estimateSize(v, (depth||0)+1);
    if (size > CFG.MAX_PAYLOAD_BYTES) return size;
  }
  return size;
}

function calculateEntropy(text) {
  if (!text || text.length < CFG.ENTROPY_MIN_LEN) return 0;
  var safe = safeSlice(text, 1000);
  var freq = {};
  for (var i = 0; i < safe.length; i++) { var c = safe[i]; freq[c] = (freq[c]||0)+1; }
  var entropy = 0, len = safe.length;
  var chars = Object.keys(freq);
  for (var j = 0; j < chars.length; j++) { var p = freq[chars[j]]/len; entropy -= p * Math.log2(p); }
  return entropy;
}

function checkNormalization(text) {
  if (!text || text.length < 5) return null;
  var safe = safeSlice(text, 500);
  try {
    if (Math.abs(safe.normalize('NFC').length - safe.length) > safe.length * 0.3)
      return { name: 'Unicode Normalization Bypass', level: THREAT.HIGH, category: 'unicode' };
    if (Math.abs(safe.normalize('NFKC').length - safe.length) > safe.length * 0.5)
      return { name: 'NFKC Obfuscation Attack', level: THREAT.HIGH, category: 'unicode' };
  } catch(e) { return { name: 'Unicode Normalization Error', level: THREAT.MEDIUM, category: 'unicode' }; }
  return null;
}

function validateMediaHeader(buffer, type) {
  var sigs = { webp:[0x52,0x49,0x46,0x46,0], mp4:[0x66,0x74,0x79,0x70,4], jpg:[0xFF,0xD8,0xFF,0], png:[0x89,0x50,0x4E,0x47,0] };
  if (!buffer || buffer.length < 12 || !sigs[type]) return null;
  var sig = sigs[type], offset = sig[sig.length-1], magic = sig.slice(0,-1);
  for (var i = 0; i < magic.length; i++) {
    if (buffer[offset+i] !== magic[i]) return { name: 'Malformed '+type.toUpperCase()+' Header', level: THREAT.MEDIUM, category: 'binary' };
  }
  return null;
}

// ─── Text patterns ────────────────────────────────────────────────────────────
var TEXT_PATTERNS = [
  { name:'Invisible Char Flood',     level:THREAT.HIGH,   rx:/[\u200B\u200C\u200D\u200E\u200F\uFEFF\u00AD\uFFF9\uFFFA\uFFFB]{3,}/ },
  { name:'RTL Override',             level:THREAT.HIGH,   rx:/[\u202A\u202B\u202C\u202D\u202E]{2,}/ },
  { name:'Direction Isolate Flood',  level:THREAT.HIGH,   rx:/[\u2066\u2067\u2068\u2069]{3,}/ },
  { name:'Null Byte Injection',      level:THREAT.HIGH,   rx:/[\u0000-\u0008\u000B\u000C\u000E-\u001F]{2,}/ },
  { name:'Word Joiner Spam',         level:THREAT.MEDIUM, rx:/\u2060{3,}/ },
  { name:'Invisible Math Spam',      level:THREAT.MEDIUM, rx:/[\u2061\u2062\u2063\u2064]{3,}/ },
  { name:'Zero Width Space Flood',   level:THREAT.HIGH,   rx:/\u200B{3,}/ },
  { name:'Line Para Separator',      level:THREAT.HIGH,   rx:/[\u2028\u2029]{2,}/ },
  { name:'Zalgo Combining Attack',   level:THREAT.HIGH,   rx:/[\u0300-\u036F]{8,}/ },
  { name:'Extended Combining Flood', level:THREAT.HIGH,   rx:/[\u1DC0-\u1DFF]{5,}/ },
  { name:'Enclosed Combining Flood', level:THREAT.HIGH,   rx:/[\u20D0-\u20FF]{5,}/ },
  { name:'Grapheme Joiner Bomb',     level:THREAT.HIGH,   rx:/\u034F{3,}/ },
  { name:'Variation Selector Flood', level:THREAT.MEDIUM, rx:/[\uFE00-\uFE0F]{8,}/ },
  { name:'Combining Half Marks',     level:THREAT.MEDIUM, rx:/[\uFE20-\uFE2F]{5,}/ },
  { name:'Character Repeat Bomb',    level:THREAT.HIGH,   rx:/(.)\1{200,}/ },
  { name:'Whitespace Bomb',          level:THREAT.MEDIUM, rx:/[ \t]{300,}/ },
  { name:'Long Word Crash',          level:THREAT.HIGH,   rx:/\S{2000,}/ },
  { name:'Object Replacement Bomb',  level:THREAT.HIGH,   rx:/\uFFFC{3,}/ },
  { name:'Replacement Char Flood',   level:THREAT.MEDIUM, rx:/\uFFFD{10,}/ },
  { name:'Braille Spam Crash',       level:THREAT.HIGH,   rx:/[\u2800-\u28FF]{15,}/ },
  { name:'Box Drawing Spam',         level:THREAT.MEDIUM, rx:/[\u2500-\u257F]{50,}/ },
  { name:'Block Element Spam',       level:THREAT.MEDIUM, rx:/[\u2580-\u259F]{50,}/ },
  { name:'Lone High Surrogate',      level:THREAT.HIGH,   rx:/[\uD800-\uDBFF](?![\uDC00-\uDFFF])/ },
  { name:'Lone Low Surrogate',       level:THREAT.HIGH,   rx:/(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/ },
  { name:'Surrogate Pair Flood',     level:THREAT.HIGH,   rx:/([\uD800-\uDFFF]){10,}/ },
  { name:'Script Tag Injection',     level:THREAT.HIGH,   rx:/<script[\s\S]{0,5}>/i },
  { name:'Javascript Protocol',      level:THREAT.HIGH,   rx:/javascript\s{0,5}:/i },
  { name:'Data URI Attack',          level:THREAT.HIGH,   rx:/data\s{0,5}:\s{0,5}text/i },
  { name:'Template Injection',       level:THREAT.MEDIUM, rx:/\{\{.{0,200}\}\}/ },
  { name:'Prototype Pollution',      level:THREAT.HIGH,   rx:/__proto__|constructor\[|prototype\[/i },
  { name:'Eval Injection',           level:THREAT.HIGH,   rx:/\beval\s{0,3}\(/ },
];

var UNICODE_PATTERNS = [
  { name:'Math Unicode Crash',    level:THREAT.HIGH,   rx:/[\u{1D400}-\u{1D7FF}]{20,}/u },
  { name:'Tag Character Flood',   level:THREAT.HIGH,   rx:/[\u{E0000}-\u{E007F}]{3,}/u },
  { name:'Emoji Bomb',            level:THREAT.HIGH,   rx:/(?:\u00a9|\u00ae|[\u2000-\u3300]|\uD83C[\uD000-\uDFFF]|\uD83D[\uD000-\uDFFF]|\uD83E[\uD000-\uDFFF]){50,}/u },
  { name:'Variation Selector 17+',level:THREAT.MEDIUM, rx:/[\u{E0100}-\u{E01EF}]{5,}/u },
];

var PHISHING_PATTERNS = [
  { name:'Phishing: Fake Win',       level:THREAT.HIGH, rx:/congratulations.{0,30}(won|winner|prize)/i },
  { name:'Phishing: Account Ban',    level:THREAT.HIGH, rx:/your\s+whatsapp\s+will\s+be\s+banned/i },
  { name:'Phishing: Verify Now',     level:THREAT.HIGH, rx:/account\s+suspended.{0,30}verify\s+now/i },
  { name:'Phishing: Crypto Double',  level:THREAT.HIGH, rx:/send\s+crypto.{0,30}double\s+back/i },
  { name:'Phishing: Emergency Money',level:THREAT.HIGH, rx:/send\s+money.{0,30}emergency/i },
];

// ─── scanText ─────────────────────────────────────────────────────────────────
function scanText(text) {
  if (!text || typeof text !== 'string') return null;
  if (text.length > CFG.MAX_TEXT_LEN) return { name:'Text Size Bomb', level:THREAT.HIGH, category:'text' };
  var safe = safeSlice(text, CFG.MAX_TEXT_LEN);
  for (var i = 0; i < TEXT_PATTERNS.length; i++) {
    try { if (TEXT_PATTERNS[i].rx.test(safe)) return { name:TEXT_PATTERNS[i].name, level:TEXT_PATTERNS[i].level, category:'text' }; } catch(e) {}
  }
  for (var j = 0; j < UNICODE_PATTERNS.length; j++) {
    try { if (UNICODE_PATTERNS[j].rx.test(safe)) return { name:UNICODE_PATTERNS[j].name, level:UNICODE_PATTERNS[j].level, category:'unicode' }; } catch(e) {}
  }
  for (var k = 0; k < PHISHING_PATTERNS.length; k++) {
    try { if (PHISHING_PATTERNS[k].rx.test(safe)) return { name:PHISHING_PATTERNS[k].name, level:PHISHING_PATTERNS[k].level, category:'phishing' }; } catch(e) {}
  }
  // Entropy check
  var entropy = calculateEntropy(safe);
  if (entropy > CFG.ENTROPY_THRESHOLD && safe.length > CFG.ENTROPY_MIN_LEN) {
    var unicodeRatio = (safe.match(/[^\x00-\x7F]/g)||[]).length / safe.length;
    if (unicodeRatio > 0.6) return { name:'High Entropy Unicode Obfuscation', level:THREAT.MEDIUM, category:'entropy' };
  }
  return checkNormalization(safe);
}

// ─── scanMedia ────────────────────────────────────────────────────────────────
function scanMedia(msg) {
  if (!msg || !msg.message) return null;
  var m = msg.message;
  if (m.imageMessage) {
    if ((m.imageMessage.fileLength||0) > CFG.MEDIA_IMG_MAX) return { name:'Image Size Bomb', level:THREAT.MEDIUM, category:'media' };
    return scanText(m.imageMessage.caption||'');
  }
  if (m.videoMessage) {
    if ((m.videoMessage.fileLength||0) > CFG.MEDIA_VID_MAX) return { name:'Video Size Bomb', level:THREAT.MEDIUM, category:'media' };
    return scanText(m.videoMessage.caption||'');
  }
  if (m.audioMessage) {
    if ((m.audioMessage.fileLength||0) > CFG.MEDIA_AUD_MAX) return { name:'Audio Size Bomb', level:THREAT.MEDIUM, category:'media' };
    return null;
  }
  if (m.documentMessage) {
    var fname = (m.documentMessage.fileName||'').toLowerCase();
    for (var ext of DANGEROUS_EXT) { if (fname.endsWith(ext)) return { name:'Malicious File: '+ext, level:THREAT.HIGH, category:'media' }; }
    if ((m.documentMessage.fileLength||0) > CFG.MEDIA_DOC_MAX) return { name:'Document Size Bomb', level:THREAT.MEDIUM, category:'media' };
  }
  if (m.stickerMessage) return scanText(m.stickerMessage.stickerSentWith||'');
  if (m.contactMessage) return scanText(m.contactMessage.displayName||'') || scanText(safeSlice(m.contactMessage.vcard||'',500));
  if (m.contactsArrayMessage) return { name:'Contact Array Exploit', level:THREAT.MEDIUM, category:'media' };
  return null;
}

// ─── scanQuoted (recursive, depth-limited) ────────────────────────────────────
function scanQuoted(q, depth) {
  if (!q || (depth||0) >= CFG.MAX_QUOTED_DEPTH) return null;
  var t = scanText((q.conversation||'') + (q.extendedTextMessage&&q.extendedTextMessage.text||'') + (q.imageMessage&&q.imageMessage.caption||''));
  if (t) return Object.assign({}, t, { name:'Quoted['+depth+']: '+t.name });
  var med = scanMedia({ message: q });
  if (med) return Object.assign({}, med, { name:'Quoted['+depth+']: '+med.name });
  var ctx = q.extendedTextMessage && q.extendedTextMessage.contextInfo;
  if (ctx && ctx.quotedMessage) return scanQuoted(ctx.quotedMessage, (depth||0)+1);
  return null;
}

// ─── scanInteractive ──────────────────────────────────────────────────────────
function scanInteractive(msg) {
  if (!msg || !msg.message) return null;
  var m = msg.message;

  // ViewOnce
  var vo = m.viewOnceMessage || m.viewOnceMessageV2 || m.viewOnceMessageV2Extension;
  if (vo) {
    var inner = vo.message || {};
    var vt = scanMedia({ message:inner }) || scanText((inner.imageMessage&&inner.imageMessage.caption||'')+(inner.videoMessage&&inner.videoMessage.caption||''));
    if (vt) return Object.assign({}, vt, { name:'ViewOnce: '+vt.name });
  }

  // Buttons
  if (m.buttonsMessage) {
    if (estimateSize(m.buttonsMessage) > CFG.MAX_PAYLOAD_BYTES) return { name:'Buttons Payload Bomb', level:THREAT.HIGH, category:'interactive' };
    if (checkDepth(m.buttonsMessage, CFG.MAX_DEPTH)) return { name:'Buttons Depth Bomb', level:THREAT.HIGH, category:'interactive' };
    var bt = scanText((m.buttonsMessage.contentText||'')+(m.buttonsMessage.footerText||''));
    if (bt) return bt;
    for (var b of (m.buttonsMessage.buttons||[])) { var bs = scanText(b.buttonText&&b.buttonText.displayText||''); if (bs) return bs; }
  }
  if (m.buttonsResponseMessage) { var br = scanText(m.buttonsResponseMessage.selectedDisplayText||''); if (br) return br; }

  // List
  if (m.listMessage) {
    if (checkDepth(m.listMessage, CFG.MAX_DEPTH)) return { name:'List Depth Bomb', level:THREAT.HIGH, category:'interactive' };
    var lt = scanText((m.listMessage.title||'')+(m.listMessage.description||'')); if (lt) return lt;
    for (var sec of (m.listMessage.sections||[])) { for (var row of (sec.rows||[])) { var rt = scanText((row.title||'')+(row.description||'')); if (rt) return rt; } }
  }
  if (m.listResponseMessage) { var lr = scanText(m.listResponseMessage.title||''); if (lr) return lr; }

  // Interactive
  if (m.interactiveMessage) {
    if (estimateSize(m.interactiveMessage) > CFG.MAX_PAYLOAD_BYTES) return { name:'Interactive Payload Bomb', level:THREAT.HIGH, category:'interactive' };
    if (checkDepth(m.interactiveMessage, CFG.MAX_DEPTH)) return { name:'Interactive Depth Bomb', level:THREAT.HIGH, category:'interactive' };
  }
  if (m.interactiveResponseMessage) { var ir = scanText(safeSlice(JSON.stringify(m.interactiveResponseMessage),1000)); if (ir) return ir; }

  // Native flow
  if (m.nativeFlowMessage) {
    if (checkDepth(m.nativeFlowMessage, CFG.MAX_DEPTH)) return { name:'Native Flow Depth Bomb', level:THREAT.HIGH, category:'flow' };
    if (estimateSize(m.nativeFlowMessage) > CFG.MAX_PAYLOAD_BYTES) return { name:'Native Flow Size Bomb', level:THREAT.HIGH, category:'flow' };
    try { var params = m.nativeFlowMessage.paramsJson||''; if (params) { var parsed = JSON.parse(params); if (checkDepth(parsed, CFG.MAX_DEPTH)) return { name:'Native Flow Params Bomb', level:THREAT.HIGH, category:'flow' }; } }
    catch(e) { return { name:'Native Flow Malformed JSON', level:THREAT.MEDIUM, category:'flow' }; }
  }

  // Template
  var tmpl = m.templateMessage || m.hydratedTemplate;
  if (tmpl) {
    if (checkDepth(tmpl, CFG.MAX_DEPTH)) return { name:'Template Depth Bomb', level:THREAT.HIGH, category:'template' };
    if (estimateSize(tmpl) > CFG.MAX_PAYLOAD_BYTES) return { name:'Template Size Bomb', level:THREAT.HIGH, category:'template' };
    var tt = scanText((tmpl.hydratedContentText||'')+(tmpl.hydratedFooterText||'')+(tmpl.hydratedTitleText||'')); if (tt) return tt;
  }

  // Poll
  var poll = m.pollCreationMessage || m.pollCreationMessageV2 || m.pollCreationMessageV3;
  if (poll) { var pt = scanText(safeSlice((poll.name||'')+JSON.stringify(poll.options||[]),500)); if (pt) return pt; }

  // Recursive quoted
  var ctx = m.extendedTextMessage && m.extendedTextMessage.contextInfo;
  if (ctx && ctx.quotedMessage) { var qt = scanQuoted(ctx.quotedMessage, 0); if (qt) return qt; }

  return null;
}

// ─── Full scan + escalation ───────────────────────────────────────────────────
function scanMessage(msg, text, senderJid) {
  var threat = scanText(text) || scanMedia(msg) || scanInteractive(msg);
  if (!threat) return null;
  if (senderJid) threat = escalateLevel(threat, senderJid);
  logger.write(threat.level, senderJid||'?', threat.name, 'detected', { category: threat.category });
  return threat;
}

// ─── Memory cleanup ───────────────────────────────────────────────────────────
setInterval(function() {
  var now = Date.now();
  for (var jid of Array.from(threatScores.keys())) { var s = threatScores.get(jid); if (now - s.lastUpdate > CFG.SCORE_DECAY_MS) threatScores.delete(jid); }
  for (var key of Array.from(floodMap.keys())) { var d = floodMap.get(key); if (!d.muted && d.msgs.every(function(t){ return now-t > CFG.FLOOD_WINDOW_MS*2; })) floodMap.delete(key); }
  for (var j of Array.from(spamTracker.keys())) { var sp = spamTracker.get(j); if (now - sp.last > 120000) spamTracker.delete(j); }
}, 300000);

module.exports = { scanText, scanMedia, scanInteractive, scanQuoted, scanMessage, calculateEntropy, checkDepth, estimateSize, checkNormalization, validateMediaHeader, checkFlood, checkSpam, escalateLevel, getScore, addScore, logger, THREAT, CFG };
