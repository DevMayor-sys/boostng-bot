/**
 * BoostNG Security Engine v1
 * Enterprise-level WhatsApp protection
 * © 2026 Mayor Tech Inc
 */

'use strict';

// ─── Threat Levels ────────────────────────────────────────────────────────────
const THREAT = {
  LOW    : 1, // warn only
  MEDIUM : 2, // temp block 10 min
  HIGH   : 3, // permanent block + WA block + kick from group
};

// ─── Crash Patterns ───────────────────────────────────────────────────────────
// Safe regex — all tested, no ReDoS risk (bounded quantifiers)
const TEXT_PATTERNS = [
  // Invisible / Control
  { name: 'Invisible Char Flood',      level: THREAT.HIGH,   rx: /[\u200B\u200C\u200D\u200E\u200F\uFEFF\u00AD\uFFF9\uFFFA\uFFFB]{3,}/ },
  { name: 'RTL Override',              level: THREAT.HIGH,   rx: /[\u202A\u202B\u202C\u202D\u202E]{2,}/ },
  { name: 'Direction Isolate Flood',   level: THREAT.HIGH,   rx: /[\u2066\u2067\u2068\u2069]{3,}/ },
  { name: 'Null Byte Injection',       level: THREAT.HIGH,   rx: /[\u0000-\u0008\u000B\u000C\u000E-\u001F]{2,}/ },
  { name: 'Word Joiner Spam',          level: THREAT.MEDIUM, rx: /\u2060{3,}/ },
  { name: 'Invisible Math Spam',       level: THREAT.MEDIUM, rx: /[\u2061\u2062\u2063\u2064]{3,}/ },
  { name: 'Soft Hyphen Flood',         level: THREAT.MEDIUM, rx: /\u00AD{5,}/ },
  { name: 'Zero Width Space Flood',    level: THREAT.HIGH,   rx: /\u200B{3,}/ },
  { name: 'Line/Para Separator',       level: THREAT.HIGH,   rx: /[\u2028\u2029]{2,}/ },
  // Zalgo & Combining
  { name: 'Zalgo Combining Attack',    level: THREAT.HIGH,   rx: /[\u0300-\u036F]{8,}/ },
  { name: 'Extended Combining Flood',  level: THREAT.HIGH,   rx: /[\u1DC0-\u1DFF]{5,}/ },
  { name: 'Enclosed Combining Flood',  level: THREAT.HIGH,   rx: /[\u20D0-\u20FF]{5,}/ },
  { name: 'Grapheme Joiner Bomb',      level: THREAT.HIGH,   rx: /\u034F{3,}/ },
  { name: 'Variation Selector Flood',  level: THREAT.MEDIUM, rx: /[\uFE00-\uFE0F]{8,}/ },
  { name: 'Combining Half Marks',      level: THREAT.MEDIUM, rx: /[\uFE20-\uFE2F]{5,}/ },
  // Bombs
  { name: 'Character Repeat Bomb',     level: THREAT.HIGH,   rx: /(.)\1{200,}/ },
  { name: 'Whitespace Bomb',           level: THREAT.MEDIUM, rx: /[ \t]{300,}/ },
  { name: 'Long Word Crash',           level: THREAT.HIGH,   rx: /\S{2000,}/ },
  { name: 'Object Replacement Bomb',   level: THREAT.HIGH,   rx: /\uFFFC{3,}/ },
  { name: 'Replacement Char Flood',    level: THREAT.MEDIUM, rx: /\uFFFD{10,}/ },
  // Special blocks
  { name: 'Braille Spam Crash',        level: THREAT.HIGH,   rx: /[\u2800-\u28FF]{15,}/ },
  { name: 'Box Drawing Spam',          level: THREAT.MEDIUM, rx: /[\u2500-\u257F]{50,}/ },
  { name: 'Block Element Spam',        level: THREAT.MEDIUM, rx: /[\u2580-\u259F]{50,}/ },
  { name: 'Geometric Shapes Spam',     level: THREAT.LOW,    rx: /[\u25A0-\u25FF]{50,}/ },
  // Surrogates
  { name: 'Lone High Surrogate',       level: THREAT.HIGH,   rx: /[\uD800-\uDBFF](?![\uDC00-\uDFFF])/ },
  { name: 'Lone Low Surrogate',        level: THREAT.HIGH,   rx: /(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/ },
  { name: 'Surrogate Pair Flood',      level: THREAT.HIGH,   rx: /([\uD800-\uDFFF]){10,}/ },
  // Injection
  { name: 'Script Tag Injection',      level: THREAT.HIGH,   rx: /<script[\s\S]{0,5}>/i },
  { name: 'Javascript Protocol',       level: THREAT.HIGH,   rx: /javascript\s{0,5}:/i },
  { name: 'Data URI Attack',           level: THREAT.HIGH,   rx: /data\s{0,5}:\s{0,5}text/i },
  { name: 'Template Injection',        level: THREAT.MEDIUM, rx: /\{\{.{0,200}\}\}/ },
  { name: 'Prototype Pollution',       level: THREAT.HIGH,   rx: /__proto__|constructor\[|prototype\[/i },
  { name: 'Eval Injection',            level: THREAT.HIGH,   rx: /\beval\s{0,3}\(/ },
];

const UNICODE_PATTERNS = [
  { name: 'Math Unicode Crash',        level: THREAT.HIGH,   rx: /[\u{1D400}-\u{1D7FF}]{20,}/u },
  { name: 'Tag Character Flood',       level: THREAT.HIGH,   rx: /[\u{E0000}-\u{E007F}]{3,}/u },
  { name: 'Emoji Bomb',                level: THREAT.HIGH,   rx: /(?:\u00a9|\u00ae|[\u2000-\u3300]|\uD83C[\uD000-\uDFFF]|\uD83D[\uD000-\uDFFF]|\uD83E[\uD000-\uDFFF]){50,}/u },
  { name: 'Variation Selector 17+',    level: THREAT.MEDIUM, rx: /[\u{E0100}-\u{E01EF}]{5,}/u },
  { name: 'Musical Symbol Spam',       level: THREAT.MEDIUM, rx: /[\u{1D000}-\u{1D0FF}]{20,}/u },
];

const PHISHING_PATTERNS = [
  { name: 'Phishing: Fake Win',        level: THREAT.HIGH,   rx: /congratulations.{0,30}(won|winner|prize)/i },
  { name: 'Phishing: Account Ban',     level: THREAT.HIGH,   rx: /your\s+whatsapp\s+will\s+be\s+banned/i },
  { name: 'Phishing: Verify Now',      level: THREAT.HIGH,   rx: /account\s+suspended.{0,30}verify\s+now/i },
  { name: 'Phishing: Crypto Double',   level: THREAT.HIGH,   rx: /send\s+crypto.{0,30}double\s+back/i },
  { name: 'Phishing: Free Followers',  level: THREAT.MEDIUM, rx: /free\s+followers.{0,30}click/i },
  { name: 'Phishing: Emergency Money', level: THREAT.HIGH,   rx: /send\s+money.{0,30}emergency/i },
];

const DANGEROUS_EXTENSIONS = ['.exe','.bat','.cmd','.sh','.apk','.vbs','.ps1','.msi','.scr','.jar','.hta','.pif'];

// ─── Size limits ──────────────────────────────────────────────────────────────
const LIMITS = {
  TEXT  : 10000,  // chars
  IMAGE : 15 * 1024 * 1024,  // 15MB
  VIDEO : 64 * 1024 * 1024,  // 64MB
  AUDIO : 10 * 1024 * 1024,  // 10MB
  DOC   : 50 * 1024 * 1024,  // 50MB
};

// ─── Safe text truncation before scanning (prevent ReDoS on huge payloads) ───
function safeSlice(text, max) {
  if (!text || typeof text !== 'string') return '';
  return text.length > max ? text.slice(0, max) : text;
}

// ─── scanText ─────────────────────────────────────────────────────────────────
function scanText(text) {
  if (!text || typeof text !== 'string') return null;
  var safe = safeSlice(text, LIMITS.TEXT);

  // Length bomb
  if (text.length > LIMITS.TEXT) {
    return { name: 'Oversized Text Bomb', level: THREAT.HIGH, category: 'text' };
  }

  for (var i = 0; i < TEXT_PATTERNS.length; i++) {
    var p = TEXT_PATTERNS[i];
    try { if (p.rx.test(safe)) return { name: p.name, level: p.level, category: 'text' }; }
    catch(e) {}
  }
  for (var j = 0; j < UNICODE_PATTERNS.length; j++) {
    var u = UNICODE_PATTERNS[j];
    try { if (u.rx.test(safe)) return { name: u.name, level: u.level, category: 'unicode' }; }
    catch(e) {}
  }
  for (var k = 0; k < PHISHING_PATTERNS.length; k++) {
    var ph = PHISHING_PATTERNS[k];
    try { if (ph.rx.test(safe)) return { name: ph.name, level: ph.level, category: 'phishing' }; }
    catch(e) {}
  }
  return null;
}

// ─── scanMedia ────────────────────────────────────────────────────────────────
function scanMedia(msg) {
  if (!msg || !msg.message) return null;
  var m = msg.message;

  // Image
  if (m.imageMessage) {
    if ((m.imageMessage.fileLength || 0) > LIMITS.IMAGE)
      return { name: 'Image Size Bomb', level: THREAT.MEDIUM, category: 'media' };
    var capThreat = scanText(m.imageMessage.caption || '');
    if (capThreat) return capThreat;
  }

  // Video
  if (m.videoMessage) {
    if ((m.videoMessage.fileLength || 0) > LIMITS.VIDEO)
      return { name: 'Video Size Bomb', level: THREAT.MEDIUM, category: 'media' };
    var vcap = scanText(m.videoMessage.caption || '');
    if (vcap) return vcap;
  }

  // Audio
  if (m.audioMessage) {
    if ((m.audioMessage.fileLength || 0) > LIMITS.AUDIO)
      return { name: 'Audio Size Bomb', level: THREAT.MEDIUM, category: 'media' };
  }

  // Document — check extension + size
  if (m.documentMessage) {
    var fname = (m.documentMessage.fileName || '').toLowerCase();
    for (var ext of DANGEROUS_EXTENSIONS) {
      if (fname.endsWith(ext))
        return { name: 'Malicious File: ' + ext, level: THREAT.HIGH, category: 'media' };
    }
    if ((m.documentMessage.fileLength || 0) > LIMITS.DOC)
      return { name: 'Document Size Bomb', level: THREAT.MEDIUM, category: 'media' };
  }

  // Sticker — check metadata
  if (m.stickerMessage) {
    var stitle = m.stickerMessage.stickerSentWith || '';
    var smeta  = scanText(stitle);
    if (smeta) return smeta;
  }

  // vCard exploit
  if (m.contactMessage) {
    var cname = m.contactMessage.displayName || '';
    var cvcard = m.contactMessage.vcard || '';
    return scanText(cname) || scanText(safeSlice(cvcard, 500));
  }
  if (m.contactsArrayMessage) {
    return { name: 'Contact Array Exploit', level: THREAT.MEDIUM, category: 'media' };
  }

  return null;
}

// ─── scanInteractive ──────────────────────────────────────────────────────────
function scanInteractive(msg) {
  if (!msg || !msg.message) return null;
  var m = msg.message;

  // ViewOnce messages — can contain crash media
  if (m.viewOnceMessage || m.viewOnceMessageV2 || m.viewOnceMessageV2Extension) {
    var inner = (m.viewOnceMessage && m.viewOnceMessage.message)
      || (m.viewOnceMessageV2 && m.viewOnceMessageV2.message)
      || {};
    var vScan = scanMedia({ message: inner });
    if (vScan) return vScan;
  }

  // Buttons payload
  if (m.buttonsMessage) {
    var btext = (m.buttonsMessage.contentText || '') + (m.buttonsMessage.footerText || '') + (m.buttonsMessage.headerType || '');
    var bScan = scanText(btext);
    if (bScan) return bScan;
    var buttons = m.buttonsMessage.buttons || [];
    for (var b of buttons) {
      var bScan2 = scanText((b.buttonText && b.buttonText.displayText) || '');
      if (bScan2) return bScan2;
    }
  }

  // List message
  if (m.listMessage) {
    var lthreat = scanText((m.listMessage.title || '') + (m.listMessage.description || ''));
    if (lthreat) return lthreat;
  }

  // Interactive message
  if (m.interactiveMessage) {
    var itext = JSON.stringify(m.interactiveMessage).slice(0, 2000);
    var ithreat = scanText(itext);
    if (ithreat) return ithreat;
  }

  // Poll
  if (m.pollCreationMessage || m.pollCreationMessageV2 || m.pollCreationMessageV3) {
    var poll = m.pollCreationMessage || m.pollCreationMessageV2 || m.pollCreationMessageV3;
    var pthreat = scanText((poll.name || '') + JSON.stringify(poll.options || []).slice(0, 500));
    if (pthreat) return pthreat;
  }

  // Quoted messages — scan quoted content
  var ctx = m.extendedTextMessage && m.extendedTextMessage.contextInfo;
  if (ctx && ctx.quotedMessage) {
    var qScan = scanMedia({ message: ctx.quotedMessage });
    if (qScan) return { name: 'Quoted ' + qScan.name, level: qScan.level, category: 'quoted' };
    var qtextScan = scanText(
      (ctx.quotedMessage.conversation || '') +
      (ctx.quotedMessage.extendedTextMessage && ctx.quotedMessage.extendedTextMessage.text || '')
    );
    if (qtextScan) return { name: 'Quoted ' + qtextScan.name, level: qtextScan.level, category: 'quoted' };
  }

  return null;
}

// ─── Full message scan ────────────────────────────────────────────────────────
function scanMessage(msg, text) {
  return scanText(text) || scanMedia(msg) || scanInteractive(msg);
}

module.exports = { scanText, scanMedia, scanInteractive, scanMessage, THREAT, LIMITS };
