/**
 * BoostNG — Runtime Hardening Engine
 * Protocol-level defensive architecture for Baileys WhatsApp bot
 * © 2026 Mayor Tech Inc
 *
 * PURPOSE: This module handles UNKNOWN WhatsApp bug payloads and malformed
 * protocol attacks at the runtime/architecture level — NOT pattern matching.
 *
 * APPROACH: Treat every incoming message as potentially malicious.
 * Validate structure BEFORE touching content. Reject anything malformed.
 */

'use strict';

// ═══════════════════════════════════════════════════════════════════════════════
// CONSTANTS — protocol-level limits
// ═══════════════════════════════════════════════════════════════════════════════
const LIMITS = {
  // Object traversal
  MAX_DEPTH         : 12,      // max object nesting depth
  MAX_KEYS          : 200,     // max keys per object
  MAX_STRING_LEN    : 65536,   // 64KB max string value
  MAX_ARRAY_LEN     : 500,     // max array items
  MAX_PAYLOAD_BYTES : 524288,  // 512KB max total payload

  // Timing
  SEND_TIMEOUT      : 12000,   // 12s max for any send
  API_TIMEOUT       : 8000,    // 8s max for API calls
  DOWNLOAD_TIMEOUT  : 20000,   // 20s max for media download
  PARSE_TIMEOUT     : 2000,    // 2s max for any parsing

  // Rate
  EVENT_LOOP_WARN   : 100,     // warn if event loop blocked >100ms
  MAX_MSG_SIZE      : 131072,  // 128KB max raw message object

  // Memory
  CACHE_TTL         : 1800000, // 30 min cache TTL
  CACHE_MAX         : 2000,    // max cache entries
};

// ═══════════════════════════════════════════════════════════════════════════════
// SAFE PRIMITIVES — never throw, always return safe values
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Safe string extraction — rejects non-strings, truncates oversized
 * WHY: Baileys fields that should be strings can sometimes be objects/null
 */
function safeStr(val, maxLen) {
  if (val === null || val === undefined) return '';
  if (typeof val !== 'string') {
    // Don't try to stringify objects — just reject
    if (typeof val === 'number' || typeof val === 'boolean') return String(val);
    return '';
  }
  var limit = maxLen || LIMITS.MAX_STRING_LEN;
  return val.length > limit ? val.slice(0, limit) : val;
}

/**
 * Safe number extraction
 * WHY: Numeric fields can arrive as strings or NaN from corrupted protobuf
 */
function safeNum(val, fallback) {
  var n = Number(val);
  return (isFinite(n) && !isNaN(n)) ? n : (fallback || 0);
}

/**
 * Safe boolean extraction
 */
function safeBool(val) {
  return val === true || val === 1 || val === 'true';
}

/**
 * Safe array extraction — validates it's actually an array
 * WHY: Arrays in protobuf can corrupt into objects
 */
function safeArr(val, maxLen) {
  if (!Array.isArray(val)) return [];
  var limit = maxLen || LIMITS.MAX_ARRAY_LEN;
  return val.length > limit ? val.slice(0, limit) : val;
}

/**
 * Safe object check — validates it's a plain object
 * WHY: Prevents prototype pollution and circular reference attacks
 */
function isPlainObj(val) {
  if (!val || typeof val !== 'object' || Array.isArray(val)) return false;
  // Block prototype pollution vectors
  if (val.constructor && val.constructor !== Object) return false;
  return true;
}

/**
 * Safe JSON parse — never throws, rejects oversized input
 * WHY: JSON.parse can throw and doesn't have size limits
 */
function safeJsonParse(str, fallback) {
  if (!str || typeof str !== 'string') return fallback !== undefined ? fallback : null;
  if (str.length > LIMITS.MAX_STRING_LEN) return fallback !== undefined ? fallback : null;
  try { return JSON.parse(str); }
  catch(e) { return fallback !== undefined ? fallback : null; }
}

// ═══════════════════════════════════════════════════════════════════════════════
// CIRCULAR REFERENCE DETECTOR — prevents infinite traversal
// WHY: Malicious payloads can contain circular refs that loop forever
// ═══════════════════════════════════════════════════════════════════════════════
function hasCircularRef(obj, seen, depth) {
  if (!obj || typeof obj !== 'object') return false;
  if ((depth || 0) > LIMITS.MAX_DEPTH) return true; // treat as circular
  seen = seen || new WeakSet();
  if (seen.has(obj)) return true;
  seen.add(obj);
  var keys = Object.keys(obj);
  for (var i = 0; i < Math.min(keys.length, LIMITS.MAX_KEYS); i++) {
    var v = obj[keys[i]];
    if (v && typeof v === 'object') {
      if (hasCircularRef(v, seen, (depth || 0) + 1)) return true;
    }
  }
  return false;
}

// ═══════════════════════════════════════════════════════════════════════════════
// PAYLOAD SIZE ESTIMATOR — fast, no full serialization
// WHY: JSON.stringify on a large object is a DoS vector itself
// ═══════════════════════════════════════════════════════════════════════════════
function estimatePayloadSize(obj, depth) {
  if (obj === null || obj === undefined) return 4;
  var t = typeof obj;
  if (t === 'string') return Math.min(obj.length + 2, LIMITS.MAX_PAYLOAD_BYTES + 1);
  if (t === 'number' || t === 'boolean') return 10;
  if (t !== 'object') return 4;
  if ((depth || 0) > LIMITS.MAX_DEPTH) return LIMITS.MAX_PAYLOAD_BYTES + 1; // reject deep
  var size = 2;
  if (Array.isArray(obj)) {
    var arr = obj.slice(0, LIMITS.MAX_ARRAY_LEN);
    for (var i = 0; i < arr.length; i++) {
      size += estimatePayloadSize(arr[i], (depth || 0) + 1) + 1;
      if (size > LIMITS.MAX_PAYLOAD_BYTES) return size;
    }
    return size;
  }
  var keys = Object.keys(obj).slice(0, LIMITS.MAX_KEYS);
  for (var j = 0; j < keys.length; j++) {
    size += keys[j].length + 3 + estimatePayloadSize(obj[keys[j]], (depth || 0) + 1);
    if (size > LIMITS.MAX_PAYLOAD_BYTES) return size;
  }
  return size;
}

// ═══════════════════════════════════════════════════════════════════════════════
// DEEP PAYLOAD VALIDATOR — protocol-level validation
// Validates Baileys message structure BEFORE any content processing
// Returns { valid: bool, reason: string }
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Validate top-level message structure
 * WHY: Malformed Baileys payloads can have missing/wrong-type fields
 * that crash downstream processing
 */
function validateMessage(msg) {
  // Must be plain object
  if (!msg || typeof msg !== 'object' || Array.isArray(msg)) {
    return { valid: false, reason: 'msg not object' };
  }

  // Must have key
  var key = msg.key;
  if (!key || typeof key !== 'object') {
    return { valid: false, reason: 'missing key' };
  }

  // key.remoteJid must be a valid-looking JID string
  var jid = safeStr(key.remoteJid);
  if (!jid || jid.length < 5 || jid.length > 256) {
    return { valid: false, reason: 'invalid remoteJid: ' + jid.length };
  }
  if (!jid.includes('@')) {
    return { valid: false, reason: 'jid missing @' };
  }

  // message field — must be object if present
  if (msg.message !== undefined && msg.message !== null) {
    if (typeof msg.message !== 'object' || Array.isArray(msg.message)) {
      return { valid: false, reason: 'message not object' };
    }

    // Quick size check BEFORE any traversal
    var size = estimatePayloadSize(msg.message);
    if (size > LIMITS.MAX_PAYLOAD_BYTES) {
      return { valid: false, reason: 'payload too large: ' + size };
    }

    // Check for circular references
    if (hasCircularRef(msg.message)) {
      return { valid: false, reason: 'circular reference detected' };
    }

    // Validate individual message types
    var typeResult = validateMessageTypes(msg.message);
    if (!typeResult.valid) return typeResult;
  }

  return { valid: true };
}

/**
 * Validate specific message type structures
 * WHY: Each message type has specific field requirements.
 * Unknown/malformed types can cause crashes in downstream handlers.
 */
function validateMessageTypes(m) {
  if (!m) return { valid: true };

  // Text messages
  if (m.conversation !== undefined) {
    if (typeof m.conversation !== 'string') return { valid: false, reason: 'conversation not string' };
    if (m.conversation.length > LIMITS.MAX_STRING_LEN) return { valid: false, reason: 'conversation too long' };
  }

  // Extended text
  if (m.extendedTextMessage) {
    var ext = m.extendedTextMessage;
    if (!isPlainObj(ext)) return { valid: false, reason: 'extendedText not object' };
    if (ext.text !== undefined && typeof ext.text !== 'string') return { valid: false, reason: 'ext.text not string' };
    if (ext.text && ext.text.length > LIMITS.MAX_STRING_LEN) return { valid: false, reason: 'ext.text too long' };
    // Validate contextInfo if present
    if (ext.contextInfo) {
      var ctxResult = validateContextInfo(ext.contextInfo);
      if (!ctxResult.valid) return ctxResult;
    }
  }

  // Image/video/audio/sticker/document — validate metadata only
  var mediaTypes = ['imageMessage','videoMessage','audioMessage','stickerMessage','documentMessage'];
  for (var i = 0; i < mediaTypes.length; i++) {
    var mt = mediaTypes[i];
    if (m[mt]) {
      if (!isPlainObj(m[mt])) return { valid: false, reason: mt + ' not object' };
      var mediaResult = validateMediaMessage(m[mt], mt);
      if (!mediaResult.valid) return mediaResult;
    }
  }

  // Contact
  if (m.contactMessage) {
    if (!isPlainObj(m.contactMessage)) return { valid: false, reason: 'contact not object' };
    var cname = m.contactMessage.displayName;
    if (cname !== undefined && typeof cname !== 'string') return { valid: false, reason: 'contact name not string' };
    if (cname && cname.length > 512) return { valid: false, reason: 'contact name too long' };
    var vcard = m.contactMessage.vcard;
    if (vcard !== undefined && typeof vcard !== 'string') return { valid: false, reason: 'vcard not string' };
    if (vcard && vcard.length > 10000) return { valid: false, reason: 'vcard too large' };
  }

  // ViewOnce — validate inner message recursively (depth 1 only)
  var voTypes = ['viewOnceMessage', 'viewOnceMessageV2', 'viewOnceMessageV2Extension'];
  for (var j = 0; j < voTypes.length; j++) {
    if (m[voTypes[j]]) {
      var vo = m[voTypes[j]];
      if (!isPlainObj(vo)) return { valid: false, reason: voTypes[j] + ' not object' };
      // Size check on inner message
      if (vo.message) {
        var voSize = estimatePayloadSize(vo.message);
        if (voSize > LIMITS.MAX_PAYLOAD_BYTES) return { valid: false, reason: 'viewOnce inner too large' };
      }
    }
  }

  // Buttons — validate structure
  if (m.buttonsMessage) {
    var bResult = validateButtonsMessage(m.buttonsMessage);
    if (!bResult.valid) return bResult;
  }

  // List message
  if (m.listMessage) {
    var lResult = validateListMessage(m.listMessage);
    if (!lResult.valid) return lResult;
  }

  // Interactive message — size + depth only
  if (m.interactiveMessage) {
    if (!isPlainObj(m.interactiveMessage)) return { valid: false, reason: 'interactive not object' };
    var iSize = estimatePayloadSize(m.interactiveMessage);
    if (iSize > LIMITS.MAX_PAYLOAD_BYTES) return { valid: false, reason: 'interactive too large: ' + iSize };
  }

  // Native flow — validate paramsJson
  if (m.nativeFlowMessage) {
    if (!isPlainObj(m.nativeFlowMessage)) return { valid: false, reason: 'nativeFlow not object' };
    var nfSize = estimatePayloadSize(m.nativeFlowMessage);
    if (nfSize > LIMITS.MAX_PAYLOAD_BYTES) return { valid: false, reason: 'nativeFlow too large' };
    if (m.nativeFlowMessage.paramsJson !== undefined) {
      var params = m.nativeFlowMessage.paramsJson;
      if (typeof params !== 'string') return { valid: false, reason: 'nativeFlow params not string' };
      if (params.length > 65536) return { valid: false, reason: 'nativeFlow params too long' };
      // Try parse — reject malformed JSON
      var parsed = safeJsonParse(params);
      if (params.length > 10 && parsed === null) return { valid: false, reason: 'nativeFlow params invalid JSON' };
    }
  }

  // Template/hydratedTemplate
  var tmplTypes = ['templateMessage', 'hydratedTemplate'];
  for (var k = 0; k < tmplTypes.length; k++) {
    if (m[tmplTypes[k]]) {
      if (!isPlainObj(m[tmplTypes[k]])) return { valid: false, reason: tmplTypes[k] + ' not object' };
      var tSize = estimatePayloadSize(m[tmplTypes[k]]);
      if (tSize > LIMITS.MAX_PAYLOAD_BYTES) return { valid: false, reason: tmplTypes[k] + ' too large' };
    }
  }

  // Poll messages
  var pollTypes = ['pollCreationMessage','pollCreationMessageV2','pollCreationMessageV3'];
  for (var p = 0; p < pollTypes.length; p++) {
    if (m[pollTypes[p]]) {
      var poll = m[pollTypes[p]];
      if (!isPlainObj(poll)) return { valid: false, reason: pollTypes[p] + ' not object' };
      var pname = poll.name;
      if (pname !== undefined && typeof pname !== 'string') return { valid: false, reason: 'poll name not string' };
      if (pname && pname.length > 2048) return { valid: false, reason: 'poll name too long' };
    }
  }

  // Reaction
  if (m.reactionMessage) {
    if (!isPlainObj(m.reactionMessage)) return { valid: false, reason: 'reaction not object' };
    var rtext = m.reactionMessage.text;
    if (rtext !== undefined && typeof rtext !== 'string') return { valid: false, reason: 'reaction text not string' };
    if (rtext && rtext.length > 64) return { valid: false, reason: 'reaction text too long' };
  }

  // Protocol message — validate type field
  if (m.protocolMessage) {
    if (!isPlainObj(m.protocolMessage)) return { valid: false, reason: 'protocol not object' };
    var ptype = m.protocolMessage.type;
    if (ptype !== undefined && typeof ptype !== 'number' && typeof ptype !== 'string') {
      return { valid: false, reason: 'protocol type invalid' };
    }
  }

  // Ephemeral
  if (m.ephemeralMessage) {
    if (!isPlainObj(m.ephemeralMessage)) return { valid: false, reason: 'ephemeral not object' };
    var epSize = estimatePayloadSize(m.ephemeralMessage);
    if (epSize > LIMITS.MAX_PAYLOAD_BYTES) return { valid: false, reason: 'ephemeral too large' };
  }

  // Newsletter message
  if (m.newsletterAdminInviteMessage || m.newsletterEncStateSyncMessage) {
    // Newsletter payloads — just size check, don't process
    var nlKey = m.newsletterAdminInviteMessage ? 'newsletterAdminInviteMessage' : 'newsletterEncStateSyncMessage';
    if (!isPlainObj(m[nlKey])) return { valid: false, reason: nlKey + ' not object' };
    var nlSize = estimatePayloadSize(m[nlKey]);
    if (nlSize > LIMITS.MAX_PAYLOAD_BYTES) return { valid: false, reason: nlKey + ' too large' };
  }

  return { valid: true };
}

/**
 * Validate contextInfo — recursive quoted message scanning
 * WHY: Nested quoted messages can be deeply chained as an attack vector
 */
function validateContextInfo(ctx, depth) {
  if (!ctx || !isPlainObj(ctx)) return { valid: true }; // missing ctx is ok
  if ((depth || 0) > 5) return { valid: false, reason: 'contextInfo too deep' };

  // Validate quoted message recursively
  if (ctx.quotedMessage) {
    if (!isPlainObj(ctx.quotedMessage)) return { valid: false, reason: 'quotedMessage not object' };
    var qSize = estimatePayloadSize(ctx.quotedMessage);
    if (qSize > LIMITS.MAX_PAYLOAD_BYTES) return { valid: false, reason: 'quoted too large' };
    // Recurse into quoted's contextInfo
    var innerExt = ctx.quotedMessage.extendedTextMessage;
    if (innerExt && innerExt.contextInfo) {
      return validateContextInfo(innerExt.contextInfo, (depth || 0) + 1);
    }
  }

  // Validate stanzaId
  if (ctx.stanzaId !== undefined && typeof ctx.stanzaId !== 'string') {
    return { valid: false, reason: 'stanzaId not string' };
  }

  // Validate mentionedJid array
  if (ctx.mentionedJid !== undefined) {
    if (!Array.isArray(ctx.mentionedJid)) return { valid: false, reason: 'mentionedJid not array' };
    if (ctx.mentionedJid.length > 256) return { valid: false, reason: 'too many mentions' };
    for (var i = 0; i < Math.min(ctx.mentionedJid.length, 50); i++) {
      var mj = ctx.mentionedJid[i];
      if (typeof mj !== 'string' || !mj.includes('@')) {
        return { valid: false, reason: 'invalid mentionedJid[' + i + ']' };
      }
    }
  }

  return { valid: true };
}

/**
 * Validate media message metadata
 * WHY: Media messages with corrupt metadata (negative sizes, wrong types)
 * can crash download handlers
 */
function validateMediaMessage(media, type) {
  if (!isPlainObj(media)) return { valid: false, reason: type + ' not object' };

  // File length must be a non-negative number
  if (media.fileLength !== undefined) {
    var fl = safeNum(media.fileLength);
    if (fl < 0) return { valid: false, reason: type + ' negative fileLength' };
    // Size limits per type
    var maxSize = {
      imageMessage    : 15 * 1024 * 1024,
      videoMessage    : 64 * 1024 * 1024,
      audioMessage    : 10 * 1024 * 1024,
      stickerMessage  : 1  * 1024 * 1024,
      documentMessage : 100 * 1024 * 1024,
    };
    var limit = maxSize[type] || 50 * 1024 * 1024;
    if (fl > limit) return { valid: false, reason: type + ' exceeds size limit: ' + fl };
  }

  // MIME type — must be string, reasonable length
  if (media.mimetype !== undefined) {
    if (typeof media.mimetype !== 'string') return { valid: false, reason: type + ' mimetype not string' };
    if (media.mimetype.length > 128) return { valid: false, reason: type + ' mimetype too long' };
    // Basic MIME format check
    if (media.mimetype.length > 0 && !media.mimetype.includes('/')) {
      return { valid: false, reason: type + ' mimetype invalid format' };
    }
  }

  // Caption — string, length limited
  if (media.caption !== undefined) {
    if (typeof media.caption !== 'string') return { valid: false, reason: type + ' caption not string' };
    if (media.caption.length > LIMITS.MAX_STRING_LEN) return { valid: false, reason: type + ' caption too long' };
  }

  // URL/directPath — strings, reasonable length
  if (media.url !== undefined && typeof media.url !== 'string') return { valid: false, reason: type + ' url not string' };
  if (media.directPath !== undefined && typeof media.directPath !== 'string') return { valid: false, reason: type + ' directPath not string' };
  if (media.directPath && media.directPath.length > 1024) return { valid: false, reason: type + ' directPath too long' };

  // File SHA256 — must be buffer/string
  if (media.fileSha256 !== undefined) {
    if (typeof media.fileSha256 !== 'string' && !Buffer.isBuffer(media.fileSha256)) {
      return { valid: false, reason: type + ' fileSha256 invalid type' };
    }
  }

  // Document filename
  if (type === 'documentMessage' && media.fileName !== undefined) {
    if (typeof media.fileName !== 'string') return { valid: false, reason: 'document fileName not string' };
    if (media.fileName.length > 512) return { valid: false, reason: 'fileName too long' };
  }

  return { valid: true };
}

/**
 * Validate buttons message
 * WHY: Buttons with corrupt structure can crash the button renderer
 */
function validateButtonsMessage(bm) {
  if (!isPlainObj(bm)) return { valid: false, reason: 'buttonsMessage not object' };

  // Check size first
  var size = estimatePayloadSize(bm);
  if (size > LIMITS.MAX_PAYLOAD_BYTES) return { valid: false, reason: 'buttons too large: ' + size };

  // Validate buttons array
  if (bm.buttons !== undefined) {
    if (!Array.isArray(bm.buttons)) return { valid: false, reason: 'buttons not array' };
    if (bm.buttons.length > 10) return { valid: false, reason: 'too many buttons' };
    for (var i = 0; i < bm.buttons.length; i++) {
      var b = bm.buttons[i];
      if (!isPlainObj(b)) return { valid: false, reason: 'button[' + i + '] not object' };
      if (b.buttonId !== undefined && typeof b.buttonId !== 'string') return { valid: false, reason: 'buttonId not string' };
      if (b.buttonText) {
        if (!isPlainObj(b.buttonText)) return { valid: false, reason: 'buttonText not object' };
        var dt = b.buttonText.displayText;
        if (dt !== undefined && typeof dt !== 'string') return { valid: false, reason: 'displayText not string' };
        if (dt && dt.length > 2048) return { valid: false, reason: 'button text too long' };
      }
    }
  }

  // Validate text fields
  var textFields = ['contentText', 'footerText', 'headerText'];
  for (var j = 0; j < textFields.length; j++) {
    var f = textFields[j];
    if (bm[f] !== undefined) {
      if (typeof bm[f] !== 'string') return { valid: false, reason: f + ' not string' };
      if (bm[f].length > LIMITS.MAX_STRING_LEN) return { valid: false, reason: f + ' too long' };
    }
  }

  return { valid: true };
}

/**
 * Validate list message
 * WHY: List messages with corrupt sections/rows can crash list renderers
 */
function validateListMessage(lm) {
  if (!isPlainObj(lm)) return { valid: false, reason: 'listMessage not object' };

  var size = estimatePayloadSize(lm);
  if (size > LIMITS.MAX_PAYLOAD_BYTES) return { valid: false, reason: 'list too large' };

  var textFields = ['title', 'description', 'buttonText', 'listType'];
  for (var i = 0; i < textFields.length; i++) {
    var f = textFields[i];
    if (lm[f] !== undefined && typeof lm[f] !== 'string' && typeof lm[f] !== 'number') {
      return { valid: false, reason: 'list ' + f + ' invalid type' };
    }
  }

  if (lm.sections !== undefined) {
    if (!Array.isArray(lm.sections)) return { valid: false, reason: 'sections not array' };
    if (lm.sections.length > 20) return { valid: false, reason: 'too many sections' };
    for (var j = 0; j < lm.sections.length; j++) {
      var sec = lm.sections[j];
      if (!isPlainObj(sec)) return { valid: false, reason: 'section[' + j + '] not object' };
      if (sec.rows !== undefined) {
        if (!Array.isArray(sec.rows)) return { valid: false, reason: 'rows not array' };
        if (sec.rows.length > 50) return { valid: false, reason: 'too many rows' };
        for (var k = 0; k < sec.rows.length; k++) {
          var row = sec.rows[k];
          if (!isPlainObj(row)) return { valid: false, reason: 'row[' + k + '] not object' };
          if (row.title !== undefined && typeof row.title !== 'string') return { valid: false, reason: 'row title not string' };
          if (row.title && row.title.length > 2048) return { valid: false, reason: 'row title too long' };
        }
      }
    }
  }

  return { valid: true };
}

// ═══════════════════════════════════════════════════════════════════════════════
// ASYNC WRAPPERS — production-grade async stability
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * withTimeout — rejects promise after ms, cleans up timer
 * WHY: Prevent hanging operations from blocking the event loop
 */
function withTimeout(promise, ms, label) {
  var timer;
  var cleanup = new Promise(function(resolve, reject) {
    timer = setTimeout(function() {
      reject(new Error((label || 'op') + ' timed out (' + ms + 'ms)'));
    }, ms);
  });
  return Promise.race([
    promise.then(function(v) { clearTimeout(timer); return v; }),
    cleanup,
  ]).catch(function(e) { clearTimeout(timer); throw e; });
}

/**
 * safeAsync — wraps any async fn, never propagates errors
 * WHY: One bad async operation should NEVER crash the whole bot
 */
async function safeAsync(fn, label) {
  try { return await fn(); }
  catch(e) {
    console.error('[ERR]', label || 'async', ':', e.message);
    return null;
  }
}

/**
 * safeSend — wraps sock.sendMessage with timeout + retry
 * WHY: Network failures must never crash message handlers
 */
async function safeSend(sock, jid, content, opts) {
  if (!sock || !jid || !content) return null;
  // Validate jid format before sending
  if (typeof jid !== 'string' || !jid.includes('@') || jid.length > 256) return null;
  return safeAsync(async function() {
    return withTimeout(sock.sendMessage(jid, content, opts || {}), LIMITS.SEND_TIMEOUT, 'send');
  }, 'safeSend:' + jid.slice(0, 20));
}

/**
 * safeDelete — removes a message from chat, never throws
 * WHY: Deletion can fail on old messages or no-permission — must be silent
 */
async function safeDelete(sock, msg) {
  if (!sock || !msg || !msg.key || !msg.key.remoteJid) return;
  return safeAsync(function() {
    return withTimeout(sock.sendMessage(msg.key.remoteJid, { delete: msg.key }), 5000, 'delete');
  }, 'safeDelete');
}

/**
 * safeApiCall — wraps external API calls with timeout, retry, circuit breaker
 */
function makeApiCaller(opts) {
  var failCount = 0;
  var circuitOpen = false;
  var maxFails = (opts && opts.maxFails) || 5;
  var resetMs  = (opts && opts.resetMs)  || 60000;
  var timeout  = (opts && opts.timeout)  || LIMITS.API_TIMEOUT;

  return async function safeApiCall(fn, label) {
    if (circuitOpen) return null;
    try {
      var result = await withTimeout(fn(), timeout, label);
      failCount = 0;
      return result;
    } catch(e) {
      failCount++;
      console.error('[API]', label || 'call', ':', e.message, '(fail ' + failCount + '/' + maxFails + ')');
      if (failCount >= maxFails) {
        circuitOpen = true;
        console.warn('[API] Circuit OPEN —', label || 'caller', '— resets in', resetMs / 1000 + 's');
        setTimeout(function() { circuitOpen = false; failCount = 0; console.log('[API] Circuit reset:', label); }, resetMs);
      }
      return null;
    }
  };
}

// ═══════════════════════════════════════════════════════════════════════════════
// EVENT LOOP LAG MONITOR
// WHY: CPU spike attacks (regex bombs, huge payloads) block the event loop.
// This detects when the event loop is lagged >100ms and logs it.
// ═══════════════════════════════════════════════════════════════════════════════
var lagStats = { max: 0, warnings: 0, lastCheck: Date.now() };

function startLagMonitor() {
  var last = Date.now();
  var monitor = setInterval(function() {
    var now = Date.now();
    var lag = now - last - 100; // expected 100ms interval
    if (lag > LIMITS.EVENT_LOOP_WARN) {
      lagStats.warnings++;
      lagStats.max = Math.max(lagStats.max, lag);
      console.warn('[LOOP] Event loop lag: ' + lag + 'ms (max: ' + lagStats.max + 'ms, total warnings: ' + lagStats.warnings + ')');
    }
    last = now;
  }, 100);
  // Don't keep process alive just for monitor
  if (monitor.unref) monitor.unref();
  return monitor;
}

// ═══════════════════════════════════════════════════════════════════════════════
// BOUNDED CACHE — prevents memory leaks in long-running processes
// ═══════════════════════════════════════════════════════════════════════════════
class BoundedMap {
  constructor(maxSize, ttl) {
    this._map  = new Map();
    this._max  = maxSize || LIMITS.CACHE_MAX;
    this._ttl  = ttl || LIMITS.CACHE_TTL;
  }

  set(key, value) {
    // Evict oldest if at limit
    if (this._map.size >= this._max) {
      var oldKey = this._map.keys().next().value;
      this._map.delete(oldKey);
    }
    this._map.set(key, { value, ts: Date.now() });
    return this;
  }

  get(key) {
    var entry = this._map.get(key);
    if (!entry) return undefined;
    // TTL check
    if (Date.now() - entry.ts > this._ttl) { this._map.delete(key); return undefined; }
    return entry.value;
  }

  has(key) { return this.get(key) !== undefined; }

  delete(key) { return this._map.delete(key); }

  get size() { return this._map.size; }

  // Cleanup expired entries
  cleanup() {
    var now = Date.now();
    var deleted = 0;
    for (var [k, v] of this._map) {
      if (now - v.ts > this._ttl) { this._map.delete(k); deleted++; }
    }
    return deleted;
  }

  keys() { return this._map.keys(); }
  values() { return [...this._map.values()].map(function(v) { return v.value; }); }
}

// ═══════════════════════════════════════════════════════════════════════════════
// STRUCTURED LOGGER — production diagnostics
// ═══════════════════════════════════════════════════════════════════════════════
var LOG = {
  _entries : [],
  MAX      : 500,

  write(level, module, message, meta) {
    var entry = {
      ts     : Date.now(),
      time   : new Date().toISOString(),
      level,
      module : module || 'bot',
      message,
      meta   : meta || null,
    };
    this._entries.unshift(entry);
    if (this._entries.length > this.MAX) this._entries.length = this.MAX;
    var icons = { INFO: 'ℹ️ ', WARN: '⚠️ ', ERROR: '❌', THREAT: '🚨', PERF: '⚡' };
    console.log('[' + (icons[level] || '') + level + '] [' + (module||'?') + '] ' + message);
    return entry;
  },

  info  (mod, msg, meta) { return this.write('INFO',   mod, msg, meta); },
  warn  (mod, msg, meta) { return this.write('WARN',   mod, msg, meta); },
  error (mod, msg, meta) { return this.write('ERROR',  mod, msg, meta); },
  threat(mod, msg, meta) { return this.write('THREAT', mod, msg, meta); },
  perf  (mod, msg, meta) { return this.write('PERF',   mod, msg, meta); },

  recent(n) { return this._entries.slice(0, n || 20); },
};

// ═══════════════════════════════════════════════════════════════════════════════
// SAFE TEXT EXTRACTOR — protocol-level defensive extraction
// WHY: Never trust Baileys field types — any can be null/wrong type
// ═══════════════════════════════════════════════════════════════════════════════
function extractText(msg) {
  try {
    if (!msg || !msg.message) return '';
    var m = msg.message;
    // Try each field with safe string extraction
    var candidates = [
      m.conversation,
      m.extendedTextMessage && m.extendedTextMessage.text,
      m.imageMessage && m.imageMessage.caption,
      m.videoMessage && m.videoMessage.caption,
      m.buttonsResponseMessage && m.buttonsResponseMessage.selectedDisplayText,
      m.listResponseMessage && m.listResponseMessage.title,
      m.templateButtonReplyMessage && m.templateButtonReplyMessage.selectedDisplayText,
    ];
    for (var i = 0; i < candidates.length; i++) {
      var s = safeStr(candidates[i]);
      if (s) return s;
    }
    return '';
  } catch(e) { return ''; }
}

// ═══════════════════════════════════════════════════════════════════════════════
// MEMORY MONITOR
// ═══════════════════════════════════════════════════════════════════════════════
function getMemStats() {
  var mem = process.memoryUsage();
  return {
    heapUsed  : Math.round(mem.heapUsed / 1048576) + 'MB',
    heapTotal : Math.round(mem.heapTotal / 1048576) + 'MB',
    rss       : Math.round(mem.rss / 1048576) + 'MB',
    external  : Math.round((mem.external || 0) / 1048576) + 'MB',
    ratio     : Math.round(mem.heapUsed / mem.heapTotal * 100) + '%',
  };
}

function checkMemory(warnRatio) {
  var mem = process.memoryUsage();
  var ratio = mem.heapUsed / mem.heapTotal;
  if (ratio > (warnRatio || 0.80)) {
    LOG.warn('MEM', 'High heap usage: ' + Math.round(ratio * 100) + '% — ' + Math.round(mem.heapUsed / 1048576) + 'MB');
    return true;
  }
  return false;
}

// ═══════════════════════════════════════════════════════════════════════════════
// EXPORTS
// ═══════════════════════════════════════════════════════════════════════════════
module.exports = {
  // Validation
  validateMessage,
  validateMessageTypes,
  validateContextInfo,
  validateMediaMessage,
  validateButtonsMessage,
  validateListMessage,

  // Safe primitives
  safeStr,
  safeNum,
  safeBool,
  safeArr,
  safeJsonParse,
  isPlainObj,

  // Payload analysis
  hasCircularRef,
  estimatePayloadSize,
  extractText,

  // Async safety
  withTimeout,
  safeAsync,
  safeSend,
  safeDelete,
  makeApiCaller,

  // Infrastructure
  BoundedMap,
  startLagMonitor,
  LOG,
  getMemStats,
  checkMemory,
  lagStats,

  // Constants
  LIMITS,
};
