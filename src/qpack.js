'use strict';

/**
 * RFC 9204: QPACK Field Compression for HTTP/3 — complete implementation.
 *
 *  - Full RFC 9204 Appendix A 99-entry Static Table (0..98)
 *  - Full RFC 7541 Appendix B 257-entry Huffman code (fast Number-accumulator encoder +
 *    byte-at-a-time state-machine decoder with strict EOS/padding validation)
 *  - Stateless `encodeHeaders()` / `decodeHeaders()` (static table only, Required Insert Count = 0)
 *  - Stateful `QpackDecoder` with Dynamic Table, Encoder-Stream instruction parsing,
 *    Required Insert Count wrap-around decoding, Post-Base indexing, Blocked Streams,
 *    Section Acknowledgment / Stream Cancellation / Insert Count Increment emission
 *  - Stateful `QpackEncoder` with Dynamic Table, never-blocking reference strategy
 *    (only acknowledged entries are referenced), eviction safety tracking and
 *    Decoder-Stream instruction handling
 *  - RFC 9114 §4.2 / RFC 9110 field validation (CR/LF/NUL injection, invalid token names,
 *    connection-specific headers, pseudo-header ordering)
 */

const { isUtf8 } = require('node:buffer');

// QPACK error codes (RFC 9204 §6)
const QPACK_DECOMPRESSION_FAILED = 0x0200;
const QPACK_ENCODER_STREAM_ERROR = 0x0201;
const QPACK_DECODER_STREAM_ERROR = 0x0202;

class QpackError extends Error {
  constructor(message, code = QPACK_DECOMPRESSION_FAILED, extra = {}) {
    super(message);
    this.name = 'QpackError';
    this.code = 'ERR_QPACK';
    this.h3Code = code;
    Object.assign(this, extra);
  }
}

function truncated(what) {
  return new QpackError(`Truncated QPACK ${what}`, QPACK_DECOMPRESSION_FAILED, { truncated: true });
}

// Exact 257-entry [code, bitLength] table from RFC 7541 Appendix B (verified Kraft sum === 1)
const HUFFMAN_TABLE = [
  [8184,13],[8388568,23],[268435426,28],[268435427,28],[268435428,28],[268435429,28],[268435430,28],[268435431,28],
  [268435432,28],[16777194,24],[1073741820,30],[268435433,28],[268435434,28],[1073741821,30],[268435435,28],[268435436,28],
  [268435437,28],[268435438,28],[268435439,28],[268435440,28],[268435441,28],[268435442,28],[1073741822,30],[268435443,28],
  [268435444,28],[268435445,28],[268435446,28],[268435447,28],[268435448,28],[268435449,28],[268435450,28],[268435451,28],
  [20,6],[1016,10],[1017,10],[4090,12],[8185,13],[21,6],[248,8],[2042,11],
  [1018,10],[1019,10],[249,8],[2043,11],[250,8],[22,6],[23,6],[24,6],
  [0,5],[1,5],[2,5],[25,6],[26,6],[27,6],[28,6],[29,6],
  [30,6],[31,6],[92,7],[251,8],[32764,15],[32,6],[4091,12],[1020,10],
  [8186,13],[33,6],[93,7],[94,7],[95,7],[96,7],[97,7],[98,7],
  [99,7],[100,7],[101,7],[102,7],[103,7],[104,7],[105,7],[106,7],
  [107,7],[108,7],[109,7],[110,7],[111,7],[112,7],[113,7],[114,7],
  [252,8],[115,7],[253,8],[8187,13],[524272,19],[8188,13],[16380,14],[34,6],
  [32765,15],[3,5],[35,6],[4,5],[36,6],[5,5],[37,6],[38,6],
  [39,6],[6,5],[116,7],[117,7],[40,6],[41,6],[42,6],[7,5],
  [43,6],[118,7],[44,6],[8,5],[9,5],[45,6],[119,7],[120,7],
  [121,7],[122,7],[123,7],[32766,15],[2044,11],[16381,14],[8189,13],[268435452,28],
  [1048550,20],[4194258,22],[1048551,20],[1048552,20],[4194259,22],[4194260,22],[4194261,22],[8388569,23],
  [4194262,22],[8388570,23],[8388571,23],[8388572,23],[8388573,23],[8388574,23],[16777195,24],[8388575,23],
  [16777196,24],[16777197,24],[4194263,22],[8388576,23],[16777198,24],[8388577,23],[8388578,23],[8388579,23],
  [8388580,23],[2097116,21],[4194264,22],[8388581,23],[4194265,22],[8388582,23],[8388583,23],[16777199,24],
  [4194266,22],[2097117,21],[1048553,20],[4194267,22],[4194268,22],[8388584,23],[8388585,23],[2097118,21],
  [8388586,23],[4194269,22],[4194270,22],[16777200,24],[2097119,21],[4194271,22],[8388587,23],[8388588,23],
  [2097120,21],[2097121,21],[4194272,22],[2097122,21],[8388589,23],[4194273,22],[8388590,23],[8388591,23],
  [1048554,20],[4194274,22],[4194275,22],[4194276,22],[8388592,23],[4194277,22],[4194278,22],[8388593,23],
  [67108832,26],[67108833,26],[1048555,20],[524273,19],[4194279,22],[8388594,23],[4194280,22],[33554412,25],
  [67108834,26],[67108835,26],[67108836,26],[134217694,27],[134217695,27],[67108837,26],[16777201,24],[33554413,25],
  [524274,19],[2097123,21],[67108838,26],[134217696,27],[134217697,27],[67108839,26],[134217698,27],[16777202,24],
  [2097124,21],[2097125,21],[67108840,26],[67108841,26],[268435453,28],[134217699,27],[134217700,27],[134217701,27],
  [1048556,20],[16777203,24],[1048557,20],[2097126,21],[4194281,22],[2097127,21],[2097128,21],[8388595,23],
  [4194282,22],[4194283,22],[33554414,25],[33554415,25],[16777204,24],[16777205,24],[67108842,26],[8388596,23],
  [67108843,26],[134217702,27],[67108844,26],[67108845,26],[134217703,27],[134217704,27],[134217705,27],[134217706,27],
  [134217707,27],[268435454,28],[134217708,27],[134217709,27],[134217710,27],[134217711,27],[134217712,27],[67108846,26],
  [1073741823,30], // 256 = EOS
];

const HUFF_CODES = new Uint32Array(256);
const HUFF_LENS = new Uint8Array(256);
for (let i = 0; i < 256; i++) {
  HUFF_CODES[i] = HUFFMAN_TABLE[i][0];
  HUFF_LENS[i] = HUFFMAN_TABLE[i][1];
}

// ---- Huffman decoding state machine (built once from the code trie) ----
// Internal trie nodes get ids 0..N-1 (root = 0). For each (node, inputByte) we precompute:
//   next node id (or -1 = invalid / EOS reached), up to 2 emitted symbols.
// We also record per-node padding validity (depth <= 7 and the path consists solely of 1-bits).
const HUFF_DECODE = (() => {
  const children = [[-1, -1]];
  const leafSym = []; // node -> symbol for leaves
  const depth = [0];
  const allOnes = [true];
  const isLeaf = [false];

  const newNode = (d, ones) => {
    children.push([-1, -1]);
    depth.push(d);
    allOnes.push(ones);
    isLeaf.push(false);
    return children.length - 1;
  };

  for (let sym = 0; sym < 256; sym++) {
    const code = HUFF_CODES[sym];
    const len = HUFF_LENS[sym];
    let node = 0;
    for (let b = len - 1; b >= 0; b--) {
      const bit = (code >>> b) & 1;
      let nxt = children[node][bit];
      if (nxt === -1) {
        nxt = newNode(depth[node] + 1, allOnes[node] && bit === 1);
        children[node][bit] = nxt;
      }
      node = nxt;
    }
    isLeaf[node] = true;
    leafSym[node] = sym;
  }

  // Map internal nodes to compact ids
  const internalIds = new Int32Array(children.length).fill(-1);
  const internalList = [];
  for (let n = 0; n < children.length; n++) {
    if (!isLeaf[n]) {
      internalIds[n] = internalList.length;
      internalList.push(n);
    }
  }
  const count = internalList.length;
  const next = new Int16Array(count * 256);
  const emitCount = new Uint8Array(count * 256);
  const sym1 = new Uint8Array(count * 256);
  const sym2 = new Uint8Array(count * 256);
  const acceptEnd = new Uint8Array(count);

  for (let id = 0; id < count; id++) {
    const n = internalList[id];
    acceptEnd[id] = depth[n] <= 7 && allOnes[n] ? 1 : 0;
    for (let byte = 0; byte < 256; byte++) {
      let node = n;
      let emitted = 0;
      let ok = true;
      for (let b = 7; b >= 0; b--) {
        const bit = (byte >>> b) & 1;
        const c = children[node][bit];
        if (c === -1) {
          ok = false;
          break;
        }
        if (isLeaf[c]) {
          if (emitted === 0) sym1[id * 256 + byte] = leafSym[c];
          else sym2[id * 256 + byte] = leafSym[c];
          emitted++;
          node = 0;
        } else {
          node = c;
        }
      }
      const slot = id * 256 + byte;
      next[slot] = ok ? internalIds[node] : -1;
      emitCount[slot] = emitted;
    }
  }
  return { next, emitCount, sym1, sym2, acceptEnd };
})();

/**
 * Returns the exact Huffman-encoded byte length of `src` (Buffer) without encoding.
 */
function huffmanEncodedLength(src) {
  let bits = 0;
  for (let i = 0; i < src.length; i++) bits += HUFF_LENS[src[i]];
  return (bits + 7) >>> 3;
}

/**
 * Encodes a Buffer (or string) with RFC 7541 Huffman coding.
 * Uses a 53-bit-safe Number accumulator (no BigInt) and a single exact-size allocation.
 */
function huffmanEncode(input) {
  const src = Buffer.isBuffer(input) ? input : Buffer.from(String(input), 'utf8');
  const out = Buffer.allocUnsafe(huffmanEncodedLength(src));
  let acc = 0; // holds < 8 pending bits between symbols (always < 2^38 after adding a code)
  let bits = 0;
  let pos = 0;

  for (let i = 0; i < src.length; i++) {
    const s = src[i];
    const len = HUFF_LENS[s];
    acc = acc * (1 << len) + HUFF_CODES[s]; // len <= 30 -> acc < 2^38 (exact in a double)
    bits += len;
    while (bits >= 8) {
      bits -= 8;
      const div = 2 ** bits;
      const byte = Math.floor(acc / div);
      out[pos++] = byte & 0xff;
      acc -= byte * div;
    }
  }

  if (bits > 0) {
    const pad = 8 - bits;
    out[pos++] = ((acc << pad) | ((1 << pad) - 1)) & 0xff;
  }
  return out;
}

/**
 * Decodes an RFC 7541 Huffman-encoded Buffer into a UTF-8 string (or Buffer if `raw = true`).
 * Throws on invalid codes, EOS symbol presence, or padding longer than 7 bits / not all-ones.
 */
function huffmanDecode(buf, raw = false) {
  const { next, emitCount, sym1, sym2, acceptEnd } = HUFF_DECODE;
  // Max expansion: shortest code is 5 bits -> at most 8/5 symbols per byte
  const out = Buffer.allocUnsafe(Math.ceil((buf.length * 8) / 5));
  let pos = 0;
  let state = 0;

  for (let i = 0; i < buf.length; i++) {
    const slot = (state << 8) | buf[i];
    const n = emitCount[slot];
    if (n > 0) {
      out[pos++] = sym1[slot];
      if (n > 1) out[pos++] = sym2[slot];
    }
    state = next[slot];
    if (state < 0) {
      throw new QpackError('Invalid QPACK Huffman code sequence');
    }
  }

  if (!acceptEnd[state]) {
    throw new QpackError('Invalid QPACK Huffman EOS padding');
  }

  const res = out.subarray(0, pos);
  return raw ? Buffer.from(res) : res.toString('utf8');
}

// Exact 99-entry QPACK Static Table from RFC 9204 Appendix A (indices 0..98)
const STATIC_TABLE = [
  [':authority', ''],                                                                 // 0
  [':path', '/'],                                                                     // 1
  ['age', '0'],                                                                       // 2
  ['content-disposition', ''],                                                        // 3
  ['content-length', '0'],                                                            // 4
  ['cookie', ''],                                                                     // 5
  ['date', ''],                                                                       // 6
  ['etag', ''],                                                                       // 7
  ['if-modified-since', ''],                                                          // 8
  ['if-none-match', ''],                                                              // 9
  ['last-modified', ''],                                                              // 10
  ['link', ''],                                                                       // 11
  ['location', ''],                                                                   // 12
  ['referer', ''],                                                                    // 13
  ['set-cookie', ''],                                                                 // 14
  [':method', 'CONNECT'],                                                             // 15
  [':method', 'DELETE'],                                                              // 16
  [':method', 'GET'],                                                                 // 17
  [':method', 'HEAD'],                                                                // 18
  [':method', 'OPTIONS'],                                                             // 19
  [':method', 'POST'],                                                                // 20
  [':method', 'PUT'],                                                                 // 21
  [':scheme', 'http'],                                                                // 22
  [':scheme', 'https'],                                                               // 23
  [':status', '103'],                                                                 // 24
  [':status', '200'],                                                                 // 25
  [':status', '304'],                                                                 // 26
  [':status', '404'],                                                                 // 27
  [':status', '503'],                                                                 // 28
  ['accept', '*/*'],                                                                  // 29
  ['accept', 'application/dns-message'],                                              // 30
  ['accept-encoding', 'gzip, deflate, br'],                                           // 31
  ['accept-ranges', 'bytes'],                                                         // 32
  ['access-control-allow-headers', 'cache-control'],                                  // 33
  ['access-control-allow-headers', 'content-type'],                                   // 34
  ['access-control-allow-origin', '*'],                                               // 35
  ['cache-control', 'max-age=0'],                                                     // 36
  ['cache-control', 'max-age=2592000'],                                               // 37
  ['cache-control', 'max-age=604800'],                                                // 38
  ['cache-control', 'no-cache'],                                                      // 39
  ['cache-control', 'no-store'],                                                      // 40
  ['cache-control', 'public, max-age=31536000'],                                      // 41
  ['content-encoding', 'br'],                                                         // 42
  ['content-encoding', 'gzip'],                                                       // 43
  ['content-type', 'application/dns-message'],                                        // 44
  ['content-type', 'application/javascript'],                                         // 45
  ['content-type', 'application/json'],                                               // 46
  ['content-type', 'application/x-www-form-urlencoded'],                              // 47
  ['content-type', 'image/gif'],                                                      // 48
  ['content-type', 'image/jpeg'],                                                     // 49
  ['content-type', 'image/png'],                                                      // 50
  ['content-type', 'text/css'],                                                       // 51
  ['content-type', 'text/html; charset=utf-8'],                                       // 52
  ['content-type', 'text/plain'],                                                     // 53
  ['content-type', 'text/plain;charset=utf-8'],                                       // 54
  ['range', 'bytes=0-'],                                                              // 55
  ['strict-transport-security', 'max-age=31536000'],                                  // 56
  ['strict-transport-security', 'max-age=31536000; includesubdomains'],               // 57
  ['strict-transport-security', 'max-age=31536000; includesubdomains; preload'],      // 58
  ['vary', 'accept-encoding'],                                                        // 59
  ['vary', 'origin'],                                                                 // 60
  ['x-content-type-options', 'nosniff'],                                              // 61
  ['x-xss-protection', '1; mode=block'],                                              // 62
  [':status', '100'],                                                                 // 63
  [':status', '204'],                                                                 // 64
  [':status', '206'],                                                                 // 65
  [':status', '302'],                                                                 // 66
  [':status', '400'],                                                                 // 67
  [':status', '403'],                                                                 // 68
  [':status', '421'],                                                                 // 69
  [':status', '425'],                                                                 // 70
  [':status', '500'],                                                                 // 71
  ['accept-language', ''],                                                            // 72
  ['access-control-allow-credentials', 'FALSE'],                                      // 73
  ['access-control-allow-credentials', 'TRUE'],                                       // 74
  ['access-control-allow-headers', '*'],                                              // 75
  ['access-control-allow-methods', 'get'],                                            // 76
  ['access-control-allow-methods', 'get, post, options'],                             // 77
  ['access-control-allow-methods', 'options'],                                        // 78
  ['access-control-expose-headers', 'content-length'],                                // 79
  ['access-control-request-headers', 'content-type'],                                 // 80
  ['access-control-request-method', 'get'],                                           // 81
  ['access-control-request-method', 'post'],                                          // 82
  ['alt-svc', 'clear'],                                                               // 83
  ['authorization', ''],                                                              // 84
  ['content-security-policy', "script-src 'none'; object-src 'none'; base-uri 'none'"], // 85
  ['early-data', '1'],                                                                // 86
  ['expect-ct', ''],                                                                  // 87
  ['forwarded', ''],                                                                  // 88
  ['if-range', ''],                                                                   // 89
  ['origin', ''],                                                                     // 90
  ['purpose', 'prefetch'],                                                            // 91
  ['server', ''],                                                                     // 92
  ['timing-allow-origin', '*'],                                                       // 93
  ['upgrade-insecure-requests', '1'],                                                 // 94
  ['user-agent', ''],                                                                 // 95
  ['x-forwarded-for', ''],                                                            // 96
  ['x-frame-options', 'deny'],                                                        // 97
  ['x-frame-options', 'sameorigin'],                                                  // 98
];

// Fast lookup maps for encoding
const STATIC_PAIR_MAP = new Map();
const STATIC_NAME_MAP = new Map();
for (let i = 0; i < STATIC_TABLE.length; i++) {
  const [name, val] = STATIC_TABLE[i];
  const pairKey = `${name}\0${val}`;
  if (!STATIC_PAIR_MAP.has(pairKey)) STATIC_PAIR_MAP.set(pairKey, i);
  if (!STATIC_NAME_MAP.has(name)) STATIC_NAME_MAP.set(name, i);
}

// Never indexed into a dynamic table & always sent with the N ("never index") bit
const SENSITIVE_HEADERS = new Set(['authorization', 'proxy-authorization', 'set-cookie']);
// Not cached in the stateless encoded-line cache (may carry secrets)
const NON_CACHEABLE_HEADERS = new Set(['authorization', 'proxy-authorization', 'cookie', 'set-cookie']);
// RFC 9114 §4.2: connection-specific fields are forbidden in HTTP/3
const CONNECTION_SPECIFIC_HEADERS = new Set([
  'connection',
  'keep-alive',
  'proxy-connection',
  'transfer-encoding',
  'upgrade',
  'http2-settings',
]);
const REQUEST_PSEUDO_HEADERS = new Set([':method', ':scheme', ':authority', ':path', ':protocol']);
const RESPONSE_PSEUDO_HEADERS = new Set([':status']);
// Volatile per-request fields the dynamic-table encoder never inserts (would only churn the table)
const ENCODER_NO_INDEX = new Set([
  'content-length',
  'if-modified-since',
  'if-none-match',
  'if-range',
  'range',
  'date',
  'x-request-id',
  'traceparent',
  'tracestate',
  'sentry-trace',
]);

// RFC 9110 §5.6.2 tchar (lowercase-only for HTTP/3 field names)
const TOKEN_CHARS = new Uint8Array(128);
for (const c of "!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyz") TOKEN_CHARS[c.charCodeAt(0)] = 1;

function isValidFieldName(name) {
  if (name.length === 0) return false;
  let i = name.charCodeAt(0) === 0x3a ? 1 : 0; // allow leading ':' for pseudo-headers
  if (i === 1 && name.length === 1) return false;
  for (; i < name.length; i++) {
    const c = name.charCodeAt(i);
    if (c >= 128 || TOKEN_CHARS[c] === 0) return false;
  }
  return true;
}

function isValidFieldValue(value) {
  for (let i = 0; i < value.length; i++) {
    const c = value.charCodeAt(i);
    if (c === 0x00 || c === 0x0a || c === 0x0d) return false;
  }
  return true;
}

// Bounded cache of encoded static/literal field lines (skips repeated Huffman work on bursts)
const ENCODED_FIELD_CACHE = new Map();
const MAX_FIELD_CACHE_SIZE = 2048;

/**
 * RFC 9204 §4.1.1: Prefixed Integer Encoding
 */
function encodePrefixInt(firstByteMask, prefixBits, value) {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new QpackError(`Invalid QPACK prefixed integer: ${value}`);
  }
  const maxPrefix = (1 << prefixBits) - 1;
  if (value < maxPrefix) {
    return Buffer.from([firstByteMask | value]);
  }
  const bytes = [firstByteMask | maxPrefix];
  let rem = value - maxPrefix;
  while (rem >= 128) {
    bytes.push((rem % 128) | 0x80);
    rem = Math.floor(rem / 128);
  }
  bytes.push(rem);
  return Buffer.from(bytes);
}

/**
 * RFC 9204 §4.1.1: Prefixed Integer Decoding (bounded to 2^53-1, max 9 continuation bytes).
 * Throws `QpackError` with `truncated: true` when more input is needed.
 */
function decodePrefixInt(buf, offset, prefixBits) {
  if (offset >= buf.length) throw truncated('prefixed integer');
  const maxPrefix = (1 << prefixBits) - 1;
  let val = buf[offset] & maxPrefix;
  let pos = offset + 1;
  if (val < maxPrefix) {
    return { value: val, nextOffset: pos };
  }
  let mul = 1;
  for (let count = 0; ; count++) {
    if (pos >= buf.length) throw truncated('multi-byte integer');
    if (count >= 8) throw new QpackError('QPACK prefixed integer overflow');
    const b = buf[pos++];
    val += (b & 0x7f) * mul;
    mul *= 128;
    if ((b & 0x80) === 0) break;
  }
  if (!Number.isSafeInteger(val)) throw new QpackError('QPACK prefixed integer overflow');
  return { value: val, nextOffset: pos };
}

/**
 * Encodes a string literal with an N-bit length prefix and the Huffman flag right above the length prefix.
 */
function encodeStringLiteral(str, firstByteMask, lenPrefixBits, allowHuffman = true) {
  const rawBuf = Buffer.isBuffer(str) ? str : Buffer.from(String(str), 'utf8');
  const huffBit = 1 << lenPrefixBits;

  if (allowHuffman && rawBuf.length > 0) {
    const hLen = huffmanEncodedLength(rawBuf);
    if (hLen < rawBuf.length) {
      return Buffer.concat([
        encodePrefixInt(firstByteMask | huffBit, lenPrefixBits, hLen),
        huffmanEncode(rawBuf),
      ]);
    }
  }
  return Buffer.concat([encodePrefixInt(firstByteMask, lenPrefixBits, rawBuf.length), rawBuf]);
}

function bytesToFieldString(bytes) {
  // UTF-8 when valid, otherwise lossless Latin-1 (matches Node's http parser behaviour)
  return isUtf8(bytes) ? bytes.toString('utf8') : bytes.toString('latin1');
}

function decodeStringLiteral(buf, offset, lenPrefixBits, maxLen = Infinity) {
  if (offset >= buf.length) throw truncated('string literal');
  const huffBit = 1 << lenPrefixBits;
  const isHuffman = (buf[offset] & huffBit) !== 0;
  const lenDec = decodePrefixInt(buf, offset, lenPrefixBits);
  if (lenDec.value > maxLen) {
    throw new QpackError(`QPACK string literal too large (${lenDec.value} > ${maxLen})`);
  }
  const start = lenDec.nextOffset;
  const end = start + lenDec.value;
  if (end > buf.length) throw truncated('string literal bytes');
  const slice = buf.subarray(start, end);
  const bytes = isHuffman ? huffmanDecode(slice, true) : slice;
  return { value: bytesToFieldString(bytes), byteLength: bytes.length, nextOffset: end };
}

/**
 * Normalizes a header object, Map, Headers-like iterable or array of [name, value] pairs into an
 * ordered list with pseudo-headers first and lowercased field names (RFC 9114 §4.3).
 * Validates names/values unless `validate === false`.
 */
function normalizeHeaderList(headers, validate = true) {
  const pseudos = [];
  const regulars = [];

  const pushEntry = (rawName, rawVal) => {
    if (rawVal === undefined || rawVal === null) return;
    const name = String(rawName).toLowerCase();
    if (CONNECTION_SPECIFIC_HEADERS.has(name)) return;
    if (Array.isArray(rawVal)) {
      for (const item of rawVal) pushEntry(name, item);
      return;
    }
    const val = String(rawVal);
    if (name === 'te' && val.toLowerCase() !== 'trailers') return; // RFC 9114 §4.2
    if (validate) {
      if (!isValidFieldName(name)) {
        throw new QpackError(`Invalid HTTP/3 header field name: ${JSON.stringify(rawName)}`, 0x010e);
      }
      if (!isValidFieldValue(val)) {
        throw new QpackError(
          `Invalid HTTP/3 header field value for "${name}" (contains CR, LF or NUL)`,
          0x010e
        );
      }
    }
    if (name.charCodeAt(0) === 0x3a) {
      pseudos.push([name, val]);
    } else {
      regulars.push([name, val]);
    }
  };

  if (Array.isArray(headers)) {
    for (const [k, v] of headers) pushEntry(k, v);
  } else if (
    headers instanceof Map ||
    (typeof Headers !== 'undefined' && headers instanceof Headers)
  ) {
    for (const [k, v] of headers.entries()) pushEntry(k, v);
  } else if (headers && typeof headers === 'object') {
    for (const k of Object.keys(headers)) pushEntry(k, headers[k]);
  }

  return pseudos.length === 0 ? regulars : pseudos.concat(regulars);
}

function encodeStaticOrLiteralLine(name, value, useHuffman, sensitive) {
  const pairIdx = !sensitive ? STATIC_PAIR_MAP.get(`${name}\0${value}`) : undefined;
  if (pairIdx !== undefined) {
    // 1 1 index(6+): Indexed Field Line (Static Table)
    return encodePrefixInt(0xc0, 6, pairIdx);
  }
  const nameIdx = STATIC_NAME_MAP.get(name);
  if (nameIdx !== undefined) {
    // 0 1 N T=1 nameIdx(4+): Literal Field Line With Static Name Reference
    return Buffer.concat([
      encodePrefixInt(0x50 | (sensitive ? 0x20 : 0x00), 4, nameIdx),
      encodeStringLiteral(value, 0x00, 7, useHuffman),
    ]);
  }
  // 0 0 1 N H nameLen(3+) name + H valLen(7+) val: Literal Field Line With Literal Name
  return Buffer.concat([
    encodeStringLiteral(name, 0x20 | (sensitive ? 0x10 : 0x00), 3, useHuffman),
    encodeStringLiteral(value, 0x00, 7, useHuffman),
  ]);
}

/**
 * Stateless encoder: encodes HTTP/3 headers into a QPACK Encoded Field Section Buffer
 * using Static Table references + Huffman literals (Required Insert Count = 0).
 *
 * @param {object|Array|Map} headers
 * @param {{ huffman?: boolean, validate?: boolean }} [options]
 */
function encodeHeaders(headers, options = {}) {
  const useHuffman = options.huffman !== false;
  const list = normalizeHeaderList(headers, options.validate !== false);

  // Encoded Field Section Prefix: Required Insert Count = 0 (0x00), S=0 & Delta Base = 0 (0x00)
  const parts = [Buffer.from([0x00, 0x00])];

  for (const [name, value] of list) {
    const cacheable = useHuffman && !NON_CACHEABLE_HEADERS.has(name) && value.length < 256;
    const cacheKey = cacheable ? `${name}\0${value}` : null;
    if (cacheKey !== null) {
      const cached = ENCODED_FIELD_CACHE.get(cacheKey);
      if (cached) {
        parts.push(cached);
        continue;
      }
    }

    const line = encodeStaticOrLiteralLine(name, value, useHuffman, SENSITIVE_HEADERS.has(name));

    if (cacheKey !== null) {
      if (ENCODED_FIELD_CACHE.size >= MAX_FIELD_CACHE_SIZE) ENCODED_FIELD_CACHE.clear();
      ENCODED_FIELD_CACHE.set(cacheKey, line);
    }
    parts.push(line);
  }

  return Buffer.concat(parts);
}

function buildHeaderObject(rawHeaders) {
  const headers = Object.create(null);
  for (const [name, value] of rawHeaders) {
    if (name === 'set-cookie') {
      if (!headers['set-cookie']) headers['set-cookie'] = [];
      headers['set-cookie'].push(value);
    } else if (headers[name] !== undefined) {
      headers[name] += (name === 'cookie' ? '; ' : ', ') + value;
    } else {
      headers[name] = value;
    }
  }
  return headers;
}

function validateDecodedFieldList(rawHeaders, kind) {
  if (!kind) return;
  let seenRegular = false;
  const seenPseudo = new Set();
  const allowed = kind === 'response' ? RESPONSE_PSEUDO_HEADERS : kind === 'request' ? REQUEST_PSEUDO_HEADERS : null;
  for (const [name, value] of rawHeaders) {
    if (!isValidFieldName(name) || name !== name.toLowerCase()) {
      throw new QpackError(`Malformed HTTP/3 field name: ${JSON.stringify(name)}`, 0x010e);
    }
    if (!isValidFieldValue(value)) {
      throw new QpackError(`Malformed HTTP/3 field value for "${name}"`, 0x010e);
    }
    if (name.charCodeAt(0) === 0x3a) {
      if (kind === 'trailers') {
        throw new QpackError(`Pseudo-header ${name} not allowed in trailers`, 0x010e);
      }
      if (seenRegular) throw new QpackError(`Pseudo-header ${name} after regular header`, 0x010e);
      if (allowed && !allowed.has(name)) throw new QpackError(`Unexpected pseudo-header ${name}`, 0x010e);
      if (seenPseudo.has(name)) throw new QpackError(`Duplicate pseudo-header ${name}`, 0x010e);
      seenPseudo.add(name);
    } else {
      seenRegular = true;
      if (CONNECTION_SPECIFIC_HEADERS.has(name)) {
        throw new QpackError(`Connection-specific header "${name}" is forbidden in HTTP/3`, 0x010e);
      }
    }
  }
  if (kind === 'response' && !seenPseudo.has(':status')) {
    throw new QpackError('HTTP/3 response missing :status pseudo-header', 0x010e);
  }
}

/**
 * Decodes representation lines of a field section body (shared by stateless & stateful decoders).
 */
function decodeFieldLines(buf, pos, ctx) {
  const rawHeaders = [];
  let listSize = 0;
  const { table, base, requiredInsertCount, maxFieldSectionSize } = ctx;

  const dynamicEntry = (absIdx) => {
    if (!table) throw new QpackError('Unexpected dynamic table reference in QPACK');
    if (absIdx >= requiredInsertCount) {
      throw new QpackError(`QPACK reference ${absIdx} >= Required Insert Count ${requiredInsertCount}`);
    }
    const entry = table.get(absIdx);
    if (!entry) throw new QpackError(`QPACK reference to evicted/invalid dynamic entry ${absIdx}`);
    return entry;
  };

  const push = (name, value) => {
    listSize += name.length + value.length + 32;
    if (listSize > maxFieldSectionSize) {
      throw new QpackError(`QPACK field section exceeds max size ${maxFieldSectionSize}`, 0x010e);
    }
    rawHeaders.push([name, value]);
  };

  while (pos < buf.length) {
    const first = buf[pos];

    if ((first & 0x80) !== 0) {
      // 1 T index(6+): Indexed Field Line
      const isStatic = (first & 0x40) !== 0;
      const idxDec = decodePrefixInt(buf, pos, 6);
      pos = idxDec.nextOffset;
      if (isStatic) {
        const entry = STATIC_TABLE[idxDec.value];
        if (!entry) throw new QpackError(`Invalid QPACK static table index: ${idxDec.value}`);
        push(entry[0], entry[1]);
      } else {
        const entry = dynamicEntry(base - 1 - idxDec.value);
        push(entry.name, entry.value);
      }
    } else if ((first & 0xc0) === 0x40) {
      // 0 1 N T nameIndex(4+): Literal Field Line With Name Reference
      const isStatic = (first & 0x10) !== 0;
      const idxDec = decodePrefixInt(buf, pos, 4);
      pos = idxDec.nextOffset;
      let name;
      if (isStatic) {
        const entry = STATIC_TABLE[idxDec.value];
        if (!entry) throw new QpackError(`Invalid QPACK static table name index: ${idxDec.value}`);
        name = entry[0];
      } else {
        name = dynamicEntry(base - 1 - idxDec.value).name;
      }
      const valDec = decodeStringLiteral(buf, pos, 7, maxFieldSectionSize);
      pos = valDec.nextOffset;
      push(name, valDec.value);
    } else if ((first & 0xe0) === 0x20) {
      // 0 0 1 N H nameLen(3+) name + H valLen(7+) value: Literal Field Line With Literal Name
      const nameDec = decodeStringLiteral(buf, pos, 3, maxFieldSectionSize);
      pos = nameDec.nextOffset;
      const valDec = decodeStringLiteral(buf, pos, 7, maxFieldSectionSize);
      pos = valDec.nextOffset;
      push(nameDec.value, valDec.value);
    } else if ((first & 0xf0) === 0x10) {
      // 0 0 0 1 index(4+): Indexed Field Line With Post-Base Index
      const idxDec = decodePrefixInt(buf, pos, 4);
      pos = idxDec.nextOffset;
      const entry = dynamicEntry(base + idxDec.value);
      push(entry.name, entry.value);
    } else {
      // 0 0 0 0 N nameIndex(3+): Literal Field Line With Post-Base Name Reference
      const idxDec = decodePrefixInt(buf, pos, 3);
      pos = idxDec.nextOffset;
      const name = dynamicEntry(base + idxDec.value).name;
      const valDec = decodeStringLiteral(buf, pos, 7, maxFieldSectionSize);
      pos = valDec.nextOffset;
      push(name, valDec.value);
    }
  }

  return rawHeaders;
}

/**
 * Stateless decoder: decodes a QPACK Encoded Field Section that only uses the static table.
 *
 * @param {Buffer} buf
 * @param {{ maxFieldSectionSize?: number, kind?: 'request'|'response'|'trailers' }} [options]
 * @returns {{ headers: object, rawHeaders: Array<[string, string]> }}
 */
function decodeHeaders(buf, options = {}) {
  if (buf.length < 2) throw truncated('field section prefix');
  const ricDec = decodePrefixInt(buf, 0, 8);
  const dbDec = decodePrefixInt(buf, ricDec.nextOffset, 7);
  if (ricDec.value !== 0) {
    throw new QpackError(
      `Received dynamic QPACK Required Insert Count (${ricDec.value}) on a stateless decoder`
    );
  }
  const rawHeaders = decodeFieldLines(buf, dbDec.nextOffset, {
    table: null,
    base: 0,
    requiredInsertCount: 0,
    maxFieldSectionSize: options.maxFieldSectionSize ?? Infinity,
  });
  validateDecodedFieldList(rawHeaders, options.kind);
  return { headers: buildHeaderObject(rawHeaders), rawHeaders };
}

/**
 * QPACK Dynamic Table (RFC 9204 §3.2) addressed by absolute index.
 */
class DynamicTable {
  constructor(capacity = 0) {
    this.capacity = capacity;
    this.size = 0;
    this.insertCount = 0; // total number of inserts ever (absolute index of next entry)
    this.dropped = 0; // number of evicted entries (absolute index of oldest live entry)
    this.entries = []; // ring of live entries, entries[0] = absolute index `dropped`
  }

  static entrySize(nameBytes, valueBytes) {
    return nameBytes + valueBytes + 32;
  }

  get length() {
    return this.entries.length;
  }

  get(absIdx) {
    if (absIdx < this.dropped || absIdx >= this.insertCount) return null;
    return this.entries[absIdx - this.dropped] || null;
  }

  /** Returns the absolute index of the entry `rel` positions before the most recent insert. */
  relativeToAbsolute(rel) {
    return this.insertCount - 1 - rel;
  }

  evictUntil(targetSize, canEvict = null) {
    while (this.size > targetSize && this.entries.length > 0) {
      if (canEvict && !canEvict(this.dropped)) return false;
      const old = this.entries.shift();
      this.size -= old.size;
      this.dropped++;
    }
    return this.size <= targetSize;
  }

  setCapacity(cap) {
    this.capacity = cap;
    this.evictUntil(cap);
  }

  insert(name, value, nameBytes, valueBytes) {
    const size = DynamicTable.entrySize(nameBytes, valueBytes);
    if (size > this.capacity) {
      throw new QpackError(
        `QPACK dynamic table entry (${size}B) exceeds capacity (${this.capacity}B)`,
        QPACK_ENCODER_STREAM_ERROR
      );
    }
    this.evictUntil(this.capacity - size);
    this.entries.push({ name, value, size, abs: this.insertCount });
    this.size += size;
    return this.insertCount++;
  }
}

/**
 * Stateful RFC 9204 QPACK Decoder (receives the peer's encoder stream, emits decoder-stream instructions).
 */
class QpackDecoder {
  constructor({ maxTableCapacity = 4096, maxBlockedStreams = 16, maxFieldSectionSize = 1 << 20 } = {}) {
    this.maxTableCapacity = Math.max(0, maxTableCapacity | 0);
    this.maxBlockedStreams = Math.max(0, maxBlockedStreams | 0);
    this.maxFieldSectionSize = maxFieldSectionSize;
    this.maxEntries = Math.floor(this.maxTableCapacity / 32);
    this.table = new DynamicTable(0);
    this.knownReceivedCount = 0; // highest insert count acknowledged to the encoder
    this._encBuf = Buffer.alloc(0);
    this._out = [];
    this.blocked = new Map(); // streamId -> requiredInsertCount
    this.stats = { inserts: 0, sectionsDecoded: 0, sectionsBlocked: 0, dynamicRefs: 0 };
  }

  get insertCount() {
    return this.table.insertCount;
  }

  /**
   * Feeds bytes received on the peer's QPACK encoder stream. Returns the number of new inserts.
   */
  feedEncoderStream(chunk) {
    this._encBuf = this._encBuf.length === 0 ? chunk : Buffer.concat([this._encBuf, chunk]);
    const before = this.table.insertCount;
    let pos = 0;
    const buf = this._encBuf;

    while (pos < buf.length) {
      const start = pos;
      try {
        pos = this._parseEncoderInstruction(buf, pos);
      } catch (err) {
        if (err.truncated) {
          pos = start;
          break;
        }
        if (err instanceof QpackError) err.h3Code = QPACK_ENCODER_STREAM_ERROR;
        throw err;
      }
    }
    this._encBuf = pos >= buf.length ? Buffer.alloc(0) : Buffer.from(buf.subarray(pos));

    const added = this.table.insertCount - before;
    if (added > 0) {
      this.stats.inserts += added;
      const increment = this.table.insertCount - this.knownReceivedCount;
      if (increment > 0) {
        this._out.push(encodePrefixInt(0x00, 6, increment)); // Insert Count Increment
        this.knownReceivedCount = this.table.insertCount;
      }
    }
    return added;
  }

  _parseEncoderInstruction(buf, pos) {
    const first = buf[pos];
    if ((first & 0x80) !== 0) {
      // 1 T nameIndex(6+) + value: Insert With Name Reference
      const isStatic = (first & 0x40) !== 0;
      const idx = decodePrefixInt(buf, pos, 6);
      const val = decodeStringLiteral(buf, idx.nextOffset, 7, this.maxTableCapacity);
      let name;
      if (isStatic) {
        const entry = STATIC_TABLE[idx.value];
        if (!entry) throw new QpackError(`Invalid static index ${idx.value} in encoder stream`);
        name = entry[0];
      } else {
        const entry = this.table.get(this.table.relativeToAbsolute(idx.value));
        if (!entry) throw new QpackError(`Invalid dynamic relative index ${idx.value} in encoder stream`);
        name = entry.name;
      }
      this.table.insert(name, val.value, Buffer.byteLength(name), val.byteLength);
      return val.nextOffset;
    }
    if ((first & 0xc0) === 0x40) {
      // 0 1 H nameLen(5+) name + value: Insert With Literal Name
      const nameDec = decodeStringLiteral(buf, pos, 5, this.maxTableCapacity);
      const val = decodeStringLiteral(buf, nameDec.nextOffset, 7, this.maxTableCapacity);
      this.table.insert(nameDec.value, val.value, nameDec.byteLength, val.byteLength);
      return val.nextOffset;
    }
    if ((first & 0xe0) === 0x20) {
      // 0 0 1 capacity(5+): Set Dynamic Table Capacity
      const cap = decodePrefixInt(buf, pos, 5);
      if (cap.value > this.maxTableCapacity) {
        throw new QpackError(
          `Encoder set dynamic table capacity ${cap.value} > advertised max ${this.maxTableCapacity}`
        );
      }
      this.table.setCapacity(cap.value);
      return cap.nextOffset;
    }
    // 0 0 0 index(5+): Duplicate
    const idx = decodePrefixInt(buf, pos, 5);
    const entry = this.table.get(this.table.relativeToAbsolute(idx.value));
    if (!entry) throw new QpackError(`Invalid duplicate index ${idx.value} in encoder stream`);
    this.table.insert(entry.name, entry.value, Buffer.byteLength(entry.name), Buffer.byteLength(entry.value));
    return idx.nextOffset;
  }

  _decodeRequiredInsertCount(encoded) {
    if (encoded === 0) return 0;
    const fullRange = 2 * this.maxEntries;
    if (fullRange === 0 || encoded > fullRange) {
      throw new QpackError(`Invalid encoded Required Insert Count ${encoded}`);
    }
    const maxValue = this.table.insertCount + this.maxEntries;
    const maxWrapped = Math.floor(maxValue / fullRange) * fullRange;
    let ric = maxWrapped + encoded - 1;
    if (ric > maxValue) {
      if (ric <= fullRange) throw new QpackError('Invalid Required Insert Count wrap');
      ric -= fullRange;
    }
    if (ric === 0) throw new QpackError('Invalid Required Insert Count 0');
    return ric;
  }

  /**
   * Decodes a field section for `streamId`.
   * Returns `{ blocked: true, requiredInsertCount }` if it references not-yet-received inserts,
   * otherwise `{ blocked: false, headers, rawHeaders, requiredInsertCount }`.
   */
  decodeFieldSection(streamId, buf, kind = null) {
    if (buf.length < 2) throw truncated('field section prefix');
    const ricDec = decodePrefixInt(buf, 0, 8);
    const requiredInsertCount = this._decodeRequiredInsertCount(ricDec.value);
    if (ricDec.nextOffset >= buf.length) throw truncated('field section base');
    const sign = (buf[ricDec.nextOffset] & 0x80) !== 0;
    const dbDec = decodePrefixInt(buf, ricDec.nextOffset, 7);
    let base;
    if (!sign) {
      base = requiredInsertCount + dbDec.value;
    } else {
      base = requiredInsertCount - dbDec.value - 1;
      if (base < 0) throw new QpackError('Negative QPACK Base');
    }

    if (requiredInsertCount > this.table.insertCount) {
      if (!this.blocked.has(streamId)) {
        if (this.blocked.size >= this.maxBlockedStreams) {
          throw new QpackError(
            `QPACK blocked streams limit (${this.maxBlockedStreams}) exceeded`
          );
        }
        this.blocked.set(streamId, requiredInsertCount);
        this.stats.sectionsBlocked++;
      }
      return { blocked: true, requiredInsertCount };
    }
    this.blocked.delete(streamId);

    const rawHeaders = decodeFieldLines(buf, dbDec.nextOffset, {
      table: this.table,
      base,
      requiredInsertCount,
      maxFieldSectionSize: this.maxFieldSectionSize,
    });
    validateDecodedFieldList(rawHeaders, kind);

    this.stats.sectionsDecoded++;
    if (requiredInsertCount > 0) {
      this.stats.dynamicRefs++;
      this._out.push(encodePrefixInt(0x80, 7, streamId)); // Section Acknowledgment
      if (requiredInsertCount > this.knownReceivedCount) {
        this.knownReceivedCount = requiredInsertCount;
      }
    }
    return { blocked: false, headers: buildHeaderObject(rawHeaders), rawHeaders, requiredInsertCount };
  }

  /** Returns `true` if the stream's pending field section can now be decoded. */
  isUnblocked(streamId) {
    const ric = this.blocked.get(streamId);
    return ric === undefined || ric <= this.table.insertCount;
  }

  /**
   * Signals the encoder that `streamId` was reset/abandoned (RFC 9204 §4.4.2).
   */
  cancelStream(streamId) {
    this.blocked.delete(streamId);
    if (this.maxTableCapacity > 0) {
      this._out.push(encodePrefixInt(0x40, 6, streamId)); // Stream Cancellation
    }
  }

  /** Returns and clears pending decoder-stream bytes (to be written to our QPACK decoder stream). */
  takeDecoderStreamData() {
    if (this._out.length === 0) return null;
    const out = Buffer.concat(this._out);
    this._out = [];
    return out;
  }
}

/**
 * Stateful RFC 9204 QPACK Encoder with a never-blocking dynamic table strategy:
 *  - Inserts reusable fields via the encoder stream,
 *  - Only references entries already acknowledged by the peer (zero head-of-line blocking risk),
 *  - Never evicts entries that are unacknowledged or referenced by unacknowledged sections.
 */
class QpackEncoder {
  constructor({ enabled = true, maxCapacity = 4096, huffman = true, validate = true } = {}) {
    this.enabled = enabled;
    this.maxCapacityLimit = maxCapacity;
    this.huffman = huffman;
    this.validate = validate;
    this.peerMaxTableCapacity = 0;
    this.peerMaxBlockedStreams = 0;
    this.maxEntries = 0;
    this.table = new DynamicTable(0);
    this.knownReceivedCount = 0;
    this.lookupPair = new Map(); // "name\0value" -> abs (latest)
    this.lookupName = new Map(); // name -> abs (latest)
    this.refCounts = new Map(); // abs -> outstanding reference count
    this.outstanding = new Map(); // streamId -> [{ ric, refs: number[] }]
    this._out = [];
    this._decBuf = null;
    this.stats = { inserts: 0, dynamicHits: 0, sections: 0, bytesSaved: 0 };
  }

  get active() {
    return this.enabled && this.table.capacity > 0;
  }

  /**
   * Applies the peer's SETTINGS_QPACK_MAX_TABLE_CAPACITY / SETTINGS_QPACK_BLOCKED_STREAMS.
   */
  applyPeerSettings(maxTableCapacity = 0, maxBlockedStreams = 0) {
    this.peerMaxTableCapacity = Number(maxTableCapacity) || 0;
    this.peerMaxBlockedStreams = Number(maxBlockedStreams) || 0;
    this.maxEntries = Math.floor(this.peerMaxTableCapacity / 32);
    if (!this.enabled || this.peerMaxTableCapacity === 0) return;
    const cap = Math.min(this.peerMaxTableCapacity, this.maxCapacityLimit);
    if (cap > 0 && cap !== this.table.capacity) {
      this.table.setCapacity(cap);
      this._out.push(encodePrefixInt(0x20, 5, cap)); // Set Dynamic Table Capacity
    }
  }

  _isEvictable(abs) {
    return abs < this.knownReceivedCount && !(this.refCounts.get(abs) > 0);
  }

  _tryInsert(name, value, nameIsStaticIdx, nameDynAbs) {
    const nameBytes = Buffer.byteLength(name);
    const valueBytes = Buffer.byteLength(value);
    const size = DynamicTable.entrySize(nameBytes, valueBytes);
    // Keep each entry small relative to the table to preserve reuse
    if (size > this.table.capacity / 2) return -1;
    const target = this.table.capacity - size;
    // Check eviction feasibility before mutating
    let simulated = this.table.size;
    for (let i = 0; simulated > target && i < this.table.entries.length; i++) {
      const e = this.table.entries[i];
      if (!this._isEvictable(e.abs)) return -1;
      simulated -= e.size;
    }
    const evicted = [];
    while (this.table.size > target) {
      const old = this.table.entries[0];
      evicted.push(old);
      this.table.evictUntil(this.table.size - old.size);
    }
    for (const old of evicted) {
      const pk = `${old.name}\0${old.value}`;
      if (this.lookupPair.get(pk) === old.abs) this.lookupPair.delete(pk);
      if (this.lookupName.get(old.name) === old.abs) this.lookupName.delete(old.name);
    }

    let instr;
    if (nameIsStaticIdx !== undefined) {
      instr = Buffer.concat([
        encodePrefixInt(0xc0, 6, nameIsStaticIdx),
        encodeStringLiteral(value, 0x00, 7, this.huffman),
      ]);
    } else if (nameDynAbs !== undefined && this.table.get(nameDynAbs)) {
      const rel = this.table.insertCount - 1 - nameDynAbs;
      instr = Buffer.concat([
        encodePrefixInt(0x80, 6, rel),
        encodeStringLiteral(value, 0x00, 7, this.huffman),
      ]);
    } else {
      instr = Buffer.concat([
        encodeStringLiteral(name, 0x40, 5, this.huffman),
        encodeStringLiteral(value, 0x00, 7, this.huffman),
      ]);
    }
    const abs = this.table.insert(name, value, nameBytes, valueBytes);
    this._out.push(instr);
    this.lookupPair.set(`${name}\0${value}`, abs);
    this.lookupName.set(name, abs);
    this.stats.inserts++;
    return abs;
  }

  /**
   * Encodes a header list for `streamId` into an Encoded Field Section.
   */
  encode(streamId, headers) {
    if (!this.active) {
      return encodeHeaders(headers, { huffman: this.huffman, validate: this.validate });
    }

    const list = normalizeHeaderList(headers, this.validate);
    const lines = [];
    const refs = [];
    let maxRef = -1;

    for (const [name, value] of list) {
      const sensitive = SENSITIVE_HEADERS.has(name);
      const staticPair = !sensitive ? STATIC_PAIR_MAP.get(`${name}\0${value}`) : undefined;
      if (staticPair !== undefined) {
        lines.push({ kind: 'static', bytes: encodePrefixInt(0xc0, 6, staticPair) });
        continue;
      }

      if (!sensitive) {
        const dynAbs = this.lookupPair.get(`${name}\0${value}`);
        if (dynAbs !== undefined && dynAbs < this.knownReceivedCount && this.table.get(dynAbs)) {
          lines.push({ kind: 'dyn', abs: dynAbs });
          refs.push(dynAbs);
          // Pin immediately so later inserts in this same section can never evict it
          this.refCounts.set(dynAbs, (this.refCounts.get(dynAbs) || 0) + 1);
          if (dynAbs > maxRef) maxRef = dynAbs;
          this.stats.dynamicHits++;
          continue;
        }
        // Not yet in the table -> insert for future reuse (skip per-request volatile fields)
        if (dynAbs === undefined && !ENCODER_NO_INDEX.has(name) && (name.charCodeAt(0) !== 0x3a || name === ':authority')) {
          const staticName = STATIC_NAME_MAP.get(name);
          const dynName = this.lookupName.get(name);
          this._tryInsert(name, value, staticName, staticName === undefined ? dynName : undefined);
        }
      }

      lines.push({ kind: 'literal', bytes: encodeStaticOrLiteralLine(name, value, this.huffman, sensitive) });
    }

    const ric = maxRef + 1;
    const base = ric;
    const parts = [];
    if (ric === 0) {
      parts.push(Buffer.from([0x00, 0x00]));
    } else {
      const encRic = (ric % (2 * this.maxEntries)) + 1;
      parts.push(encodePrefixInt(0x00, 8, encRic), encodePrefixInt(0x00, 7, 0));
    }
    for (const l of lines) {
      if (l.kind === 'dyn') {
        parts.push(encodePrefixInt(0x80, 6, base - 1 - l.abs));
      } else {
        parts.push(l.bytes);
      }
    }

    if (refs.length > 0) {
      let q = this.outstanding.get(streamId);
      if (!q) {
        q = [];
        this.outstanding.set(streamId, q);
      }
      q.push({ ric, refs });
    }
    this.stats.sections++;
    return Buffer.concat(parts);
  }

  _releaseSection(section) {
    for (const a of section.refs) {
      const c = (this.refCounts.get(a) || 0) - 1;
      if (c <= 0) this.refCounts.delete(a);
      else this.refCounts.set(a, c);
    }
  }

  /**
   * Feeds bytes received on the peer's QPACK decoder stream.
   */
  feedDecoderStream(chunk) {
    this._decBuf = this._decBuf && this._decBuf.length > 0 ? Buffer.concat([this._decBuf, chunk]) : chunk;
    const buf = this._decBuf;
    let pos = 0;
    while (pos < buf.length) {
      const start = pos;
      try {
        const first = buf[pos];
        if ((first & 0x80) !== 0) {
          // Section Acknowledgment
          const sid = decodePrefixInt(buf, pos, 7);
          pos = sid.nextOffset;
          const q = this.outstanding.get(sid.value);
          if (!q || q.length === 0) {
            throw new QpackError(
              `Unexpected Section Acknowledgment for stream ${sid.value}`,
              QPACK_DECODER_STREAM_ERROR
            );
          }
          const sec = q.shift();
          if (q.length === 0) this.outstanding.delete(sid.value);
          this._releaseSection(sec);
          if (sec.ric > this.knownReceivedCount) this.knownReceivedCount = sec.ric;
        } else if ((first & 0xc0) === 0x40) {
          // Stream Cancellation
          const sid = decodePrefixInt(buf, pos, 6);
          pos = sid.nextOffset;
          const q = this.outstanding.get(sid.value);
          if (q) {
            for (const sec of q) this._releaseSection(sec);
            this.outstanding.delete(sid.value);
          }
        } else {
          // Insert Count Increment
          const inc = decodePrefixInt(buf, pos, 6);
          pos = inc.nextOffset;
          if (inc.value === 0 || this.knownReceivedCount + inc.value > this.table.insertCount) {
            throw new QpackError('Invalid QPACK Insert Count Increment', QPACK_DECODER_STREAM_ERROR);
          }
          this.knownReceivedCount += inc.value;
        }
      } catch (err) {
        if (err.truncated) {
          pos = start;
          break;
        }
        throw err;
      }
    }
    this._decBuf = pos >= buf.length ? null : Buffer.from(buf.subarray(pos));
  }

  /** Returns and clears pending encoder-stream bytes (to be written to our QPACK encoder stream). */
  takeEncoderStreamData() {
    if (this._out.length === 0) return null;
    const out = Buffer.concat(this._out);
    this._out = [];
    return out;
  }
}

module.exports = {
  QPACK_DECOMPRESSION_FAILED,
  QPACK_ENCODER_STREAM_ERROR,
  QPACK_DECODER_STREAM_ERROR,
  QpackError,
  STATIC_TABLE,
  HUFFMAN_TABLE,
  huffmanEncode,
  huffmanDecode,
  huffmanEncodedLength,
  encodePrefixInt,
  decodePrefixInt,
  encodeStringLiteral,
  decodeStringLiteral,
  normalizeHeaderList,
  isValidFieldName,
  isValidFieldValue,
  encodeHeaders,
  decodeHeaders,
  DynamicTable,
  QpackDecoder,
  QpackEncoder,
};
