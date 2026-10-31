'use strict';

/**
 * RFC 9000 Section 16: QUIC Variable-Length Integer Encoding (1, 2, 4, or 8 bytes).
 *
 * - Supports both `number` (0 .. 2^53-1, exact) and `bigint` (0n .. 2^62-1).
 * - Strict validation: rejects negatives, non-integers, NaN/Infinity and values >= 2^62.
 * - Zero-allocation `writeVarint()` / `decodeVarint()` hot paths plus a cursor-based `VarintReader`.
 * - `encodeVarint(value, minLen)` supports forced (non-minimal) widths, e.g. 2-byte Length fields.
 */

const MAX_VARINT_1 = 63;
const MAX_VARINT_2 = 16383;
const MAX_VARINT_4 = 1073741823;
const MAX_VARINT_8 = 4611686018427387903n; // 2^62 - 1
const MAX_VARINT_NUMBER = Number.MAX_SAFE_INTEGER; // 2^53 - 1 (exact Number range)
const MAX_SAFE_BIG = 9007199254740991n;
const TWO_POW_32 = 4294967296;

class VarintError extends RangeError {
  constructor(message) {
    super(message);
    this.name = 'VarintError';
    this.code = 'ERR_QUIC_VARINT';
  }
}

function assertNumber(value) {
  if (!Number.isInteger(value) || value < 0) {
    throw new VarintError(`QUIC varint must be a non-negative integer, got: ${value}`);
  }
  if (value > MAX_VARINT_NUMBER) {
    throw new VarintError(
      `QUIC varint ${value} exceeds Number.MAX_SAFE_INTEGER; pass a BigInt for exact 62-bit values`
    );
  }
}

/**
 * Returns the byte length (1, 2, 4, or 8) required to encode `value` as a QUIC varint.
 * @param {number|bigint} value
 * @returns {1|2|4|8}
 */
function varintLen(value) {
  if (typeof value === 'bigint') {
    if (value < 0n || value > MAX_VARINT_8) {
      throw new VarintError(`QUIC varint out of range: ${value}`);
    }
    if (value <= 63n) return 1;
    if (value <= 16383n) return 2;
    if (value <= 1073741823n) return 4;
    return 8;
  }
  assertNumber(value);
  if (value <= MAX_VARINT_1) return 1;
  if (value <= MAX_VARINT_2) return 2;
  if (value <= MAX_VARINT_4) return 4;
  return 8;
}

/**
 * Writes a QUIC varint into `buf` at `offset` and returns the new offset.
 * @param {Buffer} buf
 * @param {number|bigint} value
 * @param {number} [offset=0]
 * @param {1|2|4|8} [forcedLen] optional fixed encoding width (must be >= minimal width)
 * @returns {number} next offset
 */
function writeVarint(buf, value, offset = 0, forcedLen = 0) {
  const minLen = varintLen(value);
  const len = forcedLen ? forcedLen : minLen;
  if (len !== 1 && len !== 2 && len !== 4 && len !== 8) {
    throw new VarintError(`Invalid QUIC varint width: ${len}`);
  }
  if (len < minLen) {
    throw new VarintError(`QUIC varint ${value} does not fit in ${len} byte(s)`);
  }
  if (offset + len > buf.length) {
    throw new VarintError(`Buffer too small to write ${len}-byte QUIC varint at offset ${offset}`);
  }

  if (len === 8) {
    let hi;
    let lo;
    if (typeof value === 'bigint') {
      hi = Number((value >> 32n) & 0x3fffffffn);
      lo = Number(value & 0xffffffffn);
    } else {
      hi = Math.floor(value / TWO_POW_32);
      lo = value - hi * TWO_POW_32;
    }
    buf.writeUInt32BE((0xc0000000 | hi) >>> 0, offset);
    buf.writeUInt32BE(lo >>> 0, offset + 4);
    return offset + 8;
  }

  const n = typeof value === 'bigint' ? Number(value) : value;
  if (len === 1) {
    buf[offset] = n;
  } else if (len === 2) {
    buf.writeUInt16BE((0x4000 | n) >>> 0, offset);
  } else {
    buf.writeUInt32BE((0x80000000 | n) >>> 0, offset);
  }
  return offset + len;
}

/**
 * Encodes `value` into a new Buffer containing the QUIC varint.
 * @param {number|bigint} value
 * @param {1|2|4|8} [forcedLen] optional fixed (non-minimal) width
 * @returns {Buffer}
 */
function encodeVarint(value, forcedLen = 0) {
  // Fast path for the overwhelmingly common 1-byte case
  if (forcedLen === 0 && typeof value === 'number' && value >= 0 && value <= 63 && (value | 0) === value) {
    const b = Buffer.allocUnsafe(1);
    b[0] = value;
    return b;
  }
  const len = forcedLen || varintLen(value);
  const buf = Buffer.allocUnsafe(len);
  writeVarint(buf, value, 0, len);
  return buf;
}

/**
 * Decodes a QUIC varint from `buf` starting at `offset`.
 * Returns `null` if `buf` does not contain enough bytes for the full varint.
 * `value` is a JS `number` when `<= Number.MAX_SAFE_INTEGER`, otherwise a `bigint`.
 *
 * @param {Buffer|Uint8Array} buf
 * @param {number} [offset=0]
 * @returns {{ value: number|bigint, bytesRead: number } | null}
 */
function decodeVarint(buf, offset = 0) {
  if (offset < 0 || offset >= buf.length) return null;
  const first = buf[offset];
  const prefix = first >>> 6;

  if (prefix === 0) {
    return { value: first & 0x3f, bytesRead: 1 };
  }
  if (prefix === 1) {
    if (offset + 2 > buf.length) return null;
    return { value: ((first & 0x3f) << 8) | buf[offset + 1], bytesRead: 2 };
  }
  if (prefix === 2) {
    if (offset + 4 > buf.length) return null;
    const v =
      (first & 0x3f) * 0x1000000 + ((buf[offset + 1] << 16) | (buf[offset + 2] << 8) | buf[offset + 3]);
    return { value: v, bytesRead: 4 };
  }
  if (offset + 8 > buf.length) return null;
  const hi =
    (first & 0x3f) * 0x1000000 + ((buf[offset + 1] << 16) | (buf[offset + 2] << 8) | buf[offset + 3]);
  const lo =
    buf[offset + 4] * 0x1000000 + ((buf[offset + 5] << 16) | (buf[offset + 6] << 8) | buf[offset + 7]);
  // hi < 2^30; result exact as Number iff hi < 2^21
  if (hi < 0x200000) {
    return { value: hi * TWO_POW_32 + lo, bytesRead: 8 };
  }
  const big = (BigInt(hi) << 32n) | BigInt(lo);
  return {
    value: big <= MAX_SAFE_BIG ? Number(big) : big,
    bytesRead: 8,
  };
}

/**
 * Returns the encoded length (1, 2, 4, or 8) of the varint starting at `buf[offset]`
 * without decoding it, or 0 if `offset` is out of range.
 */
function peekVarintLen(buf, offset = 0) {
  if (offset < 0 || offset >= buf.length) return 0;
  return 1 << (buf[offset] >>> 6);
}

/**
 * Returns `true` if the varint at `offset` uses the shortest possible encoding.
 * (RFC 9000 §12.4: frame types MUST use minimal encoding.)
 */
function isMinimalVarint(buf, offset = 0) {
  const dec = decodeVarint(buf, offset);
  if (!dec) return false;
  return dec.bytesRead === varintLen(dec.value);
}

/**
 * Cursor-based zero-copy varint/byte reader for parsing QUIC frames and HTTP/3 payloads.
 * All `read*` methods throw a `VarintError` on truncation; `tryRead*` return `null` instead.
 */
class VarintReader {
  constructor(buf, offset = 0, end = buf.length) {
    this.buf = buf;
    this.pos = offset;
    this.end = Math.min(end, buf.length);
  }

  get remaining() {
    return this.end - this.pos;
  }

  get done() {
    return this.pos >= this.end;
  }

  tryReadVarint() {
    if (this.pos >= this.end) return null;
    const len = 1 << (this.buf[this.pos] >>> 6);
    if (this.pos + len > this.end) return null;
    const dec = decodeVarint(this.buf, this.pos);
    this.pos += dec.bytesRead;
    return dec.value;
  }

  readVarint(what = 'varint') {
    const v = this.tryReadVarint();
    if (v === null) throw new VarintError(`Truncated QUIC ${what}`);
    return v;
  }

  /** Reads a varint and coerces it to a safe `number` (throws if > 2^53-1). */
  readVarintNumber(what = 'varint') {
    const v = this.readVarint(what);
    if (typeof v === 'bigint') {
      throw new VarintError(`QUIC ${what} (${v}) exceeds Number.MAX_SAFE_INTEGER`);
    }
    return v;
  }

  readUInt8(what = 'byte') {
    if (this.pos + 1 > this.end) throw new VarintError(`Truncated QUIC ${what}`);
    return this.buf[this.pos++];
  }

  readBytes(len, what = 'bytes') {
    if (len < 0 || this.pos + len > this.end) throw new VarintError(`Truncated QUIC ${what}`);
    const out = this.buf.subarray(this.pos, this.pos + len);
    this.pos += len;
    return out;
  }

  /** Reads a varint length prefix followed by that many bytes. */
  readLengthPrefixed(what = 'length-prefixed field') {
    const len = this.readVarintNumber(`${what} length`);
    return this.readBytes(len, what);
  }

  skip(len) {
    if (len < 0 || this.pos + len > this.end) throw new VarintError('Truncated QUIC skip');
    this.pos += len;
  }

  rest() {
    const out = this.buf.subarray(this.pos, this.end);
    this.pos = this.end;
    return out;
  }
}

/**
 * Growable zero-copy output builder for QUIC/HTTP3 serialization.
 */
class VarintWriter {
  constructor(initialSize = 64) {
    this.buf = Buffer.allocUnsafe(Math.max(16, initialSize));
    this.pos = 0;
  }

  _ensure(n) {
    if (this.pos + n <= this.buf.length) return;
    let size = this.buf.length * 2;
    while (size < this.pos + n) size *= 2;
    const next = Buffer.allocUnsafe(size);
    this.buf.copy(next, 0, 0, this.pos);
    this.buf = next;
  }

  writeVarint(value, forcedLen = 0) {
    const len = forcedLen || varintLen(value);
    this._ensure(len);
    this.pos = writeVarint(this.buf, value, this.pos, len);
    return this;
  }

  writeUInt8(b) {
    this._ensure(1);
    this.buf[this.pos++] = b & 0xff;
    return this;
  }

  writeBytes(bytes) {
    this._ensure(bytes.length);
    if (Buffer.isBuffer(bytes)) {
      bytes.copy(this.buf, this.pos);
    } else {
      this.buf.set(bytes, this.pos);
    }
    this.pos += bytes.length;
    return this;
  }

  writeLengthPrefixed(bytes) {
    this.writeVarint(bytes.length);
    return this.writeBytes(bytes);
  }

  get length() {
    return this.pos;
  }

  /** Returns a view (no copy) of the written bytes. */
  finish() {
    return this.buf.subarray(0, this.pos);
  }
}

module.exports = {
  MAX_VARINT_1,
  MAX_VARINT_2,
  MAX_VARINT_4,
  MAX_VARINT_8,
  MAX_VARINT_NUMBER,
  VarintError,
  varintLen,
  writeVarint,
  encodeVarint,
  decodeVarint,
  peekVarintLen,
  isMinimalVarint,
  VarintReader,
  VarintWriter,
};
