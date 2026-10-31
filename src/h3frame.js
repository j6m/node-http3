'use strict';

const { encodeVarint, decodeVarint } = require('./varint');

// RFC 9114 Section 7.2 HTTP/3 Frame Types
const H3_FRAME_DATA = 0x00;
const H3_FRAME_HEADERS = 0x01;
const H3_FRAME_CANCEL_PUSH = 0x03;
const H3_FRAME_SETTINGS = 0x04;
const H3_FRAME_PUSH_PROMISE = 0x05;
const H3_FRAME_GOAWAY = 0x07;
const H3_FRAME_MAX_PUSH_ID = 0x0d;

// HTTP/2 frame types explicitly reserved & forbidden in HTTP/3 (RFC 9114 §7.2.8)
const H3_RESERVED_H2_FRAMES = new Set([0x02, 0x06, 0x08, 0x09]);

// RFC 9114 Section 6.2 Unidirectional Stream Types
const H3_STREAM_CONTROL = 0x00;
const H3_STREAM_PUSH = 0x01;
const H3_STREAM_QPACK_ENCODER = 0x02;
const H3_STREAM_QPACK_DECODER = 0x03;

// HTTP/3 & QPACK Settings Identifiers
const SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0x01;
const SETTINGS_MAX_FIELD_SECTION_SIZE = 0x06;
const SETTINGS_QPACK_BLOCKED_STREAMS = 0x07;
const SETTINGS_ENABLE_CONNECT_PROTOCOL = 0x08;
const SETTINGS_H3_DATAGRAM = 0x33;

// HTTP/2 settings identifiers explicitly reserved & forbidden in HTTP/3 (RFC 9114 §7.2.4.1)
const H3_RESERVED_H2_SETTINGS = new Set(['2', '3', '4', '5']);

function h3Error(message, h3Code = 0x0106) {
  const err = new Error(message);
  err.h3Code = h3Code;
  return err;
}

function buildH3Frame(frameType, payload) {
  const buf = Buffer.isBuffer(payload) ? payload : Buffer.from(payload);
  return Buffer.concat([
    encodeVarint(frameType),
    encodeVarint(buf.length),
    buf,
  ]);
}

function buildHeadersFrame(encodedFieldSection) {
  return buildH3Frame(H3_FRAME_HEADERS, encodedFieldSection);
}

function buildDataFrame(data) {
  const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
  return buildH3Frame(H3_FRAME_DATA, buf);
}

function buildSettingsFrame(settings = {}) {
  const pairs = [
    [SETTINGS_QPACK_MAX_TABLE_CAPACITY, settings.qpackMaxTableCapacity ?? 0],
    [SETTINGS_MAX_FIELD_SECTION_SIZE, settings.maxFieldSectionSize ?? 16777216],
    [SETTINGS_QPACK_BLOCKED_STREAMS, settings.qpackBlockedStreams ?? 0],
  ];
  if (settings.enableConnectProtocol) {
    pairs.push([SETTINGS_ENABLE_CONNECT_PROTOCOL, 1]);
  }
  if (settings.h3Datagram) {
    pairs.push([SETTINGS_H3_DATAGRAM, 1]);
  }
  // Add one RFC 9114 GREASE setting (0x1f * N + 0x21) for full browser-like interoperability
  const greaseId = 0x1f * 17 + 0x21;
  pairs.push([greaseId, 0]);

  const chunks = [];
  for (const [id, val] of pairs) {
    chunks.push(encodeVarint(id), encodeVarint(val));
  }
  return buildH3Frame(H3_FRAME_SETTINGS, Buffer.concat(chunks));
}

function buildGoawayFrame(streamId = 0) {
  return buildH3Frame(H3_FRAME_GOAWAY, encodeVarint(streamId));
}

function parseSettingsPayload(buf) {
  const settings = Object.create(null);
  let pos = 0;
  while (pos < buf.length) {
    const idDec = decodeVarint(buf, pos);
    if (!idDec) throw h3Error('Truncated HTTP/3 SETTINGS identifier', 0x0106);
    pos += idDec.bytesRead;
    const valDec = decodeVarint(buf, pos);
    if (!valDec) throw h3Error('Truncated HTTP/3 SETTINGS value', 0x0106);
    pos += valDec.bytesRead;

    const key = String(idDec.value);
    if (H3_RESERVED_H2_SETTINGS.has(key)) {
      throw h3Error(`Forbidden HTTP/2 setting identifier 0x0${key} in HTTP/3 SETTINGS`, 0x0109);
    }
    if (Object.prototype.hasOwnProperty.call(settings, key)) {
      throw h3Error(`Duplicate HTTP/3 setting identifier ${key}`, 0x0109);
    }
    settings[key] = valDec.value;
  }
  return settings;
}

/**
 * Incremental RFC 9114 HTTP/3 Frame Parser for a single QUIC stream.
 * - Streams DATA (0x00) frame bytes immediately without buffering the entire frame (62-bit safe).
 * - Enforces `maxBufferedFrameSize` upfront before buffering HEADERS / SETTINGS / GOAWAY (OOM-proof).
 * - Enforces RFC 9114 stream-type frame placement rules (Control stream vs Request stream).
 */
class H3StreamParser {
  constructor(options = {}) {
    this.buf = Buffer.alloc(0);
    this.streamingType = null; // 'data' | 'skip' | null
    this.remainingBytes = 0n;
    this.maxBufferedFrameSize = options.maxBufferedFrameSize ?? 16 * 1024 * 1024;
    this.isControlStream = Boolean(options.isControlStream);
    this._sawFirstControlFrame = false;
  }

  get hasPartialFrame() {
    return this.streamingType !== null || this.buf.length > 0;
  }

  /**
   * Feeds contiguous stream bytes and returns an array of parsed HTTP/3 events:
   * - `{ type: 'data', data: Buffer }`
   * - `{ type: 'headers', payload: Buffer }`
   * - `{ type: 'settings', settings: Object }`
   * - `{ type: 'goaway', streamId: number|bigint }`
   */
  push(chunk) {
    if (!chunk || chunk.length === 0) return [];
    this.buf = this.buf.length === 0 ? chunk : Buffer.concat([this.buf, chunk]);
    const events = [];

    while (this.buf.length > 0) {
      // 1. Continue streaming an in-progress DATA or unknown/GREASE frame (62-bit BigInt safe)
      if (this.streamingType !== null) {
        const avail = BigInt(this.buf.length);
        const takeBig = avail < this.remainingBytes ? avail : this.remainingBytes;
        const take = Number(takeBig);
        const slice = this.buf.subarray(0, take);
        this.buf = this.buf.subarray(take);
        this.remainingBytes -= takeBig;

        if (this.streamingType === 'data' && slice.length > 0) {
          events.push({ type: 'data', data: Buffer.from(slice) });
        }
        if (this.remainingBytes === 0n) {
          this.streamingType = null;
        }
        continue;
      }

      // 2. Decode Frame Type + Frame Length header
      const typeDec = decodeVarint(this.buf, 0);
      if (!typeDec) break;
      const lenDec = decodeVarint(this.buf, typeDec.bytesRead);
      if (!lenDec) break;

      const headerLen = typeDec.bytesRead + lenDec.bytesRead;
      const frameType = typeDec.value;
      const rawLen = lenDec.value;
      const rawLenBig = typeof rawLen === 'bigint' ? rawLen : BigInt(rawLen);

      if (typeof frameType === 'number' && H3_RESERVED_H2_FRAMES.has(frameType)) {
        throw h3Error(`Forbidden reserved HTTP/2 frame type 0x0${frameType.toString(16)}`, 0x0105);
      }

      // Enforce RFC 9114 §6.2.1 & §7.2 frame placement rules
      if (this.isControlStream) {
        if (!this._sawFirstControlFrame) {
          this._sawFirstControlFrame = true;
          if (frameType !== H3_FRAME_SETTINGS) {
            throw h3Error('First frame on HTTP/3 control stream must be SETTINGS', 0x010a);
          }
        } else if (frameType === H3_FRAME_SETTINGS) {
          throw h3Error('Duplicate SETTINGS frame on HTTP/3 control stream', 0x0105);
        }
        if (
          frameType === H3_FRAME_DATA ||
          frameType === H3_FRAME_HEADERS ||
          frameType === H3_FRAME_PUSH_PROMISE
        ) {
          throw h3Error(`Unexpected frame 0x${frameType.toString(16)} on HTTP/3 control stream`, 0x0105);
        }
      } else if (
        frameType === H3_FRAME_SETTINGS ||
        frameType === H3_FRAME_GOAWAY ||
        frameType === H3_FRAME_CANCEL_PUSH ||
        frameType === H3_FRAME_MAX_PUSH_ID
      ) {
        throw h3Error(`Control frame 0x${frameType.toString(16)} forbidden on request stream`, 0x0105);
      }

      if (frameType === H3_FRAME_DATA) {
        this.buf = this.buf.subarray(headerLen);
        if (rawLenBig > 0n) {
          this.streamingType = 'data';
          this.remainingBytes = rawLenBig;
        }
        continue;
      }

      const isKnownBuffered =
        frameType === H3_FRAME_HEADERS ||
        frameType === H3_FRAME_SETTINGS ||
        frameType === H3_FRAME_GOAWAY;

      if (!isKnownBuffered) {
        // Unknown or GREASE frame: stream-discard its payload without buffering
        this.buf = this.buf.subarray(headerLen);
        if (rawLenBig > 0n) {
          this.streamingType = 'skip';
          this.remainingBytes = rawLenBig;
        }
        continue;
      }

      // Guard against oversized buffered frames BEFORE allocating/accumulating payload
      if (rawLenBig > BigInt(this.maxBufferedFrameSize)) {
        throw h3Error(
          `HTTP/3 frame 0x${frameType.toString(16)} length ${rawLenBig} exceeds limit ${this.maxBufferedFrameSize}`,
          0x0107
        );
      }
      const frameLen = Number(rawLenBig);

      // Wait until full payload for HEADERS / SETTINGS / GOAWAY is available
      if (this.buf.length < headerLen + frameLen) {
        break;
      }

      const payload = Buffer.from(this.buf.subarray(headerLen, headerLen + frameLen));
      this.buf = this.buf.subarray(headerLen + frameLen);

      if (frameType === H3_FRAME_HEADERS) {
        events.push({ type: 'headers', payload });
      } else if (frameType === H3_FRAME_SETTINGS) {
        events.push({ type: 'settings', settings: parseSettingsPayload(payload) });
      } else if (frameType === H3_FRAME_GOAWAY) {
        const idDec = decodeVarint(payload, 0);
        if (!idDec || idDec.bytesRead !== payload.length) {
          throw h3Error('Malformed HTTP/3 GOAWAY frame payload', 0x0106);
        }
        events.push({ type: 'goaway', streamId: idDec.value });
      }
    }

    return events;
  }
}

module.exports = {
  H3_FRAME_DATA,
  H3_FRAME_HEADERS,
  H3_FRAME_CANCEL_PUSH,
  H3_FRAME_SETTINGS,
  H3_FRAME_PUSH_PROMISE,
  H3_FRAME_GOAWAY,
  H3_FRAME_MAX_PUSH_ID,
  H3_STREAM_CONTROL,
  H3_STREAM_PUSH,
  H3_STREAM_QPACK_ENCODER,
  H3_STREAM_QPACK_DECODER,
  SETTINGS_QPACK_MAX_TABLE_CAPACITY,
  SETTINGS_MAX_FIELD_SECTION_SIZE,
  SETTINGS_QPACK_BLOCKED_STREAMS,
  SETTINGS_ENABLE_CONNECT_PROTOCOL,
  SETTINGS_H3_DATAGRAM,
  buildH3Frame,
  buildHeadersFrame,
  buildDataFrame,
  buildSettingsFrame,
  buildGoawayFrame,
  parseSettingsPayload,
  H3StreamParser,
};
