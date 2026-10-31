'use strict';

const { Duplex, Readable } = require('node:stream');
const { EventEmitter } = require('node:events');
const zlib = require('node:zlib');
const { promisify } = require('node:util');

const { QuicConnection, QuicCongestionController, defaultDnsCache } = require('./connection');
const { defaultSessionStore, SessionTicketStore } = require('./tls13');
const { decodeVarint, encodeVarint } = require('./varint');
const {
  QpackError,
  QpackDecoder,
  QpackEncoder,
  encodeHeaders,
  decodeHeaders,
} = require('./qpack');
const {
  H3_STREAM_CONTROL,
  H3_STREAM_PUSH,
  H3_STREAM_QPACK_ENCODER,
  H3_STREAM_QPACK_DECODER,
  SETTINGS_QPACK_MAX_TABLE_CAPACITY,
  SETTINGS_MAX_FIELD_SECTION_SIZE,
  SETTINGS_QPACK_BLOCKED_STREAMS,
  buildHeadersFrame,
  buildDataFrame,
  buildSettingsFrame,
  buildGoawayFrame,
  H3StreamParser,
} = require('./h3frame');

const gunzipAsync = promisify(zlib.gunzip);
const inflateAsync = promisify(zlib.inflate);
const inflateRawAsync = promisify(zlib.inflateRaw);
const brotliDecompressAsync = promisify(zlib.brotliDecompress);
const zstdDecompressAsync =
  typeof zlib.zstdDecompress === 'function' ? promisify(zlib.zstdDecompress) : null;

async function decompressBody(buf, contentEncoding) {
  if (!buf || buf.length === 0 || !contentEncoding) return buf;
  const encodings = String(contentEncoding)
    .split(',')
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean)
    .reverse();

  let out = buf;
  for (const enc of encodings) {
    if (enc === 'identity') continue;
    if (enc === 'gzip' || enc === 'x-gzip') {
      out = await gunzipAsync(out);
    } else if (enc === 'br') {
      out = await brotliDecompressAsync(out);
    } else if (enc === 'deflate') {
      try {
        out = await inflateAsync(out);
      } catch {
        out = await inflateRawAsync(out);
      }
    } else if (enc === 'zstd' && zstdDecompressAsync) {
      out = await zstdDecompressAsync(out);
    }
  }
  return out;
}

function parsePriorityHeader(val) {
  if (!val || typeof val !== 'string') return null;
  let urgency = 3;
  let incremental = false;
  let matched = false;
  for (const part of val.split(',')) {
    const t = part.trim();
    if (t.startsWith('u=')) {
      const u = Number(t.slice(2));
      if (Number.isFinite(u)) {
        urgency = Math.min(7, Math.max(0, Math.floor(u)));
        matched = true;
      }
    } else if (t === 'i' || t === 'i=?1') {
      incremental = true;
      matched = true;
    } else if (t === 'i=?0') {
      incremental = false;
      matched = true;
    }
  }
  return matched ? { urgency, incremental } : null;
}

function makeH3Error(message, h3Code = 0x0101) {
  const err = new Error(message);
  err.h3Code = h3Code;
  return err;
}

async function normalizeRequestBody(body, userHeaders) {
  if (body === undefined || body === null) return null;
  if (Buffer.isBuffer(body)) return body;
  if (ArrayBuffer.isView(body)) {
    return Buffer.from(body.buffer, body.byteOffset, body.byteLength);
  }
  if (body instanceof ArrayBuffer) {
    return Buffer.from(body);
  }
  if (body instanceof URLSearchParams) {
    if (!userHeaders['content-type']) {
      userHeaders['content-type'] = 'application/x-www-form-urlencoded;charset=UTF-8';
    }
    return Buffer.from(body.toString(), 'utf8');
  }
  if (body instanceof Readable || typeof body[Symbol.asyncIterator] === 'function') {
    const chunks = [];
    for await (const chunk of body) {
      chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
    }
    return Buffer.concat(chunks);
  }
  if (typeof body === 'object') {
    if (!userHeaders['content-type']) {
      userHeaders['content-type'] = 'application/json';
    }
    return Buffer.from(JSON.stringify(body), 'utf8');
  }
  return Buffer.from(String(body), 'utf8');
}

/**
 * Node.js `http2` ClientHttp2Stream-compatible Duplex Stream representing a single HTTP/3 request/response stream.
 */
class Http3ClientStream extends Duplex {
  constructor(session, streamId, headers, options = {}) {
    super();
    this.session = session;
    this.id = streamId;
    this.sentHeaders = headers;
    this.responseHeaders = null;
    this.rawResponseHeaders = null;
    this.informationalHeaders = [];
    this.trailers = null;
    this.statusCode = null;
    this.httpVersion = '3.0';
    this.aborted = false;
    this._h3Closed = false;
    this.rstCode = 0;

    this._h3Parser = new H3StreamParser({
      maxBufferedFrameSize: session.maxFieldSectionSize,
      isControlStream: false,
    });
    this._pendingH3Events = [];
    this._qpackBlocked = false;
    this._quicStreamEnded = false;
    this._headersSent = false;
    this._trailersSent = false;
    this._finSent = false;
    this._gotAnyHeaders = false;
    this._gotFinalHeaders = false;
    this._expectedContentLength = null;
    this._wireBodyBytes = 0;
    this._timeoutTimer = null;
    this._createdAtPerf = performance.now();
    this.ttfbMs = 0;

    const prio =
      options.priority ||
      (options.urgency !== undefined || options.incremental !== undefined
        ? { urgency: options.urgency ?? 3, incremental: Boolean(options.incremental) }
        : parsePriorityHeader(headers.priority));
    if (prio) {
      this.setPriority(prio);
    }

    const method = (headers[':method'] || 'GET').toUpperCase();
    const isSafeMethod = method === 'GET' || method === 'HEAD' || method === 'OPTIONS';
    this._allow0Rtt = options.allow0Rtt !== undefined ? Boolean(options.allow0Rtt) : isSafeMethod;

    if (options.body !== undefined && options.body !== null) {
      const bodyBuf = Buffer.isBuffer(options.body) ? options.body : Buffer.from(options.body);
      this._sendHeadersWithBody(bodyBuf);
      this.end();
    } else if (options.endStream) {
      this._sendHeaders(true);
      this.end();
    } else {
      this._sendHeaders(false);
    }
  }

  /**
   * Configures RFC 9218 stream priority (`{ urgency: 0..7, incremental: boolean }`).
   */
  setPriority(priority) {
    this.session.quic.setStreamPriority(this.id, priority);
    return this;
  }

  /**
   * Enables or disables `noDelay` on the underlying QUIC connection.
   */
  setNoDelay(noDelay = true) {
    this.session.quic.setNoDelay(noDelay);
    return this;
  }

  /**
   * Sends trailing HTTP/3 HEADERS frame and closes the outbound request stream (`FIN`).
   */
  sendTrailers(trailers) {
    if (this._h3Closed || this.aborted || this._finSent || this._trailersSent) {
      throw new Error('Cannot send trailers after HTTP/3 stream has ended');
    }
    this._sendHeaders(false);
    this._trailersSent = true;
    this._finSent = true;
    const encoded = this.session.qpackEncoder
      ? this.session.qpackEncoder.encode(this.id, trailers)
      : encodeHeaders(trailers);
    this.session._flushQpackStreams();
    const frame = buildHeadersFrame(encoded);
    this.session.quic.sendStreamData(this.id, frame, true, false);
    return this;
  }

  _sendHeadersWithBody(bodyBuf) {
    if (this._headersSent) return;
    this._headersSent = true;
    this._finSent = true;
    const encoded =
      this.session.qpackEncoder && (!this._allow0Rtt || this.session.connected)
        ? this.session.qpackEncoder.encode(this.id, this.sentHeaders)
        : encodeHeaders(this.sentHeaders);
    this.session._flushQpackStreams();
    const hFrame = buildHeadersFrame(encoded);
    const payload =
      bodyBuf.length > 0 ? Buffer.concat([hFrame, buildDataFrame(bodyBuf)]) : hFrame;
    this.session.quic.sendStreamData(this.id, payload, true, this._allow0Rtt);
  }

  _sendHeaders(fin = false) {
    if (this._headersSent) return;
    this._headersSent = true;
    // During 0-RTT (before server SETTINGS arrive), qpackEncoder.active is false -> static/literal 0-RTT safe
    const encoded =
      this.session.qpackEncoder && !this._allow0Rtt
        ? this.session.qpackEncoder.encode(this.id, this.sentHeaders)
        : this.session.qpackEncoder && this.session.connected
        ? this.session.qpackEncoder.encode(this.id, this.sentHeaders)
        : encodeHeaders(this.sentHeaders);
    this.session._flushQpackStreams();
    const frame = buildHeadersFrame(encoded);
    this._finSent = fin;
    this.session.quic.sendStreamData(this.id, frame, fin, this._allow0Rtt);
  }

  _read() {
    // Driven by incoming QUIC STREAM frames via _onStreamBytes()
  }

  _write(chunk, encoding, callback) {
    if (this._h3Closed || this.aborted) {
      return callback(new Error('HTTP/3 stream is closed'));
    }
    try {
      this._sendHeaders(false);
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, encoding);
      if (buf.length > 0) {
        const dataFrame = buildDataFrame(buf);
        this.session.quic.sendStreamData(this.id, dataFrame, false, this._allow0Rtt);
      }
      callback();
    } catch (err) {
      callback(err);
    }
  }

  _final(callback) {
    try {
      if (!this._headersSent) {
        this._sendHeaders(true);
      } else if (!this._finSent) {
        this._finSent = true;
        this.session.quic.sendStreamData(this.id, Buffer.alloc(0), true, this._allow0Rtt);
      }
      callback();
    } catch (err) {
      callback(err);
    }
  }

  _onStreamBytes(chunk, ended) {
    if (this._h3Closed) return;
    try {
      if (chunk.length > 0) {
        const events = this._h3Parser.push(chunk);
        for (const ev of events) {
          this._pendingH3Events.push(ev);
        }
      }
      if (ended) {
        this._quicStreamEnded = true;
      }
      this._drainPendingH3Events();
    } catch (err) {
      this._handleStreamProtocolError(err);
    }
  }

  _resumeBlockedQpack() {
    if (this._h3Closed || !this._qpackBlocked) return;
    if (!this.session.qpackDecoder.isUnblocked(this.id)) return;
    this._qpackBlocked = false;
    try {
      this._drainPendingH3Events();
    } catch (err) {
      this._handleStreamProtocolError(err);
    }
  }

  _drainPendingH3Events() {
    while (this._pendingH3Events.length > 0 && !this._h3Closed) {
      const ev = this._pendingH3Events[0];

      if (ev.type === 'headers') {
        if (this.trailers !== null) {
          throw makeH3Error('Unexpected HEADERS frame after trailing HEADERS', 0x0105);
        }

        const kind = this.session.strictHeaders
          ? this._gotFinalHeaders
            ? 'trailers'
            : 'response'
          : null;

        let decoded;
        if (this.session.qpackDecoder) {
          decoded = this.session.qpackDecoder.decodeFieldSection(this.id, ev.payload, kind);
          if (decoded.blocked) {
            this._qpackBlocked = true;
            return; // Wait for QPACK encoder stream to deliver missing dynamic entries
          }
          this.session._flushQpackStreams();
        } else {
          decoded = decodeHeaders(ev.payload, { kind });
        }

        this._pendingH3Events.shift();
        this._gotAnyHeaders = true;

        const { headers, rawHeaders } = decoded;
        const statusStr = headers[':status'];
        const statusNum = statusStr !== undefined ? Number(statusStr) : null;

        if (!this._gotFinalHeaders) {
          if (
            this.session.strictHeaders &&
            (statusStr === undefined || !/^[1-5]\d\d$/.test(String(statusStr)))
          ) {
            throw makeH3Error(`Invalid HTTP/3 :status pseudo-header: ${statusStr}`, 0x010e);
          }

          if (statusNum !== null && statusNum >= 100 && statusNum < 200 && statusNum !== 101) {
            this.informationalHeaders.push(headers);
            this.emit('headers', headers, 0, rawHeaders);
          } else {
            this._gotFinalHeaders = true;
            this.ttfbMs = +(performance.now() - this._createdAtPerf).toFixed(2);
            this.statusCode = statusNum;
            this.responseHeaders = headers;
            this.rawResponseHeaders = rawHeaders;

            if (headers['content-length'] !== undefined) {
              const clStr = String(headers['content-length']).trim();
              if (!/^\d+$/.test(clStr)) {
                if (this.session.strictHeaders) {
                  throw makeH3Error(`Malformed Content-Length header: ${clStr}`, 0x010e);
                }
              } else {
                this._expectedContentLength = Number(clStr);
              }
            }

            this.emit('response', headers, 0, rawHeaders);
          }
        } else {
          // Trailing HEADERS frame
          this.trailers = headers;
          this.emit('trailers', headers, 0, rawHeaders);
        }
      } else if (ev.type === 'data') {
        this._pendingH3Events.shift();
        if (!this._gotFinalHeaders || this.trailers !== null) {
          throw makeH3Error('Unexpected HTTP/3 DATA frame outside response body section', 0x0105);
        }
        this._wireBodyBytes += ev.data.length;
        if (
          this.session.strictHeaders &&
          this._expectedContentLength !== null &&
          this.sentHeaders[':method'] !== 'HEAD' &&
          this.statusCode !== 204 &&
          this.statusCode !== 304 &&
          this._wireBodyBytes > this._expectedContentLength
        ) {
          throw makeH3Error(
            `HTTP/3 response DATA (${this._wireBodyBytes}B) exceeded Content-Length (${this._expectedContentLength}B)`,
            0x010e
          );
        }
        this.push(ev.data);
      } else {
        this._pendingH3Events.shift();
      }
    }

    if (this._quicStreamEnded && !this._qpackBlocked && !this._h3Closed) {
      if (this._h3Parser.hasPartialFrame) {
        throw makeH3Error('Truncated HTTP/3 frame at end of stream', 0x0106);
      }
      if (
        this.session.strictHeaders &&
        this._expectedContentLength !== null &&
        this.sentHeaders[':method'] !== 'HEAD' &&
        this.statusCode !== 204 &&
        this.statusCode !== 304 &&
        this._wireBodyBytes !== this._expectedContentLength
      ) {
        throw makeH3Error(
          `HTTP/3 response truncated: received ${this._wireBodyBytes} of ${this._expectedContentLength} Content-Length bytes`,
          0x010e
        );
      }
      this._clearTimeout();
      this._h3Closed = true;
      this.push(null);
      this.session._streams.delete(this.id);
    }
  }

  _handleStreamProtocolError(err) {
    // QPACK decompression error (0x0200) or H3 frame error (0x0106 / 0x0107 / 0x0105) is a connection error per RFC 9114/9204
    const code = err instanceof QpackError ? err.h3Code : err.h3Code;
    if (code === 0x0200 || code === 0x0105 || code === 0x0106 || code === 0x0107) {
      this.session._closeWithH3Error(code, err.message);
    } else if (code) {
      try {
        this.session.quic.resetStream(this.id, code);
      } catch {
        // Ignore
      }
    }
    this.destroy(err);
  }

  _onPeerReset(errorCode) {
    if (this._h3Closed) return;
    this._clearTimeout();
    this.rstCode = Number(errorCode);
    this._h3Closed = true;
    this.aborted = true;
    this._cancelQpackState();
    this.session._streams.delete(this.id);
    this.destroy(new Error(`HTTP/3 stream ${this.id} reset by peer (code=0x${this.rstCode.toString(16)})`));
  }

  _cancelQpackState() {
    if (this.session.qpackDecoder) {
      this.session.qpackDecoder.cancelStream(this.id);
      this.session._flushQpackStreams();
    }
  }

  setTimeout(ms, callback) {
    this._clearTimeout();
    if (typeof callback === 'function') {
      this.once('timeout', callback);
    }
    if (ms > 0) {
      this._timeoutTimer = setTimeout(() => {
        this._timeoutTimer = null;
        this.emit('timeout');
      }, ms);
      this._timeoutTimer.unref?.();
    }
    return this;
  }

  _clearTimeout() {
    if (this._timeoutTimer) {
      clearTimeout(this._timeoutTimer);
      this._timeoutTimer = null;
    }
  }

  close(errorCode = 0x010c, callback) {
    if (typeof errorCode === 'function') {
      callback = errorCode;
      errorCode = 0x010c; // H3_REQUEST_CANCELLED
    }
    this._clearTimeout();
    if (!this._h3Closed) {
      this._h3Closed = true;
      this.aborted = true;
      this._cancelQpackState();
      this.session._streams.delete(this.id);
      try {
        this.session.quic.resetStream(this.id, errorCode);
      } catch {
        // Ignore if session already closed
      }
      this.emit('aborted');
      this.destroy();
    }
    if (typeof callback === 'function') {
      process.nextTick(callback);
    }
  }

  _destroy(err, callback) {
    this._clearTimeout();
    if (!this._h3Closed) {
      this._h3Closed = true;
      this._cancelQpackState();
      this.session._streams.delete(this.id);
      if (err) {
        try {
          this.session.quic.resetStream(this.id, err.h3Code || 0x010c);
        } catch {
          // Ignore
        }
      }
    }
    callback(err);
  }
}

/**
 * Parses authority string or URL into `{ protocol, hostname, port, origin, authorityHeader }`.
 */
function parseAuthority(authority, options = {}) {
  let urlObj;
  if (authority instanceof URL) {
    urlObj = authority;
  } else if (typeof authority === 'string') {
    const str = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(authority) ? authority : `https://${authority}`;
    urlObj = new URL(str);
  } else {
    const host = options.host || options.hostname || 'localhost';
    const port = options.port || 443;
    urlObj = new URL(`https://${host}:${port}`);
  }

  const hostname = urlObj.hostname.replace(/^\[|\]$/g, '');
  const port = options.port || (urlObj.port ? Number(urlObj.port) : 443);
  const authorityHeader = port === 443 ? urlObj.hostname : `${urlObj.hostname}:${port}`;

  return {
    protocol: urlObj.protocol || 'https:',
    hostname,
    port,
    origin: `https://${authorityHeader}`,
    authorityHeader,
  };
}

/**
 * Node.js `http2` ClientHttp2Session-compatible HTTP/3 Client Session (RFC 9114 + RFC 9204 Dynamic QPACK).
 */
class Http3ClientSession extends EventEmitter {
  constructor(authority, options = {}) {
    super();
    const parsed = parseAuthority(authority, options);
    this.origin = parsed.origin;
    this.authorityHeader = parsed.authorityHeader;
    this.hostname = options.host || parsed.hostname;
    this.port = parsed.port;
    this.servername = options.servername ?? parsed.hostname;

    this.connected = false;
    this.closed = false;
    this.destroyed = false;
    this.goawayReceived = false;
    this.goawayStreamId = null;
    this.remoteSettings = null;
    this.alpnProtocol = null;
    this.cipher = null;
    this.strictHeaders = options.strictHeaders !== false;

    this.qpackMaxTableCapacity = options.qpackMaxTableCapacity ?? 16384;
    this.qpackBlockedStreams = options.qpackBlockedStreams ?? 100;
    this.maxFieldSectionSize = options.maxFieldSectionSize ?? 16777216;

    this.qpackDecoder = new QpackDecoder({
      maxTableCapacity: this.qpackMaxTableCapacity,
      maxBlockedStreams: this.qpackBlockedStreams,
      maxFieldSectionSize: this.maxFieldSectionSize,
    });
    this.qpackEncoder = new QpackEncoder({
      enabled: options.enableDynamicQpack !== false,
      maxCapacity: options.qpackEncoderMaxCapacity ?? 4096,
      huffman: options.huffman !== false,
      validate: this.strictHeaders,
    });

    this._streams = new Map(); // streamId -> Http3ClientStream
    this._uniStreams = new Map(); // streamId -> { type: number|bigint|null, buf: Buffer, parser: H3StreamParser|null }
    this._seenServerCriticalStreams = new Set(); // 'control' | 'qpack_enc' | 'qpack_dec'
    this._controlStreamId = null;
    this._qpackEncStreamId = null;
    this._qpackDecStreamId = null;

    this.quic = new QuicConnection({
      ...options,
      host: this.hostname,
      port: this.port,
      servername: this.servername,
      alpnProtocols: options.alpnProtocols || ['h3'],
      rejectUnauthorized: options.rejectUnauthorized !== false,
      ca: options.ca || null,
      connectTimeout: options.connectTimeout ?? options.timeout ?? 10000,
      idleTimeout: options.idleTimeout ?? 60000,
      keepAliveInterval:
        options.keepAliveInterval ?? (options.keepAlive === true ? 15000 : 0),
    });

    this._setupQuicListeners();
    this._initHttp3UnidirectionalStreams();
    this.quic.connect();
  }

  get stats() {
    return this.quic.stats;
  }

  get socket() {
    return this.quic.socket;
  }

  get availableStreams() {
    return this.quic.availableBidiStreams;
  }

  get qpackStats() {
    return {
      decoder: {
        ...this.qpackDecoder.stats,
        dynamicCapacity: this.qpackDecoder.table.capacity,
        dynamicSize: this.qpackDecoder.table.size,
        insertCount: this.qpackDecoder.table.insertCount,
        blockedStreams: this.qpackDecoder.blocked.size,
      },
      encoder: {
        ...this.qpackEncoder.stats,
        active: this.qpackEncoder.active,
        dynamicCapacity: this.qpackEncoder.table.capacity,
        dynamicSize: this.qpackEncoder.table.size,
        insertCount: this.qpackEncoder.table.insertCount,
        knownReceivedCount: this.qpackEncoder.knownReceivedCount,
      },
    };
  }

  setNoDelay(noDelay = true) {
    this.quic.setNoDelay(noDelay);
    return this;
  }

  setAckDelay(delayMs = 10, threshold = 0) {
    this.quic.setAckDelay(delayMs, threshold);
    return this;
  }

  cork() {
    this.quic.cork();
    return this;
  }

  uncork() {
    this.quic.uncork();
    return this;
  }

  setKeepAlive(enable = true, intervalMs = 15000) {
    this.quic.setKeepAlive(enable, intervalMs);
    return this;
  }

  setIdleTimeout(timeoutMs) {
    this.quic.setIdleTimeout(timeoutMs);
    return this;
  }

  setSocketOptions(opts = {}) {
    this.quic.setSocketOptions(opts);
    return this;
  }

  setTTL(ttl) {
    this.quic.setTTL(ttl);
    return this;
  }

  setBroadcast(flag = true) {
    this.quic.setBroadcast(flag);
    return this;
  }

  setRecvBufferSize(bytes) {
    this.quic.setRecvBufferSize(bytes);
    return this;
  }

  setSendBufferSize(bytes) {
    this.quic.setSendBufferSize(bytes);
    return this;
  }

  ref() {
    this.quic.ref();
    return this;
  }

  unref() {
    this.quic.unref();
    return this;
  }

  getSocketState() {
    return this.quic.getSocketState();
  }

  getDiagnostics() {
    return {
      ...this.quic.getDiagnostics(),
      h3: {
        origin: this.origin,
        activeStreams: this._streams.size,
        availableBidiStreams: this.quic.availableBidiStreams,
        goawayReceived: this.goawayReceived,
        remoteSettings: this.remoteSettings,
        qpack: this.qpackStats,
      },
    };
  }

  setStreamPriority(streamId, priority) {
    this.quic.setStreamPriority(streamId, priority);
    return this;
  }

  migrate(newSocketOpts = {}) {
    return this.quic.migrate(newSocketOpts);
  }

  validatePath(timeoutMs = 3000) {
    return this.quic.validatePath(timeoutMs);
  }

  initiateKeyUpdate() {
    return this.quic.initiateKeyUpdate();
  }

  probeMtu(targetSize = 1452, timeoutMs = 1500) {
    return this.quic.probeMtu(targetSize, timeoutMs);
  }

  sendDatagram(data) {
    return this.quic.sendDatagram(data);
  }

  _initHttp3UnidirectionalStreams() {
    // 1. Client Control Stream (type 0x00) + initial SETTINGS frame (RFC 9114 §6.2.1)
    const ctrlStream = this.quic.openUniStream();
    this._controlStreamId = ctrlStream.id;
    const ctrlInit = Buffer.concat([
      encodeVarint(H3_STREAM_CONTROL),
      buildSettingsFrame({
        qpackMaxTableCapacity: this.qpackMaxTableCapacity,
        maxFieldSectionSize: this.maxFieldSectionSize,
        qpackBlockedStreams: this.qpackBlockedStreams,
        h3Datagram: this.quic.enableDatagrams,
      }),
    ]);
    this.quic.sendStreamData(ctrlStream.id, ctrlInit, false);

    // 2. Client QPACK Encoder (0x02) & Decoder (0x03) unidirectional streams
    const encStream = this.quic.openUniStream();
    this._qpackEncStreamId = encStream.id;
    this.quic.sendStreamData(encStream.id, encodeVarint(H3_STREAM_QPACK_ENCODER), false);

    const decStream = this.quic.openUniStream();
    this._qpackDecStreamId = decStream.id;
    this.quic.sendStreamData(decStream.id, encodeVarint(H3_STREAM_QPACK_DECODER), false);
  }

  _flushQpackStreams() {
    if (this.closed || this.destroyed) return;
    if (this._qpackEncStreamId !== null) {
      const encData = this.qpackEncoder.takeEncoderStreamData();
      if (encData && encData.length > 0) {
        this.quic.sendStreamData(this._qpackEncStreamId, encData, false, false);
      }
    }
    if (this._qpackDecStreamId !== null) {
      const decData = this.qpackDecoder.takeDecoderStreamData();
      if (decData && decData.length > 0) {
        this.quic.sendStreamData(this._qpackDecStreamId, decData, false, false);
      }
    }
  }

  _closeWithH3Error(h3Code, reason = '') {
    if (this.closed || this.destroyed) return;
    this.closed = true;
    const err = makeH3Error(reason || `HTTP/3 error 0x${h3Code.toString(16)}`, h3Code);
    for (const req of this._streams.values()) {
      req.destroy(err);
    }
    this._streams.clear();
    if (this.listenerCount('error') > 0) {
      this.emit('error', err);
    }
    this.quic.close(h3Code, String(reason).slice(0, 128));
  }

  _setupQuicListeners() {
    this.quic.on('connect', (info) => {
      this.connected = true;
      this.alpnProtocol = info.alpn;
      this.cipher = info.cipher;
      this.emit('connect', this, info);
    });

    this.quic.on('streamData', (streamId, chunk, ended) => {
      const isServerInitiated = (streamId & 0x01) === 1;
      const isUni = (streamId & 0x02) !== 0;

      if (isUni && isServerInitiated) {
        this._handleServerUniStream(streamId, chunk, ended);
        return;
      }

      const reqStream = this._streams.get(streamId);
      if (reqStream) {
        reqStream._onStreamBytes(chunk, ended);
      }
    });

    this.quic.on('streamReset', (streamId, errorCode) => {
      const reqStream = this._streams.get(streamId);
      if (reqStream) {
        reqStream._onPeerReset(errorCode);
      }
    });

    this.quic.on('error', (err) => {
      for (const req of this._streams.values()) {
        req.destroy(err);
      }
      this._streams.clear();
      if (this.listenerCount('error') > 0) {
        this.emit('error', err);
      }
    });

    this.quic.on('close', (info) => {
      this.connected = false;
      this.closed = true;
      for (const req of this._streams.values()) {
        if (!req._h3Closed) {
          req.destroy(new Error(`HTTP/3 connection closed (${info.reason || 'closed'})`));
        }
      }
      this._streams.clear();
      this.emit('close', info);
    });

    for (const evName of [
      'keylog',
      'datagram',
      'migration',
      'pathValidated',
      'keyUpdate',
      'mtuChange',
      'statelessReset',
      'sessionTicket',
      'streamLimit',
    ]) {
      this.quic.on(evName, (payload) => {
        if (this.listenerCount(evName) > 0) {
          this.emit(evName, payload);
        }
      });
    }
  }

  _handleServerUniStream(streamId, chunk, ended) {
    let uni = this._uniStreams.get(streamId);
    if (!uni) {
      uni = { type: null, buf: Buffer.alloc(0), parser: null };
      this._uniStreams.set(streamId, uni);
    }

    try {
      let payload = chunk;
      if (uni.type === null) {
        uni.buf = uni.buf.length === 0 ? chunk : Buffer.concat([uni.buf, chunk]);
        const typeDec = decodeVarint(uni.buf, 0);
        if (!typeDec) {
          if (ended) this._uniStreams.delete(streamId);
          return;
        }
        uni.type = typeDec.value;
        payload = uni.buf.subarray(typeDec.bytesRead);
        uni.buf = Buffer.alloc(0);

        if (uni.type === H3_STREAM_CONTROL) {
          if (this._seenServerCriticalStreams.has('control')) {
            return this._closeWithH3Error(0x0103, 'Duplicate server HTTP/3 control stream');
          }
          this._seenServerCriticalStreams.add('control');
          uni.parser = new H3StreamParser({
            maxBufferedFrameSize: 65536,
            isControlStream: true,
          });
        } else if (uni.type === H3_STREAM_QPACK_ENCODER) {
          if (this._seenServerCriticalStreams.has('qpack_enc')) {
            return this._closeWithH3Error(0x0103, 'Duplicate server QPACK encoder stream');
          }
          this._seenServerCriticalStreams.add('qpack_enc');
        } else if (uni.type === H3_STREAM_QPACK_DECODER) {
          if (this._seenServerCriticalStreams.has('qpack_dec')) {
            return this._closeWithH3Error(0x0103, 'Duplicate server QPACK decoder stream');
          }
          this._seenServerCriticalStreams.add('qpack_dec');
        } else if (uni.type === H3_STREAM_PUSH) {
          // Client never sent MAX_PUSH_ID -> server push stream is H3_ID_ERROR (0x0108)
          return this._closeWithH3Error(0x0108, 'Server opened push stream without MAX_PUSH_ID');
        }
      }

      if (payload.length > 0) {
        if (uni.type === H3_STREAM_CONTROL && uni.parser) {
          this._processControlEvents(uni.parser.push(payload));
        } else if (uni.type === H3_STREAM_QPACK_ENCODER) {
          const prevInsertCount = this.qpackDecoder.table.insertCount;
          this.qpackDecoder.feedEncoderStream(payload);
          this._flushQpackStreams();
          if (this.qpackDecoder.table.insertCount > prevInsertCount && this.qpackDecoder.blocked.size > 0) {
            for (const blockedStreamId of Array.from(this.qpackDecoder.blocked.keys())) {
              const reqStream = this._streams.get(blockedStreamId);
              if (reqStream) {
                reqStream._resumeBlockedQpack();
              }
            }
          }
        } else if (uni.type === H3_STREAM_QPACK_DECODER) {
          this.qpackEncoder.feedDecoderStream(payload);
        }
        // Unknown / GREASE unidirectional streams (0x1f*N+0x21) are drained & ignored per RFC 9114 §6.2.3
      }

      if (ended) {
        this._uniStreams.delete(streamId);
        if (
          !this.closed &&
          (uni.type === H3_STREAM_CONTROL ||
            uni.type === H3_STREAM_QPACK_ENCODER ||
            uni.type === H3_STREAM_QPACK_DECODER)
        ) {
          // RFC 9114 §6.2.1 / RFC 9204 §4.2: closing a critical stream is H3_CLOSED_CRITICAL_STREAM
          this._closeWithH3Error(0x0104, 'Server closed critical HTTP/3 unidirectional stream');
        }
      }
    } catch (err) {
      const code = err instanceof QpackError ? err.h3Code : err.h3Code || 0x0101;
      this._closeWithH3Error(code, err.message);
    }
  }

  _processControlEvents(events) {
    for (const ev of events) {
      if (ev.type === 'settings') {
        this.remoteSettings = ev.settings;
        const peerQpackCap = Number(ev.settings[String(SETTINGS_QPACK_MAX_TABLE_CAPACITY)] || 0);
        const peerQpackBlocked = Number(ev.settings[String(SETTINGS_QPACK_BLOCKED_STREAMS)] || 0);
        this.qpackEncoder.applyPeerSettings(peerQpackCap, peerQpackBlocked);
        this._flushQpackStreams();
        this.emit('remoteSettings', ev.settings);
      } else if (ev.type === 'goaway') {
        this.goawayReceived = true;
        this.goawayStreamId = ev.streamId;
        this.emit('goaway', ev.streamId);
      }
    }
  }

  /**
   * Resolves once the QUIC + TLS 1.3 handshake completes.
   */
  ready() {
    if (this.connected) return Promise.resolve(this);
    if (this.closed || this.destroyed) {
      return Promise.reject(new Error('HTTP/3 session is closed'));
    }
    return new Promise((resolve, reject) => {
      const onConnect = () => {
        cleanup();
        resolve(this);
      };
      const onError = (err) => {
        cleanup();
        reject(err);
      };
      const onClose = () => {
        cleanup();
        reject(new Error('HTTP/3 session closed before handshake completed'));
      };
      const cleanup = () => {
        this.removeListener('connect', onConnect);
        this.removeListener('error', onError);
        this.removeListener('close', onClose);
      };
      this.once('connect', onConnect);
      this.once('error', onError);
      this.once('close', onClose);
    });
  }

  /**
   * Opens a new HTTP/3 request stream (compatible with Node's `http2` `client.request(headers, options)`).
   */
  request(headers = {}, options = {}) {
    if (this.closed || this.destroyed) {
      throw new Error('Cannot create request on closed HTTP/3 session');
    }

    // Build normalized headers ensuring :method, :scheme, :authority, :path exist
    const h = Object.create(null);
    let method = 'GET';
    let scheme = 'https';
    let authority = this.authorityHeader;
    let reqPath = '/';

    for (const [k, v] of Object.entries(headers)) {
      if (v === undefined || v === null) continue;
      const lk = k.toLowerCase();
      if (lk === ':method' || lk === 'method') {
        method = String(v).toUpperCase();
      } else if (lk === ':scheme') {
        scheme = String(v);
      } else if (lk === ':authority' || lk === 'host') {
        authority = String(v);
      } else if (lk === ':path' || lk === 'path') {
        reqPath = String(v);
      } else if (lk.startsWith(':')) {
        throw makeH3Error(`Unsupported request pseudo-header "${lk}"`, 0x010e);
      } else {
        h[lk] = v;
      }
    }

    const finalHeaders = {
      ':method': method,
      ':scheme': scheme,
      ':authority': authority,
      ':path': reqPath,
      ...h,
    };

    const bidi = this.quic.openBidiStream();
    const reqStream = new Http3ClientStream(this, bidi.id, finalHeaders, options);
    this._streams.set(bidi.id, reqStream);
    return reqStream;
  }

  ping(timeoutMs = 5000) {
    return this.quic.ping(timeoutMs);
  }

  close(callback) {
    if (typeof callback === 'function') {
      this.once('close', () => callback());
    }
    if (!this.closed) {
      this.closed = true;
      if (this.connected && this._controlStreamId !== null) {
        try {
          this.quic.sendStreamData(this._controlStreamId, buildGoawayFrame(0), false);
        } catch {
          // Ignore
        }
      }
      this.quic.close(0x0100, '');
    }
  }

  destroy(err) {
    this.destroyed = true;
    this.closed = true;
    this.quic.destroy(err);
  }
}

/**
 * Connection Pool / Keep-Alive Agent that multiplexes concurrent HTTP/3 requests
 * to the same origin over a single persistent QUIC v1 connection.
 * Automatically opens an overflow session if an origin session received GOAWAY or exhausted its stream limit.
 */
class Http3Agent {
  constructor(options = {}) {
    this.options = options;
    this.sessions = new Map(); // poolKey -> Http3ClientSession
    this.idleSessionTimeoutMs = options.idleTimeout ?? 30000;
  }

  _poolKey(parsed, options = {}) {
    const sni = options.servername ?? parsed.hostname;
    const hostOverride = options.host || parsed.hostname;
    const reject = options.rejectUnauthorized !== false ? '1' : '0';
    const localAddr = options.localAddress || options.socketOptions?.localAddress || '';
    const localPort = options.localPort || options.socketOptions?.localPort || '';
    return `${hostOverride}:${parsed.port}:${sni}:${reject}:${localAddr}:${localPort}`;
  }

  getSession(urlOrAuthority, options = {}) {
    const parsed = parseAuthority(urlOrAuthority, options);
    const key = this._poolKey(parsed, options);
    const existing = this.sessions.get(key);
    if (
      existing &&
      !existing.closed &&
      !existing.destroyed &&
      !existing.goawayReceived &&
      existing.availableStreams > 0
    ) {
      return existing;
    }

    const session = new Http3ClientSession(parsed.origin, {
      ...this.options,
      ...options,
      idleTimeout: options.idleTimeout ?? this.idleSessionTimeoutMs,
    });
    // Prevent unhandled error crashes on pooled background sessions
    session.on('error', () => {});
    session.once('close', () => {
      if (this.sessions.get(key) === session) {
        this.sessions.delete(key);
      }
    });
    this.sessions.set(key, session);
    return session;
  }

  async warmup(urlOrAuthority, options = {}) {
    const session = this.getSession(urlOrAuthority, options);
    await session.ready();
    return session;
  }

  closeAll() {
    for (const session of this.sessions.values()) {
      session.close();
    }
    this.sessions.clear();
  }

  destroy() {
    for (const session of this.sessions.values()) {
      session.destroy();
    }
    this.sessions.clear();
  }
}

/**
 * Fetch-compatible HTTP/3 Response wrapper.
 */
class Http3Response {
  constructor({
    status,
    headers,
    rawHeaders,
    trailers,
    informationalHeaders,
    body,
    url,
    session,
    timings,
  }) {
    this.status = status;
    this.statusCode = status;
    this.ok = status >= 200 && status < 300;
    this.httpVersion = '3.0';
    this.alpnProtocol = session?.alpnProtocol || 'h3';
    this.cipher = session?.cipher || null;
    this.remoteAddress = session?.quic?.remoteAddress || null;
    this.rtt = session?.quic ? Math.round(session.quic.smoothedRtt) : null;
    this.timings = timings || null;
    this.url = url;
    this.headers = headers;
    this.rawHeaders = rawHeaders;
    this.trailers = trailers || null;
    this.informationalHeaders = informationalHeaders || [];
    this._body = body;
  }

  get body() {
    return this._body;
  }

  header(name) {
    return this.headers[String(name).toLowerCase()];
  }

  async buffer() {
    return this._body;
  }

  async bytes() {
    return new Uint8Array(this._body.buffer, this._body.byteOffset, this._body.byteLength);
  }

  async arrayBuffer() {
    return this._body.buffer.slice(
      this._body.byteOffset,
      this._body.byteOffset + this._body.byteLength
    );
  }

  async text(encoding = 'utf8') {
    return this._body.toString(encoding);
  }

  async json() {
    return JSON.parse(this._body.toString('utf8'));
  }
}

const defaultAgent = new Http3Agent({ idleTimeout: 15000 });

/**
 * Connects to an HTTP/3 origin and returns an `Http3ClientSession` (`http2.connect`-compatible).
 */
function connect(authority, options, listener) {
  if (typeof options === 'function') {
    listener = options;
    options = {};
  }
  const session = new Http3ClientSession(authority, options || {});
  if (typeof listener === 'function') {
    session.once('connect', listener);
  }
  return session;
}

/**
 * High-level `fetch()` over HTTP/3 (QUIC v1).
 */
async function h3Fetch(input, init = {}, _redirectCount = 0) {
  const urlObj = input instanceof URL ? input : new URL(String(input));
  if (urlObj.protocol !== 'https:') {
    throw new Error(`HTTP/3 requires https:// URL, got ${urlObj.protocol}`);
  }

  const method = (init.method || 'GET').toUpperCase();
  const decompress = init.decompress !== false;
  const timeoutMs = init.timeout ?? 15000;
  const maxRedirects = init.maxRedirects ?? 10;
  const redirectMode = init.redirect || 'follow';

  // Normalize user headers
  const userHeaders = Object.create(null);
  if (init.headers) {
    const entries =
      typeof init.headers.entries === 'function'
        ? Array.from(init.headers.entries())
        : Object.entries(init.headers);
    for (const [k, v] of entries) {
      if (v !== undefined && v !== null) {
        userHeaders[k.toLowerCase()] = v;
      }
    }
  }

  if (!userHeaders['user-agent']) {
    userHeaders['user-agent'] = 'node-http3/3.1';
  }
  if (decompress && !userHeaders['accept-encoding']) {
    userHeaders['accept-encoding'] = zstdDecompressAsync
      ? 'gzip, deflate, br, zstd'
      : 'gzip, deflate, br';
  }

  // Prepare request body (supports Buffer, TypedArray, ArrayBuffer, URLSearchParams, AsyncIterable/Readable, JSON object, string)
  const bodyBuf = await normalizeRequestBody(init.body, userHeaders);
  if (bodyBuf !== null && userHeaders['content-length'] === undefined) {
    userHeaders['content-length'] = String(bodyBuf.length);
  }

  const fetchStartPerf = performance.now();
  const usePool = init.agent !== false;
  const agent = init.agent instanceof Http3Agent ? init.agent : usePool ? defaultAgent : null;
  const session = agent
    ? agent.getSession(urlObj, init)
    : new Http3ClientSession(urlObj, init);
  const ownsSession = !agent;

  try {
    const response = await new Promise((resolve, reject) => {
      let settled = false;
      let req = null;
      const finishErr = (err) => {
        if (settled) return;
        settled = true;
        reject(err);
      };

      const onSessionError = (err) => finishErr(err);
      session.once('error', onSessionError);

      let abortHandler = null;
      if (init.signal) {
        if (init.signal.aborted) {
          session.removeListener('error', onSessionError);
          return finishErr(init.signal.reason || new Error('HTTP/3 request aborted'));
        }
        abortHandler = () => {
          if (req) req.close();
          finishErr(init.signal.reason || new Error('HTTP/3 request aborted'));
        };
        init.signal.addEventListener('abort', abortHandler, { once: true });
      }

      const reqHeaders = {
        ':method': method,
        ':scheme': 'https',
        ':authority': userHeaders['host'] || session.authorityHeader,
        ':path': (urlObj.pathname || '/') + (urlObj.search || ''),
        ...userHeaders,
      };
      delete reqHeaders['host'];

      const hasBody = bodyBuf !== null && bodyBuf.length > 0;
      const allow0Rtt =
        init.enable0Rtt === false
          ? false
          : init.enable0Rtt === true
          ? true
          : undefined;
      try {
        req = session.request(reqHeaders, {
          endStream: !hasBody,
          allow0Rtt,
          priority: init.priority,
        });
      } catch (err) {
        session.removeListener('error', onSessionError);
        if (init.signal && abortHandler) {
          init.signal.removeEventListener('abort', abortHandler);
        }
        return finishErr(err);
      }

      if (timeoutMs > 0) {
        req.setTimeout(timeoutMs, () => {
          req.close();
          finishErr(new Error(`HTTP/3 request timed out after ${timeoutMs}ms (${urlObj.href})`));
        });
      }

      const chunks = [];
      let respHeaders = null;
      let rawRespHeaders = null;

      req.on('response', (headers, _flags, rawHeaders) => {
        respHeaders = headers;
        rawRespHeaders = rawHeaders;
      });

      req.on('data', (chunk) => {
        chunks.push(chunk);
      });

      req.on('error', (err) => {
        cleanup();
        finishErr(err);
      });

      req.on('end', async () => {
        cleanup();
        if (settled) return;
        settled = true;
        try {
          const totalMs = +(performance.now() - fetchStartPerf).toFixed(2);
          const rawBody = chunks.length > 0 ? Buffer.concat(chunks) : Buffer.alloc(0);
          const hdrs = respHeaders || Object.create(null);
          const finalBody =
            decompress && method !== 'HEAD'
              ? await decompressBody(rawBody, hdrs['content-encoding'])
              : rawBody;

          const status = Number(hdrs[':status'] || 0);
          const cleanHeaders = Object.create(null);
          for (const [k, v] of Object.entries(hdrs)) {
            if (!k.startsWith(':')) cleanHeaders[k] = v;
          }

          const st = session.stats;
          resolve(
            new Http3Response({
              status,
              headers: cleanHeaders,
              rawHeaders: rawRespHeaders || [],
              trailers: req.trailers,
              informationalHeaders: req.informationalHeaders,
              body: finalBody,
              url: urlObj.href,
              session,
              timings: {
                dnsMs: st.dnsMs,
                handshakeMs: st.handshakeMs,
                ttfbMs: req.ttfbMs,
                totalMs,
                resumed: st.resumed,
                earlyDataSent: st.earlyDataSent,
                earlyDataAccepted: st.earlyDataAccepted,
                pooled: !ownsSession && st.packetsSent > 4,
              },
            })
          );
        } catch (err) {
          reject(err);
        }
      });

      const cleanup = () => {
        session.removeListener('error', onSessionError);
        if (init.signal && abortHandler) {
          init.signal.removeEventListener('abort', abortHandler);
        }
      };

      if (hasBody) {
        req.end(bodyBuf);
      }
    });

    // Handle HTTP 301/302/303/307/308 redirects if requested
    if (
      [301, 302, 303, 307, 308].includes(response.status) &&
      response.headers.location &&
      redirectMode !== 'manual'
    ) {
      if (redirectMode === 'error') {
        throw new Error(`Unexpected redirect (${response.status}) to ${response.headers.location}`);
      }
      if (_redirectCount >= maxRedirects) {
        throw new Error(`Maximum redirects (${maxRedirects}) exceeded`);
      }
      const nextUrl = new URL(response.headers.location, urlObj);
      const isCrossOrigin = nextUrl.origin !== urlObj.origin;
      const switchToGet =
        response.status === 303 ||
        ((response.status === 301 || response.status === 302) && method === 'POST');

      let nextHeaders = init.headers;
      if (isCrossOrigin && init.headers) {
        // Strip sensitive credentials when redirected across origins (RFC 9110 §15.4)
        const filtered = Object.create(null);
        const entries =
          typeof init.headers.entries === 'function'
            ? Array.from(init.headers.entries())
            : Object.entries(init.headers);
        for (const [k, v] of entries) {
          const lk = k.toLowerCase();
          if (lk !== 'authorization' && lk !== 'cookie' && lk !== 'proxy-authorization' && lk !== 'host') {
            filtered[k] = v;
          }
        }
        nextHeaders = filtered;
      }

      const nextInit = {
        ...init,
        headers: nextHeaders,
        method: switchToGet ? 'GET' : method,
        body: switchToGet ? undefined : bodyBuf,
      };
      return h3Fetch(nextUrl, nextInit, _redirectCount + 1);
    }

    return response;
  } finally {
    if (ownsSession) {
      if (session.quic.tls.sessionTickets.length === 0 && !session.closed) {
        // Allow brief background window for trailing NewSessionTicket / NEW_TOKEN packet before closing
        const closeEarly = () => session.close();
        session.quic.once('sessionTicket', closeEarly);
        setTimeout(() => {
          session.quic.removeListener('sessionTicket', closeEarly);
          session.close();
        }, 25).unref?.();
      } else {
        session.close();
      }
    }
  }
}

/**
 * Supports both Promise style `await http3.request(url, options)` AND
 * classic Node `https.request(url, options, callback)` streaming style!
 */
function request(urlOrOptions, optionsOrCallback, maybeCallback) {
  let urlObj;
  let opts = {};
  let cb = null;

  if (typeof urlOrOptions === 'string' || urlOrOptions instanceof URL) {
    urlObj = urlOrOptions instanceof URL ? urlOrOptions : new URL(urlOrOptions);
    if (typeof optionsOrCallback === 'function') {
      cb = optionsOrCallback;
    } else {
      opts = optionsOrCallback || {};
      cb = maybeCallback || null;
    }
  } else {
    opts = urlOrOptions || {};
    cb = typeof optionsOrCallback === 'function' ? optionsOrCallback : null;
    const host = opts.hostname || opts.host || 'localhost';
    const port = opts.port ? `:${opts.port}` : '';
    const path = opts.path || '/';
    urlObj = new URL(`https://${host}${port}${path}`);
  }

  // Promise mode when no callback is provided
  if (!cb) {
    return h3Fetch(urlObj, opts);
  }

  // Classic Node `https.request(url, opts, (res) => ...)` streaming mode
  const usePool = opts.agent !== false;
  const agent = opts.agent instanceof Http3Agent ? opts.agent : usePool ? defaultAgent : null;
  const session = agent ? agent.getSession(urlObj, opts) : new Http3ClientSession(urlObj, opts);

  const reqHeaders = {
    ':method': (opts.method || 'GET').toUpperCase(),
    ':scheme': 'https',
    ':authority': session.authorityHeader,
    ':path': opts.path || (urlObj.pathname || '/') + (urlObj.search || ''),
    ...(opts.headers || {}),
  };

  const req = session.request(reqHeaders, {
    priority: opts.priority,
    allow0Rtt: opts.enable0Rtt,
  });
  if (!agent) {
    req.once('close', () => session.close());
  }

  req.once('response', (headers) => {
    req.statusCode = Number(headers[':status'] || 0);
    req.headers = headers;
    cb(req);
  });

  return req;
}

function clearCaches() {
  defaultDnsCache.clear();
  defaultSessionStore.clear();
}

module.exports = {
  Http3ClientSession,
  Http3ClientStream,
  Http3Agent,
  Http3Response,
  QuicCongestionController,
  SessionTicketStore,
  defaultSessionStore,
  defaultDnsCache,
  defaultAgent,
  connect,
  fetch: h3Fetch,
  request,
  clearCaches,
  decompressBody,
  parsePriorityHeader,
};
