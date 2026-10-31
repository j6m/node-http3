'use strict';

const crypto = require('node:crypto');
const tls = require('node:tls');
const net = require('node:net');
const { encodeVarint, decodeVarint } = require('./varint');
const {
  CIPHER_SUITES,
  hkdfExtract,
  hkdfExpandLabel,
  derivePacketProtectionKeys,
} = require('./crypto');

const X25519_SPKI_PREFIX = Buffer.from('302a300506032b656e032100', 'hex');
const HRR_RANDOM = Buffer.from(
  'cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c',
  'hex'
);

// TLS Handshake message types
const MSG_CLIENT_HELLO = 1;
const MSG_SERVER_HELLO = 2;
const MSG_NEW_SESSION_TICKET = 4;
const MSG_ENCRYPTED_EXTENSIONS = 8;
const MSG_CERTIFICATE = 11;
const MSG_CERTIFICATE_REQUEST = 13;
const MSG_CERTIFICATE_VERIFY = 15;
const MSG_FINISHED = 20;
const MSG_MESSAGE_HASH = 254;

// TLS Extensions
const EXT_SERVER_NAME = 0x0000;
const EXT_SUPPORTED_GROUPS = 0x000a;
const EXT_SIGNATURE_ALGORITHMS = 0x000d;
const EXT_ALPN = 0x0010;
const EXT_PRE_SHARED_KEY = 0x0029;
const EXT_EARLY_DATA = 0x002a;
const EXT_SUPPORTED_VERSIONS = 0x002b;
const EXT_COOKIE = 0x002c;
const EXT_PSK_KEY_EXCHANGE_MODES = 0x002d;
const EXT_KEY_SHARE = 0x0033;
const EXT_QUIC_TRANSPORT_PARAMS = 0x0039;

/**
 * In-memory TLS 1.3 Session Ticket + QUIC NEW_TOKEN + Remembered Transport Parameters Store.
 * Uses a FIFO queue of tickets per origin so single-use 0-RTT anti-replay tickets are always fresh.
 */
class SessionTicketStore {
  constructor(maxOrigins = 256) {
    this.maxOrigins = maxOrigins;
    this.origins = new Map(); // key -> { tickets: [], newToken: Buffer|null, peerTransportParams: Object|null }
  }

  _getEntry(key) {
    let entry = this.origins.get(key);
    if (!entry) {
      if (this.origins.size >= this.maxOrigins) {
        const oldestKey = this.origins.keys().next().value;
        this.origins.delete(oldestKey);
      }
      entry = { tickets: [], newToken: null, peerTransportParams: null };
      this.origins.set(key, entry);
    }
    return entry;
  }

  addTicket(key, ticketInfo, peerTransportParams = null) {
    if (!key || !ticketInfo || ticketInfo.lifetime <= 0) return;
    const entry = this._getEntry(key);
    entry.tickets.push(ticketInfo);
    if (entry.tickets.length > 8) {
      entry.tickets.shift();
    }
    if (peerTransportParams) {
      entry.peerTransportParams = peerTransportParams;
    }
  }

  setNewToken(key, token) {
    if (!key || !token || token.length === 0) return;
    const entry = this._getEntry(key);
    entry.newToken = Buffer.from(token);
  }

  /**
   * Retrieves a valid session ticket (consuming from FIFO queue for 0-RTT anti-replay freshness)
   * along with any cached QUIC NEW_TOKEN and remembered peer transport parameters.
   */
  checkout(key) {
    const entry = this.origins.get(key);
    if (!entry) return null;

    const now = Date.now();
    // Prune expired tickets
    entry.tickets = entry.tickets.filter((t) => now - t.createdAt < t.lifetime * 1000);
    if (entry.tickets.length === 0) {
      return {
        ticket: null,
        newToken: entry.newToken,
        peerTransportParams: entry.peerTransportParams,
      };
    }

    // Pop oldest fresh ticket if multiple exist, or consume single ticket if earlyData (single-use)
    const chosen = entry.tickets.length > 1 || entry.tickets[0].earlyData
      ? entry.tickets.shift()
      : entry.tickets[0];

    return {
      ticket: chosen,
      newToken: entry.newToken,
      peerTransportParams: entry.peerTransportParams,
    };
  }

  clear() {
    this.origins.clear();
  }
}

const defaultSessionStore = new SessionTicketStore();

// Single-use forward-secret ephemeral X25519 key pool (replenished asynchronously when idle)
const EPHEMERAL_X25519_POOL = [];
const TARGET_X25519_POOL_SIZE = 8;
let poolRefillScheduled = false;

function createEphemeralX25519() {
  const kp = crypto.generateKeyPairSync('x25519');
  const pubRaw = kp.publicKey
    .export({ type: 'spki', format: 'der' })
    .subarray(X25519_SPKI_PREFIX.length);
  return { kp, pubRaw };
}

function scheduleX25519Refill() {
  if (poolRefillScheduled || EPHEMERAL_X25519_POOL.length >= TARGET_X25519_POOL_SIZE) return;
  poolRefillScheduled = true;
  setImmediate(() => {
    poolRefillScheduled = false;
    while (EPHEMERAL_X25519_POOL.length < TARGET_X25519_POOL_SIZE) {
      EPHEMERAL_X25519_POOL.push(createEphemeralX25519());
    }
  }).unref?.();
}

function checkoutEphemeralX25519() {
  const item = EPHEMERAL_X25519_POOL.pop() || createEphemeralX25519();
  scheduleX25519Refill();
  return item;
}
scheduleX25519Refill();

// Lazy-loaded trusted root CA store indexed by subject string
let cachedRootCertsBySubject = null;
function getRootCertsBySubject() {
  if (cachedRootCertsBySubject) return cachedRootCertsBySubject;
  cachedRootCertsBySubject = new Map();
  for (const pem of tls.rootCertificates) {
    try {
      const x509 = new crypto.X509Certificate(pem);
      const list = cachedRootCertsBySubject.get(x509.subject) || [];
      list.push(x509);
      cachedRootCertsBySubject.set(x509.subject, list);
    } catch {
      // Ignore malformed root entries
    }
  }
  return cachedRootCertsBySubject;
}

/**
 * Encodes QUIC Transport Parameters (RFC 9000 Section 18.2).
 */
function encodeTransportParameters(params) {
  const chunks = [];

  const addBytes = (id, buf) => {
    chunks.push(encodeVarint(id), encodeVarint(buf.length), buf);
  };
  const addInt = (id, val) => {
    if (val !== undefined && val !== null) {
      addBytes(id, encodeVarint(val));
    }
  };
  const addFlag = (id, enabled) => {
    if (enabled) {
      chunks.push(encodeVarint(id), encodeVarint(0));
    }
  };

  if (params.initialSourceConnectionId) {
    addBytes(0x0f, params.initialSourceConnectionId);
  }
  addInt(0x01, params.maxIdleTimeout);
  addInt(0x03, params.maxUdpPayloadSize);
  addInt(0x04, params.initialMaxData);
  addInt(0x05, params.initialMaxStreamDataBidiLocal);
  addInt(0x06, params.initialMaxStreamDataBidiRemote);
  addInt(0x07, params.initialMaxStreamDataUni);
  addInt(0x08, params.initialMaxStreamsBidi);
  addInt(0x09, params.initialMaxStreamsUni);
  addInt(0x0a, params.ackDelayExponent);
  addInt(0x0b, params.maxAckDelay);
  addFlag(0x0c, params.disableActiveMigration);
  addInt(0x0e, params.activeConnectionIdLimit);
  addInt(0x20, params.maxDatagramFrameSize);

  if (params.customParams && typeof params.customParams === 'object') {
    const entries =
      params.customParams instanceof Map
        ? Array.from(params.customParams.entries())
        : Object.entries(params.customParams);
    for (const [rawId, rawVal] of entries) {
      const id = typeof rawId === 'bigint' ? rawId : Number(rawId);
      if (Buffer.isBuffer(rawVal)) {
        addBytes(id, rawVal);
      } else if (typeof rawVal === 'number' || typeof rawVal === 'bigint') {
        addInt(id, rawVal);
      } else if (rawVal === true) {
        addFlag(id, true);
      }
    }
  }

  return Buffer.concat(chunks);
}

/**
 * Decodes QUIC Transport Parameters (RFC 9000 Section 18.2 + RFC 9221).
 */
function decodeTransportParameters(buf) {
  const params = {
    maxIdleTimeout: 0,
    maxUdpPayloadSize: 65527,
    initialMaxData: 0,
    initialMaxStreamDataBidiLocal: 0,
    initialMaxStreamDataBidiRemote: 0,
    initialMaxStreamDataUni: 0,
    initialMaxStreamsBidi: 0,
    initialMaxStreamsUni: 0,
    ackDelayExponent: 3,
    maxAckDelay: 25,
    disableActiveMigration: false,
    activeConnectionIdLimit: 2,
    maxDatagramFrameSize: 0,
    originalDestinationConnectionId: null,
    initialSourceConnectionId: null,
    retrySourceConnectionId: null,
    statelessResetToken: null,
    preferredAddress: null,
  };

  let pos = 0;
  while (pos < buf.length) {
    const idDec = decodeVarint(buf, pos);
    if (!idDec) throw new Error('Truncated transport parameter id');
    pos += idDec.bytesRead;

    const lenDec = decodeVarint(buf, pos);
    if (!lenDec) throw new Error('Truncated transport parameter length');
    pos += lenDec.bytesRead;

    const len = Number(lenDec.value);
    if (pos + len > buf.length) throw new Error('Truncated transport parameter value');
    const valBuf = buf.subarray(pos, pos + len);
    pos += len;

    const id = idDec.value;
    const readInt = () => {
      const v = decodeVarint(valBuf, 0);
      if (!v || v.bytesRead !== valBuf.length) {
        throw new Error(`Invalid varint in transport parameter 0x${id.toString(16)}`);
      }
      return Number(v.value);
    };

    switch (id) {
      case 0x00:
        params.originalDestinationConnectionId = Buffer.from(valBuf);
        break;
      case 0x01:
        params.maxIdleTimeout = readInt();
        break;
      case 0x02:
        params.statelessResetToken = Buffer.from(valBuf);
        break;
      case 0x03:
        params.maxUdpPayloadSize = readInt();
        break;
      case 0x04:
        params.initialMaxData = readInt();
        break;
      case 0x05:
        params.initialMaxStreamDataBidiLocal = readInt();
        break;
      case 0x06:
        params.initialMaxStreamDataBidiRemote = readInt();
        break;
      case 0x07:
        params.initialMaxStreamDataUni = readInt();
        break;
      case 0x08:
        params.initialMaxStreamsBidi = readInt();
        break;
      case 0x09:
        params.initialMaxStreamsUni = readInt();
        break;
      case 0x0a:
        params.ackDelayExponent = readInt();
        break;
      case 0x0b:
        params.maxAckDelay = readInt();
        break;
      case 0x0c:
        params.disableActiveMigration = true;
        break;
      case 0x0d:
        if (valBuf.length >= 41) {
          const cidLen = valBuf[24];
          if (25 + cidLen + 16 <= valBuf.length) {
            params.preferredAddress = {
              ipv4Address: `${valBuf[0]}.${valBuf[1]}.${valBuf[2]}.${valBuf[3]}`,
              ipv4Port: valBuf.readUInt16BE(4),
              ipv6Bytes: Buffer.from(valBuf.subarray(6, 22)),
              ipv6Port: valBuf.readUInt16BE(22),
              connectionId: Buffer.from(valBuf.subarray(25, 25 + cidLen)),
              statelessResetToken: Buffer.from(valBuf.subarray(25 + cidLen, 25 + cidLen + 16)),
            };
          }
        }
        break;
      case 0x0e:
        params.activeConnectionIdLimit = readInt();
        break;
      case 0x0f:
        params.initialSourceConnectionId = Buffer.from(valBuf);
        break;
      case 0x10:
        params.retrySourceConnectionId = Buffer.from(valBuf);
        break;
      case 0x20:
        params.maxDatagramFrameSize = readInt();
        break;
      default:
        break;
    }
  }

  return params;
}

function wrapHandshakeMsg(msgType, body) {
  const out = Buffer.allocUnsafe(4 + body.length);
  out[0] = msgType;
  out[1] = (body.length >>> 16) & 0xff;
  out[2] = (body.length >>> 8) & 0xff;
  out[3] = body.length & 0xff;
  body.copy(out, 4);
  return out;
}

function buildExtension(extType, data) {
  const out = Buffer.allocUnsafe(4 + data.length);
  out.writeUInt16BE(extType, 0);
  out.writeUInt16BE(data.length, 2);
  data.copy(out, 4);
  return out;
}

/**
 * TLS 1.3 Client Handshake State Machine for QUIC (RFC 9001 + RFC 8446).
 * Supports Full Handshake, PSK Session Resumption, and QUIC 0-RTT Early Data.
 */
class Tls13QuicClient {
  constructor({
    servername,
    alpnProtocols = ['h3'],
    transportParams,
    rejectUnauthorized = true,
    ca = null,
    resumptionTicket = null,
    enable0Rtt = false,
    onKeylog = null,
  }) {
    this.servername = servername || '';
    this.alpnProtocols = alpnProtocols;
    this.localTransportParams = transportParams;
    this.rejectUnauthorized = rejectUnauthorized;
    this.customCa = ca;
    this.resumptionTicket = resumptionTicket;
    this.enable0Rtt = Boolean(enable0Rtt);
    this.onKeylog = typeof onKeylog === 'function' ? onKeylog : null;

    // Checkout single-use ephemeral X25519 key pair (P-256 & P-384 generated lazily on HRR if ever requested)
    const eph = checkoutEphemeralX25519();
    this.x25519 = eph.kp;
    this.x25519PubRaw = eph.pubRaw;

    this.p256 = null;
    this.p384 = null;

    this.clientRandom = crypto.randomBytes(32);
    this.hrrCookie = null;
    this.receivedHrr = false;
    this.selectedKeyShareGroups = [0x001d]; // Send compact 32-byte X25519 key_share like Chrome/OpenSSL

    // Transcript & negotiated state
    this.transcript = [];
    this.suite = null;
    this.negotiatedAlpn = null;
    this.peerTransportParams = null;
    this.peerCertificates = [];
    this.certificateRequested = false;
    this.handshakeComplete = false;
    this.sessionTickets = [];

    // PSK & 0-RTT state
    this.offeredPsk = false;
    this.offeredEarlyData = false;
    this.pskAccepted = false;
    this.earlyDataAccepted = false;
    this.earlyDataKeys = null;

    // Key schedule secrets
    this.handshakeSecret = null;
    this.clientHandshakeTrafficSecret = null;
    this.serverHandshakeTrafficSecret = null;
    this.masterSecret = null;
    this.clientAppTrafficSecret0 = null;
    this.serverAppTrafficSecret0 = null;
    this.resumptionMasterSecret = null;

    // Per-level CRYPTO stream message accumulators
    this.buffers = {
      initial: Buffer.alloc(0),
      handshake: Buffer.alloc(0),
      app: Buffer.alloc(0),
    };
  }

  /**
   * Builds the TLS 1.3 ClientHello message (with optional PSK binder & 0-RTT early_data).
   */
  buildClientHello() {
    const exts = [];

    // 1. SNI (server_name, 0x0000)
    if (this.servername && net.isIP(this.servername) === 0) {
      const hostBuf = Buffer.from(this.servername, 'ascii');
      const sniData = Buffer.allocUnsafe(2 + 1 + 2 + hostBuf.length);
      sniData.writeUInt16BE(1 + 2 + hostBuf.length, 0);
      sniData[2] = 0x00;
      sniData.writeUInt16BE(hostBuf.length, 3);
      hostBuf.copy(sniData, 5);
      exts.push(buildExtension(EXT_SERVER_NAME, sniData));
    }

    // 2. ALPN (0x0010)
    const alpnEntries = this.alpnProtocols.map((p) => {
      const b = Buffer.from(p, 'ascii');
      return Buffer.concat([Buffer.from([b.length]), b]);
    });
    const alpnList = Buffer.concat(alpnEntries);
    const alpnData = Buffer.allocUnsafe(2 + alpnList.length);
    alpnData.writeUInt16BE(alpnList.length, 0);
    alpnList.copy(alpnData, 2);
    exts.push(buildExtension(EXT_ALPN, alpnData));

    // 3. supported_versions (0x002b) -> TLS 1.3 (0x0304)
    exts.push(buildExtension(EXT_SUPPORTED_VERSIONS, Buffer.from([0x02, 0x03, 0x04])));

    // 4. supported_groups (0x000a)
    exts.push(
      buildExtension(
        EXT_SUPPORTED_GROUPS,
        Buffer.from([0x00, 0x06, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18])
      )
    );

    // 5. signature_algorithms (0x000d)
    const sigAlgs = [0x0403, 0x0503, 0x0603, 0x0807, 0x0804, 0x0805, 0x0806];
    const sigData = Buffer.allocUnsafe(2 + sigAlgs.length * 2);
    sigData.writeUInt16BE(sigAlgs.length * 2, 0);
    sigAlgs.forEach((alg, idx) => sigData.writeUInt16BE(alg, 2 + idx * 2));
    exts.push(buildExtension(EXT_SIGNATURE_ALGORITHMS, sigData));

    // 6. psk_key_exchange_modes (0x002d) -> psk_dhe_ke (0x01)
    exts.push(buildExtension(EXT_PSK_KEY_EXCHANGE_MODES, Buffer.from([0x01, 0x01])));

    // 7. cookie (0x002c) if replying to HelloRetryRequest
    if (this.hrrCookie) {
      const cookieData = Buffer.allocUnsafe(2 + this.hrrCookie.length);
      cookieData.writeUInt16BE(this.hrrCookie.length, 0);
      this.hrrCookie.copy(cookieData, 2);
      exts.push(buildExtension(EXT_COOKIE, cookieData));
    }

    // 8. key_share (0x0033)
    const shareEntries = [];
    for (const group of this.selectedKeyShareGroups) {
      let pub;
      if (group === 0x001d) {
        pub = this.x25519PubRaw;
      } else if (group === 0x0017) {
        if (!this.p256) {
          this.p256 = crypto.createECDH('prime256v1');
          this.p256.generateKeys();
        }
        pub = this.p256.getPublicKey();
      } else if (group === 0x0018) {
        if (!this.p384) {
          this.p384 = crypto.createECDH('secp384r1');
          this.p384.generateKeys();
        }
        pub = this.p384.getPublicKey();
      }
      if (pub) {
        const entry = Buffer.allocUnsafe(4 + pub.length);
        entry.writeUInt16BE(group, 0);
        entry.writeUInt16BE(pub.length, 2);
        pub.copy(entry, 4);
        shareEntries.push(entry);
      }
    }
    const sharesConcat = Buffer.concat(shareEntries);
    const keyShareData = Buffer.allocUnsafe(2 + sharesConcat.length);
    keyShareData.writeUInt16BE(sharesConcat.length, 0);
    sharesConcat.copy(keyShareData, 2);
    exts.push(buildExtension(EXT_KEY_SHARE, keyShareData));

    // 9. quic_transport_parameters (0x0039)
    const tpData = encodeTransportParameters(this.localTransportParams);
    exts.push(buildExtension(EXT_QUIC_TRANSPORT_PARAMS, tpData));

    // Check if we have a valid PSK resumption ticket
    const ticketInfo = this.resumptionTicket;
    const pskSuite = ticketInfo ? CIPHER_SUITES[ticketInfo.suiteId] : null;
    const canOfferPsk =
      Boolean(ticketInfo && pskSuite && Date.now() - ticketInfo.createdAt < ticketInfo.lifetime * 1000);

    // 10. early_data (0x002a) - allowed only on first ClientHello (never after HRR per RFC 8446 §4.2.10)
    this.offeredEarlyData = false;
    if (canOfferPsk && this.enable0Rtt && ticketInfo.earlyData && !this.receivedHrr) {
      exts.push(buildExtension(EXT_EARLY_DATA, Buffer.alloc(0)));
      this.offeredEarlyData = true;
    }

    // 11. pre_shared_key (0x0029) MUST BE THE LAST EXTENSION IN ClientHello (RFC 8446 §4.2.11)
    this.offeredPsk = false;
    let pskEarlySecret = null;
    if (canOfferPsk) {
      this.offeredPsk = true;
      const { hash, hashLen } = pskSuite;
      const zero = Buffer.alloc(hashLen, 0);
      pskEarlySecret = hkdfExtract(hash, zero, ticketInfo.psk);

      const ageMs = Math.max(0, Date.now() - ticketInfo.createdAt);
      const obfuscatedAge = (ageMs + ticketInfo.ageAdd) >>> 0;

      // identities: uint16 list_len + (uint16 ticket_len + ticket + uint32 obfuscated_age)
      // binders:    uint16 binders_len + (uint8 binder_len + zero_placeholder[hashLen])
      const idEntryLen = 2 + ticketInfo.ticket.length + 4;
      const bindersEntryLen = 1 + hashLen;
      const pskExtData = Buffer.alloc(2 + idEntryLen + 2 + bindersEntryLen, 0);
      let pPos = 0;
      pskExtData.writeUInt16BE(idEntryLen, pPos);
      pPos += 2;
      pskExtData.writeUInt16BE(ticketInfo.ticket.length, pPos);
      pPos += 2;
      ticketInfo.ticket.copy(pskExtData, pPos);
      pPos += ticketInfo.ticket.length;
      pskExtData.writeUInt32BE(obfuscatedAge, pPos);
      pPos += 4;
      pskExtData.writeUInt16BE(bindersEntryLen, pPos);
      pPos += 2;
      pskExtData[pPos] = hashLen;
      // remaining hashLen bytes stay 0 until binder HMAC is filled in below
      exts.push(buildExtension(EXT_PRE_SHARED_KEY, pskExtData));
    }

    const extsBuf = Buffer.concat(exts);
    const suites = Buffer.from([0x00, 0x06, 0x13, 0x01, 0x13, 0x02, 0x13, 0x03]);

    const body = Buffer.allocUnsafe(2 + 32 + 1 + suites.length + 2 + 2 + extsBuf.length);
    let pos = 0;
    body.writeUInt16BE(0x0303, pos);
    pos += 2;
    this.clientRandom.copy(body, pos);
    pos += 32;
    body[pos++] = 0x00;
    suites.copy(body, pos);
    pos += suites.length;
    body[pos++] = 0x01;
    body[pos++] = 0x00;
    body.writeUInt16BE(extsBuf.length, pos);
    pos += 2;
    extsBuf.copy(body, pos);

    const msg = wrapHandshakeMsg(MSG_CLIENT_HELLO, body);

    // Fill in PSK Binder HMAC over partial ClientHello (up to identities, excluding binders list)
    if (this.offeredPsk && pskSuite && pskEarlySecret) {
      const { hash, hashLen } = pskSuite;
      const emptyHash = crypto.createHash(hash).digest();
      const binderKey = hkdfExpandLabel(hash, pskEarlySecret, 'res binder', emptyHash, hashLen);
      const binderFinKey = hkdfExpandLabel(hash, binderKey, 'finished', Buffer.alloc(0), hashLen);

      const bindersTotalLen = 2 + 1 + hashLen;
      const partialCh = msg.subarray(0, msg.length - bindersTotalLen);
      const th = crypto.createHash(hash);
      for (const prev of this.transcript) th.update(prev);
      th.update(partialCh);
      const binder = crypto.createHmac(hash, binderFinKey).update(th.digest()).digest();
      binder.copy(msg, msg.length - hashLen);
    }

    this.transcript.push(msg);

    // Derive QUIC 0-RTT Early Traffic Keys if early_data was offered (RFC 9001 §4.6)
    if (this.offeredEarlyData && pskSuite && pskEarlySecret) {
      const chHash = this.transcriptHash(pskSuite.hash);
      const clientEarlySecret = hkdfExpandLabel(
        pskSuite.hash,
        pskEarlySecret,
        'c e traffic',
        chHash,
        pskSuite.hashLen
      );
      this._emitKeylog('CLIENT_EARLY_TRAFFIC_SECRET', clientEarlySecret);
      this.earlyDataKeys = derivePacketProtectionKeys(pskSuite.id, clientEarlySecret);
    } else {
      this.earlyDataKeys = null;
    }

    return msg;
  }

  _emitKeylog(label, secretBuf) {
    if (!this.onKeylog || !secretBuf) return;
    const line = Buffer.from(
      `${label} ${this.clientRandom.toString('hex')} ${secretBuf.toString('hex')}\n`,
      'ascii'
    );
    this.onKeylog(line);
  }

  transcriptHash(hashAlg = this.suite.hash) {
    const h = crypto.createHash(hashAlg);
    for (const m of this.transcript) h.update(m);
    return h.digest();
  }

  feedCrypto(level, data) {
    this.buffers[level] =
      this.buffers[level].length === 0 ? data : Buffer.concat([this.buffers[level], data]);
    const events = [];

    while (this.buffers[level].length >= 4) {
      const buf = this.buffers[level];
      const msgType = buf[0];
      const msgLen = (buf[1] << 16) | (buf[2] << 8) | buf[3];
      if (buf.length < 4 + msgLen) break;

      const rawMsg = buf.subarray(0, 4 + msgLen);
      const body = buf.subarray(4, 4 + msgLen);
      this.buffers[level] = buf.subarray(4 + msgLen);

      const ev = this._handleHandshakeMessage(level, msgType, body, rawMsg);
      if (ev) events.push(ev);
    }

    return events;
  }

  _handleHandshakeMessage(level, msgType, body, rawMsg) {
    if (msgType === MSG_SERVER_HELLO) {
      if (level !== 'initial') {
        throw new Error(`Unexpected ServerHello at level ${level}`);
      }
      return this._handleServerHello(body, rawMsg);
    }

    if (msgType === MSG_ENCRYPTED_EXTENSIONS) {
      if (level !== 'handshake') {
        throw new Error(`Unexpected EncryptedExtensions at level ${level}`);
      }
      this.transcript.push(rawMsg);
      this._handleEncryptedExtensions(body);
      return {
        type: 'encrypted_extensions',
        peerTransportParams: this.peerTransportParams,
        earlyDataAccepted: this.earlyDataAccepted,
        pskAccepted: this.pskAccepted,
      };
    }

    if (msgType === MSG_CERTIFICATE_REQUEST) {
      this.transcript.push(rawMsg);
      this.certificateRequested = true;
      return null;
    }

    if (msgType === MSG_CERTIFICATE) {
      this.transcript.push(rawMsg);
      this._handleCertificate(body);
      return null;
    }

    if (msgType === MSG_CERTIFICATE_VERIFY) {
      this._handleCertificateVerify(body);
      this.transcript.push(rawMsg);
      return null;
    }

    if (msgType === MSG_FINISHED) {
      if (level !== 'handshake') {
        throw new Error(`Unexpected server Finished at level ${level}`);
      }
      return this._handleServerFinished(body, rawMsg);
    }

    if (msgType === MSG_NEW_SESSION_TICKET) {
      const ticket = this._handleNewSessionTicket(body);
      if (ticket) {
        return { type: 'new_session_ticket', ticket };
      }
      return null;
    }

    throw new Error(`Unexpected TLS 1.3 handshake message type: ${msgType}`);
  }

  _handleServerHello(body, rawMsg) {
    if (body.length < 38) throw new Error('Truncated ServerHello');
    let pos = 2;
    const serverRandom = body.subarray(pos, pos + 32);
    pos += 32;
    const sessIdLen = body[pos++];
    pos += sessIdLen;
    const cipherSuiteId = body.readUInt16BE(pos);
    pos += 2;
    pos += 1;

    const suite = CIPHER_SUITES[cipherSuiteId];
    if (!suite) {
      throw new Error(`Server selected unsupported cipher suite: 0x${cipherSuiteId.toString(16)}`);
    }
    this.suite = suite;

    const extsLen = body.readUInt16BE(pos);
    pos += 2;
    const extsEnd = pos + extsLen;

    let selectedVersion = 0;
    let keyShareGroup = 0;
    let keySharePub = null;
    let hrrSelectedGroup = 0;
    let cookie = null;
    let pskSelectedIdentity = -1;

    const isHrr = serverRandom.equals(HRR_RANDOM);

    while (pos + 4 <= extsEnd) {
      const extType = body.readUInt16BE(pos);
      const extLen = body.readUInt16BE(pos + 2);
      pos += 4;
      const extData = body.subarray(pos, pos + extLen);
      pos += extLen;

      if (extType === EXT_SUPPORTED_VERSIONS) {
        selectedVersion = extData.readUInt16BE(0);
      } else if (extType === EXT_KEY_SHARE) {
        if (isHrr) {
          hrrSelectedGroup = extData.readUInt16BE(0);
        } else {
          keyShareGroup = extData.readUInt16BE(0);
          const ksLen = extData.readUInt16BE(2);
          keySharePub = extData.subarray(4, 4 + ksLen);
        }
      } else if (extType === EXT_COOKIE) {
        const cLen = extData.readUInt16BE(0);
        cookie = Buffer.from(extData.subarray(2, 2 + cLen));
      } else if (extType === EXT_PRE_SHARED_KEY && !isHrr) {
        pskSelectedIdentity = extData.readUInt16BE(0);
      }
    }

    if (selectedVersion !== 0x0304) {
      throw new Error(`Server did not negotiate TLS 1.3 (got 0x${selectedVersion.toString(16)})`);
    }

    if (isHrr) {
      this.receivedHrr = true;
      const ch1Hash = this.transcriptHash(suite.hash);
      const msgHash = wrapHandshakeMsg(MSG_MESSAGE_HASH, ch1Hash);
      this.transcript = [msgHash, rawMsg];
      if (cookie) this.hrrCookie = cookie;
      if (hrrSelectedGroup) this.selectedKeyShareGroups = [hrrSelectedGroup];
      const ch2 = this.buildClientHello();
      return { type: 'hello_retry_request', clientHello2: ch2 };
    }

    this.transcript.push(rawMsg);

    // Check if PSK resumption was accepted
    this.pskAccepted =
      this.offeredPsk &&
      pskSelectedIdentity === 0 &&
      this.resumptionTicket &&
      this.resumptionTicket.suiteId === suite.id;

    // Compute ECDHE shared secret
    let sharedSecret;
    if (keyShareGroup === 0x001d) {
      const peerKeyObj = crypto.createPublicKey({
        key: Buffer.concat([X25519_SPKI_PREFIX, keySharePub]),
        format: 'der',
        type: 'spki',
      });
      sharedSecret = crypto.diffieHellman({
        privateKey: this.x25519.privateKey,
        publicKey: peerKeyObj,
      });
    } else if (keyShareGroup === 0x0017) {
      sharedSecret = this.p256.computeSecret(keySharePub);
    } else if (keyShareGroup === 0x0018 && this.p384) {
      sharedSecret = this.p384.computeSecret(keySharePub);
    } else {
      throw new Error(`Unsupported server key_share group: 0x${keyShareGroup.toString(16)}`);
    }

    // TLS 1.3 Key Schedule (with PSK IKM if resumed, else zero IKM)
    const { hash, hashLen } = suite;
    const zero = Buffer.alloc(hashLen, 0);
    const emptyHash = crypto.createHash(hash).digest();

    const ikm = this.pskAccepted ? this.resumptionTicket.psk : zero;
    const earlySecret = hkdfExtract(hash, zero, ikm);
    const derived1 = hkdfExpandLabel(hash, earlySecret, 'derived', emptyHash, hashLen);
    this.handshakeSecret = hkdfExtract(hash, derived1, sharedSecret);

    const th = this.transcriptHash(hash);
    this.clientHandshakeTrafficSecret = hkdfExpandLabel(
      hash,
      this.handshakeSecret,
      'c hs traffic',
      th,
      hashLen
    );
    this.serverHandshakeTrafficSecret = hkdfExpandLabel(
      hash,
      this.handshakeSecret,
      's hs traffic',
      th,
      hashLen
    );
    this._emitKeylog('CLIENT_HANDSHAKE_TRAFFIC_SECRET', this.clientHandshakeTrafficSecret);
    this._emitKeylog('SERVER_HANDSHAKE_TRAFFIC_SECRET', this.serverHandshakeTrafficSecret);

    const derived2 = hkdfExpandLabel(hash, this.handshakeSecret, 'derived', emptyHash, hashLen);
    this.masterSecret = hkdfExtract(hash, derived2, zero);

    return {
      type: 'handshake_keys',
      pskAccepted: this.pskAccepted,
      clientHandshakeKeys: derivePacketProtectionKeys(suite.id, this.clientHandshakeTrafficSecret),
      serverHandshakeKeys: derivePacketProtectionKeys(suite.id, this.serverHandshakeTrafficSecret),
    };
  }

  _handleEncryptedExtensions(body) {
    const extsLen = body.readUInt16BE(0);
    let pos = 2;
    const end = 2 + extsLen;
    this.earlyDataAccepted = false;

    while (pos + 4 <= end) {
      const extType = body.readUInt16BE(pos);
      const extLen = body.readUInt16BE(pos + 2);
      pos += 4;
      const extData = body.subarray(pos, pos + extLen);
      pos += extLen;

      if (extType === EXT_ALPN) {
        const listLen = extData.readUInt16BE(0);
        if (listLen > 0) {
          const protoLen = extData[2];
          this.negotiatedAlpn = extData.subarray(3, 3 + protoLen).toString('ascii');
        }
      } else if (extType === EXT_QUIC_TRANSPORT_PARAMS) {
        this.peerTransportParams = decodeTransportParameters(extData);
      } else if (extType === EXT_EARLY_DATA) {
        if (!this.offeredEarlyData || !this.pskAccepted) {
          throw new Error('Server sent unsolicited early_data in EncryptedExtensions');
        }
        this.earlyDataAccepted = true;
      }
    }

    if (!this.peerTransportParams) {
      throw new Error('Server omitted required quic_transport_parameters extension');
    }
    if (this.alpnProtocols.length > 0 && !this.alpnProtocols.includes(this.negotiatedAlpn)) {
      throw new Error(`ALPN mismatch: expected ${this.alpnProtocols.join(',')}, got ${this.negotiatedAlpn}`);
    }
  }

  _handleCertificate(body) {
    let pos = 0;
    const ctxLen = body[pos++];
    pos += ctxLen;

    const listLen = (body[pos] << 16) | (body[pos + 1] << 8) | body[pos + 2];
    pos += 3;
    const end = pos + listLen;

    this.peerCertificates = [];
    while (pos + 3 <= end) {
      const certLen = (body[pos] << 16) | (body[pos + 1] << 8) | body[pos + 2];
      pos += 3;
      const certDer = Buffer.from(body.subarray(pos, pos + certLen));
      pos += certLen;

      const extLen = body.readUInt16BE(pos);
      pos += 2 + extLen;

      this.peerCertificates.push(new crypto.X509Certificate(certDer));
    }

    if (this.peerCertificates.length === 0) {
      throw new Error('Server sent empty Certificate message');
    }

    if (this.rejectUnauthorized) {
      this._verifyCertificateChain();
    }
  }

  _verifyCertificateChain() {
    const chain = this.peerCertificates;
    const leaf = chain[0];
    const now = new Date();

    if (this.servername) {
      if (net.isIP(this.servername) !== 0) {
        if (!leaf.checkIP(this.servername)) {
          throw new Error(`Certificate IP mismatch for ${this.servername}`);
        }
      } else {
        const matched = leaf.checkHost(this.servername);
        if (!matched) {
          throw new Error(`Certificate hostname mismatch for ${this.servername} (subject: ${leaf.subject})`);
        }
      }
    }

    const rootsBySubject = getRootCertsBySubject();
    const customRoots = [];
    if (this.customCa) {
      const caList = Array.isArray(this.customCa) ? this.customCa : [this.customCa];
      for (const item of caList) {
        customRoots.push(item instanceof crypto.X509Certificate ? item : new crypto.X509Certificate(item));
      }
    }

    const isSignedByTrustedRoot = (cert) => {
      for (const root of customRoots) {
        if (cert.checkIssued(root) && cert.verify(root.publicKey)) {
          return true;
        }
      }
      const candidates = rootsBySubject.get(cert.issuer);
      if (candidates) {
        for (const root of candidates) {
          if (cert.checkIssued(root) && cert.verify(root.publicKey)) {
            return true;
          }
        }
      }
      return false;
    };

    let anchored = false;
    for (let i = 0; i < chain.length; i++) {
      const cert = chain[i];
      if (now < cert.validFromDate || now > cert.validToDate) {
        throw new Error(`Certificate expired or not yet valid: ${cert.subject}`);
      }
      if (i > 0 && !cert.ca) {
        throw new Error(`Intermediate certificate is not a CA: ${cert.subject}`);
      }
      if (isSignedByTrustedRoot(cert)) {
        anchored = true;
        break;
      }
      if (i + 1 < chain.length) {
        const issuer = chain[i + 1];
        if (!cert.verify(issuer.publicKey)) {
          throw new Error(`Certificate signature verification failed at ${cert.subject}`);
        }
      }
    }

    if (!anchored) {
      throw new Error(
        `Unable to verify certificate chain to a trusted root CA (issuer: ${chain[chain.length - 1].issuer})`
      );
    }
  }

  _handleCertificateVerify(body) {
    if (this.peerCertificates.length === 0) {
      throw new Error('Received CertificateVerify before Certificate');
    }
    const sigScheme = body.readUInt16BE(0);
    const sigLen = body.readUInt16BE(2);
    const signature = body.subarray(4, 4 + sigLen);

    const th = this.transcriptHash();
    const prefix = Buffer.alloc(64, 0x20);
    const contextStr = Buffer.from('TLS 1.3, server CertificateVerify\x00', 'ascii');
    const signedData = Buffer.concat([prefix, contextStr, th]);

    const pubKey = this.peerCertificates[0].publicKey;
    let ok = false;

    if (sigScheme === 0x0403) {
      ok = crypto.verify('sha256', signedData, pubKey, signature);
    } else if (sigScheme === 0x0503) {
      ok = crypto.verify('sha384', signedData, pubKey, signature);
    } else if (sigScheme === 0x0603) {
      ok = crypto.verify('sha512', signedData, pubKey, signature);
    } else if (sigScheme === 0x0807) {
      ok = crypto.verify(null, signedData, pubKey, signature);
    } else if (sigScheme === 0x0804 || sigScheme === 0x0805 || sigScheme === 0x0806) {
      const digest = sigScheme === 0x0804 ? 'sha256' : sigScheme === 0x0805 ? 'sha384' : 'sha512';
      ok = crypto.verify(
        digest,
        signedData,
        {
          key: pubKey,
          padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
          saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST,
        },
        signature
      );
    } else {
      throw new Error(`Unsupported CertificateVerify signature scheme: 0x${sigScheme.toString(16)}`);
    }

    if (!ok) {
      throw new Error('TLS 1.3 CertificateVerify cryptographic signature check failed');
    }
  }

  _handleServerFinished(body, rawMsg) {
    if (!this.pskAccepted && this.peerCertificates.length === 0) {
      throw new Error('Server omitted Certificate on non-PSK handshake');
    }

    const { hash, hashLen, id: suiteId } = this.suite;
    const serverFinishedKey = hkdfExpandLabel(
      hash,
      this.serverHandshakeTrafficSecret,
      'finished',
      Buffer.alloc(0),
      hashLen
    );
    const thBeforeSF = this.transcriptHash(hash);
    const expectedVerifyData = crypto
      .createHmac(hash, serverFinishedKey)
      .update(thBeforeSF)
      .digest();

    if (body.length !== expectedVerifyData.length || !crypto.timingSafeEqual(body, expectedVerifyData)) {
      throw new Error('Server Finished verify_data mismatch');
    }

    this.transcript.push(rawMsg);

    const thAfterSF = this.transcriptHash(hash);
    this.clientAppTrafficSecret0 = hkdfExpandLabel(
      hash,
      this.masterSecret,
      'c ap traffic',
      thAfterSF,
      hashLen
    );
    this.serverAppTrafficSecret0 = hkdfExpandLabel(
      hash,
      this.masterSecret,
      's ap traffic',
      thAfterSF,
      hashLen
    );
    this._emitKeylog('CLIENT_TRAFFIC_SECRET_0', this.clientAppTrafficSecret0);
    this._emitKeylog('SERVER_TRAFFIC_SECRET_0', this.serverAppTrafficSecret0);

    const clientHandshakeResponseParts = [];

    if (this.certificateRequested) {
      const emptyCertMsg = wrapHandshakeMsg(MSG_CERTIFICATE, Buffer.from([0x00, 0x00, 0x00, 0x00]));
      this.transcript.push(emptyCertMsg);
      clientHandshakeResponseParts.push(emptyCertMsg);
    }

    // Note: RFC 9001 §8.3 forbids EndOfEarlyData in QUIC (not sent and not in transcript)
    const clientFinishedKey = hkdfExpandLabel(
      hash,
      this.clientHandshakeTrafficSecret,
      'finished',
      Buffer.alloc(0),
      hashLen
    );
    const thBeforeCF = this.transcriptHash(hash);
    const clientVerifyData = crypto
      .createHmac(hash, clientFinishedKey)
      .update(thBeforeCF)
      .digest();
    const clientFinishedMsg = wrapHandshakeMsg(MSG_FINISHED, clientVerifyData);
    this.transcript.push(clientFinishedMsg);
    clientHandshakeResponseParts.push(clientFinishedMsg);

    // Derive resumption_master_secret over transcript [ClientHello .. ClientFinished] (RFC 8446 §7.1)
    const thAfterCF = this.transcriptHash(hash);
    this.resumptionMasterSecret = hkdfExpandLabel(
      hash,
      this.masterSecret,
      'res master',
      thAfterCF,
      hashLen
    );

    this.handshakeComplete = true;

    return {
      type: 'handshake_complete',
      clientHandshakeFlight: Buffer.concat(clientHandshakeResponseParts),
      clientAppKeys: derivePacketProtectionKeys(suiteId, this.clientAppTrafficSecret0),
      serverAppKeys: derivePacketProtectionKeys(suiteId, this.serverAppTrafficSecret0),
      alpn: this.negotiatedAlpn,
      peerTransportParams: this.peerTransportParams,
      pskAccepted: this.pskAccepted,
      earlyDataAccepted: this.earlyDataAccepted,
    };
  }

  _handleNewSessionTicket(body) {
    if (body.length < 13 || !this.resumptionMasterSecret || !this.suite) return null;
    let pos = 0;
    const lifetime = body.readUInt32BE(pos);
    pos += 4;
    const ageAdd = body.readUInt32BE(pos);
    pos += 4;
    const nonceLen = body[pos++];
    const nonce = Buffer.from(body.subarray(pos, pos + nonceLen));
    pos += nonceLen;
    const ticketLen = body.readUInt16BE(pos);
    pos += 2;
    const ticket = Buffer.from(body.subarray(pos, pos + ticketLen));
    pos += ticketLen;

    let earlyData = false;
    if (pos + 2 <= body.length) {
      const extsLen = body.readUInt16BE(pos);
      pos += 2;
      const end = Math.min(body.length, pos + extsLen);
      while (pos + 4 <= end) {
        const extType = body.readUInt16BE(pos);
        const extLen = body.readUInt16BE(pos + 2);
        pos += 4;
        const extData = body.subarray(pos, pos + extLen);
        pos += extLen;
        if (extType === EXT_EARLY_DATA && extData.length >= 4) {
          const maxEarly = extData.readUInt32BE(0) >>> 0;
          // RFC 9001 §4.6.1: QUIC NewSessionTicket early_data value MUST be 0xffffffff
          if (maxEarly === 0xffffffff) {
            earlyData = true;
          }
        }
      }
    }

    const psk = hkdfExpandLabel(
      this.suite.hash,
      this.resumptionMasterSecret,
      'resumption',
      nonce,
      this.suite.hashLen
    );

    const info = {
      suiteId: this.suite.id,
      psk,
      ticket,
      ageAdd,
      lifetime,
      createdAt: Date.now(),
      earlyData,
      alpn: this.negotiatedAlpn,
    };
    this.sessionTickets.push(info);
    return info;
  }
}

module.exports = {
  Tls13QuicClient,
  SessionTicketStore,
  defaultSessionStore,
  encodeTransportParameters,
  decodeTransportParameters,
};
