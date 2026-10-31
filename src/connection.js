'use strict';

const dgram = require('node:dgram');
const crypto = require('node:crypto');
const dns = require('node:dns');
const net = require('node:net');
const { EventEmitter } = require('node:events');

const {
  deriveInitialSecrets,
  deriveUpdatedKeys,
  verifyRetryIntegrityTag,
} = require('./crypto');
const {
  buildInitialPacket,
  buildZeroRttPacket,
  buildHandshakePacket,
  buildShortPacket,
  splitDatagram,
  unprotectPacket,
} = require('./packet');
const {
  parseFrames,
  isAckEliciting,
  buildPingFrame,
  buildCryptoFrame,
  buildStreamFrame,
  buildAckFrameFromPacketNumbers,
  buildMaxDataFrame,
  buildMaxStreamDataFrame,
  buildResetStreamFrame,
  buildStopSendingFrame,
  buildNewConnectionIdFrame,
  buildRetireConnectionIdFrame,
  buildStreamsBlockedFrame,
  buildPathChallengeFrame,
  buildPathResponseFrame,
  buildDatagramFrame,
  buildConnectionCloseFrame,
} = require('./frame');
const { Tls13QuicClient, defaultSessionStore } = require('./tls13');

const INITIAL_MIN_DGRAM_SIZE = 1200;
const DEFAULT_INITIAL_MTU = 1350;
const DEFAULT_MAX_MTU = 1472;
const MAX_INITIAL_CRYPTO_CHUNK = 1120;
const MAX_CRYPTO_CHUNK = 1100;

const PACKET_THRESHOLD = 3;
const TIME_THRESHOLD = 9 / 8; // RFC 9002 §6.1.2 kTimeThreshold
const GRANULARITY_MS = 1; // RFC 9002 kGranularity

/**
 * Fast in-memory TTL DNS Cache to avoid repeated OS/threadpool lookup latency.
 */
class DnsCache {
  constructor(ttlMs = 60000, maxEntries = 512) {
    this.ttlMs = ttlMs;
    this.maxEntries = maxEntries;
    this.cache = new Map();
  }

  get(key) {
    const item = this.cache.get(key);
    if (!item) return null;
    if (Date.now() > item.expiresAt) {
      this.cache.delete(key);
      return null;
    }
    return item.value;
  }

  set(key, value) {
    if (this.cache.size >= this.maxEntries) {
      const oldest = this.cache.keys().next().value;
      this.cache.delete(oldest);
    }
    this.cache.set(key, { value, expiresAt: Date.now() + this.ttlMs });
  }

  clear() {
    this.cache.clear();
  }
}

const defaultDnsCache = new DnsCache();

/**
 * Out-of-order & overlapping byte-stream reassembler for CRYPTO and STREAM frames.
 */
class ByteReassembler {
  constructor() {
    this.readOffset = 0;
    this.segments = [];
    this.finalOffset = null;
    this.emittedEnd = false;
    this.highestReceivedOffset = 0;
  }

  push(offset, data, fin = false) {
    const endOffset = offset + data.length;
    if (endOffset > this.highestReceivedOffset) {
      this.highestReceivedOffset = endOffset;
    }
    if (fin) {
      this.finalOffset = endOffset;
    }

    // Fast path: exact in-order chunk with empty segments queue
    if (this.segments.length === 0 && offset === this.readOffset) {
      this.readOffset += data.length;
      let ended = false;
      if (!this.emittedEnd && this.finalOffset !== null && this.readOffset >= this.finalOffset) {
        this.emittedEnd = true;
        ended = true;
      }
      return { contiguous: data, ended };
    }

    if (endOffset > this.readOffset && data.length > 0) {
      let adjOffset = offset;
      let adjData = data;
      if (adjOffset < this.readOffset) {
        adjData = adjData.subarray(this.readOffset - adjOffset);
        adjOffset = this.readOffset;
      }
      this.segments.push({ offset: adjOffset, data: Buffer.from(adjData) });
      this.segments.sort((a, b) => a.offset - b.offset);
    }

    const ready = [];
    while (this.segments.length > 0) {
      const seg = this.segments[0];
      if (seg.offset > this.readOffset) break;
      this.segments.shift();
      const segEnd = seg.offset + seg.data.length;
      if (segEnd <= this.readOffset) continue;
      const slice =
        seg.offset < this.readOffset
          ? seg.data.subarray(this.readOffset - seg.offset)
          : seg.data;
      ready.push(slice);
      this.readOffset += slice.length;
    }

    const contiguous =
      ready.length === 0
        ? Buffer.alloc(0)
        : ready.length === 1
        ? ready[0]
        : Buffer.concat(ready);

    let ended = false;
    if (!this.emittedEnd && this.finalOffset !== null && this.readOffset >= this.finalOffset) {
      this.emittedEnd = true;
      ended = true;
    }

    return { contiguous, ended };
  }
}

/**
 * Packet Number Space tracker (Initial, Handshake, Application / 0-RTT + 1-RTT).
 */
class PacketSpace {
  constructor(name) {
    this.name = name;
    this.nextPn = 0;
    this.largestAckedSent = -1;
    this.largestReceived = -1;
    this.largestReceivedTime = 0;
    this.receivedPns = new Set();
    this.ackPending = false;
    this.ackElicitingSinceLastAck = 0;
    this.sentPackets = new Map();
    this.cryptoSendOffset = 0;
    this.cryptoReassembler = new ByteReassembler();
  }

  recordReceived(pn) {
    const isDuplicate = this.receivedPns.has(pn);
    this.receivedPns.add(pn);
    if (this.receivedPns.size > 600) {
      const minKeep = this.largestReceived - 512;
      for (const old of this.receivedPns) {
        if (old < minKeep) this.receivedPns.delete(old);
      }
    }
    if (pn > this.largestReceived) {
      this.largestReceived = pn;
      this.largestReceivedTime = performance.now();
    }
    return isDuplicate;
  }
}

/**
 * Pluggable QUIC Congestion Controller & Optional Packet Pacer (RFC 9002 + RFC 9438 CUBIC + BBR).
 * Supports `'cubic' | 'newreno' | 'bbr' | 'unlimited'`.
 */
class QuicCongestionController {
  constructor({
    algorithm = 'cubic',
    maxDatagramSize = DEFAULT_INITIAL_MTU,
    initialCwndPackets = 32,
    minCwndPackets = 4,
    maxCwndBytes = 16 * 1024 * 1024,
    pacing = false,
  } = {}) {
    this.algorithm = String(algorithm || 'cubic').toLowerCase();
    this.maxDatagramSize = maxDatagramSize;
    this.initialCwndPackets = Math.max(2, initialCwndPackets);
    this.minCwndPackets = Math.max(2, minCwndPackets);
    this.maxCwndBytes = maxCwndBytes;

    this.initialCwnd = this.initialCwndPackets * this.maxDatagramSize;
    this.minCwnd = this.minCwndPackets * this.maxDatagramSize;
    this.cwnd = this.initialCwnd;
    this.ssthresh = Infinity;
    this.bytesInFlight = 0;
    this.recoveryStartTime = 0;
    this.congestionEvents = 0;
    this.highestEcnCe = 0n;

    // CUBIC parameters (RFC 9438: C = 0.4, beta_cubic = 0.7)
    this.cubicC = 0.4;
    this.cubicBeta = 0.7;
    this.wMax = 0;
    this.cubicK = 0;
    this.epochStart = 0;
    this.originPoint = 0;

    // BBRv1-lite delivery rate estimator
    this.bbrMaxBwBytesPerMs = 0;
    this.bbrSamples = [];

    // Token-bucket Packet Pacer
    this.pacingEnabled = Boolean(pacing);
    this.pacingBurstBytes = Math.max(10 * this.maxDatagramSize, Math.floor(this.initialCwnd / 2));
    this.pacingTokens = this.pacingBurstBytes;
    this.lastPacingRefill = performance.now();
  }

  setMtu(newMtu) {
    this.maxDatagramSize = newMtu;
    this.initialCwnd = this.initialCwndPackets * newMtu;
    this.minCwnd = this.minCwndPackets * newMtu;
    if (this.cwnd < this.minCwnd) {
      this.cwnd = this.minCwnd;
    }
    this.pacingBurstBytes = Math.max(10 * newMtu, Math.floor(this.cwnd / 4));
  }

  availableWindow() {
    if (this.algorithm === 'unlimited') return Infinity;
    return Math.max(0, this.cwnd - this.bytesInFlight);
  }

  canSend(bytes = 1) {
    if (this.algorithm === 'unlimited') return true;
    return this.bytesInFlight + bytes <= this.cwnd;
  }

  consumePacingTokens(bytes, smoothedRttMs, now = performance.now()) {
    if (!this.pacingEnabled || this.algorithm === 'unlimited') return 0;
    const elapsedMs = Math.max(0, now - this.lastPacingRefill);
    this.lastPacingRefill = now;

    const rtt = Math.max(1, smoothedRttMs || 50);
    const rateBytesPerMs = (1.25 * this.cwnd) / rtt;
    const maxBurst = Math.max(10 * this.maxDatagramSize, Math.floor(this.cwnd / 4));

    this.pacingTokens = Math.min(maxBurst, this.pacingTokens + elapsedMs * rateBytesPerMs);
    this.pacingTokens -= bytes;
    if (this.pacingTokens >= 0) return 0;
    return Math.min(25, Math.max(1, Math.ceil(-this.pacingTokens / Math.max(1, rateBytesPerMs))));
  }

  onPacketSent(bytes) {
    if (bytes > 0) {
      this.bytesInFlight += bytes;
    }
  }

  onPacketRemoved(bytes) {
    if (bytes > 0) {
      this.bytesInFlight = Math.max(0, this.bytesInFlight - bytes);
    }
  }

  onPacketsAcked(ackedPackets, latestRttMs, minRttMs, smoothedRttMs, now = performance.now()) {
    let ackedBytes = 0;
    let latestSentTime = 0;

    for (const pkt of ackedPackets) {
      if (pkt.inFlightBytes > 0) {
        this.bytesInFlight = Math.max(0, this.bytesInFlight - pkt.inFlightBytes);
        if (!pkt.isMtuProbe) {
          ackedBytes += pkt.inFlightBytes;
          if (pkt.sentTime > latestSentTime) latestSentTime = pkt.sentTime;
        }
      }
    }

    if (ackedBytes === 0 || this.algorithm === 'unlimited') return;

    if (this.algorithm === 'bbr') {
      const sampleRtt = Math.max(1, latestRttMs || smoothedRttMs || 20);
      const bw = ackedBytes / sampleRtt;
      this.bbrSamples.push({ bw, t: now });
      if (this.bbrSamples.length > 16) this.bbrSamples.shift();
      let maxBw = bw;
      for (const s of this.bbrSamples) {
        if (s.bw > maxBw) maxBw = s.bw;
      }
      this.bbrMaxBwBytesPerMs = maxBw;
      const bdp = maxBw * Math.max(1, Number.isFinite(minRttMs) ? minRttMs : sampleRtt);
      const targetCwnd = Math.max(this.initialCwnd, Math.round(2.25 * bdp));
      this.cwnd = Math.min(this.maxCwndBytes, Math.max(this.minCwnd, targetCwnd));
      return;
    }

    // Do not grow cwnd for packets sent before entering current recovery epoch
    if (latestSentTime <= this.recoveryStartTime) {
      return;
    }

    // Slow Start
    if (this.cwnd < this.ssthresh) {
      this.cwnd = Math.min(this.maxCwndBytes, this.cwnd + ackedBytes);
      return;
    }

    // Congestion Avoidance: NewReno
    if (this.algorithm === 'newreno') {
      const inc = (this.maxDatagramSize * ackedBytes) / Math.max(1, this.cwnd);
      this.cwnd = Math.min(this.maxCwndBytes, this.cwnd + inc);
      return;
    }

    // Congestion Avoidance: CUBIC (RFC 9438)
    if (this.epochStart <= 0) {
      this.epochStart = now;
      if (this.cwnd < this.wMax) {
        const wDiffSegs = (this.wMax - this.cwnd) / this.maxDatagramSize;
        this.cubicK = Math.cbrt(wDiffSegs / this.cubicC);
        this.originPoint = this.wMax;
      } else {
        this.cubicK = 0;
        this.originPoint = this.cwnd;
      }
    }

    const rttSec = Math.max(0.001, (Number.isFinite(minRttMs) ? minRttMs : smoothedRttMs) / 1000);
    const tSec = (now - this.epochStart) / 1000 + rttSec;
    const diff = tSec - this.cubicK;
    const targetBytes =
      this.originPoint + this.cubicC * (diff * diff * diff) * this.maxDatagramSize;

    let cubicInc;
    if (targetBytes > this.cwnd) {
      cubicInc = ((targetBytes - this.cwnd) / Math.max(1, this.cwnd)) * ackedBytes;
    } else {
      cubicInc = (0.01 * this.maxDatagramSize * ackedBytes) / Math.max(1, this.cwnd);
    }

    // Reno-friendly region floor
    const renoInc = (this.maxDatagramSize * ackedBytes) / Math.max(1, this.cwnd);
    this.cwnd = Math.min(this.maxCwndBytes, this.cwnd + Math.max(cubicInc, renoInc * 0.5));
  }

  onCongestionEvent(sentTime, now = performance.now()) {
    if (this.algorithm === 'unlimited') return;
    if (sentTime <= this.recoveryStartTime) return;

    this.recoveryStartTime = now;
    this.epochStart = 0;
    this.congestionEvents++;

    if (this.algorithm === 'cubic') {
      // Fast convergence (RFC 9438 §4.6)
      if (this.cwnd < this.wMax) {
        this.wMax = this.cwnd * ((1 + this.cubicBeta) / 2);
      } else {
        this.wMax = this.cwnd;
      }
      this.ssthresh = Math.max(this.minCwnd, Math.floor(this.cwnd * this.cubicBeta));
      this.cwnd = this.ssthresh;
    } else if (this.algorithm === 'bbr') {
      this.cwnd = Math.max(this.minCwnd, Math.floor(this.cwnd * 0.85));
    } else {
      // NewReno multiplicative decrease (0.5)
      this.ssthresh = Math.max(this.minCwnd, Math.floor(this.cwnd * 0.5));
      this.cwnd = this.ssthresh;
    }
  }

  onEcnCe(ceCount, largestSentTime, now = performance.now()) {
    const ceBig = BigInt(ceCount);
    if (ceBig > this.highestEcnCe) {
      this.highestEcnCe = ceBig;
      this.onCongestionEvent(largestSentTime, now);
    }
  }

  onPathChange() {
    this.cwnd = this.initialCwnd;
    this.ssthresh = Infinity;
    this.recoveryStartTime = 0;
    this.epochStart = 0;
    this.wMax = 0;
  }

  getState() {
    return {
      algorithm: this.algorithm,
      cwnd: Math.round(this.cwnd),
      ssthresh: Number.isFinite(this.ssthresh) ? Math.round(this.ssthresh) : null,
      bytesInFlight: this.bytesInFlight,
      availableWindow:
        this.algorithm === 'unlimited' ? null : Math.round(this.availableWindow()),
      inRecovery: this.recoveryStartTime > 0 && performance.now() - this.recoveryStartTime < 200,
      congestionEvents: this.congestionEvents,
      pacing: this.pacingEnabled,
    };
  }
}

/**
 * Enterprise QUIC v1 High-Performance Client Connection
 * (RFC 9000 + RFC 9001 + RFC 9002 + RFC 8899 DPLPMTUD + RFC 9218 Priorities + RFC 9221 Datagrams).
 *
 * Includes full UDP socket configuration, `setNoDelay` / `cork` / `uncork`,
 * Active Connection Migration (`migrate`), Client-Initiated 1-RTT Key Update (`initiateKeyUpdate`),
 * Pluggable Congestion Control (`cubic` / `newreno` / `bbr` / `unlimited`), Packet Pacing,
 * Path MTU Discovery (`probeMtu`), Stateless Reset Detection, and NSS `keylog` export.
 */
class QuicConnection extends EventEmitter {
  constructor(options = {}) {
    super();
    this.host = options.host || 'localhost';
    this.port = options.port || 443;
    this.servername = options.servername ?? this.host;
    this.alpnProtocols = options.alpnProtocols || ['h3'];
    this.rejectUnauthorized = options.rejectUnauthorized !== false;
    this.ca = options.ca || null;
    this.connectTimeoutMs = options.connectTimeout ?? 10000;
    this.idleTimeoutMs = options.idleTimeout ?? 60000;
    this._configuredIdleTimeoutMs = this.idleTimeoutMs;
    this.keepAliveIntervalMs =
      options.keepAliveInterval ?? (options.keepAlive === true ? 15000 : 0);

    // DNS & Happy Eyeballs options
    this.lookup = options.lookup || null;
    this.family = options.family || 0;
    this.preferIpv6 = Boolean(options.preferIpv6);
    this.happyEyeballs = options.happyEyeballs !== false;
    this.useDnsCache = options.dnsCache !== false && !this.lookup;

    // Socket, Framing, NoDelay, Corking & ACK Delay options
    const sockOpts = options.socketOptions || {};
    this.noDelay = Boolean(options.noDelay ?? sockOpts.noDelay ?? false);
    this.ackNoDelay = Boolean(
      options.ackNoDelay ?? sockOpts.ackNoDelay ?? options.ackDelayMs === 0
    );
    this.ackDelayMs = this.ackNoDelay ? 0 : Math.max(0, options.ackDelayMs ?? 10);
    this.ackThreshold = options.ackThreshold ?? 0; // 0 = adaptive (2 early, 8 steady)
    this._corked = 0;

    this.socketOptions = {
      localAddress: options.localAddress ?? sockOpts.localAddress ?? null,
      localPort: options.localPort ?? sockOpts.localPort ?? 0,
      reuseAddr: Boolean(options.reuseAddr ?? sockOpts.reuseAddr ?? false),
      ipv6Only: Boolean(options.ipv6Only ?? sockOpts.ipv6Only ?? false),
      recvBufferSize: options.recvBufferSize ?? sockOpts.recvBufferSize ?? 1024 * 1024,
      sendBufferSize: options.sendBufferSize ?? sockOpts.sendBufferSize ?? 1024 * 1024,
      connectedUdp: options.connectedUdp ?? sockOpts.connectedUdp ?? true,
      ttl: options.ttl ?? sockOpts.ttl ?? null,
      broadcast: options.broadcast ?? sockOpts.broadcast ?? null,
      multicastTTL: options.multicastTTL ?? sockOpts.multicastTTL ?? null,
      multicastLoopback: options.multicastLoopback ?? sockOpts.multicastLoopback ?? null,
      multicastInterface: options.multicastInterface ?? sockOpts.multicastInterface ?? null,
      unref: Boolean(options.unref ?? sockOpts.unref ?? false),
      customSocket: options.customSocket ?? sockOpts.customSocket ?? null,
      createSocket: options.createSocket ?? sockOpts.createSocket ?? null,
      closeCustomSocket: Boolean(options.closeCustomSocket ?? sockOpts.closeCustomSocket ?? false),
    };

    // Session Resumption & 0-RTT configuration
    this.sessionResume = options.sessionResume !== false;
    this.enable0Rtt = options.enable0Rtt !== false && this.sessionResume;
    this.sessionStore = options.sessionStore || defaultSessionStore;
    this.sessionKey = `${this.servername || this.host}:${this.port}`;

    const cachedSession = this.sessionResume ? this.sessionStore.checkout(this.sessionKey) : null;
    this._rememberedTp = cachedSession?.peerTransportParams || null;

    this.socket = null;
    this._ownsSocket = true;
    this._socketConnected = false;
    this._unrefed = Boolean(this.socketOptions.unref);
    this._retiringSockets = new Set();

    this.remoteAddress = null;
    this.remoteFamily = 4;
    this.state = 'idle'; // 'idle' | 'connecting' | 'connected' | 'closing' | 'closed'

    // Dynamic MTU & DPLPMTUD configuration
    this.maxMtu = Math.max(INITIAL_MIN_DGRAM_SIZE, options.maxMtu || DEFAULT_MAX_MTU);
    this.maxUdpPayloadSize = Math.min(
      this.maxMtu,
      Math.max(INITIAL_MIN_DGRAM_SIZE, options.initialMtu || DEFAULT_INITIAL_MTU)
    );
    this.maxPacketPayload = this.maxUdpPayloadSize - 110;
    this.maxStreamChunk = this.maxUdpPayloadSize - 170;
    this.autoPmtud = Boolean(options.pmtud);
    this._pendingMtuProbes = new Map(); // pn -> { targetSize, resolve, timer }

    // Spin bit, Datagrams & Key Rotation configuration
    this.enableSpinBit = options.enableSpinBit !== false;
    this._spinBit = 0;
    this.enableDatagrams = options.enableDatagrams !== false;
    this.maxPacketsPerKeyPhase = options.maxPacketsPerKeyPhase || 0;

    // Congestion Controller
    this.cc = new QuicCongestionController({
      algorithm: options.congestionControl || 'cubic',
      maxDatagramSize: this.maxUdpPayloadSize,
      initialCwndPackets: options.initialCwndPackets ?? 32,
      minCwndPackets: options.minCwndPackets ?? 4,
      maxCwndBytes: options.maxCwndBytes ?? 16 * 1024 * 1024,
      pacing: Boolean(options.pacing),
    });

    // Telemetry & Benchmarks stats
    this._createdAtPerf = performance.now();
    this._connectStartPerf = 0;
    this.stats = {
      dnsMs: 0,
      handshakeMs: 0,
      resumed: false,
      earlyDataSent: false,
      earlyDataAccepted: false,
      packetsSent: 0,
      packetsReceived: 0,
      packetsLost: 0,
      packetsRetransmitted: 0,
      datagramsSent: 0,
      datagramsReceived: 0,
      quicDatagramsSent: 0,
      quicDatagramsReceived: 0,
      bytesSent: 0,
      bytesReceived: 0,
      keyUpdates: 0,
      migrations: 0,
      statelessResets: 0,
      currentMtu: this.maxUdpPayloadSize,
    };

    // Connection IDs, Stateless Reset Tokens & Cached NEW_TOKEN
    const cidLen = Math.min(20, Math.max(4, options.cidLength ?? 8));
    this.localCid = crypto.randomBytes(cidLen);
    this.localConnectionIds = new Map([
      [0, { sequenceNumber: 0, cid: this.localCid, statelessResetToken: null, retired: false }],
    ]);
    this._nextLocalCidSeq = 1;
    this.originalDcid = crypto.randomBytes(cidLen);
    this.remoteCid = Buffer.from(this.originalDcid);
    this.activePeerCidSeq = 0;
    this.peerConnectionIds = new Map(); // seq -> { sequenceNumber, retirePriorTo, cid, statelessResetToken, retired }
    this._statelessResetTokens = [];
    this.retryReceived = false;
    this.retryToken = cachedSession?.newToken ? Buffer.from(cachedSession.newToken) : Buffer.alloc(0);
    this.retryScid = null;

    // Encryption keys & Key Phase
    this.keys = {
      initial: deriveInitialSecrets(this.originalDcid),
      zeroRtt: null,
      handshake: null,
      app: null,
    };
    this.initialKeysDiscarded = false;
    this.handshakeKeysDiscarded = false;
    this.handshakeConfirmed = false;
    this.keyPhase = 0;
    this.nextServerAppKeys = null;
    this.prevServerAppKeys = null;
    this._lowestPnInCurrentKeyPhase = 0;
    this._packetsInCurrentKeyPhase = 0;
    this._keyPhaseAcked = false;
    this._awaitingPeerKeyUpdate = false;

    // Packet spaces
    this.spaces = {
      initial: new PacketSpace('initial'),
      handshake: new PacketSpace('handshake'),
      app: new PacketSpace('app'),
    };

    this.pendingPackets = {
      handshake: [],
      app: [],
    };

    // Local & peer transport parameters
    this.initStreamWindowBidi = options.initialMaxStreamDataBidiLocal ?? 16 * 1024 * 1024;
    this.initConnWindow = options.initialMaxData ?? 32 * 1024 * 1024;
    this.localTransportParams = {
      initialSourceConnectionId: this.localCid,
      maxIdleTimeout: this.idleTimeoutMs,
      maxUdpPayloadSize: this.maxMtu,
      initialMaxData: this.initConnWindow,
      initialMaxStreamDataBidiLocal: this.initStreamWindowBidi,
      initialMaxStreamDataBidiRemote: options.initialMaxStreamDataBidiRemote ?? 2 * 1024 * 1024,
      initialMaxStreamDataUni: options.initialMaxStreamDataUni ?? 4 * 1024 * 1024,
      initialMaxStreamsBidi: options.initialMaxStreamsBidi ?? 256,
      initialMaxStreamsUni: options.initialMaxStreamsUni ?? 32,
      ackDelayExponent: 3,
      maxAckDelay: 25,
      disableActiveMigration: Boolean(options.disableActiveMigration),
      activeConnectionIdLimit: options.activeConnectionIdLimit ?? 8,
      maxDatagramFrameSize: this.enableDatagrams
        ? options.maxDatagramFrameSize ?? 65535
        : undefined,
      ...(options.transportParams || {}),
    };
    this.localTransportParams.initialSourceConnectionId = this.localCid;
    this.peerTransportParams = null;

    // Connection-level flow control (pre-seeded from remembered transport params for 0-RTT if available)
    this.connSendOffset = 0;
    this.connSendMax = this._rememberedTp ? this._rememberedTp.initialMaxData : 0;
    // Peer stream concurrency limits (RFC 9000 §4.6) — remembered values gate 0-RTT, exact values after TP
    this.peerMaxStreamsBidi = this._rememberedTp ? this._rememberedTp.initialMaxStreamsBidi : Infinity;
    this.peerMaxStreamsUni = this._rememberedTp ? this._rememberedTp.initialMaxStreamsUni : Infinity;
    this._streamsBlockedSent = { bidi: -1, uni: -1 };
    this.connRecvConsumed = 0;
    this.connRecvMax = this.initConnWindow;

    // Streams, RFC 9218 Priorities & 0-RTT replay backup
    this.streams = new Map();
    this.nextBidiStreamId = 0;
    this.nextUniStreamId = 2;
    this._hasCustomPriorities = false;
    this._priorityRrCursor = 0;
    this._zeroRttBackup = new Map();
    this._appFlushScheduled = false;
    this._controlAppQueue = []; // reliable 1-RTT control frames
    this._datagramQueue = []; // unreliable RFC 9221 DATAGRAM frames

    // Active Path Challenges & Live Ping trackers
    this._pendingPathChallenges = new Map(); // hex -> { data, resolve, reject, timer, retries, sentAt }
    this._pendingPings = new Map(); // pn -> { sentAt, resolve, reject, timer }

    // RTT & Loss Recovery (RFC 9002)
    this.latestRtt = 0;
    this.smoothedRtt = 120;
    this.rttVar = 60;
    this.minRtt = Infinity;
    this.ptoCount = 0;

    // Timers
    this.ptoTimer = null;
    this.lossTimer = null;
    this.pacingTimer = null;
    this.ackTimer = null;
    this.connectTimer = null;
    this.idleTimer = null;
    this.keepAliveTimer = null;

    // AbortSignal support
    this._abortSignal = options.signal || null;
    this._abortHandler = null;
    if (this._abortSignal) {
      if (this._abortSignal.aborted) {
        queueMicrotask(() =>
          this._destroyWithError(this._abortSignal.reason || new Error('QUIC connection aborted'))
        );
      } else {
        this._abortHandler = () => {
          this._destroyWithError(this._abortSignal.reason || new Error('QUIC connection aborted'));
        };
        this._abortSignal.addEventListener('abort', this._abortHandler, { once: true });
      }
    }

    // TLS 1.3 engine with SSLKEYLOGFILE hook
    const userOnKeylog = typeof options.onKeylog === 'function' ? options.onKeylog : null;
    this.tls = new Tls13QuicClient({
      servername: this.servername,
      alpnProtocols: this.alpnProtocols,
      transportParams: this.localTransportParams,
      rejectUnauthorized: this.rejectUnauthorized,
      ca: this.ca,
      resumptionTicket: cachedSession?.ticket || null,
      enable0Rtt: this.enable0Rtt && Boolean(this._rememberedTp),
      onKeylog: (line) => {
        if (userOnKeylog) userOnKeylog(line);
        if (this.listenerCount('keylog') > 0) {
          this.emit('keylog', line);
        }
      },
    });
  }

  // ---- Runtime Socket & Connection Configuration Methods ----

  /**
   * Enables or disables `noDelay` (synchronous zero-microtask packet flushing).
   */
  setNoDelay(noDelay = true) {
    this.noDelay = Boolean(noDelay);
    if (this.noDelay && this._corked === 0 && this.state === 'connected' && this.keys.app) {
      this._flushBatchedAppPackets();
    }
    return this;
  }

  /**
   * Configures 1-RTT ACK delay (`0` enables immediate `ackNoDelay` mode) and packet threshold.
   */
  setAckDelay(delayMs = 10, threshold = 0) {
    this.ackDelayMs = Math.max(0, Number(delayMs) || 0);
    this.ackNoDelay = this.ackDelayMs === 0;
    if (threshold !== undefined) {
      this.ackThreshold = Math.max(0, Number(threshold) || 0);
    }
    if (this.ackNoDelay && this.state === 'connected' && this.spaces.app.ackPending) {
      this._sendAppAckNow();
    }
    return this;
  }

  /**
   * Corks outgoing 1-RTT frames in memory until `uncork()` is called (supports nested calls).
   */
  cork() {
    this._corked++;
    return this;
  }

  /**
   * Uncorks the connection and synchronously packs & transmits queued frames into minimal UDP datagrams.
   */
  uncork() {
    if (this._corked > 0) {
      this._corked--;
    }
    if (this._corked === 0 && this.state === 'connected' && this.keys.app) {
      this._flushBatchedAppPackets();
    }
    return this;
  }

  /**
   * Dynamically enables, updates, or disables QUIC `PING` keep-alive frames.
   */
  setKeepAlive(enable = true, intervalMs = 15000) {
    if (this.keepAliveTimer) {
      clearInterval(this.keepAliveTimer);
      this.keepAliveTimer = null;
    }
    this.keepAliveIntervalMs = enable ? Math.max(500, Number(intervalMs) || 15000) : 0;
    if (this.state === 'connected' && this.keepAliveIntervalMs > 0) {
      this._startKeepAlive();
    }
    return this;
  }

  /**
   * Dynamically updates the connection idle timeout (ms). Pass `0` to disable local idle timer.
   */
  setIdleTimeout(timeoutMs) {
    const val = Math.max(0, Number(timeoutMs) || 0);
    this._configuredIdleTimeoutMs = val;
    if (val > 0 && this.peerTransportParams && this.peerTransportParams.maxIdleTimeout > 0) {
      this.idleTimeoutMs = Math.min(val, this.peerTransportParams.maxIdleTimeout);
    } else {
      this.idleTimeoutMs = val;
    }
    this._resetIdleTimer();
    return this;
  }

  setTTL(ttl) {
    this.socketOptions.ttl = ttl;
    if (this.socket) {
      this.socket.setTTL(ttl);
    }
    return this;
  }

  setBroadcast(flag = true) {
    const bool = Boolean(flag);
    this.socketOptions.broadcast = bool;
    if (this.socket) {
      this.socket.setBroadcast(bool);
    }
    return this;
  }

  setMulticastTTL(ttl) {
    this.socketOptions.multicastTTL = ttl;
    if (this.socket) {
      this.socket.setMulticastTTL(ttl);
    }
    return this;
  }

  setMulticastLoopback(flag = true) {
    const bool = Boolean(flag);
    this.socketOptions.multicastLoopback = bool;
    if (this.socket) {
      this.socket.setMulticastLoopback(bool);
    }
    return this;
  }

  setMulticastInterface(iface) {
    this.socketOptions.multicastInterface = iface;
    if (this.socket) {
      this.socket.setMulticastInterface(iface);
    }
    return this;
  }

  setRecvBufferSize(bytes) {
    this.socketOptions.recvBufferSize = bytes;
    if (this.socket && typeof this.socket.setRecvBufferSize === 'function') {
      this.socket.setRecvBufferSize(bytes);
    }
    return this;
  }

  setSendBufferSize(bytes) {
    this.socketOptions.sendBufferSize = bytes;
    if (this.socket && typeof this.socket.setSendBufferSize === 'function') {
      this.socket.setSendBufferSize(bytes);
    }
    return this;
  }

  getRecvBufferSize() {
    if (!this.socket || typeof this.socket.getRecvBufferSize !== 'function') return null;
    try {
      return this.socket.getRecvBufferSize();
    } catch {
      return null;
    }
  }

  getSendBufferSize() {
    if (!this.socket || typeof this.socket.getSendBufferSize !== 'function') return null;
    try {
      return this.socket.getSendBufferSize();
    } catch {
      return null;
    }
  }

  ref() {
    this._unrefed = false;
    this.socketOptions.unref = false;
    this.socket?.ref?.();
    return this;
  }

  unref() {
    this._unrefed = true;
    this.socketOptions.unref = true;
    this.socket?.unref?.();
    return this;
  }

  /**
   * Bulk runtime socket & connection tuning helper.
   */
  setSocketOptions(opts = {}) {
    if (opts.noDelay !== undefined) this.setNoDelay(opts.noDelay);
    if (opts.ackDelayMs !== undefined || opts.ackThreshold !== undefined) {
      this.setAckDelay(opts.ackDelayMs ?? this.ackDelayMs, opts.ackThreshold ?? this.ackThreshold);
    }
    if (opts.ackNoDelay !== undefined) {
      this.setAckDelay(opts.ackNoDelay ? 0 : this.ackDelayMs || 10, this.ackThreshold);
    }
    if (opts.keepAlive !== undefined || opts.keepAliveInterval !== undefined) {
      const en = opts.keepAlive !== undefined ? Boolean(opts.keepAlive) : opts.keepAliveInterval > 0;
      this.setKeepAlive(en, opts.keepAliveInterval ?? (this.keepAliveIntervalMs || 15000));
    }
    if (opts.idleTimeout !== undefined) this.setIdleTimeout(opts.idleTimeout);
    if (opts.ttl !== undefined && opts.ttl !== null) this.setTTL(opts.ttl);
    if (opts.broadcast !== undefined && opts.broadcast !== null) this.setBroadcast(opts.broadcast);
    if (opts.multicastTTL !== undefined && opts.multicastTTL !== null) {
      this.setMulticastTTL(opts.multicastTTL);
    }
    if (opts.multicastLoopback !== undefined && opts.multicastLoopback !== null) {
      this.setMulticastLoopback(opts.multicastLoopback);
    }
    if (opts.multicastInterface) this.setMulticastInterface(opts.multicastInterface);
    if (opts.recvBufferSize) this.setRecvBufferSize(opts.recvBufferSize);
    if (opts.sendBufferSize) this.setSendBufferSize(opts.sendBufferSize);
    if (opts.unref === true) this.unref();
    else if (opts.unref === false) this.ref();
    return this;
  }

  /**
   * Inspects the underlying OS `dgram.Socket` state, addresses, buffer sizes, and send queue.
   */
  getSocketState() {
    let local = null;
    let sendQueueSize = null;
    let sendQueueCount = null;
    if (this.socket) {
      try {
        local = this.socket.address();
      } catch {
        local = null;
      }
      try {
        if (typeof this.socket.getSendQueueSize === 'function') {
          sendQueueSize = this.socket.getSendQueueSize();
        }
        if (typeof this.socket.getSendQueueCount === 'function') {
          sendQueueCount = this.socket.getSendQueueCount();
        }
      } catch {
        // Ignore if socket not running
      }
    }
    return {
      bound: Boolean(local),
      connectedUdp: this._socketConnected,
      unrefed: this._unrefed,
      noDelay: this.noDelay,
      ackNoDelay: this.ackNoDelay,
      ackDelayMs: this.ackDelayMs,
      corked: this._corked,
      localAddress: local?.address || null,
      localPort: local?.port || null,
      localFamily: local?.family || null,
      remoteAddress: this.remoteAddress,
      remotePort: this.port,
      recvBufferSize: this.getRecvBufferSize(),
      sendBufferSize: this.getSendBufferSize(),
      sendQueueSize,
      sendQueueCount,
      ttl: this.socketOptions.ttl,
      broadcast: Boolean(this.socketOptions.broadcast),
    };
  }

  /**
   * Returns a comprehensive diagnostic snapshot of QUIC transport, crypto, congestion, and socket state.
   */
  getDiagnostics() {
    return {
      state: this.state,
      host: this.host,
      port: this.port,
      servername: this.servername,
      remoteAddress: this.remoteAddress,
      alpn: this.tls.negotiatedAlpn,
      cipher: this.tls.suite?.name || null,
      ids: {
        localCid: this.localCid.toString('hex'),
        originalDcid: this.originalDcid.toString('hex'),
        remoteCid: this.remoteCid.toString('hex'),
        activePeerCidSeq: this.activePeerCidSeq,
        availablePeerCids: Array.from(this.peerConnectionIds.values()).filter((c) => !c.retired).length,
      },
      rtt: {
        latestRtt: +this.latestRtt.toFixed(2),
        smoothedRtt: +this.smoothedRtt.toFixed(2),
        minRtt: Number.isFinite(this.minRtt) ? +this.minRtt.toFixed(2) : null,
        rttVar: +this.rttVar.toFixed(2),
        ptoCount: this.ptoCount,
      },
      congestion: this.cc.getState(),
      flowControl: {
        connSendOffset: this.connSendOffset,
        connSendMax: this.connSendMax,
        connRecvConsumed: this.connRecvConsumed,
        connRecvMax: this.connRecvMax,
        activeStreams: this.streams.size,
      },
      mtu: {
        currentMtu: this.maxUdpPayloadSize,
        maxPacketPayload: this.maxPacketPayload,
        maxStreamChunk: this.maxStreamChunk,
        peerMaxUdpPayloadSize: this.peerTransportParams?.maxUdpPayloadSize || null,
      },
      datagrams: {
        enabled: this.enableDatagrams,
        peerMaxDatagramFrameSize: this.peerTransportParams?.maxDatagramFrameSize || 0,
        maxSendPayloadSize: this.maxPeerDatagramSize,
      },
      crypto: {
        keyPhase: this.keyPhase,
        keyUpdates: this.stats.keyUpdates,
        handshakeConfirmed: this.handshakeConfirmed,
        resumed: this.stats.resumed,
        earlyDataAccepted: this.stats.earlyDataAccepted,
      },
      socket: this.getSocketState(),
      stats: { ...this.stats },
    };
  }

  // ---- Socket Lifecycle & Connection Establishment ----

  _applyLiveSocketTunables(sock, opts) {
    if (opts.recvBufferSize && typeof sock.setRecvBufferSize === 'function') {
      try {
        sock.setRecvBufferSize(opts.recvBufferSize);
      } catch {
        // OS clamped or unsupported before bind
      }
    }
    if (opts.sendBufferSize && typeof sock.setSendBufferSize === 'function') {
      try {
        sock.setSendBufferSize(opts.sendBufferSize);
      } catch {
        // OS clamped or unsupported
      }
    }
    if (opts.ttl !== undefined && opts.ttl !== null) {
      sock.setTTL(opts.ttl);
    }
    if (opts.broadcast !== undefined && opts.broadcast !== null) {
      sock.setBroadcast(Boolean(opts.broadcast));
    }
    if (opts.multicastTTL !== undefined && opts.multicastTTL !== null) {
      sock.setMulticastTTL(opts.multicastTTL);
    }
    if (opts.multicastLoopback !== undefined && opts.multicastLoopback !== null) {
      sock.setMulticastLoopback(Boolean(opts.multicastLoopback));
    }
    if (opts.multicastInterface) {
      sock.setMulticastInterface(opts.multicastInterface);
    }
    if (opts.unref) {
      sock.unref?.();
    } else if (opts.unref === false) {
      sock.ref?.();
    }
  }

  async _createAndBindSocket(family, targetAddress, overrideOpts = {}, allowCustomSocket = true) {
    const opts = { ...this.socketOptions, ...overrideOpts };
    const udpType = family === 6 ? 'udp6' : 'udp4';
    let sock = null;
    let ownsSocket = true;

    if (allowCustomSocket && opts.customSocket) {
      sock = opts.customSocket;
      ownsSocket = Boolean(opts.closeCustomSocket);
    } else if (typeof opts.createSocket === 'function') {
      sock = opts.createSocket({ type: udpType, family, options: opts });
      ownsSocket = true;
    } else {
      sock = dgram.createSocket({
        type: udpType,
        reuseAddr: Boolean(opts.reuseAddr),
        ipv6Only: family === 6 ? Boolean(opts.ipv6Only) : false,
        recvBufferSize: opts.recvBufferSize || 1024 * 1024,
        sendBufferSize: opts.sendBufferSize || 1024 * 1024,
      });
      ownsSocket = true;
    }

    let alreadyBound = false;
    try {
      sock.address();
      alreadyBound = true;
    } catch {
      alreadyBound = false;
    }

    if (!alreadyBound) {
      await new Promise((resolve, reject) => {
        const onBindErr = (err) => reject(err);
        sock.once('error', onBindErr);
        const bindOpts = {
          port: opts.localPort || 0,
          address: opts.localAddress || undefined,
          exclusive: !opts.reuseAddr,
        };
        sock.bind(bindOpts, () => {
          sock.removeListener('error', onBindErr);
          resolve();
        });
      });
    }

    this._applyLiveSocketTunables(sock, opts);

    let isConnected = false;
    try {
      sock.remoteAddress();
      isConnected = true;
    } catch {
      isConnected = false;
    }

    const wantConnect =
      !isConnected &&
      opts.connectedUdp !== false &&
      !(allowCustomSocket && opts.customSocket && opts.connectedUdp !== true);

    if (wantConnect && typeof sock.connect === 'function') {
      isConnected = await new Promise((resolve, reject) => {
        const onConnErr = (err) => {
          // Routing failure should surface for Happy Eyeballs fallback; other errors fall back to unconnected send
          if (
            err &&
            (err.code === 'ENETUNREACH' ||
              err.code === 'EHOSTUNREACH' ||
              err.code === 'EADDRNOTAVAIL')
          ) {
            reject(err);
          } else {
            resolve(false);
          }
        };
        sock.once('error', onConnErr);
        try {
          sock.connect(this.port, targetAddress, () => {
            sock.removeListener('error', onConnErr);
            resolve(true);
          });
        } catch {
          sock.removeListener('error', onConnErr);
          resolve(false);
        }
      });
    }

    return { sock, ownsSocket, isConnected };
  }

  async connect() {
    if (this.state !== 'idle') return;
    this.state = 'connecting';
    this._connectStartPerf = performance.now();

    try {
      const tDns = performance.now();
      const candidates = await this._resolveCandidates(this.host);
      this.stats.dnsMs = +(performance.now() - tDns).toFixed(2);
      if (this.state === 'closed' || this.state === 'closing') return;

      let boundInfo = null;
      let chosen = null;
      let lastSocketErr = null;

      for (let i = 0; i < candidates.length; i++) {
        const cand = candidates[i];
        try {
          boundInfo = await this._createAndBindSocket(cand.family, cand.address, {}, true);
          chosen = cand;
          break;
        } catch (err) {
          lastSocketErr = err;
          if (!this.happyEyeballs || i === candidates.length - 1) {
            throw err;
          }
        }
      }

      if (!boundInfo || !chosen) {
        throw lastSocketErr || new Error(`Unable to bind UDP socket for ${this.host}:${this.port}`);
      }

      if (this.state === 'closed' || this.state === 'closing') {
        if (boundInfo.ownsSocket) {
          try {
            boundInfo.sock.close();
          } catch {
            // Ignore
          }
        }
        return;
      }

      this.remoteAddress = chosen.address;
      this.remoteFamily = chosen.family;
      this.socket = boundInfo.sock;
      this._ownsSocket = boundInfo.ownsSocket;
      this._socketConnected = boundInfo.isConnected;
      this._unrefed = Boolean(this.socketOptions.unref);

      this._attachSocketHandlers(this.socket);

      if (this.connectTimeoutMs > 0) {
        this.connectTimer = setTimeout(() => {
          if (this.state === 'connecting') {
            this._destroyWithError(
              new Error(
                `QUIC handshake timed out after ${this.connectTimeoutMs}ms (${this.host}:${this.port})`
              )
            );
          }
        }, this.connectTimeoutMs);
        this.connectTimer.unref?.();
      }

      // Yield one microtask before building initial flight so synchronous `client.request()` calls
      // right after `http3.connect()` get coalesced into the VERY FIRST 0-RTT UDP datagram
      await Promise.resolve();
      if (this.state !== 'connecting') return;

      this._sendInitialClientHelloAndZeroRtt();
      this._resetIdleTimer();
    } catch (err) {
      this._destroyWithError(err);
    }
  }

  _attachSocketHandlers(sock) {
    sock.on('message', (msg) => this._onUdpDatagram(msg));
    sock.on('error', (err) => {
      if (sock === this.socket) {
        this._destroyWithError(err);
      }
    });
  }

  _resolveCandidates(host) {
    const ipFam = net.isIP(host);
    if (ipFam !== 0) {
      return Promise.resolve([{ address: host, family: ipFam }]);
    }
    const cacheKey = `${host}:${this.family}:${this.preferIpv6 ? 6 : 4}`;
    if (this.useDnsCache) {
      const cached = defaultDnsCache.get(cacheKey);
      if (cached) return Promise.resolve(cached);
    }
    return new Promise((resolve, reject) => {
      const lookupFn = this.lookup || dns.lookup;
      const opts = this.family ? { family: this.family } : { all: true };
      lookupFn(host, opts, (err, res, fam) => {
        if (err) return reject(err);
        let list;
        if (Array.isArray(res)) {
          if (res.length === 0) {
            return reject(new Error(`DNS lookup returned no addresses for ${host}`));
          }
          const primaryFam = this.preferIpv6 ? 6 : 4;
          const primary = res.filter((r) => r.family === primaryFam);
          const secondary = res.filter((r) => r.family !== primaryFam);
          list = [...primary, ...secondary];
        } else {
          list = [{ address: res, family: fam || 4 }];
        }
        if (this.useDnsCache) {
          defaultDnsCache.set(cacheKey, list);
        }
        resolve(list);
      });
    });
  }

  // ---- Advanced QUIC Operations: Migration, Key Update, PMTUD, Datagrams, Ping ----

  _replenishLocalConnectionIds(sendImmediately = false) {
    if (!this.keys.app || this.state !== 'connected') return;
    const peerLimit = Math.min(
      4,
      Math.max(2, this.peerTransportParams?.activeConnectionIdLimit || 2)
    );
    let activeCount = 0;
    for (const entry of this.localConnectionIds.values()) {
      if (!entry.retired) activeCount++;
    }

    const frames = [];
    while (activeCount < peerLimit) {
      const seq = this._nextLocalCidSeq++;
      const cid = crypto.randomBytes(this.localCid.length);
      const token = crypto.randomBytes(16);
      this.localConnectionIds.set(seq, {
        sequenceNumber: seq,
        cid,
        statelessResetToken: token,
        retired: false,
      });
      frames.push(buildNewConnectionIdFrame(seq, 0, cid, token));
      activeCount++;
    }

    if (frames.length > 0) {
      if (sendImmediately) {
        this._sendAppPacket(frames, frames);
      } else {
        this._controlAppQueue.push(...frames);
        this._triggerAppFlush();
      }
    }
  }

  /**
   * Active Connection Migration & Path Validation (RFC 9000 §9).
   * Binds a new local UDP socket (new port/interface), rotates to a spare peer Connection ID if available,
   * validates the new path via 1200-byte padded `PATH_CHALLENGE` / `PATH_RESPONSE`, and retires the old socket.
   */
  async migrate(newSocketOpts = {}) {
    if (this.state !== 'connected' || !this.keys.app) {
      throw new Error('Cannot migrate QUIC connection before handshake is connected');
    }
    if (
      this.peerTransportParams?.disableActiveMigration &&
      newSocketOpts.localAddress &&
      !newSocketOpts.force
    ) {
      throw new Error(
        'Peer disabled active IP address migration via transport parameters (pass { force: true } to override)'
      );
    }

    // Ensure peer has spare local CIDs from us per RFC 9000 §9.5 before switching paths
    if (this._nextLocalCidSeq <= 1) {
      this._replenishLocalConnectionIds(true);
    }

    const oldSocket = this.socket;
    const oldOwnsSocket = this._ownsSocket;
    const oldPort = this.getSocketState().localPort;

    // Bind new socket on a fresh port (default localPort: 0 unless user explicitly requested a specific port)
    const migOpts = {
      localPort: 0,
      ...newSocketOpts,
      customSocket: newSocketOpts.customSocket || null,
    };
    const { sock: newSock, ownsSocket, isConnected } = await this._createAndBindSocket(
      this.remoteFamily,
      this.remoteAddress,
      migOpts,
      Boolean(newSocketOpts.customSocket)
    );

    if (this.state !== 'connected') {
      if (ownsSocket) {
        try {
          newSock.close();
        } catch {
          // Ignore
        }
      }
      throw new Error('QUIC connection closed during migration');
    }

    this._attachSocketHandlers(newSock);

    // Switch to an unused peer Connection ID if server issued NEW_CONNECTION_ID frames (RFC 9000 §9.5)
    let switchedCid = false;
    let retiredSeq = null;
    for (const entry of this.peerConnectionIds.values()) {
      if (!entry.retired && entry.sequenceNumber !== this.activePeerCidSeq && entry.cid.length > 0) {
        retiredSeq = this.activePeerCidSeq;
        const prevEntry = this.peerConnectionIds.get(retiredSeq);
        if (prevEntry) prevEntry.retired = true;

        this.remoteCid = Buffer.from(entry.cid);
        this.activePeerCidSeq = entry.sequenceNumber;
        switchedCid = true;
        break;
      }
    }

    // Swap active socket while keeping oldSocket listening during grace window for in-flight packets
    this.socket = newSock;
    this._ownsSocket = ownsSocket;
    this._socketConnected = isConnected;
    if (migOpts.localAddress !== undefined) this.socketOptions.localAddress = migOpts.localAddress;
    if (newSocketOpts.localPort !== undefined) this.socketOptions.localPort = newSocketOpts.localPort;

    if (oldSocket && oldSocket !== newSock) {
      this._retiringSockets.add(oldSocket);
      const graceMs = newSocketOpts.graceMs ?? 1500;
      setTimeout(() => {
        this._retiringSockets.delete(oldSocket);
        if (oldOwnsSocket) {
          try {
            oldSocket.removeAllListeners();
            oldSocket.close();
          } catch {
            // Ignore
          }
        }
      }, graceMs).unref?.();
    }

    this.cc.onPathChange();
    this.stats.migrations++;

    if (switchedCid && retiredSeq !== null) {
      this._controlAppQueue.push(buildRetireConnectionIdFrame(retiredSeq));
    }

    const newLocal = this.getSocketState();
    const validationRttMs = await this.validatePath(newSocketOpts.validationTimeoutMs ?? 3000);

    const migInfo = {
      oldLocalPort: oldPort,
      newLocalPort: newLocal.localPort,
      localAddress: newLocal.localAddress,
      dcidSeq: this.activePeerCidSeq,
      switchedCid,
      validationRttMs,
    };
    this.emit('migration', migInfo);
    return migInfo;
  }

  /**
   * Sends an RFC 9000 §8.2 1200-byte padded `PATH_CHALLENGE` and awaits matching `PATH_RESPONSE`.
   */
  validatePath(timeoutMs = 3000) {
    if (this.state !== 'connected' || !this.keys.app) {
      return Promise.reject(new Error('QUIC connection is not connected'));
    }
    const challenge = crypto.randomBytes(8);
    const key = challenge.toString('hex');
    const sentAt = performance.now();

    const sendProbe = () => {
      if (this.state !== 'connected' || !this.keys.app) return;
      const frame = buildPathChallengeFrame(challenge);
      this._sendAppPacket([frame], [], INITIAL_MIN_DGRAM_SIZE);
    };

    return new Promise((resolve, reject) => {
      let retries = 0;
      const maxRetries = 3;
      const stepMs = Math.max(200, Math.floor(timeoutMs / (maxRetries + 1)));

      const retryInterval = setInterval(() => {
        retries++;
        if (retries > maxRetries || this.state !== 'connected') {
          clearInterval(retryInterval);
          this._pendingPathChallenges.delete(key);
          reject(new Error(`QUIC PATH_CHALLENGE validation timed out after ${timeoutMs}ms`));
          return;
        }
        sendProbe();
      }, stepMs);
      retryInterval.unref?.();

      this._pendingPathChallenges.set(key, {
        data: challenge,
        sentAt,
        timer: retryInterval,
        resolve: (rttMs) => {
          clearInterval(retryInterval);
          this.emit('pathValidated', { challenge: key, rttMs });
          resolve(rttMs);
        },
        reject: (err) => {
          clearInterval(retryInterval);
          reject(err);
        },
      });

      sendProbe();
    });
  }

  /**
   * Initiates a live 1-RTT QUIC Key Update (RFC 9001 §6).
   * Rotates AEAD packet protection keys without interrupting active streams while retaining
   * previous server keys for any reordered in-flight packets.
   */
  initiateKeyUpdate() {
    if (this.state !== 'connected' || !this.keys.app) {
      throw new Error('Cannot initiate key update before 1-RTT connection is established');
    }
    if (!this.handshakeConfirmed) {
      throw new Error('Cannot initiate key update before HANDSHAKE_DONE confirmation (RFC 9001 §6.1)');
    }
    if (!this._keyPhaseAcked && this.stats.keyUpdates > 0) {
      throw new Error(
        'Cannot initiate another key update before current key phase is acknowledged by peer (RFC 9001 §6.2)'
      );
    }

    this.prevServerAppKeys = this.keys.app.server;
    this.keys.app.server = this.nextServerAppKeys || deriveUpdatedKeys(this.keys.app.server);
    this.nextServerAppKeys = deriveUpdatedKeys(this.keys.app.server);
    this.keys.app.client = deriveUpdatedKeys(this.keys.app.client);

    this.keyPhase ^= 1;
    this._lowestPnInCurrentKeyPhase = this.spaces.app.nextPn;
    this._packetsInCurrentKeyPhase = 0;
    this._keyPhaseAcked = false;
    this._awaitingPeerKeyUpdate = true;
    this.stats.keyUpdates++;

    // Send an immediate PING protected under the new key phase so the peer rotates right away
    const ping = buildPingFrame();
    this._sendAppPacket([ping], [ping]);

    const info = { keyPhase: this.keyPhase, keyUpdates: this.stats.keyUpdates, initiator: 'client' };
    this.emit('keyUpdate', info);
    return info;
  }

  /**
   * DPLPMTUD Path MTU Probe (RFC 8899 / RFC 9000 §14.4).
   * Sends a non-congestion-loss padded PING datagram of `targetSize` bytes; upgrades connection MTU if ACKed.
   */
  probeMtu(targetSize = 1452, timeoutMs = 1500) {
    if (this.state !== 'connected' || !this.keys.app) {
      return Promise.reject(new Error('QUIC connection is not connected'));
    }
    const peerMax = this.peerTransportParams?.maxUdpPayloadSize || this.maxMtu;
    const clampedTarget = Math.min(peerMax, Math.min(this.maxMtu, Math.floor(targetSize)));
    if (clampedTarget <= this.maxUdpPayloadSize) {
      return Promise.resolve({
        ok: true,
        mtu: this.maxUdpPayloadSize,
        peerMaxMtu: peerMax,
        unchanged: true,
      });
    }

    const ping = buildPingFrame();
    const pn = this._sendAppPacket([ping], [], clampedTarget, true);

    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        const entry = this._pendingMtuProbes.get(pn);
        if (entry) {
          this._pendingMtuProbes.delete(pn);
          const sentInfo = this.spaces.app.sentPackets.get(pn);
          if (sentInfo) {
            this.spaces.app.sentPackets.delete(pn);
            this.cc.onPacketRemoved(sentInfo.inFlightBytes);
          }
          resolve({
            ok: false,
            mtu: this.maxUdpPayloadSize,
            peerMaxMtu: peerMax,
            attempted: clampedTarget,
          });
        }
      }, timeoutMs);
      timer.unref?.();

      this._pendingMtuProbes.set(pn, {
        targetSize: clampedTarget,
        peerMax,
        timer,
        resolve,
      });
    });
  }

  _runAutoPmtud() {
    if (!this.autoPmtud || this.state !== 'connected') return;
    (async () => {
      for (const candidate of [1400, 1452, 1472]) {
        if (this.state !== 'connected') break;
        const peerMax = this.peerTransportParams?.maxUdpPayloadSize || this.maxMtu;
        if (candidate > peerMax || candidate <= this.maxUdpPayloadSize) continue;
        const res = await this.probeMtu(candidate, 1000);
        if (!res.ok) break;
      }
    })().catch(() => {});
  }

  _upgradeMtu(newMtu) {
    if (newMtu <= this.maxUdpPayloadSize) return;
    const oldMtu = this.maxUdpPayloadSize;
    this.maxUdpPayloadSize = newMtu;
    this.maxPacketPayload = newMtu - 110;
    this.maxStreamChunk = newMtu - 170;
    this.stats.currentMtu = newMtu;
    this.cc.setMtu(newMtu);
    this.emit('mtuChange', { oldMtu, newMtu });
  }

  /**
   * Maximum payload size accepted by peer for RFC 9221 QUIC `DATAGRAM` frames.
   */
  get maxPeerDatagramSize() {
    const peerMaxFrame = this.peerTransportParams?.maxDatagramFrameSize || 0;
    if (peerMaxFrame <= 0) return 0;
    return Math.max(0, Math.min(peerMaxFrame - 4, this.maxPacketPayload - 4));
  }

  /**
   * Sends an unreliable QUIC `DATAGRAM` frame (RFC 9221).
   */
  sendDatagram(data) {
    if (this.state !== 'connected' || !this.keys.app) {
      throw new Error('Cannot send QUIC DATAGRAM before connection is established');
    }
    const maxBytes = this.maxPeerDatagramSize;
    if (maxBytes <= 0) {
      throw new Error('Peer did not advertise RFC 9221 max_datagram_frame_size support');
    }
    const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
    if (buf.length > maxBytes) {
      throw new RangeError(`QUIC DATAGRAM payload (${buf.length}B) exceeds max (${maxBytes}B)`);
    }
    this._datagramQueue.push(buildDatagramFrame(buf, true));
    this.stats.quicDatagramsSent++;
    this._triggerAppFlush();
    return true;
  }

  /**
   * Measures live QUIC round-trip latency (ms) by sending an ack-eliciting `PING` and awaiting its `ACK`.
   */
  ping(timeoutMs = 5000) {
    if (this.state !== 'connected' || !this.keys.app) {
      return Promise.reject(new Error('QUIC connection is not connected'));
    }
    const pingFrame = buildPingFrame();
    const sentAt = performance.now();
    const pn = this._sendAppPacket([pingFrame], [pingFrame]);

    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this._pendingPings.delete(pn);
        reject(new Error(`QUIC PING timed out after ${timeoutMs}ms`));
      }, timeoutMs);
      timer.unref?.();

      this._pendingPings.set(pn, { sentAt, timer, resolve, reject });
    });
  }

  // ---- Initial Handshake & 0-RTT Flight ----

  _sendInitialClientHelloAndZeroRtt() {
    const clientHello = this.tls.buildClientHello();
    this.keys.zeroRtt = this.tls.earlyDataKeys;

    // Collect 0-RTT frames if 0-RTT keys are active and streams were queued
    let zeroRttFrames = [];
    if (this.keys.zeroRtt) {
      zeroRttFrames = this._drainStreamFramesForPacket(this.maxPacketPayload, true);
    }

    // Fast single-datagram coalesced [Initial(ClientHello) || 0-RTT(SETTINGS + Request)] when <= MTU
    if (clientHello.length <= MAX_INITIAL_CRYPTO_CHUNK && zeroRttFrames.length > 0) {
      const initSpace = this.spaces.initial;
      const cryptoFrame = buildCryptoFrame(initSpace.cryptoSendOffset, clientHello);
      initSpace.cryptoSendOffset += clientHello.length;
      const initPn = initSpace.nextPn++;

      const unpaddedInitPkt = buildInitialPacket({
        dcid: this.remoteCid,
        scid: this.localCid,
        token: this.retryToken,
        packetNumber: initPn,
        largestAcked: initSpace.largestAckedSent,
        payload: cryptoFrame,
        keys: this.keys.initial.client,
        minPacketSize: 0,
      });

      const zeroPayload = Buffer.concat(zeroRttFrames);
      const estZeroLen =
        1 + 4 + 2 + this.remoteCid.length + this.localCid.length + 2 + 2 + zeroPayload.length + 16;

      if (unpaddedInitPkt.length + estZeroLen <= this.maxUdpPayloadSize) {
        const appSpace = this.spaces.app;
        const zeroPn = appSpace.nextPn++;
        const minZeroSize = Math.max(0, INITIAL_MIN_DGRAM_SIZE - unpaddedInitPkt.length);
        const zeroPkt = buildZeroRttPacket({
          dcid: this.remoteCid,
          scid: this.localCid,
          packetNumber: zeroPn,
          largestAcked: appSpace.largestAckedSent,
          payload: zeroPayload,
          keys: this.keys.zeroRtt,
          minPacketSize: minZeroSize,
        });

        const now = performance.now();
        this._recordSentPacket(initSpace, initPn, unpaddedInitPkt.length, [cryptoFrame], {
          sentTime: now,
        });
        this._recordSentPacket(appSpace, zeroPn, zeroPkt.length, zeroRttFrames, {
          sentTime: now,
          isZeroRtt: true,
        });

        this.stats.packetsSent += 2;
        this.stats.earlyDataSent = true;
        this._sendRawDatagram(Buffer.concat([unpaddedInitPkt, zeroPkt]));
        this._flushRemainingZeroRttPackets();
        this._schedulePto();
        return;
      }
    }

    // Standard Initial flight (padded to 1200 bytes) + optional separate 0-RTT packets
    this._queueAndSendCrypto('initial', clientHello);
    if (zeroRttFrames.length > 0 && this.keys.zeroRtt) {
      this._sendZeroRttPacket(zeroRttFrames);
      this._flushRemainingZeroRttPackets();
    }
  }

  _sendZeroRttPacket(frames) {
    if (!this.keys.zeroRtt || frames.length === 0) return;
    const appSpace = this.spaces.app;
    const pn = appSpace.nextPn++;
    const pkt = buildZeroRttPacket({
      dcid: this.remoteCid,
      scid: this.localCid,
      packetNumber: pn,
      largestAcked: appSpace.largestAckedSent,
      payload: Buffer.concat(frames),
      keys: this.keys.zeroRtt,
    });
    this._recordSentPacket(appSpace, pn, pkt.length, frames, { isZeroRtt: true });
    this.stats.packetsSent++;
    this.stats.earlyDataSent = true;
    this._sendRawDatagram(pkt);
    this._schedulePto();
  }

  _flushRemainingZeroRttPackets() {
    while (this.keys.zeroRtt && this.state === 'connecting') {
      const frames = this._drainStreamFramesForPacket(this.maxPacketPayload, true);
      if (frames.length === 0) break;
      this._sendZeroRttPacket(frames);
    }
  }

  // ---- Stream & Priority API (RFC 9218) ----

  openBidiStream(priority = null) {
    const id = this.nextBidiStreamId;
    this.nextBidiStreamId += 4;
    const st = this._getOrCreateStream(id);
    if (priority) this.setStreamPriority(id, priority);
    return st;
  }

  openUniStream(priority = null) {
    const id = this.nextUniStreamId;
    this.nextUniStreamId += 4;
    const st = this._getOrCreateStream(id);
    if (priority) this.setStreamPriority(id, priority);
    return st;
  }

  /**
   * Configures RFC 9218 Extensible HTTP/3 Priority (`urgency: 0..7`, `incremental: boolean`) on a stream.
   */
  setStreamPriority(streamId, { urgency = 3, incremental = false } = {}) {
    const st = this._getOrCreateStream(streamId);
    const clampedUrgency = Math.min(7, Math.max(0, Math.floor(Number(urgency) ?? 3)));
    st.urgency = clampedUrgency;
    st.incremental = Boolean(incremental);
    if (clampedUrgency !== 3 || st.incremental) {
      this._hasCustomPriorities = true;
    }
    return this;
  }

  getStreamPriority(streamId) {
    const st = this.streams.get(streamId);
    if (!st) return { urgency: 3, incremental: false };
    return { urgency: st.urgency, incremental: st.incremental };
  }

  _getOrCreateStream(streamId) {
    let st = this.streams.get(streamId);
    if (st) return st;

    const isClientInitiated = (streamId & 0x01) === 0;
    const isUni = (streamId & 0x02) !== 0;

    const tp = this.peerTransportParams || this._rememberedTp;
    let maxSend = Infinity;
    if (tp) {
      if (isUni) {
        maxSend = tp.initialMaxStreamDataUni;
      } else if (isClientInitiated) {
        maxSend = tp.initialMaxStreamDataBidiRemote;
      } else {
        maxSend = tp.initialMaxStreamDataBidiLocal;
      }
    }

    st = {
      id: streamId,
      isClientInitiated,
      isUni,
      urgency: isUni ? 0 : 3, // Control/QPACK uni streams get urgency 0 automatically
      incremental: false,
      sendOffset: 0,
      maxSendOffset: maxSend,
      sendQueue: [],
      finSent: false,
      recvReassembler: new ByteReassembler(),
      recvConsumed: 0,
      recvMaxOffset: isUni ? 4 * 1024 * 1024 : this.initStreamWindowBidi,
      resetReceived: false,
    };
    this.streams.set(streamId, st);
    return st;
  }

  /**
   * Queues stream data and dispatches immediately in `noDelay` mode, holds while `cork()`ed,
   * or batches via microtask packet packing by default.
   */
  sendStreamData(streamId, data, fin = false, allow0Rtt = true) {
    if (this.state === 'closing' || this.state === 'closed') {
      throw new Error('QUIC connection is closed');
    }
    const st = this._getOrCreateStream(streamId);
    const buf = data ? (Buffer.isBuffer(data) ? data : Buffer.from(data)) : Buffer.alloc(0);
    const last = st.sendQueue.length > 0 ? st.sendQueue[st.sendQueue.length - 1] : null;
    if (last && !last.fin && last.allow0Rtt === allow0Rtt) {
      if (buf.length > 0) {
        last.data = last.data.length === 0 ? buf : Buffer.concat([last.data, buf]);
      }
      if (fin) last.fin = true;
    } else {
      st.sendQueue.push({ data: buf, fin: Boolean(fin), allow0Rtt });
    }

    if (this.state === 'connected') {
      this._triggerAppFlush();
    } else if (this.state === 'connecting' && this.keys.zeroRtt && this.socket && allow0Rtt) {
      this._flushRemainingZeroRttPackets();
    }
  }

  resetStream(streamId, errorCode = 0x010c) {
    const st = this.streams.get(streamId);
    if (!st || this.state !== 'connected') return;
    st.sendQueue.length = 0;
    const resetFrame = buildResetStreamFrame(streamId, errorCode, st.sendOffset);
    const stopFrame = buildStopSendingFrame(streamId, errorCode);
    this._controlAppQueue.push(resetFrame, stopFrame);
    this._triggerAppFlush();
  }

  _triggerAppFlush() {
    if (this._corked > 0 || this.state !== 'connected' || !this.keys.app) return;
    if (this.noDelay) {
      this._flushBatchedAppPackets();
    } else {
      this._scheduleAppFlush();
    }
  }

  _scheduleAppFlush() {
    if (
      this._corked > 0 ||
      this._appFlushScheduled ||
      this.state !== 'connected' ||
      !this.keys.app
    ) {
      return;
    }
    this._appFlushScheduled = true;
    queueMicrotask(() => {
      this._appFlushScheduled = false;
      if (this._corked === 0) {
        this._flushBatchedAppPackets();
      }
    });
  }

  /**
   * Packs pending control frames + unreliable DATAGRAMs + prioritized STREAM frames into dense 1-RTT packets,
   * respecting congestion window (`cwnd`) and optional packet pacing.
   */
  _flushBatchedAppPackets() {
    if (this._corked > 0 || this.state !== 'connected' || !this.keys.app) return;
    if (this.pacingTimer) return; // Waiting for pacer token refill

    while (true) {
      const reliableFrames = [];
      const unreliableFrames = [];
      let budget = this.maxPacketPayload;

      // 1. Control frames always go first (FLOW CONTROL / RESET / RETIRE_CID / PATH_RESPONSE)
      while (this._controlAppQueue.length > 0 && this._controlAppQueue[0].length <= budget) {
        const cf = this._controlAppQueue.shift();
        reliableFrames.push(cf);
        budget -= cf.length;
      }

      // 2. Unreliable RFC 9221 DATAGRAM frames (not retransmitted on loss)
      while (
        this._datagramQueue.length > 0 &&
        this._datagramQueue[0].length <= budget &&
        this.cc.canSend(this._datagramQueue[0].length)
      ) {
        const df = this._datagramQueue.shift();
        unreliableFrames.push(df);
        budget -= df.length;
      }

      // 3. Stream data frames (bounded by remaining packet MTU AND congestion window)
      const cwndAvail = this.cc.availableWindow();
      const streamBudget =
        Number.isFinite(cwndAvail) ? Math.min(budget, Math.max(0, cwndAvail)) : budget;
      const streamFrames =
        streamBudget > 20 ? this._drainStreamFramesForPacket(streamBudget, false) : [];
      reliableFrames.push(...streamFrames);

      const allPayloadFrames =
        unreliableFrames.length > 0
          ? [...reliableFrames.slice(0, reliableFrames.length - streamFrames.length), ...unreliableFrames, ...streamFrames]
          : reliableFrames;

      if (allPayloadFrames.length === 0) {
        if (this._controlAppQueue.length > 0) continue;
        break;
      }

      const approxBytes = allPayloadFrames.reduce((acc, b) => acc + b.length, 28);
      const paceWaitMs = this.cc.consumePacingTokens(approxBytes, this.smoothedRtt);

      this._sendAppPacket(allPayloadFrames, reliableFrames);

      // Automatic Key Phase rotation if maxPacketsPerKeyPhase is configured
      if (
        this.maxPacketsPerKeyPhase > 0 &&
        this.handshakeConfirmed &&
        this._keyPhaseAcked &&
        this._packetsInCurrentKeyPhase >= this.maxPacketsPerKeyPhase
      ) {
        try {
          this.initiateKeyUpdate();
        } catch {
          // Ignore if already rotating
        }
      }

      if (paceWaitMs > 0 && this._hasPendingAppData()) {
        this.pacingTimer = setTimeout(() => {
          this.pacingTimer = null;
          this._flushBatchedAppPackets();
        }, paceWaitMs);
        this.pacingTimer.unref?.();
        break;
      }
    }
  }

  _hasPendingAppData() {
    if (this._controlAppQueue.length > 0 || this._datagramQueue.length > 0) return true;
    for (const st of this.streams.values()) {
      if (st.sendQueue.length > 0) return true;
    }
    return false;
  }

  _getOrderedWritableStreams() {
    if (!this._hasCustomPriorities) {
      return this.streams.values();
    }
    const active = [];
    for (const st of this.streams.values()) {
      if (st.sendQueue.length > 0) active.push(st);
    }
    if (active.length <= 1) return active;

    active.sort((a, b) => a.urgency - b.urgency || a.id - b.id);

    // Rotate incremental streams within equal urgency buckets for fair round-robin interleaving
    if (this._priorityRrCursor > 0) {
      let i = 0;
      while (i < active.length) {
        let j = i + 1;
        while (j < active.length && active[j].urgency === active[i].urgency) j++;
        if (j - i > 1 && active.slice(i, j).some((s) => s.incremental)) {
          const group = active.slice(i, j);
          const rot = this._priorityRrCursor % group.length;
          for (let k = 0; k < group.length; k++) {
            active[i + k] = group[(k + rot) % group.length];
          }
        }
        i = j;
      }
    }
    this._priorityRrCursor = (this._priorityRrCursor + 1) >>> 0;
    return active;
  }

  /**
   * Drains up to `byteBudget` bytes of STREAM frames across active streams respecting RFC 9218 priorities.
   * When `isZeroRtt === true`, records backup copies in `_zeroRttBackup` for RFC 9001 §4.6.2 fallback.
   */
  _isStreamWithinPeerLimit(st) {
    if (!st.isClientInitiated) return true;
    const ordinal = Math.floor(st.id / 4);
    const limit = st.isUni ? this.peerMaxStreamsUni : this.peerMaxStreamsBidi;
    if (ordinal < limit) return true;
    // Tell the peer we are blocked on its stream limit once per limit value (RFC 9000 §19.14)
    const key = st.isUni ? 'uni' : 'bidi';
    if (Number.isFinite(limit) && this._streamsBlockedSent[key] !== limit && this.keys.app) {
      this._streamsBlockedSent[key] = limit;
      this._controlAppQueue.push(buildStreamsBlockedFrame(limit, !st.isUni));
    }
    return false;
  }

  /**
   * Number of additional client-initiated bidirectional streams the peer currently allows.
   */
  get availableBidiStreams() {
    const opened = this.nextBidiStreamId / 4;
    return Number.isFinite(this.peerMaxStreamsBidi)
      ? Math.max(0, this.peerMaxStreamsBidi - opened)
      : Infinity;
  }

  _drainStreamFramesForPacket(byteBudget, isZeroRtt = false) {
    const frames = [];
    let remainingBudget = byteBudget;
    const iterable = this._getOrderedWritableStreams();

    for (const st of iterable) {
      if (st.sendQueue.length === 0) continue;
      if (!this._isStreamWithinPeerLimit(st)) continue;
      while (st.sendQueue.length > 0 && remainingBudget > 16) {
        const item = st.sendQueue[0];
        if (isZeroRtt && item.allow0Rtt === false) break;

        const streamCredit = st.maxSendOffset - st.sendOffset;
        const connCredit = this.connSendMax - this.connSendOffset;
        const availableCredit = Math.min(streamCredit, connCredit);

        if (item.data.length > 0 && availableCredit <= 0) {
          break;
        }

        // For incremental streams, yield after 1 fair quantum (~half packet) if other streams exist
        const quantumCap =
          st.incremental && this._hasCustomPriorities
            ? Math.max(256, Math.floor(this.maxStreamChunk / 2))
            : this.maxStreamChunk;

        const maxDataBytes = Math.min(
          item.data.length,
          quantumCap,
          remainingBudget - 12,
          Math.max(0, availableCredit)
        );
        if (maxDataBytes <= 0 && item.data.length > 0) {
          break;
        }

        const chunk = item.data.subarray(0, maxDataBytes);
        const isLastPart = maxDataBytes === item.data.length;
        const sendFin = isLastPart && item.fin && !st.finSent;

        if (isLastPart) {
          st.sendQueue.shift();
        } else {
          item.data = item.data.subarray(maxDataBytes);
        }

        if (chunk.length === 0 && !sendFin) {
          continue;
        }

        if (isZeroRtt) {
          let backup = this._zeroRttBackup.get(st.id);
          if (!backup) {
            backup = [];
            this._zeroRttBackup.set(st.id, backup);
          }
          backup.push({ data: Buffer.from(chunk), fin: sendFin, allow0Rtt: true });
        }

        const frame = buildStreamFrame(st.id, st.sendOffset, chunk, sendFin, true);
        st.sendOffset += chunk.length;
        this.connSendOffset += chunk.length;
        if (sendFin) st.finSent = true;

        frames.push(frame);
        remainingBudget -= frame.length;

        if (st.incremental && this._hasCustomPriorities) {
          break; // Yield to next equal-urgency incremental stream
        }
      }
      if (remainingBudget <= 20) break;
    }

    return frames;
  }

  /**
   * Restores 0-RTT stream data into stream sendQueues if server rejected 0-RTT or sent Retry.
   */
  _rollbackZeroRttStreams() {
    this.keys.zeroRtt = null;
    for (const [pn, info] of this.spaces.app.sentPackets) {
      if (info.isZeroRtt) {
        this.spaces.app.sentPackets.delete(pn);
        this.cc.onPacketRemoved(info.inFlightBytes);
      }
    }
    this.connSendOffset = 0;
    for (const [streamId, items] of this._zeroRttBackup.entries()) {
      const st = this.streams.get(streamId);
      if (st) {
        st.sendOffset = 0;
        st.finSent = false;
        st.sendQueue = items.concat(st.sendQueue);
      }
    }
    this._zeroRttBackup.clear();
  }

  // ---- Incoming UDP Datagram Processing & Stateless Reset Detection ----

  _onUdpDatagram(datagram) {
    if (this.state === 'closed') return;
    this.stats.datagramsReceived++;
    this.stats.bytesReceived += datagram.length;
    this._resetIdleTimer();

    const packets = splitDatagram(datagram, this.localCid.length);
    for (const pkt of packets) {
      this._processIncomingPacket(pkt, datagram);
    }

    this._flushPendingAcks();
  }

  _checkStatelessReset(datagram) {
    if (datagram.length < 21 || this._statelessResetTokens.length === 0) return false;
    const tail = datagram.subarray(datagram.length - 16);
    for (const tok of this._statelessResetTokens) {
      if (tok.length === 16 && crypto.timingSafeEqual(tail, tok)) {
        return true;
      }
    }
    return false;
  }

  _registerStatelessResetToken(token) {
    if (!token || token.length !== 16) return;
    for (const existing of this._statelessResetTokens) {
      if (existing.equals(token)) return;
    }
    this._statelessResetTokens.push(Buffer.from(token));
  }

  _processIncomingPacket(pkt, fullDatagram = null) {
    try {
      if (pkt.type === 'version_negotiation') {
        if (this.stats.packetsReceived > 0 || this.retryReceived) return;
        if (!pkt.supportedVersions.includes(0x00000001)) {
          this._destroyWithError(new Error('Server does not support QUIC v1'));
        }
        return;
      }

      if (pkt.type === 'retry') {
        if (this.retryReceived) return;
        if (!verifyRetryIntegrityTag(this.originalDcid, pkt.raw)) {
          return;
        }
        this.retryReceived = true;
        this.remoteCid = Buffer.from(pkt.scid);
        this.retryScid = Buffer.from(pkt.scid);
        this.retryToken = Buffer.from(pkt.token);
        this.keys.initial = deriveInitialSecrets(this.remoteCid);

        if (this._zeroRttBackup.size > 0) {
          this._rollbackZeroRttStreams();
        }

        for (const info of this.spaces.initial.sentPackets.values()) {
          this.cc.onPacketRemoved(info.inFlightBytes);
        }
        this.spaces.initial.sentPackets.clear();
        this.spaces.initial.cryptoSendOffset = 0;
        this.tls.transcript = [];
        this._sendInitialClientHelloAndZeroRtt();
        return;
      }

      if (pkt.type === 'initial') {
        if (this.initialKeysDiscarded || !this.keys.initial) return;
        const space = this.spaces.initial;
        const dec = unprotectPacket(pkt, this.keys.initial.server, space.largestReceived);
        if (!dec) return;
        this.stats.packetsReceived++;
        if (dec.reservedBits !== 0) {
          // RFC 9000 §17.2/§17.3.1: non-zero reserved bits after HP removal => PROTOCOL_VIOLATION
          const err = new Error(`Received ${pkt.type} packet with non-zero reserved bits`);
          err.quicCode = 0x0a;
          throw err;
        }

        if (this.remoteCid.equals(this.originalDcid) && pkt.scid && pkt.scid.length > 0) {
          this.remoteCid = Buffer.from(pkt.scid);
        }

        const isDup = space.recordReceived(dec.packetNumber);
        const frames = parseFrames(dec.plaintext);
        if (isAckEliciting(frames)) {
          space.ackPending = true;
        }
        if (!isDup) {
          this._handleFrames('initial', frames);
        }
        return;
      }

      if (pkt.type === 'handshake') {
        if (this.handshakeKeysDiscarded) return;
        if (!this.keys.handshake) {
          if (this.pendingPackets.handshake.length < 32) {
            this.pendingPackets.handshake.push({
              ...pkt,
              raw: Buffer.from(pkt.raw),
            });
          }
          return;
        }
        const space = this.spaces.handshake;
        const dec = unprotectPacket(pkt, this.keys.handshake.server, space.largestReceived);
        if (!dec) return;
        this.stats.packetsReceived++;
        if (dec.reservedBits !== 0) {
          // RFC 9000 §17.2/§17.3.1: non-zero reserved bits after HP removal => PROTOCOL_VIOLATION
          const err = new Error(`Received ${pkt.type} packet with non-zero reserved bits`);
          err.quicCode = 0x0a;
          throw err;
        }

        const isDup = space.recordReceived(dec.packetNumber);
        const frames = parseFrames(dec.plaintext);
        if (isAckEliciting(frames)) {
          space.ackPending = true;
        }
        if (!isDup) {
          this._handleFrames('handshake', frames);
        }
        return;
      }

      if (pkt.type === '1rtt') {
        if (!this.keys.app) {
          if (this.pendingPackets.app.length < 64) {
            this.pendingPackets.app.push({
              ...pkt,
              raw: Buffer.from(pkt.raw),
            });
          }
          return;
        }
        const space = this.spaces.app;
        const altCandidates = [];
        if (this.prevServerAppKeys) {
          altCandidates.push({ tag: 'prev', keys: this.prevServerAppKeys });
        }
        if (this.nextServerAppKeys) {
          altCandidates.push({ tag: 'next', keys: this.nextServerAppKeys });
        }

        const dec = unprotectPacket(
          pkt,
          this.keys.app.server,
          space.largestReceived,
          this.keyPhase,
          altCandidates.length > 0 ? altCandidates : null
        );

        if (!dec) {
          // Check RFC 9000 §10.3 Stateless Reset token on undecryptable short packets
          if (fullDatagram && this._checkStatelessReset(fullDatagram)) {
            this.stats.statelessResets++;
            this.emit('statelessReset');
            this._cleanupSocket();
            this.emit('close', { errorCode: -2, reason: 'stateless_reset', peerInitiated: true });
          }
          return;
        }
        this.stats.packetsReceived++;
        if (dec.reservedBits !== 0) {
          // RFC 9000 §17.2/§17.3.1: non-zero reserved bits after HP removal => PROTOCOL_VIOLATION
          const err = new Error(`Received ${pkt.type} packet with non-zero reserved bits`);
          err.quicCode = 0x0a;
          throw err;
        }

        // Handle Key Phase transitions cleanly for both client-initiated and server-initiated updates
        if (!dec.usedAltKeys && this._awaitingPeerKeyUpdate) {
          this._awaitingPeerKeyUpdate = false;
        } else if (dec.usedAltKeys && dec.altKeyTag === 'next' && dec.keyPhase !== this.keyPhase) {
          // Peer initiated a new 1-RTT Key Update (RFC 9001 §6)
          this.prevServerAppKeys = this.keys.app.server;
          this.keys.app.server = this.nextServerAppKeys;
          this.nextServerAppKeys = deriveUpdatedKeys(this.keys.app.server);
          this.keys.app.client = deriveUpdatedKeys(this.keys.app.client);
          this.keyPhase = dec.keyPhase;
          this._lowestPnInCurrentKeyPhase = space.nextPn;
          this._packetsInCurrentKeyPhase = 0;
          this._keyPhaseAcked = false;
          this.stats.keyUpdates++;
          this.emit('keyUpdate', {
            keyPhase: this.keyPhase,
            keyUpdates: this.stats.keyUpdates,
            initiator: 'server',
          });
        }

        // Update RFC 9000 §17.4 Latency Spin Bit (client inverts server's spin bit on new largest PN)
        if (this.enableSpinBit && dec.packetNumber > space.largestReceived) {
          const peerSpin = (dec.firstByte >>> 5) & 1;
          this._spinBit = peerSpin ^ 1;
        }

        const isDup = space.recordReceived(dec.packetNumber);
        const frames = parseFrames(dec.plaintext);
        if (isAckEliciting(frames)) {
          space.ackPending = true;
          space.ackElicitingSinceLastAck++;
        }
        if (!isDup) {
          this._handleFrames('app', frames);
        }
      }
    } catch (err) {
      this._closeWithTransportError(err);
    }
  }

  /**
   * Sends a best-effort transport CONNECTION_CLOSE (0x1c) carrying `err.quicCode`
   * (default INTERNAL_ERROR) at the highest available encryption level, then tears down.
   */
  _closeWithTransportError(err) {
    if (this.state === 'closed') return;
    const code = Number.isInteger(err.quicCode) ? err.quicCode : 0x01;
    const reason = String(err.message || '').slice(0, 256);
    try {
      const frame = buildConnectionCloseFrame(code, reason, false, err.frameType || 0);
      if (this.keys.app && this.socket) {
        this._sendAppPacket([frame], []);
      } else if (this.keys.handshake && !this.handshakeKeysDiscarded) {
        this._sendHandshakePacket([frame], []);
      } else if (this.keys.initial && !this.initialKeysDiscarded) {
        this._sendInitialPacket([frame], [], INITIAL_MIN_DGRAM_SIZE);
      }
    } catch {
      // Best-effort
    }
    if (err.quicCode !== undefined && err.code === undefined) {
      err.code = 'ERR_QUIC_TRANSPORT_ERROR';
    }
    this._destroyWithError(err);
  }

  _handleFrames(level, frames) {
    for (const frame of frames) {
      switch (frame.type) {
        case 'padding':
        case 'ping':
        case 'data_blocked':
        case 'stream_data_blocked':
        case 'streams_blocked':
        case 'retire_connection_id': {
          const localEntry = this.localConnectionIds.get(frame.sequenceNumber);
          if (localEntry && !localEntry.retired) {
            localEntry.retired = true;
            this._replenishLocalConnectionIds(false);
          }
          break;
        }

        case 'path_response': {
          const key = frame.data.toString('hex');
          const pending = this._pendingPathChallenges.get(key);
          if (pending) {
            this._pendingPathChallenges.delete(key);
            const rttMs = +(performance.now() - pending.sentAt).toFixed(2);
            pending.resolve(rttMs);
          }
          break;
        }

        case 'datagram':
          this.stats.quicDatagramsReceived++;
          this.emit('datagram', Buffer.from(frame.data));
          break;

        case 'new_token':
          if (this.sessionResume) {
            this.sessionStore.setNewToken(this.sessionKey, frame.token);
          }
          break;

        case 'ack':
          this._handleAckFrame(level, frame);
          break;

        case 'crypto':
          this._handleCryptoFrame(level, frame);
          break;

        case 'stream':
          this._handleStreamFrame(frame);
          break;

        case 'reset_stream': {
          const st = this._getOrCreateStream(frame.streamId);
          st.resetReceived = true;
          this.emit('streamReset', frame.streamId, frame.errorCode);
          break;
        }

        case 'stop_sending': {
          const st = this.streams.get(frame.streamId);
          if (st) st.sendQueue.length = 0;
          break;
        }

        case 'max_data':
          if (frame.maxData > this.connSendMax) {
            this.connSendMax = frame.maxData;
            this._triggerAppFlush();
          }
          break;

        case 'max_stream_data': {
          const st = this._getOrCreateStream(frame.streamId);
          if (frame.maxStreamData > st.maxSendOffset) {
            st.maxStreamData = frame.maxStreamData;
            st.maxSendOffset = frame.maxStreamData;
            this._triggerAppFlush();
          }
          break;
        }

        case 'max_streams':
          if (frame.bidi) {
            if (frame.maxStreams > this.peerMaxStreamsBidi || !Number.isFinite(this.peerMaxStreamsBidi)) {
              this.peerMaxStreamsBidi = frame.maxStreams;
              this._triggerAppFlush();
            }
          } else if (frame.maxStreams > this.peerMaxStreamsUni || !Number.isFinite(this.peerMaxStreamsUni)) {
            this.peerMaxStreamsUni = frame.maxStreams;
            this._triggerAppFlush();
          }
          this.emit('streamLimit', { bidi: this.peerMaxStreamsBidi, uni: this.peerMaxStreamsUni });
          break;

        case 'new_connection_id': {
          this._registerStatelessResetToken(frame.statelessResetToken);
          this.peerConnectionIds.set(frame.sequenceNumber, {
            sequenceNumber: frame.sequenceNumber,
            retirePriorTo: frame.retirePriorTo,
            cid: frame.cid,
            statelessResetToken: frame.statelessResetToken,
            retired: false,
          });

          // Retire peer CIDs older than retirePriorTo per RFC 9000 §5.1.2
          if (frame.retirePriorTo > 0) {
            for (const entry of this.peerConnectionIds.values()) {
              if (!entry.retired && entry.sequenceNumber < frame.retirePriorTo) {
                entry.retired = true;
                this._controlAppQueue.push(buildRetireConnectionIdFrame(entry.sequenceNumber));
                if (entry.sequenceNumber === this.activePeerCidSeq) {
                  // Switch immediately to a non-retired CID
                  const replacement = Array.from(this.peerConnectionIds.values()).find(
                    (c) => !c.retired && c.cid.length > 0
                  );
                  if (replacement) {
                    this.remoteCid = Buffer.from(replacement.cid);
                    this.activePeerCidSeq = replacement.sequenceNumber;
                  }
                }
              }
            }
            this._triggerAppFlush();
          }
          break;
        }

        case 'path_challenge':
          if (this.keys.app) {
            // RFC 9000 §8.2.2 mandates padding PATH_RESPONSE datagrams to >= 1200 bytes
            const respFrame = buildPathResponseFrame(frame.data);
            this._sendAppPacket([respFrame], [], INITIAL_MIN_DGRAM_SIZE);
          }
          break;

        case 'handshake_done':
          this.handshakeConfirmed = true;
          this._keyPhaseAcked = true;
          this.handshakeKeysDiscarded = true;
          for (const info of this.spaces.handshake.sentPackets.values()) {
            this.cc.onPacketRemoved(info.inFlightBytes);
          }
          this.spaces.handshake.sentPackets.clear();
          this.spaces.handshake.ackPending = false;
          this._replenishLocalConnectionIds(false);
          this._schedulePto();
          this._runAutoPmtud();
          break;

        case 'connection_close':
          this._handlePeerClose(frame);
          return;
      }
    }
  }

  _handleCryptoFrame(level, frame) {
    const space = this.spaces[level];
    const { contiguous } = space.cryptoReassembler.push(frame.offset, frame.data, false);
    if (contiguous.length === 0) return;

    const tlsEvents = this.tls.feedCrypto(level, contiguous);
    for (const ev of tlsEvents) {
      if (ev.type === 'hello_retry_request') {
        if (this._zeroRttBackup.size > 0) {
          this._rollbackZeroRttStreams();
        }
        this._queueAndSendCrypto('initial', ev.clientHello2);
      } else if (ev.type === 'handshake_keys') {
        this.stats.resumed = Boolean(ev.pskAccepted);
        this.keys.handshake = {
          client: ev.clientHandshakeKeys,
          server: ev.serverHandshakeKeys,
        };
        const queued = this.pendingPackets.handshake.splice(0);
        for (const pkt of queued) this._processIncomingPacket(pkt);
      } else if (ev.type === 'encrypted_extensions') {
        this.stats.earlyDataAccepted = Boolean(ev.earlyDataAccepted);
        if (this._zeroRttBackup.size > 0) {
          if (ev.earlyDataAccepted) {
            this._zeroRttBackup.clear();
          } else {
            this._rollbackZeroRttStreams();
          }
        }
        this._applyPeerTransportParams(ev.peerTransportParams);
      } else if (ev.type === 'handshake_complete') {
        this.keys.zeroRtt = null;
        this.keys.app = {
          client: ev.clientAppKeys,
          server: ev.serverAppKeys,
        };
        this.nextServerAppKeys = deriveUpdatedKeys(ev.serverAppKeys);
        this._lowestPnInCurrentKeyPhase = this.spaces.app.nextPn;
        this.stats.handshakeMs = +(performance.now() - this._connectStartPerf).toFixed(2);

        if (this.connectTimer) {
          clearTimeout(this.connectTimer);
          this.connectTimer = null;
        }

        // Record initial peer CID (seq 0) in peerConnectionIds table
        this.peerConnectionIds.set(0, {
          sequenceNumber: 0,
          retirePriorTo: 0,
          cid: Buffer.from(this.remoteCid),
          statelessResetToken: this.peerTransportParams?.statelessResetToken || null,
          retired: false,
        });

        this.state = 'connected';
        this._startKeepAlive();

        // Coalesce [Initial ACK (if needed) + Handshake(ClientFinished) + 1-RTT(SETTINGS & Requests)] in ONE UDP datagram
        this._sendCoalescedHandshakeFinishedAndFirstAppFlight(ev.clientHandshakeFlight);

        this.emit('connect', {
          alpn: ev.alpn,
          servername: this.servername,
          remoteAddress: this.remoteAddress,
          localPort: this.getSocketState().localPort,
          cipher: this.tls.suite?.name,
          resumed: this.stats.resumed,
          earlyDataAccepted: this.stats.earlyDataAccepted,
          handshakeMs: this.stats.handshakeMs,
        });

        // Flush any remaining 1-RTT stream chunks
        this._flushBatchedAppPackets();

        // Replay any queued 1-RTT packets that arrived coalesced with ServerFinished
        const queuedApp = this.pendingPackets.app.splice(0);
        for (const pkt of queuedApp) this._processIncomingPacket(pkt);
      } else if (ev.type === 'new_session_ticket') {
        if (this.sessionResume) {
          this.sessionStore.addTicket(this.sessionKey, ev.ticket, this.peerTransportParams);
        }
        this.emit('sessionTicket', ev.ticket);
      }
    }
  }

  _applyPeerTransportParams(tp) {
    this.peerTransportParams = tp;
    if (tp.statelessResetToken) {
      this._registerStatelessResetToken(tp.statelessResetToken);
    }
    if (tp.preferredAddress?.statelessResetToken) {
      this._registerStatelessResetToken(tp.preferredAddress.statelessResetToken);
    }
    if (tp.initialMaxData > this.connSendMax) {
      this.connSendMax = tp.initialMaxData;
    }

    if (!this.stats.earlyDataAccepted || !Number.isFinite(this.peerMaxStreamsBidi)) {
      this.peerMaxStreamsBidi = tp.initialMaxStreamsBidi;
    } else if (tp.initialMaxStreamsBidi > this.peerMaxStreamsBidi) {
      this.peerMaxStreamsBidi = tp.initialMaxStreamsBidi;
    }
    if (!this.stats.earlyDataAccepted || !Number.isFinite(this.peerMaxStreamsUni)) {
      this.peerMaxStreamsUni = tp.initialMaxStreamsUni;
    } else if (tp.initialMaxStreamsUni > this.peerMaxStreamsUni) {
      this.peerMaxStreamsUni = tp.initialMaxStreamsUni;
    }

    if (tp.maxIdleTimeout > 0) {
      this.idleTimeoutMs =
        this._configuredIdleTimeoutMs > 0
          ? Math.min(this._configuredIdleTimeoutMs, tp.maxIdleTimeout)
          : tp.maxIdleTimeout;
      this._resetIdleTimer();
    }

    if (tp.maxUdpPayloadSize >= INITIAL_MIN_DGRAM_SIZE && tp.maxUdpPayloadSize < this.maxUdpPayloadSize) {
      this.maxUdpPayloadSize = tp.maxUdpPayloadSize;
      this.maxPacketPayload = this.maxUdpPayloadSize - 110;
      this.maxStreamChunk = this.maxUdpPayloadSize - 170;
      this.stats.currentMtu = this.maxUdpPayloadSize;
      this.cc.setMtu(this.maxUdpPayloadSize);
    }

    for (const st of this.streams.values()) {
      let lim;
      if (st.isUni) {
        lim = tp.initialMaxStreamDataUni;
      } else if (st.isClientInitiated) {
        lim = tp.initialMaxStreamDataBidiRemote;
      } else {
        lim = tp.initialMaxStreamDataBidiLocal;
      }
      if (lim > st.maxSendOffset || st.maxSendOffset === Infinity) {
        st.maxSendOffset = lim;
      }
    }
  }

  _handleStreamFrame(frame) {
    const st = this._getOrCreateStream(frame.streamId);
    const { contiguous, ended } = st.recvReassembler.push(frame.offset, frame.data, frame.fin);

    if (contiguous.length > 0) {
      st.recvConsumed += contiguous.length;
      this.connRecvConsumed += contiguous.length;
      this.emit('streamData', st.id, contiguous, ended);

      if (!ended && st.recvMaxOffset - st.recvConsumed < this.initStreamWindowBidi / 2) {
        st.recvMaxOffset = st.recvConsumed + this.initStreamWindowBidi;
        this._controlAppQueue.push(buildMaxStreamDataFrame(st.id, st.recvMaxOffset));
        this._triggerAppFlush();
      }
      if (this.connRecvMax - this.connRecvConsumed < this.initConnWindow / 2) {
        this.connRecvMax = this.connRecvConsumed + this.initConnWindow;
        this._controlAppQueue.push(buildMaxDataFrame(this.connRecvMax));
        this._triggerAppFlush();
      }
    } else if (ended) {
      this.emit('streamData', st.id, Buffer.alloc(0), true);
    }
  }

  // ---- ACK Handling, RTT Estimation, Congestion Control & Full RFC 9002 Loss Detection ----

  _recordSentPacket(space, pn, byteLength, retransmittableFrames, extra = {}) {
    const now = extra.sentTime || performance.now();
    const isAckElicitingPkt =
      retransmittableFrames.length > 0 || Boolean(extra.isMtuProbe) || Boolean(extra.ackEliciting);
    if (!isAckElicitingPkt) return;

    const inFlightBytes = byteLength;
    this.cc.onPacketSent(inFlightBytes);

    space.sentPackets.set(pn, {
      pn,
      sentTime: now,
      inFlightBytes,
      ackEliciting: true,
      isZeroRtt: Boolean(extra.isZeroRtt),
      isMtuProbe: Boolean(extra.isMtuProbe),
      probeSize: extra.probeSize || 0,
      retransmittableFrames,
    });
  }

  _handleAckFrame(level, ack) {
    const space = this.spaces[level];
    const now = performance.now();
    // RFC 9000 §13.1: acknowledging a packet number we never sent is a PROTOCOL_VIOLATION
    if (ack.largest >= space.nextPn) {
      const err = new Error(`Peer acknowledged unsent ${level} packet ${ack.largest} (next=${space.nextPn})`);
      err.quicCode = 0x0a;
      throw err;
    }
    if (ack.largest > space.largestAckedSent) {
      space.largestAckedSent = ack.largest;
    }

    const largestSent = space.sentPackets.get(ack.largest);
    if (largestSent) {
      const rawRtt = Math.max(0.5, now - largestSent.sentTime);
      this.latestRtt = rawRtt;
      const exp = this.peerTransportParams ? this.peerTransportParams.ackDelayExponent : 3;
      const maxPeerAckDelay = this.peerTransportParams ? this.peerTransportParams.maxAckDelay : 25;
      const rawAckDelayMs = level === 'app' ? (ack.ackDelay * (1 << exp)) / 1000 : 0;
      const ackDelayMs = Math.min(rawAckDelayMs, maxPeerAckDelay);

      const isFirstSample = !Number.isFinite(this.minRtt);
      this.minRtt = Math.min(this.minRtt, rawRtt);
      const adjustedRtt = rawRtt - ackDelayMs >= this.minRtt ? rawRtt - ackDelayMs : rawRtt;

      if (isFirstSample) {
        this.smoothedRtt = adjustedRtt;
        this.rttVar = adjustedRtt / 2;
      } else if (this.ptoCount === 0 && space.largestAckedSent === ack.largest) {
        this.rttVar = 0.75 * this.rttVar + 0.25 * Math.abs(this.smoothedRtt - adjustedRtt);
        this.smoothedRtt = 0.875 * this.smoothedRtt + 0.125 * adjustedRtt;
      }
    }

    const newlyAcked = [];
    // Iterate whichever is smaller (range width vs. in-flight set) so huge ACK ranges can't stall the loop
    const ackedPns = [];
    for (const [minPn, maxPn] of ack.ranges) {
      if (maxPn - minPn + 1 <= space.sentPackets.size) {
        for (let pn = minPn; pn <= maxPn; pn++) {
          if (space.sentPackets.has(pn)) ackedPns.push(pn);
        }
      } else {
        for (const pn of space.sentPackets.keys()) {
          if (pn >= minPn && pn <= maxPn) ackedPns.push(pn);
        }
      }
    }
    for (const pn of ackedPns) {
      {
        const pktInfo = space.sentPackets.get(pn);
        if (pktInfo) {
          space.sentPackets.delete(pn);
          newlyAcked.push(pktInfo);

          if (level === 'app') {
            if (pn >= this._lowestPnInCurrentKeyPhase) {
              this._keyPhaseAcked = true;
            }
            // Resolve DPLPMTUD probe if ACKed
            if (pktInfo.isMtuProbe) {
              const probe = this._pendingMtuProbes.get(pn);
              if (probe) {
                this._pendingMtuProbes.delete(pn);
                clearTimeout(probe.timer);
                this._upgradeMtu(probe.targetSize);
                probe.resolve({
                  ok: true,
                  mtu: this.maxUdpPayloadSize,
                  peerMaxMtu: probe.peerMax,
                });
              }
            }
            // Resolve live ping() call if ACKed
            const pingEntry = this._pendingPings.get(pn);
            if (pingEntry) {
              this._pendingPings.delete(pn);
              clearTimeout(pingEntry.timer);
              pingEntry.resolve(+(now - pingEntry.sentAt).toFixed(2));
            }
          }
        }
      }
    }

    if (newlyAcked.length > 0) {
      this.ptoCount = 0;
      this.cc.onPacketsAcked(newlyAcked, this.latestRtt, this.minRtt, this.smoothedRtt, now);

      if (ack.ecn && level === 'app') {
        const largestSentTime = newlyAcked.reduce((m, p) => Math.max(m, p.sentTime), 0);
        this.cc.onEcnCe(ack.ecn.ce, largestSentTime, now);
      }
    }

    this._detectAndRetransmitLostPackets(level, now);
    this._scheduleLossTimer();
    this._schedulePto();

    // If cwnd opened up and stream data was waiting on congestion window, flush immediately
    if (level === 'app' && newlyAcked.length > 0 && this._hasPendingAppData()) {
      this._triggerAppFlush();
    }
  }

  _getLossDelayMs() {
    const rttRef = Math.max(this.latestRtt || this.smoothedRtt, this.smoothedRtt);
    return Math.max(GRANULARITY_MS, TIME_THRESHOLD * rttRef);
  }

  _detectAndRetransmitLostPackets(level, now = performance.now()) {
    const space = this.spaces[level];
    if (space.largestAckedSent < 0 || space.sentPackets.size === 0) return;

    const lossDelay = this._getLossDelayMs();
    const lostSendTime = now - lossDelay;
    const lostFrames = [];

    for (const [pn, info] of space.sentPackets) {
      if (pn >= space.largestAckedSent) continue;

      const lostByPacketThreshold = pn + PACKET_THRESHOLD <= space.largestAckedSent;
      const lostByTimeThreshold = info.sentTime <= lostSendTime;

      if (lostByPacketThreshold || lostByTimeThreshold) {
        space.sentPackets.delete(pn);
        this.cc.onPacketRemoved(info.inFlightBytes);

        if (info.isMtuProbe) {
          // RFC 9000 §14.4: Loss of an MTU probe MUST NOT trigger congestion reaction
          const probe = this._pendingMtuProbes.get(pn);
          if (probe) {
            this._pendingMtuProbes.delete(pn);
            clearTimeout(probe.timer);
            probe.resolve({ ok: false, mtu: this.maxUdpPayloadSize, attempted: probe.targetSize });
          }
          continue;
        }

        this.stats.packetsLost++;
        this.cc.onCongestionEvent(info.sentTime, now);
        if (info.retransmittableFrames.length > 0) {
          this.stats.packetsRetransmitted++;
          lostFrames.push(...info.retransmittableFrames);
        }
      }
    }

    if (lostFrames.length > 0) {
      this._retransmitFrames(level, lostFrames);
    }
  }

  _scheduleLossTimer() {
    if (this.lossTimer) {
      clearTimeout(this.lossTimer);
      this.lossTimer = null;
    }
    if (this.state === 'closed' || this.state === 'closing') return;

    const lossDelay = this._getLossDelayMs();
    let earliestLossTime = Infinity;
    let earliestLevel = null;

    for (const [level, space] of Object.entries(this.spaces)) {
      if (level === 'initial' && this.initialKeysDiscarded) continue;
      if (level === 'handshake' && this.handshakeKeysDiscarded) continue;
      if (space.largestAckedSent < 0) continue;

      for (const [pn, info] of space.sentPackets) {
        if (pn < space.largestAckedSent) {
          const t = info.sentTime + lossDelay;
          if (t < earliestLossTime) {
            earliestLossTime = t;
            earliestLevel = level;
          }
        }
      }
    }

    if (earliestLevel && Number.isFinite(earliestLossTime)) {
      const waitMs = Math.max(1, Math.ceil(earliestLossTime - performance.now()));
      this.lossTimer = setTimeout(() => {
        this.lossTimer = null;
        if (this.state === 'closed' || this.state === 'closing') return;
        const now = performance.now();
        for (const lvl of ['initial', 'handshake', 'app']) {
          this._detectAndRetransmitLostPackets(lvl, now);
        }
        this._scheduleLossTimer();
        this._schedulePto();
      }, waitMs);
      this.lossTimer.unref?.();
    }
  }

  _retransmitFrames(level, frames) {
    if (this.state === 'closed' || this.state === 'closing') return;
    if (level === 'initial' && !this.initialKeysDiscarded && this.keys.initial) {
      for (const f of frames) {
        this._sendInitialPacket([f], [f], INITIAL_MIN_DGRAM_SIZE);
      }
    } else if (level === 'handshake' && !this.handshakeKeysDiscarded && this.keys.handshake) {
      for (const f of frames) {
        this._sendHandshakePacket([f], [f]);
      }
    } else if (level === 'app') {
      if (this.keys.app) {
        let batch = [];
        let len = 0;
        for (const f of frames) {
          if (len + f.length > this.maxPacketPayload && batch.length > 0) {
            this._sendAppPacket(batch, batch);
            batch = [];
            len = 0;
          }
          batch.push(f);
          len += f.length;
        }
        if (batch.length > 0) this._sendAppPacket(batch, batch);
      } else if (this.keys.zeroRtt) {
        this._sendZeroRttPacket(frames);
      }
    }
  }

  // ---- Packet Sending & Coalescing ----

  _queueAndSendCrypto(level, data) {
    const space = this.spaces[level];
    const maxChunk = level === 'initial' ? MAX_INITIAL_CRYPTO_CHUNK : MAX_CRYPTO_CHUNK;
    for (let pos = 0; pos < data.length; pos += maxChunk) {
      const slice = data.subarray(pos, Math.min(pos + maxChunk, data.length));
      const frame = buildCryptoFrame(space.cryptoSendOffset, slice);
      space.cryptoSendOffset += slice.length;

      if (level === 'initial') {
        this._sendInitialPacket([frame], [frame], INITIAL_MIN_DGRAM_SIZE);
      } else if (level === 'handshake') {
        this._sendHandshakePacket([frame], [frame]);
      } else {
        this._sendAppPacket([frame], [frame]);
      }
    }
  }

  /**
   * Coalesces [Initial ACK (if needed) || Handshake(ACK + ClientFinished) || 1-RTT(SETTINGS + Request)]
   * into a SINGLE UDP datagram so cold requests complete in 2 network RTTs with 1 syscall.
   */
  _sendCoalescedHandshakeFinishedAndFirstAppFlight(clientHandshakeFlight) {
    const dgramParts = [];
    const hsSpace = this.spaces.handshake;

    // 1. Final Initial ACK if pending
    if (!this.initialKeysDiscarded && this.keys.initial && this.spaces.initial.ackPending) {
      const initSpace = this.spaces.initial;
      const ackFrame = buildAckFrameFromPacketNumbers(initSpace.receivedPns, 0);
      if (ackFrame) {
        const pn = initSpace.nextPn++;
        dgramParts.push(
          buildInitialPacket({
            dcid: this.remoteCid,
            scid: this.localCid,
            token: this.retryToken,
            packetNumber: pn,
            largestAcked: initSpace.largestAckedSent,
            payload: ackFrame,
            keys: this.keys.initial.client,
            minPacketSize: 0,
          })
        );
        this.stats.packetsSent++;
        initSpace.ackPending = false;
      }
    }

    // 2. Handshake packet (Handshake ACK + Client Finished)
    const hsFrames = [];
    const hsRetransmit = [];
    if (hsSpace.ackPending) {
      const hsAck = buildAckFrameFromPacketNumbers(hsSpace.receivedPns, 0);
      if (hsAck) hsFrames.push(hsAck);
      hsSpace.ackPending = false;
    }

    const finCrypto = buildCryptoFrame(hsSpace.cryptoSendOffset, clientHandshakeFlight);
    hsSpace.cryptoSendOffset += clientHandshakeFlight.length;
    hsFrames.push(finCrypto);
    hsRetransmit.push(finCrypto);

    const currentBeforeHs = dgramParts.reduce((s, b) => s + b.length, 0);
    const estHsLen =
      1 +
      4 +
      2 +
      this.remoteCid.length +
      this.localCid.length +
      2 +
      2 +
      Buffer.concat(hsFrames).length +
      16;
    const remainingFor1Rtt = this.maxUdpPayloadSize - currentBeforeHs - estHsLen - 32;
    const firstAppFrames =
      remainingFor1Rtt > 48 ? this._drainStreamFramesForPacket(remainingFor1Rtt, false) : [];

    const hasInitPacket = dgramParts.length > 0;
    const minHsSize =
      hasInitPacket && firstAppFrames.length === 0
        ? Math.max(0, INITIAL_MIN_DGRAM_SIZE - currentBeforeHs)
        : 0;

    const hsPn = hsSpace.nextPn++;
    const hsPkt = buildHandshakePacket({
      dcid: this.remoteCid,
      scid: this.localCid,
      packetNumber: hsPn,
      largestAcked: hsSpace.largestAckedSent,
      payload: Buffer.concat(hsFrames),
      keys: this.keys.handshake.client,
      minPacketSize: minHsSize,
    });
    dgramParts.push(hsPkt);
    this.stats.packetsSent++;

    const now = performance.now();
    this._recordSentPacket(hsSpace, hsPn, hsPkt.length, hsRetransmit, { sentTime: now });

    // 3. Coalesce 1-RTT Short Header packet (LAST packet in datagram per RFC 9000 §12.2)
    if (firstAppFrames.length > 0 && this.keys.app) {
      const appSpace = this.spaces.app;
      const appPn = appSpace.nextPn++;
      const lenBeforeApp = dgramParts.reduce((s, b) => s + b.length, 0);
      const minAppSize = hasInitPacket ? Math.max(0, INITIAL_MIN_DGRAM_SIZE - lenBeforeApp) : 0;

      const appPkt = buildShortPacket({
        dcid: this.remoteCid,
        packetNumber: appPn,
        largestAcked: appSpace.largestAckedSent,
        payload: Buffer.concat(firstAppFrames),
        keys: this.keys.app.client,
        keyPhase: this.keyPhase,
        spinBit: this.enableSpinBit ? this._spinBit : 0,
        minPacketSize: minAppSize,
      });
      dgramParts.push(appPkt);
      this.stats.packetsSent++;
      this._packetsInCurrentKeyPhase++;

      this._recordSentPacket(appSpace, appPn, appPkt.length, firstAppFrames, { sentTime: now });
    }

    this._discardInitialKeys();
    this._sendRawDatagram(Buffer.concat(dgramParts));
    this._schedulePto();
  }

  _discardInitialKeys() {
    if (this.initialKeysDiscarded) return;
    this.initialKeysDiscarded = true;
    for (const info of this.spaces.initial.sentPackets.values()) {
      this.cc.onPacketRemoved(info.inFlightBytes);
    }
    this.spaces.initial.sentPackets.clear();
    this.spaces.initial.ackPending = false;
  }

  _flushPendingAcks() {
    if (this.state === 'closed') return;

    const initAckNeeded =
      !this.initialKeysDiscarded && this.keys.initial && this.spaces.initial.ackPending;
    const hsAckNeeded =
      !this.handshakeKeysDiscarded && this.keys.handshake && this.spaces.handshake.ackPending;

    if (initAckNeeded || hsAckNeeded) {
      const parts = [];

      if (initAckNeeded) {
        const initSpace = this.spaces.initial;
        const ack = buildAckFrameFromPacketNumbers(initSpace.receivedPns, 0);
        if (ack) {
          const pn = initSpace.nextPn++;
          const minSize = hsAckNeeded ? 0 : INITIAL_MIN_DGRAM_SIZE;
          parts.push(
            buildInitialPacket({
              dcid: this.remoteCid,
              scid: this.localCid,
              token: this.retryToken,
              packetNumber: pn,
              largestAcked: initSpace.largestAckedSent,
              payload: ack,
              keys: this.keys.initial.client,
              minPacketSize: minSize,
            })
          );
          this.stats.packetsSent++;
        }
        initSpace.ackPending = false;
      }

      if (hsAckNeeded) {
        const hsSpace = this.spaces.handshake;
        const ack = buildAckFrameFromPacketNumbers(hsSpace.receivedPns, 0);
        if (ack) {
          const pn = hsSpace.nextPn++;
          const curLen = parts.reduce((s, b) => s + b.length, 0);
          const minSize = Math.max(0, INITIAL_MIN_DGRAM_SIZE - curLen);
          parts.push(
            buildHandshakePacket({
              dcid: this.remoteCid,
              scid: this.localCid,
              packetNumber: pn,
              largestAcked: hsSpace.largestAckedSent,
              payload: ack,
              keys: this.keys.handshake.client,
              minPacketSize: minSize,
            })
          );
          this.stats.packetsSent++;
          this._discardInitialKeys();
        }
        hsSpace.ackPending = false;
      }

      if (parts.length > 0) {
        this._sendRawDatagram(Buffer.concat(parts));
      }
    }

    const appSpace = this.spaces.app;
    if (this.keys.app && appSpace.ackPending) {
      if (this.ackNoDelay || this.ackDelayMs === 0) {
        this._sendAppAckNow();
        return;
      }
      const ackThreshold =
        this.ackThreshold > 0 ? this.ackThreshold : appSpace.largestReceived < 12 ? 2 : 8;
      if (appSpace.ackElicitingSinceLastAck >= ackThreshold) {
        this._sendAppAckNow();
      } else if (!this.ackTimer) {
        this.ackTimer = setTimeout(() => {
          this.ackTimer = null;
          if (this.state !== 'closed' && this.spaces.app.ackPending && this.keys.app) {
            this._sendAppAckNow();
          }
        }, this.ackDelayMs);
        this.ackTimer.unref?.();
      }
    }
  }

  _buildEncodedAppAck() {
    const appSpace = this.spaces.app;
    if (!appSpace.ackPending || appSpace.receivedPns.size === 0) return null;
    const delayMicros = Math.max(0, (performance.now() - appSpace.largestReceivedTime) * 1000);
    const encodedDelay = Math.floor(delayMicros / (1 << 3));
    appSpace.ackPending = false;
    appSpace.ackElicitingSinceLastAck = 0;
    if (this.ackTimer) {
      clearTimeout(this.ackTimer);
      this.ackTimer = null;
    }
    return buildAckFrameFromPacketNumbers(appSpace.receivedPns, encodedDelay);
  }

  _sendAppAckNow() {
    const ack = this._buildEncodedAppAck();
    if (!ack) return;
    this._sendAppPacket([ack], []);
  }

  _sendInitialPacket(frames, retransmittableFrames = [], minPacketSize = INITIAL_MIN_DGRAM_SIZE) {
    if (!this.keys.initial || this.initialKeysDiscarded) return;
    const space = this.spaces.initial;
    const allFrames = [];
    if (space.ackPending) {
      const ack = buildAckFrameFromPacketNumbers(space.receivedPns, 0);
      if (ack) allFrames.push(ack);
      space.ackPending = false;
    }
    allFrames.push(...frames);

    const pn = space.nextPn++;
    const pkt = buildInitialPacket({
      dcid: this.remoteCid,
      scid: this.localCid,
      token: this.retryToken,
      packetNumber: pn,
      largestAcked: space.largestAckedSent,
      payload: Buffer.concat(allFrames),
      keys: this.keys.initial.client,
      minPacketSize,
    });
    this.stats.packetsSent++;

    if (retransmittableFrames.length > 0) {
      this._recordSentPacket(space, pn, pkt.length, retransmittableFrames);
      this._schedulePto();
    }

    this._sendRawDatagram(pkt);
  }

  _sendHandshakePacket(frames, retransmittableFrames = [], minPacketSize = 0) {
    if (!this.keys.handshake || this.handshakeKeysDiscarded) return;
    const space = this.spaces.handshake;
    const allFrames = [];
    if (space.ackPending) {
      const ack = buildAckFrameFromPacketNumbers(space.receivedPns, 0);
      if (ack) allFrames.push(ack);
      space.ackPending = false;
    }
    allFrames.push(...frames);

    const pn = space.nextPn++;
    const pkt = buildHandshakePacket({
      dcid: this.remoteCid,
      scid: this.localCid,
      packetNumber: pn,
      largestAcked: space.largestAckedSent,
      payload: Buffer.concat(allFrames),
      keys: this.keys.handshake.client,
      minPacketSize,
    });
    this.stats.packetsSent++;

    this._discardInitialKeys();

    if (retransmittableFrames.length > 0) {
      this._recordSentPacket(space, pn, pkt.length, retransmittableFrames);
      this._schedulePto();
    }

    this._sendRawDatagram(pkt);
  }

  _sendAppPacket(frames, retransmittableFrames = [], minPacketSize = 0, isMtuProbe = false) {
    if (!this.keys.app || this.state === 'closed') return -1;
    const space = this.spaces.app;
    const allFrames = [];

    if (!isMtuProbe && space.ackPending && !(frames.length === 1 && frames[0][0] === 0x02)) {
      const ack = this._buildEncodedAppAck();
      if (ack) allFrames.push(ack);
    }
    allFrames.push(...frames);

    const pn = space.nextPn++;
    const pkt = buildShortPacket({
      dcid: this.remoteCid,
      packetNumber: pn,
      largestAcked: space.largestAckedSent,
      payload: Buffer.concat(allFrames),
      keys: this.keys.app.client,
      keyPhase: this.keyPhase,
      spinBit: this.enableSpinBit ? this._spinBit : 0,
      minPacketSize,
    });
    this.stats.packetsSent++;
    this._packetsInCurrentKeyPhase++;

    const hasAckEliciting =
      retransmittableFrames.length > 0 ||
      isMtuProbe ||
      frames.some((f) => f[0] !== 0x00 && f[0] !== 0x02 && f[0] !== 0x03 && f[0] !== 0x1c && f[0] !== 0x1d);

    if (hasAckEliciting) {
      this._recordSentPacket(space, pn, pkt.length, retransmittableFrames, {
        ackEliciting: true,
        isMtuProbe,
        probeSize: isMtuProbe ? minPacketSize : 0,
      });
      this._schedulePto();
    }

    this._sendRawDatagram(pkt);
    return pn;
  }

  _sendRawDatagram(buf) {
    if (!this.socket || this.state === 'closed') return;
    this.stats.datagramsSent++;
    this.stats.bytesSent += buf.length;
    const sock = this.socket;
    const onSendErr = (err) => {
      if (err && this.state !== 'closed' && sock === this.socket) {
        this._destroyWithError(err);
      }
    };
    if (this._socketConnected) {
      sock.send(buf, onSendErr);
    } else {
      sock.send(buf, this.port, this.remoteAddress, onSendErr);
    }
  }

  // ---- PTO Loss Recovery, Keep-Alive & Idle Timers ----

  _hasInFlightAckEliciting() {
    for (const space of Object.values(this.spaces)) {
      if (space.sentPackets.size > 0) return true;
    }
    return false;
  }

  _schedulePto() {
    if (this.ptoTimer) {
      clearTimeout(this.ptoTimer);
      this.ptoTimer = null;
    }
    if (this.state === 'closed' || this.state === 'closing') return;
    if (!this._hasInFlightAckEliciting() && this.state === 'connected') {
      return;
    }

    const maxAckDelay = this.peerTransportParams ? this.peerTransportParams.maxAckDelay : 25;
    const basePto = this.smoothedRtt + Math.max(4 * this.rttVar, 5) + maxAckDelay;
    const timeoutMs = Math.min(4000, Math.max(80, basePto * Math.pow(2, this.ptoCount)));

    this.ptoTimer = setTimeout(() => {
      this.ptoTimer = null;
      this._onPtoExpired();
    }, timeoutMs);
    this.ptoTimer.unref?.();
  }

  _onPtoExpired() {
    if (this.state === 'closed' || this.state === 'closing') return;
    this.ptoCount++;

    if (!this.initialKeysDiscarded && this.spaces.initial.sentPackets.size > 0) {
      const oldest = this.spaces.initial.sentPackets.values().next().value;
      this._retransmitFrames('initial', oldest.retransmittableFrames);
      return;
    }
    if (!this.handshakeKeysDiscarded && this.spaces.handshake.sentPackets.size > 0) {
      const oldest = this.spaces.handshake.sentPackets.values().next().value;
      this._retransmitFrames('handshake', oldest.retransmittableFrames);
      return;
    }
    if ((this.keys.app || this.keys.zeroRtt) && this.spaces.app.sentPackets.size > 0) {
      for (const item of this.spaces.app.sentPackets.values()) {
        if (item.isMtuProbe) continue;
        if (item.retransmittableFrames.length > 0) {
          this._retransmitFrames('app', item.retransmittableFrames);
          return;
        }
      }
      if (this.keys.app) {
        const ping = buildPingFrame();
        this._sendAppPacket([ping], [ping]);
      }
      return;
    }
    if (this.state === 'connecting' && !this.handshakeKeysDiscarded && this.keys.handshake) {
      const ping = buildPingFrame();
      this._sendHandshakePacket([ping], [ping], INITIAL_MIN_DGRAM_SIZE);
    }
  }

  _resetIdleTimer() {
    if (this.idleTimer) {
      clearTimeout(this.idleTimer);
      this.idleTimer = null;
    }
    if (this.idleTimeoutMs <= 0 || this.state === 'closed') return;
    this.idleTimer = setTimeout(() => {
      this.close(0, 'idle_timeout');
    }, this.idleTimeoutMs);
    this.idleTimer.unref?.();
  }

  _startKeepAlive() {
    if (this.keepAliveIntervalMs <= 0 || this.keepAliveTimer) return;
    this.keepAliveTimer = setInterval(() => {
      if (this.state === 'connected' && this.keys.app) {
        const ping = buildPingFrame();
        this._sendAppPacket([ping], [ping]);
      }
    }, this.keepAliveIntervalMs);
    this.keepAliveTimer.unref?.();
  }

  // ---- Connection Shutdown ----

  _handlePeerClose(frame) {
    const code = Number(frame.errorCode);
    const isNoError = code === 0 || (frame.isApplication && code === 0x0100);
    if (!isNoError && this.state === 'connecting') {
      this._destroyWithError(
        new Error(
          `Peer closed QUIC connection (code=0x${code.toString(16)}, reason=${frame.reason || 'none'})`
        )
      );
      return;
    }
    this._cleanupSocket();
    this.emit('close', { errorCode: code, reason: frame.reason, peerInitiated: true });
  }

  close(errorCode = 0x0100, reason = '') {
    if (this.state === 'closed' || this.state === 'closing') return;
    this.state = 'closing';

    try {
      if (this.keys.app) {
        const closeFrame = buildConnectionCloseFrame(errorCode, reason, true);
        this._sendAppPacket([closeFrame], []);
      } else if (this.keys.handshake && !this.handshakeKeysDiscarded) {
        const closeFrame = buildConnectionCloseFrame(0, reason, false);
        this._sendHandshakePacket([closeFrame], []);
      } else if (this.keys.initial && !this.initialKeysDiscarded) {
        const closeFrame = buildConnectionCloseFrame(0, reason, false);
        this._sendInitialPacket([closeFrame], [], INITIAL_MIN_DGRAM_SIZE);
      }
    } catch {
      // Best-effort CONNECTION_CLOSE
    }

    setTimeout(() => {
      if (this.state !== 'closed') {
        this._cleanupSocket();
        this.emit('close', { errorCode, reason, peerInitiated: false });
      }
    }, 8).unref?.();
  }

  destroy(err = null) {
    if (err) {
      this._destroyWithError(err);
    } else if (this.state !== 'closed') {
      this._cleanupSocket();
      this.emit('close', { errorCode: 0, reason: 'destroyed', peerInitiated: false });
    }
  }

  _destroyWithError(err) {
    if (this.state === 'closed') return;
    this._cleanupSocket(err);
    if (this.listenerCount('error') > 0) {
      this.emit('error', err);
    }
    this.emit('close', { errorCode: -1, reason: err.message, peerInitiated: false });
  }

  _cleanupSocket(err = null) {
    this.state = 'closed';
    for (const t of [
      this.ptoTimer,
      this.lossTimer,
      this.pacingTimer,
      this.ackTimer,
      this.connectTimer,
      this.idleTimer,
    ]) {
      if (t) clearTimeout(t);
    }
    if (this.keepAliveTimer) clearInterval(this.keepAliveTimer);
    this.ptoTimer = null;
    this.lossTimer = null;
    this.pacingTimer = null;
    this.ackTimer = null;
    this.connectTimer = null;
    this.idleTimer = null;
    this.keepAliveTimer = null;

    if (this._abortSignal && this._abortHandler) {
      this._abortSignal.removeEventListener('abort', this._abortHandler);
      this._abortHandler = null;
    }

    for (const [, p] of this._pendingPathChallenges) {
      clearInterval(p.timer);
      p.reject(err || new Error('QUIC connection closed'));
    }
    this._pendingPathChallenges.clear();

    for (const [, p] of this._pendingPings) {
      clearTimeout(p.timer);
      p.reject(err || new Error('QUIC connection closed'));
    }
    this._pendingPings.clear();

    for (const [, p] of this._pendingMtuProbes) {
      clearTimeout(p.timer);
      p.resolve({ ok: false, mtu: this.maxUdpPayloadSize });
    }
    this._pendingMtuProbes.clear();

    for (const oldSock of this._retiringSockets) {
      try {
        oldSock.removeAllListeners();
        oldSock.close();
      } catch {
        // Ignore
      }
    }
    this._retiringSockets.clear();

    if (this.socket) {
      const sock = this.socket;
      const shouldClose = this._ownsSocket;
      this.socket = null;
      this._socketConnected = false;
      try {
        sock.removeAllListeners();
        if (shouldClose) sock.close();
      } catch {
        // Ignore
      }
    }
  }
}

module.exports = {
  QuicConnection,
  QuicCongestionController,
  ByteReassembler,
  DnsCache,
  defaultDnsCache,
};
