'use strict';

/**
 * RFC 9000 §17 QUIC v1 packet formats + RFC 9001 §5 packet protection.
 *
 *  - Single generic Long Header builder (Initial / 0-RTT / Handshake) + Short Header (1-RTT) builder
 *  - Exact RFC 9000 Appendix A.2/A.3 packet number truncation & reconstruction (fast Number path,
 *    BigInt fallback beyond 2^52)
 *  - Robust `splitDatagram()` coalesced packet parser (drops packets with Fixed Bit = 0,
 *    oversized CIDs, truncated lengths, unsupported versions)
 *  - `unprotectPacket()` with multi-candidate Key Phase decryption and reserved-bit reporting
 *  - Helpers: `peekDestinationConnectionId`, `buildVersionNegotiationPacket`, packet type constants
 */

const { encodeVarint, decodeVarint } = require('./varint');
const {
  QUIC_VERSION_1,
  aeadEncrypt,
  aeadDecrypt,
  headerProtectionMask,
} = require('./crypto');

const PACKET_TYPE_INITIAL = 0x00;
const PACKET_TYPE_0RTT = 0x01;
const PACKET_TYPE_HANDSHAKE = 0x02;
const PACKET_TYPE_RETRY = 0x03;

const LONG_TYPE_NAMES = ['initial', '0rtt', 'handshake', 'retry'];
const MAX_CID_LENGTH = 20;
const AEAD_TAG_LENGTH = 16;
const TWO_POW_52 = 2 ** 52;

/**
 * RFC 9000 Appendix A.2: Encode Packet Number in 1..4 bytes.
 * @param {number} fullPn
 * @param {number} [largestAcked=-1]
 * @returns {Buffer}
 */
function encodePacketNumber(fullPn, largestAcked = -1) {
  const numUnacked = largestAcked < 0 ? fullPn + 1 : fullPn - largestAcked;
  let pnLen;
  if (numUnacked < 1 << 7) {
    pnLen = 1;
  } else if (numUnacked < 1 << 15) {
    pnLen = 2;
  } else if (numUnacked < 1 << 23) {
    pnLen = 3;
  } else {
    pnLen = 4;
  }

  const buf = Buffer.allocUnsafe(pnLen);
  const low32 = fullPn % 4294967296;
  if (pnLen === 1) {
    buf[0] = low32 & 0xff;
  } else if (pnLen === 2) {
    buf.writeUInt16BE(low32 & 0xffff, 0);
  } else if (pnLen === 3) {
    buf[0] = (low32 >>> 16) & 0xff;
    buf.writeUInt16BE(low32 & 0xffff, 1);
  } else {
    buf.writeUInt32BE(low32 >>> 0, 0);
  }
  return buf;
}

/**
 * RFC 9000 Appendix A.3: Reconstruct full 62-bit Packet Number from a truncated PN.
 */
function decodePacketNumber(largestPn, truncatedPn, pnNbits) {
  const expectedPn = largestPn + 1;
  const pnWin = 2 ** pnNbits;
  const pnHwin = pnWin / 2;

  if (expectedPn < TWO_POW_52) {
    // Fast exact Number path: (expected & ~mask) | truncated
    const candidatePn = expectedPn - (expectedPn % pnWin) + truncatedPn;
    if (candidatePn <= expectedPn - pnHwin && candidatePn < 2 ** 62 - pnWin) {
      return candidatePn + pnWin;
    }
    if (candidatePn > expectedPn + pnHwin && candidatePn >= pnWin) {
      return candidatePn - pnWin;
    }
    return candidatePn;
  }

  const exp = BigInt(expectedPn);
  const win = BigInt(pnWin);
  const hwin = win >> 1n;
  const mask = win - 1n;
  const candidate = (exp & ~mask) | BigInt(truncatedPn);
  if (candidate <= exp - hwin && candidate < (1n << 62n) - win) return Number(candidate + win);
  if (candidate > exp + hwin && candidate >= win) return Number(candidate - win);
  return Number(candidate);
}

/**
 * Applies Header Protection in-place on `packet` starting at `pnOffset` with `pnLen` (1..4).
 */
function applyHeaderProtection(keys, packet, pnOffset, pnLen) {
  const sampleOffset = pnOffset + 4;
  const mask = headerProtectionMask(keys, packet.subarray(sampleOffset, sampleOffset + 16));

  packet[0] ^= (packet[0] & 0x80) !== 0 ? mask[0] & 0x0f : mask[0] & 0x1f;
  for (let i = 0; i < pnLen; i++) {
    packet[pnOffset + i] ^= mask[1 + i];
  }
  return packet;
}

/**
 * Ensures `pnLen + payload.length >= 4` (RFC 9001 §5.4.2 sampling requirement),
 * and optionally pads with PADDING (0x00) frames so the whole packet reaches `minPacketSize`.
 */
function padPayloadForProtection(payload, headerLenBeforePn, pnLen, minPacketSize = 0) {
  let minPayload = Math.max(payload.length, 4 - pnLen);
  if (minPacketSize > 0) {
    const neededForTotal = minPacketSize - headerLenBeforePn - pnLen - AEAD_TAG_LENGTH;
    if (neededForTotal > minPayload) minPayload = neededForTotal;
  }
  if (minPayload <= payload.length) return payload;
  const padded = Buffer.alloc(minPayload, 0); // 0x00 = QUIC PADDING frame
  payload.copy(padded, 0);
  return padded;
}

function sealPacket(header, pnOffset, pnLen, payload, keys, packetNumber) {
  const encrypted = aeadEncrypt(keys, packetNumber, payload, header);
  const packet = Buffer.allocUnsafe(header.length + encrypted.length);
  header.copy(packet, 0);
  encrypted.copy(packet, header.length);
  return applyHeaderProtection(keys, packet, pnOffset, pnLen);
}

/**
 * Builds and protects a QUIC v1 Long Header packet (Initial, 0-RTT or Handshake).
 */
function buildLongHeaderPacket({
  type,
  dcid,
  scid,
  token = null,
  packetNumber,
  largestAcked = -1,
  payload,
  keys,
  minPacketSize = 0,
  version = QUIC_VERSION_1,
}) {
  if (dcid.length > MAX_CID_LENGTH || scid.length > MAX_CID_LENGTH) {
    throw new RangeError('QUIC v1 Connection IDs must be <= 20 bytes');
  }
  const pnBytes = encodePacketNumber(packetNumber, largestAcked);
  const pnLen = pnBytes.length;
  const isInitial = type === PACKET_TYPE_INITIAL;
  const tok = isInitial ? token || Buffer.alloc(0) : null;
  const tokenLenBytes = isInitial ? encodeVarint(tok.length) : null;

  // Header before PN: first(1) + version(4) + dcidLen(1)+dcid + scidLen(1)+scid
  //                   [+ tokenLen + token] + Length(2-byte varint)
  const pnOffset =
    7 + dcid.length + scid.length + (isInitial ? tokenLenBytes.length + tok.length : 0) + 2;
  const paddedPayload = padPayloadForProtection(payload, pnOffset, pnLen, minPacketSize);
  const lengthField = pnLen + paddedPayload.length + AEAD_TAG_LENGTH;
  if (lengthField > 16383) {
    throw new RangeError(`QUIC long header packet too large for 2-byte Length field: ${lengthField}`);
  }

  const header = Buffer.allocUnsafe(pnOffset + pnLen);
  let pos = 0;
  // Long Header (1) | Fixed (1) | Type (2) | Reserved (00) | PN Length (2)
  header[pos++] = 0xc0 | ((type & 0x03) << 4) | ((pnLen - 1) & 0x03);
  header.writeUInt32BE(version >>> 0, pos);
  pos += 4;
  header[pos++] = dcid.length;
  dcid.copy(header, pos);
  pos += dcid.length;
  header[pos++] = scid.length;
  scid.copy(header, pos);
  pos += scid.length;
  if (isInitial) {
    tokenLenBytes.copy(header, pos);
    pos += tokenLenBytes.length;
    if (tok.length > 0) {
      tok.copy(header, pos);
      pos += tok.length;
    }
  }
  header.writeUInt16BE((0x4000 | lengthField) >>> 0, pos);
  pos += 2;
  pnBytes.copy(header, pos);

  return sealPacket(header, pnOffset, pnLen, paddedPayload, keys, packetNumber);
}

/** Builds and protects a QUIC v1 Long Header Initial packet (type = 0x00). */
function buildInitialPacket(opts) {
  return buildLongHeaderPacket({ ...opts, type: PACKET_TYPE_INITIAL });
}

/** Builds and protects a QUIC v1 Long Header 0-RTT packet (type = 0x01). */
function buildZeroRttPacket(opts) {
  return buildLongHeaderPacket({ ...opts, type: PACKET_TYPE_0RTT });
}

/** Builds and protects a QUIC v1 Long Header Handshake packet (type = 0x02). */
function buildHandshakePacket(opts) {
  return buildLongHeaderPacket({ ...opts, type: PACKET_TYPE_HANDSHAKE });
}

/**
 * Builds and protects a QUIC v1 Short Header (1-RTT) packet.
 */
function buildShortPacket({
  dcid,
  packetNumber,
  largestAcked = -1,
  payload,
  keys,
  keyPhase = 0,
  spinBit = 0,
  minPacketSize = 0,
}) {
  const pnBytes = encodePacketNumber(packetNumber, largestAcked);
  const pnLen = pnBytes.length;
  const pnOffset = 1 + dcid.length;
  const paddedPayload = padPayloadForProtection(payload, pnOffset, pnLen, minPacketSize);

  const header = Buffer.allocUnsafe(pnOffset + pnLen);
  // Short Header (0) | Fixed (1) | Spin (1) | Reserved (00) | Key Phase (1) | PN Length (2)
  header[0] = 0x40 | ((spinBit & 1) << 5) | ((keyPhase & 1) << 2) | ((pnLen - 1) & 0x03);
  dcid.copy(header, 1);
  pnBytes.copy(header, pnOffset);

  return sealPacket(header, pnOffset, pnLen, paddedPayload, keys, packetNumber);
}

/**
 * Builds a Version Negotiation packet (RFC 9000 §17.2.1) — useful for tests / server tooling.
 */
function buildVersionNegotiationPacket({ dcid, scid, versions }) {
  const out = Buffer.allocUnsafe(7 + dcid.length + scid.length + versions.length * 4);
  let pos = 0;
  out[pos++] = 0x80 | (Math.random() * 0x7f) | 0x40;
  out.writeUInt32BE(0, pos);
  pos += 4;
  out[pos++] = dcid.length;
  dcid.copy(out, pos);
  pos += dcid.length;
  out[pos++] = scid.length;
  scid.copy(out, pos);
  pos += scid.length;
  for (const v of versions) {
    out.writeUInt32BE(v >>> 0, pos);
    pos += 4;
  }
  return out;
}

/**
 * Returns the Destination Connection ID of the first packet in `datagram` without full parsing.
 */
function peekDestinationConnectionId(datagram, shortHeaderCidLen) {
  if (datagram.length === 0) return null;
  if ((datagram[0] & 0x80) === 0) {
    if (datagram.length < 1 + shortHeaderCidLen) return null;
    return datagram.subarray(1, 1 + shortHeaderCidLen);
  }
  if (datagram.length < 6) return null;
  const len = datagram[5];
  if (len > 255 || 6 + len > datagram.length) return null;
  return datagram.subarray(6, 6 + len);
}

/**
 * Splits a received UDP datagram into one or more coalesced QUIC packets.
 * Malformed trailing data is ignored (RFC 9000 §12.2).
 */
function splitDatagram(datagram, localCidLen) {
  const packets = [];
  let offset = 0;

  while (offset < datagram.length) {
    const first = datagram[offset];

    // Short Header (1-RTT): always the last packet in a coalesced UDP datagram
    if ((first & 0x80) === 0) {
      if ((first & 0x40) === 0) break; // Fixed Bit = 0 -> not QUIC (or trailing padding)
      // Keep short (>= 21 byte) packets too so Stateless Reset detection (RFC 9000 §10.3) can inspect them
      if (offset + 1 + localCidLen >= datagram.length) break;
      packets.push({
        type: '1rtt',
        dcid: datagram.subarray(offset + 1, offset + 1 + localCidLen),
        pnOffset: 1 + localCidLen,
        raw: datagram.subarray(offset),
      });
      break;
    }

    // Long Header invariant fields
    if (offset + 7 > datagram.length) break;
    const version = datagram.readUInt32BE(offset + 1) >>> 0;
    const dcidLen = datagram[offset + 5];
    if (offset + 7 + dcidLen > datagram.length) break;
    const dcid = datagram.subarray(offset + 6, offset + 6 + dcidLen);
    const scidLen = datagram[offset + 6 + dcidLen];
    let pos = offset + 7 + dcidLen + scidLen;
    if (pos > datagram.length) break;
    const scid = datagram.subarray(offset + 7 + dcidLen, pos);

    // Version Negotiation packet (version == 0)
    if (version === 0) {
      const supportedVersions = [];
      for (let vPos = pos; vPos + 4 <= datagram.length; vPos += 4) {
        supportedVersions.push(datagram.readUInt32BE(vPos) >>> 0);
      }
      packets.push({
        type: 'version_negotiation',
        version: 0,
        dcid,
        scid,
        supportedVersions,
        raw: datagram.subarray(offset),
      });
      break;
    }

    if (version !== QUIC_VERSION_1) {
      packets.push({ type: 'unsupported_version', version, dcid, scid, raw: datagram.subarray(offset) });
      break;
    }
    if ((first & 0x40) === 0) break; // Fixed Bit MUST be 1 in QUIC v1 long headers
    if (dcidLen > MAX_CID_LENGTH || scidLen > MAX_CID_LENGTH) break;

    const longType = (first & 0x30) >>> 4;

    // Retry packet: extends to the end of the datagram
    if (longType === PACKET_TYPE_RETRY) {
      if (datagram.length - pos < AEAD_TAG_LENGTH) break;
      packets.push({
        type: 'retry',
        version,
        dcid,
        scid,
        token: datagram.subarray(pos, datagram.length - AEAD_TAG_LENGTH),
        raw: datagram.subarray(offset),
      });
      break;
    }

    let token = null;
    if (longType === PACKET_TYPE_INITIAL) {
      const tokLenDec = decodeVarint(datagram, pos);
      if (!tokLenDec || typeof tokLenDec.value !== 'number') break;
      pos += tokLenDec.bytesRead;
      if (pos + tokLenDec.value > datagram.length) break;
      token = datagram.subarray(pos, pos + tokLenDec.value);
      pos += tokLenDec.value;
    }

    const pktLenDec = decodeVarint(datagram, pos);
    if (!pktLenDec || typeof pktLenDec.value !== 'number') break;
    pos += pktLenDec.bytesRead;
    const pktEnd = pos + pktLenDec.value;
    if (pktEnd > datagram.length || pktLenDec.value < 1 + AEAD_TAG_LENGTH) break;

    packets.push({
      type: LONG_TYPE_NAMES[longType],
      version,
      dcid,
      scid,
      token: token || Buffer.alloc(0),
      pnOffset: pos - offset,
      raw: datagram.subarray(offset, pktEnd),
    });

    offset = pktEnd;
  }

  return packets;
}

/**
 * Removes Header Protection and decrypts the AEAD payload of a parsed packet.
 * `altKeys` may be a single key object or an array of `{ tag, keys }` candidates which are tried
 * when the packet's Key Phase bit differs from `expectedKeyPhase` (RFC 9001 §6).
 *
 * @returns {{ packetNumber: number, plaintext: Buffer, keyPhase: number, usedAltKeys: boolean,
 *             altKeyTag: string|null, firstByte: number, reservedBits: number, pnLength: number } | null}
 */
function unprotectPacket(pkt, keys, largestPn = -1, expectedKeyPhase = 0, altKeys = null) {
  const { pnOffset, raw } = pkt;
  if (pnOffset + 4 + 16 > raw.length) return null;

  const buf = Buffer.from(raw);
  const mask = headerProtectionMask(keys, buf.subarray(pnOffset + 4, pnOffset + 20));

  const isLong = (buf[0] & 0x80) !== 0;
  buf[0] ^= isLong ? mask[0] & 0x0f : mask[0] & 0x1f;

  const pnLen = (buf[0] & 0x03) + 1;
  if (pnOffset + pnLen + AEAD_TAG_LENGTH > buf.length) return null;
  let truncatedPn = 0;
  for (let i = 0; i < pnLen; i++) {
    buf[pnOffset + i] ^= mask[1 + i];
    truncatedPn = truncatedPn * 256 + buf[pnOffset + i];
  }

  const packetNumber = decodePacketNumber(largestPn, truncatedPn, pnLen * 8);
  const keyPhase = isLong ? 0 : (buf[0] & 0x04) >>> 2;
  const reservedBits = isLong ? buf[0] & 0x0c : buf[0] & 0x18;

  const aad = buf.subarray(0, pnOffset + pnLen);
  const ciphertext = buf.subarray(pnOffset + pnLen);

  let plaintext = null;
  let usedAltKeys = false;
  let altKeyTag = null;

  if (!isLong && keyPhase !== expectedKeyPhase && altKeys) {
    if (Array.isArray(altKeys)) {
      for (const candidate of altKeys) {
        if (!candidate || !candidate.keys) continue;
        plaintext = aeadDecrypt(candidate.keys, packetNumber, ciphertext, aad);
        if (plaintext) {
          usedAltKeys = true;
          altKeyTag = candidate.tag || null;
          break;
        }
      }
    } else {
      plaintext = aeadDecrypt(altKeys, packetNumber, ciphertext, aad);
      if (plaintext) {
        usedAltKeys = true;
        altKeyTag = 'alt';
      }
    }
  } else {
    plaintext = aeadDecrypt(keys, packetNumber, ciphertext, aad);
  }

  if (!plaintext) return null;

  return {
    packetNumber,
    plaintext,
    keyPhase,
    usedAltKeys,
    altKeyTag,
    firstByte: buf[0],
    reservedBits,
    pnLength: pnLen,
  };
}

module.exports = {
  PACKET_TYPE_INITIAL,
  PACKET_TYPE_0RTT,
  PACKET_TYPE_HANDSHAKE,
  PACKET_TYPE_RETRY,
  MAX_CID_LENGTH,
  encodePacketNumber,
  decodePacketNumber,
  applyHeaderProtection,
  buildLongHeaderPacket,
  buildInitialPacket,
  buildZeroRttPacket,
  buildHandshakePacket,
  buildShortPacket,
  buildVersionNegotiationPacket,
  peekDestinationConnectionId,
  splitDatagram,
  unprotectPacket,
};
