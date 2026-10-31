'use strict';

const crypto = require('node:crypto');

const QUIC_VERSION_1 = 0x00000001;
const INITIAL_SALT_V1 = Buffer.from('38762cf7f55934b34d179ae6a4c80cadccbb7f0a', 'hex');
const RETRY_KEY_V1 = Buffer.from('be0c690b9f66575a1d766b54e368c84e', 'hex');
const RETRY_NONCE_V1 = Buffer.from('461599d35d632bf2239825bb', 'hex');

const CIPHER_SUITES = {
  0x1301: {
    id: 0x1301,
    name: 'TLS_AES_128_GCM_SHA256',
    hash: 'sha256',
    hashLen: 32,
    keyLen: 16,
    ivLen: 12,
    hpLen: 16,
    tagLen: 16,
    aead: 'aes-128-gcm',
    hpAlg: 'aes-128-ecb',
  },
  0x1302: {
    id: 0x1302,
    name: 'TLS_AES_256_GCM_SHA384',
    hash: 'sha384',
    hashLen: 48,
    keyLen: 32,
    ivLen: 12,
    hpLen: 32,
    tagLen: 16,
    aead: 'aes-256-gcm',
    hpAlg: 'aes-256-ecb',
  },
  0x1303: {
    id: 0x1303,
    name: 'TLS_CHACHA20_POLY1305_SHA256',
    hash: 'sha256',
    hashLen: 32,
    keyLen: 32,
    ivLen: 12,
    hpLen: 32,
    tagLen: 16,
    aead: 'chacha20-poly1305',
    hpAlg: 'chacha20',
  },
};

/**
 * RFC 5869 HKDF-Extract(salt, IKM) -> PRK
 */
function hkdfExtract(hash, salt, ikm) {
  const hashLen = hash === 'sha384' ? 48 : 32;
  const actualSalt = salt && salt.length > 0 ? salt : Buffer.alloc(hashLen, 0);
  return crypto.createHmac(hash, actualSalt).update(ikm).digest();
}

/**
 * RFC 5869 HKDF-Expand(PRK, info, L) -> OKM
 */
function hkdfExpand(hash, prk, info, length) {
  const hashLen = hash === 'sha384' ? 48 : 32;
  const blocks = Math.ceil(length / hashLen);
  const out = Buffer.allocUnsafe(blocks * hashLen);
  let prev = Buffer.alloc(0);
  for (let i = 1; i <= blocks; i++) {
    const hmac = crypto.createHmac(hash, prk);
    hmac.update(prev);
    hmac.update(info);
    hmac.update(Buffer.from([i]));
    prev = hmac.digest();
    prev.copy(out, (i - 1) * hashLen);
  }
  return out.subarray(0, length);
}

/**
 * RFC 8446 Section 7.1 HKDF-Expand-Label(Secret, Label, Context, Length)
 */
function hkdfExpandLabel(hash, secret, label, context, length) {
  const fullLabel = Buffer.from('tls13 ' + label, 'ascii');
  const ctx = context || Buffer.alloc(0);
  const info = Buffer.allocUnsafe(2 + 1 + fullLabel.length + 1 + ctx.length);
  info.writeUInt16BE(length, 0);
  info[2] = fullLabel.length;
  fullLabel.copy(info, 3);
  info[3 + fullLabel.length] = ctx.length;
  if (ctx.length > 0) {
    ctx.copy(info, 4 + fullLabel.length);
  }
  return hkdfExpand(hash, secret, info, length);
}

/**
 * Derives QUIC Packet Protection keys (key, iv, hp) from a TLS 1.3 traffic secret.
 */
function derivePacketProtectionKeys(suiteId, trafficSecret, existingHp = null) {
  const suite = CIPHER_SUITES[suiteId];
  if (!suite) {
    throw new Error(`Unsupported TLS 1.3 cipher suite: 0x${suiteId.toString(16)}`);
  }
  const empty = Buffer.alloc(0);
  const key = hkdfExpandLabel(suite.hash, trafficSecret, 'quic key', empty, suite.keyLen);
  const iv = hkdfExpandLabel(suite.hash, trafficSecret, 'quic iv', empty, suite.ivLen);
  const hp = existingHp || hkdfExpandLabel(suite.hash, trafficSecret, 'quic hp', empty, suite.hpLen);
  return {
    suite,
    secret: trafficSecret,
    key,
    iv,
    hp,
  };
}

/**
 * RFC 9001 Section 5.2: Derive client and server Initial packet protection keys from DCID.
 */
function deriveInitialSecrets(dcid) {
  const initialSecret = hkdfExtract('sha256', INITIAL_SALT_V1, dcid);
  const empty = Buffer.alloc(0);
  const clientInitialSecret = hkdfExpandLabel('sha256', initialSecret, 'client in', empty, 32);
  const serverInitialSecret = hkdfExpandLabel('sha256', initialSecret, 'server in', empty, 32);
  return {
    client: derivePacketProtectionKeys(0x1301, clientInitialSecret),
    server: derivePacketProtectionKeys(0x1301, serverInitialSecret),
  };
}

/**
 * RFC 9001 Section 6.1: Derive next-generation 1-RTT keys for Key Update ("quic ku").
 * Note: Header protection key `hp` is NOT updated during Key Update.
 */
function deriveUpdatedKeys(currentKeys) {
  const { suite, secret, hp } = currentKeys;
  const nextSecret = hkdfExpandLabel(suite.hash, secret, 'quic ku', Buffer.alloc(0), suite.hashLen);
  return derivePacketProtectionKeys(suite.id, nextSecret, hp);
}

const SCRATCH_ENC_NONCE = Buffer.allocUnsafe(12);
const SCRATCH_DEC_NONCE = Buffer.allocUnsafe(12);

/**
 * RFC 9001 Section 5.3: Compute 12-byte AEAD nonce by XORing 12-byte IV with 62-bit packet number.
 */
function buildNonceInto(target, iv, packetNumber) {
  iv.copy(target, 0, 0, 12);
  if (typeof packetNumber === 'number' && packetNumber <= 0xffffffff) {
    target.writeUInt32BE((target.readUInt32BE(8) ^ (packetNumber >>> 0)) >>> 0, 8);
    return target;
  }
  const pn = typeof packetNumber === 'bigint' ? packetNumber : BigInt(packetNumber);
  const hi = Number((pn >> 32n) & 0xffffffffn);
  const lo = Number(pn & 0xffffffffn);
  target.writeUInt32BE((target.readUInt32BE(4) ^ hi) >>> 0, 4);
  target.writeUInt32BE((target.readUInt32BE(8) ^ lo) >>> 0, 8);
  return target;
}

function buildNonce(iv, packetNumber) {
  return buildNonceInto(Buffer.allocUnsafe(12), iv, packetNumber);
}

/**
 * Encrypts QUIC packet payload using AEAD (AES-128-GCM, AES-256-GCM, or ChaCha20-Poly1305).
 * Returns `ciphertext || 16-byte authTag`.
 */
function aeadEncrypt(keys, packetNumber, plaintext, aad) {
  const { suite, key, iv } = keys;
  const nonce = buildNonceInto(SCRATCH_ENC_NONCE, iv, packetNumber);
  const opts = suite.aead === 'chacha20-poly1305' ? { authTagLength: 16 } : undefined;
  const cipher = crypto.createCipheriv(suite.aead, key, nonce, opts);
  cipher.setAAD(aad, { plaintextLength: plaintext.length });
  const enc1 = cipher.update(plaintext);
  const enc2 = cipher.final();
  const tag = cipher.getAuthTag();
  if (enc2.length === 0) {
    const out = Buffer.allocUnsafe(enc1.length + 16);
    enc1.copy(out, 0);
    tag.copy(out, enc1.length);
    return out;
  }
  return Buffer.concat([enc1, enc2, tag], enc1.length + enc2.length + tag.length);
}

/**
 * Decrypts QUIC packet payload using AEAD. Returns plaintext Buffer, or `null` if authentication fails.
 */
function aeadDecrypt(keys, packetNumber, ciphertextWithTag, aad) {
  const { suite, key, iv } = keys;
  if (ciphertextWithTag.length < suite.tagLen) return null;
  const ciphertext = ciphertextWithTag.subarray(0, ciphertextWithTag.length - suite.tagLen);
  const tag = ciphertextWithTag.subarray(ciphertextWithTag.length - suite.tagLen);
  const nonce = buildNonceInto(SCRATCH_DEC_NONCE, iv, packetNumber);
  try {
    const opts = suite.aead === 'chacha20-poly1305' ? { authTagLength: 16 } : undefined;
    const decipher = crypto.createDecipheriv(suite.aead, key, nonce, opts);
    decipher.setAAD(aad, { plaintextLength: ciphertext.length });
    decipher.setAuthTag(tag);
    const dec1 = decipher.update(ciphertext);
    const dec2 = decipher.final();
    return dec2.length > 0 ? Buffer.concat([dec1, dec2]) : dec1;
  } catch {
    return null;
  }
}

const ZERO_5 = Buffer.alloc(5, 0);

/**
 * RFC 9001 Section 5.4: Generate 5-byte Header Protection mask from 16-byte sample.
 */
function headerProtectionMask(keys, sample) {
  if (sample.length < 16) {
    throw new Error(`Header protection sample too short: ${sample.length}`);
  }
  const s16 = sample.length === 16 ? sample : sample.subarray(0, 16);
  const { suite, hp } = keys;
  if (suite.hpAlg === 'chacha20') {
    const cipher = crypto.createCipheriv('chacha20', hp, s16);
    return cipher.update(ZERO_5);
  }
  const cipher = crypto.createCipheriv(suite.hpAlg, hp, null);
  cipher.setAutoPadding(false);
  return cipher.update(s16).subarray(0, 5);
}

/**
 * RFC 9001 Section 5.8: Verify Retry packet 16-byte Integrity Tag.
 */
function verifyRetryIntegrityTag(originalDcid, retryPacket) {
  if (retryPacket.length < 16) return false;
  const withoutTag = retryPacket.subarray(0, retryPacket.length - 16);
  const receivedTag = retryPacket.subarray(retryPacket.length - 16);

  const pseudo = Buffer.allocUnsafe(1 + originalDcid.length + withoutTag.length);
  pseudo[0] = originalDcid.length;
  originalDcid.copy(pseudo, 1);
  withoutTag.copy(pseudo, 1 + originalDcid.length);

  const cipher = crypto.createCipheriv('aes-128-gcm', RETRY_KEY_V1, RETRY_NONCE_V1);
  cipher.setAAD(pseudo);
  cipher.final();
  const computedTag = cipher.getAuthTag();
  return crypto.timingSafeEqual(computedTag, receivedTag);
}

module.exports = {
  QUIC_VERSION_1,
  INITIAL_SALT_V1,
  CIPHER_SUITES,
  hkdfExtract,
  hkdfExpand,
  hkdfExpandLabel,
  derivePacketProtectionKeys,
  deriveInitialSecrets,
  deriveUpdatedKeys,
  buildNonce,
  aeadEncrypt,
  aeadDecrypt,
  headerProtectionMask,
  verifyRetryIntegrityTag,
};

