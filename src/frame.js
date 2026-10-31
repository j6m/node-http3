'use strict';

const { encodeVarint, decodeVarint } = require('./varint');

/**
 * RFC 9000 Section 19: QUIC Frame Parser and Builders.
 */

function frameError(message, frameType = 0, quicCode = 0x07) {
  const err = new Error(message);
  err.quicCode = quicCode;
  err.frameType = Number(frameType) || 0;
  return err;
}

function parseFrames(buf) {
  const frames = [];
  let pos = 0;

  while (pos < buf.length) {
    // Fast skip consecutive PADDING (0x00) bytes
    if (buf[pos] === 0x00) {
      const start = pos;
      while (pos < buf.length && buf[pos] === 0x00) pos++;
      frames.push({ type: 'padding', length: pos - start });
      continue;
    }

    const typeDec = decodeVarint(buf, pos);
    if (!typeDec) throw frameError('Truncated QUIC frame type');
    pos += typeDec.bytesRead;
    const frameType = typeDec.value;

    if (frameType === 0x01) {
      frames.push({ type: 'ping' });
      continue;
    }

    if (frameType === 0x02 || frameType === 0x03) {
      const largestDec = decodeVarint(buf, pos);
      if (!largestDec) throw frameError('Truncated ACK largest', frameType);
      pos += largestDec.bytesRead;

      const delayDec = decodeVarint(buf, pos);
      if (!delayDec) throw frameError('Truncated ACK delay', frameType);
      pos += delayDec.bytesRead;

      const countDec = decodeVarint(buf, pos);
      if (!countDec) throw frameError('Truncated ACK range count', frameType);
      pos += countDec.bytesRead;

      const firstRangeDec = decodeVarint(buf, pos);
      if (!firstRangeDec) throw frameError('Truncated first ACK range', frameType);
      pos += firstRangeDec.bytesRead;

      const largest = Number(largestDec.value);
      const firstRange = Number(firstRangeDec.value);
      const rangeCount = Number(countDec.value);
      if (firstRange > largest) {
        throw frameError('Invalid ACK first range exceeds largest acknowledged', frameType);
      }

      const ranges = [[largest - firstRange, largest]];
      let prevSmallest = largest - firstRange;

      for (let i = 0; i < rangeCount; i++) {
        const gapDec = decodeVarint(buf, pos);
        if (!gapDec) throw frameError('Truncated ACK gap', frameType);
        pos += gapDec.bytesRead;

        const lenDec = decodeVarint(buf, pos);
        if (!lenDec) throw frameError('Truncated ACK range length', frameType);
        pos += lenDec.bytesRead;

        const gap = Number(gapDec.value);
        const rangeLen = Number(lenDec.value);
        if (prevSmallest < gap + 2) {
          throw frameError('Invalid ACK gap underflow', frameType);
        }
        const nextLargest = prevSmallest - gap - 2;
        if (rangeLen > nextLargest) {
          throw frameError('Invalid ACK range length underflow', frameType);
        }
        const nextSmallest = nextLargest - rangeLen;
        ranges.push([nextSmallest, nextLargest]);
        prevSmallest = nextSmallest;
      }

      let ecn = null;
      if (frameType === 0x03) {
        const ect0 = decodeVarint(buf, pos);
        if (!ect0) throw new Error('Truncated ACK ECT0');
        pos += ect0.bytesRead;
        const ect1 = decodeVarint(buf, pos);
        if (!ect1) throw new Error('Truncated ACK ECT1');
        pos += ect1.bytesRead;
        const ce = decodeVarint(buf, pos);
        if (!ce) throw new Error('Truncated ACK ECN-CE');
        pos += ce.bytesRead;
        ecn = { ect0: ect0.value, ect1: ect1.value, ce: ce.value };
      }

      frames.push({
        type: 'ack',
        largest,
        ackDelay: Number(delayDec.value),
        ranges, // array of [minPn, maxPn] inclusive
        ecn,
      });
      continue;
    }

    if (frameType === 0x04) {
      // RESET_STREAM
      const sid = decodeVarint(buf, pos);
      if (!sid) throw new Error('Truncated RESET_STREAM');
      pos += sid.bytesRead;
      const err = decodeVarint(buf, pos);
      if (!err) throw new Error('Truncated RESET_STREAM error');
      pos += err.bytesRead;
      const finalSize = decodeVarint(buf, pos);
      if (!finalSize) throw new Error('Truncated RESET_STREAM finalSize');
      pos += finalSize.bytesRead;
      frames.push({
        type: 'reset_stream',
        streamId: Number(sid.value),
        errorCode: err.value,
        finalSize: Number(finalSize.value),
      });
      continue;
    }

    if (frameType === 0x05) {
      // STOP_SENDING
      const sid = decodeVarint(buf, pos);
      if (!sid) throw new Error('Truncated STOP_SENDING');
      pos += sid.bytesRead;
      const err = decodeVarint(buf, pos);
      if (!err) throw new Error('Truncated STOP_SENDING error');
      pos += err.bytesRead;
      frames.push({
        type: 'stop_sending',
        streamId: Number(sid.value),
        errorCode: err.value,
      });
      continue;
    }

    if (frameType === 0x06) {
      // CRYPTO
      const offDec = decodeVarint(buf, pos);
      if (!offDec) throw new Error('Truncated CRYPTO offset');
      pos += offDec.bytesRead;
      const lenDec = decodeVarint(buf, pos);
      if (!lenDec) throw new Error('Truncated CRYPTO length');
      pos += lenDec.bytesRead;
      const len = Number(lenDec.value);
      if (pos + len > buf.length) throw new Error('Truncated CRYPTO data');
      const data = buf.subarray(pos, pos + len);
      pos += len;
      frames.push({
        type: 'crypto',
        offset: Number(offDec.value),
        data,
      });
      continue;
    }

    if (frameType === 0x07) {
      // NEW_TOKEN
      const lenDec = decodeVarint(buf, pos);
      if (!lenDec) throw new Error('Truncated NEW_TOKEN length');
      pos += lenDec.bytesRead;
      const len = Number(lenDec.value);
      if (pos + len > buf.length) throw new Error('Truncated NEW_TOKEN');
      const token = buf.subarray(pos, pos + len);
      pos += len;
      frames.push({ type: 'new_token', token });
      continue;
    }

    if (typeof frameType === 'number' && frameType >= 0x08 && frameType <= 0x0f) {
      // STREAM (0x08..0x0f)
      const hasOff = (frameType & 0x04) !== 0;
      const hasLen = (frameType & 0x02) !== 0;
      const fin = (frameType & 0x01) !== 0;

      const sidDec = decodeVarint(buf, pos);
      if (!sidDec) throw new Error('Truncated STREAM id');
      pos += sidDec.bytesRead;

      let offset = 0;
      if (hasOff) {
        const offDec = decodeVarint(buf, pos);
        if (!offDec) throw new Error('Truncated STREAM offset');
        pos += offDec.bytesRead;
        offset = Number(offDec.value);
      }

      let len = buf.length - pos;
      if (hasLen) {
        const lenDec = decodeVarint(buf, pos);
        if (!lenDec) throw new Error('Truncated STREAM length');
        pos += lenDec.bytesRead;
        len = Number(lenDec.value);
      }
      if (pos + len > buf.length) throw new Error('Truncated STREAM data');
      const data = buf.subarray(pos, pos + len);
      pos += len;

      frames.push({
        type: 'stream',
        streamId: Number(sidDec.value),
        offset,
        fin,
        data,
      });
      continue;
    }

    if (frameType === 0x10) {
      // MAX_DATA
      const maxDec = decodeVarint(buf, pos);
      if (!maxDec) throw new Error('Truncated MAX_DATA');
      pos += maxDec.bytesRead;
      frames.push({ type: 'max_data', maxData: Number(maxDec.value) });
      continue;
    }

    if (frameType === 0x11) {
      // MAX_STREAM_DATA
      const sid = decodeVarint(buf, pos);
      if (!sid) throw new Error('Truncated MAX_STREAM_DATA sid');
      pos += sid.bytesRead;
      const maxDec = decodeVarint(buf, pos);
      if (!maxDec) throw new Error('Truncated MAX_STREAM_DATA');
      pos += maxDec.bytesRead;
      frames.push({
        type: 'max_stream_data',
        streamId: Number(sid.value),
        maxStreamData: Number(maxDec.value),
      });
      continue;
    }

    if (frameType === 0x12 || frameType === 0x13) {
      // MAX_STREAMS
      const maxDec = decodeVarint(buf, pos);
      if (!maxDec) throw new Error('Truncated MAX_STREAMS');
      pos += maxDec.bytesRead;
      frames.push({
        type: 'max_streams',
        bidi: frameType === 0x12,
        maxStreams: Number(maxDec.value),
      });
      continue;
    }

    if (frameType === 0x14) {
      // DATA_BLOCKED
      const lim = decodeVarint(buf, pos);
      if (!lim) throw new Error('Truncated DATA_BLOCKED');
      pos += lim.bytesRead;
      frames.push({ type: 'data_blocked', limit: Number(lim.value) });
      continue;
    }

    if (frameType === 0x15) {
      // STREAM_DATA_BLOCKED
      const sid = decodeVarint(buf, pos);
      if (!sid) throw new Error('Truncated STREAM_DATA_BLOCKED');
      pos += sid.bytesRead;
      const lim = decodeVarint(buf, pos);
      if (!lim) throw new Error('Truncated STREAM_DATA_BLOCKED limit');
      pos += lim.bytesRead;
      frames.push({
        type: 'stream_data_blocked',
        streamId: Number(sid.value),
        limit: Number(lim.value),
      });
      continue;
    }

    if (frameType === 0x16 || frameType === 0x17) {
      // STREAMS_BLOCKED
      const lim = decodeVarint(buf, pos);
      if (!lim) throw new Error('Truncated STREAMS_BLOCKED');
      pos += lim.bytesRead;
      frames.push({
        type: 'streams_blocked',
        bidi: frameType === 0x16,
        limit: Number(lim.value),
      });
      continue;
    }

    if (frameType === 0x18) {
      // NEW_CONNECTION_ID
      const seq = decodeVarint(buf, pos);
      if (!seq) throw new Error('Truncated NEW_CONNECTION_ID seq');
      pos += seq.bytesRead;
      const retire = decodeVarint(buf, pos);
      if (!retire) throw new Error('Truncated NEW_CONNECTION_ID retire');
      pos += retire.bytesRead;
      if (pos >= buf.length) throw new Error('Truncated NEW_CONNECTION_ID len');
      const cidLen = buf[pos++];
      if (cidLen < 1 || cidLen > 20) {
        throw frameError(`Invalid NEW_CONNECTION_ID length ${cidLen}`, frameType);
      }
      if (Number(retire.value) > Number(seq.value)) {
        throw frameError('NEW_CONNECTION_ID retire_prior_to exceeds sequence_number', frameType);
      }
      if (pos + cidLen + 16 > buf.length) throw frameError('Truncated NEW_CONNECTION_ID cid', frameType);
      const cid = Buffer.from(buf.subarray(pos, pos + cidLen));
      pos += cidLen;
      const statelessResetToken = Buffer.from(buf.subarray(pos, pos + 16));
      pos += 16;
      frames.push({
        type: 'new_connection_id',
        sequenceNumber: Number(seq.value),
        retirePriorTo: Number(retire.value),
        cid,
        statelessResetToken,
      });
      continue;
    }

    if (frameType === 0x19) {
      // RETIRE_CONNECTION_ID
      const seq = decodeVarint(buf, pos);
      if (!seq) throw new Error('Truncated RETIRE_CONNECTION_ID');
      pos += seq.bytesRead;
      frames.push({ type: 'retire_connection_id', sequenceNumber: Number(seq.value) });
      continue;
    }

    if (frameType === 0x1a || frameType === 0x1b) {
      // PATH_CHALLENGE (0x1a) / PATH_RESPONSE (0x1b)
      if (pos + 8 > buf.length) throw new Error('Truncated PATH_CHALLENGE/RESPONSE');
      const data = Buffer.from(buf.subarray(pos, pos + 8));
      pos += 8;
      frames.push({
        type: frameType === 0x1a ? 'path_challenge' : 'path_response',
        data,
      });
      continue;
    }

    if (frameType === 0x1c || frameType === 0x1d) {
      // CONNECTION_CLOSE (0x1c = transport, 0x1d = application)
      const errDec = decodeVarint(buf, pos);
      if (!errDec) throw new Error('Truncated CONNECTION_CLOSE error');
      pos += errDec.bytesRead;

      let triggerFrameType = 0;
      if (frameType === 0x1c) {
        const ftDec = decodeVarint(buf, pos);
        if (!ftDec) throw new Error('Truncated CONNECTION_CLOSE frame type');
        pos += ftDec.bytesRead;
        triggerFrameType = ftDec.value;
      }

      const reasonLenDec = decodeVarint(buf, pos);
      if (!reasonLenDec) throw new Error('Truncated CONNECTION_CLOSE reason len');
      pos += reasonLenDec.bytesRead;
      const reasonLen = Number(reasonLenDec.value);
      if (pos + reasonLen > buf.length) throw new Error('Truncated CONNECTION_CLOSE reason');
      const reason = buf.subarray(pos, pos + reasonLen).toString('utf8');
      pos += reasonLen;

      frames.push({
        type: 'connection_close',
        isApplication: frameType === 0x1d,
        errorCode: errDec.value,
        triggerFrameType,
        reason,
      });
      continue;
    }

    if (frameType === 0x1e) {
      frames.push({ type: 'handshake_done' });
      continue;
    }

    if (frameType === 0x30 || frameType === 0x31) {
      // RFC 9221 DATAGRAM (in case sent)
      let len = buf.length - pos;
      if (frameType === 0x31) {
        const lenDec = decodeVarint(buf, pos);
        if (!lenDec) throw new Error('Truncated DATAGRAM length');
        pos += lenDec.bytesRead;
        len = Number(lenDec.value);
      }
      const data = buf.subarray(pos, pos + len);
      pos += len;
      frames.push({ type: 'datagram', data });
      continue;
    }

    throw frameError(`Unknown QUIC frame type: 0x${frameType.toString(16)}`, frameType, 0x07);
  }

  return frames;
}

function isAckEliciting(frames) {
  for (const f of frames) {
    if (f.type !== 'padding' && f.type !== 'ack' && f.type !== 'connection_close') {
      return true;
    }
  }
  return false;
}

// ---- Frame Encoders ----

function buildPingFrame() {
  return Buffer.from([0x01]);
}

function buildCryptoFrame(offset, data) {
  return Buffer.concat([
    Buffer.from([0x06]),
    encodeVarint(offset),
    encodeVarint(data.length),
    data,
  ]);
}

function buildStreamFrame(streamId, offset, data, fin = false, includeLength = true) {
  let typeByte = 0x08;
  const parts = [];
  if (offset > 0) typeByte |= 0x04;
  if (includeLength) typeByte |= 0x02;
  if (fin) typeByte |= 0x01;

  parts.push(Buffer.from([typeByte]));
  parts.push(encodeVarint(streamId));
  if (offset > 0) parts.push(encodeVarint(offset));
  if (includeLength) parts.push(encodeVarint(data.length));
  if (data.length > 0) parts.push(data);
  return Buffer.concat(parts);
}

/**
 * Builds an ACK frame (0x02) from a list/Set of received packet numbers.
 * Keeps up to `maxRanges` most recent contiguous ACK ranges.
 */
function buildAckFrameFromPacketNumbers(receivedPns, ackDelayEncoded = 0, maxRanges = 32) {
  if (!receivedPns || receivedPns.length === 0) return null;
  const sorted = Array.from(receivedPns).sort((a, b) => b - a); // descending

  // Build descending inclusive ranges [[high, low], ...]
  const ranges = [];
  let high = sorted[0];
  let low = sorted[0];

  for (let i = 1; i < sorted.length; i++) {
    const pn = sorted[i];
    if (pn === low) continue;
    if (pn === low - 1) {
      low = pn;
    } else {
      ranges.push([high, low]);
      if (ranges.length >= maxRanges) {
        high = -1;
        break;
      }
      high = pn;
      low = pn;
    }
  }
  if (high >= 0 && ranges.length < maxRanges) {
    ranges.push([high, low]);
  }

  const [firstHigh, firstLow] = ranges[0];
  const parts = [
    Buffer.from([0x02]),
    encodeVarint(firstHigh),
    encodeVarint(ackDelayEncoded),
    encodeVarint(ranges.length - 1),
    encodeVarint(firstHigh - firstLow),
  ];

  let prevLow = firstLow;
  for (let i = 1; i < ranges.length; i++) {
    const [rHigh, rLow] = ranges[i];
    const gap = prevLow - rHigh - 2;
    const rangeLen = rHigh - rLow;
    parts.push(encodeVarint(gap));
    parts.push(encodeVarint(rangeLen));
    prevLow = rLow;
  }

  return Buffer.concat(parts);
}

function buildMaxDataFrame(maxData) {
  return Buffer.concat([Buffer.from([0x10]), encodeVarint(maxData)]);
}

function buildMaxStreamDataFrame(streamId, maxStreamData) {
  return Buffer.concat([
    Buffer.from([0x11]),
    encodeVarint(streamId),
    encodeVarint(maxStreamData),
  ]);
}

function buildMaxStreamsFrame(maxStreams, bidi = false) {
  return Buffer.concat([
    Buffer.from([bidi ? 0x12 : 0x13]),
    encodeVarint(maxStreams),
  ]);
}

function buildStreamsBlockedFrame(maxStreams, bidi = true) {
  return Buffer.concat([
    Buffer.from([bidi ? 0x16 : 0x17]),
    encodeVarint(maxStreams),
  ]);
}

function buildResetStreamFrame(streamId, errorCode = 0, finalSize = 0) {
  return Buffer.concat([
    Buffer.from([0x04]),
    encodeVarint(streamId),
    encodeVarint(errorCode),
    encodeVarint(finalSize),
  ]);
}

function buildStopSendingFrame(streamId, errorCode = 0) {
  return Buffer.concat([
    Buffer.from([0x05]),
    encodeVarint(streamId),
    encodeVarint(errorCode),
  ]);
}

function buildNewConnectionIdFrame(sequenceNumber, retirePriorTo, cid, statelessResetToken) {
  return Buffer.concat([
    Buffer.from([0x18]),
    encodeVarint(sequenceNumber),
    encodeVarint(retirePriorTo),
    Buffer.from([cid.length]),
    cid,
    statelessResetToken.subarray(0, 16),
  ]);
}

function buildRetireConnectionIdFrame(sequenceNumber) {
  return Buffer.concat([Buffer.from([0x19]), encodeVarint(sequenceNumber)]);
}

function buildPathChallengeFrame(data8) {
  return Buffer.concat([Buffer.from([0x1a]), data8.subarray(0, 8)]);
}

function buildPathResponseFrame(data8) {
  return Buffer.concat([Buffer.from([0x1b]), data8.subarray(0, 8)]);
}

function buildDatagramFrame(data, includeLength = true) {
  const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
  if (includeLength) {
    return Buffer.concat([Buffer.from([0x31]), encodeVarint(buf.length), buf]);
  }
  return Buffer.concat([Buffer.from([0x30]), buf]);
}

function buildConnectionCloseFrame(errorCode = 0, reason = '', isApplication = false, frameType = 0) {
  const reasonBuf = Buffer.from(reason, 'utf8');
  if (isApplication) {
    return Buffer.concat([
      Buffer.from([0x1d]),
      encodeVarint(errorCode),
      encodeVarint(reasonBuf.length),
      reasonBuf,
    ]);
  }
  return Buffer.concat([
    Buffer.from([0x1c]),
    encodeVarint(errorCode),
    encodeVarint(frameType),
    encodeVarint(reasonBuf.length),
    reasonBuf,
  ]);
}

module.exports = {
  parseFrames,
  isAckEliciting,
  buildPingFrame,
  buildCryptoFrame,
  buildStreamFrame,
  buildAckFrameFromPacketNumbers,
  buildMaxDataFrame,
  buildMaxStreamDataFrame,
  buildMaxStreamsFrame,
  buildStreamsBlockedFrame,
  buildResetStreamFrame,
  buildStopSendingFrame,
  buildNewConnectionIdFrame,
  buildRetireConnectionIdFrame,
  buildPathChallengeFrame,
  buildPathResponseFrame,
  buildDatagramFrame,
  buildConnectionCloseFrame,
};

