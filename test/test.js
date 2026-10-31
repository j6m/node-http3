'use strict';

const assert = require('node:assert/strict');
const dgram = require('node:dgram');
const http3 = require('../index');
const { encodeVarint, decodeVarint } = require('../src/varint');
const { deriveInitialSecrets, deriveUpdatedKeys } = require('../src/crypto');
const {
  buildInitialPacket,
  buildHandshakePacket,
  buildShortPacket,
  splitDatagram,
  unprotectPacket,
} = require('../src/packet');
const {
  parseFrames,
  buildAckFrameFromPacketNumbers,
  buildCryptoFrame,
  buildRetireConnectionIdFrame,
  buildPathChallengeFrame,
  buildPathResponseFrame,
  buildDatagramFrame,
} = require('../src/frame');
const { encodeTransportParameters, decodeTransportParameters } = require('../src/tls13');
const { ByteReassembler, QuicCongestionController } = require('../src/connection');
const { huffmanEncode, huffmanDecode, encodeHeaders, decodeHeaders } = require('../src/qpack');

async function runUnitTests() {
  console.log('--- [1/3] Unit & RFC Test Vectors ---');

  // 1. Varint tests (1, 2, 4, 8 bytes + 62-bit BigInt)
  for (const val of [
    0,
    37,
    63,
    64,
    15293,
    16383,
    16384,
    494878333,
    1073741823,
    1073741824,
    151288809941952652n,
    4611686018427387903n,
  ]) {
    const enc = encodeVarint(val);
    const dec = decodeVarint(enc, 0);
    assert.ok(dec, `Failed to decode varint ${val}`);
    assert.equal(dec.bytesRead, enc.length);
    assert.equal(BigInt(dec.value), BigInt(val));
  }
  console.log('  [OK] QUIC Varint (1, 2, 4, 8-byte & 62-bit BigInt)');

  // 2. RFC 9001 Appendix A.1 Initial Secrets Test Vector
  const rfcDcid = Buffer.from('8394c8f03e515708', 'hex');
  const secrets = deriveInitialSecrets(rfcDcid);
  assert.equal(secrets.client.key.toString('hex'), '1f369613dd76d5467730efcbe3b1a22d');
  assert.equal(secrets.client.iv.toString('hex'), 'fa044b2f42a3fd3b46fb255c');
  assert.equal(secrets.client.hp.toString('hex'), '9f50449e04a0e810283a1e9933adedd2');
  assert.equal(secrets.server.key.toString('hex'), 'cf3a5331653c364c88f0f379b6067e37');
  assert.equal(secrets.server.iv.toString('hex'), '0ac1493ca1905853b0bba03e');
  assert.equal(secrets.server.hp.toString('hex'), 'c206b8d9b9f0f37644430b490eeaa314');
  console.log('  [OK] RFC 9001 Appendix A.1 QUIC v1 Initial Key Derivation exact match');

  // 3. Coalesced Packet Protection & Multi-Phase Key Update Unprotection
  const scid = Buffer.from('0102030405060708', 'hex');
  const pInit = buildInitialPacket({
    dcid: rfcDcid,
    scid,
    packetNumber: 2,
    payload: buildCryptoFrame(0, Buffer.from('hello-initial')),
    keys: secrets.client,
    minPacketSize: 1200,
  });
  assert.equal(pInit.length, 1200);

  const pHs = buildHandshakePacket({
    dcid: rfcDcid,
    scid,
    packetNumber: 0,
    payload: buildCryptoFrame(0, Buffer.from('hello-handshake')),
    keys: secrets.server,
  });

  const phase1Keys = deriveUpdatedKeys(secrets.client);
  const pShortRotated = buildShortPacket({
    dcid: scid,
    packetNumber: 7,
    payload: Buffer.from([0x01]),
    keys: phase1Keys,
    keyPhase: 1,
    spinBit: 1,
  });

  const coalesced = Buffer.concat([pInit, pHs, pShortRotated]);
  const split = splitDatagram(coalesced, scid.length);
  assert.equal(split.length, 3);

  const u0 = unprotectPacket(split[0], secrets.client, -1);
  assert.equal(u0.packetNumber, 2);
  assert.equal(
    parseFrames(u0.plaintext).find((f) => f.type === 'crypto').data.toString(),
    'hello-initial'
  );

  const u1 = unprotectPacket(split[1], secrets.server, -1);
  assert.equal(u1.packetNumber, 0);

  const u2 = unprotectPacket(split[2], secrets.client, -1, 0, [
    { tag: 'next', keys: phase1Keys },
  ]);
  assert.ok(u2);
  assert.equal(u2.packetNumber, 7);
  assert.equal(u2.keyPhase, 1);
  assert.equal(u2.usedAltKeys, true);
  assert.equal(u2.altKeyTag, 'next');
  assert.equal((u2.firstByte >>> 5) & 1, 1); // spinBit preserved
  console.log('  [OK] Coalesced Packet Framing, Spin Bit & Multi-Phase Key Update Unprotection');

  // 4. Advanced QUIC Frames (RETIRE_CONNECTION_ID, PATH_CHALLENGE/RESPONSE, RFC 9221 DATAGRAM) & Transport Params
  const chalBytes = Buffer.from('1122334455667788', 'hex');
  const advFramesBuf = Buffer.concat([
    buildRetireConnectionIdFrame(3),
    buildPathChallengeFrame(chalBytes),
    buildPathResponseFrame(chalBytes),
    buildDatagramFrame(Buffer.from('hello-dgram'), true),
  ]);
  const parsedAdv = parseFrames(advFramesBuf);
  assert.equal(parsedAdv.length, 4);
  assert.equal(parsedAdv[0].type, 'retire_connection_id');
  assert.equal(parsedAdv[0].sequenceNumber, 3);
  assert.equal(parsedAdv[1].type, 'path_challenge');
  assert.ok(parsedAdv[1].data.equals(chalBytes));
  assert.equal(parsedAdv[2].type, 'path_response');
  assert.ok(parsedAdv[2].data.equals(chalBytes));
  assert.equal(parsedAdv[3].type, 'datagram');
  assert.equal(parsedAdv[3].data.toString(), 'hello-dgram');

  const tpEnc = encodeTransportParameters({
    maxIdleTimeout: 30000,
    maxUdpPayloadSize: 1472,
    maxDatagramFrameSize: 65535,
    activeConnectionIdLimit: 8,
    customParams: { 0x3127: 42 },
  });
  const tpDec = decodeTransportParameters(tpEnc);
  assert.equal(tpDec.maxIdleTimeout, 30000);
  assert.equal(tpDec.maxDatagramFrameSize, 65535);
  assert.equal(tpDec.activeConnectionIdLimit, 8);
  console.log('  [OK] Migration/Datagram QUIC Frames & RFC 9221 Transport Parameters');

  // 5. ACK Multi-Range, ByteReassembler & Pluggable Congestion Control (CUBIC / BBR / NewReno)
  const ackBuf = buildAckFrameFromPacketNumbers([0, 1, 2, 5, 6, 10], 24);
  const [ackParsed] = parseFrames(ackBuf);
  assert.equal(ackParsed.largest, 10);
  assert.deepEqual(ackParsed.ranges, [
    [10, 10],
    [5, 6],
    [0, 2],
  ]);

  const reasm = new ByteReassembler();
  assert.equal(reasm.push(6, Buffer.from('world'), true).ended, false);
  const rDone = reasm.push(0, Buffer.from('hello '), false);
  assert.equal(rDone.contiguous.toString(), 'hello world');
  assert.equal(rDone.ended, true);

  for (const algo of ['cubic', 'newreno', 'bbr', 'unlimited']) {
    const cc = new QuicCongestionController({
      algorithm: algo,
      maxDatagramSize: 1350,
      initialCwndPackets: 10,
      pacing: true,
    });
    const initCwnd = cc.cwnd;
    cc.onPacketSent(1350);
    assert.equal(cc.bytesInFlight, 1350);
    cc.onPacketsAcked([{ inFlightBytes: 1350, sentTime: 100 }], 15, 12, 15, 120);
    assert.equal(cc.bytesInFlight, 0);
    if (algo !== 'unlimited') {
      assert.ok(cc.cwnd >= initCwnd);
      const beforeLoss = cc.cwnd;
      cc.onCongestionEvent(150, 200);
      assert.ok(cc.cwnd < beforeLoss);
    }
  }
  console.log('  [OK] ACK Multi-Range, Reassembler & CUBIC / NewReno / BBR Congestion Controllers');

  // 6. QPACK & Huffman all-256-bytes round-trip
  const allBytes = Buffer.alloc(256);
  for (let i = 0; i < 256; i++) allBytes[i] = i;
  const hEnc = huffmanEncode(allBytes);
  const hDec = huffmanDecode(hEnc, true);
  assert.ok(allBytes.equals(hDec));

  const qEnc = encodeHeaders({
    ':method': 'POST',
    ':scheme': 'https',
    ':authority': 'example.com',
    ':path': '/api/v1/test?x=1',
    'content-type': 'application/json',
    authorization: 'Bearer secret-token-123',
    'x-custom-header': 'Merhaba Dunya!',
  });
  const { headers: qDec } = decodeHeaders(qEnc);
  assert.equal(qDec[':method'], 'POST');
  assert.equal(qDec[':path'], '/api/v1/test?x=1');
  assert.equal(qDec['x-custom-header'], 'Merhaba Dunya!');
  console.log('  [OK] QPACK Static Table + 256-Symbol Huffman Encoder/Decoder');
}

async function runLiveHttp3Tests() {
  console.log('\n--- [2/3] Live HTTP/3 Network Tests (Pure Node.js UDP/QUIC v1) ---');

  // Test 1: Cloudflare /cdn-cgi/trace -> server verifies `http=http/3`
  const t0 = performance.now();
  const cfRes = await http3.fetch('https://cloudflare.com/cdn-cgi/trace');
  const elapsed1 = Math.round(performance.now() - t0);
  const traceText = await cfRes.text();
  assert.equal(cfRes.status, 200);
  assert.equal(cfRes.httpVersion, '3.0');
  assert.match(traceText, /http=(http\/3|h3)\b/);
  const traceLines = Object.fromEntries(
    traceText
      .trim()
      .split('\n')
      .map((l) => l.split('='))
  );
  console.log(
    `  [OK] GET https://cloudflare.com/cdn-cgi/trace -> status=${cfRes.status}, protocol=${traceLines.http}, tls=${traceLines.tls}, colo=${traceLines.colo}, cipher=${cfRes.cipher} (${elapsed1}ms)`
  );

  // Test 2: Reused pooled connection (0-handshake 1-RTT speed)
  const t1 = performance.now();
  const cfRes2 = await http3.get('https://cloudflare.com/cdn-cgi/trace');
  const elapsed2 = Math.round(performance.now() - t1);
  assert.equal(cfRes2.status, 200);
  assert.match(await cfRes2.text(), /http=(http\/3|h3)\b/);
  console.log(`  [OK] Pooled 2nd GET on same QUIC connection -> status=${cfRes2.status} (${elapsed2}ms!)`);

  // Test 3: `http2`-compatible `http3.connect()` API with 3 concurrent multiplexed streams
  const client = http3.connect('https://www.google.com');
  const paths = ['/robots.txt', '/generate_204', '/favicon.ico'];
  const multiResults = await Promise.all(
    paths.map(
      (p) =>
        new Promise((resolve, reject) => {
          const req = client.request({
            ':method': 'GET',
            ':path': p,
            'user-agent': 'node-http3-test/3.0',
          });
          let status = 0;
          const chunks = [];
          req.setTimeout(10000, () => {
            req.close();
            reject(new Error(`Timeout on ${p}`));
          });
          req.on('response', (headers) => {
            status = Number(headers[':status']);
          });
          req.on('data', (c) => chunks.push(c));
          req.on('end', () =>
            resolve({ path: p, status, bytes: Buffer.concat(chunks).length, streamId: req.id })
          );
          req.on('error', reject);
          req.end();
        })
    )
  );
  client.close();
  for (const r of multiResults) {
    assert.ok(r.status >= 200 && r.status < 400, `Unexpected status ${r.status} for ${r.path}`);
  }
  console.log('  [OK] Concurrent Multiplexed Streams on www.google.com:', multiResults);

  // Test 4: HTTP/3 POST request with binary payload (RFC 8484 DoH over HTTP/3) + Multi-packet JSON POST
  const dnsQuery = Buffer.from(
    'abcd01000001000000000000' + '076578616d706c6503636f6d00' + '00010001',
    'hex'
  );
  const dohRes = await http3.post('https://cloudflare-dns.com/dns-query', dnsQuery, {
    headers: {
      'content-type': 'application/dns-message',
      accept: 'application/dns-message',
    },
  });
  assert.equal(dohRes.status, 200);
  const dohBuf = await dohRes.buffer();
  assert.ok(dohBuf.length > dnsQuery.length && dohBuf.readUInt16BE(0) === 0xabcd);
  console.log(
    `  [OK] POST https://cloudflare-dns.com/dns-query (DoH over HTTP/3) -> status=${dohRes.status}, responseBytes=${dohBuf.length}`
  );

  const largePayload = {
    items: Array.from({ length: 120 }, (_, i) => ({ id: i, text: 'merhaba-http3-quic-nodejs' })),
  };
  const largePostRes = await http3.post('https://cloudflare.com/cdn-cgi/trace', largePayload);
  assert.ok(largePostRes.status >= 200 && largePostRes.status < 500);
  console.log(
    `  [OK] Multi-Packet (>5 KB) JSON POST over HTTP/3 -> status=${largePostRes.status}, httpVersion=${largePostRes.httpVersion}`
  );

  // Test 5: Classic Node `https.request(url, opts, callback)` streaming API + ESM import check
  const cbBody = await new Promise((resolve, reject) => {
    const req = http3.request('https://cloudflare.com/cdn-cgi/trace', { method: 'GET' }, (res) => {
      assert.equal(res.statusCode, 200);
      let str = '';
      res.setEncoding('utf8');
      res.on('data', (chunk) => (str += chunk));
      res.on('end', () => resolve(str));
    });
    req.on('error', reject);
    req.end();
  });
  assert.match(cbBody, /http=(http\/3|h3)\b/);

  const esmMod = await import('../index.mjs');
  assert.equal(typeof esmMod.fetch, 'function');
  assert.equal(typeof esmMod.QuicConnection, 'function');
  assert.equal(typeof esmMod.QuicCongestionController, 'function');
  console.log('  [OK] Classic callback http3.request() & ESM import("./index.mjs") verified');

  // Test 6: TLS 1.3 PSK Session Resumption + QUIC 0-RTT Early Data on a brand-new connection
  http3.clearCaches();
  const coldRes = await http3.get('https://cloudflare.com/cdn-cgi/trace', { agent: false });
  assert.equal(coldRes.status, 200);
  await new Promise((r) => setTimeout(r, 40));

  const zeroRttRes = await http3.get('https://cloudflare.com/cdn-cgi/trace', { agent: false });
  assert.equal(zeroRttRes.status, 200);
  assert.match(await zeroRttRes.text(), /http=(http\/3|h3)\b/);
  assert.equal(zeroRttRes.timings.resumed, true, 'Expected TLS 1.3 PSK Session Resumption to succeed');
  console.log(
    `  [OK] TLS 1.3 PSK Resumption & 0-RTT Cold Reconnect -> cold=${coldRes.timings.totalMs}ms vs resumed=${zeroRttRes.timings.totalMs}ms (resumed=${zeroRttRes.timings.resumed}, 0RTT_sent=${zeroRttRes.timings.earlyDataSent}, 0RTT_accepted=${zeroRttRes.timings.earlyDataAccepted})`
  );

  // Test 7: Microtask Multi-Frame Packet Packing (25 concurrent requests packed into minimal UDP datagrams)
  const burstSession = http3.connect('https://cloudflare.com');
  await burstSession.ready();
  const dgramsBefore = burstSession.stats.datagramsSent;
  const burstResponses = await Promise.all(
    Array.from({ length: 25 }, () =>
      new Promise((resolve, reject) => {
        const r = burstSession.request(
          { ':method': 'GET', ':path': '/cdn-cgi/trace' },
          { endStream: true }
        );
        let status = 0;
        r.on('response', (h) => (status = Number(h[':status'])));
        r.on('data', () => {});
        r.on('end', () => resolve(status));
        r.on('error', reject);
      })
    )
  );
  const dgramsFor25Reqs = burstSession.stats.datagramsSent - dgramsBefore;
  burstSession.close();
  assert.ok(burstResponses.every((s) => s === 200));
  console.log(
    `  [OK] 25 Concurrent Requests Multiplexed & Packed -> all 200 OK using only ${dgramsFor25Reqs} outgoing UDP datagrams!`
  );

  http3.closePool();
}

async function runEnterpriseConnectionTests() {
  console.log('\n--- [3/3] Enterprise QuicConnection v3.0 Tests (Socket Tuning, NoDelay, Cork, Migration, KeyUpdate, PMTUD) ---');

  const keylogLines = [];
  const session = http3.connect('https://cloudflare.com', {
    sessionResume: false, // Full handshake to verify all 4 SSLKEYLOGFILE secrets
    congestionControl: 'cubic',
    initialMtu: 1200, // Start at RFC 9000 minimum 1200B so DPLPMTUD probe upgrades live over the wire!
    ackNoDelay: true,
    socketOptions: {
      ttl: 58,
      recvBufferSize: 512 * 1024,
      sendBufferSize: 512 * 1024,
      connectedUdp: true,
    },
    onKeylog: (line) => keylogLines.push(line.toString('ascii').trim()),
  });

  await session.ready();

  // 1. Verify SSLKEYLOGFILE export
  assert.ok(
    keylogLines.some((l) => l.startsWith('CLIENT_HANDSHAKE_TRAFFIC_SECRET ')),
    'Missing CLIENT_HANDSHAKE_TRAFFIC_SECRET in keylog'
  );
  assert.ok(
    keylogLines.some((l) => l.startsWith('CLIENT_TRAFFIC_SECRET_0 ')),
    'Missing CLIENT_TRAFFIC_SECRET_0 in keylog'
  );
  console.log(`  [OK] NSS SSLKEYLOGFILE export verified (${keylogLines.length} secret lines emitted)`);

  // 2. Verify Socket Options & Runtime Tuning (getSocketState, setTTL, connectedUdp, buffer sizes)
  const sockState1 = session.getSocketState();
  assert.equal(sockState1.bound, true);
  assert.equal(sockState1.connectedUdp, true);
  assert.equal(sockState1.ttl, 58);
  assert.equal(sockState1.ackNoDelay, true);
  assert.ok(sockState1.localPort > 0);
  assert.ok(sockState1.recvBufferSize > 0 && sockState1.sendBufferSize > 0);

  session.setSocketOptions({ ttl: 62, keepAlive: true, keepAliveInterval: 20000 });
  assert.equal(session.getSocketState().ttl, 62);
  console.log(
    `  [OK] UDP Socket Tuning verified -> port=${sockState1.localPort}, connectedUdp=${sockState1.connectedUdp}, ttl=${session.getSocketState().ttl}, recvBuf=${sockState1.recvBufferSize}B, sendBuf=${sockState1.sendBufferSize}B`
  );

  // 3. Verify `setNoDelay(true)` synchronous zero-microtask send!
  session.setNoDelay(true);
  assert.equal(session.getSocketState().noDelay, true);
  const beforeNoDelayDgrams = session.stats.datagramsSent;
  const ndReqPromise = new Promise((resolve, reject) => {
    const req = session.request(
      { ':method': 'GET', ':path': '/cdn-cgi/trace' },
      { endStream: true, priority: { urgency: 0, incremental: false } }
    );
    // MUST have flushed synchronously BEFORE this callback even returns!
    assert.equal(
      session.stats.datagramsSent,
      beforeNoDelayDgrams + 1,
      'setNoDelay(true) must flush UDP packet synchronously in the same call stack!'
    );
    let status = 0;
    req.on('response', (h) => (status = Number(h[':status'])));
    req.on('data', () => {});
    req.on('end', () => resolve(status));
    req.on('error', reject);
  });
  assert.equal(await ndReqPromise, 200);
  console.log('  [OK] setNoDelay(true) -> synchronous 0-microtask UDP packet dispatch verified!');

  // 4. Verify `cork()` + `uncork()` manual single-datagram batching + RFC 9218 Stream Prioritization!
  const beforeCorkDgrams = session.stats.datagramsSent;
  session.cork();
  const corkPromises = [7, 5, 1, 0, 3].map(
    (urg) =>
      new Promise((resolve, reject) => {
        const req = session.request(
          { ':method': 'GET', ':path': '/cdn-cgi/trace', priority: `u=${urg}, i` },
          { endStream: true }
        );
        let status = 0;
        req.on('response', (h) => (status = Number(h[':status'])));
        req.on('data', () => {});
        req.on('end', () => resolve(status));
        req.on('error', reject);
      })
  );
  // While corked, even with noDelay=true, 0 UDP datagrams may be sent!
  assert.equal(
    session.stats.datagramsSent,
    beforeCorkDgrams,
    'cork() must hold all frames in memory without sending UDP datagrams'
  );
  session.uncork();
  const corkSentDgrams = session.stats.datagramsSent - beforeCorkDgrams;
  assert.equal(
    corkSentDgrams,
    1,
    `Expected uncork() to pack 5 prioritized requests into 1 UDP datagram, got ${corkSentDgrams}`
  );
  const corkStatuses = await Promise.all(corkPromises);
  assert.ok(corkStatuses.every((s) => s === 200));
  session.setNoDelay(false);
  console.log(
    `  [OK] cork() / uncork() + RFC 9218 Priority (u=0..7, i) -> 5 requests held at 0 dgrams, flushed synchronously in ${corkSentDgrams} UDP datagram!`
  );

  // 5. Live QUIC `ping()` round-trip measurement
  const livePingMs = await session.ping();
  assert.ok(livePingMs > 0 && livePingMs < 2000);
  console.log(`  [OK] Live QUIC PING -> ACK round-trip measured at ${livePingMs}ms`);

  // 6. Live DPLPMTUD Path MTU Probe (`probeMtu(1420)`)
  assert.equal(session.getDiagnostics().mtu.currentMtu, 1200);
  const mtuRes = await session.probeMtu(1420);
  assert.equal(mtuRes.ok, true, 'Expected DPLPMTUD probe to succeed');
  assert.ok(mtuRes.mtu > 1200, `Expected MTU upgrade above 1200, got ${mtuRes.mtu}`);
  assert.equal(mtuRes.mtu, Math.min(1420, mtuRes.peerMaxMtu));
  assert.equal(session.getDiagnostics().mtu.currentMtu, mtuRes.mtu);
  console.log(
    `  [OK] Live DPLPMTUD Path MTU Discovery -> upgraded MTU 1200 -> ${mtuRes.mtu} bytes (peerMax=${mtuRes.peerMaxMtu}B)!`
  );

  // 7. Live Client-Initiated 1-RTT Key Update (`initiateKeyUpdate()` - RFC 9001 §6)
  const kuInfo = session.initiateKeyUpdate();
  assert.equal(kuInfo.keyPhase, 1);
  assert.equal(kuInfo.keyUpdates, 1);

  const postKeyUpdateStatus = await new Promise((resolve, reject) => {
    const req = session.request({ ':method': 'GET', ':path': '/cdn-cgi/trace' }, { endStream: true });
    let status = 0;
    req.on('response', (h) => (status = Number(h[':status'])));
    req.on('data', () => {});
    req.on('end', () => resolve(status));
    req.on('error', reject);
  });
  assert.equal(postKeyUpdateStatus, 200);
  console.log(
    `  [OK] Live 1-RTT Key Update (RFC 9001 §6) -> rotated AEAD keys to keyPhase=${kuInfo.keyPhase} & completed HTTP/3 GET 200 OK!`
  );

  // 8. Live Active Connection Migration (`migrate()` - RFC 9000 §9) across a brand-new local UDP port!
  const migResult = await session.migrate();
  assert.notEqual(
    migResult.oldLocalPort,
    migResult.newLocalPort,
    'Migration must bind a new local UDP port'
  );
  assert.ok(migResult.validationRttMs > 0);

  const postMigBody = await new Promise((resolve, reject) => {
    const req = session.request({ ':method': 'GET', ':path': '/cdn-cgi/trace' }, { endStream: true });
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
  assert.match(postMigBody, /http=(http\/3|h3)\b/);
  const diag = session.getDiagnostics();
  session.close();
  console.log(
    `  [OK] Live Active Connection Migration (RFC 9000 §9) -> port ${migResult.oldLocalPort} -> ${migResult.newLocalPort} (switchedCid=${migResult.switchedCid}, dcidSeq=${migResult.dcidSeq}, pathValidated=${migResult.validationRttMs}ms, cwnd=${diag.congestion.cwnd}B)`
  );

  // 9. Bring-Your-Own Custom `dgram.Socket` (`customSocket`) test
  const customUdp = dgram.createSocket('udp4');
  await new Promise((resolve) => customUdp.bind(0, resolve));
  const customLocalPort = customUdp.address().port;

  const customRes = await http3.get('https://cloudflare.com/cdn-cgi/trace', {
    agent: false,
    socketOptions: {
      customSocket: customUdp,
      closeCustomSocket: false,
    },
  });
  assert.equal(customRes.status, 200);
  // Since closeCustomSocket: false, our custom socket remains open and owned by us!
  assert.equal(customUdp.address().port, customLocalPort);
  customUdp.close();
  console.log(
    `  [OK] Bring-Your-Own dgram.Socket (customSocket on port ${customLocalPort}) -> HTTP/3 200 OK & socket ownership preserved!`
  );
}

async function runHardenedV31Tests() {
  console.log('\n--- [4/4] Hardened v3.1 Tests (Varint/Packet/H3Frame Guards, Dynamic QPACK & 300-Stream MAX_STREAMS) ---');

  // 1. Varint strict bounds, forced-width, VarintReader & VarintWriter
  assert.throws(() => http3.varint.encodeVarint(2 ** 53), http3.VarintError);
  assert.throws(() => http3.varint.encodeVarint(3.14), http3.VarintError);
  assert.throws(() => http3.varint.encodeVarint(-1), http3.VarintError);
  const forced4 = http3.varint.encodeVarint(37, 4);
  assert.equal(forced4.length, 4);
  assert.equal(http3.varint.isMinimalVarint(forced4), false);
  assert.equal(http3.varint.decodeVarint(forced4).value, 37);

  const vw = new http3.VarintWriter(8);
  vw.writeVarint(15293).writeVarint(4611686018427387903n).writeUInt8(0xaa);
  const vr = new http3.VarintReader(vw.finish());
  assert.equal(vr.readVarintNumber(), 15293);
  assert.equal(vr.readVarint(), 4611686018427387903n);
  assert.equal(vr.readUInt8(), 0xaa);
  assert.equal(vr.done, true);
  console.log('  [OK] Varint strict bounds (unsafe Number rejection, forced-width, VarintReader/Writer) verified');

  // 2. >32-bit Packet Number reconstruction & splitDatagram Fixed-Bit/CID guards
  const bigPn = 2 ** 35 + 12345;
  const encPn = http3.packet.encodePacketNumber(bigPn, bigPn - 10);
  const recPn = http3.packet.decodePacketNumber(bigPn - 1, encPn.readUIntBE(0, encPn.length), encPn.length * 8);
  assert.equal(recPn, bigPn);
  assert.equal(http3.packet.splitDatagram(Buffer.from([0x80, 0, 0, 0, 1, 21, ...new Array(30).fill(0)]), 8).length, 0);
  console.log('  [OK] >32-bit Packet Number reconstruction & malformed datagram filtering verified');

  // 3. H3StreamParser OOM & RFC 9114 frame/settings placement guards
  const reqParser = new http3.h3frame.H3StreamParser({ maxBufferedFrameSize: 1024, isControlStream: false });
  const hugeHeadersHeader = Buffer.concat([
    http3.varint.encodeVarint(0x01), // HEADERS
    http3.varint.encodeVarint(4611686018427387903n), // 2^62 - 1 bytes!
  ]);
  assert.throws(() => reqParser.push(hugeHeadersHeader), (err) => err.h3Code === 0x0107);

  const reqParser2 = new http3.h3frame.H3StreamParser({ isControlStream: false });
  assert.throws(() => reqParser2.push(http3.h3frame.buildSettingsFrame()), (err) => err.h3Code === 0x0105);

  const ctrlParser = new http3.h3frame.H3StreamParser({ isControlStream: true });
  assert.throws(() => ctrlParser.push(http3.h3frame.buildGoawayFrame(0)), (err) => err.h3Code === 0x010a);
  console.log('  [OK] H3StreamParser 62-bit OOM guard & RFC 9114 stream/frame placement rules verified');

  // 4. QPACK CR/LF injection guard + Stateful Dynamic Table out-of-order blocked stream unblocking
  assert.throws(() => http3.qpack.encodeHeaders({ ':method': 'GET', 'x-evil': 'ok\r\nInjected: 1' }), http3.QpackError);
  assert.throws(() => http3.qpack.encodeHeaders({ ':method': 'GET', 'bad name': 'val' }), http3.QpackError);

  const enc = new http3.QpackEncoder({ maxCapacity: 4096 });
  const dec = new http3.QpackDecoder({ maxTableCapacity: 4096, maxBlockedStreams: 16 });
  enc.applyPeerSettings(4096, 16);

  // Pass 1 inserts into encoder stream; simulate ACK so Pass 2 emits dynamic table references
  const sec1 = enc.encode(0, { ':method': 'GET', ':scheme': 'https', ':authority': 'example.com', ':path': '/api', 'x-tenant': 'antigravity-pro' });
  const encInstr1 = enc.takeEncoderStreamData();
  assert.ok(encInstr1 && encInstr1.length > 0);
  dec.feedEncoderStream(encInstr1);
  assert.equal(dec.decodeFieldSection(0, sec1, 'request').blocked, false);
  // Send Insert Count Increment from decoder -> encoder so encoder knows dynamic entries are received
  enc.feedDecoderStream(http3.qpack.encodePrefixInt(0x00, 6, dec.table.insertCount));

  // Now simulate an out-of-order dynamic reference arriving BEFORE a new encoder insert
  const decOutOfOrder = new http3.QpackDecoder({ maxTableCapacity: 4096, maxBlockedStreams: 16 });
  const sec2 = enc.encode(4, { ':method': 'GET', ':scheme': 'https', ':authority': 'example.com', ':path': '/api', 'x-tenant': 'antigravity-pro' });
  assert.ok(sec2.length < sec1.length, 'Dynamic QPACK encoding must shrink repeated headers');
  const blockedAttempt = decOutOfOrder.decodeFieldSection(4, sec2, 'request');
  assert.equal(blockedAttempt.blocked, true, 'Must report blocked when encoder stream has not arrived yet');
  decOutOfOrder.feedEncoderStream(encInstr1);
  assert.equal(decOutOfOrder.isUnblocked(4), true);
  const unblockedRes = decOutOfOrder.decodeFieldSection(4, sec2, 'request');
  assert.equal(unblockedRes.blocked, false);
  assert.equal(unblockedRes.headers['x-tenant'], 'antigravity-pro');
  console.log(
    `  [OK] QPACK CR/LF injection guard + Stateful Dynamic Table (${sec1.length}B -> ${sec2.length}B) & out-of-order unblocking verified`
  );

  // 5. Live 300-Concurrent-Stream MAX_STREAMS / STREAMS_BLOCKED Stress Test on Cloudflare (limit=256)!
  const stressSession = http3.connect('https://cloudflare.com');
  await stressSession.ready();
  const initialPeerLimit = stressSession.quic.peerMaxStreamsBidi;
  const totalStreams = 300;
  const statuses = await Promise.all(
    Array.from({ length: totalStreams }, () =>
      new Promise((resolve, reject) => {
        const req = stressSession.request({ ':method': 'GET', ':path': '/cdn-cgi/trace' }, { endStream: true });
        let st = 0;
        req.on('response', (h) => (st = Number(h[':status'])));
        req.on('data', () => {});
        req.on('end', () => resolve(st));
        req.on('error', reject);
      })
    )
  );
  const finalPeerLimit = stressSession.quic.peerMaxStreamsBidi;
  const qStats = stressSession.qpackStats;
  stressSession.close();
  assert.equal(statuses.filter((s) => s === 200).length, totalStreams);
  console.log(
    `  [OK] Live 300-Stream Concurrency Stress Test -> 300/300 200 OK! (peerMaxStreamsBidi grew ${initialPeerLimit} -> ${finalPeerLimit}, QPACK dynamic inserts=${qStats.decoder.insertCount}, dynamicRefs=${qStats.decoder.dynamicRefs})`
  );
}

(async () => {
  try {
    await runUnitTests();
    await runLiveHttp3Tests();
    await runEnterpriseConnectionTests();
    await runHardenedV31Tests();
    console.log('\nALL HTTP/3 & ENTERPRISE QUIC v3.1 TESTS PASSED!');
  } catch (err) {
    console.error('\nTEST FAILED:', err);
    http3.closePool();
    process.exit(1);
  }
})();
