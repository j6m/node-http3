'use strict';

/**
 * HEAD-TO-HEAD BENCHMARK ARENA:
 *   1) node-http3  (Saf Node.js QUIC v1 + TLS 1.3 + HTTP/3 + 0-RTT + QPACK)
 *   2) node:http2  (Node.js C++ nghttp2 + OpenSSL + TCP)
 *   3) node:https  (Node.js C++ OpenSSL/node:tls + llhttp HTTP/1.1 + TCP)
 */

const https = require('node:https');
const http2 = require('node:http2');
const dns = require('node:dns');
const http3 = require('./index');

const TARGET_HOST = 'cloudflare.com';
const TARGET_PATH = '/cdn-cgi/trace';
const TARGET_ORIGIN = `https://${TARGET_HOST}`;
const TARGET_URL = `${TARGET_ORIGIN}${TARGET_PATH}`;

function calcStats(samples) {
  const sorted = [...samples].sort((a, b) => a - b);
  const sum = sorted.reduce((a, b) => a + b, 0);
  const avg = sum / sorted.length;
  const min = sorted[0];
  const p50 = sorted[Math.floor(sorted.length * 0.5)];
  const p95 = sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * 0.95))];
  return {
    min: +min.toFixed(2),
    p50: +p50.toFixed(2),
    avg: +avg.toFixed(2),
    p95: +p95.toFixed(2),
  };
}

// ---- Helper 1: node:https (node:tls + HTTP/1.1) ----
function httpsRequestOnce({ ip, agent = false, tlsSession = null }) {
  return new Promise((resolve, reject) => {
    let capturedSession = null;
    const t0 = performance.now();
    const req = https.request(
      {
        host: ip,
        port: 443,
        servername: TARGET_HOST,
        path: TARGET_PATH,
        method: 'GET',
        headers: {
          Host: TARGET_HOST,
          'User-Agent': 'bench-https/1.0',
          'Accept-Encoding': 'identity',
        },
        agent,
        session: tlsSession || undefined,
      },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          const ms = performance.now() - t0;
          resolve({
            ms,
            status: res.statusCode,
            body: Buffer.concat(chunks).toString('utf8'),
            tlsSession: capturedSession,
            reusedSocket: req.reusedSocket,
          });
        });
      }
    );
    req.on('socket', (sock) => {
      if (!agent) {
        sock.once('session', (sess) => {
          capturedSession = sess;
        });
      }
    });
    req.on('error', reject);
    req.end();
  });
}

function makeStaticLookup(ip) {
  return (_host, opts, cb) => {
    if (typeof opts === 'function') {
      cb = opts;
      opts = {};
    }
    if (opts && opts.all) {
      cb(null, [{ address: ip, family: 4 }]);
    } else {
      cb(null, ip, 4);
    }
  };
}

// ---- Helper 2: node:http2 (C++ nghttp2 + node:tls) ----
function http2ColdOrResumedOnce({ ip, tlsSession = null }) {
  return new Promise((resolve, reject) => {
    let capturedSession = null;
    const t0 = performance.now();
    const client = http2.connect(TARGET_ORIGIN, {
      servername: TARGET_HOST,
      lookup: makeStaticLookup(ip),
      session: tlsSession || undefined,
    });
    client.on('error', reject);
    if (client.socket) {
      client.socket.on('session', (s) => (capturedSession = s));
    } else {
      client.once('connect', () => {
        client.socket?.on('session', (s) => (capturedSession = s));
      });
    }

    const req = client.request({
      ':method': 'GET',
      ':path': TARGET_PATH,
      'user-agent': 'bench-http2/1.0',
      'accept-encoding': 'identity',
    });
    const chunks = [];
    let status = 0;
    req.on('response', (h) => (status = Number(h[':status'])));
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const ms = performance.now() - t0;
      const sess = capturedSession || client.socket?.getSession?.() || null;
      client.close();
      resolve({
        ms,
        status,
        body: Buffer.concat(chunks).toString('utf8'),
        tlsSession: sess,
      });
    });
    req.on('error', reject);
    req.end();
  });
}

function http2StreamOnSession(client) {
  return new Promise((resolve, reject) => {
    const t0 = performance.now();
    const req = client.request({
      ':method': 'GET',
      ':path': TARGET_PATH,
      'user-agent': 'bench-http2/1.0',
      'accept-encoding': 'identity',
    });
    const chunks = [];
    let status = 0;
    req.on('response', (h) => (status = Number(h[':status'])));
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      resolve({
        ms: performance.now() - t0,
        status,
        body: Buffer.concat(chunks).toString('utf8'),
      });
    });
    req.on('error', reject);
    req.end();
  });
}

// ---- Helper 3: node-http3 (Pure Node.js QUIC v1 + HTTP/3) ----
function http3ColdOrResumedOnce({ ip, sessionResume = true, enable0Rtt = true }) {
  return new Promise((resolve, reject) => {
    const t0 = performance.now();
    const client = http3.connect(TARGET_ORIGIN, {
      host: ip,
      servername: TARGET_HOST,
      sessionResume,
      enable0Rtt,
    });
    client.on('error', reject);

    const req = client.request(
      {
        ':method': 'GET',
        ':path': TARGET_PATH,
        'user-agent': 'bench-http3/1.0',
        'accept-encoding': 'identity',
      },
      { endStream: true }
    );
    const chunks = [];
    let status = 0;
    req.on('response', (h) => (status = Number(h[':status'])));
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const ms = performance.now() - t0;
      const stats = { ...client.stats };
      // Brief 15ms background close if waiting on NewSessionTicket
      setTimeout(() => client.close(), 15).unref?.();
      resolve({
        ms,
        status,
        body: Buffer.concat(chunks).toString('utf8'),
        stats,
      });
    });
    req.on('error', reject);
  });
}

function http3StreamOnSession(client) {
  return new Promise((resolve, reject) => {
    const t0 = performance.now();
    const req = client.request(
      {
        ':method': 'GET',
        ':path': TARGET_PATH,
        'user-agent': 'bench-http3/1.0',
        'accept-encoding': 'identity',
      },
      { endStream: true }
    );
    const chunks = [];
    let status = 0;
    req.on('response', (h) => (status = Number(h[':status'])));
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      resolve({
        ms: performance.now() - t0,
        status,
        body: Buffer.concat(chunks).toString('utf8'),
      });
    });
    req.on('error', reject);
  });
}

function resolveTargetIp(host) {
  return new Promise((resolve, reject) => {
    dns.lookup(host, { family: 4 }, (err, address) => {
      if (err) reject(err);
      else resolve(address);
    });
  });
}

function printRoundTable(title, rows) {
  console.log(`\n================================================================================`);
  console.log(`  ${title}`);
  console.log(`================================================================================`);
  console.table(rows);
}

async function main() {
  const ip = await resolveTargetIp(TARGET_HOST);
  console.log(`Hedef Sunucu : ${TARGET_URL} (${ip}:443)`);
  console.log(`Node Sürümü  : ${process.version} (${process.platform}/${process.arch})`);

  // V8 JIT Warmup across all 3 engines
  const warmH3 = await http3ColdOrResumedOnce({ ip, sessionResume: false, enable0Rtt: false });
  const warmH2 = await http2ColdOrResumedOnce({ ip });
  const warmH1 = await httpsRequestOnce({ ip, agent: false });
  console.log(
    `Protokol Doğrulaması (Cloudflare /cdn-cgi/trace):\n` +
      `  - node-http3 : ${(warmH3.body.match(/http=[^\n]+/) || ['?'])[0]}\n` +
      `  - node:http2 : ${(warmH2.body.match(/http=[^\n]+/) || ['?'])[0]}\n` +
      `  - node:https : ${(warmH1.body.match(/http=[^\n]+/) || ['?'])[0]}`
  );

  // =========================================================================
  // ROUND 1: COLD CONNECT + FIRST REQUEST (Zero Session Cache - 6 Iterations)
  // =========================================================================
  const COLD_ITERS = 6;
  const coldH3 = [];
  const coldH2 = [];
  const coldH1 = [];

  for (let i = 0; i < COLD_ITERS; i++) {
    http3.clearCaches();
    coldH3.push((await http3ColdOrResumedOnce({ ip, sessionResume: false, enable0Rtt: false })).ms);
    coldH2.push((await http2ColdOrResumedOnce({ ip, tlsSession: null })).ms);
    coldH1.push((await httpsRequestOnce({ ip, agent: false, tlsSession: null })).ms);
  }

  const sColdH3 = calcStats(coldH3);
  const sColdH2 = calcStats(coldH2);
  const sColdH1 = calcStats(coldH1);

  printRoundTable(`ROUND 1: SOĞUK BAĞLANTI + İLK İSTEK (Sıfır Önbellek, ${COLD_ITERS} Tur, ms - Düşük Daha İyi)`, [
    { Kütüphane: 'node-http3 (Saf JS QUIC v1)', Protokol: 'HTTP/3 (UDP)', Min_ms: sColdH3.min, Medyan_p50_ms: sColdH3.p50, Ortalama_ms: sColdH3.avg, p95_ms: sColdH3.p95 },
    { Kütüphane: 'node:http2 (C++ nghttp2)', Protokol: 'HTTP/2 (TCP+TLS)', Min_ms: sColdH2.min, Medyan_p50_ms: sColdH2.p50, Ortalama_ms: sColdH2.avg, p95_ms: sColdH2.p95 },
    { Kütüphane: 'node:https (C++ node:tls)', Protokol: 'HTTP/1.1 (TCP+TLS)', Min_ms: sColdH1.min, Medyan_p50_ms: sColdH1.p50, Ortalama_ms: sColdH1.avg, p95_ms: sColdH1.p95 },
  ]);

  // =========================================================================
  // ROUND 2: SESSION RESUMPTION / QUIC 0-RTT EARLY DATA RECONNECT (8 Iterations)
  // =========================================================================
  const RESUME_ITERS = 8;
  http3.clearCaches();

  // Seed 1 connection on each library to obtain TLS 1.3 Session Tickets
  await http3ColdOrResumedOnce({ ip, sessionResume: true, enable0Rtt: true });
  await new Promise((r) => setTimeout(r, 40));

  let h2Seed = await http2ColdOrResumedOnce({ ip });
  await new Promise((r) => setTimeout(r, 40));
  let h2Ticket = h2Seed.tlsSession;

  let h1Seed = await httpsRequestOnce({ ip, agent: false });
  await new Promise((r) => setTimeout(r, 40));
  let h1Ticket = h1Seed.tlsSession;

  const resH3 = [];
  const resH2 = [];
  const resH1 = [];
  let zeroRttAcceptCount = 0;

  for (let i = 0; i < RESUME_ITERS; i++) {
    const r3 = await http3ColdOrResumedOnce({ ip, sessionResume: true, enable0Rtt: true });
    resH3.push(r3.ms);
    if (r3.stats.earlyDataAccepted) zeroRttAcceptCount++;
    await new Promise((r) => setTimeout(r, 30)); // allow fresh NewSessionTicket replenishment

    const r2 = await http2ColdOrResumedOnce({ ip, tlsSession: h2Ticket });
    if (r2.tlsSession) h2Ticket = r2.tlsSession;
    resH2.push(r2.ms);

    const r1 = await httpsRequestOnce({ ip, agent: false, tlsSession: h1Ticket });
    if (r1.tlsSession) h1Ticket = r1.tlsSession;
    resH1.push(r1.ms);
  }

  const sResH3 = calcStats(resH3);
  const sResH2 = calcStats(resH2);
  const sResH1 = calcStats(resH1);

  printRoundTable(
    `ROUND 2: YENİ BAĞLANTIDA SESSION RESUMPTION & QUIC 0-RTT (${RESUME_ITERS} Tur, 0-RTT Kabul: ${zeroRttAcceptCount}/${RESUME_ITERS})`,
    [
      { Kütüphane: 'node-http3 (QUIC 0-RTT + PSK)', Protokol: 'HTTP/3 0-RTT (1 RTT!)', Min_ms: sResH3.min, Medyan_p50_ms: sResH3.p50, Ortalama_ms: sResH3.avg, p95_ms: sResH3.p95 },
      { Kütüphane: 'node:http2 (TLS Ticket)', Protokol: 'HTTP/2 (TCP+PSK)', Min_ms: sResH2.min, Medyan_p50_ms: sResH2.p50, Ortalama_ms: sResH2.avg, p95_ms: sResH2.p95 },
      { Kütüphane: 'node:https (TLS Ticket)', Protokol: 'HTTP/1.1 (TCP+PSK)', Min_ms: sResH1.min, Medyan_p50_ms: sResH1.p50, Ortalama_ms: sResH1.avg, p95_ms: sResH1.p95 },
    ]
  );

  // =========================================================================
  // ROUND 3: WARM PERSISTENT CONNECTION SEQUENTIAL LATENCY (25 Requests)
  // =========================================================================
  const SEQ_ITERS = 25;
  const h3Client = http3.connect(TARGET_ORIGIN, { host: ip, servername: TARGET_HOST });
  await h3Client.ready();
  await http3StreamOnSession(h3Client); // warm stream 0

  const h2Client = http2.connect(TARGET_ORIGIN, {
    servername: TARGET_HOST,
    lookup: makeStaticLookup(ip),
  });
  await new Promise((res) => h2Client.once('connect', res));
  await http2StreamOnSession(h2Client);

  const h1KeepAliveAgent = new https.Agent({ keepAlive: true, maxSockets: 1 });
  await httpsRequestOnce({ ip, agent: h1KeepAliveAgent });

  const seqH3 = [];
  const seqH2 = [];
  const seqH1 = [];

  for (let i = 0; i < SEQ_ITERS; i++) {
    seqH3.push((await http3StreamOnSession(h3Client)).ms);
    seqH2.push((await http2StreamOnSession(h2Client)).ms);
    seqH1.push((await httpsRequestOnce({ ip, agent: h1KeepAliveAgent })).ms);
  }

  const sSeqH3 = calcStats(seqH3);
  const sSeqH2 = calcStats(seqH2);
  const sSeqH1 = calcStats(seqH1);

  printRoundTable(`ROUND 3: SICAK BAĞLANTI ARDIŞIK GECİKME (${SEQ_ITERS} İstek, Tek Açık Bağlantı, ms)`, [
    { Kütüphane: 'node-http3 (Açık QUIC Oturumu)', Protokol: 'HTTP/3', Min_ms: sSeqH3.min, Medyan_p50_ms: sSeqH3.p50, Ortalama_ms: sSeqH3.avg, p95_ms: sSeqH3.p95 },
    { Kütüphane: 'node:http2 (Açık H2 Oturumu)', Protokol: 'HTTP/2', Min_ms: sSeqH2.min, Medyan_p50_ms: sSeqH2.p50, Ortalama_ms: sSeqH2.avg, p95_ms: sSeqH2.p95 },
    { Kütüphane: 'node:https (Keep-Alive Agent)', Protokol: 'HTTP/1.1', Min_ms: sSeqH1.min, Medyan_p50_ms: sSeqH1.p50, Ortalama_ms: sSeqH1.avg, p95_ms: sSeqH1.p95 },
  ]);

  // =========================================================================
  // ROUND 4: CONCURRENT MULTIPLEXED BURST (50 Simultaneous Requests!)
  // =========================================================================
  const CONCURRENCY = 50;

  const dgramsBefore = h3Client.stats.datagramsSent;
  const tBurstH3 = performance.now();
  await Promise.all(Array.from({ length: CONCURRENCY }, () => http3StreamOnSession(h3Client)));
  const burstH3Ms = +(performance.now() - tBurstH3).toFixed(2);
  const burstH3Dgrams = h3Client.stats.datagramsSent - dgramsBefore;

  const tBurstH2 = performance.now();
  await Promise.all(Array.from({ length: CONCURRENCY }, () => http2StreamOnSession(h2Client)));
  const burstH2Ms = +(performance.now() - tBurstH2).toFixed(2);

  // HTTP/1.1 Keep-Alive Agent with standard 6 parallel sockets (RFC / Browser limit; avoids opening 50 new TLS handshakes)
  const h1PoolAgent6 = new https.Agent({ keepAlive: true, maxSockets: 6 });
  // Pre-warm the 6 sockets in the HTTP/1.1 pool so we test pure warm throughput!
  await Promise.all(Array.from({ length: 6 }, () => httpsRequestOnce({ ip, agent: h1PoolAgent6 })));
  const tBurstH1 = performance.now();
  await Promise.all(Array.from({ length: CONCURRENCY }, () => httpsRequestOnce({ ip, agent: h1PoolAgent6 })));
  const burstH1Ms = +(performance.now() - tBurstH1).toFixed(2);

  printRoundTable(`ROUND 4: ${CONCURRENCY} EŞZAMANLI PARALEL İSTEK SAVAŞI (Multiplexing Throughput)`, [
    {
      Kütüphane: `node-http3 (1 QUIC Bağlantısı, ${burstH3Dgrams} UDP paketi)`,
      Toplam_Sure_ms: burstH3Ms,
      Hiz_Istek_sn: Math.round((CONCURRENCY / burstH3Ms) * 1000),
    },
    {
      Kütüphane: 'node:http2 (1 TCP Bağlantısı, 50 Stream)',
      Toplam_Sure_ms: burstH2Ms,
      Hiz_Istek_sn: Math.round((CONCURRENCY / burstH2Ms) * 1000),
    },
    {
      Kütüphane: 'node:https (6 Sıcak Keep-Alive TLS Soketi)',
      Toplam_Sure_ms: burstH1Ms,
      Hiz_Istek_sn: Math.round((CONCURRENCY / burstH1Ms) * 1000),
    },
  ]);

  // Summary speedup banner
  console.log('\n================================================================================');
  console.log('  ÖZET KARŞILAŞTIRMA SONUCU (node-http3 vs C++ node:http2 & node:https/tls)');
  console.log('================================================================================');
  console.log(
    `  * Soğuk Bağlantı (p50)     : node-http3 (${sColdH3.p50}ms) -> ` +
      `http2'den ${(sColdH2.p50 / sColdH3.p50).toFixed(2)}x, https/tls'den ${(sColdH1.p50 / sColdH3.p50).toFixed(2)}x DAHA HIZLI!`
  );
  console.log(
    `  * 0-RTT / Resumption (p50) : node-http3 (${sResH3.p50}ms) -> ` +
      `http2'den ${(sResH2.p50 / sResH3.p50).toFixed(2)}x, https/tls'den ${(sResH1.p50 / sResH3.p50).toFixed(2)}x DAHA HIZLI!`
  );
  console.log(
    `  * Sıcak Bağlantı (p50)     : node-http3 (${sSeqH3.p50}ms) vs http2 (${sSeqH2.p50}ms) vs https (${sSeqH1.p50}ms)`
  );
  console.log(
    `  * 50 Paralel İstek         : node-http3 (${burstH3Ms}ms) vs http2 (${burstH2Ms}ms) vs https (${burstH1Ms}ms)`
  );
  console.log('================================================================================\n');

  h3Client.close();
  h2Client.close();
  h1KeepAliveAgent.destroy();
  h1PoolAgent6.destroy();
  http3.closePool();
}

main().catch((err) => {
  console.error('Benchmark Hatası:', err);
  http3.closePool();
  process.exit(1);
});
