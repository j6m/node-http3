'use strict';

const http3 = require('./index');

async function main() {
  console.log('1) http3.get() ile Cloudflare HTTP/3 istegi atiliyor...\n');
  const res = await http3.get('https://cloudflare.com/cdn-cgi/trace');
  console.log(`Durum: ${res.status} | HTTP Versiyon: ${res.httpVersion} | Cipher: ${res.cipher} | RTT: ${res.rtt}ms`);
  console.log(await res.text());

  console.log('2) Ayni QUIC baglantisi uzerinden 2. istek (0-Handshake, 1-RTT)...');
  const t0 = performance.now();
  const res2 = await http3.get('https://cloudflare.com/cdn-cgi/trace');
  console.log(`2. istek tamamlandi: ${res2.status} (${Math.round(performance.now() - t0)}ms)\n`);

  console.log('3) http2 uyumlu http3.connect() ile paralel coklu stream ornegi...');
  const client = http3.connect('https://www.google.com');

  await new Promise((resolve, reject) => {
    const req = client.request({
      ':method': 'GET',
      ':path': '/robots.txt',
      'user-agent': 'Mozilla/5.0 Node-HTTP3',
    });

    let body = '';
    req.on('response', (headers) => {
      console.log('Google Yanit Basliklari (:status, server, alt-svc):', {
        status: headers[':status'],
        server: headers['server'],
        contentType: headers['content-type'],
      });
    });
    req.on('data', (chunk) => {
      body += chunk.toString('utf8');
    });
    req.on('end', () => {
      console.log(`Google /robots.txt alindi (${body.length} karakter). Ilk satir: ${body.split('\n')[0]}`);
      client.close();
      resolve();
    });
    req.on('error', reject);
    req.end();
  });

  http3.closePool();
}

main().catch((err) => {
  console.error('Hata:', err);
  http3.closePool();
});

