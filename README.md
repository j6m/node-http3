# node-http3 v3.1 (Saf Node.js ile Enterprise HTTP/3 & QUIC v1 İstemcisi)

Sıfır dış bağımlılık (**zero-dependency**), `curl` veya C++/Rust native eklentisi (`node-gyp`) gerektirmeden **%100 Node.js'in kendi yerleşik modülleriyle (`node:dgram`, `node:crypto`, `node:tls`, `node:dns`, `node:net`, `node:zlib`, `node:stream`)** sıfırdan yazılmış yüksek performanslı **QUIC v1 (RFC 9000 / RFC 9001 / RFC 9002) + TLS 1.3 (0-RTT & PSK, RFC 8446) + HTTP/3 (RFC 9114) + Dinamik QPACK (RFC 9204)** modülü.

## Kurulum

```bash
npm install node-http3
```

---

## Canlı Benchmark: `node-http3` (Saf JS) vs `node:http2` (C++ `nghttp2`) vs `node:https` (C++ `OpenSSL`)

Hedef: `https://cloudflare.com/cdn-cgi/trace` (`npm run bench` canlı ölçüm sonuçları — düşük ms ve yüksek istek/sn daha iyidir):

### 1. Soğuk Bağlantı + İlk İstek (`Zero Cache`, Sıfırdan El Sıkışma)
| Kütüphane | Protokol | Min | Medyan (p50) | Ortalama | p95 |
| :--- | :--- | :---: | :---: | :---: | :---: |
| **`node-http3` (Saf JS QUIC v1)** | **HTTP/3 (UDP)** | **25.02 ms** | **27.58 ms** | **27.21 ms** | **29.44 ms** |
| `node:https` (C++ `node:tls`) | HTTP/1.1 (TCP + TLS) | 34.77 ms | 38.50 ms | 37.68 ms | 41.83 ms |
| `node:http2` (C++ `nghttp2`) | HTTP/2 (TCP + TLS) | 32.97 ms | 40.10 ms | 47.34 ms | 69.48 ms |

### 2. Yeni Sokette Session Resumption & QUIC `0-RTT` (`8/8` %100 `0-RTT` Kabul!)
| Kütüphane | Protokol | Min | Medyan (p50) | Ortalama |
| :--- | :--- | :---: | :---: | :---: |
| **`node-http3` (QUIC `0-RTT` + PSK)** | **HTTP/3 `0-RTT` (1 RTT!)** | **13.29 ms** | **15.13 ms** | **15.89 ms** |
| `node:https` (TLS Session Ticket) | HTTP/1.1 (TCP + PSK) | 32.52 ms | 34.86 ms | 34.34 ms |
| `node:http2` (TLS Session Ticket) | HTTP/2 (TCP + PSK) | 33.09 ms | 36.62 ms | 35.91 ms |

### 3. Sıcak Bağlantı Ardışık Gecikme & 50 Eşzamanlı Paralel İstek (Multiplexing)
| Senaryo | **`node-http3` (Saf JS)** | `node:http2` (C++ `nghttp2`) | `node:https` (6 Keep-Alive Soketi) |
| :--- | :---: | :---: | :---: |
| **Sıcak Bağlantı (25 Ardışık İstek p50)** | **10.77 ms** | 23.15 ms | 12.54 ms |
| **50 Eşzamanlı İstek Toplam Süre** | **16.59 ms** *(9 UDP paketi!)* | 61.82 ms | 101.87 ms |
| **50 Eşzamanlı İstek Throughput** | **3,014 istek/sn** | 809 istek/sn | 491 istek/sn |

---

## Öne Çıkan Özellikler (v3.1)

- **%100 Saf Node.js & Zero-Dependency**: Derleme, `node-gyp`, Rust veya harici binary yok. CommonJS (`require`) ve ESM (`import`) + tam TypeScript (`index.d.ts`) tanımları.
- **Kapsamlı UDP Soket Yönetimi & `noDelay` / `cork` / `uncork`**:
  - **`setNoDelay(true/false)`**: `true` iken microtask beklemeden aynı çağrı yığınında (**0-microtask senkron**) UDP paketi ateşleme; `false` (varsayılan) modunda otomatik mikro-görev çoklu-stream paket birleştirme (packet packing).
  - **`cork()` & `uncork()`**: Birden fazla paralel HTTP/3 isteğini bellekte tutup `uncork()` anında öncelik sırasına göre tek UDP datagramında gönderme.
  - **Tam `dgram.Socket` Kontrolü (`socketOptions` & Çalışma Zamanı Metodları)**: `connectedUdp` (`uv_udp_connect` çekirdek seviyesi bağlı UDP), `localAddress`, `localPort`, `reuseAddr`, `ipv6Only`, `recvBufferSize` (`SO_RCVBUF`), `sendBufferSize` (`SO_SNDBUF`), `ttl` (`setTTL`), `broadcast`, `multicastTTL`, `multicastLoopback`, `multicastInterface`, `unref`/`ref` ve dışarıdan kendi `dgram.Socket` nesnenizi bağlayabilme (`customSocket` / `createSocket`).
  - **`setAckDelay(ms, threshold)` & `ackNoDelay`**: Gecikmeli ACK süresini çalışma zamanında sıfırlama veya özelleştirme.
- **Tam RFC 9204 Dinamik QPACK + Hızlı Huffman Tablosu**:
  - **Durumlu (Stateful) `QpackDecoder` & `QpackEncoder`**: Tek yönlü QPACK Encoder (`0x02`) ve Decoder (`0x03`) stream'leri üzerinden canlı dinamik tablo güncellemeleri, sıra dışı (out-of-order) UDP paketlerinde otomatik **Blocked Stream** bekletme ve çözme, Section Acknowledgment ve Stream Cancellation desteği (Google/YouTube `gquic` ve Cloudflare ile canlı doğrulanmış).
  - **Bayt-Tabanlı Hızlı Huffman & Güvenlik Doğrulaması**: 53-bit `Number` bit-biriktirici Huffman kodlayıcı + 256-girişli durum makinesi çözücü, RFC 9110/9114 CR/LF/NUL başlık enjeksiyon koruması ve strict EOS/padding denetimi.
- **İleri Seviye QUIC v1 & RFC Güvenlik Sertleştirmeleri**:
  - **TLS 1.3 PSK Session Resumption & QUIC `0-RTT` Early Data**: Tek UDP paketinde `[Initial(ClientHello) || 0-RTT(SETTINGS + Request)]` coalescing ve `0-RTT` reddedilirse kayıpsız `1-RTT` geri dönüşü.
  - **Otomatik `MAX_STREAMS` & `STREAMS_BLOCKED` Eşzamanlı Stream Yönetimi**: Sunucunun `initial_max_streams_bidi` sınırı aşıldığında (örn. tek bağlantıda 300+ eşzamanlı istek) `STREAM_LIMIT_ERROR` almadan fazla stream'leri kuyruklayıp `STREAMS_BLOCKED` göndererek `MAX_STREAMS` kredisi geldikçe otomatik akıtma.
  - **Canlı Bağlantı Göçü (`await session.migrate()`)**: Aktif HTTP/3 oturumu kopmadan yeni yerel UDP portuna/arayüzüne geçiş, otomatik `NEW_CONNECTION_ID` / `RETIRE_CONNECTION_ID` rotasyonu ve 1200B dolgulu `PATH_CHALLENGE` / `PATH_RESPONSE` doğrulaması (RFC 9000 §9).
  - **Canlı 1-RTT Anahtar Güncelleme (`session.initiateKeyUpdate()`)**: Bağlantı kesilmeden AEAD anahtarlarını döndürme (RFC 9001 §6).
  - **Değiştirilebilir Tıkanıklık Kontrolü (`congestionControl`) & Packet Pacing**: `'cubic'` (RFC 9438), `'bbr'`, `'newreno'` (RFC 9002), `'unlimited'` + ECN-CE tepkisi, Zaman/Paket eşikli kayıp algılama + PTO ve token-bucket `pacing`.
  - **Canlı Path MTU Keşfi (`await session.probeMtu(1452)` & `pmtud: true`)**, **RFC 9218 Stream Önceliklendirme**, **RFC 9221 QUIC `DATAGRAM`**, **Stateless Reset Algılama**, **Spin Bit**, **62-bit OOM Korumalı `H3StreamParser`**, **`VarintReader`/`VarintWriter`** ve Wireshark için **NSS `SSLKEYLOGFILE` (`onKeylog`)**.

---

## Kullanım Örnekleri

### 1. Hızlı `fetch` / `get` / `post` API'si

```js
const http3 = require('node-http3');

async function main() {
  const res = await http3.get('https://cloudflare.com/cdn-cgi/trace');
  console.log('Durum:', res.status, 'Protokol:', res.httpVersion, 'Süre:', res.timings.totalMs + 'ms');
  console.log(await res.text());

  http3.closePool();
}

main();
```

### 2. Doğrudan HTTP/3 QUIC UDP Soketi Açma, `setNoDelay`, `cork`/`uncork`, `migrate` ve `KeyUpdate`

```js
const http3 = require('node-http3');

async function canliHttp3Soket() {
  const client = http3.connect('https://www.google.com', {
    noDelay: true,                // 0-microtask senkron UDP paketi gönderimi
    ackNoDelay: true,             // 0ms gecikmesiz anında QUIC ACK
    congestionControl: 'cubic',   // 'cubic' | 'bbr' | 'newreno' | 'unlimited'
    qpackMaxTableCapacity: 16384, // RFC 9204 16 KB Dinamik QPACK tablosu
    socketOptions: {
      connectedUdp: true,         // Çekirdek seviyesi hızlı bağlı UDP soketi
      recvBufferSize: 1024 * 1024,
      sendBufferSize: 1024 * 1024,
      ttl: 64,
    },
  });

  await client.ready();
  console.log('Açık UDP Soketi:', client.getSocketState());

  // Cork + Uncork + RFC 9218 Önceliklendirme ile iki isteği TEK UDP paketinde ateşleme:
  client.cork();
  const r1 = client.request({ ':method': 'GET', ':path': '/robots.txt' }, { endStream: true, priority: { urgency: 0 } });
  const r2 = client.request({ ':method': 'GET', ':path': '/generate_204' }, { endStream: true, priority: { urgency: 4, incremental: true } });
  client.uncork();

  r1.on('response', (headers) => console.log('Yanıt Başlıkları:', headers[':status'], headers['alt-svc']));
  await new Promise((resolve) => { r1.resume(); r1.on('end', resolve); });
  await new Promise((resolve) => { r2.resume(); r2.on('end', resolve); });

  console.log('Canlı QUIC Ping RTT:', await client.ping(), 'ms');
  console.log('1-RTT Anahtar Rotasyonu:', client.initiateKeyUpdate());
  console.log('Yeni UDP Portuna Canlı Göç:', await client.migrate());
  console.log('QPACK & QUIC Tanılama:', client.getDiagnostics().h3.qpack);

  client.close();
}

canliHttp3Soket();
```

### 3. Alt Seviye Protokol Modülleri (`qpack`, `varint`, `packet`, `frame`, `h3frame`)

```js
const {
  QpackEncoder,
  QpackDecoder,
  VarintReader,
  VarintWriter,
  qpack,
  varint,
  packet,
} = require('node-http3');

const writer = new VarintWriter();
writer.writeVarint(15293).writeVarint(4611686018427387903n);
const reader = new VarintReader(writer.finish());
console.log(reader.readVarintNumber(), reader.readVarint());
```

## Testler ve Benchmark Yarışı

```bash
# Birim + Canlı HTTP/3 + Dinamik QPACK + 300-Stream Stress + Enterprise QUIC v3.1 testleri
npm test

# C++ node:http2 ve C++ node:https/tls ile canlı hız kapışması
npm run bench
```
