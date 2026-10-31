'use strict';

const {
  Http3ClientSession,
  Http3ClientStream,
  Http3Agent,
  Http3Response,
  SessionTicketStore,
  defaultSessionStore,
  defaultDnsCache,
  defaultAgent,
  connect,
  fetch: h3Fetch,
  request,
  clearCaches,
} = require('./src/client');
const { QuicConnection, QuicCongestionController, DnsCache } = require('./src/connection');
const qpack = require('./src/qpack');
const varint = require('./src/varint');
const packet = require('./src/packet');
const frame = require('./src/frame');
const h3frame = require('./src/h3frame');

const constants = Object.freeze({
  HTTP3_HEADER_METHOD: ':method',
  HTTP3_HEADER_PATH: ':path',
  HTTP3_HEADER_AUTHORITY: ':authority',
  HTTP3_HEADER_SCHEME: ':scheme',
  HTTP3_HEADER_STATUS: ':status',
  H3_NO_ERROR: 0x0100,
  H3_GENERAL_PROTOCOL_ERROR: 0x0101,
  H3_INTERNAL_ERROR: 0x0102,
  H3_STREAM_CREATION_ERROR: 0x0103,
  H3_CLOSED_CRITICAL_STREAM: 0x0104,
  H3_FRAME_UNEXPECTED: 0x0105,
  H3_FRAME_ERROR: 0x0106,
  H3_EXCESSIVE_LOAD: 0x0107,
  H3_ID_ERROR: 0x0108,
  H3_SETTINGS_ERROR: 0x0109,
  H3_MISSING_SETTINGS: 0x010a,
  H3_REQUEST_REJECTED: 0x010b,
  H3_REQUEST_CANCELLED: 0x010c,
  H3_REQUEST_INCOMPLETE: 0x010d,
  H3_MESSAGE_ERROR: 0x010e,
  H3_CONNECT_ERROR: 0x010f,
  H3_VERSION_FALLBACK: 0x0110,
  QPACK_DECOMPRESSION_FAILED: 0x0200,
  QPACK_ENCODER_STREAM_ERROR: 0x0201,
  QPACK_DECODER_STREAM_ERROR: 0x0202,
});

function get(url, options = {}) {
  return h3Fetch(url, { ...options, method: 'GET' });
}

function head(url, options = {}) {
  return h3Fetch(url, { ...options, method: 'HEAD' });
}

function post(url, body, options = {}) {
  return h3Fetch(url, { ...options, method: 'POST', body });
}

function put(url, body, options = {}) {
  return h3Fetch(url, { ...options, method: 'PUT', body });
}

function patch(url, body, options = {}) {
  return h3Fetch(url, { ...options, method: 'PATCH', body });
}

function del(url, options = {}) {
  return h3Fetch(url, { ...options, method: 'DELETE' });
}

function closePool() {
  defaultAgent.closeAll();
}

module.exports = {
  connect,
  fetch: h3Fetch,
  request,
  get,
  head,
  post,
  put,
  patch,
  delete: del,
  closePool,
  clearCaches,
  defaultAgent,
  defaultSessionStore,
  defaultDnsCache,
  SessionTicketStore,
  Agent: Http3Agent,
  Http3Agent,
  Http3ClientSession,
  Http3ClientStream,
  Http3Response,
  QuicConnection,
  QuicCongestionController,
  DnsCache,
  QpackEncoder: qpack.QpackEncoder,
  QpackDecoder: qpack.QpackDecoder,
  DynamicTable: qpack.DynamicTable,
  QpackError: qpack.QpackError,
  VarintReader: varint.VarintReader,
  VarintWriter: varint.VarintWriter,
  VarintError: varint.VarintError,
  qpack,
  varint,
  packet,
  frame,
  h3frame,
  constants,
};
