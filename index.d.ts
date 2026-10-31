/// <reference types="node" />
import * as dgram from 'node:dgram';
import { Duplex } from 'node:stream';
import { EventEmitter } from 'node:events';

export type CongestionAlgorithm = 'cubic' | 'newreno' | 'bbr' | 'unlimited';

export interface StreamPriority {
  urgency?: number;
  incremental?: boolean;
}

export interface QuicSocketOptions {
  noDelay?: boolean;
  ackNoDelay?: boolean;
  ackDelayMs?: number;
  ackThreshold?: number;
  keepAlive?: boolean;
  keepAliveInterval?: number;
  idleTimeout?: number;
  localAddress?: string | null;
  localPort?: number;
  reuseAddr?: boolean;
  ipv6Only?: boolean;
  recvBufferSize?: number;
  sendBufferSize?: number;
  connectedUdp?: boolean;
  ttl?: number | null;
  broadcast?: boolean | null;
  multicastTTL?: number | null;
  multicastLoopback?: boolean | null;
  multicastInterface?: string | null;
  unref?: boolean;
  customSocket?: dgram.Socket | null;
  createSocket?: (info: {
    type: 'udp4' | 'udp6';
    family: 4 | 6;
    options: QuicSocketOptions;
  }) => dgram.Socket;
  closeCustomSocket?: boolean;
}

export interface QuicSocketState {
  bound: boolean;
  connectedUdp: boolean;
  unrefed: boolean;
  noDelay: boolean;
  ackNoDelay: boolean;
  ackDelayMs: number;
  corked: number;
  localAddress: string | null;
  localPort: number | null;
  localFamily: string | null;
  remoteAddress: string | null;
  remotePort: number;
  recvBufferSize: number | null;
  sendBufferSize: number | null;
  sendQueueSize: number | null;
  sendQueueCount: number | null;
  ttl: number | null;
  broadcast: boolean;
}

export interface QuicMigrationResult {
  oldLocalPort: number | null;
  newLocalPort: number | null;
  localAddress: string | null;
  dcidSeq: number;
  switchedCid: boolean;
  validationRttMs: number;
}

export interface QuicMtuProbeResult {
  ok: boolean;
  mtu: number;
  unchanged?: boolean;
  attempted?: number;
}

export interface Http3ConnectOptions extends QuicSocketOptions {
  host?: string;
  port?: number;
  servername?: string;
  alpnProtocols?: string[];
  rejectUnauthorized?: boolean;
  ca?: string | Buffer | Array<string | Buffer>;
  connectTimeout?: number;
  timeout?: number;
  family?: 0 | 4 | 6;
  preferIpv6?: boolean;
  happyEyeballs?: boolean;
  lookup?: Function;
  dnsCache?: boolean;
  sessionResume?: boolean;
  enable0Rtt?: boolean;
  socketOptions?: QuicSocketOptions;
  congestionControl?: CongestionAlgorithm;
  initialCwndPackets?: number;
  minCwndPackets?: number;
  maxCwndBytes?: number;
  pacing?: boolean;
  initialMtu?: number;
  maxMtu?: number;
  pmtud?: boolean;
  enableDatagrams?: boolean;
  maxDatagramFrameSize?: number;
  enableSpinBit?: boolean;
  disableActiveMigration?: boolean;
  maxPacketsPerKeyPhase?: number;
  activeConnectionIdLimit?: number;
  cidLength?: number;
  transportParams?: Record<string, any>;
  qpackMaxTableCapacity?: number;
  qpackBlockedStreams?: number;
  maxFieldSectionSize?: number;
  enableDynamicQpack?: boolean;
  qpackEncoderMaxCapacity?: number;
  strictHeaders?: boolean;
  huffman?: boolean;
  signal?: AbortSignal;
  onKeylog?: (line: Buffer) => void;
}

export interface Http3Timings {
  dnsMs: number;
  handshakeMs: number;
  ttfbMs: number;
  totalMs: number;
  resumed: boolean;
  earlyDataSent: boolean;
  earlyDataAccepted: boolean;
  pooled: boolean;
}

export interface Http3FetchOptions extends Http3ConnectOptions {
  method?: string;
  headers?: Record<string, string | string[]>;
  body?: string | Buffer | Uint8Array | ArrayBuffer | URLSearchParams | Record<string, any> | null;
  decompress?: boolean;
  redirect?: 'follow' | 'manual' | 'error';
  maxRedirects?: number;
  priority?: StreamPriority;
  agent?: Http3Agent | false;
}

export class QuicCongestionController {
  algorithm: string;
  cwnd: number;
  ssthresh: number;
  bytesInFlight: number;
  constructor(options?: {
    algorithm?: CongestionAlgorithm;
    maxDatagramSize?: number;
    initialCwndPackets?: number;
    minCwndPackets?: number;
    maxCwndBytes?: number;
    pacing?: boolean;
  });
  availableWindow(): number;
  canSend(bytes?: number): boolean;
  getState(): Record<string, any>;
}

export class QuicConnection extends EventEmitter {
  host: string;
  port: number;
  servername: string;
  remoteAddress: string | null;
  state: 'idle' | 'connecting' | 'connected' | 'closing' | 'closed';
  noDelay: boolean;
  ackNoDelay: boolean;
  ackDelayMs: number;
  socket: dgram.Socket | null;
  cc: QuicCongestionController;
  readonly maxPeerDatagramSize: number;
  readonly stats: Record<string, any>;

  constructor(options?: Http3ConnectOptions);
  connect(): Promise<void>;
  setNoDelay(noDelay?: boolean): this;
  setAckDelay(delayMs?: number, threshold?: number): this;
  cork(): this;
  uncork(): this;
  setKeepAlive(enable?: boolean, intervalMs?: number): this;
  setIdleTimeout(timeoutMs: number): this;
  setTTL(ttl: number): this;
  setBroadcast(flag?: boolean): this;
  setMulticastTTL(ttl: number): this;
  setMulticastLoopback(flag?: boolean): this;
  setMulticastInterface(iface: string): this;
  setRecvBufferSize(bytes: number): this;
  setSendBufferSize(bytes: number): this;
  getRecvBufferSize(): number | null;
  getSendBufferSize(): number | null;
  setSocketOptions(opts: QuicSocketOptions): this;
  ref(): this;
  unref(): this;
  getSocketState(): QuicSocketState;
  getDiagnostics(): Record<string, any>;
  setStreamPriority(streamId: number, priority: StreamPriority): this;
  getStreamPriority(streamId: number): Required<StreamPriority>;
  migrate(newSocketOpts?: QuicSocketOptions & { force?: boolean; graceMs?: number; validationTimeoutMs?: number }): Promise<QuicMigrationResult>;
  validatePath(timeoutMs?: number): Promise<number>;
  initiateKeyUpdate(): { keyPhase: number; keyUpdates: number; initiator: 'client' };
  probeMtu(targetSize?: number, timeoutMs?: number): Promise<QuicMtuProbeResult>;
  sendDatagram(data: Buffer | Uint8Array | string): boolean;
  ping(timeoutMs?: number): Promise<number>;
  close(errorCode?: number, reason?: string): void;
  destroy(err?: Error | null): void;
}

export class Http3Response {
  readonly status: number;
  readonly statusCode: number;
  readonly ok: boolean;
  readonly httpVersion: '3.0';
  readonly alpnProtocol: string;
  readonly cipher: string | null;
  readonly remoteAddress: string | null;
  readonly rtt: number | null;
  readonly timings: Http3Timings | null;
  readonly url: string;
  readonly headers: Record<string, string | string[]>;
  readonly rawHeaders: Array<[string, string]>;
  readonly body: Buffer;

  header(name: string): string | string[] | undefined;
  buffer(): Promise<Buffer>;
  arrayBuffer(): Promise<ArrayBuffer>;
  text(encoding?: BufferEncoding): Promise<string>;
  json<T = any>(): Promise<T>;
}

export class Http3ClientStream extends Duplex {
  readonly id: number;
  readonly session: Http3ClientSession;
  statusCode: number | null;
  readonly httpVersion: '3.0';
  responseHeaders: Record<string, string | string[]> | null;
  rawResponseHeaders: Array<[string, string]> | null;
  trailers: Record<string, string | string[]> | null;
  aborted: boolean;
  closed: boolean;
  rstCode: number;

  setPriority(priority: StreamPriority): this;
  setNoDelay(noDelay?: boolean): this;
  sendTrailers(trailers: Record<string, string | number | string[]>): this;
  setTimeout(ms: number, callback?: () => void): this;
  close(errorCode?: number, callback?: () => void): void;
}

export class Http3ClientSession extends EventEmitter {
  readonly origin: string;
  readonly authorityHeader: string;
  readonly hostname: string;
  readonly port: number;
  readonly servername: string;
  readonly quic: QuicConnection;
  readonly socket: dgram.Socket | null;
  readonly stats: Record<string, any>;
  connected: boolean;
  closed: boolean;
  destroyed: boolean;
  alpnProtocol: string | null;
  cipher: string | null;

  ready(): Promise<this>;
  request(
    headers?: Record<string, string | number | string[]>,
    options?: {
      endStream?: boolean;
      body?: Buffer | Uint8Array | string | null;
      allow0Rtt?: boolean;
      priority?: StreamPriority;
      urgency?: number;
      incremental?: boolean;
    }
  ): Http3ClientStream;
  setNoDelay(noDelay?: boolean): this;
  setAckDelay(delayMs?: number, threshold?: number): this;
  cork(): this;
  uncork(): this;
  setKeepAlive(enable?: boolean, intervalMs?: number): this;
  setIdleTimeout(timeoutMs: number): this;
  setSocketOptions(opts: QuicSocketOptions): this;
  setTTL(ttl: number): this;
  setBroadcast(flag?: boolean): this;
  setRecvBufferSize(bytes: number): this;
  setSendBufferSize(bytes: number): this;
  ref(): this;
  unref(): this;
  getSocketState(): QuicSocketState;
  getDiagnostics(): Record<string, any>;
  setStreamPriority(streamId: number, priority: StreamPriority): this;
  migrate(newSocketOpts?: QuicSocketOptions & { force?: boolean; graceMs?: number; validationTimeoutMs?: number }): Promise<QuicMigrationResult>;
  validatePath(timeoutMs?: number): Promise<number>;
  initiateKeyUpdate(): { keyPhase: number; keyUpdates: number; initiator: 'client' };
  probeMtu(targetSize?: number, timeoutMs?: number): Promise<QuicMtuProbeResult>;
  sendDatagram(data: Buffer | Uint8Array | string): boolean;
  ping(timeoutMs?: number): Promise<number>;
  close(callback?: () => void): void;
  destroy(err?: Error): void;
}

export class Http3Agent {
  constructor(options?: Http3ConnectOptions);
  getSession(urlOrAuthority: string | URL, options?: Http3ConnectOptions): Http3ClientSession;
  warmup(urlOrAuthority: string | URL, options?: Http3ConnectOptions): Promise<Http3ClientSession>;
  closeAll(): void;
  destroy(): void;
}

export function clearCaches(): void;

export const defaultAgent: Http3Agent;
export const Agent: typeof Http3Agent;
export const constants: Readonly<Record<string, string | number>>;
export const qpack: Record<string, any>;
export const varint: Record<string, any>;
export const packet: Record<string, any>;
export const frame: Record<string, any>;
export const h3frame: Record<string, any>;

export function connect(
  authority: string | URL,
  options?: Http3ConnectOptions | ((session: Http3ClientSession) => void),
  listener?: (session: Http3ClientSession) => void
): Http3ClientSession;

export function fetch(input: string | URL, init?: Http3FetchOptions): Promise<Http3Response>;
export function request(url: string | URL, options?: Http3FetchOptions): Promise<Http3Response>;
export function request(
  url: string | URL,
  options: Http3FetchOptions,
  callback: (res: Http3ClientStream) => void
): Http3ClientStream;
export function get(url: string | URL, options?: Http3FetchOptions): Promise<Http3Response>;
export function head(url: string | URL, options?: Http3FetchOptions): Promise<Http3Response>;
export function post(url: string | URL, body?: any, options?: Http3FetchOptions): Promise<Http3Response>;
export function put(url: string | URL, body?: any, options?: Http3FetchOptions): Promise<Http3Response>;
export function patch(url: string | URL, body?: any, options?: Http3FetchOptions): Promise<Http3Response>;
export function del(url: string | URL, options?: Http3FetchOptions): Promise<Http3Response>;
export { del as delete };
export function closePool(): void;
