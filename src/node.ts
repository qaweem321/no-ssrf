// @qaweem321/no-ssrf/node: make the request safely. Checking a URL first and fetching it second isn't enough:
// a domain can answer DNS with a public address for the check and a private one for the request
// (DNS rebinding). Here the address is checked inside the connection's own DNS lookup, so the
// address checked is the address connected to.
import { type LookupAddress, lookup as dnsLookup } from "node:dns";
import { request as httpRequest, type IncomingHttpHeaders } from "node:http";
import { request as httpsRequest } from "node:https";
import type { LookupFunction } from "node:net";
import { checkAddress } from "./address.js";
import { checkUrl, type UrlOptions } from "./url.js";

export class SsrfError extends Error {
  constructor(
    message: string,
    readonly url: string,
  ) {
    super(message);
    this.name = "SsrfError";
  }
}

type DnsLookup = typeof dnsLookup;

export type LookupOptions = {
  // Addresses that are always allowed (an internal service you trust).
  allowAddresses?: readonly string[];
  // Host names whose DNS answers are always allowed (an internal service you trust).
  allowHosts?: readonly string[];
  // Replaces node:dns lookup (tests, custom resolvers).
  lookup?: DnsLookup;
};

// A `lookup` for http.request, https.request, net.connect or an http.Agent. Refuses the
// connection when any address the name resolves to is private.
export function safeLookup(options: LookupOptions = {}): LookupFunction {
  const resolve = options.lookup ?? dnsLookup;
  const allowed = new Set(options.allowAddresses ?? []);
  const trustedHosts = new Set((options.allowHosts ?? []).map(normalizeHost));
  return (hostname, lookupOptions, callback) => {
    resolve(hostname, { ...lookupOptions, all: true }, (error, found) => {
      if (error) return callback(error, "", 0);
      const addresses = found as unknown as LookupAddress[];
      const trusted = trustedHosts.has(normalizeHost(hostname));
      for (const entry of addresses) {
        if (trusted || allowed.has(entry.address)) continue;
        const verdict = checkAddress(entry.address);
        if (!verdict.allowed) {
          const blocked = new SsrfError(`${hostname} resolves to ${entry.address}: ${verdict.reason}`, hostname);
          return callback(blocked as NodeJS.ErrnoException, "", 0);
        }
      }
      if (addresses.length === 0) return callback(new Error(`${hostname} has no address`), "", 0);
      if (lookupOptions.all) return callback(null, addresses);
      callback(null, addresses[0].address, addresses[0].family);
    });
  };
}

const normalizeHost = (host: string) => host.toLowerCase().replace(/\.+$/, "");

// Headers a browser drops when a redirect leaves the origin: they'd hand your credentials to
// whoever the first server points at.
const CREDENTIAL_HEADERS = new Set(["authorization", "cookie", "proxy-authorization"]);

function withoutCredentials(headers: Record<string, string>) {
  return Object.fromEntries(Object.entries(headers).filter(([name]) => !CREDENTIAL_HEADERS.has(name.toLowerCase())));
}

export type SafeRequestOptions = UrlOptions &
  LookupOptions & {
    method?: string;
    headers?: Record<string, string>;
    body?: string | Uint8Array;
    // Default 10 s for the whole request.
    timeoutMs?: number;
    // Responses larger than this are cut off (default 1 MB). The rest isn't downloaded.
    maxResponseBytes?: number;
    // Redirects to follow (default 0). Each one is checked like the first URL, and credential
    // headers (Authorization, Cookie) are dropped when one leaves the original origin.
    maxRedirects?: number;
  };

export type SafeResponse = {
  status: number;
  headers: IncomingHttpHeaders;
  body: Uint8Array;
  url: string;
  truncated: boolean;
};

// Sends a request to a URL a user typed, refusing private addresses at every step: the URL,
// every DNS answer, and every redirect.
export async function safeRequest(input: string | URL, options: SafeRequestOptions = {}): Promise<SafeResponse> {
  const allowHosts = [...(options.allowHosts ?? []), ...(options.allowAddresses ?? [])];
  let current = String(input);
  let method = options.method ?? "GET";
  let body = options.body;
  let headers = options.headers ?? {};
  let origin: string | null = null;
  // One deadline for the whole request, redirects included.
  const deadline = Date.now() + (options.timeoutMs ?? 10_000);
  for (let hop = 0; ; hop++) {
    const verdict = checkUrl(current, { ...options, allowHosts });
    if (!verdict.ok) throw new SsrfError(`Blocked ${current}: ${verdict.reason}`, current);
    origin ??= verdict.url.origin;
    if (verdict.url.origin !== origin) headers = withoutCredentials(headers);
    const response = await send(verdict.url, method, body, headers, deadline, options);
    const location = response.headers.location;
    const isRedirect = response.status >= 300 && response.status < 400 && location;
    if (!isRedirect || hop >= (options.maxRedirects ?? 0)) return { ...response, url: current };
    current = new URL(location, verdict.url).toString();
    if (response.status === 303 || ((response.status === 301 || response.status === 302) && method === "POST")) {
      method = "GET";
      body = undefined;
    }
  }
}

function send(
  url: URL,
  method: string,
  body: string | Uint8Array | undefined,
  baseHeaders: Record<string, string>,
  deadline: number,
  options: SafeRequestOptions,
): Promise<Omit<SafeResponse, "url">> {
  const limit = options.maxResponseBytes ?? 1_000_000;
  const request = url.protocol === "https:" ? httpsRequest : httpRequest;
  const headers = { ...baseHeaders };
  if (body !== undefined) headers["content-length"] = String(Buffer.byteLength(body));
  return new Promise((resolve, reject) => {
    // `agent: false`: a fresh connection every time. A pooled keep-alive connection opened by
    // other code would skip the DNS lookup, and with it the address check.
    const req = request(url, { method, headers, lookup: safeLookup(options), agent: false }, (res) => {
      const chunks: Buffer[] = [];
      let size = 0;
      let truncated = false;
      res.on("data", (chunk: Buffer) => {
        if (truncated) return;
        size += chunk.length;
        if (size > limit) {
          truncated = true;
          chunks.push(chunk.subarray(0, chunk.length - (size - limit)));
          res.destroy();
          finish();
          return;
        }
        chunks.push(chunk);
      });
      const finish = () => {
        clearTimeout(timer);
        resolve({ status: res.statusCode ?? 0, headers: res.headers, body: new Uint8Array(Buffer.concat(chunks)), truncated });
      };
      res.on("end", finish);
      res.on("error", (error) => {
        clearTimeout(timer);
        if (!truncated) reject(error);
      });
    });
    // A wall-clock limit, not Node's idle `timeout`: a server sending one byte at a time never
    // goes idle.
    const timer = setTimeout(() => {
      const error = new Error(`Timed out after ${options.timeoutMs ?? 10_000} ms`);
      reject(error);
      req.destroy(error);
    }, Math.max(0, deadline - Date.now()));
    req.on("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    req.end(body);
  });
}

export * from "./index.js";
