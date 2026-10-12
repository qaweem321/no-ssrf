import { checkAddress } from "./address.js";
import { parseIp } from "./ip.js";

export type UrlOptions = {
  // Allow plain http:// (default: https only).
  allowHttp?: boolean;
  // Ports a URL may use (default: any). For webhooks, [443] or [80, 443] is a good choice.
  allowedPorts?: readonly number[];
  // Exact hostnames or IPs that are always allowed (an internal service you trust).
  allowHosts?: readonly string[];
  // Longest URL accepted (default 2048).
  maxLength?: number;
};

export type UrlVerdict =
  | { ok: true; url: URL; hostname: string; isIp: boolean }
  | { ok: false; reason: string; hostname?: string };

// Names that point at the server itself or its private network, whatever DNS says.
const BLOCKED_NAMES = [/^localhost$/, /\.localhost$/, /\.local$/, /\.internal$/, /\.home\.arpa$/, /^metadata$/];

// Checks a URL a user typed, *after* `new URL()` has rewritten it (the form the request really
// uses). A name that passes still has to be checked again when it's resolved: see
// `@qaweem321/no-ssrf/node` (`safeRequest`, `safeLookup`) or check DNS answers with `checkAddress`.
export function checkUrl(input: string | URL, options: UrlOptions = {}): UrlVerdict {
  const text = String(input).trim();
  if (text.length > (options.maxLength ?? 2048)) return { ok: false, reason: "URL is too long" };
  let url: URL;
  try {
    url = new URL(text);
  } catch {
    return { ok: false, reason: "not a valid URL" };
  }
  const allowed = options.allowHttp ? ["https:", "http:"] : ["https:"];
  if (!allowed.includes(url.protocol)) {
    return { ok: false, reason: `${url.protocol.replace(":", "")} URLs are not allowed` };
  }
  if (url.username || url.password) {
    return { ok: false, reason: "URLs with a user name or password are not allowed" };
  }
  const port = Number(url.port || (url.protocol === "https:" ? 443 : 80));
  if (options.allowedPorts && !options.allowedPorts.includes(port)) {
    return { ok: false, reason: `port ${port} is not allowed` };
  }

  // A trailing dot ("localhost.") names the same host.
  const hostname = url.hostname.toLowerCase().replace(/\.$/, "");
  if (options.allowHosts?.some((h) => h.toLowerCase() === hostname)) {
    return { ok: true, url, hostname, isIp: parseIp(hostname) !== null };
  }
  if (parseIp(hostname)) {
    const verdict = checkAddress(hostname);
    return verdict.allowed
      ? { ok: true, url, hostname, isIp: true }
      : { ok: false, reason: verdict.reason, hostname };
  }
  if (hostname.includes(":") || hostname.startsWith("[")) {
    return { ok: false, reason: "unrecognized address", hostname };
  }
  if (!hostname.includes(".") || BLOCKED_NAMES.some((pattern) => pattern.test(hostname))) {
    return { ok: false, reason: "internal host name", hostname };
  }
  return { ok: true, url, hostname, isIp: false };
}
