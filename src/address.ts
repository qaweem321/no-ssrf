import { type Bytes, formatIPv4, inSubnet, parseIp, parseIPv4, parseIPv6 } from "./ip.js";

// Address ranges a server must never be sent to by a user. Each has a reason people can read.
type Range = { network: Bytes; prefix: number; reason: string };

const v4 = (network: string, prefix: number, reason: string): Range => ({
  network: parseIPv4(network) as Bytes,
  prefix,
  reason,
});
const v6 = (network: string, prefix: number, reason: string): Range => ({
  network: parseIPv6(network) as Bytes,
  prefix,
  reason,
});

// Frozen all the way down: the lists are exported, and a caller changing an entry at runtime
// would weaken every check.
const freeze = (ranges: Range[]): readonly Range[] =>
  Object.freeze(ranges.map((r) => Object.freeze({ ...r, network: Object.freeze(r.network) as Bytes })));

export const IPV4_BLOCKED = freeze([
  v4("0.0.0.0", 8, "\"this network\" (0.0.0.0 reaches the server itself on many systems)"),
  v4("10.0.0.0", 8, "private network"),
  v4("100.64.0.0", 10, "carrier-grade NAT (shared address space)"),
  v4("127.0.0.0", 8, "loopback (the server itself)"),
  v4("169.254.0.0", 16, "link-local (includes the cloud metadata service 169.254.169.254)"),
  v4("172.16.0.0", 12, "private network"),
  v4("192.0.0.0", 24, "IETF protocol assignments"),
  v4("192.0.2.0", 24, "documentation range"),
  v4("192.88.99.0", 24, "former 6to4 relay anycast (deprecated)"),
  v4("192.168.0.0", 16, "private network"),
  v4("198.18.0.0", 15, "benchmarking range"),
  v4("198.51.100.0", 24, "documentation range"),
  v4("203.0.113.0", 24, "documentation range"),
  v4("224.0.0.0", 4, "multicast"),
  v4("240.0.0.0", 4, "reserved (includes broadcast 255.255.255.255)"),
]);

export const IPV6_BLOCKED = freeze([
  v6("::", 128, "unspecified address"),
  v6("::1", 128, "loopback (the server itself)"),
  v6("64:ff9b:1::", 48, "local-use NAT64 (translates to your own network's IPv4 addresses)"),
  v6("100::", 64, "discard-only range"),
  v6("2001::", 32, "Teredo tunnel (hides an IPv4 address)"),
  v6("2001:db8::", 32, "documentation range"),
  v6("3fff::", 20, "documentation range"),
  v6("fc00::", 7, "unique local (private network)"),
  v6("fe80::", 10, "link-local"),
  v6("fec0::", 10, "site-local (deprecated private range)"),
  v6("ff00::", 8, "multicast"),
]);

// IPv6 forms that carry an IPv4 address inside: it's checked as that IPv4 address.
const EMBEDDED_V4: readonly { network: Bytes; prefix: number; at: number; form: string }[] = [
  { network: parseIPv6("::ffff:0:0") as Bytes, prefix: 96, at: 12, form: "IPv4-mapped IPv6" },
  { network: parseIPv6("::") as Bytes, prefix: 96, at: 12, form: "IPv4-compatible IPv6" },
  { network: parseIPv6("64:ff9b::") as Bytes, prefix: 96, at: 12, form: "NAT64" },
  { network: parseIPv6("2002::") as Bytes, prefix: 16, at: 2, form: "6to4" },
];

export type AddressVerdict =
  | { allowed: true; address: string; version: 4 | 6 }
  | { allowed: false; address: string; version: 4 | 6; reason: string }
  | { allowed: false; address: string; version: null; reason: string };

function checkIPv4(bytes: Bytes) {
  return IPV4_BLOCKED.find((r) => inSubnet(bytes, r.network, r.prefix))?.reason ?? null;
}

// Is this IP address safe to connect to? Handles IPv4 wrapped in IPv6 (::ffff:7f00:1 is
// 127.0.0.1), NAT64, 6to4 and the old IPv4-compatible form. Local-use NAT64 (64:ff9b:1::/48)
// is refused outright: its networks may put the IPv4 address at several positions.
export function checkAddress(address: string): AddressVerdict {
  const ip = parseIp(address);
  if (!ip) return { allowed: false, address, version: null, reason: "not an IP address" };
  if (ip.version === 4) {
    const reason = checkIPv4(ip.bytes);
    return reason ? { allowed: false, address, version: 4, reason } : { allowed: true, address, version: 4 };
  }
  for (const embed of EMBEDDED_V4) {
    if (!inSubnet(ip.bytes, embed.network, embed.prefix)) continue;
    const inner = ip.bytes.slice(embed.at, embed.at + 4);
    // "::" and "::1" sit inside the IPv4-compatible range but are their own thing.
    if (embed.form === "IPv4-compatible IPv6" && inner.slice(0, 3).every((b) => b === 0) && inner[3] <= 1) break;
    const reason = checkIPv4(inner);
    if (reason) {
      return { allowed: false, address, version: 6, reason: `${reason}, as ${embed.form} (${formatIPv4(inner)})` };
    }
    if (embed.form === "IPv4-compatible IPv6") {
      return { allowed: false, address, version: 6, reason: "IPv4-compatible IPv6 (deprecated)" };
    }
    return { allowed: true, address, version: 6 };
  }
  const reason = IPV6_BLOCKED.find((r) => inSubnet(ip.bytes, r.network, r.prefix))?.reason;
  return reason ? { allowed: false, address, version: 6, reason } : { allowed: true, address, version: 6 };
}

export function isPrivateAddress(address: string) {
  const verdict = checkAddress(address);
  return verdict.version !== null && !verdict.allowed;
}
