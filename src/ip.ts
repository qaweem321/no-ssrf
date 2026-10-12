// IP address parsing in plain TypeScript (no node:net), so the checks run anywhere: Node, Bun,
// Deno, browsers and edge runtimes.

export type Bytes = number[];

// "10.0.0.1" -> [10, 0, 0, 1]. Only the plain dotted form: `new URL()` and DNS answers always give
// that form (new URL() turns "127.1" or "2130706433" into "127.0.0.1").
export function parseIPv4(text: string): Bytes | null {
  const parts = text.split(".");
  if (parts.length !== 4) return null;
  const bytes: Bytes = [];
  for (const part of parts) {
    if (!/^(0|[1-9]\d{0,2})$/.test(part)) return null;
    const n = Number(part);
    if (n > 255) return null;
    bytes.push(n);
  }
  return bytes;
}

// "::ffff:7f00:1" -> 16 bytes. Accepts "::" compression and a dotted IPv4 tail ("::ffff:1.2.3.4").
// Zone ids ("fe80::1%eth0") are refused: they never appear in a URL hostname.
export function parseIPv6(text: string): Bytes | null {
  if (!/^[0-9a-fA-F:.]+$/.test(text) || text.length > 45) return null;
  let head = text;
  let tailV4: Bytes | null = null;
  if (text.includes(".")) {
    const at = text.lastIndexOf(":");
    tailV4 = parseIPv4(text.slice(at + 1));
    if (!tailV4) return null;
    head = `${text.slice(0, at)}:0:0`; // placeholder groups, replaced below
  }
  const halves = head.split("::");
  if (halves.length > 2) return null;
  const groups = (half: string) => (half === "" ? [] : half.split(":"));
  const left = groups(halves[0]);
  const right = halves.length === 2 ? groups(halves[1]) : [];
  const missing = 8 - left.length - right.length;
  if (halves.length === 1 ? missing !== 0 : missing < 1) return null;
  const all = [...left, ...Array(halves.length === 2 ? missing : 0).fill("0"), ...right];
  const bytes: Bytes = [];
  for (const group of all) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(group)) return null;
    const n = Number.parseInt(group, 16);
    bytes.push(n >> 8, n & 0xff);
  }
  if (tailV4) bytes.splice(12, 4, ...tailV4);
  return bytes;
}

export type ParsedIp = { version: 4 | 6; bytes: Bytes };

// An IP address as written in a hostname or DNS answer (brackets allowed), or null for a name.
export function parseIp(text: string): ParsedIp | null {
  const bare = text.startsWith("[") && text.endsWith("]") ? text.slice(1, -1) : text;
  const v4 = parseIPv4(bare);
  if (v4) return { version: 4, bytes: v4 };
  const v6 = bare.includes(":") ? parseIPv6(bare) : null;
  return v6 ? { version: 6, bytes: v6 } : null;
}

export function formatIPv4(bytes: Bytes) {
  return bytes.join(".");
}

// True when the first `prefix` bits of `bytes` equal those of `network`.
export function inSubnet(bytes: Bytes, network: Bytes, prefix: number) {
  for (let bit = 0; bit < prefix; bit += 8) {
    const remaining = Math.min(8, prefix - bit);
    const mask = (0xff << (8 - remaining)) & 0xff;
    const i = bit / 8;
    if ((bytes[i] & mask) !== (network[i] & mask)) return false;
  }
  return true;
}
