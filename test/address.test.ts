import { BlockList, isIP } from "node:net";
import { describe, expect, test } from "vitest";
import { checkAddress, IPV4_BLOCKED, IPV6_BLOCKED, isPrivateAddress } from "../src/index.js";
import { inSubnet, parseIp, parseIPv4, parseIPv6 } from "../src/ip.js";

// A small deterministic random generator, so failures can be reproduced.
function random(seed: number) {
  return () => {
    seed = (seed * 1103515245 + 12345) & 0x7fffffff;
    return seed / 0x7fffffff;
  };
}

describe("parsing", () => {
  test("IPv4", () => {
    expect(parseIPv4("10.0.0.1")).toEqual([10, 0, 0, 1]);
    for (const bad of ["256.0.0.1", "1.2.3", "1.2.3.4.5", "01.2.3.4", "1.2.3.-4", "a.b.c.d", ""]) {
      expect(parseIPv4(bad), bad).toBeNull();
    }
  });

  test("IPv6 forms", () => {
    expect(parseIPv6("::1")).toEqual([...Array(15).fill(0), 1]);
    expect(parseIPv6("::ffff:1.2.3.4")?.slice(10)).toEqual([0xff, 0xff, 1, 2, 3, 4]);
    expect(parseIPv6("::ffff:7f00:1")?.slice(12)).toEqual([127, 0, 0, 1]);
    expect(parseIp("[::1]")?.version).toBe(6);
    for (const bad of ["1::2::3", ":::", "12345::", "fe80::1%eth0", "1:2:3:4:5:6:7:8:9", "g::1", "::1.2.3"]) {
      expect(parseIPv6(bad), bad).toBeNull();
    }
  });

  test("agrees with node:net isIP on many strings", () => {
    const next = random(7);
    const pieces = ["0", "1", "ff", "ffff", "::", ":", ".", "127", "255", "256", "1.2.3.4", "a", "g", "%"];
    for (let i = 0; i < 20_000; i++) {
      let s = "";
      const n = 1 + Math.floor(next() * 8);
      for (let j = 0; j < n; j++) s += pieces[Math.floor(next() * pieces.length)];
      const ours = parseIp(s)?.version ?? 0;
      // Node accepts leading zeros in IPv6 tails and zone ids; we don't need either.
      if (s.includes("%")) continue;
      expect(ours, s).toBe(isIP(s));
    }
  });

  test("round-trips every IPv6 form new URL() produces", () => {
    const next = random(11);
    for (let i = 0; i < 5_000; i++) {
      const bytes = Array.from({ length: 16 }, () => (next() < 0.4 ? 0 : Math.floor(next() * 256)));
      const groups = [];
      for (let g = 0; g < 16; g += 2) groups.push(((bytes[g] << 8) | bytes[g + 1]).toString(16));
      const hostname = new URL(`http://[${groups.join(":")}]/`).hostname; // compressed by URL
      expect(parseIp(hostname)?.bytes, hostname).toEqual(bytes);
    }
  });
});

describe("range matching agrees with node:net BlockList", () => {
  const list = new BlockList();
  for (const r of IPV4_BLOCKED) list.addSubnet(r.network.join("."), r.prefix, "ipv4");
  const v6text = (b: number[]) =>
    Array.from({ length: 8 }, (_, i) => ((b[2 * i] << 8) | b[2 * i + 1]).toString(16)).join(":");
  const list6 = new BlockList();
  for (const r of IPV6_BLOCKED) list6.addSubnet(v6text(r.network), r.prefix, "ipv6");

  test("IPv4, 50,000 random addresses", () => {
    const next = random(3);
    for (let i = 0; i < 50_000; i++) {
      const bytes = Array.from({ length: 4 }, () => Math.floor(next() * 256));
      const ours = IPV4_BLOCKED.some((r) => inSubnet(bytes, r.network, r.prefix));
      expect(ours, bytes.join(".")).toBe(list.check(bytes.join("."), "ipv4"));
    }
  });

  test("IPv6, 50,000 random addresses near the blocked ranges", () => {
    const next = random(5);
    for (let i = 0; i < 50_000; i++) {
      const base = IPV6_BLOCKED[Math.floor(next() * IPV6_BLOCKED.length)].network;
      // Keep a random number of leading bytes from a blocked network, randomize the rest.
      const keep = Math.floor(next() * 17);
      const bytes = base.map((b, j) => (j < keep ? b : Math.floor(next() * 256)));
      const ours = IPV6_BLOCKED.some((r) => inSubnet(bytes, r.network, r.prefix));
      expect(ours, v6text(bytes)).toBe(list6.check(v6text(bytes), "ipv6"));
    }
  });
});

describe("checkAddress", () => {
  test("local-use NAT64, the 2024 documentation range and the old 6to4 relay range are blocked", () => {
    for (const ip of ["64:ff9b:1::808:808", "64:ff9b:1:ffff::1", "3fff::1", "3fff:fff::1", "192.88.99.1"]) {
      expect(isPrivateAddress(ip), ip).toBe(true);
    }
    expect(isPrivateAddress("4000::1")).toBe(false);
  });

  test("the exported lists can't be changed to weaken the checks", () => {
    expect(() => (IPV4_BLOCKED as unknown as unknown[]).pop()).toThrow(TypeError);
    expect(() => ((IPV4_BLOCKED[3] as { prefix: number }).prefix = 32)).toThrow(TypeError);
    expect(() => (IPV6_BLOCKED[1].network[15] = 2)).toThrow(TypeError);
    expect(isPrivateAddress("127.0.0.2")).toBe(true);
  });

  test("IPv4 inside IPv6 is checked as IPv4", () => {
    for (const ip of ["::ffff:127.0.0.1", "::ffff:7f00:1", "::ffff:a9fe:a9fe", "64:ff9b::a9fe:a9fe", "2002:a00:1::", "::7f00:1"]) {
      expect(isPrivateAddress(ip), ip).toBe(true);
    }
    expect(isPrivateAddress("::ffff:8.8.8.8")).toBe(false);
    expect(isPrivateAddress("64:ff9b::808:808")).toBe(false);
  });

  test("the reason says what the address is", () => {
    const verdict = checkAddress("::ffff:169.254.169.254");
    expect(verdict.allowed).toBe(false);
    if (!verdict.allowed) expect(verdict.reason).toMatch(/metadata.*IPv4-mapped IPv6 \(169\.254\.169\.254\)/);
  });

  test("special IPv6 addresses", () => {
    for (const ip of ["::", "::1", "::2", "fe80::1", "fd00::1", "ff02::1", "2001:db8::1", "2001::1"]) {
      expect(isPrivateAddress(ip), ip).toBe(true);
    }
    for (const ip of ["2606:4700:4700::1111", "2a00:1450:4001::200e", "8.8.8.8", "1.1.1.1"]) {
      expect(isPrivateAddress(ip), ip).toBe(false);
    }
  });

  test("names are not addresses", () => {
    expect(checkAddress("example.com")).toMatchObject({ allowed: false, version: null });
    expect(isPrivateAddress("example.com")).toBe(false);
  });
});
