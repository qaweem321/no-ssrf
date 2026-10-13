import { Agent, createServer, get, globalAgent, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, describe, expect, test } from "vitest";
import { SsrfError, safeLookup, safeRequest } from "../src/node.js";

// A local server standing in for "the server's own network".
let server: Server;
let base: string;
let hits = 0;

beforeAll(async () => {
  server = createServer((req, res) => {
    hits++;
    if (req.url === "/redirect-to-loopback") {
      res.writeHead(302, { location: `http://[::1]:${(server.address() as AddressInfo).port}/secret` });
      return res.end();
    }
    if (req.url === "/redirect-same") {
      res.writeHead(303, { location: "/ok" });
      return res.end();
    }
    if (req.url === "/big") {
      res.writeHead(200);
      return res.end("x".repeat(5000));
    }
    if (req.url === "/slow") return; // never answers
    if (req.url === "/drip") {
      // Never idle, never done: one byte every 100 ms.
      res.writeHead(200);
      const timer = setInterval(() => res.write("x"), 100);
      return res.on("close", () => clearInterval(timer));
    }
    if (req.url === "/redirect-elsewhere") {
      res.writeHead(302, { location: `http://elsewhere.example:${(server.address() as AddressInfo).port}/auth` });
      return res.end();
    }
    if (req.url === "/redirect-here") {
      res.writeHead(302, { location: "/auth" });
      return res.end();
    }
    if (req.url === "/auth") return res.end(`${req.headers.authorization ?? "none"} ${req.headers.cookie ?? "none"}`);
    res.writeHead(200, { "content-type": "text/plain" });
    res.end(`${req.method} ${req.url}`);
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterAll(() => server.close());

// Pretends a public domain resolves to the given address (as an attacker's DNS would).
function fakeDns(answer: string) {
  return ((_host: string, _options: unknown, callback: (e: null, a: { address: string; family: number }[]) => void) =>
    callback(null, [{ address: answer, family: answer.includes(":") ? 6 : 4 }])) as never;
}

describe("safeRequest", () => {
  test("refuses a private IP before connecting", async () => {
    const before = hits;
    await expect(safeRequest(`${base}/secret`, { allowHttp: true })).rejects.toThrow(SsrfError);
    expect(hits).toBe(before);
  });

  test("refuses a public-looking name that resolves to a private address (DNS rebinding)", async () => {
    const before = hits;
    const port = (server.address() as AddressInfo).port;
    const error = await safeRequest(`http://totally-public.example:${port}/secret`, {
      allowHttp: true,
      lookup: fakeDns("127.0.0.1"),
    }).catch((e) => e);
    expect(error).toBeInstanceOf(SsrfError);
    expect(String(error.message)).toMatch(/resolves to 127\.0\.0\.1: loopback/);
    expect(hits).toBe(before);
  });

  test("reaches an allowed address, and returns the body", async () => {
    const res = await safeRequest(`${base}/hello`, { allowHttp: true, allowAddresses: ["127.0.0.1"] });
    expect(res.status).toBe(200);
    expect(new TextDecoder().decode(res.body)).toBe("GET /hello");
  });

  test("a name resolving to an allowed address works (the check is on the address)", async () => {
    const port = (server.address() as AddressInfo).port;
    const res = await safeRequest(`http://internal.example:${port}/x`, {
      allowHttp: true,
      allowAddresses: ["127.0.0.1"],
      lookup: fakeDns("127.0.0.1"),
    });
    expect(res.status).toBe(200);
  });

  test("redirects are not followed by default", async () => {
    const res = await safeRequest(`${base}/redirect-to-loopback`, { allowHttp: true, allowAddresses: ["127.0.0.1"] });
    expect(res.status).toBe(302);
  });

  test("a followed redirect to a private address is refused", async () => {
    await expect(
      safeRequest(`${base}/redirect-to-loopback`, { allowHttp: true, allowAddresses: ["127.0.0.1"], maxRedirects: 3 }),
    ).rejects.toThrow(/\[::1\].*loopback/);
  });

  test("a followed redirect to an allowed place works, and 303 turns POST into GET", async () => {
    const res = await safeRequest(`${base}/redirect-same`, {
      method: "POST",
      body: "{}",
      allowHttp: true,
      allowAddresses: ["127.0.0.1"],
      maxRedirects: 1,
    });
    expect(new TextDecoder().decode(res.body)).toBe("GET /ok");
  });

  test("large responses are cut off", async () => {
    const res = await safeRequest(`${base}/big`, { allowHttp: true, allowAddresses: ["127.0.0.1"], maxResponseBytes: 100 });
    expect(res.truncated).toBe(true);
    expect(res.body.length).toBe(100);
  });

  test("a server that keeps sending a byte at a time still times out", async () => {
    const started = Date.now();
    await expect(
      safeRequest(`${base}/drip`, { allowHttp: true, allowAddresses: ["127.0.0.1"], timeoutMs: 300 }),
    ).rejects.toThrow(/Timed out/);
    expect(Date.now() - started).toBeLessThan(1500);
  });

  test("credentials don't follow a redirect to another origin", async () => {
    const options = {
      allowHttp: true,
      allowAddresses: ["127.0.0.1"],
      lookup: fakeDns("127.0.0.1"),
      maxRedirects: 1,
      headers: { Authorization: "Bearer SECRET", cookie: "session=1", "x-other": "kept" },
    };
    const away = await safeRequest(`${base}/redirect-elsewhere`, options);
    expect(new TextDecoder().decode(away.body)).toBe("none none");
    const same = await safeRequest(`${base}/redirect-here`, options);
    expect(new TextDecoder().decode(same.body)).toBe("Bearer SECRET session=1");
  });

  test("a keep-alive connection pooled by other code doesn't skip the DNS check", async () => {
    const port = (server.address() as AddressInfo).port;
    // Other code in the app talks to the same host:port and leaves the connection open.
    await new Promise<void>((resolve, reject) => {
      get(
        { host: "pooled.example", port, path: "/", agent: globalAgent, lookup: fakeDns("127.0.0.1") },
        (res) => res.resume().on("end", resolve),
      ).on("error", reject);
    });
    await expect(
      safeRequest(`http://pooled.example:${port}/secret`, { allowHttp: true, lookup: fakeDns("127.0.0.1") }),
    ).rejects.toThrow(SsrfError);
  });

  test("a host in allowHosts may resolve to a private address", async () => {
    const port = (server.address() as AddressInfo).port;
    const res = await safeRequest(`http://Internal.Example.:${port}/x`, {
      allowHttp: true,
      allowHosts: ["internal.example"],
      lookup: fakeDns("127.0.0.1"),
    });
    expect(res.status).toBe(200);
  });

  test("slow endpoints time out", async () => {
    await expect(
      safeRequest(`${base}/slow`, { allowHttp: true, allowAddresses: ["127.0.0.1"], timeoutMs: 300 }),
    ).rejects.toThrow(/Timed out/);
  });
});

describe("safeLookup", () => {
  test("passes public answers through", async () => {
    const lookup = safeLookup({ lookup: fakeDns("93.184.215.14") });
    const address = await new Promise((resolve, reject) =>
      lookup("example.com", {}, (error, addr) => (error ? reject(error) : resolve(addr))),
    );
    expect(address).toBe("93.184.215.14");
  });

  test("refuses IPv4-mapped private answers", async () => {
    const lookup = safeLookup({ lookup: fakeDns("::ffff:169.254.169.254") });
    const error = await new Promise((resolve) => lookup("example.com", {}, (e) => resolve(e)));
    expect(error).toBeInstanceOf(SsrfError);
  });
});

describe("safeLookup in an http.Agent (as the README shows)", () => {
  test("a request through the agent to a name resolving to loopback is refused", async () => {
    const before = hits;
    const port = (server.address() as AddressInfo).port;
    const agent = new Agent({ lookup: safeLookup({ lookup: fakeDns("127.0.0.1") }) } as never);
    const error = await new Promise((resolve) => {
      get(`http://looks-public.example:${port}/`, { agent }, () => resolve(null)).on("error", resolve);
    });
    expect(error).toBeInstanceOf(SsrfError);
    expect(hits).toBe(before);
  });
});
