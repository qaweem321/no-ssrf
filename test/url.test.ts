import { readFileSync } from "node:fs";
import { describe, expect, test } from "vitest";
import { gallery, naiveFilters } from "../playground/gallery.js";
import { checkUrl } from "../src/index.js";

describe("the gallery", () => {
  test.each(gallery)("$url", ({ url, block }) => {
    expect(checkUrl(url).ok).toBe(!block);
  });

  test("the README and the playground page give the gallery's real size", () => {
    const readme = readFileSync(new URL("../README.md", import.meta.url), "utf8");
    const page = readFileSync(new URL("../playground/index.html", import.meta.url), "utf8");
    expect(readme).toContain(`${gallery.length} URLs (the playground's list)`);
    expect(page).toContain(`${gallery.length} tricky URLs`);
  });

  test("the naive filters really miss some of it (what the playground shows)", () => {
    for (const filter of naiveFilters) {
      const missed = gallery.filter((e) => e.block && !filter.blocks(e.url));
      expect(missed.length, filter.name).toBeGreaterThan(5);
    }
  });
});

describe("options", () => {
  test("allowHttp", () => {
    expect(checkUrl("http://example.com/").ok).toBe(false);
    expect(checkUrl("http://example.com/", { allowHttp: true }).ok).toBe(true);
    expect(checkUrl("http://127.0.0.1/", { allowHttp: true }).ok).toBe(false);
  });

  test("allowedPorts", () => {
    expect(checkUrl("https://example.com:8443/", { allowedPorts: [443] }).ok).toBe(false);
    expect(checkUrl("https://example.com/", { allowedPorts: [443] }).ok).toBe(true);
  });

  test("allowHosts lets a trusted internal service through", () => {
    expect(checkUrl("https://10.0.0.5/", { allowHosts: ["10.0.0.5"] }).ok).toBe(true);
    expect(checkUrl("https://10.0.0.6/", { allowHosts: ["10.0.0.5"] }).ok).toBe(false);
  });

  test("any number of trailing dots names the same host", () => {
    for (const url of ["https://localhost./", "https://localhost../", "https://metadata.google.internal.../"]) {
      expect(checkUrl(url).ok, url).toBe(false);
    }
  });

  test("bad input", () => {
    expect(checkUrl("not a url")).toMatchObject({ ok: false, reason: "not a valid URL" });
    expect(checkUrl(`https://example.com/${"a".repeat(3000)}`).ok).toBe(false);
  });

  test("a verdict carries the parsed URL to use for the request", () => {
    const verdict = checkUrl("  https://Example.com/path?q=1 ");
    expect(verdict.ok && verdict.url.href).toBe("https://example.com/path?q=1");
  });
});
