import { readFileSync } from "node:fs";
import { describe, expect, test } from "vitest";
import { gallery } from "../playground/gallery.js";
import { escapeHtml, renderPage, testerHtml } from "../playground/render.js";

describe("the playground page", () => {
  const page = renderPage(readFileSync(new URL("../playground/index.html", import.meta.url), "utf8"));

  test("is rendered at build time: every slot filled, every gallery URL in the table", () => {
    expect(page).not.toContain("<!--slot:");
    expect(page.match(/<tr tabindex="0" data-url=/g)).toHaveLength(gallery.length);
    for (const entry of gallery) expect(page).toContain(`data-url="${escapeHtml(entry.url)}"`);
    expect(page).toMatch(/no-ssrf: \d+\/\d+<\/p>/);
  });

  test("an unknown slot fails the build", () => {
    expect(() => renderPage("<!--slot:nope-->")).toThrow("unknown slot");
  });

  test("text is escaped before it goes into the HTML", () => {
    expect(escapeHtml(`<a href="x" title='y'>&</a>`)).toBe("&lt;a href=&quot;x&quot; title=&#39;y&#39;&gt;&amp;&lt;/a&gt;");
    expect(testerHtml("https://[::1]/")).toContain("<span class=\"blocked\">blocked: loopback (the server itself)</span>");
    expect(testerHtml("  ")).toBe("");
  });
});
