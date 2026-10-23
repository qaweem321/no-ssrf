// The playground's markup as HTML strings. The build puts it straight into index.html (no layout
// shift when the script loads), and main.ts uses the same functions for the live URL tester.
import { checkUrl } from "../src/index.js";
import { gallery, naiveFilters } from "./gallery.js";

export const DEFAULT_URL = "https://[::ffff:169.254.169.254]/latest/meta-data/";

export function escapeHtml(text: string) {
  return text
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

const blocks = (url: string) => !checkUrl(url).ok;

function hostnameOf(url: string) {
  try {
    return new URL(url).hostname;
  } catch {
    return "(not a URL)";
  }
}

// What each filter, and no-ssrf, decides for one URL.
export function testerHtml(url: string) {
  if (!url.trim()) return "";
  const line = (label: string, value: string, className = "") =>
    `<p><strong>${escapeHtml(label)}</strong> <span${className ? ` class="${className}"` : ""}>${escapeHtml(value)}</span></p>`;
  const verdict = checkUrl(url);
  return [
    line("new URL() turns the host into:", hostnameOf(url), "mono"),
    ...naiveFilters.map((filter) => line(`${filter.name}:`, filter.blocks(url) ? "blocked" : "allowed")),
    line("no-ssrf:", verdict.ok ? "allowed" : `blocked: ${verdict.reason}`, verdict.ok ? "allowed" : "blocked"),
  ].join("");
}

// Green when the filter decides right, red when it gets it wrong.
const verdictCell = (blocked: boolean, shouldBlock: boolean) =>
  `<td class="${blocked === shouldBlock ? "right" : "wrong"}">${blocked ? "blocked" : "allowed"}</td>`;

export function galleryHeadHtml() {
  return naiveFilters.map((f) => `<th title="${escapeHtml(f.code)}">${escapeHtml(f.name)}</th>`).join("");
}

export function galleryRowsHtml() {
  return gallery
    .map((entry) => {
      const naive = naiveFilters.map((f) => verdictCell(f.blocks(entry.url), entry.block)).join("");
      return (
        `<tr tabindex="0" data-url="${escapeHtml(entry.url)}">` +
        `<td class="mono url">${escapeHtml(entry.url)}<div class="why">${escapeHtml(entry.why)}</div></td>` +
        `<td class="expected">${entry.block ? "blocked" : "allowed"}</td>` +
        naive +
        verdictCell(blocks(entry.url), entry.block) +
        "</tr>"
      );
    })
    .join("");
}

export function scoreText() {
  const total = gallery.length;
  const right = (decide: (url: string) => boolean) => gallery.filter((e) => decide(e.url) === e.block).length;
  const parts = naiveFilters.map((f) => `${f.name}: ${right(f.blocks)}/${total}`);
  return `Right answers. ${parts.join(" · ")} · no-ssrf: ${right(blocks)}/${total}`;
}

// Fills the placeholders in index.html.
export function renderPage(html: string) {
  const slots: Record<string, string> = {
    "default-url": escapeHtml(DEFAULT_URL),
    tester: testerHtml(DEFAULT_URL),
    "gallery-head": galleryHeadHtml(),
    "gallery-rows": galleryRowsHtml(),
    score: escapeHtml(scoreText()),
  };
  return html.replace(/<!--slot:([a-z-]+)-->/g, (match, name: string) => {
    if (!(name in slots)) throw new Error(`index.html has an unknown slot: ${match}`);
    return slots[name];
  });
}
