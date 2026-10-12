import { checkUrl } from "../src/index.js";
import { gallery, naiveFilters } from "./gallery.js";

const input = document.querySelector<HTMLInputElement>("#url");
const result = document.querySelector<HTMLDivElement>("#result");
const body = document.querySelector<HTMLTableSectionElement>("#gallery tbody");
const score = document.querySelector<HTMLParagraphElement>("#score");

function cell(text: string, className = "") {
  const td = document.createElement("td");
  td.textContent = text;
  if (className) td.className = className;
  return td;
}

// Green when the filter decides right, red when it gets it wrong.
function verdictCell(blocks: boolean, shouldBlock: boolean) {
  return cell(blocks ? "blocked" : "allowed", blocks === shouldBlock ? "right" : "wrong");
}

function hostnameOf(url: string) {
  try {
    return new URL(url).hostname;
  } catch {
    return "(not a URL)";
  }
}

function renderTester() {
  if (!input || !result) return;
  const url = input.value;
  result.replaceChildren();
  if (!url.trim()) return;
  const line = (label: string, value: string, className = "") => {
    const p = document.createElement("p");
    const strong = document.createElement("strong");
    strong.textContent = `${label} `;
    const span = document.createElement("span");
    span.textContent = value;
    if (className) span.className = className;
    p.append(strong, span);
    result.append(p);
  };
  line("new URL() turns the host into:", hostnameOf(url), "mono");
  for (const filter of naiveFilters) {
    line(`${filter.name}:`, filter.blocks(url) ? "blocked" : "allowed");
  }
  const verdict = checkUrl(url);
  line("no-ssrf:", verdict.ok ? "allowed" : `blocked: ${verdict.reason}`, verdict.ok ? "allowed" : "blocked");
}

function renderGallery() {
  if (!body) return;
  naiveFilters.forEach((filter, i) => {
    const th = document.querySelector(`#naive-${i}`);
    if (th) {
      th.textContent = filter.name;
      th.setAttribute("title", filter.code);
    }
  });
  const right = naiveFilters.map(() => 0);
  let ours = 0;
  for (const entry of gallery) {
    const tr = document.createElement("tr");
    const urlCell = cell(entry.url, "mono url");
    const why = document.createElement("div");
    why.className = "why";
    why.textContent = entry.why;
    urlCell.append(why);
    tr.append(urlCell, cell(entry.block ? "blocked" : "allowed", "expected"));
    naiveFilters.forEach((filter, i) => {
      const blocks = filter.blocks(entry.url);
      if (blocks === entry.block) right[i]++;
      tr.append(verdictCell(blocks, entry.block));
    });
    const blocks = !checkUrl(entry.url).ok;
    if (blocks === entry.block) ours++;
    tr.append(verdictCell(blocks, entry.block));
    tr.tabIndex = 0;
    const choose = () => {
      if (!input) return;
      input.value = entry.url;
      renderTester();
      input.scrollIntoView({ behavior: "smooth", block: "center" });
    };
    tr.addEventListener("click", choose);
    tr.addEventListener("keydown", (event) => {
      if (event.key === "Enter") choose();
    });
    body.append(tr);
  }
  if (score) {
    const total = gallery.length;
    const parts = naiveFilters.map((f, i) => `${f.name}: ${right[i]}/${total}`);
    score.textContent = `Right answers. ${parts.join(" · ")} · no-ssrf: ${ours}/${total}`;
  }
}

input?.addEventListener("input", renderTester);
renderGallery();
renderTester();
