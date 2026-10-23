// The gallery and the first result are already in the HTML (rendered at build time by render.ts).
// This only keeps the tester live and makes the gallery rows clickable.
import { testerHtml } from "./render.js";

const input = document.querySelector<HTMLInputElement>("#url");
const result = document.querySelector<HTMLDivElement>("#result");
const rows = document.querySelector<HTMLTableSectionElement>("#gallery tbody");

function renderTester() {
  if (input && result) result.innerHTML = testerHtml(input.value);
}

function choose(row: HTMLTableRowElement | null) {
  const url = row?.dataset.url;
  if (!input || url === undefined) return;
  input.value = url;
  renderTester();
  input.scrollIntoView({ behavior: "smooth", block: "center" });
}

const rowOf = (event: Event) => (event.target as Element).closest<HTMLTableRowElement>("tr[data-url]");

input?.addEventListener("input", renderTester);
rows?.addEventListener("click", (event) => choose(rowOf(event)));
rows?.addEventListener("keydown", (event) => {
  if (event.key === "Enter") choose(rowOf(event));
});
// The browser may restore a different value into the field (back/forward, autofill).
renderTester();
