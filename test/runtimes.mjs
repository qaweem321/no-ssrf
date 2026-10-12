// Runs the built library in other runtimes (Bun, Deno) to back up "runs anywhere".
// Usage: bun test/runtimes.mjs, deno run test/runtimes.mjs (after npm run build).
import { checkUrl, isPrivateAddress } from "../dist/index.js";

const cases = [
  ["https://example.com/", true],
  ["https://[::ffff:169.254.169.254]/", false],
  ["https://127.1/", false],
  ["https://metadata.google.internal/", false],
  ["https://[2606:4700:4700::1111]/", true],
];

let failed = 0;
for (const [url, ok] of cases) {
  if (checkUrl(url).ok !== ok) {
    failed++;
    console.error(`wrong verdict for ${url}`);
  }
}
if (!isPrivateAddress("::ffff:7f00:1")) {
  failed++;
  console.error("isPrivateAddress missed ::ffff:7f00:1");
}
console.log(failed === 0 ? "all runtime checks passed" : `${failed} runtime checks failed`);
if (failed > 0) throw new Error("runtime checks failed");
