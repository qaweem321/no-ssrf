import { defineConfig } from "vite";
import { renderPage } from "./render.js";

// The playground, served from https://<user>.github.io/no-ssrf/ on GitHub Pages. The gallery is
// rendered into index.html at build time, so nothing moves when the script loads.
export default defineConfig({
  base: "/no-ssrf/",
  build: { outDir: "dist", emptyOutDir: true },
  plugins: [{ name: "render-gallery", transformIndexHtml: (html) => renderPage(html) }],
});
