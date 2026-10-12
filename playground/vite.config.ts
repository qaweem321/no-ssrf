import { defineConfig } from "vite";

// The playground, served from https://<user>.github.io/no-ssrf/ on GitHub Pages.
export default defineConfig({
  base: "/no-ssrf/",
  build: { outDir: "dist", emptyOutDir: true },
});
