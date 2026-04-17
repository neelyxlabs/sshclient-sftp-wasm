import { defineConfig } from "vite";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  root: resolve(here, "page"),
  server: {
    port: 5173,
    strictPort: true,
  },
  publicDir: resolve(here, "..", "..", "public"),
});
