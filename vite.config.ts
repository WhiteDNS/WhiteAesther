import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { readFileSync } from "node:fs";
import { fileURLToPath, URL } from "node:url";

// @ts-expect-error process is a nodejs global
const host = process.env.TAURI_DEV_HOST;

// The version shown in the app footer. CI sets this to a tag or a branch build
// string; without it a local build used to fall back to a hardcoded "1.0.0" and
// claim a version it was not. package.json is the one place the number lives,
// so default to it and let CI override.
const pkg = JSON.parse(readFileSync(new URL("./package.json", import.meta.url), "utf8"));
// @ts-expect-error process is a nodejs global
process.env.VITE_APP_VERSION ||= pkg.version;

// https://vite.dev/config/
export default defineConfig(async () => ({
  plugins: [react()],

  resolve: {
    alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) },
  },

  // Vite options tailored for Tauri development and only applied in `tauri dev` or `tauri build`
  //
  // 1. prevent Vite from obscuring rust errors
  clearScreen: false,
  // 2. tauri expects a fixed port, fail if that port is not available
  server: {
    port: 1420,
    strictPort: true,
    host: host || false,
    hmr: host
      ? {
          protocol: "ws",
          host,
          port: 1421,
        }
      : undefined,
    watch: {
      // 3. tell Vite to ignore watching `src-tauri`
      ignored: ["**/src-tauri/**", "**/.core-work/**", "**/.core-reference/**",
        "**/aether-core/**", "**/aether-source/**", "**/artifacts/**", "**/test-results/**"],
    },
  },
}));
