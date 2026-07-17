import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import path from "node:path";
import { fileURLToPath } from "node:url";

/* Vite 設定

build outDir 為 dist 供 Go //go:embed 內嵌
dev 時 proxy /api 到 Go 伺服器 */
const __dirname = path.dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  server: {
    proxy: {
      "/api": "http://localhost:7780",
    },
  },
  build: {
    outDir: "dist",
    emptyOutDir: true,
  },
});
