import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

/* Vite 設定

build outDir 為 dist 供 Go //go:embed 內嵌
dev 時 proxy /api 到 Go 伺服器 */
export default defineConfig({
  plugins: [react()],
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
