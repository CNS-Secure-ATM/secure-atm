import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";

// https://vitejs.dev/config/
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "");
  const basePath = env.VITE_BASE_PATH || "/";

  return {
    base: basePath,
    plugins: [react()],
    server: {
      // In dev mode, proxy /api/* calls to the Node.js backend.
      proxy: {
        "/api": {
          target: "http://127.0.0.1:4000",
          changeOrigin: false,
        },
      },
    },
  };
});
