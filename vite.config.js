import { resolve } from 'path'
import { defineConfig } from "vite";

export default defineConfig({
  build: {
    rollupOptions: {
      input: {
        layout: resolve(__dirname, 'resources', 'css', 'app.scss'),
      },
    },
    outDir: '',
    assetsDir: 'static/assets',
    manifest: 'static/assets/manifest.json',
    emptyOutDir: false,
  },
})