import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  build: {
    // The daemon embeds this directory, so the output has to land where the
    // //go:embed directive in cmd/orbisd expects it.
    outDir: '../cmd/orbisd/web/dist',
    emptyOutDir: true,
    chunkSizeWarningLimit: 900,
    rollupOptions: {
      output: {
        manualChunks: {
          // three is ~600 KB and only the globe needs it; splitting it lets
          // every other route load without paying for the renderer.
          three: ['three'],
        },
      },
    },
  },
  server: {
    port: 5173,
    proxy: {
      '/api': { target: 'http://127.0.0.1:8080', changeOrigin: true, ws: true },
      '/orbis-ca.crt': 'http://127.0.0.1:8080',
    },
  },
})
