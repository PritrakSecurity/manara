import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },

  server: {
    host: 'localhost',       // Listen only on localhost for dev
    port: 5173,              // Use port 5173
    strictPort: true,        // Fail if port is in use (don't switch to 5174)
    open: false,             // Don't auto-open browser
    cors: true,              // Enable CORS
    proxy: {
      '/api': {
        target: 'http://localhost:8080',
        changeOrigin: true,
        rewrite: (path) => path
      },
      '/ws': {
        target: 'ws://localhost:8080',
        ws: true,
        changeOrigin: true
      }
    },
    hmr: {
      host: 'localhost',
      port: 5173,
      protocol: 'ws'
    }
  },
  
  preview: {
    host: 'localhost',
    port: 5173,
    strictPort: true
  },

  // Ensure assets are handled correctly
  build: {
    assetsDir: 'assets',
    rollupOptions: {
      output: {
        assetFileNames: 'assets/[name]-[hash][extname]'
      }
    }
  }
})
