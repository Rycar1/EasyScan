import {defineConfig} from 'vite'
import react from '@vitejs/plugin-react'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  build: {
    rollupOptions: {
      output: {
        // Keep the application bundle small and cache framework/UI updates
        // independently. Wails serves these chunks from the same embedded
        // asset directory, so this changes no runtime paths.
        manualChunks(id) {
          if (!id.includes('node_modules')) {
            return undefined
          }
          if (id.includes('@fluentui/react-icons')) {
            return 'fluent-icons'
          }
          if (id.includes('@fluentui')) {
            return 'fluent-ui'
          }
          if (id.includes('/react/') || id.includes('/react-dom/') || id.includes('/scheduler/')) {
            return 'react-vendor'
          }
          return 'vendor'
        }
      }
    }
  }
})
