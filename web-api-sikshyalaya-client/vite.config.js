import path from "path";
import fs from "fs";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";
import obfuscator from "rollup-plugin-obfuscator";

export default defineConfig({
  plugins: [
    react()
  ],
  build: {
    outDir: 'dist',
    minify: 'esbuild',
    rollupOptions: {
      plugins: [
        obfuscator({
          compact: true,
          controlFlowFlattening: true,
          deadCodeInjection: true,
          stringArray: true,
          rotateStringArray: true,
          disableConsoleOutput: true
        }, ['**/*.css']) // don't obfuscate CSS
      ]
    }
  },
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  server: {
    https: {
      key: fs.readFileSync(path.resolve(__dirname, "ssl/key.pem")),
      cert: fs.readFileSync(path.resolve(__dirname, "ssl/cert.pem")),
    },
  },
});
