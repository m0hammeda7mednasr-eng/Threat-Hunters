import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const baseSecurityHeaders = {
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "Permissions-Policy":
    "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Resource-Policy": "same-origin",
};

const previewSecurityHeaders = {
  ...baseSecurityHeaders,
  "Content-Security-Policy": [
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "img-src 'self' data:",
    "font-src 'self' data: https://fonts.gstatic.com",
    "connect-src 'self'",
    "object-src 'none'",
    "base-uri 'self'",
    "frame-ancestors 'none'",
    "form-action 'self'",
  ].join("; "),
};

const isGithubPagesBuild = process.env.GITHUB_ACTIONS === "true";

// https://vite.dev/config/
export default defineConfig(({ command }) => ({
  plugins: [react()],
  // Use a sub-path only for GitHub Pages builds; keep root paths for Vercel and local runs.
  base: command === "serve" ? "/" : isGithubPagesBuild ? "/Threat-Hunters/" : "/",
  server: {
    headers: baseSecurityHeaders,
  },
  preview: {
    headers: previewSecurityHeaders,
  },
  optimizeDeps: {
    include: ["react", "react-dom"],
  },
  build: {
    target: "es2020",
    sourcemap: false,
    cssCodeSplit: true,
    reportCompressedSize: false,
    chunkSizeWarningLimit: 700,
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (!id.includes("node_modules")) {
            return;
          }

          if (id.includes("react") || id.includes("scheduler")) {
            return "react-vendor";
          }

          if (id.includes("lucide-react")) {
            return "icons-vendor";
          }

          return "vendor";
        },
      },
    },
  },
}));
