import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// https://vite.dev/config/

/**
 * Returns true when a request is a browser HTML navigation (the browser sends
 * Accept: text/html for page loads / reloads / bookmarks).  API fetch() calls
 * send Accept: application/json and do NOT match this check.
 *
 * Used by the proxy bypass below to let bare /logs and /analytics fall through
 * to the SPA (index.html) instead of being forwarded to the API (#77).
 */
function isHtmlNavigation(req: { headers: Record<string, string | string[] | undefined> }): boolean {
  const accept = req.headers['accept'] ?? ''
  return (typeof accept === 'string' ? accept : accept[0] ?? '').includes('text/html')
}

export default defineConfig({
  plugins: [
    react(),
    tailwindcss(),
    // Vite 8 (Rolldown) only applies the JSON→`export default` transform to
    // `.json` files, not `.geojson`. Without this plugin the asset is served
    // as raw JSON with a JS content-type, causing a SyntaxError that crashes
    // the entire module graph before React mounts (blank screen / build fail).
    // ADR-0052 bundled world-outline.geojson for air-gap safety — we keep the
    // .geojson extension and the geojson.d.ts declaration; this transform
    // supplies the missing `export default` wrapper. (fix/geojson-app-crash)
    {
      name: 'geojson-loader',
      transform(src, id) {
        if (id.endsWith('.geojson')) {
          return { code: `export default ${src}`, map: null }
        }
      },
    },
  ],
  server: {
    // Dev-only proxy: forwards API path prefixes to the loopback API so the
    // browser talks to the Vite origin (no CORS needed) while the API remains
    // loopback-only (ADR-0026). The client uses a relative base URL in dev
    // (resolveBaseUrl returns '' when import.meta.env.DEV is true), so every
    // /sources/* and /config/* fetch is transparently forwarded here.
    //
    // FIX #77: /logs and /analytics are ALSO React Router routes.  A plain
    // prefix-match proxy would intercept bare /logs and /analytics GET
    // requests from the browser (Accept: text/html) and return an API 404
    // instead of the SPA.  The bypass function returns '/index.html' for
    // any HTML navigation so React Router handles those routes; API sub-path
    // calls (Accept: application/json) fall through to the proxy normally.
    proxy: {
      '/sources': {
        target: 'http://127.0.0.1:8000',
        bypass: (req) => (isHtmlNavigation(req) ? '/index.html' : undefined),
      },
      '/config': {
        target: 'http://127.0.0.1:8000',
        bypass: (req) => (isHtmlNavigation(req) ? '/index.html' : undefined),
      },
      '/stats': {
        target: 'http://127.0.0.1:8000',
        bypass: (req) => (isHtmlNavigation(req) ? '/index.html' : undefined),
      },
      '/health': {
        target: 'http://127.0.0.1:8000',
        bypass: (req) => (isHtmlNavigation(req) ? '/index.html' : undefined),
      },
      '/threats': {
        target: 'http://127.0.0.1:8000',
        bypass: (req) => (isHtmlNavigation(req) ? '/index.html' : undefined),
      },
      '/logs': {
        target: 'http://127.0.0.1:8000',
        // HTML navigation to bare /logs (browser reload/bookmark) → serve SPA.
        // API requests to /logs/paginated, /logs/recent, etc. → forward to API.
        bypass: (req) => (isHtmlNavigation(req) ? '/index.html' : undefined),
      },
      '/analytics': {
        target: 'http://127.0.0.1:8000',
        // HTML navigation to bare /analytics → serve SPA.
        // API requests to /analytics/summary, /analytics/geo, etc. → forward to API.
        bypass: (req) => (isHtmlNavigation(req) ? '/index.html' : undefined),
      },
      '/sync': {
        target: 'http://127.0.0.1:8000',
        bypass: (req) => (isHtmlNavigation(req) ? '/index.html' : undefined),
      },
      '/rules': {
        target: 'http://127.0.0.1:8000',
        bypass: (req) => (isHtmlNavigation(req) ? '/index.html' : undefined),
      },
      '/ai': {
        target: 'http://127.0.0.1:8000',
        // HTML navigation to bare /ai (the AI Analysis page route) → serve SPA.
        // API requests to /ai/models (Accept: application/json) → forward to API.
        bypass: (req) => (isHtmlNavigation(req) ? '/index.html' : undefined),
      },
      '/cases': {
        target: 'http://127.0.0.1:8000',
        // Covers POST /cases, GET /cases, GET /cases/{id}, PATCH /cases/{id}/disposition,
        // POST /cases/{id}/notes, GET /cases/{id}/notes, POST /cases/{id}/events,
        // GET /cases/{id}/timeline, POST /cases/{id}/summary (DEFECT-MO-01).
        bypass: (req) => (isHtmlNavigation(req) ? '/index.html' : undefined),
      },
      '/escalation': {
        target: 'http://127.0.0.1:8000',
        // GET /escalation/policy — the Escalation Policy card registry + 24h
        // hit-counts (issue #650). API-only (Accept: application/json); no bare
        // route, but keep the SPA bypass for consistency.
        bypass: (req) => (isHtmlNavigation(req) ? '/index.html' : undefined),
      },
    },
  },
  test: {
    globals: true,
    environment: 'jsdom',
    setupFiles: ['./src/test/setup.ts'],
    pool: 'threads',
  },
})
