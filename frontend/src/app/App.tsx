/**
 * App — root composition for the FireWatch SOC console (F1 #107).
 *
 * Shell structure (matches kit.css/App.jsx):
 *   <html data-theme="dark|light">  ← set by ThemeContext / main.tsx
 *     sticky AppHeader              ← wordmark + source-filter seam + live + toggle + clock
 *     sticky AppNav                 ← tab bar; active = 2px amber underline
 *     <main>                        ← 1400px max-width, 24px gutter container
 *       <Routes>                    ← react-router v7 client-side routing
 *     </main>
 *
 * OD-1 (approved): shell built from ported DS chrome (flat 1px-bordered,
 * 10px radius, no shadow), NOT coerced shadcn. shadcn stays only under rjsf (F4).
 *
 * Route → tab mapping:
 *   /            → redirect → /dashboard
 *   /dashboard   → DashboardRoute
 *   /ai          → AIRoute
 *   /logs        → LogsRoute
 *   /analytics   → AnalyticsRoute
 *   /settings    → SettingsRoute
 *   /threats     → redirect → /dashboard (threat-actor table lives on Dashboard; #316)
 *   *            → NotFoundView (catch-all; honest 404, not a silent blank; #316)
 *
 * ADR-0028 D1: standalone Vite app; react-router v7 for client-side routing.
 */

import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { ThemeProvider } from './ThemeContext'
import { RefreshProvider } from './refresh/RefreshContext'
import AppHeader from './AppHeader'
import AppNav from './AppNav'
import DashboardRoute from '../routes/DashboardRoute'
import AIRoute from '../routes/AIRoute'
import LogsRoute from '../routes/LogsRoute'
import AnalyticsRoute from '../routes/AnalyticsRoute'
import SettingsRoute from '../routes/SettingsRoute'
import EntityPanelProvider from '../components/entity/EntityPanelProvider'
import NotFoundView from '../components/NotFoundView'

export default function App() {
  return (
    <BrowserRouter>
      <ThemeProvider>
        {/* RefreshProvider — app-wide live-refresh signal (ADR-0064 D1).
            Calls useStatsHeartbeat() ONCE: the single GET /stats interval for
            the entire app. AppHeader + all routed pages consume the signal via
            useRefreshSignal() / useHeaderRefresh() without prop-drilling.
            Mounted at the same architectural seam as EntityPanelProvider
            (ADR-0037 precedent). */}
        <RefreshProvider>
          {/* EntityPanelProvider — app-wide entity slide-over panel host (ADR-0037).
              Mounted once here so any route can call openEntity({ kind, value })
              without props-drilling. The SlideOver renders as a portal-like fixed
              element outside the main scroll container. */}
          <EntityPanelProvider>
            <div
              data-testid="app-shell"
              style={{ minHeight: '100vh', background: 'var(--fw-bg)' }}
            >
              <AppHeader />
              <AppNav />

              <main
                data-testid="main-content"
                style={{
                  maxWidth: 'var(--fw-container)',
                  margin: '0 auto',
                  padding: '20px 24px',
                }}
              >
                <Routes>
                  <Route path="/" element={<Navigate to="/dashboard" replace />} />
                  <Route path="/dashboard" element={<DashboardRoute />} />
                  <Route path="/ai" element={<AIRoute />} />
                  <Route path="/logs" element={<LogsRoute />} />
                  <Route path="/analytics" element={<AnalyticsRoute />} />
                  <Route path="/settings" element={<SettingsRoute />} />
                  {/* /threats redirect — threat-actor table lives on Dashboard; #316 */}
                  <Route path="/threats" element={<Navigate to="/dashboard" replace />} />
                  {/* catch-all — honest not-found surface instead of a silent blank; #316 */}
                  <Route path="*" element={<NotFoundView />} />
                </Routes>
              </main>
            </div>
          </EntityPanelProvider>
        </RefreshProvider>
      </ThemeProvider>
    </BrowserRouter>
  )
}
