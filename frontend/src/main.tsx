import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './app/App.tsx'

/*
 * Dark-first theme (F1 #107, DS spec): set data-theme="dark" on <html> before
 * the first render so there is no flash of unstyled content. App's ThemeContext
 * owns the toggle logic and updates this attribute reactively.
 */
document.documentElement.setAttribute('data-theme', 'dark')

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
