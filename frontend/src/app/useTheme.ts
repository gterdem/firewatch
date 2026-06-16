/**
 * useTheme — hook to consume ThemeContext.
 *
 * Kept in a separate file to satisfy the react-refresh/only-export-components
 * lint rule (ThemeContext.tsx exports only React components; hooks live here).
 */
export { useTheme } from './ThemeContext'
