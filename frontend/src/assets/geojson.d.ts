/**
 * Type declaration for GeoJSON asset imports (ADR-0052: bundled world-outline).
 * Vite handles .geojson as a JSON import; this declaration gives TypeScript the
 * unknown type so callers can safely cast to their expected GeoJSON shape.
 */
declare module '*.geojson' {
  const value: unknown
  export default value
}
