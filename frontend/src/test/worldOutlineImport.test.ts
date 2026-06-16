/**
 * Regression test for fix/geojson-app-crash.
 *
 * Vite 8 (Rolldown) does not apply the JSON → `export default` transform to
 * `.geojson` files.  Without the `geojson-loader` plugin in vite.config.ts the
 * import throws a SyntaxError at parse time, collapsing the entire module graph
 * and producing a blank screen on every route.
 *
 * This test asserts that the bundler transform works: the import resolves to an
 * object whose `type` property is "FeatureCollection" (Natural Earth GeoJSON
 * identity check).  If the transform is absent the import either throws or
 * returns a raw string, and both assertions below will fail.
 */

import { describe, it, expect } from 'vitest'
import worldOutlineRaw from '../assets/world-outline.geojson'

describe('world-outline.geojson import (geojson-loader Vite plugin)', () => {
  it('resolves to an object (not a raw string or undefined)', () => {
    expect(typeof worldOutlineRaw).toBe('object')
    expect(worldOutlineRaw).not.toBeNull()
  })

  it('has type === "FeatureCollection" — confirms valid GeoJSON was parsed', () => {
    const geo = worldOutlineRaw as { type: string }
    expect(geo.type).toBe('FeatureCollection')
  })
})
