/**
 * ESLint configuration — FireWatch frontend.
 *
 * Includes the FireWatch SOC Design System adherence rules (F5 #111),
 * ported from legacy/FireWatch SOC Design System/_adherence.oxlintrc.json.
 *
 * Adherence rules enforce:
 *   - No raw hex color literals in src/ (use --fw-* CSS tokens).
 *   - No stroke-icon library imports (lucide-react, heroicons, etc.).
 *   - DS components imported from the ds/index.ts barrel, not deep paths.
 *   - DS component prop/value whitelists (Badge tone, Button variant/size, etc.).
 *
 * Allowlisted from the raw-hex / raw-px rule:
 *   - src/index.css  — the token source-of-truth (CSS, not linted here anyway).
 *   - src/lib/socTokens.ts — CSS class names only, no hex.
 *   - test/**        — fixture data and JSDOM colour assertions may use hex.
 *   - assets/**      — SVG/image files.
 */

import js from '@eslint/js'
import globals from 'globals'
import reactHooks from 'eslint-plugin-react-hooks'
import reactRefresh from 'eslint-plugin-react-refresh'
import tseslint from 'typescript-eslint'
import { defineConfig, globalIgnores } from 'eslint/config'

// ---------------------------------------------------------------------------
// DS adherence — no-restricted-syntax selectors
// Ported from _adherence.oxlintrc.json §no-restricted-syntax.
// ---------------------------------------------------------------------------

/** Catch raw hex literals: #rgb, #rrggbb, #rrggbbaa — not inside comments. */
const NO_RAW_HEX = {
  selector: "Literal[value=/#[0-9a-fA-F]{3,8}\\b/]",
  message:
    'Raw hex color — use a design-system token via var(--fw-*). ' +
    'Token definitions belong in src/index.css (exempted from this rule).',
}

/** Catch raw px values as string literals (e.g. style={{ width: "12px" }}). */
const NO_RAW_PX = {
  selector: "Literal[value=/^\\d+px$/]",
  message:
    'Raw px value as string — use a design-system spacing token via var(--fw-sp-*) ' +
    'or a numeric pixel value for inline styles (numbers, not "12px" strings).',
}

// DS component prop whitelist rules — ported from _adherence.oxlintrc.json
const DS_PROP_RULES = [
  // Badge
  {
    selector:
      "JSXOpeningElement[name.name='Badge'] > JSXAttribute[name.name='tone'] > Literal[value!=/^(?:critical|high|medium|low|block|allow|alert|drop|waf|ids|syslog|file|neutral)$/]",
    message:
      "<Badge> tone must be one of 'critical'|'high'|'medium'|'low'|'block'|'allow'|'alert'|'drop'|'waf'|'ids'|'syslog'|'file'|'neutral'.",
  },
  // Button
  {
    selector:
      "JSXOpeningElement[name.name='Button'] > JSXAttribute[name.name='variant'] > Literal[value!=/^(?:primary|danger|deep|secondary|ghost)$/]",
    message:
      "<Button> variant must be one of 'primary'|'danger'|'deep'|'secondary'|'ghost'.",
  },
  {
    selector:
      "JSXOpeningElement[name.name='Button'] > JSXAttribute[name.name='size'] > Literal[value!=/^(?:md|sm)$/]",
    message: "<Button> size must be one of 'md'|'sm'.",
  },
  // StatCard
  {
    selector:
      "JSXOpeningElement[name.name='StatCard'] > JSXAttribute[name.name='accent'] > Literal[value!=/^(?:amber|red|blue|green|orange|purple|cyan|default)$/]",
    message:
      "<StatCard> accent must be one of 'amber'|'red'|'blue'|'green'|'orange'|'purple'|'cyan'|'default'.",
  },
  // SourceCard
  {
    selector:
      "JSXOpeningElement[name.name='SourceCard'] > JSXAttribute[name.name='status'] > Literal[value!=/^(?:active|listening|syncing|error|idle)$/]",
    message:
      "<SourceCard> status must be one of 'active'|'listening'|'syncing'|'error'|'idle'.",
  },
  // Toast
  {
    selector:
      "JSXOpeningElement[name.name='Toast'] > JSXAttribute[name.name='tone'] > Literal[value!=/^(?:ok|err|info)$/]",
    message: "<Toast> tone must be one of 'ok'|'err'|'info'.",
  },
  // ThemeToggle
  {
    selector:
      "JSXOpeningElement[name.name='ThemeToggle'] > JSXAttribute[name.name='theme'] > Literal[value!=/^(?:dark|light)$/]",
    message: "<ThemeToggle> theme must be one of 'dark'|'light'.",
  },
  // Input
  {
    selector:
      "JSXOpeningElement[name.name='Input'] > JSXAttribute[name.name='size'] > Literal[value!=/^(?:md|sm)$/]",
    message: "<Input> size must be one of 'md'|'sm'.",
  },
  // ProvenanceChip (ADR-0035)
  {
    selector:
      "JSXOpeningElement[name.name='ProvenanceChip'] > JSXAttribute[name.name='derivation'] > Literal[value!=/^(?:rule|ai|ai\\+rule)$/]",
    message:
      "<ProvenanceChip> derivation must be one of 'rule'|'ai'|'ai+rule' (ADR-0035 vocabulary).",
  },
]

export default defineConfig([
  // Playwright e2e files use console.log and Playwright-specific globals — exclude from the
  // no-console rule. The sweep.spec.ts file is untracked (not in git) but lives in frontend/e2e/
  // and would otherwise cause 60+ no-console errors.
  globalIgnores(['dist', 'e2e/**', 'playwright.config.ts']),

  // ---------------------------------------------------------------------------
  // Main rule set — all TS/TSX files
  // ---------------------------------------------------------------------------
  {
    files: ['**/*.{ts,tsx}'],
    extends: [
      js.configs.recommended,
      tseslint.configs.recommended,
      reactHooks.configs.flat.recommended,
      reactRefresh.configs.vite,
    ],
    languageOptions: {
      globals: globals.browser,
    },
    rules: {
      'no-console': ['error', { allow: ['warn', 'error'] }],

      // --- DS adherence: no stroke-icon library imports ---
      // lucide-react was removed from package.json; this rule prevents regression.
      'no-restricted-imports': [
        'error',
        {
          patterns: [
            {
              group: ['lucide-react', 'lucide-react/*'],
              message:
                'Stroke-icon libraries are banned — emoji is the icon system (DS Iconography). ' +
                'Use an emoji glyph matching the meaning from the DS readme.',
            },
            {
              group: ['@heroicons/*', 'react-icons', 'react-icons/*'],
              message:
                'Stroke-icon libraries are banned — emoji is the icon system (DS Iconography). ' +
                'Use an emoji glyph matching the meaning from the DS readme.',
            },
            {
              group: [
                // Without leading ./ — alias or node_modules-style imports
                'components/ds/core/*',
                'components/ds/feedback/*',
                'components/ds/filters/*',
                'components/ds/forms/*',
                'components/ds/nav/*',
                'components/ds/sources/*',
                'components/ds/analytics/*',
                // One level up (routes/, widgets/ → ../ds/*)
                '../ds/core/*',
                '../ds/feedback/*',
                '../ds/filters/*',
                '../ds/forms/*',
                '../ds/nav/*',
                '../ds/sources/*',
                '../ds/analytics/*',
                // Two levels up (components/logs/ → ../../ds/*)
                '../../ds/core/*',
                '../../ds/feedback/*',
                '../../ds/filters/*',
                '../../ds/forms/*',
                '../../ds/nav/*',
                '../../ds/sources/*',
                '../../ds/analytics/*',
                // From routes/ using components/ prefix (../components/ds/*/Name)
                '../components/ds/core/*',
                '../components/ds/feedback/*',
                '../components/ds/filters/*',
                '../components/ds/forms/*',
                '../components/ds/nav/*',
                '../components/ds/sources/*',
                '../components/ds/analytics/*',
              ],
              message:
                'Import DS components from the barrel (components/ds/index.ts), not deep paths. ' +
                "Use: import { Button, Badge } from '../ds' (or '../../ds').",
            },
          ],
        },
      ],

      // --- DS adherence: no raw hex / raw px + DS prop whitelists ---
      'no-restricted-syntax': [
        'error',
        NO_RAW_HEX,
        NO_RAW_PX,
        ...DS_PROP_RULES,
      ],
    },
  },

  // ---------------------------------------------------------------------------
  // Exemptions — places where raw hex is legitimate
  // ---------------------------------------------------------------------------

  // The DS barrel (ds/index.ts) re-exports from sub-paths — must be allowed to
  // import from deep paths (it IS the barrel).
  {
    files: ['**/ds/index.ts'],
    rules: {
      'no-restricted-imports': 'off',
    },
  },

  // Test files may assert on computed colours (hex/rgb in JSDOM) and use fixture
  // hex values.  Relax raw-hex and raw-px there; keep icon/barrel rules active.
  {
    files: ['**/test/**', '**/*.test.{ts,tsx}'],
    rules: {
      'no-restricted-syntax': [
        'error',
        // Keep DS prop whitelist rules in tests; relax hex/px literals.
        ...DS_PROP_RULES,
      ],
    },
  },
])
