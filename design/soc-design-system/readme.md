# FireWatch SOC Design System

A design system extracted from **FireWatch AI** — an AI-powered, **multi-source** log
analyzer and Security Operations Center (SOC) console. FireWatch ingests security events
from several sources (Azure WAF, Suricata IDS, syslog, file import), normalizes them through
a collect → enrich → store → detect → score → alert pipeline, scores attacking IPs with a
dual engine (deterministic rules + a local Ollama LLM) and cross-source correlation, and
presents real-time threat intelligence through a dark, data-dense dashboard.

This system captures that console's visual language so new FireWatch surfaces — dashboards,
reports, slides, alerting UIs — can be built consistently and quickly.

> **Status:**  The brand foundations (color, type,
> spacing) are unchanged from v1; v2 is an *additive* evolution (sources, IDS verdicts,
> filter bar, correlation). The goal of this system is to let you *recreate and extend* the
> existing FireWatch console, not redesign it.

## Sources

- **GitHub:** `gterdem/firewatch-legacy` — https://github.com/gterdem/firewatch_legacy *(private)*
  - **Branch built from:** `v2/pipeline-architecture` .
    `main` is stable v1.2.1 (Azure WAF only).
  - `dashboard.html` — the single-file dashboard (dark/light themes); the source of truth
    for every token and component here.
  - `core/` · `ports/` · `adapters/` · `api/` · `config/` — the v2 pipeline architecture
    (domain logic, Protocol interfaces, source/AI/notifier implementations, thin FastAPI).
  - `app/` — the v1 FastAPI backend (rule + AI scoring, Azure sync).
  - `README.md` / `CLAUDE.md` — architecture, the AI sampling pipeline, the OWASP CRS rule
    map, the multi-source design, and the recommendation logic.
- **Related infra:** `gterdem/azure-waf` (Terraform for the WAF + Log Analytics).

If you have access, explore the repo to design with higher fidelity — especially
`dashboard.html` on `v2/pipeline-architecture` for exact layout, and the `core/` + `adapters/`
dirs for the multi-source threat model and the language the product uses.

---

## Product context

FireWatch AI is one product: a **SOC console** for a single operator/analyst. It is not a
multi-tenant SaaS; it runs locally. In v2 it ingests from **multiple sources** (Azure WAF,
Suricata IDS, syslog, file import) selectable from a header filter, with per-source health
dots. The console has working areas, all in one page:

| Area | What it does |
|------|--------------|
| **Dashboard** | Overview KPIs, attack-category bars, ranked threat actors, activity timeline, blocked-log feed, and an AI sidebar (summary / recommendations / scores). |
| **AI Analysis** | One-click Ollama analysis of every IP via "smart sampling" (one prompt per actor), with per-IP threat scores and recommendations. |
| **Network Logs** | Server-paginated log viewer with category tabs, IP/rule search, and CSV/JSON export. |
| **Settings** | Azure sync, Ollama model + alert threshold, webhook alerting, theme. |

Plus a **drill-down modal** (click any IP) and a **rule popup** (click any OWASP rule ID).

---

## Content fundamentals

How FireWatch writes copy:

- **Voice:** terse, operational, analyst-to-analyst. Short noun phrases over sentences in
  the UI ("Total events", "Block rate", "Threat actors", "Clear & re-sync"). Full sentences
  appear only in AI-generated insight text.
- **Casing:** **Sentence case** for headings and labels ("Attack categories", "Activity
  timeline", "AI threat summary"). **UPPERCASE** is reserved for micro-labels, table
  headers, badges and verdicts ("BLOCKED", "CRITICAL", "BLOCK / ALLOW"). Never Title Case.
- **Person:** mostly impersonal/imperative — the UI labels things and issues commands
  ("Sync now", "Generate summary", "Send test alert"). No "you"; no "we" except the docs.
- **Numbers & data:** always monospace, always precise. Counts use thousands separators
  (`8,412`), rates use whole-percent (`28%`), IPs/rules/payloads are shown verbatim.
- **Severity language:** the canonical ladder is **LOW → MEDIUM → HIGH → CRITICAL**.
  Action verbs are **BLOCK / INVESTIGATE / MONITOR / REVIEW**.
- **Emoji:** **yes — emoji are the icon system** (see Iconography). Used as section glyphs
  in headers and KPI tiles. One leading emoji per title; never mid-sentence, never decorative
  clusters.
- **Vibe:** a calm, professional war-room. Authoritative but not alarmist — color and badges
  carry urgency so the text doesn't have to shout.

Representative strings: `"AI-powered threat intelligence beyond rule-based detection"`,
`"Uses smart sampling — one prompt per IP for fast results."`, `"Custom rule. No description
available."`, `"Light theme recommended for projectors in bright rooms"`.

---

## Visual foundations

- **Theme:** **dark-first.** The default "operations" theme is a deep navy-black
  (`#0a0e17`) with slate panels (`#111827`). A light theme exists strictly for projectors in
  bright rooms — design for dark, verify both. Theme is toggled via `data-theme="light"` on
  `<html>`.
- **Brand color:** a single **amber** signature (`#f59e0b`). It marks the logo word, active
  nav/tabs, primary buttons, and focus rings — and almost nothing else. Restraint is the point.
- **Functional palette:** a fixed set of hues each carry meaning — red = blocked/critical/drop,
  blue = allowed/medium/links, green = live/online/low, orange = high/SQLi/**IDS alert**, purple =
  anomaly/AI-deep, cyan = rule links/geo, pink = LFI. Attack categories each own a fixed hue (see the
  Colors cards). Don't introduce new colors; reuse these by meaning.
- **Source palette (v2):** each ingest source owns a hue — **WAF = blue, IDS/Suricata = orange,
  syslog = green, file = purple** — used for source badges, header health dots, and the
  correlated event-timeline dots. **Verdicts:** BLOCK/DROP (red tint), ALLOW (green tint), and
  **ALERT** (IDS) as a *solid* orange chip — the one badge that isn't a tint.
- **Type:** the system UI stack (**Segoe UI**, system-ui) for chrome; **monospace** for *all*
  data — numbers, IPs, rule IDs, timestamps, payloads. This sans/mono split is the core
  typographic signal of the console. Sizes run small and dense (10–14px UI; 30px for KPI values).
- **Layout:** a centered `1400px` max-width column with a `24px` gutter. Everything is built
  from **1px-bordered panels** on grids with 12–16px gaps. Sticky header + tab nav. No hero
  units, no marketing whitespace — density is a feature.
- **Cards & panels:** flat surfaces, `10px` radius, `1px` solid border, **no drop shadow**.
  Elevation is reserved for *floating* overlays only (modals, popups, toasts) which use a
  soft, deep shadow. Inset wells (inputs, sidebar cards) drop to `#1e293b`.
- **Badges/pills:** uppercase, `8px` radius, a ~9% tint of the hue with a ~19% border of the
  same hue. This tinted-pill recipe is used everywhere for severity, verdicts and categories.
- **Bars:** progress/category/timeline bars sit in a `#1e293b` track at `3px` radius, filled
  with the category/verdict hue. Stacked red+blue bars encode blocked vs allowed.
- **Borders:** the whole UI is assembled from `1px` hairlines (`--fw-border`); a slightly
  lighter border (`--fw-border-l`) rings focusable wells and floating surfaces. Active tabs use
  a `2px` amber underline; insight rows use a `3px` colored left stripe.
- **Motion:** fast and functional — `0.15s ease` on hovers/tabs, a `0.7s` spinner, a `2s`
  opacity pulse on the live dot. **No bounce, no slides** except the toast (slides in from the
  right). Reduced, purposeful animation.
- **Hover / press:** hover = a brighter surface (`--fw-bg-hover`) for rows, lighter amber for
  the primary button, color shift from faint→muted→primary on links/tabs. Links underline on
  hover. No scale/press transforms.
- **Transparency & blur:** minimal. Tints use rgba over solid surfaces; the modal backdrop is
  a flat `rgba(0,0,0,.7)` (lighter in light theme). No glassmorphism, no backdrop blur.
- **Imagery:** essentially none — this is a data tool. The only "imagery" is the Leaflet geo
  threat map (dark tiles) and Chart.js donut/bar charts on the Analytics tab. No photography,
  no illustration, no gradients except the subtle header fade.

---

## Iconography

FireWatch uses **emoji as its icon system** — deliberately, throughout the product. There is
no icon font, no SVG sprite, no PNG icon set in the codebase.

- **Logo:** the flame emoji **🔥** beside the wordmark "FireWatch *AI*" (amber + muted).
- **Section glyphs:** one leading emoji per panel/KPI title — e.g. 📊 stats, 🛡️ blocked,
  🌐 IPs, 🤖 AI status, 🧠 AI summary, 🎯 threat actors, ⚡ recommendations, 📈 timeline,
  🔬 deep analysis, 🌍 geo map, 🎨 appearance, 🔍 drill-down.
- **Source glyphs (v2):** ☁️ Azure WAF, 🛰️ Suricata IDS, 📡 syslog, 📄 file import; 🌙/☀️ on
  the theme toggle.
- **Status:** a pulsing green ● dot for "live"; ● colored dots for connection status.
- **Rules:** when adding new surfaces, keep the emoji-as-icon convention. Match an existing
  glyph's meaning before introducing a new one. Do **not** swap in a stroke-icon library
  (Lucide/Heroicons) — it would break the product's voice. (If a future direction calls for a
  real icon set, flag it as a deliberate change.)

See the **Brand → Logo & iconography** card for the lockup and the working glyph set.

---

## Foundations at a glance

| Token group | File | Highlights |
|-------------|------|-----------|
| Colors | `tokens/colors.css` | dark + light themes; surfaces, text ramp, functional hues, tints; v2 source hues + verdicts |
| Typography | `tokens/typography.css` | UI vs mono families; 10–30px scale; weights, tracking |
| Spacing | `tokens/spacing.css` | spacing scale, radii, borders, overlay shadows, layout, motion |
| Animations | `tokens/animations.css` | `fw-pulse`, `fw-spin` keyframes |

All are aggregated by **`styles.css`** (root) — the single file consumers link.

---

## Index / manifest

```
styles.css                  Global entry point (import manifest only)
tokens/                     Design tokens (colors, type, spacing, animations)
guidelines/                 Foundation specimen cards (Design System tab)
components/
  core/                     Button · Badge · StatCard · Panel
  forms/                    Input · Select
  navigation/               Tabs · ThemeToggle
  feedback/                 Spinner · LiveBadge · Toast · EmptyState
  filters/                  Combobox · FilterChip            (v2)
  sources/                  SourceBadge · SourceHealth · SourceCard · EventTimeline  (v2)
ui_kits/
  soc-console/              FireWatch console recreation (interactive, multi-source)
    index.html              Console: Dashboard / AI / Logs / Settings + drill-down
    data.js, *.jsx          Sample multi-source data and screen modules
SKILL.md                    Agent Skill manifest (for Claude Code)
readme.md                   This file
```

### Components (`window.FireWatchSOCDesignSystem_f0469e`)

Core: `Button`, `Badge` (severity / verdict / source / neutral), `StatCard`, `Panel`. Forms:
`Input`, `Select`. Navigation: `Tabs`, `ThemeToggle`. Feedback: `Spinner`, `LiveBadge`,
`Toast`, `EmptyState`. Filters (v2): `Combobox`, `FilterChip`. Sources (v2): `SourceBadge`,
`SourceHealth`, `SourceCard`, `EventTimeline`. Each has a `.d.ts` (props), a `.prompt.md`
(usage), and a card demoing its states.

### UI kit

`soc-console` — a faithful, interactive recreation of the FireWatch v2 console composed from
the components above. Pick a source (or All) in the header and watch health dots; switch
tabs; click any IP for the drill-down (now with a **cross-source correlated event timeline**);
filter logs with the combobox **filter bar + removable chips** across Source / Category /
Action / Severity; configure ingest **source cards** in Settings; flip the theme.

---

## Using this system

- Link `styles.css` and read components from `window.FireWatchSOCDesignSystem_f0469e`.
- Build on dark by default (`<html data-theme="dark">`); test light for presentation output.
- Reach for tokens (`var(--fw-*)`) over raw hex; reuse functional hues *by meaning*.
- Keep data monospace, keep emoji as the icon system, keep panels flat and bordered.

## Caveats / substitutions

- **Fonts:** the product ships the system stack (Segoe UI / system-ui) with a monospace stack
  for data — there are **no bundled webfont files**, so none are included here. If you want a
  pinned brand mono (e.g. for cross-platform consistency), supply the font files and we'll add
  the `@font-face` rules.
- The original `dashboard.html` (`v2/pipeline-architecture`) is a live tool (Leaflet, Chart.js,
  FastAPI fetches) and is not vendored here; see the GitHub repo to run it. The kit's Analytics
  tab (Leaflet geo-map + Chart.js donut/bar) is omitted from this static recreation — it needs
  live data.
- **Source data is illustrative.** The multi-source kit fabricates Suricata signatures, syslog
  lines, dest ports and severities to demonstrate the v2 components; wire to the real pipeline
  for production.
