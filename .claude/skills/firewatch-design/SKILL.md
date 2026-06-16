---
name: firewatch-design
description: Use this skill to generate well-branded interfaces and assets for FireWatch AI (a dark, data-dense, multi-source SOC / WAF+IDS log-analysis console), either for production or throwaway prototypes/mocks/etc. Contains essential design guidelines, colors, type, fonts, assets, and UI kit components for prototyping.
user-invocable: true
---

Read the README.md file within this skill, and explore the other available files.
If creating visual artifacts (slides, mocks, throwaway prototypes, etc), copy assets out and create static HTML files for the user to view. If working on production code, you can copy assets and read the rules here to become an expert in designing with this brand.
If the user invokes this skill without any other guidance, ask them what they want to build or design, ask some questions, and act as an expert designer who outputs HTML artifacts _or_ production code, depending on the need.

Key things to honor for FireWatch:
- Dark-first. Default theme is navy-black `#0a0e17`; light theme is for projectors only.
- One amber accent (`#f59e0b`) for primary/active state — used sparingly.
- All data (numbers, IPs, rule IDs, timestamps, payloads) is monospace; chrome is the system UI stack.
- Emoji ARE the icon system (🔥 logo, 📊 🛡️ 🌐 🤖 🧠 🎯 …; sources ☁️ WAF 🛰️ IDS 📡 syslog). Do not substitute a stroke-icon library.
- Flat 1px-bordered panels (10px radius, no shadow); shadows only on floating overlays. Tinted uppercase pills for severity/verdict/source — except IDS **ALERT** which is a solid orange chip.
- v2 is **multi-source**: WAF (blue) / Suricata IDS (orange) / syslog (green) / file (purple). Header source filter + health dots; logs carry Source / Dest Port / Severity / Signature; drill-down shows a cross-source correlated event timeline.
- Tokens live in `styles.css` → `tokens/*`. Components mount from `window.FireWatchSOCDesignSystem_f0469e`. The full console recreation is in `ui_kits/soc-console/`.
