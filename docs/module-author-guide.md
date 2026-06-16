# Module Author Guide — Writing a FireWatch Source Plugin (current state → North Star)

**Status:** DRAFT for Maintainer's review (no ADR Accepted; no issues filed). Pairs with
`PLUGIN_CONTRACT.md` (the normative interface), ADR-0024 (legacy = feature/UX oracle only),
ADR-0025 (DB contract), and the `firewatch-plugin-author` + `canonical-schema` skills.

> **North Star (the keystone — ADR-0018 product positioning, the modularity non-negotiable):**
> a contributor writes **ONLY a plugin package** — a backend `normalize()` + `config_schema()`
> + a Pull or Push collector — and gets, **for free and with zero further work:** a Settings UI
> card, source-scoped DB access, dashboard/log views, correlation, supervised lifecycle, and
> golden-test scaffolding. **Zero frontend code. Zero DDL. Zero core edits.** If a source author
> ever has to touch the React app, the core schema, or `firewatch-core`, the contract has leaked
> and that is a bug in the platform, not the plugin.

This guide is the contributor-DX spec: what a plugin must do **today**, what the **target** looks
like, and exactly which infrastructure pieces must exist for "backend-only, UI/DB-free" to be true.

---

## 1. What a source plugin IS (unchanged, normative)

A plugin packages ONE telemetry source **type** under `packages/sources/<type>/`, registered on
the `firewatch.sources` entry point, discovered with **zero core edits**. The user runs N named
**instances** of it, each with its own config and `source_id` (ADR-0016). It depends on
`firewatch-sdk` **only** — never `firewatch-core`, never `legacy/`.

The plugin provides exactly five methods (PLUGIN_CONTRACT.md):

```python
def metadata(self) -> SourceMetadata: ...        # type_key, display_name, version, flavor
def config_schema(self) -> type[BaseModel]: ...  # Pydantic model → drives the UI card
def validate_config(self, cfg: dict) -> None: ...
def normalize(self, raw: RawEvent, source_id: str) -> SecurityEvent: ...  # the plugin OWNS this
async def health_check(self, cfg: BaseModel) -> bool: ...
```

…plus a flavor: `PullSource.collect(cfg, since)` (watermark-driven) or
`PushSource.start(cfg, emit)`/`stop()` (listener).

---

## 2. Current state — what a contributor must do TODAY (from the Suricata reference)

Measured against `packages/sources/suricata/` (the canonical PullSource). Today a contributor
hand-writes **all** of the following:

| Concern | What the author writes today | Reference |
|---|---|---|
| Package skeleton | `pyproject.toml` (deps = `firewatch-sdk` only), `src/firewatch_<type>/` layout, the `[project.entry-points."firewatch.sources"]` line, a `tests/` dir | `suricata/pyproject.toml` |
| Plugin class | `plugin.py` implementing the 5 methods + the flavor; `_VERSION`, `_TYPE_KEY` constants | `suricata/.../plugin.py` |
| Config schema | `config.py`: a Pydantic model with `title`/`description`, `SecretStr` for secrets, **and hand-written JSON-Schema `if/then/else`** via `json_schema_extra` for any conditional fields; **plus a hand-written `build_config()` env>file>default resolver and a per-field `_ENV_MAP`** | `suricata/.../config.py` |
| Collector | `collector.py`: the actual pull/push I/O, cancellable, never raises out of its loop | `suricata/.../collector.py` |
| Normalizer | `normalize.py`: raw → `SecurityEvent`, setting action/severity/category/rule ids + MITRE/CAPEC + OCSF, all **looked up by hand** | `suricata/.../normalize.py` |
| Golden tests | record sample vendor logs, hand-assert the expected `SecurityEvent` fields | `suricata/tests/` + `tests/golden` |

**Where today's DX is heavier than the North Star (the gaps to close):**

1. **Boilerplate is copied by hand.** The package skeleton, entry-point wiring, the `_ENV_MAP` +
   `build_config()` env>file>default resolver, and the test layout are all re-typed per source. The
   `build_config()`/`_ENV_MAP` pattern in Suricata is ~70 lines that every plugin would otherwise
   duplicate.
2. **`if/then/else` is raw JSON Schema by hand.** Authors must know rjsf's conditional schema shape
   and inject it via `json_schema_extra` — easy to get subtly wrong, untested until the UI renders.
3. **`normalize()` mapping tables are written from scratch.** Each author re-derives rule-ID →
   (category, MITRE technique/tactic, CAPEC, severity, OCSF class) and the action-vocabulary
   mapping. This is exactly where legacy went wrong (the Azure 68%-"Other" fall-through and the
   `Detected/Matched→BLOCK` collapse, `docs/research/azure-waf-log-standard.md` §3). There is no
   shared kit, so every author can reproduce those mistakes.
4. **No discovery endpoint yet.** Even though the loader (`firewatch_core/loader.py`) discovers
   plugins and each plugin can emit `config_schema().model_json_schema()`, **nothing exposes that
   over HTTP**, so a UI cannot yet render a card per installed plugin. This is the single missing
   seam between "backend plugin exists" and "Settings card appears for free."
5. **No source-scoped KV yet.** Auxiliary state has only the specific `*_rule_descriptions`
   helpers; the generic `source_kv_*` surface (ADR-0025) is not on the `EventStore` protocol yet.
6. **No scaffold tool.** Starting a source is "copy the Suricata package and rename everything."

---

## 3. The North Star target — what "backend-only" requires (the contract made real)

For the North Star to be true, the platform — not the author — must provide each of these. This
list **is** the acceptance set for the "base infrastructure" milestone.

### 3a. Settings UI for free — a discovery endpoint + schema-driven card

- **Discovery endpoint (NEW core/API):** `GET /sources/types` returns, for each **installed**
  plugin: `type_key`, `display_name`, `version`, `flavor`, and `config_schema` as JSON Schema
  (`config_schema().model_json_schema()`). The loader already builds the registry; this exposes it.
- **Module-aware UI (NEW frontend, ADR-0019/0010):** the React app fetches `GET /sources/types`
  and renders **one rjsf Settings card per installed plugin**, from that plugin's JSON Schema. **If
  a source package is not installed, NONE of its settings/UI appear** — no source is ever hardcoded
  in the frontend. The Suricata `if/then/else` and `SecretStr`→password widget must round-trip
  through this path. This is the schema-driven bet of ADR-0010/0019 made literal: a new source's
  card is *generated*, not coded.

### 3b. DB access for free — the source-scoped KV surface (ADR-0025)

- `EventStore` gains `source_kv_put/get/get_all(namespace, key, value)` with `source_type` injected
  by core. The author calls the SDK; never writes DDL; never opens a connection. Rule descriptions,
  signature catalogs, and richer-than-watermark cursors all use this.

### 3c. Lifecycle + correlation for free (already specified)

- The supervisor (ADR-0023 / #NNN) runs pull intervals and push listeners, isolates crashes, backs
  off, shuts down gracefully. Correlation keys on `source_type` automatically (PLUGIN_CONTRACT.md).
  The author writes a cancellable `collect()`/listener and gets all of this.

### 3d. Config resolution for free — a config service (NEW, 12-Factor III)

- The hand-written `build_config()`/`_ENV_MAP` per plugin is replaced by a **config service** that
  resolves env>file>default (ADR-0006) generically from the plugin's `config_schema()` field names,
  persists per-source config, validates against the schema, and is hot-reloadable by the supervisor.
  The author declares the schema; the service does resolution. (This removes the ~70-line
  `build_config` boilerplate from every future plugin.)

### 3e. A runtime entrypoint for free

- A CLI (`firewatch run` supervised loop, `firewatch sync --once`, `firewatch serve` for the API)
  loads plugins via entry points and wires them to the store/config/supervisor. The author ships a
  package; the runtime finds and runs it.

---

## 4. Concrete DX simplification proposals (the work that makes §3 real for authors)

These are **proposals for Maintainer**, not decided. 

### P1 — Scaffold tool: `firewatch new-source <name>`
Generate a ready-to-edit package: `packages/sources/<name>/` with `pyproject.toml` (deps =
`firewatch-sdk` only) + the entry-point line, a `plugin.py` stub implementing the 5 methods + a
chosen flavor, a `config.py` stub (a `BaseModel` with `SecretStr`/`if-then-else` examples), a
`normalize.py` stub wired to the mapping kit (P2), and a `tests/` dir pre-seeded with the
golden-test template (P4). Outcome: a contributor goes from `git clone` to "fill in `normalize()`"
in one command, and the boilerplate that today is copied by hand (skeleton, entry point, env
resolver) is generated correct-by-construction. (Compare: `npx @backstage/create-app`,
`cargo generate`, `cookiecutter`.)

### P2 — `normalize()` mapping kit in the SDK (canonical-schema + MITRE/OCSF helpers)
Ship reusable, standards-backed helpers in `firewatch-sdk` so authors do not re-derive — and
cannot re-break — the mappings:
- `categorize_rule(rule_id)` and rule-ID-range → (category, MITRE T-id, TA-id, CAPEC, severity,
  OCSF class) tables for the common corpora (OWASP CRS — the table in
  `docs/research/azure-waf-log-standard.md` §2c; Suricata ET Open `mitre_*`).
- action-vocabulary normalizers (case-fold + map to `ActionLiteral`/`disposition_id`), explicitly
  encoding `Detected`/`Matched`/`AnomalyScoring` → `ALERT` (NOT `BLOCK`) so no plugin reproduces the
  legacy collapse.
- a `severity_from_category(...)` helper so `severity` is never left `None` (the legacy Azure bug).
- OCSF helpers: `ocsf_class`/`category` setters with the **correct** WAF mapping = HTTP Activity
  `4002` / category `4` (NOT the stale `6004`). This kit is where the §5 code fix lands.
Outcome: `normalize()` shrinks to "pull the fields, call the kit," and the kit is unit-tested once.

### P3 — Schema-driven Settings UI + discovery endpoint (§3a)
The `GET /sources/types` endpoint + the rjsf card renderer. Outcome: an installed plugin's card
appears with zero frontend code; an uninstalled plugin contributes nothing to the UI.

### P4 — Golden-test template
A parametrized `tests/golden` harness: drop `fixtures/<type>/<case>.input.json` +
`<case>.expected.json` pairs and the runner feeds them through `normalize()` + the pipeline and
diffs against the **canonical-standard** expectation (ADR-0024 — never recorded from `legacy/`).
Fixtures use RFC 5737 doc IPs (testing-conventions skill). Outcome: a source is "done" when its
fixtures pass, with no per-source test code.

### P5 — Config service + source-scoped KV (§3b/§3d)
The generic env>file>default config service driven by `config_schema()` field names, and the
`source_kv_*` `EventStore` methods (ADR-0025). Outcome: authors delete `build_config()`/`_ENV_MAP`
and never touch the DB.

---

## 5. Required code correction (flagged, not done by the architect)

`packages/firewatch-sdk/src/firewatch_sdk/models.py:79` documents `ocsf_class` as
`# e.g. 6004 = Web Resources Activity`. Per `docs/research/azure-waf-log-standard.md` §2a this is
**stale and wrong for WAF**: the released OCSF web class is 6001 (a content-management class), and
the idiomatic 2026 target for a WAF is **OCSF HTTP Activity, `class_uid = 4002`, `category_uid =
4` (Network Activity)**, with the WAF disposition on `disposition_id`. This is the same outdated
mapping the legacy normalizer baked in. **Action:** correct the comment (and any normalizer
examples referencing 6004) when the mapping kit (P2) / Azure plugin lands. Small follow-up code
issue; the architect does not write code.

---

## 6. The "done" checklist for a source author (target state)

A source is complete when:
- [ ] entry point registered; discovered by the loader with zero core edits;
- [ ] `normalize()` emits a standards-correct `SecurityEvent` (action ADR-0012, severity never
      `None`, MITRE/CAPEC ADR-0014, OCSF ADR-0020) — using the mapping kit (P2) where applicable;
- [ ] `config_schema()` renders an rjsf card via the discovery endpoint; secrets are `SecretStr`;
      env>file>default honored by the config service (no hand-written resolver);
- [ ] auxiliary state (if any) uses `source_kv_*` — no DDL, no DB connection (ADR-0025);
- [ ] golden fixtures pass against the **canonical-standard** expectation (never recorded from
      `legacy/`; RFC 5737 doc IPs);
- [ ] `collect()`/listener is cancellable and never raises out of its loop;
- [ ] `security-reviewer`: no blocking findings (payloads delimited if they reach the LLM).
