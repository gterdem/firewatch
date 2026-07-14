---
name: firewatch-plugin-author
description: How to build a FireWatch telemetry source plugin against PLUGIN_CONTRACT.md — pull vs push flavors, normalize(), config schema, entry-point registration. Use whenever creating or modifying anything under packages/sources/.
---
# Building a source plugin

A plugin packages ONE source TYPE (suricata, azure_waf, …) under `packages/sources/<type>/`,
auto-discovered via entry points — **zero edits to firewatch-core**. The user runs N named
INSTANCES of it, each with its own config + `source_id`. (ADR-0016)

## Pick a flavor (ADR-0005)
- **PullSource**: `async collect(cfg, since) -> AsyncIterator[RawEvent]` (Suricata SSH, Azure)
- **PushSource**: `async start(cfg, emit)` / `async stop()` (Syslog listener)

## Local-first (endpoint sources — settled principle, D3)
An endpoint source (ClamAV, Linux auth, …) MUST collect from the machine FireWatch runs on by
default — a self-sufficient Solo install with zero network config. Remote transports (rsyslog/
shipper push, SSH pull) are additive extensions, each scoped explicitly in its issue's acceptance
criteria. Read local logs **journald-first** via the shared SDK readers (portable across Arch,
Ubuntu, Fedora, Debian), with plain file-tail as the fallback — never require per-distro paths or
ask the user to install a forwarder just to read their own machine.

## Implement (exact signatures in PLUGIN_CONTRACT.md)
`metadata()` · `config_schema()` · `validate_config()` · `normalize(raw, source_id)` · `health_check()`

## normalize() owns the mapping (load the canonical-schema skill)
Emit a valid SecurityEvent: action mapping (ALERT vs BLOCK), severity, category, rule ids,
`source_type`+`source_id`, and MITRE/CAPEC where derivable.

## Steps
1. `packages/sources/<type>/` with its own `pyproject.toml` + the `firewatch.sources` entry point.
2. `config_schema` = Pydantic model; resolved **env > file > default** (ADR-0006). Secret *values*
   (tokens, passwords, key material) = `SecretStr`; file *paths* (e.g. an SSH key path) are
   identifiers, not secrets — plain `str`.
3. Golden tests: sample vendor logs → expected SecurityEvents (`tests/baseline` pattern).

## Hard rules
- Import `firewatch_sdk` ONLY. Never `firewatch_core`.
- `collect()` / the listener must be cancellable and must not raise out of their loop.
- Do NOT modify PLUGIN_CONTRACT.md. If it seems necessary, stop and raise a `contract-change` issue.

## Reference
`packages/sources/suricata/` — the canonical PullSource.
