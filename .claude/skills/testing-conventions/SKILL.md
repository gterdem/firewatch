---
name: testing-conventions
description: What "done" means and how to write tests in FireWatch — normalization golden tests, the AI prompt-baseline oracle, and mocked-SSH collector tests. Use before marking any task complete or touching the AI path.
---
# Testing conventions

## "Done" gate
`ruff check . && pyright && pytest` ALL green (incl. golden), AND security-reviewer raises no
blocking finding. Tests are written FIRST, against the issue's acceptance criteria.

## Test fixtures: IPs & PII (gitleaks gate)
Fixtures MUST use non-routable / documentation IPs — never a real, routable IP. The
`public-ipv4` rule in `.gitleaks.toml` flags any routable IPv4 as possible real source/attacker
PII and the CI `scan` job (`gitleaks git`, full history) fails on it. Allowed ranges (already
whitelisted): RFC 5737 docs `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`; plus
private/loopback `10/8`, `172.16/12`, `192.168/16`, `127/8`. Prefer `192.0.2.1` as the default
example IP. Because the gate scans *history*, a fix-on-top is not enough — amend the offending
commit so the IP never appears, then force-push. The pre-commit hook catches this locally first
(`scripts/setup-hooks.sh` wires the relative `core.hooksPath=.githooks`, which covers every
worktree); run it once per clone.

## Normalization golden tests
Per source: sample vendor logs → expected SecurityEvents (fields incl. action, severity,
category, MITRE/CAPEC). These are the regression oracle: the same input logs always produce the same SecurityEvents.

## AI prompt-baseline oracle (no Ollama, ~20ms)
The AI path is protected by prompt-baseline tests:
```bash
python -m tests.test_ai_prompt --save      # capture current prompt as baseline
python -m tests.test_ai_prompt --compare   # fail if the generated prompt changed
```
Any change to prompts or sample-building MUST keep `--compare` green, or be an INTENTIONAL
rebaseline noted in the PR. (See the `ai-engine-invariants` skill.)

## Collector tests
Mocked SSH (no real host): `tests/adapters/test_suricata_remote.py` is the pattern for pull collectors.
