## Summary

<!-- What does this PR change and why? Link the issue: Closes #NNN -->

## Type of change

- [ ] Source plugin (new package under `packages/sources/`, **zero core edits**)
- [ ] Core / SDK
- [ ] UI (frontend)
- [ ] Docs / governance

## Checklist

- [ ] One issue → one branch → one PR
- [ ] `uv run ruff check .` clean
- [ ] `uv run pyright` clean
- [ ] `uv run pytest` green (including the `tests/golden` regression oracle)
- [ ] Frontend (if touched): `scripts/gates-frontend.sh` green
- [ ] Data-plane / API / external-call change: security review requested
- [ ] New/changed source plugin: `normalize()` golden test + mocked-collector test added
- [ ] Modularity preserved — core imports no plugin; plugin imports no core
- [ ] `PROGRESS.md` / relevant docs updated
