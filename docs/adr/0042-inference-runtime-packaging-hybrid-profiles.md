# ADR-0042: Inference Runtime Packaging — Hybrid Compose Profiles (Ollama Default, llama.cpp Lean)

**Date:** June 2026 (accepted 2026-06-12)
**Status:** Accepted (complements ADR-0022 — the runtime-packaging counterpart to its interface decision)

**Decision:** The inference *runtime* is a **packaging choice, operator-selectable at deploy
time** — never a code seam. FireWatch ships **two docker-compose profiles** over the one stable
interface ADR-0022 pinned (the local OpenAI-compatible `/v1` endpoint):

- **`default` — FireWatch + Ollama.** Today's recommended path, unchanged: best model UX
  (`ollama pull`/list, hot-swap, GPU auto-detect). Stays the default per ADR-0022.
- **`lean` — FireWatch + llama.cpp `llama-server`** with an operator-supplied pre-quantized GGUF
  mounted as a volume (model never baked into the image — keeps it swappable and the image
  redistributable). Target ~100–200 MB runtime image (vs Ollama's ~3.2 GB official image — ~95%
  smaller) for the small-footprint/air-gapped story; llama.cpp also runs 10–30% faster CPU-only
  on 3B-class GGUFs (Ollama wraps llama.cpp, so the wrapper overhead is pure cost there).
- **Profile selection changes only compose wiring + the `base_url` config** — zero changes to
  `firewatch_core/adapters/ai_openai.py`, prompts, or engine selection. Both runtimes expose `/v1`
  natively; ADR-0022's loopback/LAN `base_url` validation applies to both (no cloud egress either
  way).
- A documented **pipx path** covers bare-metal (FireWatch only; operator brings a local `/v1`
  endpoint). Install-path details fold into `docs/pre-release-checklist.md` — deliberately **no
  separate install ADR**.

**Alternatives considered:**
- **Switch the default to llama.cpp (smallest footprint everywhere)** — rejected: drops Ollama's
  model library/auto-versioning/hot-swap/GPU auto-detect, which is real UX for the dev/POC boxes
  that are most first installs. The lean profile serves the appliance case without taxing everyone
  else.
- **Ollama-only (status quo packaging)** — rejected: leaves ~3 GB of runtime image plus
  registry-pull friction in the air-gapped/minimal story, when a `/v1`-identical runtime exists at
  ~5% of the size.
- **llamafile (single-file runtime+model)** — rejected: bundling the model into the binary fights
  the operator-supplied-GGUF modularity; right for "ship one fixed model," wrong for "drop in your
  own."
- **mistral.rs** — monitor: clean Rust `/v1` server, CPU-first, auto-tuning — but smaller community
  and less battle-tested than llama.cpp; revisit if it matures.
- **vLLM / TGI as the lean runtime** — rejected for this niche: GPU-first with no real CPU story
  (TGI in maintenance since Dec 2025); vLLM remains the *throughput* swap ADR-0022 already allows.
- **A runtime-selection seam in code (adapter per runtime)** — rejected: re-litigates ADR-0022;
  `/v1` is the seam, so runtime choice belongs in deployment artifacts, not source.

**Reasoning:** ADR-0022 deliberately reduced the engine contract to "a local OpenAI-compatible
endpoint" — which makes the runtime swappable *by construction*; this ADR just exploits that at the
packaging layer where the footprint problem actually lives. The hybrid keeps both honest claims at
once: friendly one-command default, and a genuinely small air-gapped profile (the GGUF loads from
disk; llama.cpp needs no registry). Research with measurements and field survey:
`scratch/improvement_ideas_inference_runtime_2026-06-12.md` (sources: llama.cpp server README +
releases, Ollama Docker Hub, Red Hat vLLM-vs-llama.cpp). Maintainer's note: the lean profile is
low-priority/testable-later — ship it as the optional profile; don't block the milestone on deep
llama.cpp validation.

**Consequences:**
- MI-3 (#384) implements: `deploy/docker-compose.yml` (profiles), `deploy/Dockerfile` (app image,
  uv multi-stage), `deploy/lean/Dockerfile.llamacpp`, `deploy/README.md`; MI-2 (#383) benchmarks
  both profiles; MI-4 (#385) documents the offline model-copy flow.
- Any model/format quirk found under llama.cpp is recorded per ADR-0022's consequence
  (re-validate `ai-engine-invariants` quirks against the runtime), not patched ad hoc.
- The pre-release checklist gains the install-path items; no separate install ADR exists or is
  planned.
