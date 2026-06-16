# FireWatch Footprint Benchmark — 2026-06-12

Measures both MI-3 compose profiles (`default` = Ollama, `lean` = llama.cpp
`llama-server`) on a single reference host.  Every number in this document is
a real measured result from a live run on the hardware below.

**Governing rule (MI-2):** numbers that could not be measured are labelled
`NOT MEASURED — <reason>`.  No estimates or third-party figures are used.

Re-run script: `scripts/benchmark/footprint.sh [--profile default|lean]`

---

## Reference hardware

| Field | Value |
|---|---|
| CPU | AMD Ryzen 7 9800X3D 8-Core Processor |
| Physical cores | 8 (16 logical / hyperthreaded) |
| Total RAM | 31 GiB |
| GPU | NVIDIA GeForce RTX 4090 (24 GiB VRAM) — **not used**; inference runs CPU-only |
| OS | WSL2 / Linux 6.6.87.2-microsoft-standard-WSL2 |
| Platform | Linux x86-64, CPU-only inference (Docker in WSL2) |
| Docker | 29.1.3 |
| Docker Compose | v2.27.0 |
| Benchmark date | 2026-06-12 |
| Benchmark script | `scripts/benchmark/footprint.sh` |

> The RTX 4090 is present on this host but Docker containers run without
> `--gpus all` in these profiles (CPU-only is the air-gapped one-box story).

---

## Container image sizes

Measured with `docker image inspect <image> --format '{{.Size}}'` (bytes) and
`docker images` (human-readable).

| Image | Bytes (uncompressed) | Human-readable | Notes |
|---|---|---|---|
| `firewatch:latest` | 203,396,175 | 203 MB | FireWatch app (Python + uv venv) |
| `firewatch-nginx:latest` | 49,636,844 | 49.6 MB | nginx SPA + reverse-proxy sidecar |
| `ollama/ollama:0.30.8` | 4,863,878,510 | 4.86 GB | Ollama inference runtime (pinned tag) |
| `firewatch-lean:latest` (Alpine, broken) | 20,510,489 | **20.5 MB** | Defective — binary runs on Alpine (musl) but fails at runtime; see lean image note |
| `firewatch-lean:latest` (Debian slim, fixed — issue #NNN) | 97,122,277 | **97.1 MB** | Runnable — debian:bookworm-slim + all required .so files (measured 2026-06-13) |

### lean image note

**Update (2026-06-13, issue #NNN fixed):** `deploy/lean/Dockerfile.llamacpp`
has been updated to `debian:bookworm-slim` (glibc) + all five required shared
libraries (`libllama.so`, `libggml.so`, `libggml-base.so`, `libggml-cpu.so`,
`libggml-rpc.so`).  The fixed image is **97.1 MB** (97,122,277 bytes
uncompressed) and passes `ldd` + `llama-server --version` and binds port 8080.

**Original finding (recorded at benchmark time, 2026-06-12):** the production
lean image at the time of this benchmark run (`firewatch-lean:latest`, 20.5 MB)
was built from an Alpine base and shipped only the `llama-server` ELF binary.
The binary is **dynamically linked to glibc** (ELF interpreter
`/lib64/ld-linux-x86-64.so.2`) and required shared libraries (`libggml*.so`,
`libllama.so`) that were not bundled in the image.  The binary could not run on
Alpine musl libc and failed with
`exec /usr/local/bin/llama-server: no such file or directory`.

This was a defect in `deploy/lean/Dockerfile.llamacpp`: the `install` command
copied only `llama-server` but not its sibling `.so` files from the release ZIP.

**Impact on this benchmark:** the 20.5 MB image-size figure was real and
correct — the image built successfully.  The runtime (RSS, CPU, verdict
timing) was measured using a benchmark-only corrected image
(`firewatch-lean-bench:benchmark`, Ubuntu 22.04 base, ~92.7 MB) that included
all required shared libraries.  Runtime numbers below remain labelled with that
benchmark image; re-run the benchmark with the fixed production image to update.

---

## default profile — FireWatch + Ollama

### Stack composition

| Service | Image |
|---|---|
| `firewatch` | `firewatch:latest` |
| `nginx` | `firewatch-nginx:latest` |
| `ollama` | `ollama/ollama:0.30.8` |

All services started via:
```bash
docker compose -p fwbench -f deploy/docker-compose.yml --profile default up -d
```
Host port: 19999 (non-conflicting; production stacks use 8080).

### Model

`qwen2.5:3b` — pulled via `docker compose exec ollama ollama pull qwen2.5:3b`.
Stored in the `fwbench_ollama_models` named volume.

### Idle RSS (model not yet loaded into runtime memory)

Measured with `docker stats --no-stream` approximately 5 s after all containers
became healthy, before any inference call was made.

| Container | RSS (docker stats) | Notes |
|---|---|---|
| `fwbench-firewatch-1` | 71.8 MiB | FastAPI app at rest |
| `fwbench-ollama-1` | 109 MiB | Ollama daemon, no model loaded |
| `fwbench-nginx-1` | 3.6 MiB | nginx SPA + proxy |
| **Total (default, no model)** | **~185 MiB** | |

### Idle RSS (model resident in runtime memory, after first inference call)

After the first `analyze_ip_detailed` call completes, qwen2.5:3b remains
resident in Ollama's model cache.

| Container | RSS (docker stats) | Notes |
|---|---|---|
| `fwbench-firewatch-1` | 94.2 MiB | Steady post-first-call |
| `fwbench-ollama-1` | 2.25 GiB | qwen2.5:3b (Q4, ~1.9 GB) resident |
| `fwbench-nginx-1` | 3.0 MiB | |
| **Total (default, model resident)** | **~2.35 GiB** | |

### Active RSS + CPU during scoring

Captured mid-inference (2 s into a subsequent `analyze_ip_detailed` call).

| Container | RSS | CPU % | Notes |
|---|---|---|---|
| `fwbench-firewatch-1` | 95.9 MiB | 3.6% | HTTP + Python pipeline |
| `fwbench-ollama-1` | 2.25 GiB | **643–748%** | CPU-only inference, all 16 vCPUs |
| `fwbench-nginx-1` | 3.0 MiB | 0% | |

> CPU% > 100 is expected: `docker stats` reports across all cores.
> 643–748% / 16 logical cores ≈ 40–47% average per-core utilisation.

### Disk usage (model store + app data)

| Store | Size | Notes |
|---|---|---|
| `fwbench_ollama_models` volume | **1.8 GiB** | qwen2.5:3b after pull |
| `fwbench_fw_data` volume | 680 KiB | SQLite + config (after test ingest) |

### Time-to-verdict (`analyze_ip_detailed`, qwen2.5:3b, CPU-only)

Each call ingests 5 SSH brute-force syslog events for `192.0.2.100` and
requests a full AI-annotated threat assessment via
`GET /threats/192.0.2.100/detailed?ai=true`.

Wall-clock measured with `date +%s%N` around the HTTP call from inside the
container.

| Call | Wall-clock (ms) | Notes |
|---|---|---|
| Call 1 (model cold-load into Ollama) | **14,905 ms** | Model loaded from volume into RAM |
| Call 2 (model resident) | **12,562 ms** | |
| Call 3 (model resident) | **16,483 ms** | |
| Call 4 (model resident) | **17,374 ms** | |
| Call 5 (model resident) | **18,373 ms** | |
| **Median (resident)** | **~16,500 ms** | ~16 s per verdict, CPU-only |

> Variance is typical for CPU-only inference at 3B token context.
> All calls return a non-empty `executive_summary`, `score`, and `confidence=1.0`.

---

## lean profile — FireWatch + llama.cpp

### Stack composition

| Service | Image |
|---|---|
| `firewatch` | `firewatch:latest` |
| `nginx` | `firewatch-nginx:latest` |
| `llama` | `firewatch-lean-bench:benchmark` (benchmark-only; see image note above) |

Started via:
```bash
docker compose -p fwbenchlean -f deploy/docker-compose.yml \
  -f <lean-override.yml> --profile lean up -d
```
Host port: 19998.  GGUF bind-mounted from `/tmp/fw_models/qwen2.5-3b-instruct-q4_k_m.gguf`.

### Model

`qwen2.5-3b-instruct-q4_k_m.gguf` — downloaded from
`Qwen/Qwen2.5-3B-Instruct-GGUF` on Hugging Face.
File size: **2.0 GiB** (2,104,932,768 bytes).
Bind-mounted at `/models/qwen2.5-3b-instruct-q4_k_m.gguf` inside the container.

This is the quantisation-equivalent of the Ollama `qwen2.5:3b` model used in
the default profile.  Ollama stores the same model as **1.8 GiB** inside its
volume (slightly smaller due to manifest/layer overhead differences).

### Idle RSS (model not yet loaded — server started, model not yet requested)

| Container | RSS (docker stats) | Notes |
|---|---|---|
| `fwbenchlean-firewatch-1` | 59.4 MiB | FastAPI app at rest |
| `fwbenchlean-llama-1` | 1.46 GiB | llama-server: model pre-loaded at start |
| `fwbenchlean-nginx-1` | 2.9 MiB | |
| **Total (lean, server started)** | **~1.52 GiB** | Model loaded at server start |

> llama-server loads the model into memory during startup (before any request),
> which explains the 1.46 GiB idle RSS.  Ollama, by contrast, loads the model
> lazily on first request — hence the Ollama idle RSS without model is only ~109 MiB.

### Idle RSS (model resident — same as above; model is always resident after start)

| Container | RSS (docker stats) | Notes |
|---|---|---|
| `fwbenchlean-firewatch-1` | 65.1 MiB | |
| `fwbenchlean-llama-1` | 1.56 GiB | After first inference call |
| `fwbenchlean-nginx-1` | 3.0 MiB | |
| **Total (lean, model resident)** | **~1.63 GiB** | |

### Active RSS + CPU during scoring

Captured mid-inference (2 s into a `analyze_ip_detailed` call).

| Container | RSS | CPU % | Notes |
|---|---|---|---|
| `fwbenchlean-firewatch-1` | 65.5 MiB | 0.19% | |
| `fwbenchlean-llama-1` | 1.52 GiB | **1,503%** | CPU-only; all 16 vCPUs |
| `fwbenchlean-nginx-1` | 3.0 MiB | 0% | |

> 1,503% / 16 logical cores ≈ 94% average per-core utilisation.
> llama-server uses OpenMP threading aggressively across all available cores.

### Disk usage

| Store | Size | Notes |
|---|---|---|
| Operator GGUF (host bind-mount) | **2.0 GiB** | qwen2.5-3b-instruct-q4_k_m.gguf |
| `fwbenchlean_fw_data` volume | 364 KiB | SQLite + config |

The GGUF is a bind-mount from the host, not a named Docker volume.
Operators place the file wherever suits their system (e.g. `/opt/models/`).

### Time-to-verdict (`analyze_ip_detailed`, qwen2.5:3b Q4_K_M, CPU-only)

| Call | Wall-clock (ms) | Notes |
|---|---|---|
| Call 1 (first request after server start) | **21,658 ms** | Server already loaded model at startup |
| Call 2 | **25,636 ms** | |
| Call 3 | **17,789 ms** | |
| Call 4 | **19,955 ms** | |
| **Median** | **~21,000 ms** | ~21 s per verdict, CPU-only |

---

## Profile comparison (lean vs default)

| Metric | default (Ollama) | lean (llama.cpp) | Delta |
|---|---|---|---|
| **Inference image size (production, fixed — #NNN)** | 4.86 GB (ollama:0.30.8) | **97.1 MB** (debian:bookworm-slim + .so files) | **−98.0%** |
| **Inference image size (broken original)** | 4.86 GB | 20.5 MB (Alpine, did not run) | record only — not runnable |
| **Inference image size (benchmark image)** | 4.86 GB | **92.7 MB** (Ubuntu+libs) | benchmark-only; runtime numbers measured here |
| **Idle RSS (no model)** | ~185 MiB | ~1.52 GiB (model pre-loaded) | lean higher; different load semantics |
| **Idle RSS (model resident)** | ~2.35 GiB | ~1.63 GiB | **−30.6%** |
| **Active RSS (inference)** | ~2.35 GiB | ~1.52 GiB | **−35.3%** |
| **Active CPU** | 643–748% (16 vCPUs) | 1,503% (16 vCPUs) | lean uses +80–100% more CPU |
| **Model disk (qwen2.5:3b Q4)** | 1.8 GiB (Ollama volume) | 2.0 GiB (GGUF file) | lean +200 MiB (format overhead) |
| **Median time-to-verdict** | ~16,500 ms | ~21,000 ms | lean +27% slower |
| **Total stack size (images)** | 5.11 GB | 342 MB (bench image) | lean **−93.3%** |

### Key observations

1. **Image size**: the fixed production lean image (debian:bookworm-slim +
   required .so files, issue #NNN) is **97.1 MB** — still ~98% smaller than
   Ollama's 4.86 GB.  The original 20.5 MB Alpine image built but could not run
   (missing glibc + .so files); it is superseded by the fixed image.  The
   benchmark runtime numbers used the Ubuntu 22.04 corrected image (92.7 MB);
   re-run the benchmark script against the new production image for updated
   runtime figures.

2. **Memory**: lean uses **less RAM overall when the model is loaded** (~1.6 GiB
   vs ~2.35 GiB) because llama-server has lower runtime overhead than Ollama.
   However, lean preloads the model at startup, while Ollama loads lazily on
   first request — the "idle RSS before any request" comparison is misleading
   for lean.

3. **CPU throughput**: lean uses more CPU per verdict (+80–100%) on this
   CPU-only configuration.  The scratch research document predicted
   "+10–30% faster" for llama.cpp vs Ollama; the measured results show the
   opposite — lean is ~27% *slower* per verdict at this context size on a
   Ryzen 7 9800X3D.  This contradicts the scratch doc's claim and underscores
   the MI-2 mandate to measure rather than rely on third-party benchmarks.
   Possible factors: Ollama's internal llama.cpp version may be newer/better
   optimised; thread-count tuning differs; BLAS library differences.

4. **Lean runtime defect (fixed — issue #NNN)**: the original production
   `deploy/lean/Dockerfile.llamacpp` did not include the shared libraries the
   binary requires.  Fixed in PR for issue #NNN: the Dockerfile now uses
   `debian:bookworm-slim` (glibc-compatible) and copies all five required .so
   files (`libllama.so`, `libggml*.so`).  The fixed image is 97.1 MB and passes
   `ldd` + runtime startup verification.

---

## Measurement methodology

- Containers brought up with `docker compose -p fwbench* ... up -d` using a
  non-conflicting host port (19999/19998) and isolated project name.
- Image sizes: `docker image inspect --format '{{.Size}}'` (uncompressed
  on-disk bytes, not compressed registry size).
- RSS: `docker stats --no-stream` (Linux cgroup `memory.usage_in_bytes` via
  the Docker stats API).  These include all memory mapped by the process
  including shared pages; they are not `RssAnon` (private pages only).
- CPU%: `docker stats --no-stream` during an active inference call.  Units are
  percentage of a single core; >100% indicates multi-core usage.
- Time-to-verdict: `date +%s%N` wall-clock around
  `curl GET /threats/192.0.2.100/detailed?ai=true` inside the container.
  Includes HTTP latency, prompt formatting, LLM inference, and JSON parsing.
- Disk: `du -sh` from inside the container for named volumes;
  `du -sh <path>` on the host for the GGUF bind-mount.
- Test workload: 5 SSH brute-force syslog events for `192.0.2.100`
  (RFC 5737 documentation IP — never a real/public address).

---

## Re-running this benchmark

```bash
# Default profile (requires ollama/ollama:0.30.8 image pulled):
./scripts/benchmark/footprint.sh --profile default

# Lean profile (requires a GGUF file):
./scripts/benchmark/footprint.sh --profile lean \
  --gguf /path/to/qwen2.5-3b-instruct-q4_k_m.gguf

# Skip AI timing (image/idle-only, faster):
./scripts/benchmark/footprint.sh --profile default --skip-ai-timing
```

Output: `docs/benchmarks/footprint-<date>-<profile>.md` and `.json`.
The script tears down all containers and volumes on exit.

---

## NOT MEASURED items

| Item | Reason |
|---|---|
| GPU-accelerated inference RSS/timing | Docker containers run without `--gpus all`; CPU-only is the one-box story |
| lean production image runtime (RSS/timing re-run) | Defect fixed (issue #NNN); re-run `scripts/benchmark/footprint.sh --profile lean --gguf <path>` against the fixed production image to update runtime numbers in this doc |
| Compressed registry image sizes | Not measured; uncompressed on-disk sizes reported |
| Multi-user / concurrency throughput | Out of scope per MI-2 (concurrency/load testing excluded) |

---

*MI-2 — Measured footprint benchmark, both inference profiles.*
*Feeds MI-8 (launch copy claims checklist).*
