# FireWatch — Deploy

One-command Docker install for FireWatch. Two compose profiles are available
(ADR-0042):

| Profile | Inference runtime | Best for |
|---|---|---|
| `default` | [Ollama](https://ollama.com) | First install; best model UX; GPU auto-detect |
| `lean` | [llama.cpp `llama-server`](https://github.com/ggerganov/llama.cpp) | Minimal footprint; air-gapped; operator-supplied GGUF |

Both profiles wire the engine purely via `base_url` config — the FireWatch
source code is identical in both cases (ADR-0022 / ADR-0042).

---

## Prerequisites

- Docker 20+ and Docker Compose v2 (`docker compose version`).
- The `deploy/` directory (this folder) lives inside the cloned repo root.
- Copy `deploy/.env.example` to `deploy/.env` and adjust if needed (the
  defaults work for a local install on port 8080).

```bash
cp deploy/.env.example deploy/.env
```

---

## default profile — FireWatch + Ollama

```bash
# From the repo root:
docker compose -f deploy/docker-compose.yml --profile default up -d
```

The stack comes up in order: Ollama → FireWatch API → nginx.

> **Updating the Ollama version:** the Ollama image is pinned to a specific tag
> in `deploy/docker-compose.yml` (e.g. `ollama/ollama:0.30.8`).  To upgrade,
> check [Docker Hub](https://hub.docker.com/r/ollama/ollama/tags) for the latest
> stable release tag, update the `image:` line, and test with `docker compose
> --profile default up -d` before committing.

### Pull a model (required for AI scoring)

AI scoring starts once a model is available.  Pull a small 3B-class model to
get started quickly:

```bash
docker compose -f deploy/docker-compose.yml --profile default \
    exec ollama ollama pull qwen2.5:3b
```

The model is stored in the `ollama_models` named volume and survives restarts.
You can pull any model that Ollama supports:

```bash
docker compose -f deploy/docker-compose.yml --profile default \
    exec ollama ollama list          # list downloaded models
docker compose -f deploy/docker-compose.yml --profile default \
    exec ollama ollama pull phi4     # pull a different model
```

Update `FIREWATCH_OLLAMA_MODEL` in `.env` and restart `firewatch` to switch:

```bash
# Edit .env: FIREWATCH_OLLAMA_MODEL=phi4
docker compose -f deploy/docker-compose.yml --profile default \
    restart firewatch
```

### Check the stack

```bash
# Dashboard (through nginx):
curl -fsS http://localhost:8080/

# API health (through nginx):
curl -fsS http://localhost:8080/health

# Container status:
docker compose -f deploy/docker-compose.yml --profile default ps
```

### Tear down

```bash
# Stop and remove containers; preserve data volumes:
docker compose -f deploy/docker-compose.yml --profile default down

# Full wipe (removes fw_data and ollama_models volumes):
docker compose -f deploy/docker-compose.yml --profile default down -v
```

---

## lean profile — FireWatch + llama.cpp

The lean profile uses a pre-built `llama-server` binary (~97 MB image,
measured 2026-06-13 — see `docs/benchmarks/footprint-2026-06-12.md`) with no
Ollama dependency.  The model is NEVER baked into the image; you supply a
GGUF file via a bind-mount.

> **Runtime base:** `debian:bookworm-slim` (glibc).  The llama-server binary
> from the llama.cpp release is dynamically linked to glibc — Alpine (musl)
> cannot run it.  The Dockerfile copies all required shared libraries from the
> release ZIP alongside the binary (fix for issue #NNN).

### Step 1 — Obtain a GGUF model

Download a quantized GGUF from
[Hugging Face](https://huggingface.co/models?library=gguf) or convert one
yourself.  A 4-bit-quantized 3B model (~2 GB) is a good starting point.

```bash
# Example: download a Mistral-7B Q4 GGUF (~4 GB)
# (adjust URL for your chosen model)
mkdir -p /opt/models
wget -O /opt/models/mistral-7b-instruct.Q4_K_M.gguf \
    https://huggingface.co/TheBloke/Mistral-7B-Instruct-v0.2-GGUF/resolve/main/mistral-7b-instruct-v0.2.Q4_K_M.gguf
```

**Offline / air-gapped copy flow:** if the host has no internet access, copy
the GGUF from another machine:

```bash
# On the internet-connected machine:
scp /path/to/model.gguf user@airgapped-host:/opt/models/model.gguf

# Or via USB / shared mount — the GGUF is a plain binary file.
```

See MI-4 (`docs/adr/0042-*`) for the full air-gapped documentation (cross-ref
to be added when MI-4 lands).

### Step 2 — Configure .env

```bash
# In deploy/.env:
FIREWATCH_OLLAMA_BASE_URL=http://llama:8080
GGUF_HOST_PATH=/opt/models/mistral-7b-instruct.Q4_K_M.gguf
MODEL_FILE=mistral-7b-instruct.Q4_K_M.gguf
```

### Step 3 — Start the lean stack

> **Version pinning note:** `deploy/lean/Dockerfile.llamacpp` downloads the
> llama.cpp binary at build time and verifies its SHA256 checksum.  If you
> bump `LLAMA_CPP_VERSION`, you **must** update `LLAMA_CPP_SHA256` in the same
> commit.  Compute the new digest with:
> ```bash
> curl -fsSL -L https://github.com/ggml-org/llama.cpp/releases/download/<TAG>/<ASSET>.zip | sha256sum
> ```

```bash
# Build the lean image (only needed on first run or after Dockerfile changes):
docker compose -f deploy/docker-compose.yml --profile lean build llama

# Record the built image size for MI-2:
docker images firewatch-lean

# Start:
docker compose -f deploy/docker-compose.yml --profile lean up -d
```

### Check the stack

```bash
curl -fsS http://localhost:8080/health   # through nginx
curl -fsS http://localhost:8080/         # dashboard
```

### Tear down

```bash
docker compose -f deploy/docker-compose.yml --profile lean down
# Add -v to also remove fw_data volume.
```

---

## Bare-metal (pipx) path

If you want to run FireWatch on bare metal without Docker, install it with
[pipx](https://pipx.pypa.io/):

```bash
pipx install "firewatch[cli] @ git+https://github.com/gterdem/firewatch.git"
```

Then bring your own local `/v1`-compatible inference endpoint (Ollama, vLLM,
LM Studio, etc.) and configure FireWatch to point at it:

```bash
# With Ollama running locally on the default port:
export FIREWATCH_OLLAMA_BASE_URL=http://localhost:11434
export FIREWATCH_OLLAMA_MODEL=qwen2.5:3b

firewatch run --host 127.0.0.1 --port 8000
```

FireWatch binds loopback only (`--host 127.0.0.1`).  For UI access, either
run the Vite dev server (`cd frontend && npm run dev`) or set up your own
nginx/Caddy reverse proxy pointing to `127.0.0.1:8000`.

---

## Architecture notes

### Loopback-only API (ADR-0026)

The FireWatch API (`firewatch run --host 127.0.0.1`) binds only the loopback
interface.  The `nginx` service runs with `network_mode: "service:firewatch"`
which shares the firewatch container's network namespace.  nginx reaches the
API at `127.0.0.1:8000` over their shared loopback and proxies it outward.

Result: **the host port only publishes the nginx surface**.  The raw API port
(8000) is never host-exposed.  This is the ADR-0026 Decision 1 posture without
requiring an API key.

### No cloud egress (ADR-0022)

Both inference services (`ollama`, `llama`) are on the `fwnet` bridge network
and have no host port mappings.  Docker assigns a 172.x address (RFC-1918),
which passes FireWatch's `_is_local_address()` validator.  All inference stays
on the operator's hardware.

### Profile selection changes only wiring

`FIREWATCH_OLLAMA_BASE_URL` is the only config difference between profiles
(`http://ollama:11434` vs `http://llama:8080`).  The FireWatch source, AI
adapter, prompts, and scoring logic are identical in both profiles.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `curl: (7) Failed to connect` | Stack not up or wrong port | `docker compose ... ps`; check `FW_HOST_PORT` in `.env` |
| `"ai_status": "error"` in scores | No model pulled (default) or wrong GGUF path (lean) | Pull a model or check `GGUF_HOST_PATH` |
| llama-server OOM-killed | GGUF too large for available RAM | Use a smaller quantization (Q4 vs Q8) or a 3B model |
| Config not applied | Env var typo or stale container | `docker compose ... down && up -d` after editing `.env` |
| `Refusing to bind non-loopback` | `--host 0.0.0.0` passed without API key | Do not override `--host`; keep the loopback default |
