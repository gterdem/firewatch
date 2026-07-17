# FireWatch — Deploy

One-command Docker install for FireWatch. Three compose profiles are available
(ADR-0042, issue #4):

| Profile | Inference runtime | Best for |
|---|---|---|
| `default` | [Ollama](https://ollama.com) | First install; best model UX; GPU auto-detect |
| `lean` | [llama.cpp `llama-server`](https://github.com/ggerganov/llama.cpp) | Minimal footprint; air-gapped; operator-supplied GGUF |
| `rules-only` | **None** — no inference container at all | Zero AI footprint; a ~1 GB-class box (an old laptop, a Pi); detection/scoring/escalation only |

All three profiles wire the engine purely via `base_url` config (or, for
`rules-only`, disable it) — the FireWatch source code is identical across all
of them (ADR-0022 / ADR-0042).

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

## rules-only profile — FireWatch + nginx, zero AI footprint (issue #4)

Full detection, scoring, escalation, and dashboard — no AI narrative, and **no
inference container at all**. This is the floor of the hardware story: a
~1 GB-class box (an old laptop, a Raspberry Pi) with a one-line install.

The engine work for this profile shipped earlier: `DisabledAIEngine`
(`firewatch_core/adapters/ai_disabled.py` — core-owned; relocated from
firewatch-cli by issue #39) reports `ai_status="disabled"` and never contacts
an inference endpoint when `FIREWATCH_AI_ENABLED=false`. This profile is the
deploy-time way to make that optionality visible and installable — compose
brings up only `firewatch` + `nginx`; `ollama` and `llama` are never started.

### Start

`rules-only` requires only **one** env var on the invocation (or in `.env`):
`FIREWATCH_AI_ENABLED=false` (turns AI scoring off).

```bash
# From the repo root:
FIREWATCH_AI_ENABLED=false \
docker compose -f deploy/docker-compose.yml --profile rules-only up -d
```

The shared `FIREWATCH_OLLAMA_BASE_URL` default (`http://ollama:11434`, the
`ollama` service's DNS entry on the `fwnet` bridge network) does **not** need
to be overridden: under `rules-only` that service never starts, so the
hostname never resolves — but FireWatch's config validator is pure/syntactic
(ADR-0066, issue #40) and performs no DNS resolution, so an unresolvable
hostname no longer crashes the container at startup. It is never dialed
either way, since `FIREWATCH_AI_ENABLED=false` selects `DisabledAIEngine` and
skips the AI path entirely.

### Check the stack

```bash
# Dashboard (through nginx):
curl -fsS http://localhost:8080/

# API health (through nginx):
curl -fsS http://localhost:8080/health

# Only firewatch + nginx should be listed — no ollama, no llama:
docker compose -f deploy/docker-compose.yml --profile rules-only ps
```

### Tear down

```bash
docker compose -f deploy/docker-compose.yml --profile rules-only down
# Add -v to also remove the fw_data volume.
```

### Measured idle footprint

Measured 2026-07-14 with `docker stats --no-stream` approximately 5 s after
both containers reported healthy, no inference container present at all (the
same methodology as `docs/benchmarks/footprint-2026-06-12.md`, MI-2 — a real
measurement, not an estimate). Reference host: AMD Ryzen 7 9800X3D (16 logical
cores), 31 GiB RAM, WSL2 / Linux 6.18.33.1-microsoft-standard-WSL2, Docker
29.1.3, Compose v2.27.0. Stack brought up via
`docker compose -p fwrulesonly -f deploy/docker-compose.yml --profile rules-only up -d`
on a non-conflicting host port (19997); production stacks use 8080.

| Container | Idle RSS (`docker stats`) | Notes |
|---|---|---|
| `firewatch` | 80.9 MiB | FastAPI app at rest, no inference container to talk to |
| `nginx` | 4.4 MiB | SPA + reverse-proxy sidecar |
| **Total (rules-only, idle)** | **~85 MiB** | No `ollama`/`llama` container exists under this profile |

For comparison, the `default` profile's idle RSS with no model loaded is
**~185 MiB** (`docs/benchmarks/footprint-2026-06-12.md`) — `rules-only` is
lower still because there is no inference container process at all, not even
an unloaded one.

Image footprint (also measured, `docker image inspect --format '{{.Size}}'`):

| Image | Bytes | Human-readable |
|---|---|---|
| `firewatch:latest` | 229,405,718 | 229 MB |
| `firewatch-nginx:latest` | 50,180,461 | 50.2 MB |
| **Total (rules-only stack)** | **279,586,179** | **~280 MB** |

Compare to the `default` profile's total image footprint of **5.11 GB**
(`firewatch` + `nginx` + `ollama/ollama:0.30.8`) — `rules-only` ships **~95%
less** on disk because the inference runtime is simply absent.

Disk note: the first geo-enrichment call downloads the DB-IP Lite offline MMDB
files (ADR-0039) into the `fw_data` volume — **~135 MB** on this run
(`/app/data/geo_data`). This is unrelated to AI and identical across all three
profiles; it is not part of the "AI footprint" claim above.

### AI status honesty — what was actually verified

The rules-only profile was brought up live and exercised end-to-end (ingest →
score → query) to check what the AI surface reports, not just asserted:

- `GET /threats` and `GET /threats/{ip}` (the list/concise views the
  dashboard's AI-engine indicator reads) correctly report
  **`"ai_status": "disabled"`** — verified live against a running
  `rules-only` stack.
- `GET /threats/{ip}/detailed?ai=true` (the deep-analysis / narration path)
  **also reports `"ai_status": "disabled"`**, never `"unavailable"`, when AI
  is switched off this way (fixed by ADR-0066 / issue #39: one closed
  `ai_status` vocabulary, one stamping authority
  `firewatch_core.ai_status.resolve_ai_status`, used by both the concise and
  detailed pipeline paths). `"unavailable"` is now reserved exclusively for
  the fault case — AI enabled but the engine unreachable or erroring.

### Upgrade path: point at a LAN inference endpoint later (ADR-0022)

A rules-only box is not a dead end. Because the engine only ever talks to a
configurable `base_url` (ADR-0022), an operator can later add AI narration
**without rebuilding any image** — just change two env vars and restart:

```bash
# In deploy/.env (or on the invocation):
FIREWATCH_AI_ENABLED=true
FIREWATCH_OLLAMA_BASE_URL=http://<lan-host>:11434   # another machine on the LAN
                                                     # running Ollama/vLLM/llama.cpp
FIREWATCH_OLLAMA_MODEL=qwen2.5:3b                   # or whichever model that endpoint serves

# Restart with the new config (no image rebuild — same firewatch:latest image):
docker compose -f deploy/docker-compose.yml --profile rules-only up -d
```

`FIREWATCH_OLLAMA_BASE_URL` must still resolve to a loopback / RFC 1918 / LAN
address (ADR-0022's local-first validator; no cloud endpoints). Once the box
restarts, `_build_pipeline` selects the real `OpenAIEngine` instead of
`DisabledAIEngine` (`FIREWATCH_AI_ENABLED=true`), and narration starts as
soon as the LAN endpoint answers `/v1` requests — the `firewatch`/`nginx`
images and the FireWatch source code are unchanged either way (ADR-0042).

---

## Reading the host's own logs from the container (issue #5)

The M1 endpoint source plugins — `linux_auth` (sshd, sudo, PAM auth failures)
and `clamav` (malware detections) — read *this machine's own* logs
(ADR-0065's local-first principle). On bare metal that's automatic (see
"Bare-metal path" below). **Inside Docker, the container has its own
filesystem namespace and cannot see the host's journal or `/var/log` unless
you deliberately bind-mount them in** — this section is that deliberate
setup, plus how to verify it actually reads the host's events.

Both `linux_auth` and `clamav` are already installed in the `firewatch` image
(`deploy/Dockerfile`'s `uv sync --all-packages` pulls in every workspace
source plugin) — nothing to add to the image itself; only the **mounts** and
the plugins' own config (`mode`/`auth_log_path`/`log_path`, defaulted to the
Debian/Ubuntu conventions already — see `firewatch_linux_auth.config` /
`firewatch_clamav.config`) need to line up with what you mount.

### journald path (systemd hosts — Arch, Ubuntu, Fedora, Debian)

The primary, recommended path (ADR-0065 §3: journald-first). Apply the
compose override `deploy/docker-compose.host-logs.yml` on top of any profile:

```bash
# 1. Find your host's systemd-journal group GID and put it in deploy/.env:
getent group systemd-journal        # e.g. systemd-journal:x:999:
echo "FW_HOST_LOG_GID=999" >> deploy/.env   # use YOUR actual GID, not 999

# 2. Bring the stack up with the override applied (any profile — rules-only shown):
FIREWATCH_AI_ENABLED=false \
docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.host-logs.yml \
    --profile rules-only up -d --build

# 3. Confirm the container can read the host journal:
docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.host-logs.yml \
    exec firewatch journalctl -n 5 --no-pager
```

`deploy/docker-compose.host-logs.yml`'s journald section (the default —
active section in the file) mounts `/var/log/journal` **and**
`/etc/machine-id`, both read-only. Both are required — see the file's own
comments and "Permission model" below for why `/etc/machine-id` specifically
is load-bearing, not incidental.

**Verification (the issue's acceptance check) — EICAR + a failed SSH login:**

```bash
# Failed SSH login (generates a linux_auth event) — from any machine that
# can reach the host's sshd, or from the host itself against itself:
ssh nonexistent-user@localhost   # answer/ignore the password prompt; it will fail

# EICAR malware detection (generates a clamav event) — requires ClamAV
# already installed/configured on the HOST with on-access or manual scanning
# (see packages/sources/clamav/README.md — "Testing with EICAR", which links
# the official eicar.org download; installing ClamAV itself is out of scope
# for FireWatch, ADR-0021). The standard EICAR test string, written directly
# (no download needed — the same string every antivirus engine recognizes as
# "malware" by convention; harmless, not executable):
mkdir -p /tmp/eicar-test
printf '%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' \
    > /tmp/eicar-test/eicar.com.txt

# Then check the containerized FireWatch dashboard/API for both events:
curl -fsS http://localhost:8080/threats | jq .
```

**PENDING MAINTAINER VERIFICATION** — this exact end-to-end check (the
EICAR file and the failed SSH login actually appearing, scored, in the
containerized FireWatch's `/threats`) has not been run against a live host by
this change; it requires a real systemd host with sshd and a configured
ClamAV on-access scanner, which this environment does not have. What HAS
been verified live, on this build host (Ubuntu 24.04, systemd/journald
present, 2026-07-17): the mount + permission mechanism itself — a
`firewatch`-image container, running as the non-root `firewatch` user (UID
1001) with **no** `group_add`, gets `journalctl`'s real
`No journal files were opened due to insufficient permissions.` (exit 1)
against the bind-mounted host journal; the SAME container with
`group_add: ["999"]` (this host's real `systemd-journal` GID) successfully
reads live host journal entries via `journalctl -o json` (the exact
invocation `firewatch_sdk.localhost.journald.JournaldReader` uses) — and the
full compose stack (`docker compose ... --profile rules-only up -d --build`
with the override applied) came up healthy with `docker compose exec
firewatch journalctl -n 5` returning real host entries and
`groups=...,999(systemd-journal)` confirmed via `id`. See the git history of
this change for the exact commands run.

### file-tail path (non-systemd host, or hardened Docker/Podman)

For a host with no systemd journal (rare on the mainstream distros this
project targets, but real for minimal/container-base images or non-systemd
inits), or a hardened Docker/Podman setup whose security profile restricts
journal access specifically: edit `deploy/docker-compose.host-logs.yml`,
commenting out the two journald lines and uncommenting the one `/var/log`
line instead (the file's own comments walk through this).

```bash
# 1. Find the group that owns the auth log on your distro and put it in deploy/.env:
getent group adm                    # Debian/Ubuntu — e.g. adm:x:4:
echo "FW_HOST_LOG_GID=4" >> deploy/.env    # use YOUR actual GID

# 2. Bring the stack up the same way as the journald path (same override file,
#    now with its /var/log line uncommented instead):
FIREWATCH_AI_ENABLED=false \
docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.host-logs.yml \
    --profile rules-only up -d --build

# 3. Confirm the container can read the host's auth log:
docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.host-logs.yml \
    exec firewatch tail -n 5 /var/log/auth.log
```

Then set `linux_auth`'s `mode` to `"file"` (or leave it `"auto"` — it falls
back to file-tail automatically when journald is unavailable) and
`auth_log_path` to match your distro (`/var/log/auth.log` on Debian/Ubuntu —
the default already; `/var/log/secure` on RHEL/CentOS-family — see the
caveat below). **Verification** is the same EICAR + failed-SSH check as the
journald path above, and carries the same **PENDING MAINTAINER
VERIFICATION** status — what was verified live here is the mechanism only:
without `group_add`, `tail /var/log/auth.log` as the non-root container user
gets `Permission denied` (exit 1); with `group_add: ["4"]` (this host's
`adm` GID) it reads real lines from the host's own `auth.log`. A write
attempt (`echo hi >> /var/log/auth.log`) against the same `:ro` mount was
also confirmed refused (`Read-only file system`) even with the matching
group — the mount's read-only enforcement is independent of group access.

**RHEL/CentOS caveat — a real, honest limitation, not papered over:**
RHEL/CentOS-family distros ship `/var/log/secure` as `root:root`, mode
`0600` (root-only, not group-readable) by default — unlike Debian/Ubuntu's
`/var/log/auth.log` (`root:adm`, mode `0640`). `group_add` cannot help on
those hosts: no non-root GID grants access to a file with no group read bit
at all. On a RHEL/CentOS-family host, prefer the journald path (systemd
journal files there are still group-readable via `systemd-journal`,
unaffected by this); the file-tail path only works there if the host's own
hardening policy is changed to loosen `/var/log/secure`'s permissions — a
host-side decision this deployment does not make for you.

### Permission model — explicit, no `privileged: true` shortcut

Two independent mechanisms are in play, and conflating them is the most
common way this goes wrong:

1. **Read-only root mount (`:ro`).** Every bind mount in
   `deploy/docker-compose.host-logs.yml` is read-only — a **kernel-enforced**
   guarantee that the container cannot write to, truncate, or delete the
   host's log files, independent of which user is reading inside the
   container. Verified live above: a write attempt against the `:ro` mount
   fails with `Read-only file system` even for a process with matching group
   read access.
2. **Group membership (`group_add`).** A read-only mount does not, by
   itself, grant read access — Linux permission checks run against each
   file's own owner/group/mode, regardless of the mount flag. FireWatch's
   container runs as a non-root user (`firewatch`, UID 1001,
   `deploy/Dockerfile` — ADR-0026 minimal privilege), so for it to actually
   be *permitted* to read journal files (typically group `systemd-journal`,
   mode `0640`) or `auth.log` (typically group `adm` on Debian/Ubuntu, mode
   `0640`), it needs supplementary group membership matching the **host's**
   group GID. Compose's `group_add:` (which `deploy/docker-compose.host-logs.yml`
   uses, sourced from `FW_HOST_LOG_GID` in `deploy/.env`) adds that GID to
   the running container process — the containerized equivalent of `sudo
   usermod -aG systemd-journal $USER` for a bare-metal invocation, **without**
   elevating to root and **without** `privileged: true`.

**Never** use `privileged: true`, `user: root`, or `cap_add: [ALL]` to work
around a permission error here. Each trades a scoped, auditable group grant
(one GID, read-only data) for unrestricted host access from the one
container whose entire job is watching for intrusions — the opposite of
least privilege. If `group_add` with the correct GID still fails, that is a
signal to re-check the GID (`getent group ...` **on the host**, not inside
the container) or to reconsider the file-tail path's RHEL/CentOS caveat
above — not to reach for a broader grant.

### journald image size (issue #5 acceptance criterion)

The image needs `journalctl` on `PATH` —
`firewatch_sdk.localhost.journald.JournaldReader` shells out to
`journalctl -o json` and raises a typed
`JournaldUnavailableError` if the binary is missing (see that module's
`_spawn`). On Debian (this image's base, `python:3.12-slim`), `journalctl`
ships in the `systemd` package itself — no smaller package provides just the
binary (`systemd-journal-remote` is a different tool, for *sending/receiving
remote* journals, out of scope per this issue). `deploy/Dockerfile` installs
it `--no-install-recommends` alongside the existing `curl` dependency, which
skips systemd's optional recommends (dbus, cryptsetup, timesyncd, ...).

**Measured** (not estimated) on this build host, 2026-07-17, same methodology
as `docs/benchmarks/footprint-2026-06-12.md` (`docker image inspect --format
'{{.Size}}'`, uncompressed):

| Image | Bytes | Human-readable |
|---|---|---|
| `firewatch:latest` — before (curl only) | 230,102,016 | 230.1 MB |
| `firewatch:latest` — after (curl + systemd) | 244,473,574 | 244.5 MB |
| **Delta** | **14,371,558** | **~14.4 MB (+6.2%)** |

This delta is specific to this build host's package versions/base-image
digest at measurement time and will drift slightly as Debian ships new
`systemd`/dependency versions — re-run the same `docker image inspect`
comparison after a Dockerfile change to confirm the current number, rather
than trusting this table indefinitely.

### Bare-metal path — no extra steps

Running FireWatch directly on the host (`uv run` / pipx, see below) needs
**no container-specific setup at all**: `linux_auth`/`clamav` call
`journalctl`/read `/var/log` as whatever OS user is already running the
`firewatch` process. The only requirement is that user's own journal-read
permission — the same `sudo usermod -aG systemd-journal $USER` (and re-login)
that `JournaldReader`'s own error message recommends when it hits
`EPERM`/`Permission denied`, or plain file-read permission on
`/var/log/auth.log` for the file-tail fallback. No bind mounts, no
`group_add`, no `/etc/machine-id` — the process already shares the host's
journal and filesystem directly.

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
| `error while interpolating services.firewatch.group_add...: required variable FW_HOST_LOG_GID is missing a value` | `deploy/docker-compose.host-logs.yml` applied without `FW_HOST_LOG_GID` set | Set it in `deploy/.env` — see "Reading the host's own logs" |
| `journalctl`: `No journal files were opened due to insufficient permissions.` (exit 1) | `FW_HOST_LOG_GID` unset, wrong, or doesn't match the HOST's actual `systemd-journal` GID | Re-run `getent group systemd-journal` **on the host** (not inside the container) and correct `deploy/.env` |
| `journalctl`: `Failed to open system journal: Permission denied` | Same root cause as above, different systemd/journald phrasing (the directory itself isn't listable, vs. individual files unreadable) | Same fix — correct `FW_HOST_LOG_GID` |
| `journalctl` runs but shows nothing at all | Host's journald uses `Storage=volatile` (`/etc/systemd/journald.conf`) — no persistent files under `/var/log/journal` to bind-mount | Check `journalctl --disk-usage` on the host; either switch journald to persistent storage or use the file-tail path instead |
| `tail: /var/log/auth.log: Permission denied` (file-tail path) | `FW_HOST_LOG_GID` doesn't match the host's `adm` (or equivalent) group | Re-run `getent group adm` on the host; on RHEL/CentOS-family hosts see the RHEL/CentOS caveat above — `group_add` cannot fix a root-only `0600` file |
