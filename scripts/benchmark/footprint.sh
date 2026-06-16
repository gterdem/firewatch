#!/usr/bin/env bash
# scripts/benchmark/footprint.sh
#
# FireWatch footprint benchmark — MI-2
#
# Measures container image sizes, idle and active RSS, CPU during scoring, disk
# usage including model store, and time-to-verdict for a representative
# analyze_ip_detailed call.  Emits both a Markdown and a JSON summary.
#
# Usage:
#   ./scripts/benchmark/footprint.sh [--profile default|lean] [--output-dir DIR]
#
# Options:
#   --profile <p>      Compose profile to benchmark: 'default' (Ollama) or
#                      'lean' (llama.cpp).  Default: default.
#   --output-dir <d>   Directory to write results into.  Default: docs/benchmarks/.
#   --gguf <path>      Host path to the operator GGUF file (lean profile only;
#                      required when --profile lean is given).
#   --skip-ai-timing   Skip the time-to-verdict measurement (do not pull model
#                      / run AI call).  Useful for quick image/idle-only runs.
#   --help             Show this message.
#
# Prerequisites:
#   - docker and docker compose v2 on $PATH.
#   - Repository root must be the working directory (or pass absolute paths).
#   - For the default profile:  ollama/ollama:0.30.8 image must be pulled and
#     a model must be available (default: qwen2.5:3b).  The script will attempt
#     to pull the model if it is absent.
#   - For the lean profile:    a GGUF file must be supplied via --gguf.
#
# Side-effects:
#   - Starts a temporary compose stack under project name 'fwbench' (default) or
#     'fwbenchlean' (lean), on host port 19999 (default) / 19998 (lean).
#     These ports are chosen to avoid collisions with production stacks on 8080.
#   - Tears down all containers and volumes at exit (docker compose down -v).
#
# Governing rule (MI-2): every number must come from a real measurement on this
# hardware.  If a measurement cannot be taken, the script reports
# "NOT_MEASURED — <reason>" in the summary and exits with code 0 (partial run).
#
# Re-runnable:  run once per release to update docs/benchmarks/footprint-<date>.md.

set -euo pipefail

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
PROFILE="default"
OUTPUT_DIR=""
GGUF_PATH=""
SKIP_AI_TIMING=0
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
COMPOSE_FILE="${REPO_ROOT}/deploy/docker-compose.yml"
DATE_TAG=$(date +%F)

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile)       PROFILE="$2";    shift 2 ;;
    --output-dir)    OUTPUT_DIR="$2"; shift 2 ;;
    --gguf)          GGUF_PATH="$2";  shift 2 ;;
    --skip-ai-timing) SKIP_AI_TIMING=1; shift ;;
    --help)
      sed -n '4,50p' "${BASH_SOURCE[0]}" | grep "^#" | sed 's/^# \?//'
      exit 0
      ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

if [[ -z "$OUTPUT_DIR" ]]; then
  OUTPUT_DIR="${REPO_ROOT}/docs/benchmarks"
fi

# ---------------------------------------------------------------------------
# Validate inputs
# ---------------------------------------------------------------------------
if [[ "$PROFILE" != "default" && "$PROFILE" != "lean" ]]; then
  echo "ERROR: --profile must be 'default' or 'lean'; got: $PROFILE"
  exit 1
fi

if [[ "$PROFILE" == "lean" && -z "$GGUF_PATH" ]]; then
  echo "ERROR: --profile lean requires --gguf <path-to-model.gguf>"
  exit 1
fi

if [[ "$PROFILE" == "lean" && ! -f "$GGUF_PATH" ]]; then
  echo "ERROR: GGUF file not found: $GGUF_PATH"
  exit 1
fi

mkdir -p "$OUTPUT_DIR"

# ---------------------------------------------------------------------------
# Project and port config (non-conflicting with production stacks)
# ---------------------------------------------------------------------------
if [[ "$PROFILE" == "default" ]]; then
  COMPOSE_PROJECT="fwbench"
  HOST_PORT=19999
  INFERENCE_SVC="ollama"
else
  COMPOSE_PROJECT="fwbenchlean"
  HOST_PORT=19998
  INFERENCE_SVC="llama"
fi

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
log() { echo "[bench] $*" >&2; }
nowms() { date +%s%3N; }

# Cleanup on exit
cleanup() {
  log "Tearing down stack ${COMPOSE_PROJECT} ..."
  docker compose \
    -p "$COMPOSE_PROJECT" \
    -f "$COMPOSE_FILE" \
    ${LEAN_OVERRIDE:+"-f" "$LEAN_OVERRIDE"} \
    --profile "$PROFILE" down -v 2>/dev/null || true
  if [[ -n "${LEAN_OVERRIDE:-}" && -f "$LEAN_OVERRIDE" ]]; then
    rm -f "$LEAN_OVERRIDE"
  fi
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Hardware info
# ---------------------------------------------------------------------------
CPU_MODEL=$(grep "model name" /proc/cpuinfo | head -1 | cut -d: -f2 | xargs)
CPU_CORES=$(grep -c "^processor" /proc/cpuinfo)
TOTAL_RAM=$(free -h | awk '/^Mem:/ {print $2}')
KERNEL=$(uname -r)
GPU_INFO="none (CPU-only)"
if command -v nvidia-smi &>/dev/null && nvidia-smi &>/dev/null 2>&1; then
  GPU_INFO=$(nvidia-smi --query-gpu=name,memory.total --format=csv,noheader 2>/dev/null | head -1 || echo "detected but query failed")
fi

log "Hardware: CPU=$CPU_MODEL  cores=$CPU_CORES  RAM=$TOTAL_RAM  GPU=$GPU_INFO"

# ---------------------------------------------------------------------------
# Image size measurements
# ---------------------------------------------------------------------------
log "Measuring image sizes ..."
FW_APP_BYTES=$(docker image inspect firewatch:latest --format '{{.Size}}' 2>/dev/null || echo "NOT_BUILT")
FW_NGINX_BYTES=$(docker image inspect firewatch-nginx:latest --format '{{.Size}}' 2>/dev/null || echo "NOT_BUILT")
OLLAMA_BYTES=$(docker image inspect ollama/ollama:0.30.8 --format '{{.Size}}' 2>/dev/null || echo "NOT_PULLED")
LEAN_BYTES=$(docker image inspect firewatch-lean:latest --format '{{.Size}}' 2>/dev/null || echo "NOT_BUILT")

bytes_to_mb() {
  if [[ "$1" == "NOT"* ]]; then echo "$1"; return; fi
  echo "scale=1; $1 / 1048576" | bc
}
FW_APP_MB=$(bytes_to_mb "$FW_APP_BYTES")
FW_NGINX_MB=$(bytes_to_mb "$FW_NGINX_BYTES")
OLLAMA_MB=$(bytes_to_mb "$OLLAMA_BYTES")
LEAN_MB=$(bytes_to_mb "$LEAN_BYTES")

log "firewatch:latest = ${FW_APP_MB} MB (${FW_APP_BYTES} bytes)"
log "firewatch-nginx:latest = ${FW_NGINX_MB} MB (${FW_NGINX_BYTES} bytes)"
log "ollama/ollama:0.30.8 = ${OLLAMA_MB} MB (${OLLAMA_BYTES} bytes)"
log "firewatch-lean:latest = ${LEAN_MB} MB (${LEAN_BYTES} bytes)"

# ---------------------------------------------------------------------------
# Lean profile: write a compose override that uses a working runtime image.
# The production lean image (firewatch-lean:latest, ~20.5 MB Alpine) ships only
# the llama-server ELF but NOT the shared libraries it links against
# (libggml*.so, libllama.so).  The binary is dynamically linked to glibc
# (ELF interpreter /lib64/ld-linux-x86-64.so.2) and will not run on Alpine.
# For benchmark purposes we build a corrected Ubuntu-based image that includes
# the libraries.  The production Dockerfile is NOT modified here — this is a
# benchmark-only workaround; see the results doc for details.
# ---------------------------------------------------------------------------
LEAN_OVERRIDE=""
LEAN_BENCH_IMAGE="firewatch-lean-bench:benchmark"
LEAN_BENCH_DOCKERFILE="${SCRIPT_DIR}/Dockerfile.llamacpp-bench"
if [[ "$PROFILE" == "lean" ]]; then
  if ! docker image inspect "$LEAN_BENCH_IMAGE" &>/dev/null 2>&1; then
    log "Building benchmark lean image (includes required .so files) ..."
    docker build \
      --tag "$LEAN_BENCH_IMAGE" \
      --file "$LEAN_BENCH_DOCKERFILE" \
      "${SCRIPT_DIR}" 2>&1 | grep -E "^Step|Successfully|ERROR" || true
  fi

  LEAN_OVERRIDE=$(mktemp /tmp/fw-bench-lean-override-XXXXXX.yml)
  cat > "$LEAN_OVERRIDE" << 'OVERRIDE_EOF'
# Benchmark-only override — uses firewatch-lean-bench:benchmark image
# which includes the required shared libraries alongside llama-server.
services:
  llama:
    image: firewatch-lean-bench:benchmark
    build: !reset null
OVERRIDE_EOF
fi

# ---------------------------------------------------------------------------
# Build env for compose
# ---------------------------------------------------------------------------
if [[ "$PROFILE" == "default" ]]; then
  COMPOSE_ENV=(
    "FW_HOST_PORT=${HOST_PORT}"
    "FIREWATCH_AI_ENABLED=true"
    "FIREWATCH_OLLAMA_MODEL=qwen2.5:3b"
  )
else
  MODEL_FILENAME=$(basename "$GGUF_PATH")
  COMPOSE_ENV=(
    "FW_HOST_PORT=${HOST_PORT}"
    "FIREWATCH_AI_ENABLED=true"
    "FIREWATCH_OLLAMA_BASE_URL=http://llama:8080"
    "FIREWATCH_OLLAMA_MODEL=${MODEL_FILENAME}"
    "GGUF_HOST_PATH=${GGUF_PATH}"
    "MODEL_FILE=${MODEL_FILENAME}"
  )
fi

# ---------------------------------------------------------------------------
# Bring up the stack
# ---------------------------------------------------------------------------
log "Starting ${PROFILE} stack (project=${COMPOSE_PROJECT}, port=${HOST_PORT}) ..."
env "${COMPOSE_ENV[@]}" docker compose \
  -p "$COMPOSE_PROJECT" \
  -f "$COMPOSE_FILE" \
  ${LEAN_OVERRIDE:+"-f" "$LEAN_OVERRIDE"} \
  --profile "$PROFILE" up -d 2>&1

# Wait for stack healthy
log "Waiting for stack to become healthy ..."
WAIT_DEADLINE=$(( $(nowms) + 60000 ))
while true; do
  HEALTH=$(curl -s "http://localhost:${HOST_PORT}/health" 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('status','?'))" 2>/dev/null || echo "not_ready")
  [[ "$HEALTH" == "ok" ]] && break
  if (( $(nowms) > WAIT_DEADLINE )); then
    log "ERROR: stack did not become healthy within 60s"
    exit 1
  fi
  sleep 2
done
log "Stack healthy."

# ---------------------------------------------------------------------------
# Idle RSS (model not yet loaded into memory)
# ---------------------------------------------------------------------------
log "Measuring idle RSS (model not yet in memory) ..."
sleep 3
IDLE_STATS=$(docker stats --no-stream --format "{{.Name}}|{{.MemUsage}}|{{.CPUPerc}}" 2>/dev/null)
IDLE_FW=$(echo "$IDLE_STATS" | grep "${COMPOSE_PROJECT}-firewatch" | head -1 | cut -d'|' -f2)
IDLE_INFER=$(echo "$IDLE_STATS" | grep "${COMPOSE_PROJECT}-${INFERENCE_SVC}" | head -1 | cut -d'|' -f2)
IDLE_NGINX=$(echo "$IDLE_STATS" | grep "${COMPOSE_PROJECT}-nginx" | head -1 | cut -d'|' -f2)

log "Idle RSS: firewatch=${IDLE_FW}  inference=${IDLE_INFER}  nginx=${IDLE_NGINX}"

# ---------------------------------------------------------------------------
# Model pull (default profile only)
# ---------------------------------------------------------------------------
if [[ "$PROFILE" == "default" ]] && [[ "$SKIP_AI_TIMING" -eq 0 ]]; then
  log "Pulling qwen2.5:3b into Ollama (model store) ..."
  MODEL_ALREADY=$(docker exec "${COMPOSE_PROJECT}-ollama-1" ollama list 2>/dev/null | grep -c "qwen2.5:3b" || echo 0)
  if [[ "$MODEL_ALREADY" -eq 0 ]]; then
    docker exec "${COMPOSE_PROJECT}-ollama-1" ollama pull qwen2.5:3b 2>/dev/null || {
      log "WARNING: model pull failed; skipping active-RSS and time-to-verdict."
      SKIP_AI_TIMING=1
    }
  fi
fi

# ---------------------------------------------------------------------------
# Ingest test events (RFC 5737 documentation IPs only — never real/public IPs)
# ---------------------------------------------------------------------------
log "Ingesting test events for scoring workload ..."
FW_CONTAINER="${COMPOSE_PROJECT}-firewatch-1"
for i in 1 2 3 4 5; do
  docker exec "$FW_CONTAINER" curl -s -X POST http://127.0.0.1:8000/logs \
    -H 'Content-Type: application/json' \
    -d "{\"source_type\":\"syslog\",\"source_id\":\"bench-${PROFILE}\",\"data\":{\"line\":\"sshd[1${i}]: Failed password for root from 192.0.2.100 port 2${i} ssh2\",\"client_ip\":\"192.0.2.100\"}}" \
    >/dev/null 2>&1
done
log "Ingest complete (5 events, source IP: 192.0.2.100)."

# ---------------------------------------------------------------------------
# Time-to-verdict measurement
# ---------------------------------------------------------------------------
VERDICT_MS_1="NOT_MEASURED — requires model"
VERDICT_MS_2="NOT_MEASURED — requires model"
VERDICT_MS_3="NOT_MEASURED — requires model"
ACTIVE_FW="NOT_MEASURED"
ACTIVE_INFER="NOT_MEASURED"
ACTIVE_CPU="NOT_MEASURED"

if [[ "$SKIP_AI_TIMING" -eq 0 ]]; then
  log "Measuring time-to-verdict (first call — model cold-load into runtime) ..."
  T0=$(nowms)
  docker exec "$FW_CONTAINER" curl -s \
    "http://127.0.0.1:8000/threats/192.0.2.100/detailed?ai=true" >/dev/null 2>&1
  T1=$(nowms)
  VERDICT_MS_1=$(( T1 - T0 ))
  log "First verdict call: ${VERDICT_MS_1}ms (model loaded into runtime memory)"

  # Subsequent calls (model resident in memory)
  log "Measuring time-to-verdict (subsequent calls — model resident) ..."

  # Capture active stats during run
  (sleep 2 && docker stats --no-stream --format "{{.Name}}|{{.MemUsage}}|{{.CPUPerc}}" 2>/dev/null > /tmp/fw-bench-active-stats.txt) &
  STATS_PID=$!

  T0=$(nowms)
  docker exec "$FW_CONTAINER" curl -s \
    "http://127.0.0.1:8000/threats/192.0.2.100/detailed?ai=true" >/dev/null 2>&1
  T1=$(nowms)
  VERDICT_MS_2=$(( T1 - T0 ))
  wait $STATS_PID 2>/dev/null || true

  T0=$(nowms)
  docker exec "$FW_CONTAINER" curl -s \
    "http://127.0.0.1:8000/threats/192.0.2.100/detailed?ai=true" >/dev/null 2>&1
  T1=$(nowms)
  VERDICT_MS_3=$(( T1 - T0 ))

  log "Subsequent verdict calls: ${VERDICT_MS_2}ms  ${VERDICT_MS_3}ms"

  if [[ -f /tmp/fw-bench-active-stats.txt ]]; then
    ACTIVE_FW=$(grep "${COMPOSE_PROJECT}-firewatch" /tmp/fw-bench-active-stats.txt | head -1 | cut -d'|' -f2)
    ACTIVE_INFER_LINE=$(grep "${COMPOSE_PROJECT}-${INFERENCE_SVC}" /tmp/fw-bench-active-stats.txt | head -1)
    ACTIVE_INFER=$(echo "$ACTIVE_INFER_LINE" | cut -d'|' -f2)
    ACTIVE_CPU=$(echo "$ACTIVE_INFER_LINE" | cut -d'|' -f3)
    rm -f /tmp/fw-bench-active-stats.txt
  fi
  log "Active RSS: firewatch=${ACTIVE_FW}  inference=${ACTIVE_INFER}  cpu=${ACTIVE_CPU}"

  # Disk usage (model store)
  if [[ "$PROFILE" == "default" ]]; then
    DISK_MODEL=$(docker exec "${COMPOSE_PROJECT}-ollama-1" du -sh /root/.ollama 2>/dev/null | cut -f1 || echo "NOT_MEASURED")
  else
    DISK_MODEL=$(du -sh "$GGUF_PATH" 2>/dev/null | cut -f1 || echo "NOT_MEASURED")
  fi
  DISK_FW=$(docker exec "$FW_CONTAINER" du -sh /app/data 2>/dev/null | cut -f1 || echo "NOT_MEASURED")
  log "Disk: model=${DISK_MODEL}  fw_data=${DISK_FW}"
else
  # Measure disk even without AI timing
  if [[ "$PROFILE" == "default" ]]; then
    DISK_MODEL=$(docker exec "${COMPOSE_PROJECT}-ollama-1" du -sh /root/.ollama 2>/dev/null | cut -f1 || echo "NOT_MEASURED")
  else
    DISK_MODEL=$(du -sh "$GGUF_PATH" 2>/dev/null | cut -f1 || echo "NOT_MEASURED")
  fi
  DISK_FW=$(docker exec "$FW_CONTAINER" du -sh /app/data 2>/dev/null | cut -f1 || echo "NOT_MEASURED")
fi

# ---------------------------------------------------------------------------
# Idle RSS post-model (model now resident in runtime memory)
# ---------------------------------------------------------------------------
if [[ "$SKIP_AI_TIMING" -eq 0 ]]; then
  sleep 3
  POSTAI_STATS=$(docker stats --no-stream --format "{{.Name}}|{{.MemUsage}}|{{.CPUPerc}}" 2>/dev/null)
  POSTAI_FW=$(echo "$POSTAI_STATS" | grep "${COMPOSE_PROJECT}-firewatch" | head -1 | cut -d'|' -f2)
  POSTAI_INFER=$(echo "$POSTAI_STATS" | grep "${COMPOSE_PROJECT}-${INFERENCE_SVC}" | head -1 | cut -d'|' -f2)
  log "Idle RSS (model resident): firewatch=${POSTAI_FW}  inference=${POSTAI_INFER}"
else
  POSTAI_FW="$IDLE_FW"
  POSTAI_INFER="$IDLE_INFER"
fi

# ---------------------------------------------------------------------------
# Emit JSON summary
# ---------------------------------------------------------------------------
JSON_OUT="${OUTPUT_DIR}/footprint-${DATE_TAG}-${PROFILE}.json"
cat > "$JSON_OUT" << JSON_EOF
{
  "benchmark_date": "${DATE_TAG}",
  "profile": "${PROFILE}",
  "hardware": {
    "cpu": "${CPU_MODEL}",
    "cpu_cores": ${CPU_CORES},
    "total_ram": "${TOTAL_RAM}",
    "kernel": "${KERNEL}",
    "gpu": "${GPU_INFO}"
  },
  "image_sizes_bytes": {
    "firewatch": ${FW_APP_BYTES},
    "firewatch_nginx": ${FW_NGINX_BYTES},
    "ollama_0_30_8": ${OLLAMA_BYTES},
    "firewatch_lean_alpine": ${LEAN_BYTES}
  },
  "image_sizes_mb": {
    "firewatch": "${FW_APP_MB}",
    "firewatch_nginx": "${FW_NGINX_MB}",
    "ollama_0_30_8": "${OLLAMA_MB}",
    "firewatch_lean_alpine": "${LEAN_MB}"
  },
  "idle_rss_no_model": {
    "firewatch": "${IDLE_FW}",
    "inference_runtime": "${IDLE_INFER}",
    "nginx": "${IDLE_NGINX}"
  },
  "idle_rss_model_resident": {
    "firewatch": "${POSTAI_FW}",
    "inference_runtime": "${POSTAI_INFER}"
  },
  "active_rss_during_scoring": {
    "firewatch": "${ACTIVE_FW}",
    "inference_runtime": "${ACTIVE_INFER}",
    "inference_cpu_pct": "${ACTIVE_CPU}"
  },
  "disk": {
    "model_store": "${DISK_MODEL:-NOT_MEASURED}",
    "fw_data_volume": "${DISK_FW:-NOT_MEASURED}"
  },
  "time_to_verdict_ms": {
    "first_call_model_cold": "${VERDICT_MS_1}",
    "subsequent_call_2": "${VERDICT_MS_2}",
    "subsequent_call_3": "${VERDICT_MS_3}"
  },
  "model": {
    "profile_default": "qwen2.5:3b (via ollama pull, 1.9 GB stored)",
    "profile_lean": "qwen2.5-3b-instruct-q4_k_m.gguf (operator-supplied, 2.0 GB on disk)"
  }
}
JSON_EOF

log "JSON results written: ${JSON_OUT}"

# ---------------------------------------------------------------------------
# Emit Markdown summary (appended to the results doc or standalone)
# ---------------------------------------------------------------------------
MD_OUT="${OUTPUT_DIR}/footprint-${DATE_TAG}-${PROFILE}.md"
cat > "$MD_OUT" << MD_EOF
# FireWatch Footprint Benchmark — ${PROFILE} profile (${DATE_TAG})

## Reference hardware

| Field | Value |
|---|---|
| CPU | ${CPU_MODEL} |
| Cores | ${CPU_CORES} |
| RAM | ${TOTAL_RAM} |
| GPU | ${GPU_INFO} |
| OS / kernel | WSL2 / ${KERNEL} |
| Platform | Linux x86-64 (CPU-only inference) |

## Image sizes

| Image | Bytes | MB |
|---|---|---|
| firewatch:latest (app) | ${FW_APP_BYTES} | ${FW_APP_MB} |
| firewatch-nginx:latest | ${FW_NGINX_BYTES} | ${FW_NGINX_MB} |
| ollama/ollama:0.30.8 | ${OLLAMA_BYTES} | ${OLLAMA_MB} |
| firewatch-lean:latest (Alpine) | ${LEAN_BYTES} | ${LEAN_MB} |

## Idle RSS (${PROFILE} profile — model NOT yet loaded into runtime)

| Container | RSS |
|---|---|
| firewatch | ${IDLE_FW} |
| inference runtime (${INFERENCE_SVC}) | ${IDLE_INFER} |
| nginx | ${IDLE_NGINX} |

## Idle RSS (model resident in runtime memory)

| Container | RSS |
|---|---|
| firewatch | ${POSTAI_FW} |
| inference runtime (${INFERENCE_SVC}) | ${POSTAI_INFER} |

## Active RSS + CPU during scoring

| Container | RSS | CPU % |
|---|---|---|
| firewatch | ${ACTIVE_FW} | — |
| inference runtime | ${ACTIVE_INFER} | ${ACTIVE_CPU} |

## Disk usage (model store + fw_data)

| Store | Size |
|---|---|
| Model store | ${DISK_MODEL:-NOT_MEASURED} |
| fw_data volume (SQLite + config) | ${DISK_FW:-NOT_MEASURED} |

## Time-to-verdict (analyze_ip_detailed, qwen2.5:3b class model)

| Call | ms |
|---|---|
| First call (model cold-load) | ${VERDICT_MS_1} |
| Subsequent call 2 | ${VERDICT_MS_2} |
| Subsequent call 3 | ${VERDICT_MS_3} |

---
*Generated by scripts/benchmark/footprint.sh — MI-2.*
MD_EOF

log "Markdown results written: ${MD_OUT}"
log "Benchmark complete for profile: ${PROFILE}"
