#!/usr/bin/env bash
# Unattended run: starts llama-server, runs the whole suite, stops the server.
#   MODEL=/path/model.gguf bash run.sh <label>
#   BIN=/path/to/llama-server MODEL=... bash run.sh <label>      (default BIN: llama-server on PATH)
#   SUITE=gen SEEDS="1 2 3" bash run.sh <label>    generated tasks (fresh per seed)
#   SUITE=all bash run.sh <label>                   both
# Re-running with the same label resumes; delete results/<label>/ to start over.
set -euo pipefail
cd "$(dirname "$0")"
# Machine-specific defaults (MODEL, BIN, ...) can live in local.env (git-ignored).
[ -f local.env ] && . ./local.env
LABEL=${1:?usage: MODEL=/path/model.gguf bash run.sh <label>}
MODEL=${MODEL:?set MODEL=/path/to/model.gguf (or put it in local.env)}
BIN=${BIN:-llama-server}
PORT=${PORT:-8081}
CTX=${CTX:-32768}
NGL=${NGL:-99}
OUT=results/$LABEL
mkdir -p "$OUT"

if curl -sf "http://127.0.0.1:$PORT/health" >/dev/null 2>&1; then
  echo "port $PORT already in use - stop that server first" >&2; exit 1
fi
if command -v ollama >/dev/null 2>&1 && [ "$(ollama ps 2>/dev/null | wc -l)" -gt 1 ]; then
  echo "warning: Ollama has a model loaded (shares GPU memory):"; ollama ps
fi
[ -f tasks/manifest.json ] || python3 build_tasks.py

"$BIN" -m "$MODEL" -ngl "$NGL" -fa on -c "$CTX" -np 1 --host 127.0.0.1 --port "$PORT" >"$OUT/server.log" 2>&1 &
SRV=$!
trap 'kill $SRV 2>/dev/null || true' EXIT
for _ in $(seq 1 180); do
  curl -sf "http://127.0.0.1:$PORT/health" >/dev/null 2>&1 && break
  kill -0 $SRV 2>/dev/null || { echo "llama-server died, see $OUT/server.log" >&2; exit 1; }
  sleep 1
done
echo "model: $MODEL" | tee "$OUT/run-info.txt"
date -Is | tee -a "$OUT/run-info.txt"
# SUITE=core (default: hand-written code + logs), gen (generated code, one run per seed), all
SUITE=${SUITE:-core}
SEEDS=${SEEDS:-1 2 3}
if [ "$SUITE" = core ] || [ "$SUITE" = all ]; then
  python3 run_bench.py --label "$LABEL" --url "http://127.0.0.1:$PORT" 2>&1 | tee -a "$OUT/run.log"
fi
if [ "$SUITE" = gen ] || [ "$SUITE" = all ]; then
  for s in $SEEDS; do
    python3 run_bench.py --label "$LABEL" --suite gen --seed "$s" --url "http://127.0.0.1:$PORT" 2>&1 | tee -a "$OUT/run-gen.log"
  done
  python3 run_bench.py --label "$LABEL" --aggregate | tee -a "$OUT/run-gen.log"
fi
