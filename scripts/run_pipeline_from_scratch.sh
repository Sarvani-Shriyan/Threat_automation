#!/usr/bin/env bash
# End-to-end pipeline test from ingestion (run from repo root with venv active).
#
# Prerequisites:
#   source .venv/bin/activate
#   pip install -r requirements.txt
#   ollama serve   # separate terminal, models: gemma + phi4 per ingestion/config.py
#
# Usage:
#   ./scripts/run_pipeline_from_scratch.sh              # full run (slow filter/generate)
#   ./scripts/run_pipeline_from_scratch.sh --fresh        # wipe prior data/*.json artifacts
#   ./scripts/run_pipeline_from_scratch.sh --quick      # limit filter=20, generate=3
#   ./scripts/run_pipeline_from_scratch.sh --skip-gemma   # keyword+CVE only (no Ollama for step 2)

set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

FRESH=0
QUICK=0
SKIP_GEMMA=0
FILTER_LIMIT=""
GEN_LIMIT=""
GEN_FORCE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --fresh) FRESH=1 ;;
    --quick) QUICK=1; FILTER_LIMIT="--limit 20"; GEN_LIMIT="--limit 3" ;;
    --skip-gemma) SKIP_GEMMA=1 ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
  shift
done

if [[ "$QUICK" -eq 1 ]]; then
  GEN_FORCE="--force --no-resume"
fi

if [[ "$FRESH" -eq 1 ]]; then
  echo "Removing prior pipeline artifacts..."
  rm -f data/threat_queue.json \
        data/filtered_threat_queue.json \
        data/generated_rules_staging.json \
        data/ingestion_dedup_state.json
fi

echo ""
echo "========== STEP 1: INGESTION =========="
python main_ingestion.py

echo ""
echo "========== STEP 2: FILTER =========="
FILTER_ARGS=()
[[ "$SKIP_GEMMA" -eq 1 ]] && FILTER_ARGS+=(--skip-gemma)
# shellcheck disable=SC2086
python main_filter.py ${FILTER_ARGS[@]} $FILTER_LIMIT

echo ""
echo "========== STEP 3: RULE GENERATION (requires Ollama + Phi-4) =========="
echo "Ensure: ollama serve  (and models pulled per ingestion/config.py)"
# shellcheck disable=SC2086
python main_generator.py $GEN_LIMIT $GEN_FORCE

echo ""
echo "Done. Inspect:"
echo "  data/threat_queue.json"
echo "  data/filtered_threat_queue.json"
echo "  data/generated_rules_staging.json"
