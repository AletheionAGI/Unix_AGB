#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ -e var/benchmark/gate2b-v5-final.json && "${AGB_GATE2B_V5_ALLOW_REPLAY:-0}" != "1" ]]; then echo "v5 final exists; set AGB_GATE2B_V5_ALLOW_REPLAY=1 for reproduction" >&2; exit 2; fi
python_bin="${ASM_PYTHON:-.venv/bin/python}"; source_root="${ASM_SOURCE_ROOT:-../gitlab/ASM/src}"
checkpoint_args=()
for representation in raw canonical; do for seed in 1 2 3; do path="var/benchmark/gate2b-v4-${representation}/seed_${seed}/checkpoint_final.pt"; sha="$(sha256sum "$path" | awk '{print $1}')"; checkpoint_args+=(--checkpoint "${representation}:${seed}:${path}:${sha}"); done; done
PYTHONPATH=python:scripts "$python_bin" scripts/freeze_gate2b_v5_ensemble.py --v4-report var/benchmark/gate2b-v4-final.json "${checkpoint_args[@]}" --output var/benchmark/gate2b-v5-freeze.json
PYTHONPATH=python:scripts python3 scripts/generate_gate2b_neutral.py --seed "${AGB_GATE2B_V5_DATASET_SEED:-20260818}" --per-cell "${AGB_GATE2B_PER_CELL:-16}" --output var/benchmark/gate2b-v5-public-unused.jsonl --test-output var/benchmark/gate2b-v5-neutral-test.jsonl --manifest var/benchmark/gate2b-v5-manifest.json
PYTHONPATH=python:scripts "$python_bin" scripts/evaluate_gate2b_v5_ensemble.py --freeze var/benchmark/gate2b-v5-freeze.json --v4-corpus var/benchmark/gate2b-v4-neutral.jsonl --v4-baseline-report var/benchmark/gate2b-v4-baselines.json --v4-gru-checkpoint var/benchmark/gate2b-v4-gru.pt --fresh-test var/benchmark/gate2b-v5-neutral-test.jsonl --fresh-manifest var/benchmark/gate2b-v5-manifest.json --asm-source-root "$source_root" --device "${ASM_DEVICE:-cuda}" --output var/benchmark/gate2b-v5-final.json
