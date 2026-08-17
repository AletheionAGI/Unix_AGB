#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ -e var/benchmark/gate2b-v4-final.json && "${AGB_GATE2B_V4_ALLOW_REPLAY:-0}" != "1" ]]; then
  echo "Gate 2B v4 final report already exists; set AGB_GATE2B_V4_ALLOW_REPLAY=1 only for an explicit reproduction" >&2
  exit 2
fi
export ASM_PYTHON="${ASM_PYTHON:-.venv/bin/python}"
export ASM_SOURCE_ROOT="${ASM_SOURCE_ROOT:-../gitlab/ASM/src}"
export ASM_SOURCE_REVISION="${ASM_SOURCE_REVISION:-4c8eddf2f07d9aec800769323d7e1effbd64815a}"
export ASM_DEVICE="${ASM_DEVICE:-cuda}"
export AGB_GATE2B_CORPUS="${AGB_GATE2B_V4_CORPUS:-var/benchmark/gate2b-v4-neutral.jsonl}"
export AGB_GATE2B_TEST_CORPUS="${AGB_GATE2B_V4_TEST_CORPUS:-var/benchmark/gate2b-v4-neutral-test.jsonl}"
export AGB_GATE2B_MANIFEST="${AGB_GATE2B_V4_MANIFEST:-var/benchmark/gate2b-v4-manifest.json}"
export AGB_GATE2B_BASELINES="${AGB_GATE2B_V4_BASELINES:-var/benchmark/gate2b-v4-baselines.json}"
export AGB_GATE2B_GRU_CHECKPOINT="${AGB_GATE2B_V4_GRU:-var/benchmark/gate2b-v4-gru.pt}"
AGB_GATE2B_DATASET_SEED="${AGB_GATE2B_V4_DATASET_SEED:-20260817}" make gate2b-neutral-corpus
make benchmark-gate2b-baselines
initials=("${ASM_CM_SEED1_INITIAL:-../gitlab/ASM/runs/asm_c2_fw_lm_confirmation/seed_1/candidate/checkpoint_final.pt}" "${ASM_CM_SEED2_INITIAL:-../gitlab/ASM/runs/asm_c2_fw_lm_confirmation/seed_2/candidate/checkpoint_final.pt}" "${ASM_CM_SEED3_INITIAL:-../gitlab/ASM/runs/asm_c2_fw_lm_confirmation/seed_3/candidate/checkpoint_final.pt}")
initial_shas=("${ASM_CM_SEED1_INITIAL_SHA256:-96293688518fc0a2e83525af6ad28d16f39677980432762328bf4ad8aac654de}" "${ASM_CM_SEED2_INITIAL_SHA256:-a1a67b4e066b0cabba00d0f17d27c77d29ac2d0ad3dfabc8baf61ff51dba9342}" "${ASM_CM_SEED3_INITIAL_SHA256:-698979a684a02c4191e3a5ed09256df86d3e81939de988e0809e5433cbc90f4b}")
for representation in raw canonical; do
  for seed in 1 2 3; do
    ASM_CM_CHECKPOINT="${initials[$((seed-1))]}" ASM_CM_CHECKPOINT_SHA256="${initial_shas[$((seed-1))]}" AGB_GATE2B_V4_REPRESENTATION="$representation" AGB_GATE2B_TRAIN_SEED="$seed" AGB_GATE2B_V4_RUN="var/benchmark/gate2b-v4-${representation}/seed_${seed}" make train-gate2b-v4
  done
done
args=()
for representation in raw canonical; do
  for seed in 1 2 3; do
    path="var/benchmark/gate2b-v4-${representation}/seed_${seed}/checkpoint_final.pt"; sha="$(sha256sum "$path" | awk '{print $1}')"; args+=(--checkpoint "${representation}:${seed}:${path}:${sha}")
  done
done
PYTHONPATH=python:scripts "$ASM_PYTHON" scripts/evaluate_gate2b_v4.py --corpus "$AGB_GATE2B_CORPUS" --test-corpus "$AGB_GATE2B_TEST_CORPUS" --manifest "$AGB_GATE2B_MANIFEST" --baseline-report "$AGB_GATE2B_BASELINES" --gru-checkpoint "$AGB_GATE2B_GRU_CHECKPOINT" --asm-source-root "$ASM_SOURCE_ROOT" --asm-source-revision "$ASM_SOURCE_REVISION" --device "$ASM_DEVICE" "${args[@]}" --chart-prefix var/benchmark/gate2b-v4-comparison --output var/benchmark/gate2b-v4-final.json
