#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

export ASM_PYTHON="${ASM_PYTHON:-.venv/bin/python}"
export ASM_SOURCE_ROOT="${ASM_SOURCE_ROOT:-../gitlab/ASM/src}"
export ASM_DEVICE="${ASM_DEVICE:-cuda}"
export AGB_GATE2B_CORPUS="${AGB_GATE2B_CORPUS:-var/benchmark/gate2b-neutral.jsonl}"
export AGB_GATE2B_BASELINES="${AGB_GATE2B_BASELINES:-var/benchmark/gate2b-baselines.json}"
export AGB_GATE2B_GRU_CHECKPOINT="${AGB_GATE2B_GRU_CHECKPOINT:-var/benchmark/gate2b-gru.pt}"

seed1_initial="${ASM_CM_SEED1_INITIAL:-../gitlab/ASM/runs/asm_c2_fw_lm_confirmation/seed_1/candidate/checkpoint_final.pt}"
seed2_initial="${ASM_CM_SEED2_INITIAL:-../gitlab/ASM/runs/asm_c2_fw_lm_confirmation/seed_2/candidate/checkpoint_final.pt}"
seed3_initial="${ASM_CM_SEED3_INITIAL:-../gitlab/ASM/runs/asm_c2_fw_lm_confirmation/seed_3/candidate/checkpoint_final.pt}"
seed1_initial_sha="${ASM_CM_SEED1_INITIAL_SHA256:-96293688518fc0a2e83525af6ad28d16f39677980432762328bf4ad8aac654de}"
seed2_initial_sha="${ASM_CM_SEED2_INITIAL_SHA256:-a1a67b4e066b0cabba00d0f17d27c77d29ac2d0ad3dfabc8baf61ff51dba9342}"
seed3_initial_sha="${ASM_CM_SEED3_INITIAL_SHA256:-698979a684a02c4191e3a5ed09256df86d3e81939de988e0809e5433cbc90f4b}"

make gate2b-neutral-corpus
make benchmark-gate2b-baselines

for seed in 1 2 3; do
  case "$seed" in
    1) initial="$seed1_initial"; initial_sha="$seed1_initial_sha" ;;
    2) initial="$seed2_initial"; initial_sha="$seed2_initial_sha" ;;
    3) initial="$seed3_initial"; initial_sha="$seed3_initial_sha" ;;
  esac
  ASM_CM_CHECKPOINT="$initial" \
  ASM_CM_CHECKPOINT_SHA256="$initial_sha" \
  AGB_GATE2B_TRAIN_SEED="$seed" \
  AGB_GATE2B_RUN="var/benchmark/gate2b-asm/seed_${seed}" \
  make train-gate2b-asm
done

export ASM_CM_SEED1_CHECKPOINT="var/benchmark/gate2b-asm/seed_1/checkpoint_final.pt"
export ASM_CM_SEED2_CHECKPOINT="var/benchmark/gate2b-asm/seed_2/checkpoint_final.pt"
export ASM_CM_SEED3_CHECKPOINT="var/benchmark/gate2b-asm/seed_3/checkpoint_final.pt"
export ASM_CM_SEED1_SHA256="$(sha256sum "$ASM_CM_SEED1_CHECKPOINT" | awk '{print $1}')"
export ASM_CM_SEED2_SHA256="$(sha256sum "$ASM_CM_SEED2_CHECKPOINT" | awk '{print $1}')"
export ASM_CM_SEED3_SHA256="$(sha256sum "$ASM_CM_SEED3_CHECKPOINT" | awk '{print $1}')"
make evaluate-gate2b-final
