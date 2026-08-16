.PHONY: test test-python test-rust generate benchmark benchmark-gate2 benchmark-gate2-asm-cm benchmark-gate2-multiseed benchmark-gate2-multiseed-independent gate2b-neutral-corpus benchmark-gate2b-baselines train-gate2b-asm evaluate-gate2b-final capture-independent-events build-independent-candidates build-review-queue build-review-html review-server export-reviewed-corpus freeze-independent-corpus protected-corpus-lab gate3-dry-run benchmark-gate3-cache benchmark-gate3-asm-pipeline gate4-reversible-denial causal-proof live-proof linux-capabilities seccomp-proof bpf-pipeline policy-broker supervise-broker broker-health broker-restart cache-list admin-server identity-probe admin-userns uid-gid-matrix dedicated-accounts privileged-identity uid-gid-combinations uid-gid-variants fail-closed-config admin-rate-limit admin-operator-spoofing live-bpf-observer

test: test-python test-rust

test-python:
	PYTHONPATH=python:scripts python3 -m unittest discover -s tests -v

test-rust:
	cargo test

generate:
	python3 scripts/generate_synthetic_events.py

benchmark:
	PYTHONPATH=python:scripts python3 scripts/benchmark_synthetic.py

benchmark-gate2:
	PYTHONPATH=python:scripts python3 scripts/benchmark_gate2.py

benchmark-gate2-asm-cm:
	PYTHONPATH=python:scripts "$${ASM_PYTHON:-.venv/bin/python}" scripts/benchmark_gate2.py \
		--mode-d asm-cm \
		--asm-checkpoint "$${ASM_CM_CHECKPOINT:?set ASM_CM_CHECKPOINT}" \
		--asm-source-root "$${ASM_SOURCE_ROOT:?set ASM_SOURCE_ROOT}" \
		--asm-source-revision "$${ASM_SOURCE_REVISION:?set ASM_SOURCE_REVISION}" \
		--asm-checkpoint-sha256 "$${ASM_CM_CHECKPOINT_SHA256:?set ASM_CM_CHECKPOINT_SHA256}" \
		--device "$${ASM_DEVICE:-cuda}" \
		--asm-inference-policy "$${ASM_INFERENCE_POLICY:-security-relevant}" \
		--output var/benchmark/gate2-v1-asm-cm-report.json

benchmark-gate2-multiseed:
	PYTHONPATH=python:scripts "$${ASM_PYTHON:-.venv/bin/python}" scripts/benchmark_gate2_multiseed.py \
		--checkpoint "1:$${ASM_CM_SEED1_CHECKPOINT:?set ASM_CM_SEED1_CHECKPOINT}:$${ASM_CM_SEED1_SHA256:?set ASM_CM_SEED1_SHA256}" \
		--checkpoint "2:$${ASM_CM_SEED2_CHECKPOINT:?set ASM_CM_SEED2_CHECKPOINT}:$${ASM_CM_SEED2_SHA256:?set ASM_CM_SEED2_SHA256}" \
		--checkpoint "3:$${ASM_CM_SEED3_CHECKPOINT:?set ASM_CM_SEED3_CHECKPOINT}:$${ASM_CM_SEED3_SHA256:?set ASM_CM_SEED3_SHA256}" \
		--asm-source-root "$${ASM_SOURCE_ROOT:?set ASM_SOURCE_ROOT}" \
		--asm-source-revision "$${ASM_SOURCE_REVISION:?set ASM_SOURCE_REVISION}" \
		--device "$${ASM_DEVICE:-cuda}" \
		--asm-inference-policy "$${ASM_INFERENCE_POLICY:-security-relevant}" \
		--output var/benchmark/gate2-adversarial-v2-multiseed.json

benchmark-gate2-multiseed-independent:
	PYTHONPATH=python:scripts "$${ASM_PYTHON:-.venv/bin/python}" scripts/benchmark_gate2_multiseed.py \
		--independent-dataset "$${AGB_INDEPENDENT_CORPUS:?set AGB_INDEPENDENT_CORPUS}" \
		--checkpoint "1:$${ASM_CM_SEED1_CHECKPOINT:?set ASM_CM_SEED1_CHECKPOINT}:$${ASM_CM_SEED1_SHA256:?set ASM_CM_SEED1_SHA256}" \
		--checkpoint "2:$${ASM_CM_SEED2_CHECKPOINT:?set ASM_CM_SEED2_CHECKPOINT}:$${ASM_CM_SEED2_SHA256:?set ASM_CM_SEED2_SHA256}" \
		--checkpoint "3:$${ASM_CM_SEED3_CHECKPOINT:?set ASM_CM_SEED3_CHECKPOINT}:$${ASM_CM_SEED3_SHA256:?set ASM_CM_SEED3_SHA256}" \
		--asm-source-root "$${ASM_SOURCE_ROOT:?set ASM_SOURCE_ROOT}" \
		--asm-source-revision "$${ASM_SOURCE_REVISION:?set ASM_SOURCE_REVISION}" \
		--device "$${ASM_DEVICE:-cuda}" \
		--asm-inference-policy "$${ASM_INFERENCE_POLICY:-security-relevant}" \
		--output "$${AGB_BENCHMARK_OUTPUT:-var/benchmark/gate2-independent-multiseed.json}"

gate2b-neutral-corpus:
	PYTHONPATH=python:scripts python3 scripts/generate_gate2b_neutral.py \
		--seed "$${AGB_GATE2B_DATASET_SEED:-20260816}" \
		--per-cell "$${AGB_GATE2B_PER_CELL:-16}" \
		--output "$${AGB_GATE2B_CORPUS:-var/benchmark/gate2b-neutral.jsonl}" \
		--test-output "$${AGB_GATE2B_TEST_CORPUS:-var/benchmark/gate2b-neutral-test.jsonl}" \
		--manifest "$${AGB_GATE2B_MANIFEST:-var/benchmark/gate2b-neutral-manifest.json}"

benchmark-gate2b-baselines:
	PYTHONPATH=python:scripts "$${ASM_PYTHON:-.venv/bin/python}" scripts/benchmark_gate2b.py \
		--corpus "$${AGB_GATE2B_CORPUS:-var/benchmark/gate2b-neutral.jsonl}" \
		--manifest "$${AGB_GATE2B_MANIFEST:-var/benchmark/gate2b-neutral-manifest.json}" \
		--budget "$${AGB_GATE2B_STATE_BUDGET:-64}" \
		--gru-device "$${AGB_GATE2B_GRU_DEVICE:-cuda}" \
		--gru-epochs "$${AGB_GATE2B_GRU_EPOCHS:-3}" \
		--gru-checkpoint "$${AGB_GATE2B_GRU_CHECKPOINT:-var/benchmark/gate2b-gru.pt}" \
		--output "$${AGB_GATE2B_BASELINES:-var/benchmark/gate2b-baselines.json}"

train-gate2b-asm:
	PYTHONPATH=python:scripts "$${ASM_PYTHON:-.venv/bin/python}" scripts/train_gate2b_asm.py \
		--corpus "$${AGB_GATE2B_CORPUS:-var/benchmark/gate2b-neutral.jsonl}" \
		--baseline-report "$${AGB_GATE2B_BASELINES:-var/benchmark/gate2b-baselines.json}" \
		--checkpoint "$${ASM_CM_CHECKPOINT:?set ASM_CM_CHECKPOINT}" \
		--checkpoint-sha256 "$${ASM_CM_CHECKPOINT_SHA256:?set ASM_CM_CHECKPOINT_SHA256}" \
		--asm-source-root "$${ASM_SOURCE_ROOT:?set ASM_SOURCE_ROOT}" \
		--seed "$${AGB_GATE2B_TRAIN_SEED:?set AGB_GATE2B_TRAIN_SEED}" \
		--device "$${ASM_DEVICE:-cuda}" \
		--curriculum "$${AGB_GATE2B_CURRICULUM:-4:300,16:300,64:400,256:500,1024:500}" \
		--output-root "$${AGB_GATE2B_RUN:?set AGB_GATE2B_RUN}"

evaluate-gate2b-final:
	PYTHONPATH=python:scripts "$${ASM_PYTHON:-.venv/bin/python}" scripts/evaluate_gate2b_final.py \
		--corpus "$${AGB_GATE2B_CORPUS:-var/benchmark/gate2b-neutral.jsonl}" \
		--test-corpus "$${AGB_GATE2B_TEST_CORPUS:-var/benchmark/gate2b-neutral-test.jsonl}" \
		--manifest "$${AGB_GATE2B_MANIFEST:-var/benchmark/gate2b-neutral-manifest.json}" \
		--baseline-report "$${AGB_GATE2B_BASELINES:-var/benchmark/gate2b-baselines.json}" \
		--gru-checkpoint "$${AGB_GATE2B_GRU_CHECKPOINT:-var/benchmark/gate2b-gru.pt}" \
		--asm-source-root "$${ASM_SOURCE_ROOT:?set ASM_SOURCE_ROOT}" \
		--checkpoint "1:$${ASM_CM_SEED1_CHECKPOINT:?set ASM_CM_SEED1_CHECKPOINT}:$${ASM_CM_SEED1_SHA256:?set ASM_CM_SEED1_SHA256}" \
		--checkpoint "2:$${ASM_CM_SEED2_CHECKPOINT:?set ASM_CM_SEED2_CHECKPOINT}:$${ASM_CM_SEED2_SHA256:?set ASM_CM_SEED2_SHA256}" \
		--checkpoint "3:$${ASM_CM_SEED3_CHECKPOINT:?set ASM_CM_SEED3_CHECKPOINT}:$${ASM_CM_SEED3_SHA256:?set ASM_CM_SEED3_SHA256}" \
		--device "$${ASM_DEVICE:-cuda}" \
		--chart-prefix "$${AGB_GATE2B_CHART_PREFIX:-var/benchmark/gate2b-comparison}" \
		--output "$${AGB_GATE2B_FINAL_OUTPUT:-var/benchmark/gate2b-final.json}"

capture-independent-events:
	PYTHONPATH=python:scripts python3 scripts/run_live_bpf_observer.py \
		--duration "$${AGB_CAPTURE_DURATION:-60}" \
		--bpftrace-command "$${AGB_BPFTRACE_COMMAND:-bpftrace}" \
		--target-uid "$${AGB_CAPTURE_UID:--1}" \
		$${AGB_SENSITIVE_PATH:+--sensitive-path "$${AGB_SENSITIVE_PATH}"} \
		--output-events "$${AGB_CAPTURE_EVENTS:-var/telemetry/bpf-events.jsonl}"

build-independent-candidates:
	PYTHONPATH=python:scripts python3 scripts/build_trajectory_candidates.py \
		--input "$${AGB_CAPTURE_EVENTS:-var/telemetry/bpf-events.jsonl}" \
		--output "$${AGB_CANDIDATES:-var/telemetry/trajectory-candidates.jsonl}" \
		--collector-revision "$${AGB_COLLECTOR_REVISION:-$$(python3 scripts/fingerprint_collector.py)}" \
		--min-events "$${AGB_MIN_TRAJECTORY_EVENTS:-1}" \
		--max-events "$${AGB_MAX_TRAJECTORY_EVENTS:-256}" \
		--coverage-scope "$${AGB_COVERAGE_SCOPE:-system-wide}" \
		--protected-executables "$${AGB_PROTECTED_EXECUTABLES:-}" \
		$${AGB_EXCLUDE_EXTERNAL:+--exclude-external}

build-review-queue:
	PYTHONPATH=python:scripts python3 scripts/build_review_queue.py \
		--input "$${AGB_CANDIDATES:-var/telemetry/trajectory-candidates.jsonl}" \
		--output "$${AGB_REVIEW_QUEUE:-var/telemetry/review-queue.jsonl}" \
		--review-template "$${AGB_REVIEWS:-var/telemetry/trajectory-reviews.jsonl}"

build-review-html:
	python3 scripts/build_review_html.py \
		--input "$${AGB_REVIEW_QUEUE:-var/telemetry/review-queue.jsonl}" \
		--output "$${AGB_REVIEW_HTML:-var/telemetry/review.html}"

review-server:
	python3 scripts/serve_review_ui.py \
		--queue "$${AGB_REVIEW_QUEUE:-var/telemetry/review-queue.jsonl}" \
		--reviews "$${AGB_REVIEWS:-var/telemetry/trajectory-reviews.jsonl}" \
		--port "$${AGB_REVIEW_PORT:-8765}"

export-reviewed-corpus:
	PYTHONPATH=python:scripts python3 scripts/export_reviewed_corpus.py \
		--candidates "$${AGB_CANDIDATES:-var/telemetry/trajectory-candidates.jsonl}" \
		--reviews "$${AGB_REVIEWS:-var/telemetry/trajectory-reviews.jsonl}" \
		--output "$${AGB_INDEPENDENT_CORPUS:-var/telemetry/reviewed-trajectories.jsonl}"

freeze-independent-corpus:
	PYTHONPATH=python:scripts python3 scripts/freeze_independent_corpus.py \
		--input "$${AGB_INDEPENDENT_CORPUS:?set AGB_INDEPENDENT_CORPUS}" \
		--output "$${AGB_INDEPENDENT_MANIFEST:-var/benchmark/independent-manifest.json}"

protected-corpus-lab:
	cargo build --quiet --bin agb-lab-workload
	PYTHONPATH=python:scripts python3 scripts/run_protected_corpus_lab.py \
		--bpftrace-command "$${AGB_BPFTRACE_COMMAND:-sudo bpftrace}" \
		--duration "$${AGB_PROTECTED_LAB_DURATION:-25}" \
		--cases-per-class "$${AGB_PROTECTED_LAB_CASES:-30}"

gate3-dry-run:
	cargo build --quiet --bin agb-policy-dry-run
	AGB_GATE3_POLICY_REVISION="$${AGB_GATE3_POLICY_REVISION:?set AGB_GATE3_POLICY_REVISION}" \
	AGB_GATE3_CACHE_KEY="$${AGB_GATE3_CACHE_KEY:?set AGB_GATE3_CACHE_KEY}" \
	AGB_GATE3_MIN_CONFIDENCE="$${AGB_GATE3_MIN_CONFIDENCE:-0.8}" \
	AGB_GATE3_TTL_SECONDS="$${AGB_GATE3_TTL_SECONDS:-2}" \
	AGB_GATE3_AUDIT_GROUP_SIZE="$${AGB_GATE3_AUDIT_GROUP_SIZE:-64}" \
	target/debug/agb-policy-dry-run \
		"$${AGB_GATE3_AUDIT:-var/gate3-decisions.jsonl}" \
		"$${AGB_GATE3_CACHE:-var/gate3-cache.json}" \
		< "$${AGB_GATE3_INPUT:?set AGB_GATE3_INPUT}"

benchmark-gate3-cache:
	cargo run --quiet --release --bin agb-gate3-cache-benchmark -- \
		"$${AGB_GATE3_BENCHMARK_ITERATIONS:-100000}"

benchmark-gate3-asm-pipeline:
	cargo build --quiet --bin agb-policy-dry-run
	PYTHONPATH=python:scripts "$${ASM_PYTHON:-.venv/bin/python}" scripts/run_gate3_asm_pipeline.py \
		--corpus "$${AGB_GATE3_CORPUS:?set AGB_GATE3_CORPUS}" \
		--checkpoint "$${ASM_CM_CHECKPOINT:?set ASM_CM_CHECKPOINT}" \
		--checkpoint-sha256 "$${ASM_CM_CHECKPOINT_SHA256:?set ASM_CM_CHECKPOINT_SHA256}" \
		--asm-source-root "$${ASM_SOURCE_ROOT:?set ASM_SOURCE_ROOT}" \
		--asm-source-revision "$${ASM_SOURCE_REVISION:?set ASM_SOURCE_REVISION}" \
		--device "$${ASM_DEVICE:-cuda}" \
		--policy-revision "$${AGB_GATE3_POLICY_REVISION:?set AGB_GATE3_POLICY_REVISION}" \
		--minimum-confidence "$${AGB_GATE3_MIN_CONFIDENCE:-0.8}" \
		--ttl-seconds "$${AGB_GATE3_TTL_SECONDS:-2}" \
		--audit "$${AGB_GATE3_AUDIT:-var/gate3-asm-decisions.jsonl}" \
		--cache "$${AGB_GATE3_CACHE:-var/gate3-asm-cache.json}" \
		--output "$${AGB_GATE3_BENCHMARK_OUTPUT:-var/benchmark/gate3-asm-pipeline.json}"

gate4-reversible-denial:
	cargo build --quiet --bin agb-lab-workload --bin agb-policy-dry-run
	python3 scripts/run_gate4_reversible_denial.py \
		--ttl-seconds "$${AGB_GATE4_TTL_SECONDS:-2}" \
		--output "$${AGB_GATE4_OUTPUT:-var/benchmark/gate4-reversible-denial.json}"

causal-proof:
	cargo run --quiet --bin agb-causal-proof

live-proof:
	cargo build --quiet --bin agb-gateway --bin agb-lab-workload
	python3 scripts/run_live_causal_proof.py

linux-capabilities:
	python3 scripts/check_linux_capabilities.py

seccomp-proof:
	cargo build --quiet --bin agb-gateway --bin agb-policy-broker
	python3 scripts/run_seccomp_broker_proof.py

bpf-pipeline:
	cargo build --quiet --bin agb-gateway
	python3 scripts/run_bpf_gateway_pipeline.py --input fixtures/events/bpf-sample.txt

policy-broker:
	cargo run --quiet --bin agb-policy-broker -- var/agb-policy.sock var/enforcement.jsonl

supervise-broker:
	python3 scripts/supervise_policy_broker.py

broker-health:
	python3 scripts/check_policy_broker_health.py --socket var/agb-policy.sock

broker-restart:
	cargo build --quiet --bin agb-policy-broker
	python3 scripts/test_broker_restart.py

cache-list:
	AGB_ADMIN_TOKEN="$${AGB_ADMIN_TOKEN:?set AGB_ADMIN_TOKEN}" cargo run --quiet --bin agb-cachectl -- list var/policy-cache.jsonl

admin-server:
	cargo run --quiet --bin agb-admin-server -- var/agb-admin.sock var/policy-cache.jsonl var/admin-audit.jsonl

identity-probe:
	python3 scripts/probe_linux_identity_namespace.py

admin-userns:
	cargo build --quiet --bin agb-admin-server
	python3 scripts/test_admin_user_namespace.py

uid-gid-matrix:
	cargo build --quiet --bin agb-admin-server
	python3 scripts/test_admin_uid_gid_matrix.py

dedicated-accounts:
	python3 scripts/test_admin_dedicated_accounts.py

privileged-identity:
	python3 scripts/run_privileged_identity_harness.py

uid-gid-combinations:
	python3 scripts/test_uid_gid_combinations.py

uid-gid-variants:
	python3 scripts/run_uid_gid_variants.py

fail-closed-config:
	cargo build --quiet --bin agb-admin-server
	python3 scripts/test_fail_closed_admin_config.py

admin-rate-limit:
	cargo build --quiet --bin agb-admin-server
	python3 scripts/test_admin_rate_limit.py

admin-operator-spoofing:
	cargo build --quiet --bin agb-admin-server
	python3 scripts/test_admin_operator_spoofing.py

live-bpf-observer:
	python3 scripts/run_live_bpf_observer.py

live-bpf-broker-pipeline:
	python3 scripts/run_live_bpf_broker_pipeline.py
