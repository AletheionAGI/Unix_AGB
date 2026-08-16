.PHONY: test test-python test-rust generate benchmark benchmark-gate2 benchmark-gate2-asm-cm benchmark-gate2-multiseed benchmark-gate2-multiseed-independent capture-independent-events build-independent-candidates build-review-queue build-review-html review-server export-reviewed-corpus freeze-independent-corpus causal-proof live-proof linux-capabilities seccomp-proof bpf-pipeline policy-broker supervise-broker broker-health broker-restart cache-list admin-server identity-probe admin-userns uid-gid-matrix dedicated-accounts privileged-identity uid-gid-combinations uid-gid-variants fail-closed-config admin-rate-limit admin-operator-spoofing live-bpf-observer

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
		--output var/benchmark/gate2-v1-asm-cm-report.json

benchmark-gate2-multiseed:
	PYTHONPATH=python:scripts "$${ASM_PYTHON:-.venv/bin/python}" scripts/benchmark_gate2_multiseed.py \
		--checkpoint "1:$${ASM_CM_SEED1_CHECKPOINT:?set ASM_CM_SEED1_CHECKPOINT}:$${ASM_CM_SEED1_SHA256:?set ASM_CM_SEED1_SHA256}" \
		--checkpoint "2:$${ASM_CM_SEED2_CHECKPOINT:?set ASM_CM_SEED2_CHECKPOINT}:$${ASM_CM_SEED2_SHA256:?set ASM_CM_SEED2_SHA256}" \
		--checkpoint "3:$${ASM_CM_SEED3_CHECKPOINT:?set ASM_CM_SEED3_CHECKPOINT}:$${ASM_CM_SEED3_SHA256:?set ASM_CM_SEED3_SHA256}" \
		--asm-source-root "$${ASM_SOURCE_ROOT:?set ASM_SOURCE_ROOT}" \
		--asm-source-revision "$${ASM_SOURCE_REVISION:?set ASM_SOURCE_REVISION}" \
		--device "$${ASM_DEVICE:-cuda}" \
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
		--output var/benchmark/gate2-independent-multiseed.json

capture-independent-events:
	PYTHONPATH=python:scripts python3 scripts/run_live_bpf_observer.py \
		--duration "$${AGB_CAPTURE_DURATION:-60}" \
		--bpftrace-command "$${AGB_BPFTRACE_COMMAND:-bpftrace}" \
		--target-uid "$${AGB_CAPTURE_UID:--1}" \
		--output-events "$${AGB_CAPTURE_EVENTS:-var/telemetry/bpf-events.jsonl}"

build-independent-candidates:
	PYTHONPATH=python:scripts python3 scripts/build_trajectory_candidates.py \
		--input "$${AGB_CAPTURE_EVENTS:-var/telemetry/bpf-events.jsonl}" \
		--output "$${AGB_CANDIDATES:-var/telemetry/trajectory-candidates.jsonl}" \
		--collector-revision "$${AGB_COLLECTOR_REVISION:-$$(python3 scripts/fingerprint_collector.py)}" \
		--min-events "$${AGB_MIN_TRAJECTORY_EVENTS:-1}" \
		--max-events "$${AGB_MAX_TRAJECTORY_EVENTS:-256}" \
		--coverage-scope "$${AGB_COVERAGE_SCOPE:-system-wide}" \
		--protected-executables "$${AGB_PROTECTED_EXECUTABLES:-}"

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
