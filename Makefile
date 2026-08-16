.PHONY: test test-python test-rust generate benchmark causal-proof live-proof linux-capabilities seccomp-proof bpf-pipeline policy-broker supervise-broker broker-health broker-restart cache-list admin-server identity-probe admin-userns uid-gid-matrix dedicated-accounts

test: test-python test-rust

test-python:
	PYTHONPATH=python:scripts python3 -m unittest discover -s tests -v

test-rust:
	cargo test

generate:
	python3 scripts/generate_synthetic_events.py

benchmark:
	PYTHONPATH=python:scripts python3 scripts/benchmark_synthetic.py

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
