.PHONY: test test-python test-rust generate benchmark causal-proof live-proof linux-capabilities seccomp-proof bpf-pipeline

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
	cargo build --quiet --bin agb-gateway
	python3 scripts/run_seccomp_broker_proof.py

bpf-pipeline:
	cargo build --quiet --bin agb-gateway
	python3 scripts/run_bpf_gateway_pipeline.py --input fixtures/events/bpf-sample.txt
