# Gate 2B v5 canonical ensemble

V4 remains formally unsupported because canonical seed 3 produced one false
positive among 80 benign trajectories in each split (1.25% versus a 1% limit).
V5 is a post-hoc correction and does not revise that verdict.

Before opening a fresh seed-20260818 test, V5 freezes all six v4 checkpoint
hashes and declares a canonical 2-of-3 DENY vote. It reports every member,
ensemble accuracy/FPR/recall, and disagreement as enforcement telemetry. The
original baselines and thresholds remain unchanged. No retraining occurs. The
final JSON and PNG compare the ensemble, best individual seed and best baseline.

Run `./scripts/run_gate2b_v5_ensemble.sh`. A completed report is protected from
accidental overwrite; an explicit replay requires `AGB_GATE2B_V5_ALLOW_REPLAY=1`.
