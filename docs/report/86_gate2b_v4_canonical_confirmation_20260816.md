# Gate 2B v4 canonical confirmation result

The v3 probe established that trajectory-local canonical IDs reached 100% on
new and globally permuted entities, whereas raw IDs and permutation augmentation
remained near chance. V4 turns that finding into a fresh multi-distance,
multi-seed confirmatory protocol.

The implementation preserves the baseline families and original thresholds but
uses a new physically separated test because v1 has already been observed. Raw
and canonical ASM-CM are trained symmetrically for three seeds. The final
evaluator requires all six fingerprinted checkpoints and records canonicalizer
implementation hash and mean preprocessing latency.

The fresh run confirmed the representation effect. Raw seeds remained between
45.6% and 53.1% on the test splits. Canonical seeds 1 and 2 reached 100%; seed 3
reached 99.375%, with one false positive among 80 benign trajectories in each
split. Every canonical seed reached 100% at distances 256 and 1024. Median
canonicalization cost was 57.2 microseconds per trajectory (232.4 microseconds
mean). The preregistered v4 verdict remains unsupported because seed 3 FPR was
1.25%, 0.25 percentage point above the 1% limit. No v4 criterion was changed.
