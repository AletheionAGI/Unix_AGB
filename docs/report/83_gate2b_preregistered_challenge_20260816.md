# Gate 2B preregistered causal-generalization challenge

Date: 2026-08-16

The repository now contains an unexecuted Gate 2B protocol designed to test,
and potentially refute, the scientific need for ASM-CM. The hypothesis,
five-percentage-point thresholds, three-seed requirement, false-positive bound,
and negative-result interpretation are frozen in
`docs/gate2b-causal-generalization.md`.

The deterministic generator emits abstract entity IDs and relations R0–R5/RN
at causal distances 4, 16, 64, 256 and 1024. It writes calibration/validation
and test records to physically separate files, commits both hashes in one
manifest, rejects structural signatures crossing splits, and hides family F2
from calibration. The model input terminates in a neutral query token; class
labels are never encoded in the event tokens.

Implemented controls are a bounded FSM, bounded CEP graph, sliding window,
conventional score and learned GRU. The baseline freezer has no test-corpus
argument. The ASM trainer likewise accepts only the public corpus and refuses
to run unless its hash matches the already-frozen baseline report. Candidate
checkpoints record dataset and baseline fingerprints plus `test_seen: false`.
The final evaluator is the only component accepting the sealed test path and
requires exactly three fingerprinted candidates.

Development validation generated 640 trajectories without structural leakage:
160 calibration, 160 validation, 160 held-out composition and 160 hidden
family. Public SHA-256 was
`812c8df63de5c174ecde026374ace3e8392f632ba3e7c768f04010aa2697478e`;
sealed-test SHA-256 was
`791671b5f99427c8274c71b07fa1857d1960a4123dbab7353baf6c49abe03f3e`.
These are development-corpus fingerprints, not scientific results.

The promoted ASM-CM checkpoints were inspected without training: vocabulary
size is 256 and durable fast-weight addressable memory is active, so the neutral
uint8 protocol is representable without changing the model architecture.
No ASM weights were updated and no test labels were evaluated during this work.
The operator-side runner is `scripts/run_gate2b_multiseed_training.sh`.
