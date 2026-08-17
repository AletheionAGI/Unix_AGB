# Gate 2B v2 diagnostic result

Gate 2B v1 produced a valid negative result: bounded FSM/CEP accuracy was 80%,
while the three ASM-CM seeds remained close to chance and incurred much higher
latency. The final v1 artifacts remain unchanged under `var/benchmark/`.

A separate diagnostic protocol now gates long-range experimentation on minimum
capacity tests with 2, 8 and 32 examples. It adds balanced batches, a two-logit
classification objective, aggregated loss and gradient telemetry, train
confusion/confidence, parameter-movement proxy, and a distance-by-distance
causal ladder. The sealed v1 test is not an input to this workflow.

The follow-up relational phase reuses the completed capacity/ladder report and
adds fixed-composition counterfactual pairs, globally permuted entity IDs,
full-model versus new-head/frozen-encoder training, and a clearly labeled
engineered equality upper bound. Its chart adds the missing causal-ladder panel.

The v1 comparison chart layout was also corrected: its explanatory note and
two-row legend now occupy separate footer regions and no longer overlap.

The GPU run passed all minimum-capacity checks: 2, 8 and 32 examples reached
100% training accuracy in 50, 100 and 350 steps. Every causal-ladder stage also
fit to 100%, including distance 1024, but validation remained near chance
(34.4% at 1024) with high confidence. Full fine-tuning on raw IDs reached 100%
training and 50% new-entity/permuted accuracy; a new head over a frozen encoder
reached only 71.9% training; the engineered equality upper bound reached 100%.
This localized the v1 failure to relational representation/generalization.
