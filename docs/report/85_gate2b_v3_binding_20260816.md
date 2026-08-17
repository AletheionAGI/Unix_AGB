# Gate 2B v3 identity-binding result

The v2 relational diagnostic established 100% raw-ID training fit but 50%
generalization, 71.9% head-only fit, and a 100% engineered equality upper bound.
This localizes the failure to relational representation rather than a frozen or
disconnected classifier.

V3 is implemented as a separate diagnostic with raw, trajectory-local,
permutation-augmented, canonical-plus-auxiliary, and explicit-equality arms.
Counterfactual pairing is mandatory in every batch, validation destinations are
disjoint from training, and entity permutation is evaluated explicitly. The
generated chart compares train, new-entity and permuted-ID accuracy and plots
the training curves for all arms.

The completed run found: raw IDs 100% train, 56.25% new entities and 50%
permuted; permutation augmentation remained at 50%; trajectory-local canonical
IDs reached 100% train/new/permuted; canonical plus auxiliary matching also
reached 100%; and the explicit-equality upper bound reached 100%. Canonical IDs
therefore recovered invariant binding without inserting the class or equality
answer into the input.
