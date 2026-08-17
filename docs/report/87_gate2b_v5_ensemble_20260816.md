# Gate 2B v5 ensemble confirmation result

V5 freezes the completed v4 models and tests a predeclared canonical 2-of-3
ensemble on a new physical split. Disagreement is retained as telemetry, all
individual results remain visible, and v4 is not retroactively promoted.

The new test (`sha256
3bf521f24fb330632ed182e7a01420d11ffe9023f7230659313388a7d6d9292f`)
confirmed the frozen mechanism. The ensemble achieved 100% accuracy, precision
and recall, zero false positives and zero false negatives on both composition
and hidden-family splits and at every distance through 1024. All seven criteria
passed. Seed 3 again produced one isolated false positive per split; disagreement
was 1/160 (0.625%) per split, and majority voting corrected both without losing
an attack. This supports the post-hoc ensemble hypothesis within the same
synthetic generator family; it does not retroactively change the v4 verdict or
establish performance on natural unknown attacks.
