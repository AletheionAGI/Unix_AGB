# Grouped audit and reversible Gate 4 denial

Date: 2026-08-16

Gate 3 now separates audit durability by effect without weakening the deny-only
cache boundary. `ALLOW` and `ABSTAIN` records may share a configurable group
`fsync`; a `DENY` always flushes and calls `sync_data` before it can be compiled.
The CLI synchronizes any remaining audit records before successful shutdown and
writes the authenticated cache snapshot only when a new `DENY` was compiled.

A CPU integration rerun with groups of 64 preserved TN=70, TP=71, FP=0, FN=0,
987 audit records, and 71 deny-only cache entries. Gate 3 audit/cache latency
fell from 4.802 ms to 0.252 ms p50 in this environment. The p95 still includes
neural inference and mandatory deny persistence. This CPU comparison is an
implementation check, not a replacement for the CUDA evidence in report 81.

The first Gate 4 pilot creates one temporary marker and one exact process
identity. Gate 3 durably audits and compiles a two-second `DENY`, after which a
small bridge supplies that decision to the existing process-local Landlock
workload. The protected open failed with `EACCES` (errno 13). After cache expiry,
the restricted process was terminated and a clean instance successfully opened
the same marker, proving the stated rollback mechanism.

The denial cannot be removed from the original process because Landlock is
monotonic. “Reversible” therefore means bounded process teardown and clean
restart, not relaxation inside a running process. The harness targets no system
path, performs no system-wide policy change, and cannot accept TTLs above ten
seconds. The local result hash is
`8406fd427da4bb98bd4bd1ba63c5d5591d9206959769efbfc78e857bfb331366`;
the path-independent summary is in
`fixtures/benchmark/evidence/gate4-reversible-denial-summary.json`.

This proves a narrow controlled denial only. It does not establish safe
production enforcement, crash recovery during a pending denial, notification
semantics, or a persistent external enforcement daemon.
