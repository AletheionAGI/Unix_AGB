# Persistence

## Gate 0 canonical store

The development backend is append-only JSONL. Each accepted event is serialized
on one line and flushed before the gateway acknowledges it. This provides a
simple auditable artifact, not tamper resistance or transactional durability.

## Runtime state

The fake state engine reconstructs state from accepted events. Future snapshots
must include:

- schema version;
- checkpoint fingerprint;
- configuration fingerprint;
- namespace and state revision;
- last committed event sequence;
- canonical-store revision;
- content checksum.

Restore fails closed on incompatible fingerprints, missing canonical events,
sequence regression, or checksum failure. Reinitialization cannot broaden
privilege.

## Production direction

Before Gate 2 promotion, select and benchmark a transactional or checksummed
backend, define fsync/WAL behavior, implement atomic snapshots, and test crash
points. SQLite is a candidate for local canonical metadata; the choice remains
an ADR rather than an architectural assumption.
