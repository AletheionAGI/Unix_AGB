# Event model

Gate 0 accepts synthetic events over newline-delimited JSON. The controlled
vertical slice additionally accepts `ptrace` observations and
`agent-broker` requests. Gate 1 will replace these laboratory producers with a
kernel-derived collector while preserving the normalized contract.

## Initial operation classes

- `process.exec`
- `process.exit`
- `file.open`
- `network.connect`
- `identity.change`

## Ordering

`sequence` is a monotonically increasing unsigned integer within one security
namespace. Wall-clock time is descriptive; ordering uses sequence plus
`monotonic_ns`. A gap marks state untrusted until an explicit resync policy is
applied.

## Provenance

Gate 0 provenance source is `synthetic`. The laboratory observer uses `ptrace`,
and its cooperative authorization point uses `agent-broker`. Future production
sources include `bpf` and `audit`. Source-specific data belongs under
`provenance.attributes` and must not overwrite normalized identity fields.

`result: "requested"` identifies a pre-authorization request. It must be
followed by an observed `allowed`, `denied`, or `failed` outcome when an
enforcement experiment claims an OS result.

## Minimization

The gateway should collect identifiers and security-relevant metadata, not
arbitrary file content, packet payload, secrets, or prompt bodies. Sensitive
payload resolution is a separate authorized operation.
