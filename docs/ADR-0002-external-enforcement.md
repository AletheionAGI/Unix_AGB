# ADR-0002 — External enforcement boundary

Status: accepted for the next prototype

## Decision

Use a deterministic local policy cache at the enforcement boundary and target
Linux seccomp user notification (`SECCOMP_RET_USER_NOTIF`) for the first
external adapter. The AGB policy process may approve or deny a narrowly scoped
operation, but it must not put an LLM or network request in the syscall path.

The first implementation target is a laboratory process that installs a
seccomp notification filter before executing the workload. A broker receives
notifications, looks up a versioned decision, and replies with either the
cached result or a safe fallback. The broker must be fail-closed for the
selected protected operation and fail-safe for unrelated operations.

## Why not claim this today

- Landlock rules are inherited by a process tree and are not a general external
  “attach after the fact” mechanism.
- AppArmor profile reloads require privileged host integration and a separate
  profile lifecycle.
- ptrace can observe and mediate a laboratory process but is not the intended
  production enforcement primitive.

The current `make live-proof` therefore remains explicitly cooperative: the
workload installs a process-local Landlock rule after receiving the shadow
decision. This ADR prevents that experiment from being misreported as a
system-wide enforcement result.

## Laboratory implementation

`make seccomp-proof` exercises the syscall boundary with `libseccomp.so.2`.
The child installs a notification filter before opening the secret, transfers
the listener to a separate broker process, and the broker sends the observed
trajectory to `agb-gateway`. The gateway appends the events, updates the
namespace state, and returns the versioned decision. The broker then sends
either a kernel `EACCES` response or a `CONTINUE` response. The proof is
intentionally limited to `openat` and a disposable file; its gateway records
are retained in `var/seccomp-proof/`.

## Exit criteria

The external adapter is not promoted until it demonstrates, in a disposable
namespace:

1. the filter is installed before the protected operation;
2. identical terminal operations produce ALLOW versus DENY from different
   prior trajectories;
3. denial occurs without cooperation from the target workload;
4. broker restart and timeout follow the documented safe fallback;
5. unrelated file, process, and network operations remain unaffected; and
6. the complete notification, decision, and enforcement records are persisted.
