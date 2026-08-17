# Gate 4 control-plane resilience

Date: 2026-08-17

This reversible laboratory proof covers restart budget, authenticated handoff,
policy revision binding, and launcher response to guardian death.

The handoff test used a real Unix `SOCK_SEQPACKET` connection and kernel
`SO_PEERCRED`. A message bound PID, UID, GID, a one-use nonce, monotonic expiry,
and `policy:gate4-egress-guardian-v1` under HMAC-SHA-256. The valid handoff was
accepted; replay of the nonce and a stale policy revision were rejected.

The restart budget allowed two worker restarts in a 60-second window. A third
crash was refused and caused scoped teardown of the disposable protected
process group. An unrelated control process remained alive.

In the guardian-death proof, an external launcher observed injected guardian
exit status 73 and terminated only the protected process group. Launcher
response took 21.636 ms, including a 20 ms `SIGTERM` grace period followed by
`SIGKILL`. The unrelated control process remained alive.

Process groups substitute for delegated cgroups in this proof. The local
artifact is `var/benchmark/gate4-control-plane-resilience.json`. No persistent
service was installed.

Reproduce with `make gate4-control-plane-resilience`.
