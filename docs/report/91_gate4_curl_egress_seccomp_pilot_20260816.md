# Gate 4 curl egress seccomp pilot

The executable-scoped egress pilot completed successfully without installing a
system-wide policy. A seccomp-user-notify filter existed only in a disposable
`/usr/bin/curl` process tree and was destroyed at process exit.

The loopback case reached `127.0.0.1` and exited zero. Unix-domain lookups and
the local resolver at `127.0.0.53:53` were allowed. The external case targeting
`https://example.com` exited with curl status 7 after the broker returned
`EACCES` for decoded IPv4 and IPv6 destinations on port 443.

The external run recorded ten applied denials. Destinations included
`172.66.147.243`, `104.20.23.154`, `2606:4700:10::6814:179a`, and
`2606:4700:10::ac42:93f3`. Two `AF_UNSPEC` operations were conservatively denied
after the deterministic policy abstained. Ownership of an address is not used
as evidence of malicious intent; this pilot tests an operator-selected
executable restriction.

The first implementation exposed an ABI defect: its `seccomp_notif` structure
was 72 bytes instead of the Linux ABI's 80 bytes. The kernel correctly rejected
it with `EINVAL`. A regression test now verifies both the structure size and
all six syscall arguments.

The first successful run discarded 79 stale-listener wakeups in the loopback
process and 86 in the external process after `SECCOMP_IOCTL_NOTIF_RECV`
returned `ENOENT`. They produced no policy decision or enforcement record. The
counter represented repeated readiness while process completion had not yet
been observed, rather than 165 distinct syscalls.

A follow-up changed the broker to monitor the listener and an explicit child
status channel together, prioritizing the terminal status handshake. Repeating
the complete pilot preserved loopback success and external `EACCES` denial while
reducing stale notifications from 79/86 to 0/0. The current evidence artifact
contains this corrected run.

Evidence is stored locally at
`var/benchmark/gate4-curl-egress-pilot.json`. The report records
`system_wide_changes: false` and rollback by destruction of the filtered
process tree and listener.
