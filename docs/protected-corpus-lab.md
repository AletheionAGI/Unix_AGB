# Protected causal corpus laboratory

The protected laboratory creates real, BPF-observed process trajectories without
touching host configuration, privileged control surfaces, or non-loopback network
destinations. It is an efficacy fixture, not a malware sandbox.

Each `--cases-per-class` value is applied independently to three families:

- `protected-credential-egress`: an untrusted loopback connection precedes a
  protected credential read; the benign twin reads ordinary configuration first.
- `protected-persistence-origin`: a controlled untrusted-origin marker precedes a
  write-open of a laboratory persistence target; the benign twin has the same
  terminal write-open after an ordinary configuration read.
- `protected-admin-origin`: a controlled untrusted-request marker precedes a
  write-open of a laboratory administrative target; the benign twin has the same
  terminal write-open after an ordinary configuration read.

All files live below `var/telemetry/protected-lab`. The persistence and admin
targets are inert regular files. Network activity is TCP loopback to a listener
owned by the orchestrator. File telemetry includes the kernel open flags and a
normalized read/write access mode. The workload remains alive until observation finishes,
so exact process identity can be reconciled without relying on PID alone.

The observer attaches semantic labels only to exact paths supplied by the lab's
collection policy. These labels select an associative relation and policy-query
type; they do not contain or imply the ground-truth class. Benign/malicious labels
are joined later from the PID/family/case handshake and cannot influence capture.
The raw `events.jsonl` remains unmodified.

Run the capture with:

```sh
sudo -v
AGB_BPFTRACE_COMMAND="sudo bpftrace" \
AGB_PROTECTED_LAB_DURATION=25 \
AGB_PROTECTED_LAB_CASES=30 \
make protected-corpus-lab
```

This requests 180 total trajectories: 30 benign and 30 malicious in each of the
three families. The manifest becomes promotion-eligible only when the frozen test
split retains the required class counts and all three families. Eligibility is
not promotion: the multi-seed accuracy and baseline-advantage criteria still apply.

Then run:

```sh
AGB_INDEPENDENT_CORPUS="$PWD/var/telemetry/protected-lab/corpus.jsonl" \
./var/benchmark/run-independent-multiseed.sh
```
