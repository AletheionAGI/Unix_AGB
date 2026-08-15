# Security namespaces

Every event and state update belongs to one explicit namespace.

```text
host:<machine-id>
user:<uid>
process:<boot-id>:<pid>:<start-time-ns>
service:<systemd-unit>
container:<container-id>
agent:<agent-id>
tenant:<tenant-id>
session:<session-id>
```

Gate 0 implements process namespaces and treats namespace strings as opaque
after validating their prefix and non-empty stable components.

PID alone is never a valid process namespace. Derived signals may be copied to
a parent namespace only through an explicit policy; state objects are not
implicitly shared.

Queries require an exact namespace match. Cross-namespace retrieval is rejected
and audited even when both namespaces belong to the same operating-system user.
