"""Deterministic executable-scoped external-network policy."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ExecutableEgressPolicy:
    executable: str
    allow_loopback: bool = True

    def evaluate(self, event: dict[str, Any]) -> dict[str, str]:
        if event.get("operation") != "network.connect":
            return {"effect": "ALLOW", "reason": "NOT_A_CONNECT"}
        if event.get("subject", {}).get("exe") != self.executable:
            return {"effect": "ALLOW", "reason": "EXECUTABLE_OUT_OF_SCOPE"}
        resource = event.get("resource", {})
        family = resource.get("family")
        if family == "AF_UNIX":
            return {"effect": "ALLOW", "reason": "LOCAL_UNIX_SOCKET"}
        address = resource.get("address")
        port = resource.get("port")
        if family not in {"AF_INET", "AF_INET6"} or not isinstance(address, str):
            return {"effect": "ABSTAIN", "reason": "DESTINATION_UNRESOLVED"}
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError:
            return {"effect": "ABSTAIN", "reason": "DESTINATION_INVALID"}
        if parsed.is_unspecified or not isinstance(port, int) or port == 0:
            return {"effect": "ABSTAIN", "reason": "DESTINATION_UNRESOLVED"}
        if self.allow_loopback and parsed.is_loopback:
            return {"effect": "ALLOW", "reason": "LOOPBACK_ALLOWED"}
        return {"effect": "DENY", "reason": "EXECUTABLE_EXTERNAL_NETWORK_DENIED"}
