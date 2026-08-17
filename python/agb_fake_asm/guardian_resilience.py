"""Bounded restart and authenticated handoff primitives for the Gate 4 lab."""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import dataclass


@dataclass
class RestartBudget:
    maximum: int
    window_seconds: float
    _attempts: list[float]

    def __init__(self, maximum: int, window_seconds: float) -> None:
        if maximum < 1 or window_seconds <= 0:
            raise ValueError("restart budget must be positive")
        self.maximum = maximum
        self.window_seconds = window_seconds
        self._attempts = []

    def consume(self, now: float | None = None) -> bool:
        current = time.monotonic() if now is None else now
        cutoff = current - self.window_seconds
        self._attempts = [attempt for attempt in self._attempts if attempt > cutoff]
        if len(self._attempts) >= self.maximum:
            return False
        self._attempts.append(current)
        return True


class HandoffAuthenticator:
    def __init__(self, secret: bytes, policy_revision: str, allowed_uid: int, allowed_gid: int) -> None:
        if len(secret) < 32 or not policy_revision:
            raise ValueError("strong secret and policy revision are required")
        self.secret = secret
        self.policy_revision = policy_revision
        self.allowed_uid = allowed_uid
        self.allowed_gid = allowed_gid
        self._used_nonces: set[str] = set()

    def sign(self, *, pid: int, uid: int, gid: int, nonce: str, expires_ns: int) -> dict[str, object]:
        payload = {"pid": pid, "uid": uid, "gid": gid, "nonce": nonce, "expires_ns": expires_ns, "policy_revision": self.policy_revision}
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        return {**payload, "hmac_sha256": hmac.new(self.secret, encoded, hashlib.sha256).hexdigest()}

    def verify(self, message: dict[str, object], *, peer_pid: int, peer_uid: int, peer_gid: int, now_ns: int) -> tuple[bool, str]:
        required = {"pid", "uid", "gid", "nonce", "expires_ns", "policy_revision", "hmac_sha256"}
        if set(message) != required:
            return False, "HANDOFF_FIELDS_INVALID"
        if (peer_uid, peer_gid) != (self.allowed_uid, self.allowed_gid):
            return False, "PEER_NOT_ALLOWLISTED"
        if (message["pid"], message["uid"], message["gid"]) != (peer_pid, peer_uid, peer_gid):
            return False, "PEER_CREDENTIAL_MISMATCH"
        if message["policy_revision"] != self.policy_revision:
            return False, "POLICY_REVISION_MISMATCH"
        if int(message["expires_ns"]) <= now_ns:
            return False, "HANDOFF_EXPIRED"
        nonce = str(message["nonce"])
        if nonce in self._used_nonces:
            return False, "HANDOFF_REPLAY"
        unsigned = {key: message[key] for key in required if key != "hmac_sha256"}
        encoded = json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
        expected = hmac.new(self.secret, encoded, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, str(message["hmac_sha256"])):
            return False, "HANDOFF_HMAC_INVALID"
        self._used_nonces.add(nonce)
        return True, "HANDOFF_AUTHENTICATED"
