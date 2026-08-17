"""Process/artifact binding and fail-closed scoping for enforcement adapters."""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass(frozen=True)
class ArtifactIdentity:
    path: str
    device: int
    inode: int
    sha256: str

    @classmethod
    def from_path(cls, path: Path) -> "ArtifactIdentity":
        resolved = path.resolve(strict=True)
        metadata = resolved.stat()
        return cls(str(resolved), metadata.st_dev, metadata.st_ino, sha256_file(resolved))


@dataclass(frozen=True)
class ProcessIdentity:
    pid: int
    start_time_ns: int
    artifact: ArtifactIdentity

    @classmethod
    def from_pid(cls, pid: int, *, include_hash: bool) -> "ProcessIdentity":
        tgid = process_tgid(pid)
        stat_line = Path(f"/proc/{tgid}/stat").read_text()
        close = stat_line.rfind(")")
        if close < 0:
            raise ValueError("malformed /proc process stat")
        fields_after_comm = stat_line[close + 2 :].split()
        ticks = int(fields_after_comm[19])
        executable = Path(f"/proc/{tgid}/exe").resolve(strict=True)
        metadata = executable.stat()
        artifact = ArtifactIdentity(
            str(executable),
            metadata.st_dev,
            metadata.st_ino,
            sha256_file(executable) if include_hash else "",
        )
        return cls(tgid, ticks * 1_000_000_000 // os.sysconf("SC_CLK_TCK"), artifact)


def process_tgid(pid: int) -> int:
    for line in Path(f"/proc/{pid}/status").read_text().splitlines():
        if line.startswith("Tgid:"):
            return int(line.split()[1])
    raise ValueError("process status has no Tgid")


class ExecutableProcessScope:
    def __init__(self, target_pid: int, expected: ArtifactIdentity) -> None:
        self.target_pid = target_pid
        self.expected = expected
        self.pinned: ProcessIdentity | None = None

    def bind_or_verify(self, identity: ProcessIdentity) -> tuple[bool, str]:
        if identity.pid != self.target_pid:
            return False, "PID_OUT_OF_SCOPE"
        if self.pinned is None:
            if identity.artifact != self.expected:
                return False, "EXECUTABLE_ARTIFACT_MISMATCH"
            self.pinned = identity
            return True, "IDENTITY_PINNED"
        if identity.pid != self.pinned.pid or identity.start_time_ns != self.pinned.start_time_ns:
            return False, "PROCESS_IDENTITY_CHANGED"
        if (
            identity.artifact.path != self.pinned.artifact.path
            or identity.artifact.device != self.pinned.artifact.device
            or identity.artifact.inode != self.pinned.artifact.inode
        ):
            return False, "EXECUTABLE_ARTIFACT_CHANGED"
        return True, "IDENTITY_VERIFIED"


def enforcement_effect(
    policy_effect: str,
    *,
    target_pid: bool,
    adapter_failed: bool,
    timed_out: bool = False,
    overloaded: bool = False,
) -> str:
    if not target_pid:
        return "ALLOW"
    if adapter_failed or timed_out or overloaded or policy_effect == "ABSTAIN":
        return "DENY"
    if policy_effect not in {"ALLOW", "DENY"}:
        raise ValueError("invalid policy effect")
    return policy_effect
