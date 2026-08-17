import tempfile
import unittest
from pathlib import Path

from agb_fake_asm.enforcement_scope import (
    ArtifactIdentity,
    ExecutableProcessScope,
    ProcessIdentity,
    enforcement_effect,
    process_tgid,
)


class EnforcementScopeTests(unittest.TestCase):
    def artifact(self, inode=10, digest="a" * 64):
        return ArtifactIdentity("/usr/bin/tool", 8, inode, digest)

    def identity(self, pid=42, start=100, inode=10, digest="a" * 64):
        return ProcessIdentity(pid, start, self.artifact(inode, digest))

    def test_pid_reuse_is_rejected_after_binding(self):
        scope = ExecutableProcessScope(42, self.artifact())
        self.assertTrue(scope.bind_or_verify(self.identity())[0])
        self.assertEqual(scope.bind_or_verify(self.identity(start=101)), (False, "PROCESS_IDENTITY_CHANGED"))

    def test_inode_or_hash_replacement_is_rejected(self):
        scope = ExecutableProcessScope(42, self.artifact())
        self.assertEqual(scope.bind_or_verify(self.identity(inode=11))[1], "EXECUTABLE_ARTIFACT_MISMATCH")
        self.assertEqual(scope.bind_or_verify(self.identity(digest="b" * 64))[1], "EXECUTABLE_ARTIFACT_MISMATCH")

    def test_symlink_resolves_to_same_artifact(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); binary = root / "binary"; link = root / "link"
            binary.write_bytes(b"safe"); link.symlink_to(binary)
            self.assertEqual(ArtifactIdentity.from_path(binary), ArtifactIdentity.from_path(link))

    def test_fail_closed_is_limited_to_target_pid(self):
        self.assertEqual(enforcement_effect("ABSTAIN", target_pid=True, adapter_failed=False), "DENY")
        self.assertEqual(enforcement_effect("ALLOW", target_pid=True, adapter_failed=True), "DENY")
        self.assertEqual(enforcement_effect("ABSTAIN", target_pid=False, adapter_failed=True), "ALLOW")
        self.assertEqual(
            enforcement_effect("ALLOW", target_pid=True, adapter_failed=False, timed_out=True),
            "DENY",
        )
        self.assertEqual(
            enforcement_effect("ALLOW", target_pid=True, adapter_failed=False, overloaded=True),
            "DENY",
        )
        self.assertEqual(
            enforcement_effect(
                "ALLOW", target_pid=False, adapter_failed=True, timed_out=True, overloaded=True
            ),
            "ALLOW",
        )

    def test_real_file_replacement_changes_artifact_binding(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "tool"
            path.write_bytes(b"first")
            first = ArtifactIdentity.from_path(path)
            path.write_bytes(b"second")
            content_changed = ArtifactIdentity.from_path(path)
            self.assertNotEqual(first.sha256, content_changed.sha256)
            replacement = Path(directory) / "replacement"
            replacement.write_bytes(b"first")
            replacement.replace(path)
            inode_changed = ArtifactIdentity.from_path(path)
            self.assertNotEqual(first.inode, inode_changed.inode)

    def test_thread_is_mapped_to_process_group_identity(self):
        import os
        self.assertEqual(process_tgid(os.getpid()), os.getpid())


if __name__ == "__main__":
    unittest.main()
