import importlib.util
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    loaded = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(loaded)
    return loaded


writer = module("gate4_cache_writer", ROOT / "scripts/write_gate4_gate3_cache.py")
runtime = module("gate4_cache_runtime", ROOT / "deploy/agb_gate3_runtime.py")


class Gate4ServiceFixtureTests(unittest.TestCase):
    def test_controlled_writer_is_accepted_by_runtime(self):
        secret = b"controlled-service-fixture-secret!!"
        document = writer.snapshot("process:test", secret, 200)
        entries = runtime.authenticated_entries(
            __import__("json").dumps(document, separators=(",", ":")).encode(),
            secret,
            writer.REVISION,
        )
        self.assertEqual(entries[0]["namespace_id"], "process:test")
        self.assertEqual(entries[0]["effect"], "DENY")

    def test_empty_rotation_is_authenticated(self):
        secret = b"controlled-service-fixture-secret!!"
        document = writer.snapshot(None, secret, 200)
        entries = runtime.authenticated_entries(
            __import__("json").dumps(document, separators=(",", ":")).encode(),
            secret,
            writer.REVISION,
        )
        self.assertEqual(entries, [])


if __name__ == "__main__":
    unittest.main()
