import importlib.machinery
import importlib.util
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def launcher_module():
    path = ROOT / "deploy/agb-egress-launch"
    loader = importlib.machinery.SourceFileLoader("agb_egress_launch_test", str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


class Gate4LauncherTests(unittest.TestCase):
    def test_control_readiness_wait_is_bounded(self):
        launcher = launcher_module()
        with tempfile.TemporaryDirectory() as directory:
            started = time.monotonic()
            with self.assertRaises(TimeoutError):
                launcher.connect_control(str(Path(directory) / "missing.sock"), .03)
            self.assertLess(time.monotonic() - started, .2)

    def test_control_readiness_accepts_delayed_socket(self):
        launcher = launcher_module()
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "control.sock")
            ready = threading.Event()

            def server():
                time.sleep(.03)
                listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
                listener.bind(path)
                listener.listen(1)
                ready.set()
                peer, _ = listener.accept()
                peer.close()
                listener.close()

            worker = threading.Thread(target=server)
            worker.start()
            channel = launcher.connect_control(path, .5)
            channel.close()
            worker.join()
            self.assertTrue(ready.is_set())


if __name__ == "__main__":
    unittest.main()
