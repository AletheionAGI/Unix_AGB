import array
import os
import socket
import unittest

from run_gate4_listener_guardian import receive_handoff


class ListenerGuardianTests(unittest.TestCase):
    def test_handoff_transfers_exactly_one_working_descriptor(self):
        sender, receiver = socket.socketpair(type=socket.SOCK_SEQPACKET)
        read_fd, write_fd = os.pipe()
        try:
            sender.sendmsg([b"listener"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [write_fd]))])
            received_fd = receive_handoff(receiver)
            try:
                os.write(received_fd, b"G")
                self.assertEqual(os.read(read_fd, 1), b"G")
            finally:
                os.close(received_fd)
        finally:
            os.close(read_fd)
            os.close(write_fd)
            sender.close()
            receiver.close()


if __name__ == "__main__":
    unittest.main()
