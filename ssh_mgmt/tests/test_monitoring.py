import socket
import threading
import unittest

from vikings_ssh.models import Target
from vikings_ssh.monitoring import check_target_reachability


class MonitoringTests(unittest.TestCase):
    def test_reachability_check_detects_open_port(self) -> None:
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except PermissionError:
            self.skipTest("socket creation is not permitted in this sandbox")

        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        accepted = threading.Event()

        def _accept_once() -> None:
            try:
                connection, _ = server.accept()
                connection.close()
                accepted.set()
            finally:
                server.close()

        thread = threading.Thread(target=_accept_once, daemon=True)
        thread.start()

        result = check_target_reachability(Target(label="local", host="127.0.0.1", port=port), timeout=1.0)
        thread.join(timeout=1.0)

        self.assertTrue(result.reachable)
        self.assertIsNotNone(result.latency_ms)
        self.assertTrue(accepted.is_set())


if __name__ == "__main__":
    unittest.main()
