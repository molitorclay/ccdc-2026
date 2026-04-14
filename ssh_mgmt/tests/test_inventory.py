from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from vikings_ssh.inventory import Inventory, InventoryError
from vikings_ssh.models import Target


class InventoryTests(unittest.TestCase):
    def test_load_supports_label_host_port_only(self) -> None:
        with TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "targets.txt"
            path.write_text(
                "# comment\n"
                "web-1,192.0.2.10,2222\n"
                "db-1,192.0.2.11,22\n",
                encoding="utf-8",
            )

            targets = Inventory(path).load()

        self.assertEqual(len(targets), 2)
        self.assertEqual(targets[0].label, "web-1")
        self.assertEqual(targets[0].host, "192.0.2.10")
        self.assertEqual(targets[0].port, 2222)
        self.assertIsNone(targets[0].username)
        self.assertEqual(targets[1].label, "db-1")
        self.assertEqual(targets[1].host, "192.0.2.11")
        self.assertEqual(targets[1].port, 22)

    def test_invalid_port_raises_error(self) -> None:
        with TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "targets.txt"
            path.write_text("web-1,192.0.2.10,abc\n", encoding="utf-8")

            with self.assertRaises(InventoryError):
                Inventory(path).load()

    def test_invalid_field_count_raises_error(self) -> None:
        with TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "targets.txt"
            path.write_text("192.0.2.10,22\n", encoding="utf-8")

            with self.assertRaises(InventoryError):
                Inventory(path).load()


    def test_append_target_preserves_existing_content_and_adds_line(self) -> None:
        with TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "targets.txt"
            path.write_text(
                "# existing comment\nweb-1,192.0.2.10,22\n",
                encoding="utf-8",
            )

            inventory = Inventory(path)
            inventory.append_target(Target(label="db-1", host="192.0.2.11", port=2222))

            text = path.read_text(encoding="utf-8")

        self.assertEqual(
            text,
            "# existing comment\nweb-1,192.0.2.10,22\ndb-1,192.0.2.11,2222\n",
        )

    def test_append_target_handles_missing_trailing_newline(self) -> None:
        with TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "targets.txt"
            path.write_text("web-1,192.0.2.10,22", encoding="utf-8")

            Inventory(path).append_target(Target(label="db-1", host="192.0.2.11", port=22))

            text = path.read_text(encoding="utf-8")

        self.assertEqual(text, "web-1,192.0.2.10,22\ndb-1,192.0.2.11,22\n")

    def test_append_target_rejects_duplicate_host_port(self) -> None:
        with TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "targets.txt"
            path.write_text("web-1,192.0.2.10,22\n", encoding="utf-8")

            with self.assertRaises(InventoryError):
                Inventory(path).append_target(
                    Target(label="duplicate", host="192.0.2.10", port=22)
                )

    def test_append_target_rejects_comma_in_label(self) -> None:
        with TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "targets.txt"

            with self.assertRaises(InventoryError):
                Inventory(path).append_target(
                    Target(label="bad,label", host="192.0.2.10", port=22)
                )


if __name__ == "__main__":
    unittest.main()
