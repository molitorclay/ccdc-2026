from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from vikings_ssh.snapshots import SnapshotStore


class SnapshotStoreTests(unittest.TestCase):
    def test_create_and_list_snapshot(self) -> None:
        with TemporaryDirectory() as tmpdir:
            root = Path(tmpdir) / "snapshots"
            store = SnapshotStore(root=root, blob_dir=root / "blobs", index_file=root / "index.json")

            entry = store.create_snapshot(
                target_key="web-1:127.0.0.1:22",
                source_path="/etc/passwd",
                contents="root:x:0:0:root:/root:/bin/bash\n",
                reason="manual",
                mode="644",
                owner_uid=0,
                owner_gid=0,
            )
            entries = store.list_snapshots()

        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].snapshot_id, entry.snapshot_id)
        self.assertEqual(entries[0].target_key, "127.0.0.1:22")
        self.assertEqual(entries[0].source_path, "/etc/passwd")
        self.assertEqual(entries[0].mode, "644")
        self.assertEqual(entries[0].owner_uid, 0)
        self.assertEqual(entries[0].owner_gid, 0)

    def test_read_snapshot_contents_validates_blob(self) -> None:
        with TemporaryDirectory() as tmpdir:
            root = Path(tmpdir) / "snapshots"
            store = SnapshotStore(root=root, blob_dir=root / "blobs", index_file=root / "index.json")
            entry = store.create_snapshot(
                target_key="127.0.0.1:22",
                source_path="/etc/passwd",
                contents="hello\n",
                reason="manual",
            )

            contents = store.read_snapshot_contents(entry.snapshot_id)

        self.assertEqual(contents, "hello\n")

    def test_legacy_index_migrates_target_keys(self) -> None:
        with TemporaryDirectory() as tmpdir:
            root = Path(tmpdir) / "snapshots"
            root.mkdir(parents=True, exist_ok=True)
            index_file = root / "index.json"
            index_file.write_text(
                '{"version": 1, "snapshots": [{"snapshot_id": "snap1", "target_key": "web-1:127.0.0.1:22", '
                '"source_path": "/etc/passwd", "reason": "manual", "created_at": "2026-04-13T00:00:00+00:00", '
                '"blob_path": "blobs/snap1.txt", "sha256": "abc", "size_bytes": 1}]}',
                encoding="utf-8",
            )
            store = SnapshotStore(root=root, blob_dir=root / "blobs", index_file=index_file)

            entries = store.list_snapshots(target_key="127.0.0.1:22")

        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].target_key, "127.0.0.1:22")


if __name__ == "__main__":
    unittest.main()
