import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from vikings_ssh.metadata_store import MetadataStore
from vikings_ssh.models import HostMetadata, ReachabilityResult, Target


class MetadataStoreTests(unittest.TestCase):
    def test_ensure_targets_and_record_reachability(self) -> None:
        with TemporaryDirectory() as tmpdir:
            store = MetadataStore(Path(tmpdir) / "metadata.json")
            target = Target(label="web-1", host="127.0.0.1", port=22, username="root")
            store.ensure_targets([target])
            result = ReachabilityResult(
                target=target,
                reachable=True,
                checked_at="2026-04-13T00:00:00+00:00",
                latency_ms=10.5,
            )

            store.record_reachability(result)
            host = store.get_host(target.key)

        self.assertIsNotNone(host)
        assert host is not None
        self.assertEqual(host.label, "web-1")
        self.assertEqual(host.ssh_username, "root")
        self.assertEqual(host.last_reachable_at, "2026-04-13T00:00:00+00:00")
        self.assertIsNone(host.last_error)

    def test_upsert_preserves_snapshot_ids(self) -> None:
        with TemporaryDirectory() as tmpdir:
            store = MetadataStore(Path(tmpdir) / "metadata.json")
            metadata = HostMetadata(target_key="127.0.0.1:22", snapshot_ids=["snap-1"])

            store.upsert_host(metadata)
            loaded = store.get_host(metadata.target_key)

        self.assertIsNotNone(loaded)
        assert loaded is not None
        self.assertEqual(loaded.snapshot_ids, ["snap-1"])

    def test_record_password_keeps_current_password_and_history(self) -> None:
        with TemporaryDirectory() as tmpdir:
            store = MetadataStore(Path(tmpdir) / "metadata.json")
            target_key = "127.0.0.1:22"

            store.record_password(
                target_key=target_key,
                username="root",
                password="alpha",
                source="manual-change",
                recorded_at="2026-04-13T00:00:00+00:00",
            )
            store.record_password(
                target_key=target_key,
                username="root",
                password="alpha",
                source="manual-change",
                recorded_at="2026-04-13T00:01:00+00:00",
            )
            store.record_password(
                target_key=target_key,
                username="root",
                password="bravo",
                source="manual-change",
                recorded_at="2026-04-13T00:02:00+00:00",
            )
            host = store.get_host(target_key)

        self.assertIsNotNone(host)
        assert host is not None
        self.assertEqual(host.credentials["root"], "bravo")
        self.assertTrue(host.password_material_available)
        self.assertEqual(
            [(entry.username, entry.password, entry.source, entry.recorded_at) for entry in host.password_history],
            [
                ("root", "alpha", "manual-change", "2026-04-13T00:00:00+00:00"),
                ("root", "bravo", "manual-change", "2026-04-13T00:02:00+00:00"),
            ],
        )

    def test_legacy_credentials_seed_history(self) -> None:
        with TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "metadata.json"
            path.write_text(json.dumps({
                "version": 1,
                "hosts": {
                    "web-1:127.0.0.1:22": {
                        "target_key": "web-1:127.0.0.1:22",
                        "credentials": {"root": "legacy-pass"},
                    }
                },
            }), encoding="utf-8")

            store = MetadataStore(path)
            host = store.get_host("127.0.0.1:22")

        self.assertIsNotNone(host)
        assert host is not None
        self.assertEqual(host.target_key, "127.0.0.1:22")
        self.assertEqual(host.label, "web-1")
        self.assertEqual(host.credentials["root"], "legacy-pass")
        self.assertEqual(len(host.password_history), 1)
        self.assertEqual(host.password_history[0].source, "legacy-import")
        self.assertTrue(host.password_material_available)

    def test_clear_credentials_newer_than_removes_invalid_current_passwords(self) -> None:
        with TemporaryDirectory() as tmpdir:
            store = MetadataStore(Path(tmpdir) / "metadata.json")
            target_key = "127.0.0.1:22"
            store.record_password(
                target_key=target_key,
                username="root",
                password="old-pass",
                source="manual-change",
                recorded_at="2026-04-13T00:00:00+00:00",
            )
            store.record_password(
                target_key=target_key,
                username="root",
                password="new-pass",
                source="manual-change",
                recorded_at="2026-04-13T00:10:00+00:00",
            )

            host = store.clear_credentials_newer_than(
                target_key=target_key,
                restored_at="2026-04-13T00:05:00+00:00",
            )

        self.assertEqual(host.credentials, {})
        self.assertTrue(host.password_material_available)
        self.assertEqual(len(host.password_history), 2)

    def test_clear_missing_accounts_prunes_current_credentials(self) -> None:
        with TemporaryDirectory() as tmpdir:
            store = MetadataStore(Path(tmpdir) / "metadata.json")
            target_key = "127.0.0.1:22"
            store.record_password(
                target_key=target_key,
                username="root",
                password="root-pass",
                source="manual-change",
                recorded_at="2026-04-13T00:00:00+00:00",
            )
            store.record_password(
                target_key=target_key,
                username="administrator",
                password="admin-pass",
                source="manual-change",
                recorded_at="2026-04-13T00:01:00+00:00",
            )

            host = store.clear_missing_accounts(
                target_key=target_key,
                usernames_present={"root"},
            )

        self.assertEqual(host.credentials, {"root": "root-pass"})
        self.assertTrue(host.password_material_available)


if __name__ == "__main__":
    unittest.main()
