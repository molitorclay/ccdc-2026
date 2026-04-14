import sys
import types
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

if "paramiko" not in sys.modules:
    paramiko = types.ModuleType("paramiko")
    ssh_exception = types.ModuleType("paramiko.ssh_exception")

    class _AuthenticationException(Exception):
        pass

    class _NoValidConnectionsError(Exception):
        pass

    class _SSHException(Exception):
        pass

    class _Transport:
        _preferred_kex: list[str] = []
        _preferred_ciphers: list[str] = []
        _preferred_macs: list[str] = []
        _preferred_keys: list[str] = []

    class _SSHClientStub:
        pass

    class _AutoAddPolicy:
        pass

    class _RSAKey:
        @staticmethod
        def from_private_key_file(_path: str) -> object:
            return object()

    ssh_exception.AuthenticationException = _AuthenticationException
    ssh_exception.NoValidConnectionsError = _NoValidConnectionsError
    ssh_exception.SSHException = _SSHException
    paramiko.ssh_exception = ssh_exception
    paramiko.Transport = _Transport
    paramiko.SSHClient = _SSHClientStub
    paramiko.AutoAddPolicy = _AutoAddPolicy
    paramiko.RSAKey = _RSAKey
    sys.modules["paramiko"] = paramiko
    sys.modules["paramiko.ssh_exception"] = ssh_exception

from vikings_ssh.app import App
from vikings_ssh.config import AppPaths
from vikings_ssh.inventory import InventoryError
from vikings_ssh.models import ReachabilityResult, SnapshotEntry
from vikings_ssh.password_audit import ShadowEntry
from vikings_ssh.models import Target
from vikings_ssh.ssh import SSHError


class _FakeAuditClient:
    def __init__(self, username: str = "root", password: str | None = "login-pass") -> None:
        self.username = username
        self.password = password

    def connect(self) -> None:
        return None

    def read_file(self, _path: str) -> str:
        return "shadow-data"

    def close(self) -> None:
        return None


class _FakeSSHClient:
    instances: list["_FakeSSHClient"] = []

    def __init__(
        self,
        host: str,
        port: int = 22,
        username: str = "root",
        password: str | None = None,
        key_filename: str | None = None,
        connect_timeout: float = 10.0,
    ) -> None:
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.key_filename = key_filename
        self.connect_timeout = connect_timeout
        _FakeSSHClient.instances.append(self)

    def connect(self) -> None:
        return None

    def close(self) -> None:
        return None


class _FakeSequencedSSHClient(_FakeSSHClient):
    connect_results: list[Exception | None] = []

    def connect(self) -> None:
        if _FakeSequencedSSHClient.connect_results:
            result = _FakeSequencedSSHClient.connect_results.pop(0)
            if result is not None:
                raise result
        return None


class _FakeRestoreClient:
    def __init__(self, username: str = "root", password: str | None = "login-pass") -> None:
        self.username = username
        self.password = password
        self.writes: list[tuple[str, str, str]] = []
        self.commands: list[str] = []

    def connect(self) -> None:
        return None

    def close(self) -> None:
        return None

    def run(self, _command: str, timeout: float = 30.0) -> object:
        class _Result:
            ok = False
            stdout = ""

        return _Result()

    def write_file_stdin(self, remote_path: str, contents: str, mode: str = "600") -> None:
        self.writes.append((remote_path, contents, mode))

    def run_checked(self, command: str, timeout: float = 30.0) -> str:
        self.commands.append(command)
        return ""


class AppTests(unittest.TestCase):
    def test_generate_keypair_creates_managed_rsa_key_material(self) -> None:
        with TemporaryDirectory() as tmpdir:
            app = App(AppPaths.from_root(Path(tmpdir)))

            public_key = app.generate_keypair(comment="test-key")

            self.assertTrue(public_key.startswith("ssh-rsa "))
            self.assertTrue(app.paths.identity_file.exists())
            self.assertTrue(app.paths.identity_pub_file.exists())
            self.assertEqual(app.paths.identity_file.name, "id_rsa")
            self.assertEqual(app.paths.identity_pub_file.name, "id_rsa.pub")
            self.assertIn(public_key, app.paths.authorized_keys_file.read_text(encoding="utf-8"))

    def test_deep_audit_remembers_login_password_for_followup_rotation(self) -> None:
        with TemporaryDirectory() as tmpdir:
            app = App(AppPaths.from_root(Path(tmpdir)))
            target = Target(label="hannah", host="192.0.2.10", port=22, username="root")
            fake_client = _FakeAuditClient(username="root", password="login-pass")

            with (
                patch.object(app, "_connect_client", return_value=fake_client),
                patch("vikings_ssh.app.parse_shadow_entries", return_value=[ShadowEntry("administrator", "hash")]),
                patch("vikings_ssh.app.verify_shadow_password", return_value=True),
            ):
                results = app.deep_audit_passwords([target], candidate_password="candidate-password")

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].ssh_username, "root")
        self.assertEqual(results[0].ssh_password, "login-pass")
        self.assertEqual(results[0].matched_accounts, ["administrator"])

    def test_rotate_passwords_can_reuse_prompted_login_credentials(self) -> None:
        with TemporaryDirectory() as tmpdir:
            app = App(AppPaths.from_root(Path(tmpdir)))
            target = Target(label="hannah", host="192.0.2.10", port=22, username="root")
            _FakeSSHClient.instances.clear()

            with (
                patch("vikings_ssh.app.SSHClient", _FakeSSHClient),
                patch("vikings_ssh.app.generate_passphrase", return_value="rotated-pass"),
                patch("vikings_ssh.app.change_password"),
                patch.object(app, "_snapshot_remote_file"),
            ):
                rotated = app.rotate_passwords(
                    target,
                    username="root",
                    current_password=None,
                    usernames_to_rotate=["administrator"],
                    credential_prompt=lambda _target: ("root", "login-pass"),
                )

        self.assertEqual(rotated, {"administrator": "rotated-pass"})
        self.assertEqual(len(_FakeSSHClient.instances), 1)
        self.assertEqual(_FakeSSHClient.instances[0].username, "root")
        self.assertEqual(_FakeSSHClient.instances[0].password, "login-pass")

    def test_restore_snapshots_restores_selected_files_in_safe_order(self) -> None:
        with TemporaryDirectory() as tmpdir:
            app = App(AppPaths.from_root(Path(tmpdir)))
            target = Target(label="hannah", host="192.0.2.10", port=22, username="root")
            passwd = app.snapshots.create_snapshot(
                target_key=target.key,
                source_path="/etc/passwd",
                contents="passwd-contents\n",
                reason="pre-password-change",
                mode="644",
                owner_uid=0,
                owner_gid=0,
            )
            shadow = app.snapshots.create_snapshot(
                target_key=target.key,
                source_path="/etc/shadow",
                contents="shadow-contents\n",
                reason="pre-password-change",
                mode="600",
                owner_uid=0,
                owner_gid=0,
            )
            fake_client = _FakeRestoreClient()

            with patch.object(app, "_connect_client", return_value=fake_client):
                with patch.object(
                    app,
                    "_snapshot_remote_file",
                    side_effect=[
                        SnapshotEntry(
                            snapshot_id="backup-passwd",
                            target_key=target.key,
                            source_path="/etc/passwd",
                            reason="pre-restore",
                            created_at="2026-04-13T00:00:00+00:00",
                            blob_path="blobs/backup-passwd.txt",
                            sha256="abc",
                            size_bytes=1,
                        ),
                        SnapshotEntry(
                            snapshot_id="backup-shadow",
                            target_key=target.key,
                            source_path="/etc/shadow",
                            reason="pre-restore",
                            created_at="2026-04-13T00:00:01+00:00",
                            blob_path="blobs/backup-shadow.txt",
                            sha256="def",
                            size_bytes=1,
                        ),
                    ],
                ):
                    results = app.restore_snapshots(
                        target,
                        snapshot_ids=[shadow.snapshot_id, passwd.snapshot_id],
                    )

        self.assertEqual(
            fake_client.writes,
            [
                ("/etc/passwd", "passwd-contents\n", "644"),
                ("/etc/shadow", "shadow-contents\n", "600"),
            ],
        )
        self.assertEqual([item.snapshot_id for item in results], [passwd.snapshot_id, shadow.snapshot_id])
        self.assertTrue(all(item.restored for item in results))
        self.assertIn("chown 0:0 -- '/etc/passwd'", fake_client.commands[0])
        self.assertIn("chown 0:0 -- '/etc/shadow'", fake_client.commands[1])

    def test_restore_snapshots_rejects_duplicate_file_selection(self) -> None:
        with TemporaryDirectory() as tmpdir:
            app = App(AppPaths.from_root(Path(tmpdir)))
            target = Target(label="hannah", host="192.0.2.10", port=22, username="root")
            first = app.snapshots.create_snapshot(
                target_key=target.key,
                source_path="/etc/passwd",
                contents="passwd-a\n",
                reason="manual",
            )
            second = app.snapshots.create_snapshot(
                target_key=target.key,
                source_path="/etc/passwd",
                contents="passwd-b\n",
                reason="manual",
            )

            with self.assertRaises(ValueError):
                app.restore_snapshots(target, snapshot_ids=[first.snapshot_id, second.snapshot_id])

    def test_restore_shadow_snapshot_clears_newer_current_passwords(self) -> None:
        with TemporaryDirectory() as tmpdir:
            app = App(AppPaths.from_root(Path(tmpdir)))
            target = Target(label="hannah", host="192.0.2.10", port=22, username="root")
            app.metadata.record_password(
                target_key=target.key,
                username="administrator",
                password="new-pass",
                source="manual-change",
                recorded_at="2099-04-13T00:10:00+00:00",
            )
            shadow = app.snapshots.create_snapshot(
                target_key=target.key,
                source_path="/etc/shadow",
                contents="administrator:$6$restored:20000:0:99999:7:::\n",
                reason="pre-password-change",
            )
            fake_client = _FakeRestoreClient()

            with patch.object(app, "_connect_client", return_value=fake_client):
                with patch.object(app, "_snapshot_remote_file", return_value=None):
                    results = app.restore_snapshots(target, snapshot_ids=[shadow.snapshot_id])

            host = app.metadata.get_host(target.key)

        assert host is not None
        self.assertEqual(results[0].source_path, "/etc/shadow")
        self.assertEqual(host.credentials, {})
        self.assertEqual(len(host.password_history), 1)

    def test_restore_passwd_snapshot_prunes_accounts_missing_from_restored_file(self) -> None:
        with TemporaryDirectory() as tmpdir:
            app = App(AppPaths.from_root(Path(tmpdir)))
            target = Target(label="hannah", host="192.0.2.10", port=22, username="root")
            app.metadata.record_password(
                target_key=target.key,
                username="root",
                password="root-pass",
                source="manual-change",
                recorded_at="2026-04-13T00:00:00+00:00",
            )
            app.metadata.record_password(
                target_key=target.key,
                username="administrator",
                password="admin-pass",
                source="manual-change",
                recorded_at="2026-04-13T00:01:00+00:00",
            )
            passwd = app.snapshots.create_snapshot(
                target_key=target.key,
                source_path="/etc/passwd",
                contents="root:x:0:0:root:/root:/bin/bash\n",
                reason="manual",
            )
            fake_client = _FakeRestoreClient()

            with patch.object(app, "_connect_client", return_value=fake_client):
                with patch.object(app, "_snapshot_remote_file", return_value=None):
                    app.restore_snapshots(target, snapshot_ids=[passwd.snapshot_id])

            host = app.metadata.get_host(target.key)

        assert host is not None
        self.assertEqual(host.credentials, {"root": "root-pass"})

    def test_connect_client_prefers_key_then_falls_back_to_stored_password(self) -> None:
        with TemporaryDirectory() as tmpdir:
            app = App(AppPaths.from_root(Path(tmpdir)))
            target = Target(label="hannah", host="192.0.2.10", port=22, username="root")
            app.paths.targets_file.write_text("hannah,192.0.2.10,22\n", encoding="utf-8")
            app.paths.identity_file.parent.mkdir(parents=True, exist_ok=True)
            app.paths.identity_file.write_text("PRIVATE KEY", encoding="utf-8")
            app.metadata.record_password(
                target_key=target.key,
                username="root",
                password="stored-pass",
                source="manual-change",
            )
            _FakeSSHClient.instances.clear()
            _FakeSequencedSSHClient.connect_results = [
                SSHError("Authentication failed for root@192.0.2.10:22: bad key"),
                None,
            ]
            progress: list[str] = []

            with patch("vikings_ssh.app.SSHClient", _FakeSequencedSSHClient):
                client = app._connect_client(target, progress=progress.append)

        self.assertEqual(len(_FakeSSHClient.instances), 2)
        self.assertEqual(_FakeSSHClient.instances[0].key_filename, str(app.paths.identity_file))
        self.assertIsNone(_FakeSSHClient.instances[0].password)
        self.assertIsNone(_FakeSSHClient.instances[1].key_filename)
        self.assertEqual(_FakeSSHClient.instances[1].password, "stored-pass")
        self.assertIn("Auth: trying SSH key (data/id_rsa)", "\n".join(progress))
        self.assertIn("Auth: connected as 'root' using stored password.", "\n".join(progress))
        client.close()

    def test_connect_client_prompts_after_key_auth_fails_without_saved_password(self) -> None:
        with TemporaryDirectory() as tmpdir:
            app = App(AppPaths.from_root(Path(tmpdir)))
            target = Target(label="hannah", host="192.0.2.10", port=22, username="root")
            app.paths.identity_file.parent.mkdir(parents=True, exist_ok=True)
            app.paths.identity_file.write_text("PRIVATE KEY", encoding="utf-8")
            _FakeSSHClient.instances.clear()
            _FakeSequencedSSHClient.connect_results = [
                SSHError("Authentication failed for root@192.0.2.10:22: bad key"),
                None,
            ]
            prompted_targets: list[Target] = []
            progress: list[str] = []

            with patch("vikings_ssh.app.SSHClient", _FakeSequencedSSHClient):
                client = app._connect_client(
                    target,
                    credential_prompt=lambda prompted_target: (
                        prompted_targets.append(prompted_target) or prompted_target.username or "root",
                        "prompt-pass",
                    ),
                    progress=progress.append,
                )

        self.assertEqual(len(_FakeSSHClient.instances), 2)
        self.assertEqual(_FakeSSHClient.instances[0].key_filename, str(app.paths.identity_file))
        self.assertEqual(_FakeSSHClient.instances[1].password, "prompt-pass")
        self.assertEqual(prompted_targets[0].username, "root")
        self.assertIn("Auth: requesting interactive SSH credentials", "\n".join(progress))
        self.assertIn("Auth: connected as 'root' using prompted password.", "\n".join(progress))
        client.close()

    def test_dashboard_reports_password_fallback_after_key_failure(self) -> None:
        with TemporaryDirectory() as tmpdir:
            app = App(AppPaths.from_root(Path(tmpdir)))
            target = Target(label="hannah", host="192.0.2.10", port=22, username="root")
            app.paths.targets_file.write_text("hannah,192.0.2.10,22\n", encoding="utf-8")
            app.paths.identity_file.parent.mkdir(parents=True, exist_ok=True)
            app.paths.identity_file.write_text("PRIVATE KEY", encoding="utf-8")
            app.metadata.record_password(
                target_key=target.key,
                username="root",
                password="stored-pass",
                source="manual-change",
            )
            _FakeSSHClient.instances.clear()
            _FakeSequencedSSHClient.connect_results = [
                SSHError("Authentication failed for root@192.0.2.10:22: bad key"),
                None,
            ]

            with (
                patch("vikings_ssh.app.SSHClient", _FakeSequencedSSHClient),
                patch(
                    "vikings_ssh.app.check_target_reachability",
                    return_value=ReachabilityResult(
                        target=target,
                        reachable=True,
                        checked_at="2026-04-13T00:00:00+00:00",
                        latency_ms=12.34,
                    ),
                ),
            ):
                snapshot = app.dashboard(timeout=1.0, workers=1, refresh_interval=10.0)

        self.assertEqual(len(snapshot.hosts), 1)
        self.assertTrue(snapshot.local_key_available)
        self.assertEqual(snapshot.hosts[0].login_state, "ok")
        self.assertEqual(snapshot.hosts[0].auth_method, "stored password")
        self.assertEqual(snapshot.hosts[0].auth_path, "SSH key (data/id_rsa) -> stored password")
        self.assertEqual(snapshot.hosts[0].known_password_count, 1)
        self.assertEqual(snapshot.hosts[0].latency_ms, 12.34)

    def test_dashboard_marks_host_as_no_creds_when_port_is_open(self) -> None:
        with TemporaryDirectory() as tmpdir:
            app = App(AppPaths.from_root(Path(tmpdir)))
            target = Target(label="hannah", host="192.0.2.10", port=22, username="root")
            app.paths.targets_file.write_text("hannah,192.0.2.10,22\n", encoding="utf-8")

            with patch(
                "vikings_ssh.app.check_target_reachability",
                return_value=ReachabilityResult(
                    target=target,
                    reachable=True,
                    checked_at="2026-04-13T00:00:00+00:00",
                    latency_ms=8.5,
                ),
            ):
                snapshot = app.dashboard(timeout=1.0, workers=1, refresh_interval=10.0)

        self.assertEqual(snapshot.hosts[0].login_state, "no creds")
        self.assertEqual(snapshot.hosts[0].error, "No SSH key or stored password available.")
        self.assertEqual(snapshot.hosts[0].known_password_count, 0)

    def test_connect_client_uses_legacy_ed25519_key_only_when_rsa_is_missing(self) -> None:
        with TemporaryDirectory() as tmpdir:
            app = App(AppPaths.from_root(Path(tmpdir)))
            target = Target(label="hannah", host="192.0.2.10", port=22, username="root")
            app.paths.legacy_identity_file.parent.mkdir(parents=True, exist_ok=True)
            app.paths.legacy_identity_file.write_text("PRIVATE KEY", encoding="utf-8")
            _FakeSSHClient.instances.clear()
            progress: list[str] = []

            with patch("vikings_ssh.app.SSHClient", _FakeSSHClient):
                client = app._connect_client(target, progress=progress.append)

        self.assertEqual(len(_FakeSSHClient.instances), 1)
        self.assertEqual(_FakeSSHClient.instances[0].key_filename, str(app.paths.legacy_identity_file))
        self.assertIn("Auth: trying SSH key (data/id_ed25519)", "\n".join(progress))
        client.close()


    def test_add_target_appends_to_inventory_and_seeds_metadata(self) -> None:
        with TemporaryDirectory() as tmpdir:
            app = App(AppPaths.from_root(Path(tmpdir)))
            app.bootstrap()
            app.paths.targets_file.write_text("web-1,192.0.2.10,22\n", encoding="utf-8")

            added = app.add_target(label="db-1", host="192.0.2.11", port=2222, username="admin")
            targets = app.load_targets()

            metadata = app.metadata.get_host(added.key)

        self.assertEqual(added.key, "192.0.2.11:2222")
        self.assertEqual({t.key for t in targets}, {"192.0.2.10:22", "192.0.2.11:2222"})
        assert metadata is not None
        self.assertEqual(metadata.label, "db-1")
        self.assertEqual(metadata.ssh_username, "admin")

    def test_add_target_rejects_duplicate_host_port(self) -> None:
        with TemporaryDirectory() as tmpdir:
            app = App(AppPaths.from_root(Path(tmpdir)))
            app.bootstrap()
            app.paths.targets_file.write_text("web-1,192.0.2.10,22\n", encoding="utf-8")

            with self.assertRaises(InventoryError):
                app.add_target(label="duplicate", host="192.0.2.10", port=22)


if __name__ == "__main__":
    unittest.main()
