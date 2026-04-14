import unittest

from vikings_ssh.models import (
    CredentialFile,
    CredentialReport,
    DashboardHostStatus,
    DashboardSnapshot,
    HostCredentialView,
    PasswordRecord,
    Target,
)
from vikings_ssh.render import render_credential_export, render_credentials, render_dashboard


class RenderCredentialsTests(unittest.TestCase):
    def test_render_credentials_includes_key_material_and_password_history(self) -> None:
        report = CredentialReport(
            private_key=CredentialFile(
                label="Private Key",
                path="/tmp/id_rsa",
                exists=True,
                contents="PRIVATE-KEY",
            ),
            public_key=CredentialFile(
                label="Public Key",
                path="/tmp/id_rsa.pub",
                exists=True,
                contents="ssh-rsa AAAA example",
            ),
            authorized_keys=CredentialFile(
                label="Authorized Keys",
                path="/tmp/authorized_keys",
                exists=True,
                contents="ssh-rsa AAAA example\nssh-rsa BBBB backup",
            ),
            hosts=[
                HostCredentialView(
                    target_key="192.0.2.10:22",
                    display_name="web-1 (root@192.0.2.10:22)",
                    current_passwords={"root": "new-pass"},
                    password_history=[
                        PasswordRecord(
                            username="root",
                            password="old-pass",
                            source="legacy-import",
                        ),
                        PasswordRecord(
                            username="root",
                            password="new-pass",
                            source="manual-change",
                            recorded_at="2026-04-13T00:00:00+00:00",
                        ),
                    ],
                    authorized_keys_state="managed",
                    expected_root_key_present=True,
                )
            ],
        )

        rendered = render_credentials(report)

        self.assertIn("Local Key Material", rendered)
        self.assertIn("PRIVATE-KEY", rendered)
        self.assertIn("ssh-rsa BBBB backup", rendered)
        self.assertIn("web-1 (root@192.0.2.10:22)", rendered)
        self.assertIn("Current Passwords:", rendered)
        self.assertIn("root: new-pass", rendered)
        self.assertIn("[manual-change] root: new-pass", rendered)

    def test_render_credential_export_is_machine_readable_and_includes_keys(self) -> None:
        report = CredentialReport(
            private_key=CredentialFile(
                label="Private Key",
                path="/tmp/id_rsa",
                exists=True,
                contents="PRIVATE-KEY",
            ),
            public_key=CredentialFile(
                label="Public Key",
                path="/tmp/id_rsa.pub",
                exists=True,
                contents="ssh-rsa AAAA example",
            ),
            authorized_keys=CredentialFile(
                label="Authorized Keys",
                path="/tmp/authorized_keys",
                exists=True,
                contents="ssh-rsa AAAA example\nssh-rsa BBBB backup",
            ),
            hosts=[
                HostCredentialView(
                    target_key="192.0.2.10:22",
                    display_name="web-1 (root@192.0.2.10:22)",
                    current_passwords={"root": "new-pass", "administrator": "other-pass"},
                    password_history=[],
                    authorized_keys_state="managed",
                    expected_root_key_present=True,
                )
            ],
        )

        rendered = render_credential_export(report, generated_at="2026-04-13T00:00:00+00:00")

        self.assertIn("Credential Export", rendered)
        self.assertIn("Generated At: 2026-04-13T00:00:00+00:00", rendered)
        self.assertIn("Private Key Path: /tmp/id_rsa", rendered)
        self.assertIn("Public Key:", rendered)
        self.assertIn("Managed Public Keys:", rendered)
        self.assertIn("web-1 (root@192.0.2.10:22)", rendered)
        self.assertIn("Current Passwords:", rendered)
        self.assertIn("root: new-pass", rendered)
        self.assertIn("administrator: other-pass", rendered)
        self.assertIn("SSH Keys:", rendered)
        self.assertIn("ssh-rsa BBBB backup", rendered)

    def test_render_credentials_marks_unknown_current_passwords_when_only_history_exists(self) -> None:
        report = CredentialReport(
            private_key=CredentialFile(label="Private Key", path="/tmp/id_rsa", exists=False),
            public_key=CredentialFile(label="Public Key", path="/tmp/id_rsa.pub", exists=False),
            authorized_keys=CredentialFile(label="Authorized Keys", path="/tmp/authorized_keys", exists=False),
            hosts=[
                HostCredentialView(
                    target_key="192.0.2.10:22",
                    display_name="web-1 (root@192.0.2.10:22)",
                    current_passwords={},
                    password_history=[
                        PasswordRecord(
                            username="root",
                            password="old-pass",
                            source="manual-change",
                            recorded_at="2026-04-13T00:00:00+00:00",
                        ),
                    ],
                    authorized_keys_state="managed",
                    expected_root_key_present=True,
                )
            ],
        )

        rendered = render_credentials(report)
        exported = render_credential_export(report)

        self.assertIn("Current Passwords:\n    (unknown)", rendered)
        self.assertIn("Password History (historical only):", rendered)
        self.assertIn("Current Passwords:\n    (unknown)", exported)

    def test_render_dashboard_shows_summary_and_host_login_details(self) -> None:
        snapshot = DashboardSnapshot(
            generated_at="2026-04-13T00:00:00+00:00",
            refresh_interval=10.0,
            local_key_available=True,
            managed_key_count=2,
            hosts=[
                DashboardHostStatus(
                    target=Target(label="web-1", host="192.0.2.10", port=22, username="root"),
                    checked_at="2026-04-13T00:00:00+00:00",
                    tcp_open=True,
                    login_state="ok",
                    login_username="root",
                    auth_method="SSH key (data/id_rsa)",
                    auth_path="SSH key (data/id_rsa)",
                    latency_ms=12.34,
                    authorized_keys_state="managed",
                    expected_root_key_present=True,
                    known_password_count=1,
                    snapshot_count=3,
                ),
                DashboardHostStatus(
                    target=Target(label="db-1", host="192.0.2.11", port=22, username="root"),
                    checked_at="2026-04-13T00:00:00+00:00",
                    tcp_open=True,
                    login_state="no creds",
                    login_username="root",
                    latency_ms=8.5,
                    authorized_keys_state="unknown",
                    expected_root_key_present=False,
                    known_password_count=0,
                    snapshot_count=0,
                    error="No SSH key or stored password available.",
                ),
            ],
        )

        rendered = render_dashboard(snapshot)

        self.assertIn("Live Monitoring Dashboard", rendered)
        self.assertIn("Refresh: every 10s", rendered)
        self.assertIn("Local SSH key:", rendered)
        self.assertIn("Login OK: 1", rendered)
        self.assertIn("Needs Creds: 1", rendered)
        self.assertIn("web-1", rendered)
        self.assertIn("192.0.2.10:22", rendered)
        self.assertIn("ssh key", rendered)
        self.assertIn("managed/root", rendered)
        self.assertIn("No SSH key or stored password available.", rendered)


if __name__ == "__main__":
    unittest.main()
