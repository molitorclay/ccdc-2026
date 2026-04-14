from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from vikings_ssh.config import AppPaths
from vikings_ssh.inventory import Inventory, InventoryError
from vikings_ssh.key_injection import (
    InjectionResult,
    generate_keypair,
    inject_keys_to_host,
    load_authorized_keys,
)
from vikings_ssh.metadata_store import MetadataStore
from vikings_ssh.models import (
    CredentialFile,
    CredentialReport,
    DashboardHostStatus,
    DashboardSnapshot,
    HostCredentialView,
    HostMetadata,
    normalize_target_key,
    parse_target_key,
    ReachabilityResult,
    SnapshotEntry,
    SnapshotRestoreResult,
    Target,
)
from vikings_ssh.monitoring import check_target_reachability
from vikings_ssh.password_audit import (
    DeepAuditFinding,
    DeepHostAuditResult,
    HostAuditResult,
    change_password,
    generate_passphrase,
    parse_shadow_entries,
    try_auth,
    verify_shadow_password,
)
from vikings_ssh.snapshots import SnapshotStore
from vikings_ssh.ssh import SSHClient, SSHError, _shell_quote as _sh_quote


@dataclass(slots=True, frozen=True)
class _AuthAttempt:
    username: str
    label: str
    password: str | None = None
    key_filename: str | None = None


class App:
    def __init__(self, paths: AppPaths) -> None:
        self.paths = paths
        self.inventory = Inventory(paths.targets_file)
        self.metadata = MetadataStore(paths.metadata_file)
        self.snapshots = SnapshotStore(paths.snapshot_dir, paths.snapshot_blob_dir, paths.snapshot_index_file)

    def bootstrap(self) -> None:
        self.paths.ensure()
        self.metadata.ensure()
        self.snapshots.ensure()

    @staticmethod
    def _utc_now_iso() -> str:
        return datetime.now(timezone.utc).isoformat()

    def load_targets(self) -> list[Target]:
        targets = self.inventory.load()
        metadata_by_key = {
            item.target_key: item
            for item in self.metadata.ensure_targets(targets)
        }
        return [self._resolve_target(target, metadata_by_key.get(target.key)) for target in targets]

    def _resolve_target(self, target: Target, metadata: HostMetadata | None) -> Target:
        if metadata is None:
            return target
        return Target(
            host=target.host,
            port=target.port,
            label=metadata.label or target.label,
            username=metadata.ssh_username or target.username,
        )

    def _display_name_for_metadata(self, metadata: HostMetadata) -> str:
        _, host, port = parse_target_key(metadata.target_key)
        return Target(
            host=host,
            port=port,
            label=metadata.label,
            username=metadata.ssh_username,
        ).display_name

    def _remember_target(self, target: Target, ssh_username: str | None = None) -> None:
        self.metadata.remember_target(
            target.key,
            label=target.label,
            ssh_username=ssh_username or target.username,
        )

    def add_target(
        self,
        label: str,
        host: str,
        port: int = 22,
        username: str | None = None,
    ) -> Target:
        """Append a new target to the inventory and seed its metadata.

        Raises InventoryError if the host:port already exists or if any field
        contains invalid characters.
        """
        label = label.strip()
        host = host.strip()
        if not label:
            raise InventoryError("Label must not be empty")
        if not host:
            raise InventoryError("Host must not be empty")
        if port < 1 or port > 65535:
            raise InventoryError(f"Port {port} is outside the valid range 1-65535")

        target = Target(host=host, port=port, label=label, username=username)
        self.inventory.append_target(target)
        self._remember_target(target, ssh_username=username)
        return target

    def test_target_connection(
        self,
        target: Target,
        username: str | None = None,
        password: str | None = None,
        timeout: float = 8.0,
    ) -> tuple[bool, str, str | None]:
        """Attempt a single SSH login to verify a target is reachable.

        Tries the local SSH key first (if present and no explicit password was
        given), then the provided password.  On success with a password, the
        credential is stored in metadata so subsequent commands can reuse it.
        Returns (connected, auth_label, error).
        """
        effective_user = username or self._default_login_username(target)

        if password is None:
            key_attempt = self._identity_auth_attempt(effective_user)
            if key_attempt is not None:
                try:
                    client = self._open_client_for_attempt(
                        target,
                        key_attempt,
                        connect_timeout=timeout,
                    )
                except SSHError as exc:
                    if not self._is_authentication_error(exc):
                        return False, key_attempt.label, str(exc)
                else:
                    client.close()
                    self._remember_target(target, ssh_username=effective_user)
                    return True, key_attempt.label, None

        if password is None:
            return False, "SSH key", "No SSH key accepted and no password provided."

        password_attempt = _AuthAttempt(
            username=effective_user,
            label="password",
            password=password,
        )
        try:
            client = self._open_client_for_attempt(
                target,
                password_attempt,
                connect_timeout=timeout,
            )
        except SSHError as exc:
            return False, password_attempt.label, str(exc)
        client.close()
        self._remember_target(target, ssh_username=effective_user)
        self.metadata.record_password(
            target_key=target.key,
            username=effective_user,
            password=password,
            source="add-host-wizard",
        )
        return True, password_attempt.label, None

    def get_target(self, target_key: str) -> Target | None:
        normalized_key, _ = normalize_target_key(target_key)
        for target in self.load_targets():
            if target.key == normalized_key:
                return target

        metadata = self.metadata.get_host(normalized_key)
        try:
            _, host, port = parse_target_key(normalized_key)
        except ValueError:
            return None

        return Target(
            host=host,
            port=port,
            label=metadata.label if metadata else "",
            username=metadata.ssh_username if metadata else None,
        )

    def dashboard(self, timeout: float, workers: int, refresh_interval: float = 10.0) -> DashboardSnapshot:
        targets = self.load_targets()
        metadata_by_key = {
            item.target_key: item
            for item in self.metadata.list_hosts()
        }
        if not targets:
            return DashboardSnapshot(
                generated_at=self._utc_now_iso(),
                refresh_interval=refresh_interval,
                local_key_available=self._auth_identity_file() is not None,
                managed_key_count=len(load_authorized_keys(self.paths.authorized_keys_file)),
                hosts=[],
            )

        worker_count = max(1, min(workers, len(targets)))
        indexed_targets = list(enumerate(targets))
        statuses_by_index: dict[int, DashboardHostStatus] = {}

        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            future_map = {
                executor.submit(
                    self._dashboard_status_for_target,
                    target,
                    metadata_by_key.get(target.key),
                    timeout,
                ): index
                for index, target in indexed_targets
            }
            for future, index in future_map.items():
                statuses_by_index[index] = future.result()

        statuses = [statuses_by_index[index] for index in range(len(targets))]
        for status in statuses:
            self.metadata.record_reachability(ReachabilityResult(
                target=status.target,
                reachable=status.tcp_open,
                checked_at=status.checked_at,
                latency_ms=status.latency_ms,
                error=None if status.tcp_open else status.error,
            ))
            if status.login_state == "ok":
                self._remember_target(status.target, status.login_username)

        return DashboardSnapshot(
            generated_at=self._utc_now_iso(),
            refresh_interval=refresh_interval,
            local_key_available=self._auth_identity_file() is not None,
            managed_key_count=len(load_authorized_keys(self.paths.authorized_keys_file)),
            hosts=statuses,
        )

    def list_metadata(self) -> list[HostMetadata]:
        return self.metadata.list_hosts()

    def _read_credential_file(self, label: str, path: Path) -> CredentialFile:
        if not path.exists():
            return CredentialFile(label=label, path=str(path), exists=False)
        return CredentialFile(
            label=label,
            path=str(path),
            exists=True,
            contents=path.read_text(encoding="utf-8").rstrip("\n"),
        )

    def _identity_pairs(self) -> list[tuple[Path, Path]]:
        pairs = [(self.paths.identity_file, self.paths.identity_pub_file)]
        legacy_pair = (self.paths.legacy_identity_file, self.paths.legacy_identity_pub_file)
        if legacy_pair not in pairs:
            pairs.append(legacy_pair)
        return pairs

    def _display_identity_pair(self) -> tuple[Path, Path]:
        for private_key, public_key in self._identity_pairs():
            if private_key.exists():
                return private_key, public_key
        for private_key, public_key in self._identity_pairs():
            if private_key.exists() or public_key.exists():
                return private_key, public_key
        return self.paths.identity_file, self.paths.identity_pub_file

    def _auth_identity_file(self) -> Path | None:
        for private_key, _ in self._identity_pairs():
            if private_key.exists():
                return private_key
        return None

    def list_credentials(self, target_key: str | None = None) -> CredentialReport:
        private_key_path, public_key_path = self._display_identity_pair()
        targets = {target.key: target for target in self.load_targets()}
        hosts: list[HostCredentialView] = []
        for metadata in self.metadata.list_hosts():
            if target_key and metadata.target_key != target_key:
                continue
            target = targets.get(metadata.target_key)
            hosts.append(HostCredentialView(
                target_key=metadata.target_key,
                display_name=target.display_name if target else self._display_name_for_metadata(metadata),
                current_passwords=dict(sorted(metadata.credentials.items())),
                password_history=list(metadata.password_history),
                authorized_keys_state=metadata.authorized_keys_state,
                expected_root_key_present=metadata.expected_root_key_present,
            ))

        return CredentialReport(
            private_key=self._read_credential_file("Private Key", private_key_path),
            public_key=self._read_credential_file("Public Key", public_key_path),
            authorized_keys=self._read_credential_file("Authorized Keys", self.paths.authorized_keys_file),
            hosts=hosts,
        )

    def list_snapshots(self, target_key: str | None = None) -> list[SnapshotEntry]:
        return self.snapshots.list_snapshots(target_key=target_key)

    def create_snapshot(self, target_key: str, source_path: str, from_file: Path, reason: str) -> SnapshotEntry:
        contents = from_file.read_text(encoding="utf-8")
        entry = self.snapshots.create_snapshot(
            target_key=target_key,
            source_path=source_path,
            contents=contents,
            reason=reason,
        )
        self.metadata.attach_snapshot(target_key, entry.snapshot_id)
        return entry

    def get_snapshot(self, snapshot_id: str) -> SnapshotEntry | None:
        return self.snapshots.get_snapshot(snapshot_id)

    def _snapshot_remote_file(
        self,
        client: SSHClient,
        target_key: str,
        remote_path: str,
        reason: str,
    ) -> SnapshotEntry | None:
        """Read *remote_path* from the connected host and store it as a snapshot."""
        try:
            mode, owner_uid, owner_gid = self._read_remote_file_metadata(client, remote_path)
            contents = client.read_file(remote_path)
        except SSHError:
            return None
        entry = self.snapshots.create_snapshot(
            target_key=target_key,
            source_path=remote_path,
            contents=contents,
            reason=reason,
            mode=mode,
            owner_uid=owner_uid,
            owner_gid=owner_gid,
        )
        self.metadata.attach_snapshot(target_key, entry.snapshot_id)
        return entry

    def _read_remote_file_metadata(
        self,
        client: SSHClient,
        remote_path: str,
    ) -> tuple[str | None, int | None, int | None]:
        result = client.run(
            f"stat -c '%a %u %g' -- {_sh_quote(remote_path)}",
            timeout=10.0,
        )
        if not result.ok:
            return None, None, None
        parts = result.stdout.strip().split()
        if len(parts) != 3:
            return None, None, None
        mode, raw_uid, raw_gid = parts
        try:
            return mode, int(raw_uid), int(raw_gid)
        except ValueError:
            return None, None, None

    def _restore_write_metadata(
        self,
        client: SSHClient,
        snapshot: SnapshotEntry,
    ) -> tuple[str, int | None, int | None]:
        if snapshot.mode is not None:
            return snapshot.mode, snapshot.owner_uid, snapshot.owner_gid

        live_mode, live_uid, live_gid = self._read_remote_file_metadata(client, snapshot.source_path)
        if live_mode is not None:
            return live_mode, live_uid, live_gid

        default_mode = "600"
        if snapshot.source_path == "/etc/passwd":
            default_mode = "644"
        elif snapshot.source_path == "/etc/shadow":
            default_mode = "600"
        elif snapshot.source_path.endswith("/authorized_keys"):
            default_mode = "600"
        return default_mode, snapshot.owner_uid, snapshot.owner_gid

    def _restore_priority(self, source_path: str) -> tuple[int, str]:
        if source_path.endswith("/authorized_keys"):
            return 0, source_path
        if source_path == "/etc/passwd":
            return 1, source_path
        if source_path == "/etc/shadow":
            return 2, source_path
        return 10, source_path

    def restore_snapshots(
        self,
        target: Target,
        snapshot_ids: list[str],
        credential_prompt: Callable[[Target], tuple[str, str | None]] | None = None,
        progress: Callable[[str], None] | None = None,
    ) -> list[SnapshotRestoreResult]:
        if not snapshot_ids:
            raise ValueError("No snapshots selected for restore.")

        snapshots: list[SnapshotEntry] = []
        seen_paths: set[str] = set()
        for snapshot_id in snapshot_ids:
            snapshot = self.snapshots.get_snapshot(snapshot_id)
            if snapshot is None:
                raise ValueError(f"Snapshot '{snapshot_id}' not found.")
            if snapshot.target_key != target.key:
                raise ValueError(
                    f"Snapshot '{snapshot_id}' belongs to {snapshot.target_key}, not {target.key}."
                )
            if snapshot.source_path in seen_paths:
                raise ValueError(
                    f"Multiple snapshots selected for {snapshot.source_path}. Choose one snapshot per file."
                )
            seen_paths.add(snapshot.source_path)
            snapshots.append(snapshot)

        snapshots.sort(key=lambda item: self._restore_priority(item.source_path))

        if progress:
            progress(f"Connecting to {target.display_name} …")
        client: SSHClient | None = None
        results: list[SnapshotRestoreResult] = []
        try:
            client = self._connect_client(
                target,
                credential_prompt=credential_prompt,
                progress=progress,
            )

            for snapshot in snapshots:
                if progress:
                    progress(f"Restoring {snapshot.source_path} from snapshot {snapshot.snapshot_id} …")
                try:
                    if progress:
                        progress(f"  Snapshotting current {snapshot.source_path} before restore …")
                    backup = self._snapshot_remote_file(
                        client,
                        target.key,
                        snapshot.source_path,
                        f"pre-restore:{snapshot.snapshot_id}",
                    )
                    contents = self.snapshots.read_snapshot_contents(snapshot.snapshot_id)
                    mode, owner_uid, owner_gid = self._restore_write_metadata(client, snapshot)
                    client.write_file_stdin(snapshot.source_path, contents, mode=mode)
                    if owner_uid is not None and owner_gid is not None:
                        client.run_checked(
                            f"chown {owner_uid}:{owner_gid} -- {_sh_quote(snapshot.source_path)}",
                            timeout=10.0,
                        )
                    if snapshot.source_path == "/etc/passwd":
                        self.metadata.clear_missing_accounts(
                            target.key,
                            usernames_present=self._parse_passwd_usernames(contents),
                        )
                    elif snapshot.source_path == "/etc/shadow":
                        self.metadata.clear_credentials_newer_than(
                            target.key,
                            restored_at=snapshot.created_at,
                        )
                    if progress:
                        progress(f"  ✓ Restored {snapshot.source_path}.")
                    results.append(
                        SnapshotRestoreResult(
                            snapshot_id=snapshot.snapshot_id,
                            target_key=snapshot.target_key,
                            source_path=snapshot.source_path,
                            restored=True,
                            backup_snapshot_id=None if backup is None else backup.snapshot_id,
                        )
                    )
                except (SSHError, ValueError) as exc:
                    results.append(
                        SnapshotRestoreResult(
                            snapshot_id=snapshot.snapshot_id,
                            target_key=snapshot.target_key,
                            source_path=snapshot.source_path,
                            restored=False,
                            error=str(exc),
                        )
                    )
                    break
        finally:
            if client is not None:
                client.close()

        return results

    def _parse_passwd_usernames(self, contents: str) -> set[str]:
        usernames: set[str] = set()
        for line in contents.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            parts = stripped.split(":", 1)
            if parts and parts[0]:
                usernames.add(parts[0])
        return usernames

    def _default_login_username(self, target: Target, metadata: HostMetadata | None = None) -> str:
        meta = metadata if metadata is not None else self.metadata.get_host(target.key)
        return target.username or (meta.ssh_username if meta else None) or "root"

    def _stored_password_for(
        self,
        target_key: str,
        username: str,
        metadata: HostMetadata | None = None,
    ) -> str | None:
        meta = metadata if metadata is not None else self.metadata.get_host(target_key)
        if meta is None or not meta.credentials:
            return None
        return meta.credentials.get(username)

    def _identity_auth_attempt(self, username: str) -> _AuthAttempt | None:
        identity_file = self._auth_identity_file()
        if identity_file is None:
            return None
        try:
            display_path = identity_file.relative_to(self.paths.root)
        except ValueError:
            display_path = identity_file
        return _AuthAttempt(
            username=username,
            label=f"SSH key ({display_path})",
            key_filename=str(identity_file),
        )

    def _auth_attempts_for(
        self,
        target: Target,
        password_candidates: list[tuple[str, str | None]] | None = None,
        metadata: HostMetadata | None = None,
    ) -> list[_AuthAttempt]:
        username = self._default_login_username(target, metadata=metadata)
        attempts: list[_AuthAttempt] = []

        key_attempt = self._identity_auth_attempt(username)
        if key_attempt is not None:
            attempts.append(key_attempt)

        seen_passwords: set[str] = set()
        for label, password in password_candidates or []:
            if password is None or password in seen_passwords:
                continue
            attempts.append(_AuthAttempt(username=username, label=label, password=password))
            seen_passwords.add(password)

        stored_password = self._stored_password_for(target.key, username, metadata=metadata)
        if stored_password is not None and stored_password not in seen_passwords:
            attempts.append(_AuthAttempt(username=username, label="stored password", password=stored_password))

        return attempts

    @staticmethod
    def _is_authentication_error(exc: SSHError) -> bool:
        return "authentication failed" in str(exc).lower()

    def _open_client_for_attempt(
        self,
        target: Target,
        attempt: _AuthAttempt,
        progress: Callable[[str], None] | None = None,
        connect_timeout: float | None = None,
    ) -> SSHClient:
        location = f"{attempt.username}@{target.host}:{target.port}"
        if progress:
            progress(f"  Auth: trying {attempt.label} for {location} …")

        client_kwargs = dict(
            host=target.host,
            port=target.port,
            username=attempt.username,
            password=attempt.password,
            key_filename=attempt.key_filename,
        )
        if connect_timeout is not None:
            client_kwargs["connect_timeout"] = connect_timeout
        client = SSHClient(**client_kwargs)
        try:
            client.connect()
        except SSHError as exc:
            client.close()
            if progress:
                progress(f"  Auth: {attempt.label} failed for {location}: {exc}")
            raise

        return client

    def _connect_with_attempt(
        self,
        target: Target,
        attempt: _AuthAttempt,
        progress: Callable[[str], None] | None = None,
    ) -> SSHClient:
        client = self._open_client_for_attempt(target, attempt, progress=progress)
        self._remember_target(target, client.username)
        if progress:
            progress(f"  Auth: connected as '{client.username}' using {attempt.label}.")
        return client

    def _dashboard_status_for_target(
        self,
        target: Target,
        metadata: HostMetadata | None,
        timeout: float,
    ) -> DashboardHostStatus:
        reachability = check_target_reachability(target, timeout=timeout)
        login_username = self._default_login_username(target, metadata=metadata)
        known_password_count = 0 if metadata is None else len(metadata.credentials)
        snapshot_count = 0 if metadata is None else len(metadata.snapshot_ids)
        authorized_keys_state = "unknown" if metadata is None else metadata.authorized_keys_state
        expected_root_key_present = False if metadata is None else metadata.expected_root_key_present

        if not reachability.reachable:
            return DashboardHostStatus(
                target=target,
                checked_at=reachability.checked_at,
                tcp_open=False,
                login_state="down",
                login_username=login_username,
                latency_ms=reachability.latency_ms,
                authorized_keys_state=authorized_keys_state,
                expected_root_key_present=expected_root_key_present,
                known_password_count=known_password_count,
                snapshot_count=snapshot_count,
                error=reachability.error,
            )

        attempts = self._auth_attempts_for(target, metadata=metadata)
        if not attempts:
            return DashboardHostStatus(
                target=target,
                checked_at=reachability.checked_at,
                tcp_open=True,
                login_state="no creds",
                login_username=login_username,
                latency_ms=reachability.latency_ms,
                authorized_keys_state=authorized_keys_state,
                expected_root_key_present=expected_root_key_present,
                known_password_count=known_password_count,
                snapshot_count=snapshot_count,
                error="No SSH key or stored password available.",
            )

        attempted_labels: list[str] = []
        final_error = "Authentication failed."
        for attempt in attempts:
            attempted_labels.append(attempt.label)
            client: SSHClient | None = None
            try:
                client = self._open_client_for_attempt(
                    target,
                    attempt,
                    connect_timeout=max(timeout, 2.0),
                )
                return DashboardHostStatus(
                    target=target,
                    checked_at=reachability.checked_at,
                    tcp_open=True,
                    login_state="ok",
                    login_username=client.username,
                    auth_method=attempt.label,
                    auth_path=" -> ".join(attempted_labels),
                    latency_ms=reachability.latency_ms,
                    authorized_keys_state=authorized_keys_state,
                    expected_root_key_present=expected_root_key_present,
                    known_password_count=known_password_count,
                    snapshot_count=snapshot_count,
                )
            except SSHError as exc:
                final_error = str(exc)
                if not self._is_authentication_error(exc):
                    return DashboardHostStatus(
                        target=target,
                        checked_at=reachability.checked_at,
                        tcp_open=True,
                        login_state="error",
                        login_username=login_username,
                        auth_path=" -> ".join(attempted_labels),
                        latency_ms=reachability.latency_ms,
                        authorized_keys_state=authorized_keys_state,
                        expected_root_key_present=expected_root_key_present,
                        known_password_count=known_password_count,
                        snapshot_count=snapshot_count,
                        error=final_error,
                    )
            finally:
                if client is not None:
                    client.close()

        return DashboardHostStatus(
            target=target,
            checked_at=reachability.checked_at,
            tcp_open=True,
            login_state="auth failed",
            login_username=login_username,
            auth_path=" -> ".join(attempted_labels),
            latency_ms=reachability.latency_ms,
            authorized_keys_state=authorized_keys_state,
            expected_root_key_present=expected_root_key_present,
            known_password_count=known_password_count,
            snapshot_count=snapshot_count,
            error=final_error,
        )

    def _connect_client(
        self,
        target: Target,
        credential_prompt: Callable[[Target], tuple[str, str | None]] | None = None,
        progress: Callable[[str], None] | None = None,
        password_candidates: list[tuple[str, str | None]] | None = None,
    ) -> SSHClient:
        default_username = self._default_login_username(target)
        last_error: SSHError | None = None

        for attempt in self._auth_attempts_for(target, password_candidates=password_candidates):
            try:
                return self._connect_with_attempt(target, attempt, progress=progress)
            except SSHError as exc:
                last_error = exc
                if not self._is_authentication_error(exc):
                    raise

        if credential_prompt is not None:
            if progress:
                progress(f"  Auth: requesting interactive SSH credentials for {target.display_name} …")
            username, password = credential_prompt(Target(
                host=target.host,
                port=target.port,
                label=target.label,
                username=default_username,
            ))
            return self._connect_with_attempt(
                target,
                _AuthAttempt(
                    username=username or default_username,
                    label="prompted password",
                    password=password,
                ),
                progress=progress,
            )

        if last_error is not None:
            raise last_error

        raise SSHError(
            f"No usable SSH credentials available for {default_username}@{target.host}:{target.port}."
        )

    # ------------------------------------------------------------------
    # Password audit
    # ------------------------------------------------------------------

    def audit_passwords(
        self,
        targets: list[Target],
        candidate_username: str,
        candidate_password: str,
        progress: Callable[[str], None] | None = None,
    ) -> list[HostAuditResult]:
        """Try SSH authentication with *candidate_username*/*candidate_password* on each target.

        Returns one HostAuditResult per target indicating whether auth succeeded.
        """
        results: list[HostAuditResult] = []
        for target in targets:
            username = candidate_username or target.username or "root"
            if progress:
                progress(f"Trying password authentication for {username}@{target.host}:{target.port} …")
            authenticated, error = try_auth(
                host=target.host,
                port=target.port,
                username=username,
                password=candidate_password,
            )
            if authenticated:
                self._remember_target(target, username)
            results.append(HostAuditResult(
                target_key=target.key,
                username=username,
                authenticated=authenticated,
                error=error if not authenticated else None,
            ))
        return results

    def deep_audit_passwords(
        self,
        targets: list[Target],
        candidate_password: str,
        credential_prompt: Callable[[Target], tuple[str, str | None]] | None = None,
        progress: Callable[[str], None] | None = None,
    ) -> list[DeepHostAuditResult]:
        """Log in to each target and check every /etc/shadow account against *candidate_password*.

        Prefers the configured SSH key when one is available, otherwise falls
        back to stored or prompted credentials. Reads /etc/shadow, then
        verifies the candidate password against each account's hash locally.
        Returns one DeepHostAuditResult per target.
        """
        results: list[DeepHostAuditResult] = []
        for target in targets:
            if progress:
                progress(f"Connecting to {target.display_name} …")
            result = DeepHostAuditResult(
                target_key=target.key,
                ssh_username=self._default_login_username(target),
                ssh_password=None,
                connected=False,
            )
            client: SSHClient | None = None
            try:
                client = self._connect_client(
                    target,
                    credential_prompt=credential_prompt,
                    progress=progress,
                )
                result.ssh_username = client.username
                result.ssh_password = client.password
                result.connected = True

                if progress:
                    progress("  Reading /etc/shadow …")
                shadow_text = client.read_file("/etc/shadow")
                entries = parse_shadow_entries(shadow_text)
                if progress:
                    progress(f"  Checking {len(entries)} account(s) …")

                for entry in entries:
                    try:
                        matches = verify_shadow_password(entry.stored_hash, candidate_password)
                    except SSHError as exc:
                        result.error = str(exc)
                        break
                    result.findings.append(DeepAuditFinding(
                        username=entry.username,
                        password_matches=matches,
                    ))

                matched = result.matched_accounts
                if progress and matched:
                    progress(f"  ! {len(matched)} match(es): {', '.join(matched)}")
                elif progress:
                    progress(f"  ✓ No accounts matched.")

            except SSHError as exc:
                result.error = str(exc)
                if progress:
                    progress(f"  ✗ {exc}")
            finally:
                if client is not None:
                    client.close()
            results.append(result)
        return results

    def change_account_password(
        self,
        target: Target,
        account: str,
        new_password: str | None = None,
        credential_prompt: Callable[[Target], tuple[str, str | None]] | None = None,
        progress: Callable[[str], None] | None = None,
    ) -> str:
        """Change *account*'s password on *target* using the best available SSH auth.

        If *new_password* is None a passphrase is generated automatically.
        Snapshots /etc/shadow and /etc/passwd before the change.
        Saves the new credential to metadata and returns the new password.
        """
        if new_password is None:
            new_password = generate_passphrase()

        if progress:
            progress(f"Connecting to {target.display_name} …")
        client: SSHClient | None = None
        try:
            client = self._connect_client(
                target,
                credential_prompt=credential_prompt,
                progress=progress,
            )

            if progress:
                progress("  Snapshotting /etc/shadow before change …")
            self._snapshot_remote_file(client, target.key, "/etc/shadow", "pre-password-change")
            if progress:
                progress("  Snapshotting /etc/passwd before change …")
            self._snapshot_remote_file(client, target.key, "/etc/passwd", "pre-password-change")

            if progress:
                progress(f"  Changing password for '{account}' …")
            change_password(client, account, new_password)
            if progress:
                progress(f"  ✓ Password changed successfully.")

            self.metadata.record_password(
                target_key=target.key,
                username=account,
                password=new_password,
                source="manual-change",
            )
        finally:
            if client is not None:
                client.close()

        return new_password

    def rotate_passwords(
        self,
        target: Target,
        username: str,
        current_password: str | None,
        usernames_to_rotate: list[str],
        credential_prompt: Callable[[Target], tuple[str, str | None]] | None = None,
        progress: Callable[[str], None] | None = None,
    ) -> dict[str, str]:
        """Generate and apply new passphrases for *usernames_to_rotate* on *target*.

        Prefers the configured SSH key, then tries the provided password,
        stored password, and prompted credentials in that order. Snapshots
        /etc/shadow and /etc/passwd before any change. Updates metadata with
        the new credentials on success. Returns a mapping of username -> new
        passphrase for successfully rotated accounts.
        """
        login_target = Target(
            host=target.host,
            port=target.port,
            label=target.label,
            username=username,
        )
        rotated: dict[str, str] = {}
        if progress:
            progress(f"Connecting to {login_target.display_name} …")
        client: SSHClient | None = None
        try:
            client = self._connect_client(
                login_target,
                credential_prompt=credential_prompt,
                progress=progress,
                password_candidates=[("provided password", current_password)],
            )

            # Snapshot critical files before making any changes.
            if progress:
                progress("  Snapshotting /etc/shadow before rotation …")
            self._snapshot_remote_file(client, target.key, "/etc/shadow", "pre-password-rotation")
            if progress:
                progress("  Snapshotting /etc/passwd before rotation …")
            self._snapshot_remote_file(client, target.key, "/etc/passwd", "pre-password-rotation")

            for uname in usernames_to_rotate:
                new_pass = generate_passphrase()
                if progress:
                    progress(f"  Changing password for '{uname}' …")
                change_password(client, uname, new_pass)
                rotated[uname] = new_pass
                if progress:
                    progress(f"  ✓ '{uname}' changed successfully.")

            if rotated:
                self.metadata.record_passwords(
                    target_key=target.key,
                    credentials=rotated,
                    source="audit-rotation",
                )

        finally:
            if client is not None:
                client.close()

        return rotated

    # ------------------------------------------------------------------
    # Key generation + injection
    # ------------------------------------------------------------------

    def generate_keypair(self, comment: str = "vikings-ssh", overwrite: bool = False) -> str:
        """Generate an RSA keypair and register the public key in authorized_keys.

        Private key → data/id_rsa (mode 600)
        Public key  → data/id_rsa.pub
        Public key also appended to data/authorized_keys

        Returns the public key line.  Raises FileExistsError if the key already
        exists and *overwrite* is False.
        """
        if overwrite and self.paths.identity_file.exists():
            self.paths.identity_file.unlink()
            self.paths.identity_pub_file.unlink(missing_ok=True)

        return generate_keypair(
            identity_file=self.paths.identity_file,
            identity_pub_file=self.paths.identity_pub_file,
            authorized_keys_file=self.paths.authorized_keys_file,
            comment=comment,
        )

    def inject_authorized_keys(
        self,
        targets: list[Target],
        remote_user: str = "root",
        credential_prompt: Callable[[Target], tuple[str, str | None]] | None = None,
        progress: Callable[[str], None] | None = None,
    ) -> list[InjectionResult]:
        """Push the local authorized_keys to each target for *remote_user*.

        Prefers the configured SSH key when connecting, otherwise falls back
        to stored or prompted credentials. Snapshots the remote authorized_keys
        file before any modification. Updates host metadata to reflect the
        new key state.
        """
        keys = load_authorized_keys(self.paths.authorized_keys_file)
        if not keys:
            raise ValueError(
                f"No valid public keys found in {self.paths.authorized_keys_file}. "
                "Add at least one key before injecting."
            )

        results: list[InjectionResult] = []
        for target in targets:
            if progress:
                progress(f"Injecting keys → {target.display_name} …")
            result = InjectionResult(
                target_key=target.key,
                connected=False,
                remote_user=remote_user,
            )
            client: SSHClient | None = None
            try:
                client = self._connect_client(
                    target,
                    credential_prompt=credential_prompt,
                    progress=progress,
                )
                result.connected = True

                # Snapshot authorized_keys before we touch it.
                if progress:
                    progress(f"  Looking up {remote_user}'s home directory …")
                home_result = client.run(f"getent passwd {remote_user} | cut -d: -f6")
                home_dir = home_result.stdout.strip() or f"/root"
                if remote_user != "root":
                    home_dir = home_result.stdout.strip() or f"/home/{remote_user}"
                ak_path = f"{home_dir}/.ssh/authorized_keys"
                if progress:
                    progress(f"  Snapshotting {ak_path} before key injection …")
                self._snapshot_remote_file(client, target.key, ak_path, "pre-key-injection")

                added, skipped = inject_keys_to_host(client, keys, remote_user=remote_user)
                result.keys_added = added
                result.skipped = skipped

                # Update metadata.
                meta = self.metadata.get_host(target.key) or HostMetadata(target_key=target.key)
                meta.expected_root_key_present = True
                meta.authorized_keys_state = "managed"
                self.metadata.upsert_host(meta)

                if progress:
                    progress(f"  ✓ {added} added, {skipped} already present.")
            except SSHError as exc:
                result.error = str(exc)
                if progress:
                    progress(f"  ✗ {exc}")
            finally:
                if client is not None:
                    client.close()
            results.append(result)
        return results
