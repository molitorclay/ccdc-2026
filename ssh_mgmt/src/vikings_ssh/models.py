from __future__ import annotations

from dataclasses import asdict, dataclass, field


def make_target_key(host: str, port: int) -> str:
    return f"{host}:{port}"


def parse_target_key(target_key: str) -> tuple[str | None, str, int]:
    parts = target_key.split(":")
    if len(parts) == 2:
        label = None
        host, raw_port = parts
    elif len(parts) == 3:
        label, host, raw_port = parts
        label = label or None
    else:
        raise ValueError(f"Invalid target key {target_key!r}")

    if not host:
        raise ValueError(f"Invalid target key {target_key!r}: empty host")

    try:
        port = int(raw_port)
    except ValueError as exc:
        raise ValueError(f"Invalid target key {target_key!r}: invalid port") from exc

    if port < 1 or port > 65535:
        raise ValueError(f"Invalid target key {target_key!r}: invalid port")

    return label, host, port


def normalize_target_key(target_key: str) -> tuple[str, str | None]:
    label, host, port = parse_target_key(target_key)
    return make_target_key(host, port), label


@dataclass(slots=True, frozen=True)
class Target:
    host: str
    port: int = 22
    label: str = ""
    username: str | None = None

    @property
    def key(self) -> str:
        return make_target_key(self.host, self.port)

    @property
    def display_label(self) -> str:
        return self.label or self.host

    @property
    def display_name(self) -> str:
        if self.username:
            return f"{self.display_label} ({self.username}@{self.host}:{self.port})"
        return f"{self.display_label} ({self.host}:{self.port})"

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(slots=True, frozen=True)
class PasswordRecord:
    username: str
    password: str
    source: str
    recorded_at: str | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: dict[str, object]) -> "PasswordRecord":
        return cls(
            username=str(payload["username"]),
            password=str(payload["password"]),
            source=str(payload.get("source", "unknown")),
            recorded_at=None if payload.get("recorded_at") is None else str(payload["recorded_at"]),
        )


@dataclass(slots=True)
class HostMetadata:
    target_key: str
    label: str = ""
    ssh_username: str | None = None
    notes: str = ""
    tags: list[str] = field(default_factory=list)
    # username -> current password (stored in plaintext; treat this file as sensitive)
    credentials: dict[str, str] = field(default_factory=dict)
    password_history: list[PasswordRecord] = field(default_factory=list)
    password_material_available: bool = False
    expected_root_key_present: bool = False
    authorized_keys_state: str = "unknown"
    last_reachable_at: str | None = None
    last_error: str | None = None
    snapshot_ids: list[str] = field(default_factory=list)

    def record_password(
        self,
        username: str,
        password: str,
        source: str,
        recorded_at: str | None = None,
    ) -> None:
        self.credentials[username] = password
        self.password_material_available = True

        if any(item.username == username and item.password == password for item in self.password_history):
            return

        self.password_history.append(
            PasswordRecord(
                username=username,
                password=password,
                source=source,
                recorded_at=recorded_at,
            )
        )

    def to_dict(self) -> dict[str, object]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: dict[str, object]) -> "HostMetadata":
        raw_creds = payload.get("credentials", {})
        credentials = {str(k): str(v) for k, v in raw_creds.items()} if isinstance(raw_creds, dict) else {}
        raw_history = payload.get("password_history", [])
        password_history = [
            PasswordRecord.from_dict(item)
            for item in raw_history
            if isinstance(item, dict)
        ] if isinstance(raw_history, list) else []

        history_pairs = {(item.username, item.password) for item in password_history}
        for username, password in sorted(credentials.items()):
            if (username, password) not in history_pairs:
                password_history.append(
                    PasswordRecord(
                        username=username,
                        password=password,
                        source="legacy-import",
                    )
                )

        return cls(
            target_key=str(payload["target_key"]),
            label=str(payload.get("label", "")),
            ssh_username=(
                None
                if payload.get("ssh_username", payload.get("username")) is None
                else str(payload.get("ssh_username", payload.get("username")))
            ),
            notes=str(payload.get("notes", "")),
            tags=[str(item) for item in payload.get("tags", [])],
            credentials=credentials,
            password_history=password_history,
            password_material_available=(
                bool(payload.get("password_material_available", False))
                or bool(credentials)
                or bool(password_history)
            ),
            expected_root_key_present=bool(payload.get("expected_root_key_present", False)),
            authorized_keys_state=str(payload.get("authorized_keys_state", "unknown")),
            last_reachable_at=(
                None if payload.get("last_reachable_at") is None else str(payload["last_reachable_at"])
            ),
            last_error=None if payload.get("last_error") is None else str(payload["last_error"]),
            snapshot_ids=[str(item) for item in payload.get("snapshot_ids", [])],
        )


@dataclass(slots=True, frozen=True)
class SnapshotEntry:
    snapshot_id: str
    target_key: str
    source_path: str
    reason: str
    created_at: str
    blob_path: str
    sha256: str
    size_bytes: int
    mode: str | None = None
    owner_uid: int | None = None
    owner_gid: int | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: dict[str, object]) -> "SnapshotEntry":
        return cls(
            snapshot_id=str(payload["snapshot_id"]),
            target_key=str(payload["target_key"]),
            source_path=str(payload["source_path"]),
            reason=str(payload["reason"]),
            created_at=str(payload["created_at"]),
            blob_path=str(payload["blob_path"]),
            sha256=str(payload["sha256"]),
            size_bytes=int(payload["size_bytes"]),
            mode=None if payload.get("mode") is None else str(payload["mode"]),
            owner_uid=None if payload.get("owner_uid") is None else int(payload["owner_uid"]),
            owner_gid=None if payload.get("owner_gid") is None else int(payload["owner_gid"]),
        )


@dataclass(slots=True, frozen=True)
class SnapshotRestoreResult:
    snapshot_id: str
    target_key: str
    source_path: str
    restored: bool
    backup_snapshot_id: str | None = None
    error: str | None = None


@dataclass(slots=True, frozen=True)
class CredentialFile:
    label: str
    path: str
    exists: bool
    contents: str | None = None


@dataclass(slots=True, frozen=True)
class HostCredentialView:
    target_key: str
    display_name: str
    current_passwords: dict[str, str]
    password_history: list[PasswordRecord]
    authorized_keys_state: str
    expected_root_key_present: bool


@dataclass(slots=True, frozen=True)
class CredentialReport:
    private_key: CredentialFile
    public_key: CredentialFile
    authorized_keys: CredentialFile
    hosts: list[HostCredentialView]


@dataclass(slots=True, frozen=True)
class ReachabilityResult:
    target: Target
    reachable: bool
    checked_at: str
    latency_ms: float | None = None
    error: str | None = None


@dataclass(slots=True, frozen=True)
class DashboardHostStatus:
    target: Target
    checked_at: str
    tcp_open: bool
    login_state: str
    login_username: str
    auth_method: str | None = None
    auth_path: str | None = None
    latency_ms: float | None = None
    authorized_keys_state: str = "unknown"
    expected_root_key_present: bool = False
    known_password_count: int = 0
    snapshot_count: int = 0
    error: str | None = None


@dataclass(slots=True, frozen=True)
class DashboardSnapshot:
    generated_at: str
    refresh_interval: float
    local_key_available: bool
    managed_key_count: int
    hosts: list[DashboardHostStatus]
