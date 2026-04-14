from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from vikings_ssh.models import HostMetadata, ReachabilityResult, Target, normalize_target_key

DB_VERSION = 2
LEGACY_DB_VERSION = 1


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class MetadataStore:
    def __init__(self, path: Path) -> None:
        self.path = path

    def ensure(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self._save_payload({"version": DB_VERSION, "hosts": {}})

    def list_hosts(self) -> list[HostMetadata]:
        payload = self._load_payload()
        hosts = [HostMetadata.from_dict(item) for item in payload["hosts"].values()]
        return sorted(hosts, key=lambda item: (item.label or item.target_key, item.target_key))

    def get_host(self, target_key: str) -> HostMetadata | None:
        payload = self._load_payload()
        normalized_key, _ = normalize_target_key(target_key)
        item = payload["hosts"].get(normalized_key)
        return None if item is None else HostMetadata.from_dict(item)

    def upsert_host(self, metadata: HostMetadata) -> HostMetadata:
        metadata = self._normalize_metadata(metadata)
        payload = self._load_payload()
        payload["hosts"][metadata.target_key] = metadata.to_dict()
        self._save_payload(payload)
        return metadata

    def ensure_targets(self, targets: list[Target]) -> list[HostMetadata]:
        payload = self._load_payload()
        changed = False
        for target in targets:
            current = self.get_host(target.key) or HostMetadata(target_key=target.key)
            if target.label and not current.label:
                current.label = target.label
            if target.username and not current.ssh_username:
                current.ssh_username = target.username
            if payload["hosts"].get(target.key) != current.to_dict():
                payload["hosts"][target.key] = current.to_dict()
                changed = True
        if changed:
            self._save_payload(payload)
        return [HostMetadata.from_dict(item) for item in payload["hosts"].values()]

    def remember_target(self, target_key: str, label: str = "", ssh_username: str | None = None) -> HostMetadata:
        metadata = self.get_host(target_key) or HostMetadata(target_key=target_key)
        changed = False
        if label and metadata.label != label:
            metadata.label = label
            changed = True
        if ssh_username and metadata.ssh_username != ssh_username:
            metadata.ssh_username = ssh_username
            changed = True
        if changed:
            return self.upsert_host(metadata)
        return metadata

    def record_reachability(self, result: ReachabilityResult) -> HostMetadata:
        metadata = self.get_host(result.target.key) or HostMetadata(target_key=result.target.key)
        if result.reachable:
            metadata.last_reachable_at = result.checked_at
            metadata.last_error = None
        else:
            metadata.last_error = result.error
        return self.upsert_host(metadata)

    def attach_snapshot(self, target_key: str, snapshot_id: str) -> HostMetadata:
        metadata = self.get_host(target_key) or HostMetadata(target_key=target_key)
        if snapshot_id not in metadata.snapshot_ids:
            metadata.snapshot_ids.append(snapshot_id)
        return self.upsert_host(metadata)

    def record_password(
        self,
        target_key: str,
        username: str,
        password: str,
        source: str,
        recorded_at: str | None = None,
    ) -> HostMetadata:
        return self.record_passwords(
            target_key=target_key,
            credentials={username: password},
            source=source,
            recorded_at=recorded_at,
        )

    def record_passwords(
        self,
        target_key: str,
        credentials: dict[str, str],
        source: str,
        recorded_at: str | None = None,
    ) -> HostMetadata:
        metadata = self.get_host(target_key) or HostMetadata(target_key=target_key)
        timestamp = recorded_at or utc_now_iso()
        for username, password in credentials.items():
            metadata.record_password(
                username=username,
                password=password,
                source=source,
                recorded_at=timestamp,
            )
        return self.upsert_host(metadata)

    def clear_missing_accounts(self, target_key: str, usernames_present: set[str]) -> HostMetadata:
        metadata = self.get_host(target_key) or HostMetadata(target_key=target_key)
        metadata.credentials = {
            username: password
            for username, password in metadata.credentials.items()
            if username in usernames_present
        }
        metadata.password_material_available = bool(metadata.credentials) or bool(metadata.password_history)
        return self.upsert_host(metadata)

    def clear_credentials_newer_than(
        self,
        target_key: str,
        restored_at: str,
    ) -> HostMetadata:
        metadata = self.get_host(target_key) or HostMetadata(target_key=target_key)
        retained: dict[str, str] = {}

        for username, password in metadata.credentials.items():
            matching = [
                record
                for record in metadata.password_history
                if record.username == username and record.password == password
            ]
            if not matching:
                continue

            recorded_times = [record.recorded_at for record in matching if record.recorded_at is not None]
            if not recorded_times:
                continue

            if max(recorded_times) <= restored_at:
                retained[username] = password

        metadata.credentials = retained
        metadata.password_material_available = bool(metadata.credentials) or bool(metadata.password_history)
        return self.upsert_host(metadata)

    def _load_payload(self) -> dict[str, object]:
        self.ensure()
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError(f"Metadata file is not valid JSON: {self.path}") from exc

        version = payload.get("version")
        if version not in {LEGACY_DB_VERSION, DB_VERSION}:
            raise ValueError(f"Unsupported metadata version in {self.path}")

        hosts = payload.get("hosts")
        if not isinstance(hosts, dict):
            raise ValueError(f"Metadata file has invalid host payloads: {self.path}")

        normalized_hosts, changed = self._normalize_hosts(hosts)
        normalized_payload = {"version": DB_VERSION, "hosts": normalized_hosts}
        if version != DB_VERSION or changed:
            self._save_payload(normalized_payload)

        return normalized_payload

    def _save_payload(self, payload: dict[str, object]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temp_path = self.path.with_name(f"{self.path.name}.{uuid4().hex}.tmp")
        temp_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        temp_path.replace(self.path)

    def _normalize_metadata(self, metadata: HostMetadata) -> HostMetadata:
        normalized_key, legacy_label = normalize_target_key(metadata.target_key)
        if normalized_key == metadata.target_key and (not legacy_label or metadata.label):
            return metadata

        normalized = HostMetadata.from_dict(metadata.to_dict())
        normalized.target_key = normalized_key
        if legacy_label and not normalized.label:
            normalized.label = legacy_label
        return normalized

    def _normalize_hosts(self, hosts: dict[str, object]) -> tuple[dict[str, dict[str, object]], bool]:
        normalized_hosts: dict[str, dict[str, object]] = {}
        changed = False
        for raw_key, raw_item in hosts.items():
            if not isinstance(raw_item, dict):
                raise ValueError(f"Metadata file has invalid host payloads: {self.path}")

            item = dict(raw_item)
            item.setdefault("target_key", str(raw_key))
            metadata = self._normalize_metadata(HostMetadata.from_dict(item))
            existing = normalized_hosts.get(metadata.target_key)
            if existing is None:
                normalized_hosts[metadata.target_key] = metadata.to_dict()
            else:
                merged = self._merge_hosts(HostMetadata.from_dict(existing), metadata)
                normalized_hosts[metadata.target_key] = merged.to_dict()
                changed = True

            if str(raw_key) != metadata.target_key:
                changed = True
            if str(item.get("target_key")) != metadata.target_key:
                changed = True

        return normalized_hosts, changed

    def _merge_hosts(self, existing: HostMetadata, incoming: HostMetadata) -> HostMetadata:
        merged = HostMetadata.from_dict(existing.to_dict())

        if incoming.label and not merged.label:
            merged.label = incoming.label
        if incoming.ssh_username and not merged.ssh_username:
            merged.ssh_username = incoming.ssh_username

        if incoming.notes and incoming.notes != merged.notes:
            merged.notes = "\n\n".join(part for part in [merged.notes, incoming.notes] if part)

        for tag in incoming.tags:
            if tag not in merged.tags:
                merged.tags.append(tag)

        for username, password in incoming.credentials.items():
            merged.credentials[username] = password

        history_pairs = {(item.username, item.password) for item in merged.password_history}
        for record in incoming.password_history:
            pair = (record.username, record.password)
            if pair not in history_pairs:
                merged.password_history.append(record)
                history_pairs.add(pair)

        merged.password_material_available = (
            merged.password_material_available
            or incoming.password_material_available
            or bool(merged.credentials)
            or bool(merged.password_history)
        )
        merged.expected_root_key_present = (
            merged.expected_root_key_present or incoming.expected_root_key_present
        )

        if incoming.authorized_keys_state != "unknown":
            merged.authorized_keys_state = incoming.authorized_keys_state

        if incoming.last_reachable_at and (
            merged.last_reachable_at is None or incoming.last_reachable_at > merged.last_reachable_at
        ):
            merged.last_reachable_at = incoming.last_reachable_at
            merged.last_error = incoming.last_error
        elif incoming.last_error and merged.last_error is None:
            merged.last_error = incoming.last_error

        for snapshot_id in incoming.snapshot_ids:
            if snapshot_id not in merged.snapshot_ids:
                merged.snapshot_ids.append(snapshot_id)

        return merged
