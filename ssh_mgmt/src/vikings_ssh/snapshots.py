from __future__ import annotations

import hashlib
import json
from pathlib import Path
from uuid import uuid4

from vikings_ssh.metadata_store import utc_now_iso
from vikings_ssh.models import SnapshotEntry, normalize_target_key

INDEX_VERSION = 3
LEGACY_INDEX_VERSION_1 = 1
LEGACY_INDEX_VERSION_2 = 2


class SnapshotStore:
    def __init__(self, root: Path, blob_dir: Path, index_file: Path) -> None:
        self.root = root
        self.blob_dir = blob_dir
        self.index_file = index_file

    def ensure(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        self.blob_dir.mkdir(parents=True, exist_ok=True)
        if not self.index_file.exists():
            self._save_index({"version": INDEX_VERSION, "snapshots": []})

    def create_snapshot(
        self,
        target_key: str,
        source_path: str,
        contents: str,
        reason: str,
        mode: str | None = None,
        owner_uid: int | None = None,
        owner_gid: int | None = None,
    ) -> SnapshotEntry:
        self.ensure()
        normalized_target_key, _ = normalize_target_key(target_key)
        encoded = contents.encode("utf-8")
        digest = hashlib.sha256(encoded).hexdigest()
        snapshot_id = uuid4().hex[:12]
        blob_name = f"{snapshot_id}.txt"
        blob_path = self.blob_dir / blob_name
        blob_path.write_text(contents, encoding="utf-8")

        entry = SnapshotEntry(
            snapshot_id=snapshot_id,
            target_key=normalized_target_key,
            source_path=source_path,
            reason=reason,
            created_at=utc_now_iso(),
            blob_path=str(blob_path.relative_to(self.root)),
            sha256=digest,
            size_bytes=len(encoded),
            mode=mode,
            owner_uid=owner_uid,
            owner_gid=owner_gid,
        )

        payload = self._load_index()
        payload["snapshots"].append(entry.to_dict())
        self._save_index(payload)
        return entry

    def list_snapshots(self, target_key: str | None = None) -> list[SnapshotEntry]:
        payload = self._load_index()
        entries = [SnapshotEntry.from_dict(item) for item in payload["snapshots"]]
        if target_key is not None:
            normalized_target_key, _ = normalize_target_key(target_key)
            entries = [entry for entry in entries if entry.target_key == normalized_target_key]
        return sorted(entries, key=lambda entry: entry.created_at, reverse=True)

    def get_snapshot(self, snapshot_id: str) -> SnapshotEntry | None:
        payload = self._load_index()
        for item in payload["snapshots"]:
            entry = SnapshotEntry.from_dict(item)
            if entry.snapshot_id == snapshot_id:
                return entry
        return None

    def read_snapshot_contents(self, snapshot_id: str) -> str:
        entry = self.get_snapshot(snapshot_id)
        if entry is None:
            raise ValueError(f"Snapshot '{snapshot_id}' not found")
        blob_path = self.root / entry.blob_path
        if not blob_path.exists():
            raise ValueError(f"Snapshot blob is missing for '{snapshot_id}': {blob_path}")
        contents = blob_path.read_text(encoding="utf-8")
        digest = hashlib.sha256(contents.encode("utf-8")).hexdigest()
        if digest != entry.sha256:
            raise ValueError(f"Snapshot blob checksum mismatch for '{snapshot_id}'")
        return contents

    def _load_index(self) -> dict[str, object]:
        self.ensure()
        try:
            payload = json.loads(self.index_file.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError(f"Snapshot index is not valid JSON: {self.index_file}") from exc

        version = payload.get("version")
        if version not in {LEGACY_INDEX_VERSION_1, LEGACY_INDEX_VERSION_2, INDEX_VERSION}:
            raise ValueError(f"Unsupported snapshot index version in {self.index_file}")

        snapshots = payload.get("snapshots")
        if not isinstance(snapshots, list):
            raise ValueError(f"Snapshot index has invalid entries: {self.index_file}")

        normalized_snapshots: list[dict[str, object]] = []
        changed = False
        for item in snapshots:
            if not isinstance(item, dict):
                raise ValueError(f"Snapshot index has invalid entries: {self.index_file}")
            entry = SnapshotEntry.from_dict(item)
            normalized_target_key, _ = normalize_target_key(entry.target_key)
            if normalized_target_key != entry.target_key:
                changed = True
            normalized_snapshots.append(
                SnapshotEntry(
                    snapshot_id=entry.snapshot_id,
                    target_key=normalized_target_key,
                    source_path=entry.source_path,
                    reason=entry.reason,
                    created_at=entry.created_at,
                    blob_path=entry.blob_path,
                    sha256=entry.sha256,
                    size_bytes=entry.size_bytes,
                    mode=entry.mode,
                    owner_uid=entry.owner_uid,
                    owner_gid=entry.owner_gid,
                ).to_dict()
            )

        normalized_payload = {"version": INDEX_VERSION, "snapshots": normalized_snapshots}
        if version != INDEX_VERSION or changed:
            self._save_index(normalized_payload)

        return normalized_payload

    def _save_index(self, payload: dict[str, object]) -> None:
        self.index_file.parent.mkdir(parents=True, exist_ok=True)
        temp_path = self.index_file.with_name(f"{self.index_file.name}.{uuid4().hex}.tmp")
        temp_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        temp_path.replace(self.index_file)
