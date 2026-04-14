from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


DEFAULT_TARGETS_TEMPLATE = """# label,host,port
# web-1,192.0.2.10,22
"""

@dataclass(slots=True, frozen=True)
class AppPaths:
    root: Path
    logo_file: Path
    targets_file: Path
    authorized_keys_file: Path
    identity_file: Path       # private key  (data/id_rsa)
    identity_pub_file: Path   # public key   (data/id_rsa.pub)
    legacy_identity_file: Path       # compatibility fallback (data/id_ed25519)
    legacy_identity_pub_file: Path   # compatibility fallback (data/id_ed25519.pub)
    metadata_file: Path
    snapshot_dir: Path
    snapshot_blob_dir: Path
    snapshot_index_file: Path

    @classmethod
    def from_root(cls, root: Path | None = None) -> "AppPaths":
        env_root = os.environ.get("VIKINGS_SSH_ROOT")
        base = Path(env_root).expanduser().resolve() if env_root else (root or Path.cwd()).resolve()
        data = base / "data"
        return cls(
            root=base,
            logo_file=base / "wwu_logo.txt",
            targets_file=base / "targets.txt",
            authorized_keys_file=data / "authorized_keys",
            identity_file=data / "id_rsa",
            identity_pub_file=data / "id_rsa.pub",
            legacy_identity_file=data / "id_ed25519",
            legacy_identity_pub_file=data / "id_ed25519.pub",
            metadata_file=data / "metadata.json",
            snapshot_dir=base / "snapshots",
            snapshot_blob_dir=base / "snapshots" / "blobs",
            snapshot_index_file=base / "snapshots" / "index.json",
        )

    def ensure(self) -> None:
        (self.root / "data").mkdir(parents=True, exist_ok=True)
        self.snapshot_blob_dir.mkdir(parents=True, exist_ok=True)
        self.snapshot_dir.mkdir(parents=True, exist_ok=True)

        if not self.targets_file.exists():
            self.targets_file.write_text(DEFAULT_TARGETS_TEMPLATE, encoding="utf-8")
