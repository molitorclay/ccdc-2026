"""SSH authorized-key injection and keypair generation for CCDC competition hosts.

Workflow:
  1. (Optional) Generate an RSA keypair with generate_keypair(); the public
     key is appended to data/authorized_keys automatically.
  2. Connect to each host with stored credentials (or prompt the user).
  3. Snapshot the current authorized_keys on the host before any change.
  4. Merge local data/authorized_keys into the remote authorized_keys (no dupes).
  5. Set safe permissions: ~/.ssh = 700, authorized_keys = 600.
  6. Update host metadata to reflect the new key state.

Stealth:  All file writes go through the SSH exec channel (no bash history).
          Key content is transferred via stdin / dd, not via echo.
"""
from __future__ import annotations

import re
import stat
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from vikings_ssh.ssh import SSHClient, SSHError, _shell_quote as _sh_quote


# ---------------------------------------------------------------------------
# Keypair generation
# ---------------------------------------------------------------------------

def generate_keypair(
    identity_file: Path,
    identity_pub_file: Path,
    authorized_keys_file: Path,
    comment: str = "vikings-ssh",
) -> str:
    """Generate an RSA keypair and register the public key locally.

    Writes the private key to *identity_file* (mode 600) and the public key to
    *identity_pub_file*.  The public key line is also appended to
    *authorized_keys_file* so it is picked up by inject_keys immediately.

    Returns the public key line.
    Raises FileExistsError if *identity_file* already exists (caller should
    confirm overwrite before calling).
    """
    if identity_file.exists():
        raise FileExistsError(f"Key already exists at {identity_file}")

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # OpenSSH private key file (the format `ssh` and paramiko both accept).
    private_pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.OpenSSH,
        encryption_algorithm=NoEncryption(),
    ).decode("ascii")

    # "ssh-rsa AAAA... comment" — the authorized_keys / -i flag format.
    pub_raw = private_key.public_key().public_bytes(
        encoding=Encoding.OpenSSH,
        format=PublicFormat.OpenSSH,
    ).decode("ascii")
    pub_line = f"{pub_raw} {comment}"

    # Write private key with strict permissions.
    identity_file.parent.mkdir(parents=True, exist_ok=True)
    identity_file.write_text(private_pem, encoding="utf-8")
    identity_file.chmod(stat.S_IRUSR | stat.S_IWUSR)  # 0600

    # Write public key file.
    identity_pub_file.write_text(pub_line + "\n", encoding="utf-8")

    # Append to authorized_keys (create if absent).
    if authorized_keys_file.exists():
        existing = authorized_keys_file.read_text(encoding="utf-8")
        if pub_line in existing:
            return pub_line  # already present, nothing to append
        sep = "" if existing.endswith("\n") or not existing else "\n"
        authorized_keys_file.write_text(existing + sep + pub_line + "\n", encoding="utf-8")
    else:
        authorized_keys_file.parent.mkdir(parents=True, exist_ok=True)
        authorized_keys_file.write_text(pub_line + "\n", encoding="utf-8")

    return pub_line


# ---------------------------------------------------------------------------
# Key parsing
# ---------------------------------------------------------------------------

_KEY_TYPES = frozenset([
    "ssh-rsa", "ssh-dss", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521", "ssh-ed25519", "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
])

_KEY_LINE_RE = re.compile(
    r"^(ssh-[a-zA-Z0-9@._-]+|ecdsa-sha2-[a-zA-Z0-9@._-]+)\s+\S+"
)


def load_authorized_keys(path: Path) -> list[str]:
    """Read a local authorized_keys file and return non-empty, non-comment lines."""
    if not path.exists():
        return []
    keys: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if _KEY_LINE_RE.match(stripped):
            keys.append(stripped)
    return keys


def parse_authorized_keys(raw: str) -> list[str]:
    """Parse the raw text of a remote authorized_keys into individual key lines."""
    keys: list[str] = []
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        keys.append(stripped)
    return keys


def merge_keys(existing: list[str], to_add: list[str]) -> tuple[list[str], int]:
    """Merge *to_add* into *existing*, returning (merged_list, num_added)."""
    existing_set = set(existing)
    added = 0
    merged = list(existing)
    for key in to_add:
        if key not in existing_set:
            merged.append(key)
            existing_set.add(key)
            added += 1
    return merged, added


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class InjectionResult:
    target_key: str
    connected: bool
    error: str | None = None
    keys_added: int = 0
    skipped: int = 0  # keys already present
    remote_user: str = "root"


# ---------------------------------------------------------------------------
# Core injection logic
# ---------------------------------------------------------------------------

def inject_keys_to_host(
    client: SSHClient,
    keys_to_inject: list[str],
    remote_user: str = "root",
) -> tuple[int, int]:
    """Inject *keys_to_inject* for *remote_user* on the already-connected host.

    Returns (num_added, num_skipped).

    Steps:
      1. Determine the user's home directory.
      2. Ensure ~/.ssh exists with mode 700.
      3. Read current authorized_keys (if any).
      4. Merge and write the updated file with mode 600.
      5. Verify the file was written correctly.
    """
    if not keys_to_inject:
        return 0, 0

    # Resolve home directory for the target user.
    home_result = client.run(f"getent passwd {_sh_quote(remote_user)} | cut -d: -f6")
    if not home_result.ok or not home_result.stdout.strip():
        # Fall back to ~user expansion.
        home_result = client.run(f"echo ~{remote_user}")
    home_dir = home_result.stdout.strip()
    if not home_dir or home_dir == f"~{remote_user}":
        raise SSHError(f"Could not determine home directory for user '{remote_user}'")

    ssh_dir = f"{home_dir}/.ssh"
    ak_path = f"{ssh_dir}/authorized_keys"

    # Ensure ~/.ssh exists with strict permissions.
    client.run_checked(
        f"mkdir -p {_sh_quote(ssh_dir)} && "
        f"chmod 700 {_sh_quote(ssh_dir)} && "
        f"chown {_sh_quote(remote_user)}:{_sh_quote(remote_user)} {_sh_quote(ssh_dir)} 2>/dev/null || true"
    )

    # Read existing keys (may not exist yet).
    existing_raw = ""
    check = client.run(f"cat {_sh_quote(ak_path)} 2>/dev/null")
    if check.ok:
        existing_raw = check.stdout

    existing = parse_authorized_keys(existing_raw)
    merged, added = merge_keys(existing, keys_to_inject)
    skipped = len(keys_to_inject) - added

    # Write the merged file regardless of whether we added anything (ensures
    # permissions and ownership are correct).
    merged_text = "\n".join(merged) + "\n"
    client.write_file_stdin(ak_path, merged_text, mode="600")

    # Fix ownership on authorized_keys.
    client.run(
        f"chown {_sh_quote(remote_user)}:{_sh_quote(remote_user)} {_sh_quote(ak_path)} 2>/dev/null || true"
    )

    # Verify the write landed.
    verify = client.run(f"wc -l < {_sh_quote(ak_path)}")
    if not verify.ok:
        raise SSHError(f"Could not verify authorized_keys was written to {ak_path}")

    return added, skipped
