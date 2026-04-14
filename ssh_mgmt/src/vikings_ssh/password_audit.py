"""Password auditing and rotation for CCDC competition hosts.

Workflow:
  1. User provides a candidate password (and optionally a username).
  2. The tool attempts SSH authentication to each host with those credentials.
  3. Hosts that accept the password are flagged.
  4. Optionally: generate a new passphrase and rotate on flagged hosts.
     /etc/shadow and /etc/passwd are snapshotted before any change.

Password format:   word-Word-word-word-NN
  • 4 words joined by "-"
  • One word randomly Title-cased
  • Two-digit random number suffix
  • Example: "marble-Frozen-anchor-clinic-47"

SAFETY: Password changes are done via chpasswd with the payload sent over
stdin — the new password never appears in a process listing or shell log.
If chpasswd exits non-zero, the error is surfaced immediately and no
further accounts on that host are touched.
"""
from __future__ import annotations

import random
import warnings
from dataclasses import dataclass, field

import paramiko.ssh_exception

from vikings_ssh.ssh import SSHClient, SSHError

# ---------------------------------------------------------------------------
# Word list for passphrase generation
# ---------------------------------------------------------------------------

_WORDS = [
    "anchor", "arctic", "arrow", "atlas", "basin", "blade", "blast", "blaze",
    "blend", "block", "bloom", "board", "brave", "brick", "brine", "brisk",
    "broad", "broom", "brush", "cabin", "cable", "cedar", "chalk", "chess",
    "chief", "chime", "chord", "civic", "clamp", "clasp", "clean", "clear",
    "cliff", "climb", "clock", "cloud", "coast", "crane", "crest", "crisp",
    "cross", "crown", "crush", "crust", "curve", "delta", "depot", "depth",
    "drift", "drill", "drone", "eagle", "ember", "epoch", "fence", "fever",
    "field", "finch", "fjord", "flame", "flash", "flask", "fleet", "flint",
    "float", "flood", "flour", "fluid", "forge", "forth", "forum", "frame",
    "fresh", "frost", "glass", "gleam", "glide", "globe", "glove", "grand",
    "graph", "grasp", "grass", "gravel", "graze", "green", "grind", "grove",
    "haven", "hedge", "helix", "herbs", "hinge", "horse", "hound", "hover",
    "index", "ingot", "inlet", "ivory", "jewel", "judge", "knife", "knoll",
    "lance", "latch", "lemon", "level", "light", "linen", "lodge", "lunar",
    "maple", "marble", "march", "marsh", "merit", "metal", "model", "moose",
    "mount", "mouse", "naval", "noble", "north", "notch", "novel", "ocean",
    "orbit", "otter", "oxide", "ozone", "paste", "patch", "pause", "pearl",
    "perch", "petal", "pilot", "pinch", "pixel", "place", "plain", "plank",
    "plant", "plaza", "pluck", "polar", "prism", "probe", "prose", "pulse",
    "queen", "quest", "quick", "quiet", "quill", "radar", "raven", "reach",
    "realm", "relay", "resin", "rider", "ridge", "rivet", "robin", "rocky",
    "rough", "round", "route", "ruler", "salve", "sauce", "scale", "scout",
    "screw", "serve", "shade", "shaft", "shale", "sharp", "shelf", "shell",
    "shift", "shore", "shrub", "sigma", "skate", "skull", "slate", "sleek",
    "slope", "smash", "smoke", "snare", "solar", "sound", "spark", "spear",
    "speed", "spell", "spine", "spire", "spore", "spray", "stack", "staff",
    "stain", "stake", "stalk", "stark", "steal", "steel", "steep", "stern",
    "stick", "still", "stoic", "stone", "storm", "stout", "strap", "straw",
    "strip", "stump", "style", "surge", "swamp", "swift", "swirl", "sword",
    "table", "talon", "taunt", "tempo", "thorn", "tidal", "tiger", "tight",
    "timer", "token", "torch", "touch", "tower", "trace", "track", "trail",
    "train", "trawl", "trick", "troop", "trout", "trove", "truce", "truck",
    "tuner", "twine", "twist", "ultra", "under", "union", "upper", "urban",
    "valid", "valve", "vapor", "vault", "venom", "vigor", "viper", "vista",
    "vocal", "voter", "waltz", "watch", "water", "weave", "wedge", "whale",
    "wheat", "wheel", "whirl", "white", "whole", "winds", "witch", "woods",
    "world", "wrath", "wrist", "yacht", "yearn", "yield", "zebra", "zonal",
]


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class HostAuditResult:
    """Result of an SSH-auth password check (quick audit)."""
    target_key: str
    username: str
    authenticated: bool
    error: str | None = None


@dataclass
class ShadowEntry:
    username: str
    stored_hash: str  # full hash field, e.g. "$6$salt$..."


@dataclass
class DeepAuditFinding:
    username: str
    password_matches: bool


@dataclass
class DeepHostAuditResult:
    """Result of a shadow-file password check (deep audit)."""
    target_key: str
    ssh_username: str       # account used to log in
    ssh_password: str | None = None
    connected: bool = False
    error: str | None = None
    findings: list[DeepAuditFinding] = field(default_factory=list)

    @property
    def matched_accounts(self) -> list[str]:
        return [f.username for f in self.findings if f.password_matches]

    @property
    def checked_count(self) -> int:
        return len(self.findings)


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------

def generate_passphrase() -> str:
    """Return a passphrase in the format: word-Word-word-word-NN."""
    words = random.sample(_WORDS, 4)
    cap_index = random.randrange(4)
    words[cap_index] = words[cap_index].title()
    number = random.randint(10, 99)
    return "-".join(words) + f"-{number}"


def try_auth(host: str, port: int, username: str, password: str, timeout: float = 8.0) -> tuple[bool, str | None]:
    """Attempt SSH password authentication.  Returns (success, error_or_None)."""
    client = SSHClient(
        host=host,
        port=port,
        username=username,
        password=password,
        connect_timeout=timeout,
    )
    try:
        client.connect()
        return True, None
    except SSHError as exc:
        msg = str(exc)
        # Distinguish auth failure from unreachable so the caller can surface it clearly.
        return False, msg
    finally:
        client.close()


def parse_shadow_entries(shadow_text: str) -> list[ShadowEntry]:
    """Parse /etc/shadow text and return accounts that have a real password hash."""
    entries: list[ShadowEntry] = []
    for line in shadow_text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) < 2:
            continue
        username, pw_field = parts[0], parts[1]
        # Skip locked ("!", "!!"), no-login ("*"), and empty fields.
        if pw_field and pw_field not in {"!", "!!", "*", "x", ""}:
            entries.append(ShadowEntry(username=username, stored_hash=pw_field))
    return entries


def verify_shadow_password(stored_hash: str, candidate: str) -> bool:
    """Return True if *candidate* hashes to *stored_hash*.

    Uses the stdlib ``crypt`` module (deprecated in 3.13 but present in 3.12).
    Falls back to a remote-side check via the caller if unavailable.
    Supports $1$ (MD5), $5$ (SHA-256), $6$ (SHA-512), and $2b$ (bcrypt) prefixes
    — anything the local glibc crypt() understands.
    """
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            import crypt  # noqa: PLC0415
        return crypt.crypt(candidate, stored_hash) == stored_hash
    except ImportError:
        raise SSHError(
            "Python 'crypt' module not available on this system. "
            "Deep audit requires Python ≤ 3.12 on the operator machine."
        )
    except Exception:
        return False


def change_password(client: SSHClient, username: str, new_password: str) -> None:
    """Change *username*'s password on the already-connected host via chpasswd.

    The new password is sent over stdin — it never appears in a process
    listing, shell log, or command history.  Raises SSHError on failure.
    """
    if "\n" in new_password or "\r" in new_password or ":" in new_password:
        raise SSHError("New password contains illegal characters (':', newline).")

    if client._client is None:
        raise SSHError("Not connected")

    stdin, stdout, stderr = client._client.exec_command(
        "env HISTFILE=/dev/null HISTSIZE=0 HISTFILESIZE=0 chpasswd",
        timeout=15.0,
    )
    stdin.write(f"{username}:{new_password}\n".encode("utf-8"))
    stdin.channel.shutdown_write()
    exit_code = stdout.channel.recv_exit_status()
    err = stderr.read().decode("utf-8", errors="replace").strip()
    if exit_code != 0:
        raise SSHError(f"chpasswd failed (exit {exit_code}): {err}")
