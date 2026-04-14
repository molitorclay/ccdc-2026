"""Low-level SSH client wrapping paramiko.

Design goals:
- Broad algorithm compatibility for old/hardened CCDC boxes.
- No-trace execution: commands run via exec channel (never touches shell history).
  When a shell is explicitly invoked, HISTFILE is suppressed.
- Simple interface: connect, run, read_file, write_file, close.
"""
from __future__ import annotations

import socket
from dataclasses import dataclass
from typing import Iterator
from contextlib import contextmanager

import paramiko
import paramiko.ssh_exception

# Ordered from most-preferred to least.  We include older algorithms so we can
# reach legacy CCDC boxes that haven't been patched or upgraded in years.
_PREFERRED_KEX = [
    "curve25519-sha256",
    "curve25519-sha256@libssh.org",
    "ecdh-sha2-nistp256",
    "ecdh-sha2-nistp384",
    "ecdh-sha2-nistp521",
    "diffie-hellman-group-exchange-sha256",
    "diffie-hellman-group14-sha256",
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group-exchange-sha1",
]

_PREFERRED_CIPHERS = [
    "aes256-ctr",
    "aes192-ctr",
    "aes128-ctr",
    "aes256-cbc",
    "aes192-cbc",
    "aes128-cbc",
    "3des-cbc",
]

_PREFERRED_MACS = [
    "hmac-sha2-256",
    "hmac-sha2-256-etm@openssh.com",
    "hmac-sha2-512",
    "hmac-sha2-512-etm@openssh.com",
    "hmac-sha1",
    "hmac-md5",
    "hmac-sha1-96",
    "hmac-md5-96",
]

_PREFERRED_KEYS = [
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "rsa-sha2-512",
    "rsa-sha2-256",
    "ssh-rsa",
    "ssh-dss",
]


class SSHError(Exception):
    """Raised for connection or command errors."""


@dataclass
class CommandResult:
    stdout: str
    stderr: str
    exit_code: int

    @property
    def ok(self) -> bool:
        return self.exit_code == 0


def _build_transport(host: str, port: int, timeout: float) -> paramiko.Transport:
    """Open a raw Transport with legacy-compatible algorithm preferences."""
    sock = socket.create_connection((host, port), timeout=timeout)
    # Paramiko 4.x defaults RSA pubkey auth to rsa-sha2-512 when the server
    # doesn't advertise server-sig-algs (OpenSSH < 7.4).  Pre-7.2 servers
    # (e.g. the old Debian/Ubuntu boxes we target) only understand the SHA-1
    # "ssh-rsa" signature, so auth_publickey fails silently with those defaults.
    # Disabling the SHA-2 RSA variants forces paramiko to sign with ssh-rsa.
    transport = paramiko.Transport(
        sock,
        disabled_algorithms={"pubkeys": ["rsa-sha2-512", "rsa-sha2-256"]},
    )
    opts = transport.get_security_options()
    # Intersect our preferred list with what paramiko actually compiled in.
    compiled_kex = set(paramiko.Transport._preferred_kex)  # type: ignore[attr-defined]
    compiled_ciphers = set(paramiko.Transport._preferred_ciphers)  # type: ignore[attr-defined]
    compiled_macs = set(paramiko.Transport._preferred_macs)  # type: ignore[attr-defined]
    compiled_keys = set(paramiko.Transport._preferred_keys)  # type: ignore[attr-defined]

    opts.kex = [k for k in _PREFERRED_KEX if k in compiled_kex] or list(compiled_kex)
    opts.ciphers = [c for c in _PREFERRED_CIPHERS if c in compiled_ciphers] or list(compiled_ciphers)
    opts.digests = [m for m in _PREFERRED_MACS if m in compiled_macs] or list(compiled_macs)
    opts.key_types = [k for k in _PREFERRED_KEYS if k in compiled_keys] or list(compiled_keys)
    return transport


def _load_private_key(key_filename: str) -> object:
    """Load an SSH private key without assuming a specific algorithm."""
    loader_names = ("RSAKey", "Ed25519Key", "ECDSAKey", "DSSKey")
    errors: list[str] = []
    for loader_name in loader_names:
        key_cls = getattr(paramiko, loader_name, None)
        if key_cls is None or not hasattr(key_cls, "from_private_key_file"):
            continue
        try:
            return key_cls.from_private_key_file(key_filename)
        except Exception as exc:
            errors.append(f"{loader_name}: {exc}")

    detail = "; ".join(errors) if errors else "no compatible key loaders available"
    raise SSHError(f"Could not load private key {key_filename}: {detail}")


class SSHClient:
    """Paramiko-backed SSH client with legacy algorithm support."""

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
        self._client: paramiko.SSHClient | None = None
        self._transport: paramiko.Transport | None = None

    # ------------------------------------------------------------------
    # Connection lifecycle
    # ------------------------------------------------------------------

    def connect(self) -> None:
        """Establish an authenticated SSH session.

        Tries a standard SSHClient connect first; if algorithm negotiation
        fails, falls back to a direct Transport with a wider algorithm set.
        """
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        connect_kwargs: dict = dict(
            hostname=self.host,
            port=self.port,
            username=self.username,
            timeout=self.connect_timeout,
            look_for_keys=False,
            allow_agent=False,
            banner_timeout=20.0,
            auth_timeout=20.0,
        )
        if self.password is not None:
            connect_kwargs["password"] = self.password
        if self.key_filename is not None:
            connect_kwargs["key_filename"] = self.key_filename

        try:
            client.connect(**connect_kwargs)
            self._client = client
            return
        except paramiko.ssh_exception.AuthenticationException as exc:
            client.close()
            raise SSHError(f"Authentication failed for {self.username}@{self.host}:{self.port}: {exc}") from exc
        except (paramiko.ssh_exception.NoValidConnectionsError, OSError) as exc:
            client.close()
            raise SSHError(f"Cannot reach {self.host}:{self.port}: {exc}") from exc
        except paramiko.ssh_exception.SSHException:
            # Likely algorithm mismatch — fall through to legacy path.
            client.close()

        # Legacy fallback: direct Transport with broader algorithm support.
        try:
            transport = _build_transport(self.host, self.port, self.connect_timeout)
            transport.start_client(timeout=self.connect_timeout)
            if self.key_filename:
                try:
                    key = _load_private_key(self.key_filename)
                    transport.auth_publickey(self.username, key)
                except (SSHError, paramiko.ssh_exception.AuthenticationException):
                    if self.password is None:
                        raise
            if not transport.is_authenticated() and self.password is not None:
                transport.auth_password(self.username, self.password)
            elif not transport.is_authenticated():
                raise SSHError("No credentials provided")

            if not transport.is_authenticated():
                transport.close()
                raise SSHError(f"Authentication failed (legacy) for {self.username}@{self.host}:{self.port}")

            # Attach the raw transport to a fresh SSHClient shell.
            legacy_client = paramiko.SSHClient()
            legacy_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            legacy_client._transport = transport  # type: ignore[attr-defined]
            self._client = legacy_client
            self._transport = transport
        except SSHError:
            raise
        except paramiko.ssh_exception.AuthenticationException as exc:
            raise SSHError(f"Authentication failed (legacy) for {self.username}@{self.host}: {exc}") from exc
        except Exception as exc:
            raise SSHError(f"Failed to connect to {self.host}:{self.port}: {exc}") from exc

    def close(self) -> None:
        if self._client:
            self._client.close()
            self._client = None
        if self._transport:
            self._transport.close()
            self._transport = None

    # ------------------------------------------------------------------
    # Command execution
    # ------------------------------------------------------------------

    def run(self, command: str, timeout: float = 30.0, suppress_history: bool = True) -> CommandResult:
        """Execute a command and return its output.

        Commands are run through the SSH exec channel, which never writes to
        the shell's history.  When *suppress_history* is True, HISTFILE and
        HISTSIZE are also zeroed out in the environment for any sub-shell that
        might be spawned by the command.
        """
        if self._client is None:
            raise SSHError("Not connected")

        if suppress_history:
            # Suppress history in case the command spawns a shell.
            cmd = f"env HISTFILE=/dev/null HISTSIZE=0 HISTFILESIZE=0 {command}"
        else:
            cmd = command

        stdin, stdout, stderr = self._client.exec_command(cmd, timeout=timeout)
        stdin.close()
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        exit_code = stdout.channel.recv_exit_status()
        return CommandResult(stdout=out, stderr=err, exit_code=exit_code)

    def run_checked(self, command: str, timeout: float = 30.0) -> str:
        """Run a command and raise SSHError if it fails."""
        result = self.run(command, timeout=timeout)
        if not result.ok:
            raise SSHError(
                f"Command failed (exit {result.exit_code}): {command!r}\n"
                f"stderr: {result.stderr.strip()}"
            )
        return result.stdout

    # ------------------------------------------------------------------
    # File I/O
    # ------------------------------------------------------------------

    def read_file(self, remote_path: str) -> str:
        """Read a remote file via cat."""
        return self.run_checked(f"cat -- {_shell_quote(remote_path)}")

    def write_file_sftp(self, remote_path: str, contents: str) -> None:
        """Write a file on the remote host via SFTP."""
        if self._client is None:
            raise SSHError("Not connected")
        sftp = self._client.open_sftp()
        try:
            with sftp.open(remote_path, "w") as fh:
                fh.write(contents)
        finally:
            sftp.close()

    def write_file_stdin(self, remote_path: str, contents: str, mode: str = "600") -> None:
        """Write a file on the remote host by piping stdin to tee/dd.

        Falls back to write_file_sftp if tee is not available.
        """
        if self._client is None:
            raise SSHError("Not connected")
        # Use dd to avoid echoing file contents in any process listing.
        cmd = f"dd of={_shell_quote(remote_path)} bs=1 2>/dev/null && chmod {mode} {_shell_quote(remote_path)}"
        stdin, stdout, stderr = self._client.exec_command(
            f"env HISTFILE=/dev/null HISTSIZE=0 {cmd}", timeout=30.0
        )
        stdin.write(contents.encode("utf-8"))
        stdin.channel.shutdown_write()
        exit_code = stdout.channel.recv_exit_status()
        if exit_code != 0:
            err = stderr.read().decode("utf-8", errors="replace").strip()
            raise SSHError(f"write_file_stdin failed for {remote_path}: {err}")

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    def __enter__(self) -> "SSHClient":
        self.connect()
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


def _shell_quote(path: str) -> str:
    """Minimal single-quote escaping for shell arguments."""
    return "'" + path.replace("'", "'\\''") + "'"
