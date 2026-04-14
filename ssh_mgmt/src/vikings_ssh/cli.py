from __future__ import annotations

import argparse
from datetime import datetime, timezone
import getpass
from pathlib import Path
import sys
import time
from typing import Callable

from vikings_ssh.app import App
from vikings_ssh.config import AppPaths
from vikings_ssh.inventory import InventoryError
from vikings_ssh.models import SnapshotEntry, Target
from vikings_ssh.render import (
    banner,
    render_audit_results,
    render_credential_export,
    render_credentials,
    render_dashboard,
    render_deep_audit_results,
    render_injection_results,
    render_metadata,
    render_notice,
    render_snapshot_restore_results,
    render_snapshots,
    render_targets,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vikings-ssh", description="WWU vi_kings SSH management tool")
    parser.add_argument("--root", type=Path, default=None, help="Project root path")

    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("menu", help="Launch the interactive menu")

    dashboard = subparsers.add_parser("dashboard", help="Run the live monitoring dashboard")
    dashboard.add_argument("--timeout", type=float, default=3.0, help="Per-host probe timeout in seconds")
    dashboard.add_argument("--workers", type=int, default=16, help="Maximum concurrent checks")
    dashboard.add_argument("--interval", type=float, default=10.0, help="Refresh interval in seconds")
    dashboard.add_argument("--once", action="store_true", help="Render one snapshot and exit")

    subparsers.add_parser("targets", help="List configured targets")

    add_host = subparsers.add_parser(
        "add-host",
        help="Add a host to the inventory (non-interactive; use 'menu' for a wizard)",
    )
    add_host.add_argument("--label", required=True, help="Short label / display name")
    add_host.add_argument("--host", required=True, help="Hostname or IP address")
    add_host.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    add_host.add_argument("--username", default=None, help="SSH login user (default: root)")
    add_host.add_argument(
        "--test",
        action="store_true",
        help="Test the SSH connection after adding (interactively prompts for a password if the key is rejected)",
    )

    subparsers.add_parser("metadata", help="Show stored host metadata")
    credentials = subparsers.add_parser(
        "credentials",
        help="Show local SSH key material and saved machine credentials",
    )
    credentials.add_argument("--target-key", default=None, help="Only show credentials for this target key (host:port)")
    export_credentials = subparsers.add_parser(
        "export-credentials",
        help="Write a readable text export of current passwords and SSH keys",
    )
    export_credentials.add_argument("--target-key", default=None, help="Only export this target key (host:port)")
    export_credentials.add_argument("--output", type=Path, default=None, help="Write export to this file")

    snapshots = subparsers.add_parser("snapshots", help="List local snapshots")
    snapshots.add_argument("--target-key", default=None, help="Filter to one target key")

    snapshot_add = subparsers.add_parser("snapshot-add", help="Store a local snapshot file")
    snapshot_add.add_argument("--target-key", required=True, help="Metadata target key")
    snapshot_add.add_argument("--source-path", required=True, help="Original host-side file path")
    snapshot_add.add_argument("--from-file", type=Path, required=True, help="Local file to archive")
    snapshot_add.add_argument("--reason", default="manual", help="Snapshot reason label")
    snapshot_restore = subparsers.add_parser(
        "snapshot-restore",
        help="Restore one or more snapshots to a target host",
    )
    snapshot_restore.add_argument("--target-key", required=True, help="Target key (host:port)")
    snapshot_restore.add_argument(
        "--snapshot-id",
        action="append",
        default=[],
        help="Snapshot ID to restore; repeat for multiple files",
    )

    # Quick password audit (SSH auth check)
    audit = subparsers.add_parser("audit-passwords", help="Check whether hosts accept a given password via SSH auth")
    audit.add_argument("--target-key", default=None, help="Only audit this target key (host:port)")
    audit.add_argument("--username", default=None, help="Username to test (default: each target's stored SSH user, or root)")
    audit.add_argument("--rotate", action="store_true", help="Prompt to rotate passwords on hosts that accepted the credential")

    # Manual password change
    chpw = subparsers.add_parser("change-password", help="Change a user account's password on a target host")
    chpw.add_argument("--target-key", required=True, help="Target key (host:port)")
    chpw.add_argument("--account", required=True, help="Account whose password to change")
    chpw.add_argument("--generate", action="store_true", help="Generate a passphrase instead of prompting")

    # Deep password audit (shadow file check)
    deep_audit = subparsers.add_parser(
        "deep-audit-passwords",
        help="Log in and check every /etc/shadow account against a candidate password",
    )
    deep_audit.add_argument("--target-key", default=None, help="Only audit this target key (host:port)")
    deep_audit.add_argument("--username", default=None, help="SSH login username (overrides stored metadata)")
    deep_audit.add_argument("--rotate", action="store_true", help="Prompt to rotate matched accounts after audit")

    # Key generation
    genkey = subparsers.add_parser("generate-key", help="Generate an RSA keypair and add the public key to authorized_keys")
    genkey.add_argument("--comment", default="vikings-ssh", help="Key comment (default: vikings-ssh)")
    genkey.add_argument("--overwrite", action="store_true", help="Overwrite an existing keypair")

    # Key injection
    inject = subparsers.add_parser("inject-keys", help="Push authorized keys to target hosts")
    inject.add_argument("--target-key", default=None, help="Only inject to this target key (host:port)")
    inject.add_argument("--user", default="root", help="Remote user account to configure (default: root)")

    return parser


def _print_header(app: App) -> None:
    print(banner(app.paths.logo_file))


def _clear_screen() -> None:
    if sys.stdout.isatty():
        print("\033[2J\033[H", end="")


def _run_dashboard(app: App, timeout: float, workers: int, interval: float, once: bool) -> None:
    live_mode = not once and sys.stdout.isatty()
    refresh_interval = max(1.0, interval)
    try:
        while True:
            snapshot = app.dashboard(
                timeout=timeout,
                workers=workers,
                refresh_interval=refresh_interval,
            )
            if live_mode:
                _clear_screen()
            print(render_dashboard(snapshot))
            if not live_mode:
                return
            time.sleep(refresh_interval)
    except KeyboardInterrupt:
        if live_mode:
            print()


def _run_targets(app: App) -> None:
    print(render_targets(app.load_targets()))


def _prompt_port(prompt: str, default: int = 22) -> int | None:
    raw = input(f"{prompt} [{default}]: ").strip()
    if not raw:
        return default
    try:
        port = int(raw)
    except ValueError:
        print(render_notice(f"'{raw}' is not a valid port number."))
        return None
    if port < 1 or port > 65535:
        print(render_notice(f"Port {port} is outside the valid range 1-65535."))
        return None
    return port


def _test_new_target_connection(app: App, target: Target, username: str) -> None:
    """Try SSH key auth, then optionally password auth, storing creds on success."""
    print(f"  Testing connection to {target.display_name} …")
    connected, label, error = app.test_target_connection(target, username=username)
    if connected:
        print(render_notice(f"  ✓ Authenticated via {label}."))
        return

    if error:
        print(f"  {label} did not authenticate: {error}")

    answer = input("  Try a password? [y/N] ").strip().lower()
    if answer != "y":
        return
    password = getpass.getpass(f"  Password for {username}@{target.host}: ")
    if not password:
        print(render_notice("  No password entered, skipping."))
        return
    connected, label, error = app.test_target_connection(
        target,
        username=username,
        password=password,
    )
    if connected:
        print(render_notice(f"  ✓ Authenticated via {label}. Password stored in metadata."))
    else:
        print(render_notice(f"  ✗ Password auth failed: {error}"))


def _run_add_host(
    app: App,
    label: str,
    host: str,
    port: int,
    username: str | None,
    test: bool,
) -> None:
    try:
        target = app.add_target(label=label, host=host, port=port, username=username)
    except InventoryError as exc:
        print(render_notice(f"Could not add host: {exc}"))
        return
    print(f"Added {target.display_name} to {app.paths.targets_file}.")
    if test:
        _test_new_target_connection(app, target, username=username or "root")


def _menu_add_host(app: App) -> None:
    print("Add a new host to the inventory.")
    print("(Press Enter at any required prompt to abort.)")
    print()

    label = input("Label / display name: ").strip()
    if not label:
        print(render_notice("Label is required, aborting."))
        return

    host = input("Host (IP or DNS name): ").strip()
    if not host:
        print(render_notice("Host is required, aborting."))
        return

    port = _prompt_port("SSH port", default=22)
    if port is None:
        return

    username_raw = input("SSH login user [root]: ").strip()
    username = username_raw or None

    try:
        target = app.add_target(label=label, host=host, port=port, username=username)
    except InventoryError as exc:
        print(render_notice(f"Could not add host: {exc}"))
        return

    print()
    print(f"Added {target.display_name} to {app.paths.targets_file}.")

    answer = input("Test SSH connection now? [Y/n] ").strip().lower()
    if answer in ("", "y", "yes"):
        print()
        _test_new_target_connection(app, target, username=username or "root")


def _run_metadata(app: App) -> None:
    print(render_metadata(app.list_metadata()))


def _run_credentials(app: App, target_key: str | None) -> None:
    report = app.list_credentials(target_key=target_key)
    if target_key and not report.hosts:
        print(render_notice(f"No target found with key '{target_key}'."))
        return
    print(render_credentials(report))


def _default_credential_export_path(app: App) -> Path:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return app.paths.metadata_file.parent / "exports" / f"credentials-{timestamp}.txt"


def _run_export_credentials(app: App, target_key: str | None, output: Path | None) -> None:
    report = app.list_credentials(target_key=target_key)
    if target_key and not report.hosts:
        print(render_notice(f"No target found with key '{target_key}'."))
        return

    export_path = (output or _default_credential_export_path(app)).expanduser()
    export_path.parent.mkdir(parents=True, exist_ok=True)
    export_text = render_credential_export(
        report,
        generated_at=datetime.now(timezone.utc).isoformat(),
    )
    export_path.write_text(export_text + "\n", encoding="utf-8")
    print(f"Credential export written to {export_path}.")


def _run_snapshots(app: App, target_key: str | None) -> None:
    print(render_snapshots(app.list_snapshots(target_key=target_key)))


def _run_snapshot_add(app: App, target_key: str, source_path: str, from_file: Path, reason: str) -> None:
    entry = app.create_snapshot(target_key=target_key, source_path=source_path, from_file=from_file, reason=reason)
    print(f"Stored snapshot {entry.snapshot_id} for {entry.target_key} from {entry.source_path}.")


def _parse_index_selection(raw: str, max_index: int) -> list[int]:
    chosen: list[int] = []
    seen: set[int] = set()
    for part in [item.strip() for item in raw.split(",") if item.strip()]:
        if "-" in part:
            start_raw, end_raw = part.split("-", 1)
            try:
                start = int(start_raw)
                end = int(end_raw)
            except ValueError as exc:
                raise ValueError(f"Invalid range '{part}'") from exc
            if start > end:
                raise ValueError(f"Invalid range '{part}'")
            values = range(start, end + 1)
        else:
            try:
                values = [int(part)]
            except ValueError as exc:
                raise ValueError(f"Invalid selection '{part}'") from exc

        for value in values:
            if value < 1 or value > max_index:
                raise ValueError(f"Selection {value} is outside the valid range 1-{max_index}")
            if value not in seen:
                chosen.append(value)
                seen.add(value)
    return chosen


def _print_snapshot_candidates(snapshots: list[SnapshotEntry]) -> None:
    for index, snapshot in enumerate(snapshots, start=1):
        print(
            f"[{index}] {snapshot.source_path}  "
            f"{snapshot.created_at}  "
            f"{snapshot.snapshot_id}  "
            f"[{snapshot.reason}]"
        )


def _selected_snapshots_for_restore(
    snapshots: list[SnapshotEntry],
    selections: list[int],
) -> list[SnapshotEntry]:
    chosen = [snapshots[index - 1] for index in selections]
    source_paths = [snapshot.source_path for snapshot in chosen]
    duplicates = {path for path in source_paths if source_paths.count(path) > 1}
    if duplicates:
        duplicate_list = ", ".join(sorted(duplicates))
        raise ValueError(
            f"Choose only one snapshot per file. Duplicate file selections: {duplicate_list}"
        )
    return chosen


def _snapshot_restore_priority(snapshot: SnapshotEntry) -> tuple[int, str]:
    if snapshot.source_path.endswith("/authorized_keys"):
        return 0, snapshot.source_path
    if snapshot.source_path == "/etc/passwd":
        return 1, snapshot.source_path
    if snapshot.source_path == "/etc/shadow":
        return 2, snapshot.source_path
    return 10, snapshot.source_path


def _run_snapshot_restore(app: App, target_key: str, snapshot_ids: list[str]) -> None:
    target = app.get_target(target_key)
    if target is None:
        print(render_notice(f"No target found with key '{target_key}'."))
        return

    try:
        results = app.restore_snapshots(
            target,
            snapshot_ids=snapshot_ids,
            credential_prompt=_credential_prompt,
            progress=print,
        )
    except Exception as exc:
        print(render_notice(f"ERROR: {exc}"))
        return

    print()
    print(render_snapshot_restore_results(results))


def _menu_snapshot_restore(app: App) -> None:
    snapshots = app.list_snapshots()
    if not snapshots:
        print(render_notice("No snapshots stored."))
        return

    targets_with_snapshots = sorted({entry.target_key for entry in snapshots})
    print("Targets With Snapshots")
    print("----------------------")
    for target_key in targets_with_snapshots:
        target = app.get_target(target_key)
        display_name = target.display_name if target is not None else target_key
        count = len([entry for entry in snapshots if entry.target_key == target_key])
        print(f"{target_key}  {display_name}  ({count} snapshot(s))")

    print()
    target_key = input("Target key to restore: ").strip()
    if not target_key:
        print(render_notice("No target selected, aborting."))
        return

    target = app.get_target(target_key)
    if target is None:
        print(render_notice(f"No target found with key '{target_key}'."))
        return

    target_snapshots = app.list_snapshots(target_key=target.key)
    if not target_snapshots:
        print(render_notice(f"No snapshots found for '{target.key}'."))
        return

    print()
    print(
        "Restore flow: choose one snapshot per file. "
        "For account recovery, restore matching /etc/passwd and /etc/shadow snapshots together."
    )
    _print_snapshot_candidates(target_snapshots)
    print()
    selection_raw = input("Snapshot numbers to restore (comma-separated, ranges allowed): ").strip()
    if not selection_raw:
        print(render_notice("No snapshots selected, aborting."))
        return

    try:
        selections = _parse_index_selection(selection_raw, len(target_snapshots))
        chosen = _selected_snapshots_for_restore(target_snapshots, selections)
    except ValueError as exc:
        print(render_notice(str(exc)))
        return
    chosen.sort(key=_snapshot_restore_priority)

    print()
    print("Restore Plan")
    print("------------")
    for snapshot in chosen:
        print(f"{snapshot.source_path} <- {snapshot.snapshot_id} ({snapshot.created_at}, {snapshot.reason})")
    answer = input("Proceed with restore? [y/N] ").strip().lower()
    if answer != "y":
        return

    print()
    _run_snapshot_restore(app, target.key, [snapshot.snapshot_id for snapshot in chosen])


def _credential_prompt(target: Target) -> tuple[str, str | None]:
    """Ask the user for SSH credentials for *target* interactively."""
    print(render_notice(f"Interactive SSH credentials required for {target.display_name}."))
    username = input(f"  Username [{target.username or 'root'}]: ").strip() or (target.username or "root")
    password = getpass.getpass(f"  Password for {username}@{target.host}: ")
    return username, password or None


def _run_audit_passwords(
    app: App,
    target_key: str | None,
    username: str | None,
    rotate: bool,
) -> None:
    targets = app.load_targets()
    if target_key:
        targets = [t for t in targets if t.key == target_key]
        if not targets:
            print(render_notice(f"No target found with key '{target_key}'."))
            return

    candidate_password = getpass.getpass("Password to test: ")
    if not candidate_password:
        print(render_notice("No password entered, aborting."))
        return

    candidate_username = username or ""
    print(f"\nAuditing {len(targets)} target(s) …\n")
    results = app.audit_passwords(
        targets,
        candidate_username=candidate_username,
        candidate_password=candidate_password,
        progress=print,
    )
    print()
    print(render_audit_results(results))

    if not rotate:
        return

    _offer_rotation(app, targets, results, candidate_username, candidate_password)


def _offer_rotation(
    app: App,
    targets: list[Target],
    audit_results: list,
    candidate_username: str,
    candidate_password: str,
) -> None:
    """For each host that accepted the audited password, offer to rotate it."""
    for i, result in enumerate(audit_results):
        if not result.authenticated:
            continue
        target = targets[i]
        username = result.username
        print()
        print(render_notice(f"{target.display_name}: accepted password for '{username}'."))
        accounts_raw = input(
            f"  Accounts to rotate (comma-separated, Enter for just '{username}'): "
        ).strip()
        if accounts_raw:
            usernames_to_rotate = [u.strip() for u in accounts_raw.split(",") if u.strip()]
        else:
            usernames_to_rotate = [username]

        answer = input(f"  Rotate {usernames_to_rotate} on this host? [y/N] ").strip().lower()
        if answer != "y":
            continue
        print()
        try:
            rotated = app.rotate_passwords(
                target,
                username=username,
                current_password=candidate_password,
                usernames_to_rotate=usernames_to_rotate,
                progress=print,
            )
            print()
            print(render_notice("New credentials (store securely!):"))
            for uname, new_pass in rotated.items():
                print(f"  {uname}: {new_pass}")
        except Exception as exc:
            print(render_notice(f"ERROR: {exc}"))


def _run_inject_keys(app: App, target_key: str | None, user: str) -> None:
    targets = app.load_targets()
    if target_key:
        targets = [t for t in targets if t.key == target_key]
        if not targets:
            print(render_notice(f"No target found with key '{target_key}'."))
            return

    try:
        results = app.inject_authorized_keys(
            targets,
            remote_user=user,
            credential_prompt=_credential_prompt,
            progress=print,
        )
    except ValueError as exc:
        print(render_notice(str(exc)))
        return

    print()
    print(render_injection_results(results))


def _prompt_new_password(account: str, generate: bool) -> str | None:
    """Return a new password: generated if *generate*, otherwise prompted via getpass.

    Returns None to signal the caller should abort.
    """
    if generate:
        return None  # let app.change_account_password generate one
    pw = getpass.getpass(f"  New password for '{account}': ")
    if not pw:
        return ""  # empty string signals abort to caller
    confirm = getpass.getpass(f"  Confirm password: ")
    if pw != confirm:
        print(render_notice("  Passwords do not match, aborting."))
        return ""
    return pw


def _run_change_password(app: App, target_key: str, account: str, generate: bool) -> None:
    targets = app.load_targets()
    matches = [t for t in targets if t.key == target_key]
    if not matches:
        print(render_notice(f"No target found with key '{target_key}'."))
        return
    target = matches[0]

    new_password = _prompt_new_password(account, generate)
    if new_password == "":  # empty = aborted
        return

    print()
    try:
        result = app.change_account_password(
            target,
            account=account,
            new_password=new_password,
            credential_prompt=_credential_prompt,
            progress=print,
        )
        print()
        print(render_notice(f"New password for '{account}' on {target.display_name}:"))
        print(f"  {result}")
    except Exception as exc:
        print(render_notice(f"ERROR: {exc}"))


def _menu_change_password(app: App) -> None:
    targets = app.load_targets()
    if not targets:
        print(render_notice("No targets configured."))
        return

    # Show target list and let the user pick.
    print(render_targets(targets))
    print()
    target_key = input("Target key: ").strip()
    matches = [t for t in targets if t.key == target_key]
    if not matches:
        print(render_notice(f"No target found with key '{target_key}'."))
        return
    target = matches[0]

    account = input("Account to change: ").strip()
    if not account:
        print(render_notice("No account specified, aborting."))
        return

    choice = input("  [g] Generate passphrase  [m] Enter manually  > ").strip().lower()
    if choice == "g":
        new_password = None
    elif choice == "m":
        new_password = _prompt_new_password(account, generate=False)
        if new_password == "":
            return
    else:
        print(render_notice("Invalid choice, aborting."))
        return

    print()
    try:
        result = app.change_account_password(
            target,
            account=account,
            new_password=new_password,
            credential_prompt=_credential_prompt,
            progress=print,
        )
        print()
        print(render_notice(f"New password for '{account}' on {target.display_name}:"))
        print(f"  {result}")
    except Exception as exc:
        print(render_notice(f"ERROR: {exc}"))


def _menu_credentials(app: App) -> None:
    target_filter = input("Target key to limit to (blank = all): ").strip() or None
    _run_credentials(app, target_filter)


def _menu_export_credentials(app: App) -> None:
    target_filter = input("Target key to limit to (blank = all): ").strip() or None
    output_raw = input("Output path (blank = default export file): ").strip()
    output = Path(output_raw).expanduser() if output_raw else None
    _run_export_credentials(app, target_filter, output)


def _run_deep_audit_passwords(
    app: App,
    target_key: str | None,
    username: str | None,
    rotate: bool,
) -> None:
    targets = app.load_targets()
    if target_key:
        targets = [t for t in targets if t.key == target_key]
        if not targets:
            print(render_notice(f"No target found with key '{target_key}'."))
            return
    if username:
        targets = [
            Target(
                host=target.host,
                port=target.port,
                label=target.label,
                username=username,
            )
            for target in targets
        ]

    candidate_password = getpass.getpass("Password to check against shadow hashes: ")
    if not candidate_password:
        print(render_notice("No password entered, aborting."))
        return

    # If a username override was given, patch targets' prompting credential.
    def prompt(target: Target) -> tuple[str, str | None]:
        if username:
            pw = getpass.getpass(f"  SSH password for {username}@{target.host}: ")
            return username, pw or None
        return _credential_prompt(target)

    print(f"\nDeep-auditing {len(targets)} target(s) …\n")
    results = app.deep_audit_passwords(
        targets,
        candidate_password=candidate_password,
        credential_prompt=prompt,
        progress=print,
    )
    print()
    print(render_deep_audit_results(results))

    if not rotate:
        return

    # Offer rotation for any hosts with matched accounts.
    for i, result in enumerate(results):
        if not result.connected or not result.matched_accounts:
            continue
        target = targets[i]
        print()
        print(render_notice(
            f"{target.display_name}: {len(result.matched_accounts)} account(s) matched — "
            + ", ".join(result.matched_accounts)
        ))
        answer = input("  Rotate these passwords now? [y/N] ").strip().lower()
        if answer != "y":
            continue
        print()
        try:
            rotated = app.rotate_passwords(
                target,
                username=result.ssh_username,
                current_password=result.ssh_password,
                usernames_to_rotate=result.matched_accounts,
                credential_prompt=prompt,
                progress=print,
            )
            print()
            print(render_notice("New credentials (store securely!):"))
            for uname, new_pass in rotated.items():
                print(f"  {uname}: {new_pass}")
        except Exception as exc:
            print(render_notice(f"ERROR: {exc}"))


def _menu_deep_audit_passwords(app: App) -> None:
    targets = app.load_targets()
    if not targets:
        print(render_notice("No targets configured."))
        return
    target_filter = input("Target key to limit to (blank = all): ").strip() or None
    if target_filter:
        targets = [t for t in targets if t.key == target_filter]
        if not targets:
            print(render_notice(f"No target found with key '{target_filter}'."))
            return
    candidate_password = getpass.getpass("Password to check against shadow hashes: ")
    if not candidate_password:
        print(render_notice("No password entered, aborting."))
        return

    print(f"\nDeep-auditing {len(targets)} target(s) …\n")
    results = app.deep_audit_passwords(
        targets,
        candidate_password=candidate_password,
        credential_prompt=_credential_prompt,
        progress=print,
    )
    print()
    print(render_deep_audit_results(results))

    for i, result in enumerate(results):
        if not result.connected or not result.matched_accounts:
            continue
        target = targets[i]
        print()
        print(render_notice(
            f"{target.display_name}: matched — " + ", ".join(result.matched_accounts)
        ))
        answer = input("  Rotate these passwords now? [y/N] ").strip().lower()
        if answer != "y":
            continue
        print()
        try:
            rotated = app.rotate_passwords(
                target,
                username=result.ssh_username,
                current_password=result.ssh_password,
                usernames_to_rotate=result.matched_accounts,
                credential_prompt=_credential_prompt,
                progress=print,
            )
            print()
            print(render_notice("New credentials (store securely!):"))
            for uname, new_pass in rotated.items():
                print(f"  {uname}: {new_pass}")
        except Exception as exc:
            print(render_notice(f"ERROR: {exc}"))


def _run_generate_key(app: App, comment: str, overwrite: bool) -> None:
    if app.paths.identity_file.exists() and not overwrite:
        print(render_notice(f"Key already exists at {app.paths.identity_file}"))
        print(f"  Public key: {app.paths.identity_pub_file.read_text(encoding='utf-8').strip()}")
        print(render_notice("Use --overwrite to replace it."))
        return
    try:
        pub = app.generate_keypair(comment=comment, overwrite=overwrite)
    except Exception as exc:
        print(render_notice(f"Key generation failed: {exc}"))
        return
    print(f"Private key : {app.paths.identity_file}")
    print(f"Public key  : {app.paths.identity_pub_file}")
    print(f"Added to    : {app.paths.authorized_keys_file}")
    print()
    print(pub)


def _menu_generate_key(app: App) -> None:
    if app.paths.identity_file.exists():
        print(render_notice(f"Key already exists at {app.paths.identity_file}"))
        print(f"  {app.paths.identity_pub_file.read_text(encoding='utf-8').strip()}")
        answer = input("  Overwrite? [y/N] ").strip().lower()
        if answer != "y":
            return
        overwrite = True
    else:
        overwrite = False
    comment = input("Key comment [vikings-ssh]: ").strip() or "vikings-ssh"
    try:
        pub = app.generate_keypair(comment=comment, overwrite=overwrite)
    except Exception as exc:
        print(render_notice(f"Key generation failed: {exc}"))
        return
    print()
    print(f"Private key : {app.paths.identity_file}")
    print(f"Public key  : {app.paths.identity_pub_file}")
    print(f"Added to    : {app.paths.authorized_keys_file}")
    print()
    print(pub)


def _menu_inject_keys(app: App) -> None:
    targets = app.load_targets()
    if not targets:
        print(render_notice("No targets configured."))
        return
    user = input("Remote user to configure [root]: ").strip() or "root"
    target_filter = input("Target key to limit to (blank = all): ").strip() or None
    if target_filter:
        targets = [t for t in targets if t.key == target_filter]
        if not targets:
            print(render_notice(f"No target found with key '{target_filter}'."))
            return
    try:
        results = app.inject_authorized_keys(
            targets,
            remote_user=user,
            credential_prompt=_credential_prompt,
            progress=print,
        )
    except ValueError as exc:
        print(render_notice(str(exc)))
        return
    print()
    print(render_injection_results(results))


def _menu_audit_passwords(app: App) -> None:
    targets = app.load_targets()
    if not targets:
        print(render_notice("No targets configured."))
        return
    target_filter = input("Target key to limit to (blank = all): ").strip() or None
    if target_filter:
        targets = [t for t in targets if t.key == target_filter]
        if not targets:
            print(render_notice(f"No target found with key '{target_filter}'."))
            return
    candidate_username = input("Username to test (blank = use each target's stored SSH user): ").strip()
    candidate_password = getpass.getpass("Password to test: ")
    if not candidate_password:
        print(render_notice("No password entered, aborting."))
        return

    print(f"\nAuditing {len(targets)} target(s) …\n")
    results = app.audit_passwords(
        targets,
        candidate_username=candidate_username,
        candidate_password=candidate_password,
        progress=print,
    )
    print()
    print(render_audit_results(results))
    _offer_rotation(app, targets, results, candidate_username, candidate_password)


def interactive_menu(app: App) -> int:
    actions: dict[str, tuple[str, Callable[[], None]]] = {
        "1": ("Live monitoring dashboard", lambda: _run_dashboard(app, timeout=3.0, workers=16, interval=10.0, once=False)),
        "2": ("List targets", lambda: _run_targets(app)),
        "3": ("Add host (wizard)", lambda: _menu_add_host(app)),
        "4": ("Show metadata", lambda: _run_metadata(app)),
        "5": ("List snapshots", lambda: _run_snapshots(app, target_key=None)),
        "6": ("Generate SSH keypair", lambda: _menu_generate_key(app)),
        "7": ("Inject authorized keys", lambda: _menu_inject_keys(app)),
        "8": ("Change account password", lambda: _menu_change_password(app)),
        "9": ("Password audit  [SSH auth check]", lambda: _menu_audit_passwords(app)),
        "10": ("Deep password audit  [/etc/shadow check]", lambda: _menu_deep_audit_passwords(app)),
        "11": ("View credentials", lambda: _menu_credentials(app)),
        "12": ("Export credentials", lambda: _menu_export_credentials(app)),
        "13": ("Restore snapshots", lambda: _menu_snapshot_restore(app)),
        "q": ("Quit", lambda: None),
    }

    while True:
        _print_header(app)
        print()
        for key, (label, _) in actions.items():
            print(f"[{key}] {label}")

        choice = input("\nSelection: ").strip().lower()
        if choice == "q":
            return 0

        action = actions.get(choice)
        if action is None:
            print(render_notice("Invalid selection."))
            print()
            continue

        print()
        action[1]()
        input("\nPress Enter to continue...")
        print()


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    app = App(AppPaths.from_root(args.root))
    app.bootstrap()

    command = args.command or "menu"
    if command == "menu":
        return interactive_menu(app)

    _print_header(app)
    print()

    if command == "dashboard":
        _run_dashboard(app, timeout=args.timeout, workers=args.workers, interval=args.interval, once=args.once)
    elif command == "targets":
        _run_targets(app)
    elif command == "add-host":
        _run_add_host(
            app,
            label=args.label,
            host=args.host,
            port=args.port,
            username=args.username,
            test=args.test,
        )
    elif command == "metadata":
        _run_metadata(app)
    elif command == "credentials":
        _run_credentials(app, target_key=args.target_key)
    elif command == "export-credentials":
        _run_export_credentials(app, target_key=args.target_key, output=args.output)
    elif command == "snapshots":
        _run_snapshots(app, target_key=args.target_key)
    elif command == "snapshot-add":
        _run_snapshot_add(app, args.target_key, args.source_path, args.from_file, args.reason)
    elif command == "snapshot-restore":
        _run_snapshot_restore(app, args.target_key, args.snapshot_id)
    elif command == "change-password":
        _run_change_password(app, target_key=args.target_key, account=args.account, generate=args.generate)
    elif command == "deep-audit-passwords":
        _run_deep_audit_passwords(
            app,
            target_key=args.target_key,
            username=args.username,
            rotate=args.rotate,
        )
    elif command == "audit-passwords":
        _run_audit_passwords(
            app,
            target_key=args.target_key,
            username=args.username,
            rotate=args.rotate,
        )
    elif command == "generate-key":
        _run_generate_key(app, comment=args.comment, overwrite=args.overwrite)
    elif command == "inject-keys":
        _run_inject_keys(app, target_key=args.target_key, user=args.user)
    else:
        parser.error(f"Unknown command: {command}")
    return 0
