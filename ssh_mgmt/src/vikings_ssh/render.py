from __future__ import annotations

import os
import re
from pathlib import Path

from vikings_ssh.models import (
    CredentialReport,
    DashboardHostStatus,
    DashboardSnapshot,
    HostMetadata,
    SnapshotEntry,
    SnapshotRestoreResult,
    Target,
)

RESET = "\033[0m"
GREEN = "\033[92m"
CYAN = "\033[96m"
RED = "\033[91m"
YELLOW = "\033[93m"
DIM = "\033[90m"
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def supports_color() -> bool:
    return os.getenv("TERM") not in {None, "dumb"} and os.getenv("NO_COLOR") is None


def colorize(text: str, color: str) -> str:
    if not supports_color():
        return text
    return f"{color}{text}{RESET}"


def load_logo(logo_path: Path) -> str:
    if not logo_path.exists():
        return "WWU vi_kings SSH Tool"
    return logo_path.read_text(encoding="utf-8").rstrip()


def banner(logo_path: Path) -> str:
    logo = colorize(load_logo(logo_path), CYAN)
    title = colorize("WWU vi_kings SSH Tool", GREEN)
    return f"{logo}\n{title}"


def render_table(headers: list[str], rows: list[list[str]]) -> str:
    if not rows:
        return "(no rows)"

    widths = [len(header) for header in headers]
    for row in rows:
        for index, cell in enumerate(row):
            widths[index] = max(widths[index], len(ANSI_RE.sub("", cell)))

    def _format_row(row: list[str]) -> str:
        padded: list[str] = []
        for index, cell in enumerate(row):
            visible_width = len(ANSI_RE.sub("", cell))
            padding = max(0, widths[index] - visible_width)
            padded.append(f"{cell}{' ' * padding}")
        return " | ".join(padded)

    separator = "-+-".join("-" * width for width in widths)
    parts = [_format_row(headers), separator]
    parts.extend(_format_row(row) for row in rows)
    return "\n".join(parts)


def render_targets(targets: list[Target]) -> str:
    if not targets:
        return "No targets configured. Add entries to targets.txt first."

    rows = [
        [
            target.display_label,
            target.host,
            str(target.port),
            target.username or "-",
            target.key,
        ]
        for target in targets
    ]
    return render_table(["Label", "Host", "Port", "User", "Key"], rows)


def _short_auth_label(label: str | None) -> str:
    if not label:
        return "-"
    lowered = label.lower()
    if lowered.startswith("ssh key"):
        return "ssh key"
    if lowered == "stored password":
        return "stored pw"
    if lowered == "provided password":
        return "provided pw"
    if lowered == "prompted password":
        return "prompted pw"
    return label


def _truncate(text: str, width: int) -> str:
    if len(text) <= width:
        return text
    if width <= 3:
        return text[:width]
    return text[: width - 3] + "..."


def _format_dashboard_timestamp(timestamp: str) -> str:
    try:
        return timestamp.replace("T", " ").replace("+00:00", " UTC")
    except Exception:
        return timestamp


def _dashboard_tcp(status: DashboardHostStatus) -> str:
    if status.tcp_open:
        return colorize("open", CYAN)
    return colorize("down", RED)


def _dashboard_login(status: DashboardHostStatus) -> str:
    mapping = {
        "ok": colorize("login ok", GREEN),
        "auth failed": colorize("auth fail", RED),
        "no creds": colorize("no creds", YELLOW),
        "down": colorize("down", RED),
        "error": colorize("error", RED),
    }
    return mapping.get(status.login_state, status.login_state)


def _dashboard_auth(status: DashboardHostStatus) -> str:
    if status.login_state == "ok":
        label = _short_auth_label(status.auth_method)
        if label == "ssh key":
            return colorize(label, CYAN)
        if "pw" in label:
            return colorize(label, YELLOW)
        return label
    if status.auth_path:
        parts = [_short_auth_label(part.strip()) for part in status.auth_path.split("->")]
        return _truncate(" -> ".join(parts), 18)
    return "-"


def _dashboard_keys(status: DashboardHostStatus) -> str:
    posture = f"{status.authorized_keys_state}/{'root' if status.expected_root_key_present else 'no-root'}"
    if status.authorized_keys_state == "managed" and status.expected_root_key_present:
        return colorize(posture, GREEN)
    if status.authorized_keys_state == "managed":
        return colorize(posture, CYAN)
    if status.authorized_keys_state == "unknown":
        return colorize(posture, YELLOW)
    return posture


def _dashboard_issue(status: DashboardHostStatus) -> str:
    if status.login_state == "ok":
        return colorize("-", DIM)
    return _truncate((status.error or "-").replace("\n", " "), 42)


def render_dashboard(snapshot: DashboardSnapshot) -> str:
    if not snapshot.hosts:
        return "No targets configured. Add entries to targets.txt first."

    total_hosts = len(snapshot.hosts)
    login_ok = sum(1 for item in snapshot.hosts if item.login_state == "ok")
    key_auth = sum(
        1
        for item in snapshot.hosts
        if item.login_state == "ok" and _short_auth_label(item.auth_method) == "ssh key"
    )
    password_auth = sum(
        1
        for item in snapshot.hosts
        if item.login_state == "ok" and "pw" in _short_auth_label(item.auth_method)
    )
    no_creds = sum(1 for item in snapshot.hosts if item.login_state == "no creds")
    auth_failed = sum(1 for item in snapshot.hosts if item.login_state == "auth failed")
    down = sum(1 for item in snapshot.hosts if item.login_state == "down")
    managed_hosts = sum(1 for item in snapshot.hosts if item.authorized_keys_state == "managed")
    root_key_hosts = sum(1 for item in snapshot.hosts if item.expected_root_key_present)
    total_snapshots = sum(item.snapshot_count for item in snapshot.hosts)

    rows: list[list[str]] = []
    for status in snapshot.hosts:
        latency = "-" if status.latency_ms is None else f"{status.latency_ms:.2f} ms"
        rows.append(
            [
                status.target.display_label,
                f"{status.target.host}:{status.target.port}",
                _dashboard_tcp(status),
                _dashboard_login(status),
                _dashboard_auth(status),
                status.login_username,
                latency,
                _dashboard_keys(status),
                str(status.known_password_count),
                str(status.snapshot_count),
                _dashboard_issue(status),
            ]
        )

    local_key = colorize("ready", GREEN) if snapshot.local_key_available else colorize("missing", RED)
    lines = [
        "Live Monitoring Dashboard",
        "-------------------------",
        f"Updated: {_format_dashboard_timestamp(snapshot.generated_at)}",
        f"Refresh: every {snapshot.refresh_interval:g}s  |  Ctrl-C to stop",
        f"Local SSH key: {local_key}  |  Managed public keys: {snapshot.managed_key_count}",
        (
            f"Hosts: {total_hosts}  |  Login OK: {login_ok}  |  Key Auth: {key_auth}  |  "
            f"Password Auth: {password_auth}"
        ),
        (
            f"Needs Creds: {no_creds}  |  Auth Failed: {auth_failed}  |  Down: {down}  |  "
            f"Managed Hosts: {managed_hosts}  |  Root Key Expected: {root_key_hosts}  |  "
            f"Snapshots: {total_snapshots}"
        ),
        "",
        render_table(
            ["Label", "Target", "TCP", "Login", "Auth", "User", "Latency", "Keys", "Pwds", "Snaps", "Issue"],
            rows,
        ),
        "",
        (
            "Legend: 'no creds' means SSH is reachable but this controller has no local key "
            "or stored password for that host."
        ),
    ]
    return "\n".join(lines)


def render_metadata(entries: list[HostMetadata]) -> str:
    if not entries:
        return "Metadata store is empty."

    rows = [
        [
            entry.label or "-",
            entry.ssh_username or "-",
            entry.target_key,
            entry.authorized_keys_state,
            "yes" if entry.password_material_available else "no",
            "yes" if entry.expected_root_key_present else "no",
            entry.last_reachable_at or "-",
            entry.last_error or "-",
            str(len(entry.snapshot_ids)),
        ]
        for entry in entries
    ]
    return render_table(
        [
            "Label",
            "SSH User",
            "Target",
            "Auth Keys",
            "Password Material",
            "Root Key Expected",
            "Last Reachable",
            "Last Error",
            "Snapshots",
        ],
        rows,
    )


def _append_indented_block(lines: list[str], text: str, prefix: str = "  ") -> None:
    for line in text.splitlines():
        lines.append(f"{prefix}{line}")


def _key_lines(contents: str | None) -> list[str]:
    if not contents:
        return []
    return [
        line.strip()
        for line in contents.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


def render_credentials(report: CredentialReport) -> str:
    lines = ["Local Key Material", "------------------"]
    for material in (report.private_key, report.public_key, report.authorized_keys):
        lines.append(f"{material.label}: {material.path}")
        if not material.exists:
            lines.append("  (missing)")
        elif material.contents:
            _append_indented_block(lines, material.contents)
        else:
            lines.append("  (empty)")
        lines.append("")

    lines.extend(["Per-Machine Credentials", "-----------------------"])
    if not report.hosts:
        lines.append("(no machine credentials)")
        return "\n".join(lines)

    for host in report.hosts:
        lines.append(host.display_name)
        lines.append(f"  Target Key: {host.target_key}")
        lines.append(f"  Authorized Keys State: {host.authorized_keys_state}")
        lines.append(
            f"  Expected Root Key Present: {'yes' if host.expected_root_key_present else 'no'}"
        )
        lines.append("  Current Passwords:")
        if host.current_passwords:
            for username, password in host.current_passwords.items():
                lines.append(f"    {username}: {password}")
        elif host.password_history:
            lines.append("    (unknown)")
        else:
            lines.append("    (none)")
        lines.append("  Password History (historical only):")
        if host.password_history:
            for record in host.password_history:
                recorded_at = record.recorded_at or "unknown-time"
                lines.append(
                    f"    {recorded_at} [{record.source}] {record.username}: {record.password}"
                )
        else:
            lines.append("    (none)")
        lines.append("")

    return "\n".join(lines).rstrip()


def render_credential_export(report: CredentialReport, generated_at: str | None = None) -> str:
    managed_keys = _key_lines(report.authorized_keys.contents if report.authorized_keys.exists else None)

    lines = ["Credential Export", "================="]
    if generated_at:
        lines.append(f"Generated At: {generated_at}")
    lines.append("")
    lines.extend(["Local SSH Material", "------------------"])
    lines.append(f"Private Key Path: {report.private_key.path}")
    if not report.private_key.exists:
        lines.append("  (missing)")
    lines.append(f"Public Key Path: {report.public_key.path}")
    if report.public_key.exists and report.public_key.contents:
        lines.append("Public Key:")
        _append_indented_block(lines, report.public_key.contents)
    else:
        lines.append("Public Key:")
        lines.append("  (missing)")
    lines.append(f"Authorized Keys Path: {report.authorized_keys.path}")
    lines.append("Managed Public Keys:")
    if managed_keys:
        for key in managed_keys:
            lines.append(f"  {key}")
    elif report.authorized_keys.exists:
        lines.append("  (empty)")
    else:
        lines.append("  (missing)")
    lines.append("")

    lines.extend(["Per-Machine Export", "------------------"])
    if not report.hosts:
        lines.append("(no machine credentials)")
        return "\n".join(lines)

    for host in report.hosts:
        lines.append(host.display_name)
        lines.append(f"  Target Key: {host.target_key}")
        lines.append(f"  Authorized Keys State: {host.authorized_keys_state}")
        lines.append(
            f"  Expected Root Key Present: {'yes' if host.expected_root_key_present else 'no'}"
        )
        lines.append("  Current Passwords:")
        if host.current_passwords:
            for username, password in host.current_passwords.items():
                lines.append(f"    {username}: {password}")
        elif host.password_history:
            lines.append("    (unknown)")
        else:
            lines.append("    (none)")
        lines.append("  SSH Keys:")
        if managed_keys:
            for key in managed_keys:
                lines.append(f"    {key}")
        elif report.authorized_keys.exists:
            lines.append("    (none)")
        else:
            lines.append("    (missing local authorized_keys file)")
        lines.append("")

    return "\n".join(lines).rstrip()


def render_snapshots(entries: list[SnapshotEntry]) -> str:
    if not entries:
        return "No snapshots stored."

    rows = [
        [
            entry.snapshot_id,
            entry.target_key,
            entry.source_path,
            entry.reason,
            entry.created_at,
            str(entry.size_bytes),
        ]
        for entry in entries
    ]
    return render_table(["ID", "Target", "Source", "Reason", "Created At", "Bytes"], rows)


def render_snapshot_restore_results(results: list[SnapshotRestoreResult]) -> str:
    if not results:
        return "No restore actions were run."

    rows = [
        [
            result.snapshot_id,
            result.source_path,
            colorize("restored", GREEN) if result.restored else colorize("failed", RED),
            result.backup_snapshot_id or "-",
            result.error or "-",
        ]
        for result in results
    ]
    return render_table(["Snapshot", "Source", "Status", "Pre-Restore Backup", "Detail"], rows)


def render_notice(message: str) -> str:
    return colorize(message, YELLOW)


def render_audit_results(results: object) -> str:  # type: ignore[override]
    from vikings_ssh.password_audit import HostAuditResult  # avoid circular at module level

    typed: list[HostAuditResult] = results  # type: ignore[assignment]
    if not typed:
        return "No audit results."

    rows: list[list[str]] = []
    for result in typed:
        if result.authenticated:
            status = colorize("ACCEPTED", RED)
        elif result.error and "Authentication" in result.error:
            status = colorize("rejected", GREEN)
        elif result.error:
            status = colorize("error", YELLOW)
        else:
            status = colorize("rejected", GREEN)
        rows.append([result.target_key, result.username, status, result.error or "-"])

    return render_table(["Target", "Username", "Auth Result", "Detail"], rows)


def render_deep_audit_results(results: object) -> str:  # type: ignore[override]
    from vikings_ssh.password_audit import DeepHostAuditResult  # avoid circular at module level

    typed: list[DeepHostAuditResult] = results  # type: ignore[assignment]
    if not typed:
        return "No deep audit results."

    rows: list[list[str]] = []
    for result in typed:
        if not result.connected:
            rows.append([result.target_key, result.ssh_username, colorize("ERROR", RED), "-", "-", result.error or ""])
            continue
        matched = result.matched_accounts
        if matched:
            status = colorize(f"{len(matched)} matched", RED)
            matched_str = colorize(", ".join(matched), RED)
        else:
            status = colorize("clean", GREEN)
            matched_str = "-"
        rows.append([
            result.target_key,
            result.ssh_username,
            status,
            str(result.checked_count),
            matched_str,
            result.error or "-",
        ])

    return render_table(
        ["Target", "Login As", "Status", "Checked", "Matched Accounts", "Error"],
        rows,
    )


def render_injection_results(results: object) -> str:  # type: ignore[override]
    from vikings_ssh.key_injection import InjectionResult  # avoid circular at module level

    typed: list[InjectionResult] = results  # type: ignore[assignment]
    if not typed:
        return "No injection results."

    rows: list[list[str]] = []
    for result in typed:
        if not result.connected:
            rows.append([
                result.target_key,
                result.remote_user,
                colorize("ERROR", RED),
                "0",
                "0",
                result.error or "unknown error",
            ])
        else:
            status = colorize("ok", GREEN)
            rows.append([
                result.target_key,
                result.remote_user,
                status,
                str(result.keys_added),
                str(result.skipped),
                "-",
            ])

    return render_table(
        ["Target", "User", "Status", "Added", "Skipped", "Error"],
        rows,
    )
