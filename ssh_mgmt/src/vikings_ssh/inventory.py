from __future__ import annotations

from pathlib import Path

from vikings_ssh.models import Target


class InventoryError(ValueError):
    """Raised when the targets inventory file contains invalid data."""


def parse_target_line(line: str, line_number: int) -> Target | None:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None

    parts = [part.strip() for part in stripped.split(",")]
    if len(parts) != 3:
        raise InventoryError(f"Line {line_number}: expected label,host,port")

    label, host, raw_port = parts
    port = _parse_port(raw_port, line_number)

    if not label:
        raise InventoryError(f"Line {line_number}: label must not be empty")

    if not host:
        raise InventoryError(f"Line {line_number}: host must not be empty")

    return Target(host=host, port=port, label=label)


def _parse_port(raw_port: str, line_number: int) -> int:
    try:
        port = int(raw_port)
    except ValueError as exc:
        raise InventoryError(f"Line {line_number}: invalid port {raw_port!r}") from exc

    if port < 1 or port > 65535:
        raise InventoryError(f"Line {line_number}: port {port} is outside the valid range")
    return port


def format_target_line(target: Target) -> str:
    """Serialize a Target back to the `label,host,port` inventory format."""
    if not target.label:
        raise InventoryError("Target label must not be empty")
    for field_name, value in (("label", target.label), ("host", target.host)):
        if "," in value:
            raise InventoryError(f"Target {field_name} must not contain commas: {value!r}")
        if "\n" in value or "\r" in value:
            raise InventoryError(f"Target {field_name} must not contain newlines: {value!r}")
    return f"{target.label},{target.host},{target.port}"


class Inventory:
    def __init__(self, path: Path) -> None:
        self.path = path

    def load(self) -> list[Target]:
        if not self.path.exists():
            return []

        targets: list[Target] = []
        for line_number, line in enumerate(self.path.read_text(encoding="utf-8").splitlines(), start=1):
            target = parse_target_line(line, line_number)
            if target is not None:
                targets.append(target)
        return targets

    def append_target(self, target: Target) -> Target:
        """Append *target* to the inventory file, preserving existing content.

        Raises InventoryError if a target with the same host:port already exists,
        or if the target's label/host contain delimiter characters.
        """
        line_to_add = format_target_line(target)

        existing = self.load()
        for current in existing:
            if current.host == target.host and current.port == target.port:
                raise InventoryError(
                    f"Target {target.host}:{target.port} already exists "
                    f"(label: {current.label!r})"
                )

        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.exists():
            text = self.path.read_text(encoding="utf-8")
        else:
            text = ""
        if text and not text.endswith("\n"):
            text += "\n"
        text += line_to_add + "\n"
        self.path.write_text(text, encoding="utf-8")
        return target
