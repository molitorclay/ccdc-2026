from pathlib import Path

_SRC_PACKAGE = Path(__file__).resolve().parents[1] / "src" / "vikings_ssh"
if _SRC_PACKAGE.is_dir():
    __path__.append(str(_SRC_PACKAGE))

__all__ = ["__version__"]
__version__ = "0.1.0"

