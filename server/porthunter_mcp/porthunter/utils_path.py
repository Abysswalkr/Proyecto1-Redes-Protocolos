from __future__ import annotations
from pathlib import Path
from . import config

class PathOutsideAllowedDir(PermissionError):
    """La ruta solicitada está fuera de las carpetas permitidas."""

def ensure_allowed_path(user_path: str | Path) -> Path:
    """
    Devuelve la ruta normalizada si está bajo ALLOWED_READ_DIRS.
    Si no, lanza PathOutsideAllowedDir.
    """
    p = Path(user_path).expanduser().resolve()
    for base in config.ALLOWED_READ_DIRS:
        base = Path(base).resolve()
        try:
            p.relative_to(base)
            return p
        except ValueError:
            continue
    raise PathOutsideAllowedDir(f"{p} no está dentro de {config.ALLOWED_READ_DIRS}")
