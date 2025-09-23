from __future__ import annotations
from pathlib import Path
import os

HERE = Path(__file__).resolve()

def _find_captures_dir(start: Path) -> Path:
    """Busca automáticamente la carpeta <repo>/captures subiendo directorios."""
    for parent in [start.parent, *start.parents]:
        cand = parent / "captures"
        if cand.is_dir():
            return cand.resolve()
    # Fallback: sube varios niveles asumiendo repo estándar
    repo_root = HERE.parents[4] if len(HERE.parents) >= 5 else HERE.parents[-1]
    return (repo_root / "captures").resolve()

# Carpeta por defecto de PCAPs
CAPTURES_DIR = Path(
    os.getenv("PORT_HUNTER_CAPTURES_DIR", _find_captures_dir(HERE).as_posix())
).resolve()

def _split_paths(var_value: str | None) -> list[Path]:
    """
    Acepta lista de rutas separadas por:
    - el separador del SO (os.pathsep -> ';' en Windows, ':' en Linux/Mac)
    - coma ',' (por si acaso)
    - dos puntos ':' o punto y coma ';' (cross-platform)
    Devuelve las rutas normalizadas/resueltas.
    """
    if not var_value:
        return []
    raw = []
    for sep in (os.pathsep, ',', ';', ':'):
        if sep in var_value:
            raw = [s for s in var_value.split(sep) if s.strip()]
            # Rompemos en el primer separador que encontremos para no re-splitear
            break
    else:
        raw = [var_value]

    paths: list[Path] = []
    for s in raw:
        try:
            p = Path(s).expanduser().resolve()
            paths.append(p)
        except Exception:
            # ignoramos rutas inválidas
            pass
    return paths

# ⚠️ NUEVO: permitir inyectar directorios extra vía env
# Soportamos tanto PORT_HUNTER_ALLOWED_DIRS (lista) como PORT_HUNTER_ALLOWED_DIR (una sola).
_env_allowed = (
    os.getenv("PORT_HUNTER_ALLOWED_DIRS")
    or os.getenv("PORT_HUNTER_ALLOWED_DIR")
    or ""
)
EXTRA_ALLOWED_DIRS = _split_paths(_env_allowed)

# Lista final de carpetas desde donde SÍ se puede leer
# Siempre incluimos CAPTURES_DIR y luego añadimos las extra (sin duplicados).
ALLOWED_READ_DIRS: list[Path] = []
_seen = set()
for p in [CAPTURES_DIR, *EXTRA_ALLOWED_DIRS]:
    rp = Path(p).resolve()
    if rp not in _seen:
        ALLOWED_READ_DIRS.append(rp)
        _seen.add(rp)
