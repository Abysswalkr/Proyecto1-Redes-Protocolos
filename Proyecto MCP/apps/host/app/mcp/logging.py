# apps/host/app/mcp/logging.py
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional
import json
import os


def _iso_utc_now() -> str:
    # TZ-aware, evita warnings de utcnow()
    return datetime.now(timezone.utc).isoformat()


@dataclass
class McpJsonLogger:
    """
    Logger simple en JSONL para tráfico MCP y eventos del host.
    Escribe en apps/host/logs/mcp/*.jsonl
    """
    base_dir: Path = Path("apps/host/logs/mcp")

    def __post_init__(self) -> None:
        self.base_dir.mkdir(parents=True, exist_ok=True)
        # Archivos por defecto
        self._traffic = self.base_dir / "traffic.jsonl"   # eventos genéricos
        self._mcp = self.base_dir / "mcp.jsonl"           # eventos MCP (por server)

    # ---------- Núcleo ----------
    def _append_jsonl(self, path: Path, obj: Dict[str, Any]) -> None:
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(obj, ensure_ascii=False) + "\n")

    # ---------- API genérica ----------
    def log(self, kind: str, payload: Optional[Dict[str, Any]] = None) -> None:
        """
        Evento genérico (sin 'server'), compatible con usos futuros.
        """
        line = {
            "ts": _iso_utc_now(),
            "kind": kind,
            "payload": payload or {},
        }
        self._append_jsonl(self._traffic, line)

    # ---------- API usada por stdio_client ----------
    def write(
        self,
        kind: str,
        server: str,
        payload: Optional[Dict[str, Any]] = None,
        *,
        file: Optional[str] = None,
    ) -> None:
        """
        Evento con 'server' (compatibilidad con stdio_client.py).
        'file' permite forzar otro archivo si se desea.
        """
        line = {
            "ts": _iso_utc_now(),
            "kind": kind,
            "server": server,
            "payload": payload or {},
        }
        target = self._mcp if file is None else (self.base_dir / file)
        self._append_jsonl(target, line)

    def log_event(
        self,
        kind: str,
        server: str,
        *,
        tool: Optional[str] = None,
        payload: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Evento con semántica de herramienta (compatibilidad con stdio_client.py).
        """
        line = {
            "ts": _iso_utc_now(),
            "kind": kind,          # p.ej. "tools", "call", "result", "error"
            "server": server,      # p.ej. "filesystem", "git", "porthunter", "trivia"
            "tool": tool,          # p.ej. "read_file", "git_commit", "scan_overview"
            "payload": payload or {},
        }
        self._append_jsonl(self._mcp, line)

    # ---------- Atajos opcionales ----------
    def start(self, server: str, command: str, cwd: Optional[str]) -> None:
        self.write("start", server, {"command": command, "cwd": cwd})

    def started(self, servers: list[str]) -> None:
        self.log("started", {"servers": servers})

    def stop(self, server: str, returncode: Optional[int] = None) -> None:
        self.write("stop", server, {"returncode": returncode})

    def error(self, server: str, when: str, error: str) -> None:
        self.write("error", server, {"when": when, "error": error})
