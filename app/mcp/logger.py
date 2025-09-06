import json
import uuid
from pathlib import Path
from datetime import datetime
from typing import Any, Dict, List, Optional


class MCPLogger:
    """
    Logger JSONL de interacciones MCP (solicitudes y respuestas).
    Escribe en logs/mcp/mcp-YYYYMMDD.jsonl por día.
    """
    def __init__(self, log_dir: str = "logs/mcp") -> None:
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)

    def _file_path(self) -> Path:
        fname = f"mcp-{datetime.now().strftime('%Y%m%d')}.jsonl"
        return self.log_dir / fname

    def _write(self, obj: Dict[str, Any]) -> None:
        with open(self._file_path(), "a", encoding="utf-8") as f:
            f.write(json.dumps(obj, ensure_ascii=False) + "\n")

    def log_request(self, server: str, tool: str, args: Dict[str, Any]) -> str:
        corr_id = str(uuid.uuid4())
        self._write({
            "t": datetime.now().isoformat(timespec="seconds"),
            "kind": "request",
            "correlation_id": corr_id,
            "server": server,
            "tool": tool,
            "args": args,
        })
        return corr_id

    def log_response(
        self, correlation_id: str, server: str, tool: str,
        status: str, result: Optional[Dict[str, Any]] = None, error: Optional[str] = None
    ) -> None:
        self._write({
            "t": datetime.now().isoformat(timespec="seconds"),
            "kind": "response",
            "correlation_id": correlation_id,
            "server": server,
            "tool": tool,
            "status": status,
            "result": result,
            "error": error,
        })

    def tail(self, n: int = 20) -> List[str]:
        """Devuelve las últimas n líneas del archivo de hoy (como strings)."""
        p = self._file_path()
        if not p.exists():
            return []
        with open(p, "r", encoding="utf-8") as f:
            lines = f.readlines()
        return [l.rstrip("\n") for l in lines[-n:]]
