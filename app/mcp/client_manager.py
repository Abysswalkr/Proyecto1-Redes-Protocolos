import subprocess
import threading
import json
from typing import Dict, Any, Optional
from app.mcp.logger import MCPLogger

class MCPClientManager:
    """
    Administra procesos MCP (stdio) y su invocación.
    """
    def __init__(self) -> None:
        self.processes = {}
        self.logger = MCPLogger()

    def start_server(self, name: str, cmd: str, cwd: Optional[str] = None) -> None:
        if name in self.processes:
            return
        proc = subprocess.Popen(
            cmd, shell=True, cwd=cwd,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, bufsize=1
        )
        self.processes[name] = proc

    def stop_server(self, name: str) -> None:
        proc = self.processes.get(name)
        if proc and proc.poll() is None:
            proc.terminate()
        self.processes.pop(name, None)

    def simulate_invoke(self, server: str, tool: str, args: Dict[str, Any]) -> None:
        corr = self.logger.log_request(server, tool, args)
        # Respuesta simulada
        self.logger.log_response(correlation_id=corr, server=server, tool=tool, status="ok", result={"demo": True})
