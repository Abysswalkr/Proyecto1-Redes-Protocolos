# propósito: gestionar servidores MCP por STDIO con un único ciclo async,
#            arranque tolerante, y trazabilidad JSONL de requests/responses.

from __future__ import annotations
import os
import sys
import yaml
import anyio
from contextlib import AsyncExitStack
from typing import Dict, Any, List, Optional

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

# Logger JSONL (si no existe apps/host/app/mcp/logging.py, caemos a un no-op)
try:
    from .logging import McpJsonLogger  # type: ignore
except Exception:  # pragma: no cover
    class McpJsonLogger:  # type: ignore
        def __init__(self, *a, **kw): pass
        def write(self, *a, **kw): pass


class StdioClient:
    """
    Carga un perfil YAML con la lista de servers MCP (command/args/cwd),
    lanza cada server por STDIO, establece handshake MCP y expone helpers
    para listar tools e invocar tools via JSON-RPC.

    Notas:
    - Mantiene un único bucle asíncrono con AsyncExitStack (evita cierres
      desordenados tipo "Attempted to exit cancel scope...").
    - En Windows reemplaza 'python' -> sys.executable y 'npx' -> 'npx.cmd'.
    - No detiene el host si un server falla al iniciar (registra y sigue).
    """

    def __init__(self, profile_path: str):
        self.profile_path: str = profile_path
        self.exit_stack: Optional[AsyncExitStack] = None
        self.sessions: Dict[str, ClientSession] = {}
        self.logger = McpJsonLogger()

    # ---------------- Internos ----------------

    def _fix_cmd_for_windows(self, cmd: List[str]) -> List[str]:
        """Ajustes de ejecutables en Windows para CreateProcess."""
        if os.name == "nt" and cmd:
            if cmd[0].lower() == "python":
                cmd[0] = sys.executable  # usa el mismo intérprete del host
            if cmd[0].lower() == "npx":
                cmd[0] = "npx.cmd"       # necesario para que CreateProcess lo encuentre
        return cmd

    async def _start_one_server(
        self, name: str, command: List[str], args: List[str], cwd: Optional[str]
    ) -> Optional[ClientSession]:
        """Lanza un server por stdio y hace handshake. Devuelve la sesión o None si falla."""
        full = self._fix_cmd_for_windows(list(command) + list(args))
        params = StdioServerParameters(command=full[0], args=full[1:], cwd=cwd)
        try:
            self.logger.write("start", name, {"command": full, "cwd": cwd})
            read, write = await self.exit_stack.enter_async_context(stdio_client(params))
            session = await self.exit_stack.enter_async_context(ClientSession(read, write))
            await session.initialize()  # handshake MCP
            # Log de tools disponibles
            try:
                tools = await session.list_tools()
                self.logger.write("list_tools", name, {"tools": [t.name for t in tools.tools]})
                print(f"[MCP Host] {name} tools: {[t.name for t in tools.tools]}")
            except Exception as e:
                self.logger.write("error", name, {"when": "list_tools", "error": repr(e)})
                print(f"[MCP Host][WARN] No pude listar tools de '{name}': {e!r}")
            return session
        except Exception as e:
            self.logger.write("error", name, {"when": "start", "error": repr(e)})
            print(f"[MCP Host][WARN] '{name}' no inició: {e!r}")
            return None

    # ---------------- Ciclo de vida ----------------

    async def start_async(self) -> Dict[str, List[str]]:
        """
        Abre el perfil YAML, lanza servidores y crea sesiones MCP dentro del
        mismo AsyncExitStack (vida útil coherente). Devuelve dict con started/failed.
        """
        self.exit_stack = AsyncExitStack()
        await self.exit_stack.__aenter__()

        # Cargar perfil
        with open(self.profile_path, "r", encoding="utf-8") as f:
            profile = yaml.safe_load(f)

        started: List[str] = []
        failed: List[str] = []

        for s in profile.get("servers", []):
            name: str = s["name"]
            command: List[str] = s.get("command", [])
            args: List[str] = s.get("args", [])
            cwd: Optional[str] = s.get("cwd")
            session = await self._start_one_server(name, command, args, cwd)
            if session is not None:
                self.sessions[name] = session
                started.append(name)
            else:
                failed.append(name)

        if failed:
            print(f"[MCP Host] started: {started}  failed: {failed}")
        else:
            print(f"[MCP Host] started: {started}")

        return {"started": started, "failed": failed}

    async def aclose(self) -> None:
        """Cierra todas las sesiones/procesos del AsyncExitStack."""
        if self.exit_stack is not None:
            await self.exit_stack.aclose()
            self.exit_stack = None

    # ---------------- Operaciones ----------------

    async def list_tools_async(self, server: str) -> List[str]:
        """Devuelve la lista de nombres de tools expuestas por el server."""
        sess = self.sessions[server]
        resp = await sess.list_tools()
        return [t.name for t in resp.tools]

    async def call_tool_async(self, server: str, tool: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Invoca una tool del server y devuelve el resultado como dict serializable.
        Registra la llamada y el resultado en el logger JSONL.
        """
        self.logger.write("call_tool", server, {"tool": tool, "params": params})
        try:
            result = await self.sessions[server].call_tool(tool, params)
            try:
                payload = result.model_dump()  # objetos pydantic -> dict
            except Exception:
                payload = {"content": getattr(result, "content", None)}
            self.logger.write("tool_result", server, {"tool": tool, "result": payload})
            return payload
        except Exception as e:
            self.logger.write("error", server, {"when": f"call_tool:{tool}", "error": repr(e)})
            raise

    # --------- (Opcional) envoltorios síncronos ---------

    def start(self) -> Dict[str, List[str]]:
        """Wrapper síncrono (por compatibilidad)."""
        return anyio.run(self.start_async)

    def close(self) -> None:
        """Wrapper síncrono (por compatibilidad)."""
        anyio.run(self.aclose)

    def list_tools(self, server: str) -> List[str]:
        return anyio.run(self.list_tools_async, server)

    def call_tool(self, server: str, tool: str, params: Dict[str, Any]) -> Dict[str, Any]:
        return anyio.run(self.call_tool_async, server, tool, params)
