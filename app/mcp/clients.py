# app/mcp/clients.py
import asyncio
import os
from mcp.client.streamable_http import streamablehttp_client
from mcp import ClientSession
from typing import Any, Dict, Optional, Tuple, List

from mcp import types, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamablehttp_client

# ======================================================================
# Parámetros de servidores MCP (STDIO)
# ======================================================================

def filesystem_params(allowed_dirs: List[str]) -> StdioServerParameters:
    return StdioServerParameters(
        command="npx",
        args=["-y", "@modelcontextprotocol/server-filesystem", *allowed_dirs],
        env=os.environ.copy(),
    )

def git_params() -> StdioServerParameters:
    return StdioServerParameters(
        command="python",
        args=["-m", "mcp_server_git"],
        env=os.environ.copy(),
    )

def porthunter_params(
    python_exe: str = "python",
    module: str = "porthunter.server",
) -> StdioServerParameters:
    return StdioServerParameters(
        command=python_exe,
        args=["-m", module],
        env=os.environ.copy(),
    )

# ======================================================================
# Ejecutor STDIO (común)
# ======================================================================

async def _call_tool_async_stdio(
    server_params: StdioServerParameters,
    tool_name: str,
    arguments: Dict[str, Any],
) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool(tool_name, arguments=arguments)

            text_out: Optional[str] = None
            if result.content:
                for block in result.content:
                    if isinstance(block, types.TextContent):
                        text_out = (text_out or "") + block.text

            structured: Optional[Dict[str, Any]] = None
            if getattr(result, "structuredContent", None) and isinstance(result.structuredContent, dict):
                structured = result.structuredContent

            return text_out, structured

def call_tool(
    server_params: StdioServerParameters,
    tool_name: str,
    arguments: Dict[str, Any],
) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
    return asyncio.run(_call_tool_async_stdio(server_params, tool_name, arguments))

# ======================================================================
# Cliente REMOTO por Streamable HTTP (conexión a la RAÍZ "/")
# ======================================================================

_REMOTE_URL: Optional[str] = None  # p.ej. "http://127.0.0.1:8080"

def remote_set(url: str) -> str:
    global _REMOTE_URL
    _REMOTE_URL = url.strip().rstrip("/")
    return _REMOTE_URL

def remote_get() -> Optional[str]:
    return _REMOTE_URL

async def _call_tool_async_http(
    base_url: str,
    tool_name: str,
    arguments: Dict[str, Any],
) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
    # Conectamos DIRECTO a la base (la app MCP está montada en "/")
    endpoint = base_url.rstrip("/")
    async with streamablehttp_client(endpoint) as (read, write, _session_id):
        async with ClientSession(read, write) as session:
            await session.initialize()

            if tool_name == "__list_tools__":
                tools = await session.list_tools()
                tools_info = []
                for t in tools.tools:
                    tools_info.append({
                        "name": t.name,
                        "description": t.description,
                        "inputSchema": getattr(t, "inputSchema", None),
                    })
                return None, {"tools": tools_info}

            result = await session.call_tool(tool_name, arguments=arguments)

            text_out: Optional[str] = None
            if result.content:
                for block in result.content:
                    if isinstance(block, types.TextContent):
                        text_out = (text_out or "") + block.text

            structured: Optional[Dict[str, Any]] = None
            if getattr(result, "structuredContent", None) and isinstance(result.structuredContent, dict):
                structured = result.structuredContent

            return text_out, structured

def remote_list_tools() -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
    if not _REMOTE_URL:
        return None, {"error": "Primero configura la URL: /remote-set <url>"}
    try:
        return asyncio.run(_call_tool_async_http(_REMOTE_URL, "__list_tools__", {}))
    except Exception as e:
        return None, {"error": f"Fallo listando tools remotas: {e}"}

def remote_call(
    tool_name: str,
    arguments: Dict[str, Any]
) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
    if not _REMOTE_URL:
        return None, {"error": "Primero configura la URL: /remote-set <url>"}
    try:
        return asyncio.run(_call_tool_async_http(_REMOTE_URL, tool_name, arguments))
    except Exception as e:
        return None, {"error": f"Fallo llamando tool remota '{tool_name}': {e}"}

def _normalize_endpoint(url: str) -> str:
    url = url.rstrip("/")
    # Si el usuario pasó .../mcp/ o .../mcp lo dejamos tal cual
    if url.endswith("/mcp"):
        return url
    # Si pasó la base (p. ej. http://127.0.0.1:8080), le agregamos /mcp
    return url + "/mcp"

class RemoteMCPClient:
    def __init__(self, base_url: str):
        self.endpoint = _normalize_endpoint(base_url)

    async def list_tools(self):
        async with streamablehttp_client(self.endpoint) as (r, w, _):
            async with ClientSession(r, w) as s:
                await s.initialize()
                return await s.list_tools()

    async def call_tool(self, name: str, arguments: dict):
        async with streamablehttp_client(self.endpoint) as (r, w, _):
            async with ClientSession(r, w) as s:
                await s.initialize()
                return await s.call_tool(name=name, arguments=arguments)
