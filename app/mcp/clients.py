import asyncio
import os
from typing import Any, Dict, Optional, Tuple, Union, List

from mcp import ClientSession, StdioServerParameters, types
from mcp.client.stdio import stdio_client

# --------- Helpers para construir parámetros de servidor (stdio) ---------

def filesystem_params(allowed_dirs: List[str]) -> StdioServerParameters:

    # npx -y @modelcontextprotocol/server-filesystem <dir1> <dir2> ...
    return StdioServerParameters(
        command="npx",
        args=["-y", "@modelcontextprotocol/server-filesystem", *allowed_dirs],
        env=os.environ.copy(),
    )

def git_params() -> StdioServerParameters:
    """
    Usa el server oficial de Git (Python).
    """
    return StdioServerParameters(
        command="python",
        args=["-m", "mcp_server_git"],
        env=os.environ.copy(),
    )

# --------- Ejecutores ---------

async def _call_tool_async(
    server_params: StdioServerParameters,
    tool_name: str,
    arguments: Dict[str, Any],
) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
    """
    Abre sesión MCP (stdio) y llama la tool `tool_name` con `arguments`.
    Devuelve (texto_unstructured, structured_json) si hay.
    """
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            result = await session.call_tool(tool_name, arguments=arguments)

            # parsear salida (puede devolver bloques de texto y/o structuredContent)
            text_out: Optional[str] = None
            if result.content:
                # Si el servidor devolvió contenido textual
                for block in result.content:
                    if isinstance(block, types.TextContent):
                        text_out = (text_out or "") + block.text

            structured: Optional[Dict[str, Any]] = None
            if result.structuredContent and isinstance(result.structuredContent, dict):
                structured = result.structuredContent

            return text_out, structured

def call_tool(
    server_params: StdioServerParameters,
    tool_name: str,
    arguments: Dict[str, Any],
) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
    return asyncio.run(_call_tool_async(server_params, tool_name, arguments))

def porthunter_params(python_exe: str = "python", module: str = "porthunter.server") -> StdioServerParameters:
    """
    Ejecuta el servidor PortHunter MCP vía stdio:
    """
    return StdioServerParameters(
        command=python_exe,
        args=["-m", module],
        env=os.environ.copy(),
    )
