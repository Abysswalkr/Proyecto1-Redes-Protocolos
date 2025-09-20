import os, sys, json, asyncio
from typing import Any, Dict

from mcp import StdioServerParameters, types
from mcp.client.stdio import stdio_client
from mcp.client.session import ClientSession

# <-- Los tests importan esto:
TOKEN = os.getenv("PORT_HUNTER_TOKEN", "TEST_TOKEN")

def _mk_params() -> StdioServerParameters:
    """Construye los parámetros usando el entorno ACTUAL (ya modificado por fixtures)."""
    env = {
        "PORT_HUNTER_TOKEN": os.getenv("PORT_HUNTER_TOKEN", "TEST_TOKEN"),
        "PORT_HUNTER_ALLOWED_DIR": os.getenv("PORT_HUNTER_ALLOWED_DIR", "."),
        "PORT_HUNTER_ALLOW_PRIVATE": "false",
        "PORT_HUNTER_REQUIRE_TOKEN": os.getenv("PORT_HUNTER_REQUIRE_TOKEN", "true"),
        "PORT_HUNTER_MAX_PCAP_MB": os.getenv("PORT_HUNTER_MAX_PCAP_MB", "50"),
    }
    return StdioServerParameters(
        command=sys.executable,               # robusto en Windows
        args=["-m", "porthunter.server"],     # usa el mismo módulo que tu CLI (probado)
        env=env,
    )

async def call_tool(name: str, arguments: Dict[str, Any], timeout_s: float = 25.0) -> Any:
    params = _mk_params()
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            rsp = await asyncio.wait_for(
                session.call_tool(name=name, arguments=arguments),
                timeout=timeout_s,
            )

            # 1) Prioriza structuredContent (JSON)
            sc = getattr(rsp, "structuredContent", None)
            if isinstance(sc, dict):
                # Muchas versiones de FastMCP ponen el retorno bajo "result".
                if "result" in sc:
                    val = sc["result"]
                    # result puede ser dict o cadena JSON
                    if isinstance(val, dict):
                        return val
                    if isinstance(val, str):
                        try:
                            return json.loads(val)
                        except Exception:
                            # Si no es JSON, igual devuélvelo como texto
                            return val
                # Si no hay "result", devuelve structuredContent tal cual
                return sc

            # 2) Fallback: concatenar bloques de texto y parsear JSON
            if rsp.content:
                txt = ""
                for block in rsp.content:
                    if isinstance(block, types.TextContent):
                        txt += block.text
                if txt:
                    try:
                        return json.loads(txt)
                    except Exception:
                        return txt
            return None
