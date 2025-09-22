import os
import sys
import json
import asyncio
from pathlib import Path
from typing import Any, Dict, Tuple

from mcp import StdioServerParameters, types
from mcp.client.stdio import stdio_client
from mcp.client.session import ClientSession

TOKEN    = os.getenv("PORT_HUNTER_TOKEN", "MiTOKENultraSecreto123")
PCAP_DIR = Path(os.getenv("PORT_HUNTER_ALLOWED_DIR", "./captures")).resolve()

SERVER = StdioServerParameters(
    command=sys.executable,  # más robusto en Windows que "python"
    args=["-m", "porthunter.server"],
    env={
        "PORT_HUNTER_TOKEN": TOKEN,
        "PORT_HUNTER_ALLOWED_DIR": str(PCAP_DIR),
        "PORT_HUNTER_ALLOW_PRIVATE": os.getenv("PORT_HUNTER_ALLOW_PRIVATE", "false"),
        "PORT_HUNTER_CACHE_DIR": os.getenv("PORT_HUNTER_CACHE_DIR", ".cache/porthunter"),
        "PORT_HUNTER_REQUIRE_TOKEN": os.getenv("PORT_HUNTER_REQUIRE_TOKEN", "true"),
        "PORT_HUNTER_MAX_PCAP_MB": os.getenv("PORT_HUNTER_MAX_PCAP_MB", "200"),
        "OTX_API_KEY": os.getenv("OTX_API_KEY", ""),
        "GREYNOISE_API_KEY": os.getenv("GREYNOISE_API_KEY", ""),
        "GEOLITE2_CITY_DB": os.getenv("GEOLITE2_CITY_DB") or os.getenv("GEOIP_DB_PATH", ""),
    },
)

async def open_session() -> Tuple[ClientSession, Any, Any]:
    """Devuelve (session, read, write). Inicializa el handshake MCP."""
    read = write = None
    cm = stdio_client(SERVER)
    read, write = await cm.__aenter__()  # abrimos manualmente el context manager
    session = ClientSession(read, write)
    await session.__aenter__()
    await session.initialize()
    return session, read, write

async def close_session(session: ClientSession, read, write):
    await session.__aexit__(None, None, None)
    await stdio_client(SERVER).__aexit__(None, None, None)  # No-op para simetría

async def call_tool(name: str, arguments: Dict[str, Any]) -> Any:
    """Llama una tool y normaliza JSON/texto."""
    async with stdio_client(SERVER) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            rsp = await session.call_tool(name=name, arguments=arguments)

            sc = getattr(rsp, "structuredContent", None)
            if isinstance(sc, dict):
                return sc

            if rsp.content:
                txt = ""
                for part in rsp.content:
                    if isinstance(part, types.TextContent):
                        txt += part.text
                if txt:
                    try:
                        return json.loads(txt)
                    except Exception:
                        return txt
            return None
