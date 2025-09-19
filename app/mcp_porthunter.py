# app/mcp_porthunter.py
import os, asyncio
from pathlib import Path
from mcp.client.stdio import StdioServerParams, connect_stdio

TOKEN    = os.getenv("PORT_HUNTER_TOKEN", "MiTOKENultraSecreto123")
PCAP_DIR = Path(os.getenv("PORT_HUNTER_ALLOWED_DIR", "./captures")).resolve()

SERVER = StdioServerParams(
    command="python",
    args=["-m", "porthunter.server"],
    env={
        "PORT_HUNTER_TOKEN": TOKEN,
        "PORT_HUNTER_ALLOWED_DIR": str(PCAP_DIR),
        "PORT_HUNTER_ALLOW_PRIVATE": os.getenv("PORT_HUNTER_ALLOW_PRIVATE", "false"),
        "PORT_HUNTER_CACHE_DIR": os.getenv("PORT_HUNTER_CACHE_DIR", ".cache/porthunter"),
        "OTX_API_KEY": os.getenv("OTX_API_KEY", ""),
        "GREYNOISE_API_KEY": os.getenv("GREYNOISE_API_KEY", ""),
        "GEOLITE2_CITY_DB": os.getenv("GEOLITE2_CITY_DB") or os.getenv("GEOIP_DB_PATH", ""),
    },
)

async def with_client():
    return await connect_stdio(SERVER)  # (client, server)

async def call(client, name: str, arguments: dict):
    rsp = await client.call_tool(name, arguments)
    # devolvemos el primer content.json/text legible
    if rsp and rsp.content:
        for part in rsp.content:
            if getattr(part, "type", None) == "json":
                return part.data
            if getattr(part, "type", None) == "text":
                return part.text
    return None
