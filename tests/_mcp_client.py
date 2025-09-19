import os
import json
import asyncio
from typing import Any, Dict

try:
    from mcp.client.stdio import StdioServerParameters as _StdParams
except ImportError:
    from mcp.client.stdio import StdioServerParams as _StdParams
try:
    from mcp.client.stdio import connect_stdio as _connect_stdio
except ImportError:
    from mcp.client.stdio import connect as _connect_stdio

TOKEN = os.getenv("PORT_HUNTER_TOKEN", "TEST_TOKEN")
ALLOWED_DIR = os.getenv("PORT_HUNTER_ALLOWED_DIR", ".")

SERVER_ENV = {
    "PORT_HUNTER_TOKEN": TOKEN,
    "PORT_HUNTER_ALLOWED_DIR": ALLOWED_DIR,
    "PORT_HUNTER_ALLOW_PRIVATE": "false",
    "PORT_HUNTER_REQUIRE_TOKEN": os.getenv("PORT_HUNTER_REQUIRE_TOKEN", "true"),
    "PORT_HUNTER_MAX_PCAP_MB": os.getenv("PORT_HUNTER_MAX_PCAP_MB", "50"),
}

PORT_HUNTER = _StdParams(
    command="python",
    args=["-m", "porthunter.server"],
    env=SERVER_ENV,
)

async def call_tool(name: str, arguments: Dict[str, Any]) -> Any:
    async with await _connect_stdio(PORT_HUNTER) as (client, _proc):
        rsp = await client.call_tool(name, arguments)
        if not rsp or not rsp.content:
            return None
        for part in rsp.content:
            t = getattr(part, "type", None)
            if t == "json":
                return part.data
            if t == "text":
                try:
                    return json.loads(part.text)
                except Exception:
                    return part.text
        return None
