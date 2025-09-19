#!/usr/bin/env python3
import os
import time
import json
import asyncio
from pathlib import Path
from typing import Any, Dict

# Reutilizamos la lógica del cliente MCP estilo main.py sin requerir UI
try:
    from mcp.client.stdio import StdioServerParameters as _StdParams
except ImportError:
    from mcp.client.stdio import StdioServerParams as _StdParams
try:
    from mcp.client.stdio import connect_stdio as _connect_stdio
except ImportError:
    from mcp.client.stdio import connect as _connect_stdio

ROOT_DIR = Path(__file__).resolve().parents[1]
DEFAULT_PCAP_DIR = ROOT_DIR / "captures"

TOKEN = os.getenv("PORT_HUNTER_TOKEN", "MiTOKENultraSecreto123")
PCAP_DIR = Path(os.getenv("PORT_HUNTER_ALLOWED_DIR", str(DEFAULT_PCAP_DIR))).resolve()

SERVER_ENV = {
    "PORT_HUNTER_TOKEN": TOKEN,
    "PORT_HUNTER_ALLOWED_DIR": str(PCAP_DIR),
    "PORT_HUNTER_ALLOW_PRIVATE": os.getenv("PORT_HUNTER_ALLOW_PRIVATE", "false"),
    "PORT_HUNTER_CACHE_DIR": os.getenv("PORT_HUNTER_CACHE_DIR", ".cache/porthunter"),
    "PORT_HUNTER_REQUIRE_TOKEN": os.getenv("PORT_HUNTER_REQUIRE_TOKEN", "true"),
    "PORT_HUNTER_MAX_PCAP_MB": os.getenv("PORT_HUNTER_MAX_PCAP_MB", "200"),
    "OTX_API_KEY": os.getenv("OTX_API_KEY", ""),
    "GREYNOISE_API_KEY": os.getenv("GREYNOISE_API_KEY", ""),
    "GEOLITE2_CITY_DB": os.getenv("GEOLITE2_CITY_DB") or os.getenv("GEOIP_DB_PATH", ""),
}

PORT_HUNTER = _StdParams(
    command="python",
    args=["-m", "porthunter.server"],
    env=SERVER_ENV,
)

async def _call_tool(name: str, arguments: Dict[str, Any]) -> Any:
    async with await _connect_stdio(PORT_HUNTER) as (client, _proc):
        rsp = await client.call_tool(name, arguments)
        if not rsp or not rsp.content:
            return None
        for part in rsp.content:
            if getattr(part, "type", None) == "json":
                return part.data
            if getattr(part, "type", None) == "text":
                try:
                    return json.loads(part.text)
                except Exception:
                    return part.text
        return None

def _abs_pcap(path: str) -> str:
    p = Path(path)
    if not p.is_absolute():
        p = (PCAP_DIR / p).resolve()
    return str(p)

async def run_bench(pcap_name: str) -> Dict[str, Any]:
    results: Dict[str, Any] = {"pcap": pcap_name}

    t0 = time.perf_counter()
    info = await _call_tool("get_info", {"auth_token": TOKEN})
    t1 = time.perf_counter()

    p = _abs_pcap(pcap_name)
    ov0 = time.perf_counter()
    overview = await _call_tool("scan_overview", {"path": p, "auth_token": TOKEN})
    ov1 = time.perf_counter()

    fe0 = time.perf_counter()
    first = await _call_tool("first_scan_event", {"path": p, "auth_token": TOKEN})
    fe1 = time.perf_counter()

    results["get_info_s"] = round(t1 - t0, 3)
    results["overview_s"] = round(ov1 - ov0, 3)
    results["first_event_s"] = round(fe1 - fe0, 3)

    try:
        ov = overview.get("overview", {})
        results["total_pkts"] = ov.get("total_pkts")
        results["interval_s"] = ov.get("interval_s")
        results["suspected_patterns"] = ov.get("suspected_patterns", [])
        results["scanners_count"] = len(ov.get("scanners", []))
    except Exception:
        pass

    results["ok"] = bool(overview and first)
    return results

def main():
    import argparse
    ap = argparse.ArgumentParser(description="Benchmark PortHunter (MCP stdio)")
    ap.add_argument("pcap", help="Archivo .pcap o .pcapng dentro de PORT_HUNTER_ALLOWED_DIR")
    args = ap.parse_args()

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    res = loop.run_until_complete(run_bench(args.pcap))
    print(json.dumps(res, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    main()
