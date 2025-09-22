from __future__ import annotations
import re, json, os
from pathlib import Path
from typing import Dict, Any, Optional, Tuple
from mcp import StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.client.session import ClientSession

PORT_HUNTER = StdioServerParameters(
    command="python",
    args=["-m", "porthunter.server"],
    env={
        "PORT_HUNTER_TOKEN": os.getenv("PORT_HUNTER_TOKEN", "TEST_TOKEN"),
        "PORT_HUNTER_ALLOWED_DIR": os.getenv("PORT_HUNTER_ALLOWED_DIR", os.getcwd()),
    },
)

def _extract_path(text: str) -> Optional[str]:
    # Busca algo con .pcap o .pcapng
    m = re.search(r'([\w\-.\\/]+\.pcapng|[\w\-.\\/]+\.pcap)', text, re.IGNORECASE)
    return m.group(1) if m else None

def _extract_ip(text: str) -> Optional[str]:
    m = re.search(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b', text)
    return m.group(1) if m else None

async def _call_tool(name: str, args: Dict[str, Any]) -> Dict[str, Any]:
    # Inyecta auth_token si falta
    token = PORT_HUNTER.env.get("PORT_HUNTER_TOKEN", "TEST_TOKEN")
    if "auth_token" not in args:
        args["auth_token"] = token

    async with stdio_client(PORT_HUNTER) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            resp = await session.call_tool(name=name, arguments=args)
            sc = getattr(resp, "structuredContent", None)
            if isinstance(sc, dict):
                return sc.get("result", sc)
            # fallback: texto plano JSON
            text = "".join(getattr(b, "text", "") for b in resp.content)
            try:
                return json.loads(text)
            except Exception:
                return {"raw": text}

async def route_message(user_text: str) -> Tuple[str, Dict[str, Any]]:
    """
    Devuelve: (tipo_respuesta, payload_json)
    tipo_respuesta: 'overview' | 'suspects' | 'first_event' | 'enrich' | 'correlate' | 'error'
    """
    t = user_text.lower()
    p = _extract_path(user_text)

    # 1) Overview
    if any(k in t for k in ["analiza", "overview", "resumen", "scan_overview"]):
        if not p:
            return "error", {"error": "missing_path", "hint": "Incluye un .pcap o .pcapng"}
        data = await _call_tool("scan_overview", {"path": p})
        return "overview", data

    # 2) Sospechosos / suspects
    if any(k in t for k in ["sospech", "suspect", "list_suspects"]):
        if not p:
            return "error", {"error": "missing_path", "hint": "Incluye un .pcap o .pcapng"}
        data = await _call_tool("list_suspects", {"path": p})
        return "suspects", data

    # 3) Primer evento de escaneo
    if any(k in t for k in ["primer evento", "first event", "first_scan_event"]):
        if not p:
            return "error", {"error": "missing_path", "hint": "Incluye un .pcap o .pcapng"}
        data = await _call_tool("first_scan_event", {"path": p})
        return "first_event", data

    # 4) Enriquecimiento de IP
    if any(k in t for k in ["enriquec", "enrich", "info ip"]):
        ip = _extract_ip(user_text)
        if not ip:
            return "error", {"error": "missing_ip", "hint": "Incluye una IP v4"}
        data = await _call_tool("enrich_ip", {"ip": ip})
        return "enrich", data

    # 5) Correlate múltiples IPs (si el usuario pega varias IPs)
    ips = re.findall(r'\b\d{1,3}(?:\.\d{1,3}){3}\b', user_text)
    if "correl" in t and ips:
        data = await _call_tool("correlate", {"ips": ips})
        return "correlate", data

    return "error", {"error": "no_intent", "hint": "Ejemplos: 'analiza captures\\scan-demo-20250906-1.pcapng', 'lista sospechosos tiny.pcap', 'enriquece ip 8.8.8.8'."}
