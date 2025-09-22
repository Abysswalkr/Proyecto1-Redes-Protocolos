from __future__ import annotations
import re
from pathlib import Path
from typing import Dict, Any, Optional

from app.mcp_local.clients import stdio_client

PORT_HUNTER_CMD = {"command": "python", "args": ["-m", "porthunter.server"], "env": {}}

PCAP_RE = re.compile(r"(?P<path>[\w\-/\\.:]+\.pcapng?|\.pcap)\b", re.IGNORECASE)
IP_RE   = re.compile(r"\b(\d{1,3}\.){3}\d{1,3}\b")

def detect_intent(text: str) -> Optional[Dict[str, Any]]:
    """Devuelve {action, args} o None."""
    text_low = text.lower()

    m = PCAP_RE.search(text)
    if m:
        return {"action": "scan_overview", "args": {"path": Path(m.group("path")).as_posix()}}

    if "primer evento" in text_low or "first event" in text_low:
        pm = PCAP_RE.search(text)
        if pm:
            return {"action": "first_scan_event", "args": {"path": Path(pm.group("path")).as_posix()}}

    if "sospechos" in text_low or "suspects" in text_low or "escaners" in text_low:
        pm = PCAP_RE.search(text)
        if pm:
            return {"action": "list_suspects", "args": {"path": Path(pm.group("path")).as_posix()}}

    if "enriquece" in text_low or "enrich" in text_low:
        ipm = IP_RE.search(text)
        if ipm:
            return {"action": "enrich_ip", "args": {"ip": ipm.group(0)}}

    if "correla" in text_low or "correlate" in text_low:
        ips = IP_RE.findall(text)
        if ips:
            # flatten findall’s tuples -> strings
            flat = [re.match(IP_RE, ip).group(0) if isinstance(ip, str) else "".join(ip) for ip in ips]
            return {"action": "correlate", "args": {"ips": list(dict.fromkeys(flat))}}

    return None

async def run_intent(action: str, args: Dict[str, Any], auth_token: str) -> Dict[str, Any]:
    payload = {**args, "auth_token": auth_token}
    tool = action
    async with stdio_client(PORT_HUNTER_CMD) as (read, write):
        # ensure tools list (warmup)
        await write({"type": "list_tools"})
        await read()

        await write({"type": "call_tool", "toolName": tool, "arguments": payload})
        resp = await read()

    # Normaliza: si el server devolvió texto JSON dentro de content.text, sácale el JSON
    raw = None
    try:
        raw = resp["content"][0]["text"]
    except Exception:
        pass

    if raw:
        import json
        try:
            parsed = json.loads(raw)
            return parsed
        except Exception:
            pass

    # Algunos clientes devuelven en meta["result"]
    result = resp.get("meta", {}).get("result")
    if isinstance(result, str):
        import json
        try:
            return json.loads(result)
        except Exception:
            return {"ok": False, "error": "malformed_result", "raw": resp}

    if isinstance(result, dict):
        return result

    return {"ok": False, "error": "unexpected_response", "raw": resp}
