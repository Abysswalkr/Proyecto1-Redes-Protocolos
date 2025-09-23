from __future__ import annotations

import os
import sys
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional
import re
from datetime import datetime, UTC
from ipaddress import ip_address, ip_network

# -----------------------------------------------------------------------------
# Logging SOLO a STDERR (stdout es exclusivo del protocolo MCP/JSON-RPC)
# -----------------------------------------------------------------------------
logging.basicConfig(
    level=os.getenv("PORT_HUNTER_LOG_LEVEL", "WARNING"),
    stream=sys.stderr,
    format="%(levelname)s:%(name)s:%(message)s",
)
log = logging.getLogger("porthunter.stdio_server")

APP_NAME = "PortHunter MCP (stdio)"
ENV_TOKEN = os.getenv("PORT_HUNTER_TOKEN")
ALLOWED_DIR = Path(os.getenv("PORT_HUNTER_ALLOWED_DIR", ".")).resolve()
ALLOW_PRIVATE = os.getenv("PORT_HUNTER_ALLOW_PRIVATE", "false").lower() in {"1", "true", "yes"}

CACHE_DIR = Path(os.getenv("PORT_HUNTER_CACHE_DIR", ".cache/porthunter")).resolve()
CACHE_DIR.mkdir(parents=True, exist_ok=True)
try:
    _ttl_days = int(os.getenv("PORT_HUNTER_CACHE_TTL_DAYS", "7"))
except Exception:
    _ttl_days = 7

# === Utils del proyecto (sin cambios de negocio)
from .utils.pcap import analyze_pcap   # devuelve (overview, first_event)
from .utils.cache import SimpleCache
from .utils.intel.otx import otx_enrich
from .utils.intel.greynoise import greynoise_enrich
from .utils.intel.asn import asn_lookup
from .utils.intel.geo import geo_lookup

CACHE_FILE = CACHE_DIR / "intel_cache.json"
cache = SimpleCache(CACHE_FILE, ttl_seconds=_ttl_days * 24 * 3600)

# --- políticas / límites (config por .env)
REQUIRE_TOKEN = os.getenv("PORT_HUNTER_REQUIRE_TOKEN", "true").lower() in {"1", "true", "yes"}
MAX_PCAP_MB   = int(os.getenv("PORT_HUNTER_MAX_PCAP_MB", "200"))
ALLOWED_EXTS  = {".pcap", ".pcapng"}
IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")

_PRIVATE_NETS = [
    ip_network("10.0.0.0/8"),
    ip_network("172.16.0.0/12"),
    ip_network("192.168.0.0/16"),
    ip_network("127.0.0.0/8"),
    ip_network("169.254.0.0/16"),
    ip_network("::1/128"),
    ip_network("fc00::/7"),
    ip_network("fe80::/10"),
]

def _now() -> str:
    return datetime.now(UTC).isoformat()

def _is_private_ip(ip: str) -> bool:
    try:
        a = ip_address(ip)
        return any(a in n for n in _PRIVATE_NETS)
    except Exception:
        return True

def _is_valid_ip(ip: str) -> bool:
    try:
        ip_address(ip)
        return True
    except Exception:
        return False

def _require_token(auth: Optional[str]) -> None:
    """Si se habilita REQUIRE_TOKEN, exige que auth coincida con PORT_HUNTER_TOKEN."""
    if not REQUIRE_TOKEN:
        return
    if not ENV_TOKEN:
        raise PermissionError("server_misconfigured: missing PORT_HUNTER_TOKEN")
    if auth != ENV_TOKEN:
        raise PermissionError("authentication_required")

def _sanitize_path(path: str) -> Path:
    """Normaliza, restringe a ALLOWED_DIR, fuerza extensión válida y tamaño máximo."""
    p = (Path(path).expanduser()).resolve()
    if not str(p).startswith(str(ALLOWED_DIR)):
        raise ValueError("path_outside_allowed_dir")
    if not p.exists():
        raise FileNotFoundError("path_not_found")
    if not p.is_file():
        raise ValueError("path_not_a_file")
    if p.suffix.lower() not in ALLOWED_EXTS:
        raise ValueError("unsupported_file_type")
    size_mb = p.stat().st_size / (1024 * 1024)
    if size_mb > MAX_PCAP_MB:
        raise ValueError(f"file_too_large:{int(size_mb)}MB>{MAX_PCAP_MB}MB")
    return p

def _safe_enrich_ip(ip: str) -> Dict[str, Any]:
    if _is_private_ip(ip) and not ALLOW_PRIVATE:
        return {"ip": ip, "skipped": True, "reason": "private_or_local_ip", "generated_at": _now()}
    cache_key = f"enrich:{ip}"
    c = cache.get(cache_key)
    if c:
        return c
    otx_key = os.getenv("OTX_API_KEY", "")
    gn_key  = os.getenv("GREYNOISE_API_KEY", "")
    geo_db  = os.getenv("GEOLITE2_CITY_DB") or os.getenv("GEOIP_DB_PATH")
    out = {
        "ip": ip,
        "generated_at": _now(),
        "otx": otx_enrich(ip, otx_key),
        "greynoise": greynoise_enrich(ip, gn_key),
        "asn": asn_lookup(ip),
        "geo": geo_lookup(ip, geo_db),
    }
    cache.set(cache_key, out)
    return out

# =============================================================================
#  STDIO framing para MCP: **UNA LÍNEA JSON POR MENSAJE** (sin Content-Length)
# =============================================================================
def _read_msg_line(fin) -> Optional[Dict[str, Any]]:
    """
    Lee una línea UTF-8 de stdin y la parsea como JSON.
    La spec indica que cada mensaje es un JSON *en una sola línea* separado por '\n'.
    """
    line = fin.readline()
    if not line:
        return None
    try:
        s = line.decode("utf-8").rstrip("\r\n").strip()
        if not s:
            return None
        return json.loads(s)
    except Exception as e:
        log.error("Línea JSON inválida (ignorada): %r (%s)", line, e)
        return None

def _write_msg_line(fout, payload: Dict[str, Any]) -> None:
    """
    Escribe el payload como una *única* línea JSON (sin newlines embebidos).
    """
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    # Seguridad adicional: por si acaso alguien mete '\n' en texto, lo colapsamos.
    body = body.replace("\r", " ").replace("\n", " ")
    fout.write((body + "\n").encode("utf-8"))
    fout.flush()

# =============================================================================
#  Tools (definición)
# =============================================================================
def _tool_def(name: str, description: str, properties: Dict[str, Any] | None = None, required: List[str] | None = None):
    return {
        "name": name,
        "description": description,
        "inputSchema": {
            "type": "object",
            "properties": properties or {},
            "required": required or [],
        },
    }

TOOLS_SPEC = [
    _tool_def(
        "get_info",
        "Estado del servidor PortHunter y capacidades.",
        {"auth_token": {"type": "string", "description": "Token de autenticación (si se requiere)"}},
    ),
    _tool_def(
        "scan_overview",
        "Resumen de actividad (scanners, puertos, targets) para un PCAP.",
        {
            "path": {"type": "string", "description": "Ruta del archivo .pcap o .pcapng"},
            "time_window_s": {"type": "integer", "description": "Ventana temporal para agrupación", "default": 60},
            "top_k": {"type": "integer", "description": "Top K resultados", "default": 20},
            "auth_token": {"type": "string"},
        },
        required=["path"],
    ),
    _tool_def(
        "first_scan_event",
        "Primer evento de escaneo detectado en el PCAP.",
        {
            "path": {"type": "string", "description": "Ruta del archivo .pcap o .pcapng"},
            "auth_token": {"type": "string"},
        },
        required=["path"],
    ),
    _tool_def(
        "list_suspects",
        "IPs sospechosas por umbrales básicos.",
        {
            "path": {"type": "string"},
            "min_ports": {"type": "integer", "default": 2},
            "min_rate_pps": {"type": "number", "default": 1.0},
            "auth_token": {"type": "string"},
        },
        required=["path"],
    ),
    _tool_def(
        "enrich_ip",
        "Enriquecimiento OTX, GreyNoise, ASN, Geo de una IP.",
        {"ip": {"type": "string"}, "auth_token": {"type": "string"}},
        required=["ip"],
    ),
    _tool_def(
        "correlate",
        "Puntaje simple 0–100 por IP a partir de enriquecimientos.",
        {"ips": {"type": "array", "items": {"type": "string"}}, "auth_token": {"type": "string"}},
        required=["ips"],
    ),
]

# =============================================================================
#  Handlers JSON-RPC
# =============================================================================
def _ok_text_and_struct(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Devuelve ambos formatos:
    - content: bloque 'text' con el JSON serializado (compatible universal)
    - structuredContent: el mismo JSON como objeto (para clientes que lo lean tipado)
    """
    return {
        "content": [{"type": "text", "text": json.dumps(data, ensure_ascii=False)}],
        "structuredContent": data,
    }

def _handle_initialize(params: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "protocolVersion": "2025-06-18",
        "serverInfo": {"name": APP_NAME, "version": "1.0"},
        "capabilities": {
            "tools": {},  # <-- Debe ser objeto (no boolean)
        },
    }

def _handle_tools_list(params: Dict[str, Any]) -> Dict[str, Any]:
    return {"tools": TOOLS_SPEC}

def _handle_tools_call(params: Dict[str, Any]) -> Dict[str, Any]:
    name = params.get("name")
    arguments = params.get("arguments") or {}

    if name == "get_info":
        try:
            _require_token(arguments.get("auth_token"))
            data = {
                "ok": True,
                "serverInfo": {"name": APP_NAME, "version": "1.0"},
                "protocolVersion": "2025-06-18",
                "capabilities": {"tools": {}},
                "secure_mode": bool(ENV_TOKEN),
                "allow_private": ALLOW_PRIVATE,
                "allowed_dir": str(ALLOWED_DIR),
                "cache_file": str(CACHE_FILE),
                "ttl_days": _ttl_days,
                "generated_at": _now(),
            }
        except PermissionError as e:
            data = {"ok": False, "error": str(e), "generated_at": _now()}
        return _ok_text_and_struct(data)

    if name == "scan_overview":
        try:
            _require_token(arguments.get("auth_token"))
            p = _sanitize_path(arguments.get("path", ""))
            tw = int(arguments.get("time_window_s", 60))
            tk = int(arguments.get("top_k", 20))
            overview, first_event = analyze_pcap(str(p), time_window_s=tw, top_k=tk)
            data = {"ok": True, "overview": overview, "first_event": first_event, "generated_at": _now()}
        except Exception as e:
            log.exception("scan_overview error")
            data = {"ok": False, "error": str(e), "generated_at": _now()}
        return _ok_text_and_struct(data)

    if name == "first_scan_event":
        try:
            _require_token(arguments.get("auth_token"))
            p = _sanitize_path(arguments.get("path", ""))
            _, fe = analyze_pcap(str(p), time_window_s=60, top_k=50)
            data = {"ok": True, "first_event": fe, "generated_at": _now()}
        except Exception as e:
            log.exception("first_scan_event error")
            data = {"ok": False, "error": str(e), "generated_at": _now()}
        return _ok_text_and_struct(data)

    if name == "list_suspects":
        try:
            _require_token(arguments.get("auth_token"))
            p = _sanitize_path(arguments.get("path", ""))
            overview, _ = analyze_pcap(str(p), time_window_s=60, top_k=200)
            interval = max(1, int(overview.get("interval_s", 0)) or 1)
            suspects: List[Dict[str, Any]] = []
            min_ports = int(arguments.get("min_ports", 2))
            min_rate_pps = float(arguments.get("min_rate_pps", 1.0))
            for s in overview.get("scanners", []):
                pkts = int(s.get("pkts", 0))
                dp = int(s.get("distinct_ports", 0))
                dh = int(s.get("distinct_hosts", 0))
                rate = pkts / float(interval)
                if dp >= min_ports and rate >= min_rate_pps:
                    suspects.append({
                        "scanner": s.get("ip"),
                        "pattern": s.get("pattern") or "mixed",
                        "rate_pps": round(rate, 2),
                        "evidence": {
                            "first_t": s.get("first_t"),
                            "pkts": pkts,
                            "unique_ports": dp,
                            "unique_targets": dh,
                            "flag_stats": s.get("flag_stats", {}),
                        },
                    })
            data = {"ok": True, "suspects": suspects, "generated_at": _now()}
        except Exception as e:
            log.exception("list_suspects error")
            data = {"ok": False, "error": str(e), "generated_at": _now()}
        return _ok_text_and_struct(data)

    if name == "enrich_ip":
        try:
            _require_token(arguments.get("auth_token"))
            ip = str(arguments.get("ip", "")).strip()
            if not _is_valid_ip(ip):
                raise ValueError("invalid_ip")
            data = {"ok": True, "enrichment": _safe_enrich_ip(ip), "generated_at": _now()}
        except Exception as e:
            data = {"ok": False, "error": str(e), "generated_at": _now()}
        return _ok_text_and_struct(data)

    if name == "correlate":
        try:
            _require_token(arguments.get("auth_token"))
            ips_in = list(arguments.get("ips") or [])
            out: List[Dict[str, Any]] = []
            for ip in ips_in:
                ip = str(ip).strip()
                if not _is_valid_ip(ip):
                    out.append({"ip": ip, "ok": False, "error": "invalid_ip"})
                    continue
                enr = _safe_enrich_ip(ip)
                if enr.get("skipped"):
                    out.append({
                        "ip": ip,
                        "skipped": True,
                        "reason": enr.get("reason"),
                        "threat_score": 0,
                        "rationale": ["private_ip"],
                    })
                    continue
                score = 0
                rationale: List[str] = []
                otx = enr.get("otx", {})
                if otx.get("enabled") and otx.get("pulse_count", 0) > 0:
                    score += min(40, 10 + otx["pulse_count"] * 2)
                    rationale.append(f"otx:pulses={otx['pulse_count']}")
                gn = enr.get("greynoise", {})
                if gn.get("enabled") and gn.get("found"):
                    score += 20
                    rationale.append(f"greynoise:{gn.get('classification')}")
                asn = enr.get("asn", {})
                org = (asn.get("org") or "").lower()
                if any(k in org for k in ["cloud", "aws", "azure", "google", "digitalocean", "hosting"]):
                    score += 10
                    rationale.append("asn:cloud")
                geo = enr.get("geo", {})
                if geo.get("enabled") and geo.get("country"):
                    rationale.append(f"geo:{geo.get('country')}")
                out.append({"ip": ip, "threat_score": min(100, score), "rationale": rationale})
            data = {"ok": True, "results": out, "generated_at": _now()}
        except Exception as e:
            data = {"ok": False, "error": str(e), "generated_at": _now()}
        return _ok_text_and_struct(data)

    return _ok_text_and_struct({"ok": False, "error": "unknown_tool"})

def _handle_request(req: Dict[str, Any]) -> Dict[str, Any]:
    rid = req.get("id")
    method = req.get("method")
    params = req.get("params") or {}
    try:
        if method == "initialize":
            return {"jsonrpc": "2.0", "id": rid, "result": _handle_initialize(params)}
        if method == "tools/list":
            return {"jsonrpc": "2.0", "id": rid, "result": _handle_tools_list(params)}
        if method == "tools/call":
            return {"jsonrpc": "2.0", "id": rid, "result": _handle_tools_call(params)}
        return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": "Method not found"}}
    except Exception as e:
        log.exception("error at handling request")
        return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32000, "message": str(e)}}

def main() -> None:
    # importantísimo: no usar print; solo escribir JSON por stdout
    fin = sys.stdin.buffer
    fout = sys.stdout.buffer
    while True:
        req = _read_msg_line(fin)
        if req is None:
            # EOF o línea vacía → salida limpia
            break
        resp = _handle_request(req)
        _write_msg_line(fout, resp)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
