from __future__ import annotations
import os
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Optional
from ipaddress import ip_address, ip_network

from mcp.server.fastmcp import FastMCP
from mcp.types import InitializeRequest  # usado solo para tipar el initialize hook

# Utils existentes del proyecto
from .utils.pcap import analyze_pcap
from .utils.cache import SimpleCache
from .utils.intel.otx import otx_enrich
from .utils.intel.greynoise import greynoise_enrich
from .utils.intel.asn import asn_lookup
from .utils.intel.geo import geo_lookup

# ========= Configuración y helpers de seguridad =========

APP_NAME = "PortHunter MCP"
app = FastMCP(APP_NAME)

# Entorno
ENV_TOKEN = os.getenv("PORT_HUNTER_TOKEN")  # si existe, se exigirá
ALLOWED_DIR = Path(os.getenv("PORT_HUNTER_ALLOWED_DIR", ".")).resolve()
ALLOW_PRIVATE = os.getenv("PORT_HUNTER_ALLOW_PRIVATE", "false").lower() in {"1", "true", "yes"}

# Caché local
_CACHE_DIR = Path(os.getenv("PORT_HUNTER_CACHE_DIR", ".")).resolve()
_CACHE_DIR.mkdir(parents=True, exist_ok=True)
_CACHE_FILE = _CACHE_DIR / "intel_cache.json"
cache = SimpleCache(_CACHE_FILE, ttl_seconds=7 * 24 * 3600)

# Redes privadas / no compartibles
_PRIVATE_NETS = [
    ip_network("10.0.0.0/8"),
    ip_network("172.16.0.0/12"),
    ip_network("192.168.0.0/16"),
    ip_network("127.0.0.0/8"),
    ip_network("169.254.0.0/16"),   # link-local
    ip_network("::1/128"),
    ip_network("fc00::/7"),         # unique local
    ip_network("fe80::/10"),        # link-local v6
]

def _now() -> str:
    return datetime.utcnow().isoformat() + "Z"

def _is_private_ip(ip: str) -> bool:
    try:
        addr = ip_address(ip)
        return any(addr in net for net in _PRIVATE_NETS)
    except Exception:
        # Si no es una IP válida, trátala como "no enriquecible"
        return True

def _require_token(headers: Dict[str, str] | None) -> None:
    """Exige token si PORT_HUNTER_TOKEN está definido."""
    if not ENV_TOKEN:
        return
    given = (headers or {}).get("X-Auth-Token") or (headers or {}).get("x-auth-token")
    if given != ENV_TOKEN:
        raise PermissionError("authentication_required")

def _sanitize_path(path: str) -> Path:
    """Valida ruta dentro de ALLOWED_DIR y tipos de archivo permitidos."""
    p = (Path(path).expanduser()).resolve()
    if not str(p).startswith(str(ALLOWED_DIR)):
        raise ValueError("path_outside_allowed_dir")
    if not p.exists():
        raise FileNotFoundError("path_not_found")
    if not p.is_file():
        raise ValueError("path_not_a_file")
    if p.suffix.lower() not in {".pcap", ".pcapng"}:
        raise ValueError("unsupported_file_type")
    return p

def _safe_enrich_ip(ip: str) -> Dict[str, Any]:
    """Enriquecimiento con política do-not-share para IPs privadas."""
    if _is_private_ip(ip) and not ALLOW_PRIVATE:
        return {
            "ip": ip,
            "skipped": True,
            "reason": "private_or_local_ip",
            "generated_at": _now(),
        }
    # OTX / GreyNoise claves desde entorno (opcionales)
    otx_key = os.getenv("OTX_API_KEY")
    gn_key = os.getenv("GREYNOISE_API_KEY")
    geo_db = os.getenv("GEOLITE2_CITY_DB")  # ruta a GeoLite2 opcional

    cache_key = f"enrich:{ip}"
    cached = cache.get(cache_key)
    if cached:
        return cached

    out: Dict[str, Any] = {"ip": ip, "generated_at": _now()}
    out["otx"] = otx_enrich(ip, otx_key)
    out["greynoise"] = greynoise_enrich(ip, gn_key)
    out["asn"] = asn_lookup(ip)
    out["geo"] = geo_lookup(ip, geo_db)

    cache.set(cache_key, out)
    return out

# ========= Hooks MCP (initialize) con auth opcional =========

@app.initialize()
def _on_initialize(req: InitializeRequest) -> Dict[str, Any]:
    """
    Si PORT_HUNTER_TOKEN está definido, exigimos encabezado X-Auth-Token en initialize.headers.
    """
    try:
        _require_token(getattr(req, "headers", None))  # algunas implementaciones envían headers
        return {
            "serverInfo": {"name": APP_NAME, "version": "1.0"},
            "protocolVersion": "2025-06-18",
            "capabilities": {"tools": True},
            "generated_at": _now(),
            "secure_mode": bool(ENV_TOKEN),
            "allow_private": ALLOW_PRIVATE,
            "allowed_dir": str(ALLOWED_DIR),
        }
    except PermissionError:
        return {"error": "authentication_required", "generated_at": _now()}

# ========= Tools =========

@app.tool()
def scan_overview(path: str, time_window_s: int = 60, top_k: int = 20, headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """
    Resumen de actividad en el PCAP.
    Seguridad: token + ruta validada + sandbox.
    """
    _require_token(headers)
    p = _sanitize_path(path)
    try:
        res = analyze_pcap(str(p), time_window_s=time_window_s, top_k=top_k)
        return {"ok": True, "overview": res, "generated_at": _now()}
    except Exception as e:
        return {"ok": False, "error": str(e), "generated_at": _now()}

@app.tool()
def list_suspects(path: str, min_ports: int = 10, min_rate_pps: float = 5.0, headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """
    Lista de sospechosos con evidencia.
    Seguridad: token + ruta validada + sandbox.
    """
    _require_token(headers)
    p = _sanitize_path(path)
    try:
        res = analyze_pcap(str(p), time_window_s=60, top_k=100)  # reutilizamos overview interno
        suspects = []
        for s in res.get("src_stats", []):
            # filtros mínimos
            if s.get("distinct_ports", 0) >= int(min_ports) and s.get("rate_pps", 0.0) >= float(min_rate_pps):
                pat = s.get("pattern") or "mixed"
                v_score = float(s.get("vertical_score", 0.0))
                h_score = float(s.get("horizontal_score", 0.0))
                suspects.append({
                    "scanner": s.get("ip"),
                    "pattern": pat,
                    "vertical_score": round(v_score, 2),
                    "horizontal_score": round(h_score, 2),
                    "evidence": {
                        "first_t": s.get("first_t"),
                        "pkts": s.get("pkts"),
                        "unique_ports": s.get("distinct_ports"),
                        "unique_targets": s.get("distinct_hosts"),
                        "flag_stats": s.get("flag_stats", {}),
                    }
                })
        return {"ok": True, "suspects": suspects, "generated_at": _now()}
    except Exception as e:
        return {"ok": False, "error": str(e), "generated_at": _now()}

@app.tool()
def first_scan_event(path: str, headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """
    Primer evento de escaneo (timestamp + quién + a quién + puerto).
    """
    _require_token(headers)
    p = _sanitize_path(path)
    try:
        res = analyze_pcap(str(p), time_window_s=60, top_k=100)
        fe = res.get("first_event")
        if not fe:
            return {"ok": True, "first_event": None, "generated_at": _now()}
        return {"ok": True, "first_event": fe, "generated_at": _now()}
    except Exception as e:
        return {"ok": False, "error": str(e), "generated_at": _now()}

@app.tool()
def enrich_ip(ip: str, headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """
    Enriquecimiento con OTX, GreyNoise, ASN y Geo (con política do-not-share).
    """
    _require_token(headers)
    try:
        return {"ok": True, "enrichment": _safe_enrich_ip(ip), "generated_at": _now()}
    except Exception as e:
        return {"ok": False, "error": str(e), "generated_at": _now()}

@app.tool()
def correlate(ips: List[str], headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """
    Puntaje 0–100 por IP a partir de:
    - Evidencia local (si ya fue enriquecida antes, podemos derivar heurísticas).
    - Evidencia externa (OTX/GN/ASN/Geo).
    """
    _require_token(headers)
    try:
        out: List[Dict[str, Any]] = []
        for ip in ips:
            enr = _safe_enrich_ip(ip)
            if enr.get("skipped"):
                out.append({"ip": ip, "skipped": True, "reason": enr.get("reason"), "threat_score": 0, "rationale": ["private_ip"]})
                continue

            score = 0
            rationale: List[str] = []
            # Evidencia externa
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
            if geo.get("enabled") and geo.get("country") and geo.get("country") not in {"GT"}:
                score += 5
                rationale.append(f"geo:{geo.get('country')}")

            out.append({"ip": ip, "threat_score": min(100, score), "rationale": rationale})
        return {"ok": True, "results": out, "generated_at": _now()}
    except Exception as e:
        return {"ok": False, "error": str(e), "generated_at": _now()}

if __name__ == "__main__":
    app.run()
