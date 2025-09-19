from __future__ import annotations

import os
import sys
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Optional
from ipaddress import ip_address, ip_network

from mcp.server.fastmcp import FastMCP

# Utils del proyecto
from .utils.pcap import analyze_pcap   # <-- devuelve (overview, first_event)
from .utils.cache import SimpleCache
from .utils.intel.otx import otx_enrich
from .utils.intel.greynoise import greynoise_enrich
from .utils.intel.asn import asn_lookup
from .utils.intel.geo import geo_lookup

# ------------ Logging (NUNCA stdout) ------------
logging.basicConfig(
    level=os.getenv("PORT_HUNTER_LOG_LEVEL", "WARNING"),
    stream=sys.stderr,
    format="%(levelname)s:%(name)s:%(message)s",
)
log = logging.getLogger("porthunter.server")

APP_NAME = "PortHunter MCP"
app = FastMCP(APP_NAME)

# ------------ Config ------------
ENV_TOKEN = os.getenv("PORT_HUNTER_TOKEN")  # si existe, se exige en cada tool
ALLOWED_DIR = Path(os.getenv("PORT_HUNTER_ALLOWED_DIR", ".")).resolve()
ALLOW_PRIVATE = os.getenv("PORT_HUNTER_ALLOW_PRIVATE", "false").lower() in {"1", "true", "yes"}

# Caché
CACHE_DIR = Path(os.getenv("PORT_HUNTER_CACHE_DIR", ".")).resolve()
CACHE_DIR.mkdir(parents=True, exist_ok=True)
CACHE_FILE = CACHE_DIR / "intel_cache.json"
try:
    _ttl_days = int(os.getenv("PORT_HUNTER_CACHE_TTL_DAYS", "7"))
except ValueError:
    _ttl_days = 7
cache = SimpleCache(CACHE_FILE, ttl_seconds=_ttl_days * 24 * 3600)

# Redes privadas
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
    return datetime.utcnow().isoformat() + "Z"

def _is_private_ip(ip: str) -> bool:
    try:
        addr = ip_address(ip)
        return any(addr in net for net in _PRIVATE_NETS)
    except Exception:
        return True

def _require_token(auth_token: Optional[str]) -> None:
    if not ENV_TOKEN:
        return
    if auth_token != ENV_TOKEN:
        raise PermissionError("authentication_required")

def _sanitize_path(path: str) -> Path:
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
    if _is_private_ip(ip) and not ALLOW_PRIVATE:
        return {
            "ip": ip,
            "skipped": True,
            "reason": "private_or_local_ip",
            "generated_at": _now(),
        }

    otx_key = os.getenv("OTX_API_KEY")
    gn_key = os.getenv("GREYNOISE_API_KEY")
    geo_db = os.getenv("GEOLITE2_CITY_DB") or os.getenv("GEOIP_DB_PATH")

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

# ------------ TOOLS ------------

@app.tool()
def get_info(auth_token: Optional[str] = None) -> Dict[str, Any]:
    """
    Estado del servidor. Si PORT_HUNTER_TOKEN está definido, exige auth_token.
    """
    try:
        _require_token(auth_token)
        return {
            "ok": True,
            "serverInfo": {"name": APP_NAME, "version": "1.0"},
            "protocolVersion": "2025-06-18",
            "capabilities": {"tools": True},
            "secure_mode": bool(ENV_TOKEN),
            "allow_private": ALLOW_PRIVATE,
            "allowed_dir": str(ALLOWED_DIR),
            "cache_file": str(CACHE_FILE),
            "ttl_days": _ttl_days,
            "generated_at": _now(),
        }
    except PermissionError as e:
        return {"ok": False, "error": str(e), "generated_at": _now()}

@app.tool()
def scan_overview(
    path: str,
    time_window_s: int = 60,
    top_k: int = 20,
    auth_token: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Resumen de actividad en el PCAP.
    """
    try:
        _require_token(auth_token)
        p = _sanitize_path(path)
        overview, first_event = analyze_pcap(str(p), time_window_s=time_window_s, top_k=top_k)
        return {"ok": True, "overview": overview, "first_event": first_event, "generated_at": _now()}
    except Exception as e:
        log.exception("scan_overview error")
        return {"ok": False, "error": str(e), "generated_at": _now()}

@app.tool()
def list_suspects(
    path: str,
    min_ports: int = 10,
    min_rate_pps: float = 5.0,
    auth_token: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Lista de sospechosos con umbrales simples: número de puertos distintos y tasa (pps).
    """
    try:
        _require_token(auth_token)
        p = _sanitize_path(path)
        overview, _ = analyze_pcap(str(p), time_window_s=60, top_k=200)

        interval = max(1, int(overview.get("interval_s", 0)) or 1)
        suspects: List[Dict[str, Any]] = []
        # En nuestro pcap.py la lista de candidatos está en "scanners"
        for s in overview.get("scanners", []):
            pkts = int(s.get("pkts", 0))
            distinct_ports = int(s.get("distinct_ports", 0))
            distinct_hosts = int(s.get("distinct_hosts", 0))
            rate_pps = pkts / float(interval)
            if distinct_ports >= int(min_ports) and rate_pps >= float(min_rate_pps):
                # Scores simples (0..100) para reporte
                vertical_score = min(100.0, distinct_ports * 2.0)      # puertos distintos
                horizontal_score = min(100.0, distinct_hosts * 5.0)     # hosts distintos
                suspects.append({
                    "scanner": s.get("ip"),
                    "pattern": s.get("pattern") or "mixed",
                    "rate_pps": round(rate_pps, 2),
                    "vertical_score": round(vertical_score, 2),
                    "horizontal_score": round(horizontal_score, 2),
                    "evidence": {
                        "first_t": s.get("first_t"),
                        "pkts": pkts,
                        "unique_ports": distinct_ports,
                        "unique_targets": distinct_hosts,
                        "flag_stats": s.get("flag_stats", {}),
                    },
                })

        return {"ok": True, "suspects": suspects, "generated_at": _now()}
    except Exception as e:
        log.exception("list_suspects error")
        return {"ok": False, "error": str(e), "generated_at": _now()}

@app.tool()
def first_scan_event(path: str, auth_token: Optional[str] = None) -> Dict[str, Any]:
    """
    Primer evento de escaneo detectado.
    """
    try:
        _require_token(auth_token)
        p = _sanitize_path(path)
        _, fe = analyze_pcap(str(p), time_window_s=60, top_k=50)
        return {"ok": True, "first_event": fe, "generated_at": _now()}
    except Exception as e:
        log.exception("first_scan_event error")
        return {"ok": False, "error": str(e), "generated_at": _now()}

@app.tool()
def enrich_ip(ip: str, auth_token: Optional[str] = None) -> Dict[str, Any]:
    """
    Enriquecimiento OTX, GreyNoise, ASN y Geo con política do-not-share para IPs privadas.
    """
    try:
        _require_token(auth_token)
        return {"ok": True, "enrichment": _safe_enrich_ip(ip), "generated_at": _now()}
    except Exception as e:
        return {"ok": False, "error": str(e), "generated_at": _now()}

@app.tool()
def correlate(ips: List[str], auth_token: Optional[str] = None) -> Dict[str, Any]:
    """
    Puntaje simple 0–100 por IP a partir de evidencias externas.
    """
    try:
        _require_token(auth_token)
        out: List[Dict[str, Any]] = []
        for ip in ips:
            enr = _safe_enrich_ip(ip)
            if enr.get("skipped"):
                out.append({"ip": ip, "skipped": True, "reason": enr.get("reason"),
                            "threat_score": 0, "rationale": ["private_ip"]})
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
        return {"ok": True, "results": out, "generated_at": _now()}
    except Exception as e:
        return {"ok": False, "error": str(e), "generated_at": _now()}

# ------------ Main (STDIO, NO HTTP) ------------
if __name__ == "__main__":
    # Usar el adaptador de STDIO del submódulo correcto
    try:
        import mcp.server.fastmcp.stdio as _stdio  # ✅ submódulo real
    except Exception as e:
        logging.error(
            "No se pudo importar fastmcp.stdio (necesario para STDIO): %s", e
        )
        sys.exit(2)

    try:
        import anyio
        # Algunas versiones exponen stdio.serve(app), otras stdio.run(app)
        if hasattr(_stdio, "serve"):
            anyio.run(_stdio.serve, app)
        elif hasattr(_stdio, "run"):
            anyio.run(_stdio.run, app)
        else:
            raise RuntimeError(
                "La versión de fastmcp.stdio no expone ni 'serve' ni 'run'"
            )
    except Exception:
        logging.exception("Fallo al iniciar el servidor STDIO de MCP")
        sys.exit(2)
