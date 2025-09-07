from __future__ import annotations
import os
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List

from mcp.server.fastmcp import FastMCP

from .utils.pcap import analyze_pcap
from .utils.cache import SimpleCache
from .utils.intel.otx import otx_enrich
from .utils.intel.greynoise import greynoise_enrich
from .utils.intel.asn import asn_lookup
from .utils.intel.geo import geo_lookup

app = FastMCP("PortHunter MCP")

# Caché local (archivo junto al paquete)
_CACHE_PATH = Path(__file__).resolve().parent / "_cache.json"
_TTL_DAYS = int(os.getenv("PORT_HUNTER_CACHE_TTL_DAYS", "7"))
cache = SimpleCache(_CACHE_PATH, ttl_seconds=_TTL_DAYS * 24 * 3600)

def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")

def _ensure_pcap(p: str) -> Path:
    path = Path(p)
    if not path.exists() or not path.is_file() or path.suffix.lower() not in {".pcap", ".pcapng"}:
        if path.exists() and path.is_dir():
            return path
        raise ValueError(f"PCAP inválido o no encontrado: {p}")
    return path

@app.tool()
def scan_overview(path: str, time_window_s: int = 60, top_k: int = 20) -> Dict[str, Any]:
    p = _ensure_pcap(path)
    # Si es dir (demo), devolvemos estructura vacía coherente
    if p.is_dir():
        return {
            "total_pkts": 0, "interval_s": 0,
            "scanners": [], "targets": [], "port_distribution": [],
            "suspected_patterns": [], "generated_at": _now()
        }
    overview, _first = analyze_pcap(str(p), time_window_s=time_window_s, top_k=top_k)
    return overview

@app.tool()
def list_suspects(path: str, min_ports: int = 10, min_rate_pps: float = 5.0) -> Dict[str, Any]:
    p = _ensure_pcap(path)
    if p.is_dir():
        return {"suspects": [], "generated_at": _now()}

    overview, _first = analyze_pcap(str(p), time_window_s=60, top_k=200)
    suspects = []
    for s in overview["scanners"]:
        # Heurística de sospecha: muchos puertos o muchos hosts
        if s["distinct_ports"] >= min_ports or s["distinct_hosts"] >= min_ports:
            # vertical/horizontal score simples
            denom = max(1, s["distinct_ports"] + s["distinct_hosts"])
            vertical_score = s["distinct_ports"] / denom
            horizontal_score = s["distinct_hosts"] / denom
            suspects.append({
                "scanner": s["ip"],
                "pattern": s.get("pattern", "unknown"),
                "vertical_score": round(vertical_score, 2),
                "horizontal_score": round(horizontal_score, 2),
                "evidence": {
                    "first_t": s.get("first_t"),
                    "pkts": s["pkts"],
                    "unique_ports": s["distinct_ports"],
                    "unique_targets": s["distinct_hosts"],
                    "flag_stats": s.get("flag_stats", {})
                }
            })
    return {"suspects": suspects, "generated_at": _now()}

@app.tool()
def first_scan_event(path: str) -> Dict[str, Any]:
    p = _ensure_pcap(path)
    if p.is_dir():
        return {"t_first": None, "detail": "Directorio (demo), sin PCAP", "generated_at": _now()}
    overview, first = analyze_pcap(str(p), time_window_s=60, top_k=50)
    return (first or {"t_first": None, "detail": "No se hallaron patrones de escaneo", "generated_at": _now()})

@app.tool()
def enrich_ip(ip: str) -> Dict[str, Any]:
    # No consultamos externos para IPs privadas/localhost
    try:
        from ipaddress import ip_address
        if not (ip_address(ip).is_global):
            return {
                "ip": ip, "skipped": True, "reason": "private_or_local",
                "generated_at": _now()
            }
    except Exception:
        pass

    # Cache key
    key = f"enrich:{ip}"
    cached = cache.get(key)
    if cached:
        return cached

    # TI externa
    otx_key = os.getenv("OTX_API_KEY") or None
    gn_key = os.getenv("GREYNOISE_API_KEY") or None
    geo_db = os.getenv("GEOIP_DB_PATH") or None

    otx = otx_enrich(ip, otx_key)
    gn  = greynoise_enrich(ip, gn_key)
    asn = asn_lookup(ip)
    geo = geo_lookup(ip, geo_db) if geo_db else {"enabled": False}

    result = {
        "ip": ip,
        "otx": otx,
        "greynoise": gn,
        "asn": asn,
        "geo": geo,
        "generated_at": _now()
    }
    cache.set(key, result)
    return result

@app.tool()
def correlate(ips: List[str]) -> Dict[str, Any]:
    """
    Threat score simple combinando señales externas y patrón dominante.
    """
    out = []
    for ip in ips:
        enr = enrich_ip(ip)
        score = 0
        rationale = []
        # Heurística: pulses OTX elevan score
        if enr.get("otx", {}).get("enabled"):
            pc = enr["otx"].get("pulse_count", 0)
            if pc > 0:
                score += min(50, pc * 10)
                rationale.append(f"otx:pulses={pc}")
        # GreyNoise
        gn = enr.get("greynoise", {})
        if gn.get("enabled") and gn.get("found"):
            score += 20
            rationale.append(f"greynoise:{gn.get('classification')}")
        # ASN: si es cloud genérico, subir un poco
        asn = enr.get("asn", {})
        org = (asn.get("org") or "").lower()
        if any(k in org for k in ["cloud", "digitalocean", "aws", "azure", "google", "hosting"]):
            score += 10
            rationale.append("asn:cloud")
        out.append({"ip": ip, "threat_score": min(100, score), "rationale": rationale})
    return {"results": out, "generated_at": _now()}

if __name__ == "__main__":
    # FastMCP corre por STDIO directamente
    app.run()
