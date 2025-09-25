"""
Purpose: Lightweight Threat Intelligence enrichment for PortHunter MCP.
Adds OTX, GreyNoise (community), ASN (best-effort), and GeoLite2 lookups with SQLite TTL cache.
Safe to run without any keys; gracefully degrades to what's available.
"""
from __future__ import annotations
import json, os, sqlite3, time, ipaddress, urllib.request
from typing import Any, Dict, Optional

TTL_SECONDS = int(os.getenv("PORTHUNTER_TTL_S", "86400"))
CACHE_DB = os.getenv("PORTHUNTER_CACHE_DB", ".porthunter_cache.sqlite3")
OTX_KEY = os.getenv("OTX_API_KEY")
GREYNOISE_KEY = os.getenv("GREYNOISE_API_KEY")
GEOLITE_DB = os.getenv("MAXMIND_DB_PATH")  # e.g., "./GeoLite2-City.mmdb"

def _ensure_db():
    con = sqlite3.connect(CACHE_DB)
    cur = con.cursor()
    cur.execute("""CREATE TABLE IF NOT EXISTS cache (
        k TEXT PRIMARY KEY,
        v TEXT NOT NULL,
        ts INTEGER NOT NULL
    )""")
    con.commit()
    return con

def _cache_get(con, k):
    cur = con.cursor()
    cur.execute("SELECT v, ts FROM cache WHERE k=?", (k,))
    row = cur.fetchone()
    if not row: return None
    v, ts = row
    if (time.time() - ts) > TTL_SECONDS: return None
    return json.loads(v)

def _cache_set(con, k, obj):
    cur = con.cursor()
    cur.execute("REPLACE INTO cache(k,v,ts) VALUES(?,?,?)", (k, json.dumps(obj), int(time.time())))
    con.commit()

def _http_json(url: str, headers: Dict[str, str] | None = None, timeout: int = 10) -> Dict[str, Any] | None:
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8", "ignore"))
    except Exception:
        return None

def _enrich_otx(ip: str) -> Dict[str, Any] | None:
    if not OTX_KEY: return None
    h = {"X-OTX-API-KEY": OTX_KEY, "User-Agent": "PortHunter/1.0"}
    data = _http_json(f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general", h) or {}
    repu = _http_json(f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/reputation", h) or {}
    pdns = _http_json(f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/passive_dns", h) or {}
    if not (data or repu or pdns): return None
    return {"general": data, "reputation": repu, "passive_dns": pdns}

def _enrich_greynoise(ip: str) -> Dict[str, Any] | None:
    # Community API (v3): header 'key' with API key if available.
    headers = {"User-Agent": "PortHunter/1.0"}
    if GREYNOISE_KEY:
        headers["key"] = GREYNOISE_KEY
    return _http_json(f"https://api.greynoise.io/v3/community/{ip}", headers)

def _enrich_asn(ip: str) -> Dict[str, Any] | None:
    # Best-effort fallback (Team Cymru DNS/WHOIS is preferred; keeping HTTP light).
    # If you have a local service, plug it here. We return None on failure.
    try:
        # Quick, public, informational ASN (low-SLA) API:
        data = _http_json(f"https://api.bgpview.io/ip/{ip}")
        if not data: return None
        return {
            "asn": data.get("data", {}).get("prefixes", [{}])[0].get("asn", {}),
            "prefixes": data.get("data", {}).get("prefixes", []),
            "rir_allocation": data.get("data", {}).get("rir_allocation", {}),
        }
    except Exception:
        return None

def _enrich_geo(ip: str) -> Dict[str, Any] | None:
    if not GEOLITE_DB: return None
    try:
        import geoip2.database  # lazy import
        reader = geoip2.database.Reader(GEOLITE_DB)
        rec = reader.city(ip)
        reader.close()
        return {
            "country": getattr(rec.country, "iso_code", None),
            "city": getattr(rec.city, "name", None),
            "location": {"lat": rec.location.latitude, "lon": rec.location.longitude},
        }
    except Exception:
        return None

def enrich_ip(ip: str) -> Dict[str, Any]:
    ipaddress.ip_address(ip)  # validate
    con = _ensure_db()
    k = f"enrich:{ip}"
    cached = _cache_get(con, k)
    if cached: return cached
    out = {
        "ip": ip,
        "otx": _enrich_otx(ip),
        "greynoise": _enrich_greynoise(ip),
        "asn": _enrich_asn(ip),
        "geo": _enrich_geo(ip),
        "note": "Missing providers are None; add API keys to enhance completeness."
    }
    _cache_set(con, k, out)
    return out

def correlate(ip_info: Dict[str, Any], local_evidence: Dict[str, Any]) -> Dict[str, Any]:
    """
    Combine local evidence (pps, unique_ports/targets, pattern, handshake_absence, vertical_score)
    with TI to produce threat_score (0-100).
    """
    score = 0.0
    # Local signals
    pps = float(local_evidence.get("pps", 0))
    uni_ports = int(local_evidence.get("unique_ports", 0))
    uni_targets = int(local_evidence.get("unique_targets", 0))
    vertical = float(local_evidence.get("vertical_score", 0))
    pattern = (local_evidence.get("pattern") or "").lower()
    handshake_absence = 1.0 if local_evidence.get("no_handshake", False) else 0.0

    score += min(pps / 50.0, 20.0) * 1.0
    score += min(uni_ports / 50.0, 20.0) * 1.0
    score += min(uni_targets / 20.0, 15.0) * 1.0
    if "syn" in pattern or "xmas" in pattern or "fin" in pattern or "null" in pattern:
        score += 10.0
    score += 10.0 * vertical
    score += 10.0 * handshake_absence

    # External TI
    otx = ip_info.get("otx") or {}
    rep = (otx.get("reputation") or {}).get("reputation", 0)
    score += min(float(rep), 15.0)

    gn = ip_info.get("greynoise") or {}
    if str(gn.get("classification", "")).lower() in ("malicious", "unknown"):
        score += 10.0
    if gn.get("noise") in (True, "true"):
        score += 5.0

    # Bound
    score = max(0.0, min(100.0, score))
    rationale = [
        "Local: pps/ports/targets/pattern/vertical/handshake",
        "TI: OTX reputation, GreyNoise noise/classification, ASN/Geo context"
    ]
    return {"threat_score": int(round(score)), "rationale": rationale}
