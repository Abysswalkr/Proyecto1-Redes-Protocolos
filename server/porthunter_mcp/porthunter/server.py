from __future__ import annotations
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List

from mcp.server.fastmcp import FastMCP

app = FastMCP("PortHunter MCP")

def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")

def _exists_file(p: str) -> None:
    if not Path(p).exists():
        raise ValueError(f"Archivo no encontrado: {p}")

@app.tool()
def scan_overview(path: str, time_window_s: int = 60, top_k: int = 20) -> Dict[str, Any]:
    _exists_file(path)
    return {
        "total_pkts": 123456,
        "interval_s": 600,
        "scanners": [
            {"ip": "203.0.113.5", "pkts": 520, "distinct_ports": 150, "distinct_hosts": 12},
            {"ip": "198.51.100.10", "pkts": 312, "distinct_ports": 90, "distinct_hosts": 4}
        ],
        "targets": [
            {"ip": "10.0.0.20", "pkts": 330, "ports_hit": [22, 80, 443]},
            {"ip": "10.0.0.30", "pkts": 110, "ports_hit": [3389, 53]}
        ],
        "port_distribution": [{"port": 80, "hits": 450}, {"port": 22, "hits": 200}],
        "suspected_patterns": ["syn_scan", "xmas_scan"],
        "generated_at": _now()
    }

@app.tool()
def list_suspects(path: str, min_ports: int = 10, min_rate_pps: float = 5.0) -> Dict[str, Any]:
    _exists_file(path)
    return {
        "suspects": [
            {
                "scanner": "203.0.113.5",
                "pattern": "syn_scan",
                "vertical_score": 0.82,
                "horizontal_score": 0.17,
                "evidence": {
                    "first_t": "2025-08-27T02:10:31Z",
                    "pkts": 520,
                    "unique_ports": 150,
                    "unique_targets": 12,
                    "flag_stats": {"SYN": 510, "FIN": 0, "PSH": 0, "URG": 0, "RST": 5}
                }
            }
        ],
        "generated_at": _now()
    }

@app.tool()
def first_scan_event(path: str) -> Dict[str, Any]:
    _exists_file(path)
    return {
        "t_first": "2025-08-27T02:09:01Z",
        "scanner": "203.0.113.5",
        "pattern": "syn_scan",
        "target": "10.0.0.20",
        "port": 22,
        "detail": "SYN sin 3-way handshake completado; patrón secuencial de puertos",
        "generated_at": _now()
    }

@app.tool()
def enrich_ip(ip: str) -> Dict[str, Any]:
    return {
        "ip": ip,
        "otx": {"reputation": "low", "pulses": ["ExamplePulse"], "references": [f"https://otx.alienvault.com/indicator/ip/{ip}"]},
        "greynoise": {"noise": True, "classification": "benign-scanner"},
        "asn": {"asn": 64500, "org": "Example Cloud"},
        "geo": {"country": "US", "city": "ExampleCity"},
        "generated_at": _now()
    }

@app.tool()
def correlate(ips: List[str]) -> Dict[str, Any]:
    scored = []
    for i, ip in enumerate(ips):
        scored.append({"ip": ip, "threat_score": 80 - i * 5, "rationale": ["syn_scan", "otx:pulse:ExamplePulse"]})
    return {"results": scored, "generated_at": _now()}

if __name__ == "__main__":
    app.run()
