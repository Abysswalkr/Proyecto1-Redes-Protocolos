# servers/porthunter/test/test_detections.py
from __future__ import annotations
from pathlib import Path
import re

from servers.porthunter.server import list_suspects, first_scan_event

SAMPLE = Path(__file__).resolve().parents[1] / "samples" / "nmap_syn_scan.pcap"

def test_list_suspects_syn_scan():
    res = list_suspects(str(SAMPLE), min_ports=5, min_rate_pps=0.1, min_hosts=1)
    sc = res.get("structuredContent") or res
    suspects = sc["suspects"]
    assert len(suspects) >= 1, "Debe al menos haber 1 sospechoso en el PCAP de nmap"

    s0 = suspects[0]
    # pattern exacto prometido por la propuesta
    assert s0["pattern"] == "syn_scan"
    # vertical > horizontal en un escaneo a muchos puertos
    assert s0["vertical_score"] > s0["horizontal_score"]

    fs = s0["evidence"]["flag_stats"]
    assert fs.get("SYN", 0) > 0

def test_first_scan_event_format():
    res = first_scan_event(str(SAMPLE))
    sc = res.get("structuredContent") or res

    t_first = sc["t_first"]
    assert isinstance(t_first, str)
    assert re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$", t_first), f"t_first no es ISO-UTC: {t_first}"

    pattern = sc.get("pattern")
    assert pattern and isinstance(pattern, str) and len(pattern) > 0

    # sanity extra: puerto entero positivo (si viene)
    if "port" in sc and sc["port"] is not None:
        assert isinstance(sc["port"], int)
        assert sc["port"] >= 0
