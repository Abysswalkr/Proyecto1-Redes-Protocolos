# propósito: smoke test de PortHunter.scan_overview con el PCAP de ejemplo.
import json, subprocess, sys, os

def call_host(cmd):
    return subprocess.check_output(
        [sys.executable, "-m", "apps.host.app.main",
         "--servers", "apps/host/profiles/servers.porthunter.yaml",
         "--once", cmd],
        text=True
    )

def test_scan_overview_returns_counts():
    out = call_host("analiza ./servers/porthunter/samples/nmap_syn_scan.pcap")
    data = json.loads(out)
    payload = json.loads(data["content"][0]["text"])
    assert payload["totals"]["total_pkts"] > 0
    assert any(tp["port"] == 22 for tp in payload["top_ports"])
