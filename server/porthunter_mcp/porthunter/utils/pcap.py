from __future__ import annotations
from collections import Counter, defaultdict
from datetime import datetime
from typing import Dict, Any, List, Tuple, Optional
from ipaddress import ip_address, IPv4Address, IPv6Address

from scapy.utils import PcapReader
from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv6

# ---- Flags helpers ----
SYN = 0x02
ACK = 0x10
FIN = 0x01
PSH = 0x08
URG = 0x20

def _is_public(ip: str) -> bool:
    try:
        ip_obj = ip_address(ip)
        return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved or ip_obj.is_multicast)
    except Exception:
        return False

def _scan_kind(flags: int) -> Optional[str]:
    # NULL: no flags
    if flags == 0:
        return "null_scan"
    # FIN only
    if flags & FIN and not (flags & (SYN | ACK | PSH | URG)):
        return "fin_scan"
    # Xmas: FIN + PSH + URG (y sin ACK)
    if (flags & FIN) and (flags & PSH) and (flags & URG) and not (flags & ACK):
        return "xmas_scan"
    # SYN (sin ACK) típico de -sS
    if (flags & SYN) and not (flags & ACK):
        return "syn_scan"
    return None

def _ts_iso(ts: float) -> str:
    return datetime.fromtimestamp(ts).isoformat(timespec="seconds")

def analyze_pcap(path: str, time_window_s: int = 60, top_k: int = 20) -> Tuple[Dict[str, Any], Optional[Dict[str, Any]]]:
    """
    Recorre el PCAP (streaming) y produce:
      - overview dict
      - first_event dict (o None)
    """
    total_pkts = 0
    t_first: Optional[float] = None
    t_last: Optional[float] = None

    # Acumuladores por fuente (scanner)
    src_stats = defaultdict(lambda: {
        "pkts": 0,
        "ports": set(),
        "targets": set(),
        "flag_stats": Counter(),
        "first_t": None
    })
    port_dist = Counter()
    patterns_seen = set()
    first_event: Optional[Dict[str, Any]] = None

    with PcapReader(path) as pr:
        for pkt in pr:
            total_pkts += 1
            ts = float(getattr(pkt, "time", 0.0))
            if t_first is None:
                t_first = ts
            t_last = ts

            ip_src = None
            ip_dst = None
            if IP in pkt:
                ip_src = pkt[IP].src
                ip_dst = pkt[IP].dst
            elif IPv6 in pkt:
                ip_src = pkt[IPv6].src
                ip_dst = pkt[IPv6].dst
            else:
                continue  # no IP

            if TCP not in pkt:
                continue
            tcp = pkt[TCP]
            dport = int(tcp.dport)
            flags = int(tcp.flags)

            kind = _scan_kind(flags)
            if not kind:
                continue

            # Guardar primer evento global
            if first_event is None:
                first_event = {
                    "t_first": _ts_iso(ts),
                    "scanner": ip_src,
                    "pattern": kind,
                    "target": ip_dst,
                    "port": dport,
                    "detail": f"TCP flags={flags}"
                }
            patterns_seen.add(kind)

            # Actualizar stats del scanner
            st = src_stats[ip_src]
            st["pkts"] += 1
            st["ports"].add(dport)
            st["targets"].add(ip_dst)
            # flag stats simplificado
            st["flag_stats"].update({
                "SYN": 1 if (flags & SYN) else 0,
                "FIN": 1 if (flags & FIN) else 0,
                "PSH": 1 if (flags & PSH) else 0,
                "URG": 1 if (flags & URG) else 0,
                "RST": 1 if (flags & 0x04) else 0,
                "ACK": 1 if (flags & ACK) else 0,
            })
            if st["first_t"] is None:
                st["first_t"] = ts

            port_dist.update([dport])

    interval_s = 0 if (t_first is None or t_last is None) else int(t_last - t_first)

    # Construir overview
    # ranking básico por "fuerza de sospecha": pkts + puertos + targets
    ranking = sorted(
        [
            {
                "ip": ip,
                "pkts": st["pkts"],
                "distinct_ports": len(st["ports"]),
                "distinct_hosts": len(st["targets"]),
                "flag_stats": dict(st["flag_stats"]),
                "first_t": _ts_iso(st["first_t"]) if st["first_t"] else None,
                "pattern": _dominant_pattern(st["flag_stats"])
            }
            for ip, st in src_stats.items()
        ],
        key=lambda x: (x["distinct_ports"] + x["distinct_hosts"], x["pkts"]),
        reverse=True
    )

    overview = {
        "total_pkts": total_pkts,
        "interval_s": interval_s,
        "scanners": ranking[:top_k],
        "targets": _targets_top(src_stats, top_k),
        "port_distribution": [{"port": p, "hits": c} for p, c in port_dist.most_common(top_k)],
        "suspected_patterns": sorted(patterns_seen),
        "generated_at": _ts_iso(datetime.now().timestamp())
    }
    return overview, first_event

def _dominant_pattern(flag_stats: Counter) -> str:
    syn = flag_stats.get("SYN", 0)
    fin = flag_stats.get("FIN", 0)
    psh = flag_stats.get("PSH", 0)
    urg = flag_stats.get("URG", 0)
    # heurística simple
    if syn >= max(fin, psh, urg):
        return "syn_scan"
    if fin > syn and fin >= max(psh, urg):
        return "fin_scan"
    if psh > 0 and urg > 0 and fin > 0:
        return "xmas_scan"
    return "null_or_mixed"

def _targets_top(src_stats, top_k: int):
    targets_counter = Counter()
    for st in src_stats.values():
        targets_counter.update(st["targets"])
    return [{"ip": ip, "hits": hits} for ip, hits in targets_counter.most_common(top_k)]
