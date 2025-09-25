from __future__ import annotations

import os
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

# ========================= Dependencias MCP =========================
try:
    from fastmcp import FastMCP
except Exception as e:  # pragma: no cover
    raise RuntimeError("Falta 'fastmcp'. Instala con: pip install fastmcp scapy") from e

# ========================= Scapy =========================
# Import preciso para evitar warnings de PyCharm sobre scapy.all
try:
    from scapy.layers.inet import IP, TCP  # type: ignore
except Exception as e:  # fallback por si la distro empaqueta distinto
    from scapy.all import IP, TCP  # type: ignore

from scapy.utils import PcapReader
try:
    from scapy.utils import PcapNgReader  # scapy >= 2.5
except Exception:
    PcapNgReader = None  # se detecta en runtime

# ========================= Config / seguridad =========================
ALLOWED_DIR = os.getenv("PORT_HUNTER_ALLOWED_DIR")  # opcional (jaula de rutas)
REQUIRE_TOKEN = os.getenv("PORT_HUNTER_REQUIRE_TOKEN", "false").lower() in {"1", "true", "yes", "on"}
TOKEN = os.getenv("PORT_HUNTER_TOKEN")
SCHEMA_VERSION = "1.1.0"


def _iso(ts: float) -> str:
    """Convierte timestamp (segundos) a ISO8601 UTC con segundos."""
    return datetime.fromtimestamp(float(ts), tz=timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _ensure_allowed(path: str) -> None:
    """Restringe accesos a un directorio permitido (si se configuró)."""
    if not ALLOWED_DIR:
        return
    rp = os.path.realpath(path)
    ra = os.path.realpath(ALLOWED_DIR)
    if not rp.startswith(ra):
        raise PermissionError(f"path fuera de zona permitida: {path} (allowed={ALLOWED_DIR})")


def _check_auth(auth_token: Optional[str]) -> None:
    """Valida token si PORT_HUNTER_REQUIRE_TOKEN=true."""
    if not REQUIRE_TOKEN:
        return
    if not auth_token or auth_token != TOKEN:
        raise PermissionError("auth_token inválido o ausente (PORT_HUNTER_REQUIRE_TOKEN=true).")


# ========================= Lectura PCAP/PCAP-NG =========================
MAGIC_PCAP_LE = b"\xd4\xc3\xb2\xa1"
MAGIC_PCAP_BE = b"\xa1\xb2\xc3\xd4"
MAGIC_PCAPNG = b"\x0a\x0d\x0d\x0a"


def _open_reader(path: str):
    """Devuelve el reader correcto según magic-number (PCAP vs PCAP-NG)."""
    with open(path, "rb") as f:
        head = f.read(4)
    if head in (MAGIC_PCAP_LE, MAGIC_PCAP_BE):
        return PcapReader(path)
    if head == MAGIC_PCAPNG:
        if PcapNgReader is None:
            raise RuntimeError("El archivo es PCAP-NG: requiere scapy>=2.5 (PcapNgReader no disponible).")
        return PcapNgReader(path)
    # fallback: intentarlo con PcapReader y luego PcapNgReader por si algún wrapper recorta encabezado
    try:
        return PcapReader(path)
    except Exception:
        if PcapNgReader is not None:
            return PcapNgReader(path)
        raise ValueError("Formato de captura no soportado (ni PCAP ni PCAP-NG).")


def _iter_tcp(path: str) -> Iterable[Tuple[float, str, str, int, int]]:
    """
    Itera paquetes TCP del archivo devolviendo tuplas:
      (ts, src_ip, dst_ip, dport, flags_int)
    """
    _ensure_allowed(path)
    reader = _open_reader(path)
    try:
        for pkt in reader:
            if pkt is None:
                continue
            if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
                continue
            ip = pkt[IP]
            tcp = pkt[TCP]
            ts = float(getattr(pkt, "time", 0.0))
            yield (ts, ip.src, ip.dst, int(tcp.dport), int(tcp.flags))
    finally:
        try:
            reader.close()
        except Exception:
            pass


# ========================= Detecciones / Agregados =========================
# Bits TCP
FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
# (ECE=0x40, CWR=0x80 no se usan en la clasificación simple)


def _flag_counts(flags_list: Iterable[int]) -> Dict[str, int]:
    """Cuenta flags relevantes para clasificación de escaneos."""
    c = Counter()
    for f in flags_list:
        if f == 0:
            c["NULL"] += 1
            continue
        if (f & SYN) and not (f & ACK):
            c["SYN"] += 1
        if (f & FIN) and not (f & SYN):
            # FIN-only o Xmas (FIN+PSH+URG) → diferenciamos
            if (f & (PSH | URG)) == (PSH | URG):
                c["XMAS"] += 1
            elif (f & (PSH | URG)) == 0:
                c["FIN"] += 1
            else:
                c["FIN"] += 1  # FIN + algo que no sea Xmas
        if f & ACK:
            c["ACK"] += 1
        if f & RST:
            c["RST"] += 1
        if f & PSH:
            c["PSH"] += 1
        if f & URG:
            c["URG"] += 1
    return dict(c)


def _classify_pattern(fc: Dict[str, int]) -> str:
    """Decide patrón dominante entre syn/fin/null/xmas o 'mixed' si no hay dominancia clara."""
    syn = fc.get("SYN", 0)
    fin = fc.get("FIN", 0)
    nll = fc.get("NULL", 0)
    xms = fc.get("XMAS", 0)
    tot = max(1, sum(fc.values()))
    ratios = {
        "syn_scan": syn / tot,
        "fin_scan": fin / tot,
        "null_scan": nll / tot,
        "xmas_scan": xms / tot,
    }
    top = max(ratios.items(), key=lambda kv: kv[1])
    if top[1] >= 0.6:
        return top[0]
    if sum(1 for v in ratios.values() if v > 0.2) >= 2:
        return "mixed"
    return top[0]


def _scores_vertical_horizontal(unique_ports: int, unique_targets: int) -> Tuple[float, float]:
    """Calcula scores normalizados [0..1] para vertical vs horizontal."""
    v = float(unique_ports)
    h = float(unique_targets)
    denom = (v + h) or 1.0
    return (round(v / denom, 4), round(h / denom, 4))


def _timeline_buckets(t0: float, times: List[float], win: int) -> List[Dict[str, int]]:
    """Agrupa timestamps en buckets de tamaño 'win' (segundos) relativos a t0."""
    if not times:
        return []
    buckets = Counter(int((t - t0) // max(1, win)) for t in times)
    return [{"t0": int(k) * max(1, win), "count": int(v)} for k, v in sorted(buckets.items())]


def _top_ports(counter: Counter, top_k: int) -> List[Dict[str, Any]]:
    """Convierte Counter de puertos en lista ordenada (proto/port/count)."""
    return [{"proto": "tcp", "port": p, "count": c} for p, c in counter.most_common(top_k)]


# ========================= Servidor FastMCP =========================
mcp = FastMCP("porthunter")


@mcp.tool()
def scan_overview(
    path: str,
    time_window_s: int = 1,
    top_k: int = 10,
    auth_token: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Retorna un panorama general de la captura.
    - totals: total_pkts, tcp_pkts, udp_pkts(=0 aquí)
    - top_ports: top_k puertos destino TCP
    - timeline: buckets por ventana time_window_s (t0 relativo)
    """
    _check_auth(auth_token)
    _ensure_allowed(path)

    times: List[float] = []
    dport_counter: Counter = Counter()
    pkts_total = 0
    tcp_pkts = 0
    first_ts: Optional[float] = None

    for ts, _src, _dst, dport, _flags in _iter_tcp(path):
        pkts_total += 1
        tcp_pkts += 1
        dport_counter[dport] += 1
        times.append(ts)
        first_ts = ts if first_ts is None else min(first_ts, ts)

    t0 = first_ts or 0.0
    timeline = _timeline_buckets(t0, times, max(1, int(time_window_s)))

    structured = {
        "schema_version": SCHEMA_VERSION,
        "totals": {"total_pkts": pkts_total, "tcp_pkts": tcp_pkts, "udp_pkts": 0},
        "top_ports": _top_ports(dport_counter, top_k),
        "timeline": timeline,
    }
    return {
        "structuredContent": structured,
        "content": [{"type": "text", "text": json.dumps(structured, ensure_ascii=False)}],
    }


@mcp.tool()
def list_suspects(
    path: str,
    min_ports: int = 10,
    min_rate_pps: float = 5.0,
    min_hosts: int = 2,
    auth_token: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Lista sospechosos por scanner (src_ip) con patrón y scores H/V.
    Criterio de sospecha (cualquiera):
      - unique_ports >= min_ports  (vertical)
      - unique_targets >= min_hosts (horizontal)
    Y además pps >= min_rate_pps
    """
    _check_auth(auth_token)
    _ensure_allowed(path)

    # Agregados por scanner
    first_ts: Dict[str, float] = {}
    last_ts: Dict[str, float] = {}
    ports_by_src: Dict[str, set[int]] = defaultdict(set)      # src -> {dport}
    targets_by_src: Dict[str, set[str]] = defaultdict(set)    # src -> {dst}
    flags_by_src: Dict[str, List[int]] = defaultdict(list)    # src -> [flags]
    counts_by_src: Counter = Counter()                        # src -> pkts

    for ts, src, dst, dport, flags in _iter_tcp(path):
        counts_by_src[src] += 1
        ports_by_src[src].add(dport)
        targets_by_src[src].add(dst)
        flags_by_src[src].append(flags)
        first_ts[src] = ts if src not in first_ts else min(first_ts[src], ts)
        last_ts[src] = ts if src not in last_ts else max(last_ts[src], ts)

    suspects: List[Dict[str, Any]] = []

    for src in counts_by_src:
        pkts = counts_by_src[src]
        uniq_ports = len(ports_by_src[src])
        uniq_targets = len(targets_by_src[src])
        span = max(1e-3, (last_ts[src] - first_ts[src]))  # segundos
        pps = pkts / span

        # Umbrales básicos
        if not ((uniq_ports >= min_ports) or (uniq_targets >= min_hosts)):
            continue
        if pps < min_rate_pps:
            continue

        fc = _flag_counts(flags_by_src[src])
        pattern = _classify_pattern(fc)
        v_score, h_score = _scores_vertical_horizontal(uniq_ports, uniq_targets)

        reason_bits = []
        if uniq_ports >= min_ports:
            reason_bits.append(f"{uniq_ports} puertos destino únicos")
        if uniq_targets >= min_hosts:
            reason_bits.append(f"{uniq_targets} destinos únicos")
        reason_bits.append(f"{pps:.2f} pps")

        ports_list = sorted(list(ports_by_src[src]))[:50]

        suspects.append({
            "scanner": src,
            "src_ip": src,  # compat con host actual
            "pattern": pattern,
            "vertical_score": v_score,
            "horizontal_score": h_score,
            "ports": ports_list,
            "reason": ("vertical-hint: " if v_score >= h_score else "horizontal-hint: ") + "; ".join(reason_bits),
            "evidence": {
                "first_t": _iso(first_ts[src]),
                "pkts": pkts,
                "unique_ports": uniq_ports,
                "unique_targets": uniq_targets,
                "flag_stats": fc,
                "pps": round(pps, 3),
            }
        })

    structured = {"schema_version": SCHEMA_VERSION, "suspects": suspects}
    return {
        "structuredContent": structured,
        "content": [{"type": "text", "text": json.dumps(structured, ensure_ascii=False)}],
    }


@mcp.tool()
def first_scan_event(
    path: str,
    auth_token: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Devuelve el primer evento de escaneo observado (enriquecido):
    {
      "t_first": "2025-08-27T02:09:01Z",
      "scanner": "A.B.C.D",
      "pattern": "syn_scan|fin_scan|null_scan|xmas_scan|mixed",
      "target": "X.Y.Z.W",
      "port": 22,
      "detail": "SYN sin 3-way handshake (no ACK), puertos ascendentes",
      "pps": 123.4
    }
    """
    _check_auth(auth_token)
    _ensure_allowed(path)

    # índices por src (para patrón) y primer pkt candidato
    by_src_flags: Dict[str, List[int]] = defaultdict(list)
    first_pkt: Optional[Tuple[float, str, str, int, int]] = None  # (ts, src, dst, dport, flags)
    times_by_src: Dict[str, List[float]] = defaultdict(list)      # para pps local

    # Selección preferente: SYN sin ACK > Xmas > FIN-only > NULL > otro
    best_score_seen = -1
    for ts, src, dst, dport, flags in _iter_tcp(path):
        by_src_flags[src].append(flags)
        times_by_src[src].append(ts)

        is_syn = (flags & SYN) and not (flags & ACK)
        is_xmas = (flags & FIN) and (flags & PSH) and (flags & URG) and not (flags & SYN)
        is_fin_only = (flags & FIN) and not (flags & SYN) and not (flags & PSH) and not (flags & URG)
        is_null = (flags == 0)
        score = (4 if is_syn else 3 if is_xmas else 2 if is_fin_only else 1 if is_null else 0)

        if score > best_score_seen:
            best_score_seen = score
            first_pkt = (ts, src, dst, dport, flags)
        # si score empata, conservamos el primero visto (orden temporal)

    if first_pkt is None:
        structured = {"schema_version": SCHEMA_VERSION, "t_first": None, "detail": "sin paquetes TCP en captura"}
        return {
            "structuredContent": structured,
            "content": [{"type": "text", "text": json.dumps(structured, ensure_ascii=False)}],
        }

    ts0, src0, dst0, port0, flags0 = first_pkt
    fc0 = _flag_counts(by_src_flags[src0])
    pattern = _classify_pattern(fc0)

    # pps local de ese src
    times = sorted(times_by_src[src0])
    if times:
        span = max(1e-3, (times[-1] - times[0]))
        pps = len(times) / span
    else:
        pps = 0.0

    # detalle textual
    if (flags0 & SYN) and not (flags0 & ACK):
        detail = "SYN sin 3-way handshake (no ACK)"
    elif (flags0 & FIN) and (flags0 & PSH) and (flags0 & URG) and not (flags0 & SYN):
        detail = "Xmas (FIN+PSH+URG) sin SYN"
    elif (flags0 & FIN) and not (flags0 & SYN):
        detail = "FIN sin SYN (posible FIN scan)"
    elif flags0 == 0:
        detail = "Paquete TCP sin flags (NULL scan)"
    else:
        detail = "Heurística de escaneo no concluyente"

    structured = {
        "schema_version": SCHEMA_VERSION,
        "t_first": _iso(ts0),
        "scanner": src0,
        "pattern": pattern,
        "target": dst0,
        "port": int(port0),
        "detail": detail,
        "pps": round(pps, 3),
    }
    return {
        "structuredContent": structured,
        "content": [{"type": "text", "text": json.dumps(structured, ensure_ascii=False)}],
    }


# ========================= Entrypoint =========================
if __name__ == "__main__":
    # stdio por defecto (lo usas en tus perfiles YAML). Para HTTP:
    #   mcp.run(transport="http", host="0.0.0.0", port=8010, path="/mcp")
    mcp.run(transport="stdio")
