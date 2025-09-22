from typing import Dict, Any, List

def format_overview(d: Dict[str, Any]) -> str:
    if not d.get("ok"):
        return f"❌ {d.get('error','error')}"
    ov = d.get("overview", {})
    lines = [
        f"📄 File: {ov.get('file','?')}",
        f"⏱️ Interval: {ov.get('interval_s','?')} s",
        f"📦 Total pkts: {ov.get('total_pkts','?')}",
    ]
    scanners = ov.get("scanners", [])[:5]
    if scanners:
        lines.append("👀 Top scanners:")
        for s in scanners:
            lines.append(f"  - {s.get('ip')} pkts={s.get('pkts')} ports={s.get('distinct_ports')}")
    pats = ov.get("suspected_patterns", [])
    if pats:
        lines.append("🧪 Patrones: " + ", ".join(pats))
    return "\n".join(lines)

def format_first_event(d: Dict[str, Any]) -> str:
    if not d.get("ok"):
        return f"❌ {d.get('error','error')}"
    fe = d.get("first_event")
    return "⏲️ Primer evento: " + (str(fe) if fe is not None else "no encontrado")

def format_suspects(d: Dict[str, Any]) -> str:
    if not d.get("ok"):
        return f"❌ {d.get('error','error')}"
    sus = d.get("suspects", [])[:10]
    if not sus:
        return "✅ No hay sospechosos."
    lines = ["👤 Sospechosos:"]
    for x in sus:
        lines.append(f"  - {x.get('ip')} hits={x.get('pkts')} ports={x.get('distinct_ports')}")
    return "\n".join(lines)

def format_enrich(d: Dict[str, Any]) -> str:
    if not d.get("ok"):
        return f"❌ {d.get('error','error')}"
    e = d.get("enrichment", {})
    return f"ℹ️ {e}"

def format_correlate(d: Dict[str, Any]) -> str:
    if not d.get("ok"):
        return f"❌ {d.get('error','error')}"
    parts: List[str] = ["🔗 Correlaciones:"]
    for r in d.get("results", []):
        parts.append(f"  • {r}")
    return "\n".join(parts)
