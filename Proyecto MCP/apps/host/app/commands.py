# apps/host/app/commands.py
"""
Orquestador de un único turno (--once/REPL) y despacho a MCP o chat.
Exporta:
  - build_router(debug: bool=True)
  - run_once(cmd: str, mcp) -> dict (async)

Incluye:
  - 'analiza' (resumen/--json/--detallado/--top N)
  - 'sospechosos' (imprime pattern, scores y flag_stats)
  - 'primer_evento', 'reporte'
  - Macro: 'analiza_y_repo <pcap> <repo>'
  - Trivia MCP remoto (NL y comandos)
  - NL: “analiza ... readme ... repo ...” → ejecuta macro
  - Fallback: cualquier otro texto → chat
"""

from __future__ import annotations
import os, shlex, glob, re, json, asyncio, inspect
from datetime import datetime, timezone
from typing import Any, Dict, Optional, List, Tuple
from .chat.commands_chat import cmd_chat  # imprime respuestas directamente


# ---------- Router mínimo (compat con main.py) ----------
class _DummyRouter:
    def __init__(self, debug: bool = False) -> None:
        self.debug = debug
    def names(self) -> list[str]:
        return [
            # PortHunter
            "analiza", "sospechosos", "primer_evento", "reporte", "analiza_y_repo",
            # Trivia
            "trivia",
            # Misc
            "chat", "help", "ayuda", "exit", "salir",
        ]

def build_router(*, debug: bool = True) -> _DummyRouter:
    if debug:
        print("[commands] build_router(): dummy router created (compat)")
    return _DummyRouter(debug=debug)


# ---------- Utils ----------
def _tok(cmd: str) -> list[str]:
    try:
        return shlex.split(cmd)
    except Exception:
        return cmd.strip().split()

def _get_flag(tokens: list[str], name: str, default: Optional[str] = None) -> Optional[str]:
    try:
        i = tokens.index(name);  return tokens[i + 1]
    except Exception:
        return default

def _list_pcaps_in_dir(path: str) -> List[str]:
    pats = [os.path.join(path, "*.pcap"), os.path.join(path, "*.pcapng")]
    files: List[str] = []
    for p in pats: files.extend(glob.glob(p))
    return sorted(files)

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ---------- Invocación MCP (prefiere async y evita sync en loop) ----------
async def _call_client_async_first(client: Any, server: str, tool: str, args: Dict[str, Any]) -> Any:
    if hasattr(client, "call_tool_async") and callable(getattr(client, "call_tool_async")):
        return await client.call_tool_async(server, tool, args)
    # fallback sync solo si NO estamos en un loop
    try:
        asyncio.get_running_loop(); in_loop = True
    except RuntimeError:
        in_loop = False
    if hasattr(client, "call_tool") and callable(getattr(client, "call_tool")) and not in_loop:
        return client.call_tool(server, tool, args)
    raise RuntimeError("Cliente MCP no expone call_tool_async (evito call_tool sync en loop).")

async def _mcp_call(mcp: Any, server: str, tool: str, args: Dict[str, Any]) -> Any:
    srv = getattr(mcp, server, None)
    if srv is not None:
        fn = getattr(srv, f"{tool}_async", None)
        if callable(fn):
            try: return await fn(**args)
            except TypeError: return await fn(args)
        fn = getattr(srv, tool, None)
        if callable(fn):
            try: res = fn(**args)
            except TypeError: res = fn(args)
            if inspect.isawaitable(res): return await res
            return res
        for meth in ("call_async","invoke_async","run_async","exec_async","execute_async"):
            f = getattr(srv, meth, None)
            if callable(f):
                try: return await f(tool, **args)
                except TypeError:
                    try: return await f(tool, args)
                    except Exception: pass
    for meth in ("call_async","invoke_async","run_async","exec_async","execute_async"):
        f = getattr(mcp, meth, None)
        if callable(f):
            try: return await f(server, tool, args)
            except TypeError:
                try: return await f(server, tool, **args)
                except Exception: pass
    for cname in ("client","_client","sc","stdio","stdio_client"):
        c = getattr(mcp, cname, None)
        if c is None: continue
        return await _call_client_async_first(c, server, tool, args)
    raise RuntimeError(f"No sé invocar {server}.{tool} en el objeto mcp")


# ---------- PortHunter helpers de extracción/pretty ----------
def _extract_overview_dict(reply: dict) -> dict:
    """Devuelve {totals, top_ports, timeline} priorizando 'structuredContent'."""
    if not isinstance(reply, dict): return {}
    if "structuredContent" in reply and isinstance(reply["structuredContent"], dict):
        return reply["structuredContent"]
    if "reply" in reply and isinstance(reply["reply"], dict):
        r2 = reply["reply"]
        if "structuredContent" in r2 and isinstance(r2["structuredContent"], dict):
            return r2["structuredContent"]
        return r2
    return reply

def _extract_suspects(reply: dict) -> List[Dict[str, Any]]:
    """Devuelve lista de sospechosos desde structuredContent o reply plano."""
    if not isinstance(reply, dict): return []
    sc = reply.get("structuredContent")
    if isinstance(sc, dict) and isinstance(sc.get("suspects"), list):
        return sc["suspects"]
    if isinstance(reply.get("suspects"), list):
        return reply["suspects"]
    if isinstance(reply.get("reply"), dict):
        r2 = reply["reply"]
        if isinstance(r2.get("structuredContent"), dict) and isinstance(r2["structuredContent"].get("suspects"), list):
            return r2["structuredContent"]["suspects"]
        if isinstance(r2.get("suspects"), list):
            return r2["suspects"]
    return []

def _humanize_overview(ov: dict, *, file_label: str | None = None, top_n: int = 10, full: bool = False) -> str:
    lines = []
    if file_label: lines.append(f"== {file_label} ==")
    totals = ov.get("totals", {});  total_pkts = totals.get("total_pkts");  tcp_pkts = totals.get("tcp_pkts");  udp_pkts = totals.get("udp_pkts")
    lines.append("Resumen:")
    if total_pkts is not None: lines.append(f"  • Paquetes totales: {total_pkts}")
    if tcp_pkts is not None or udp_pkts is not None: lines.append(f"  • TCP: {tcp_pkts or 0}   UDP: {udp_pkts or 0}")
    top_ports = ov.get("top_ports") or []
    if top_ports:
        lines.append("  • Puertos más activos:")
        for item in (top_ports if full else top_ports[:top_n]):
            port = item.get("port"); cnt = item.get("count"); proto = item.get("proto","?")
            pct = f"{(cnt/total_pkts*100):.1f}%" if total_pkts else None
            lines.append(f"      - {proto}/{port}: {cnt}" + (f" ({pct})" if pct else ""))
    timeline = ov.get("timeline") or []
    if timeline:
        peak = max(timeline, key=lambda x: x.get("count", 0))
        lines.append(f"  • Pico de actividad: t0={peak.get('t0')} con {peak.get('count')} paquetes")
        if full:
            spans = ", ".join(f"{p.get('t0')}:{p.get('count')}" for p in timeline[:50])
            lines.append(f"  • Timeline (primeros 50): {spans}")
    return "\n".join(lines)

def _render_readme(path: str, overview: dict, suspects: dict, first_event: dict, commands_used: list[str]) -> str:
    totals = overview.get("totals", {})
    tp = overview.get("top_ports") or []
    sus_list = (suspects.get("suspects") if isinstance(suspects, dict) else None) or []
    iso = first_event.get("iso") or first_event.get("t_first") or "n/a"
    pattern = first_event.get("pattern") or "n/a"

    lines = []
    lines.append("# PortHunter — Reporte\n")
    lines.append(f"- Fecha de reporte (UTC): { datetime.now(timezone.utc).isoformat(timespec='seconds') }\n")
    lines.append(f"- Archivo analizado: `{path}`\n")
    if totals:
        lines.append(f"- Paquetes totales: **{totals.get('total_pkts','?')}** (TCP {totals.get('tcp_pkts','?')} / UDP {totals.get('udp_pkts','?')})\n")
    if tp:
        lines.append("## Puertos más activos\n")
        for it in tp[:10]:
            lines.append(f"- {it.get('proto','?')}/{it.get('port')}: {it.get('count')}")
        lines.append("")
    lines.append("## Primer evento\n")
    lines.append(f"- ISO: {iso}\n- Patrón: {pattern}\n")
    lines.append("\n## Sospechosos\n")
    if sus_list:
        for s in sus_list:
            scanner = s.get("scanner") or s.get("src_ip","?")
            pat = s.get("pattern","?")
            v = s.get("vertical_score","?")
            h = s.get("horizontal_score","?")
            lines.append(f"- **{scanner}** → patrón {pat} | V:{v} H:{h}")
    else:
        lines.append("_Sin sospechosos con los umbrales actuales._")
    lines.append("\n---\n### Comandos utilizados\n")
    lines.extend([f"- `{c}`" for c in commands_used])
    lines.append("")
    return "\n".join(lines)


# ---------- FS/Git helpers ----------
async def _fs_mkdir(mcp: Any, path: str) -> None:
    for args in ({"path": path}, {"dir_path": path}, {"directory": path}):
        try:
            await _mcp_call(mcp, "filesystem", "create_directory", args);  return
        except Exception:
            continue
    raise RuntimeError("filesystem.create_directory falló con todas las variantes")

async def _fs_write(mcp: Any, path: str, content: str) -> None:
    variants = (
        {"path": path, "content": content},
        {"path": path, "text": content},
        {"path": path, "data": content},
    )
    for args in variants:
        try:
            await _mcp_call(mcp, "filesystem", "write_file", args);  return
        except Exception:
            continue
    raise RuntimeError("filesystem.write_file falló con todas las variantes")

async def _git_init(mcp: Any, repo: str) -> None:
    for args in ({"path": repo}, {"repository": repo}, {"repo_path": repo}):
        try:
            await _mcp_call(mcp, "git", "git_init", args);  return
        except Exception:
            continue
    raise RuntimeError("git.git_init falló con todas las variantes")

async def _git_add(mcp: Any, repo: str, paths: List[str]) -> None:
    variants = (
        {"path": repo, "paths": paths},
        {"repository": repo, "paths": paths},
        {"repo_path": repo, "files": paths},
    )
    for args in variants:
        try:
            await _mcp_call(mcp, "git", "git_add", args);  return
        except Exception:
            continue
    raise RuntimeError("git.git_add falló con todas las variantes")

async def _git_commit(mcp: Any, repo: str, message: str) -> None:
    for args in ({"path": repo, "message": message}, {"repository": repo, "message": message}):
        try:
            await _mcp_call(mcp, "git", "git_commit", args);  return
        except Exception:
            continue
    raise RuntimeError("git.git_commit falló con todas las variantes")


# ====================================================================
#                          PORT HUNTER
# ====================================================================
async def _handle_analiza(tokens: list[str], mcp: Any) -> Dict[str, Any]:
    if len(tokens) < 2:
        return {"error": "Uso: analiza <ruta.pcap|carpeta> [--json] [--detallado] [--top N]"}
    path = tokens[1]
    want_json = "--json" in tokens
    want_full = ("--detallado" in tokens) or ("--full" in tokens)
    try: top_n = int(_get_flag(tokens, "--top", "10") or "10")
    except Exception: top_n = 10

    # Directorio
    if os.path.isdir(path):
        files = _list_pcaps_in_dir(path)
        if not files:
            msg = {"mode": "scan_overview_dir", "count": 0, "results": []}
            if want_json: return msg
        total_pkts = 0; results = []
        for fp in files:
            raw = await _mcp_call(mcp, "porthunter", "scan_overview", {"path": fp})
            ov = _extract_overview_dict(raw); results.append({"path": fp, "overview": ov})
            try: total_pkts += int(ov.get("totals", {}).get("total_pkts", 0))
            except Exception: pass
            if not want_json:
                print(_humanize_overview(ov, file_label=fp, top_n=top_n, full=want_full)); print()
        if not want_json:
            print(f"Archivos analizados: {len(files)}   Paquetes totales: {total_pkts}")
            return {"mode": "scan_overview_dir", "printed": True, "count": len(files), "total_pkts": total_pkts}
        return {"mode": "scan_overview_dir", "count": len(files), "total_pkts": total_pkts, "results": results}

    # Archivo
    raw = await _mcp_call(mcp, "porthunter", "scan_overview", {"path": path})
    ov = _extract_overview_dict(raw)
    if want_json:  return {"mode": "scan_overview", "overview": ov}
    print(_humanize_overview(ov, file_label=path, top_n=top_n, full=want_full))
    return {"mode": "scan_overview", "printed": True}

async def _handle_suspechosos(tokens: list[str], mcp: Any) -> Dict[str, Any]:
    if len(tokens) < 2:
        return {"error": "Uso: sospechosos <ruta.pcap> puertos <N> tasa <PPS> [--json]"}
    path = tokens[1]; want_json = "--json" in tokens
    min_ports = int(_get_flag(tokens, "puertos", "10") or "10")
    min_rate  = float(_get_flag(tokens, "tasa", "5") or "5")
    args = {"path": path, "min_ports": min_ports, "min_rate_pps": min_rate}
    reply = await _mcp_call(mcp, "porthunter", "list_suspects", args)

    if want_json:
        return {"mode": "list_suspects", "suspects": reply}

    suspects = _extract_suspects(reply)
    if not suspects:
        print("No se detectaron sospechosos con esos umbrales.")
        return {"mode": "list_suspects", "printed": True}

    print(f"Sospechosos (min_ports={min_ports}, min_rate_pps={min_rate}):")
    for s in suspects:
        scanner = s.get("scanner") or s.get("src_ip", "?")
        pattern = s.get("pattern", "?")
        v = s.get("vertical_score", 0.0)
        h = s.get("horizontal_score", 0.0)
        ev = s.get("evidence", {}) or {}
        first_t = ev.get("first_t", "?")
        pkts = ev.get("pkts", "?")
        u_ports = ev.get("unique_ports", "?")
        u_targets = ev.get("unique_targets", "?")
        pps = ev.get("pps", "?")
        flag_stats = ev.get("flag_stats", {}) or {}

        print(f"  - {scanner}")
        print(f"      patrón: {pattern} | scores  V:{v}  H:{h}")
        print(f"      evidencia: first_t={first_t} pkts={pkts} unique_ports={u_ports} unique_targets={u_targets} pps={pps}")
        if isinstance(flag_stats, dict) and flag_stats:
            flags_fmt = ", ".join(f"{k}:{flag_stats[k]}" for k in sorted(flag_stats.keys()))
            print(f"      flags: {flags_fmt}")
        ports_list = s.get("ports") or []
        if ports_list:
            if len(ports_list) > 15:
                head = ", ".join(map(str, ports_list[:15]))
                print(f"      puertos: {head}, ... (+{len(ports_list)-15} más)")
            else:
                print(f"      puertos: {', '.join(map(str, ports_list))}")

    return {"mode": "list_suspects", "printed": True}

async def _handle_primer_evento(tokens: list[str], mcp: Any) -> Dict[str, Any]:
    if len(tokens) < 2:
        return {"error": "Uso: primer_evento <ruta.pcap>"}
    path = tokens[1]
    reply = await _mcp_call(mcp, "porthunter", "first_scan_event", {"path": path})
    body = reply.get("structuredContent") if isinstance(reply, dict) else None
    body = body if isinstance(body, dict) else (reply if isinstance(reply, dict) else {})
    print("Primer evento:")
    print(json.dumps(body, ensure_ascii=False, indent=2))
    return {"mode": "first_scan_event", "printed": True}

async def _handle_reporte(tokens: list[str], mcp: Any) -> Dict[str, Any]:
    if len(tokens) < 2:
        return {"error": "Uso: reporte <ruta.pcap>"}
    path = tokens[1]
    over_raw = await _mcp_call(mcp, "porthunter", "scan_overview", {"path": path})
    sus_raw  = await _mcp_call(mcp, "porthunter", "list_suspects", {"path": path, "min_ports": 10, "min_rate_pps": 5})
    first    = await _mcp_call(mcp, "porthunter", "first_scan_event", {"path": path})
    overview = _extract_overview_dict(over_raw)
    readme   = _render_readme(path, overview, sus_raw if isinstance(sus_raw, dict) else {}, first if isinstance(first, dict) else {}, [
        f'porthunter.scan_overview("{path}")',
        f'porthunter.list_suspects("{path}", min_ports=10, min_rate_pps=5)',
        f'porthunter.first_scan_event("{path}")'
    ])
    return {"mode": "reporte", "overview": overview, "suspects": sus_raw, "first": first, "readme": readme}

async def _handle_analiza_y_repo(path: str, repo: str, mcp: Any, *, min_ports: int = 10, min_rate_pps: float = 5.0) -> Dict[str, Any]:
    over_raw = await _mcp_call(mcp, "porthunter", "scan_overview", {"path": path})
    sus_raw  = await _mcp_call(mcp, "porthunter", "list_suspects", {"path": path, "min_ports": min_ports, "min_rate_pps": min_rate_pps})
    first    = await _mcp_call(mcp, "porthunter", "first_scan_event", {"path": path})
    overview = _extract_overview_dict(over_raw)
    readme   = _render_readme(path, overview, sus_raw if isinstance(sus_raw, dict) else {}, first if isinstance(first, dict) else {}, [
        f'porthunter.scan_overview("{path}")',
        f'porthunter.list_suspects("{path}", min_ports={min_ports}, min_rate_pps={min_rate_pps})',
        f'porthunter.first_scan_event("{path}")'
    ])

    await _fs_mkdir(mcp, repo)
    await _fs_write(mcp, os.path.join(repo, "README.md"), readme)
    await _git_init(mcp, repo)
    await _git_add(mcp, repo, ["README.md"])
    await _git_commit(mcp, repo, "chore: reporte PortHunter inicial")

    sus = _extract_suspects(sus_raw if isinstance(sus_raw, dict) else {})
    if sus:
        ports_flat = sorted({p for s in sus for p in (s.get('ports') or [])})
        print(f"[OK] README en {repo}/README.md y repo inicializado. Puertos sospechosos: {ports_flat}")
    else:
        print(f"[OK] README en {repo}/README.md y repo inicializado. (sin sospechosos)")
    return {"mode": "analiza_y_repo", "printed": True, "repo": repo}


# ====================================================================
#                              TRIVIA
# ====================================================================
# Estado mínimo de trivia (memoria de proceso)
_TRIVIA = {
    "active": False,
    "server": None,
    "question": None,
    "choices": None,        # lista de strings
    "answer_token": None,
    "letter_map": None,     # {'A': '...', 'B': '...'}
}

_TRIVIA_SERVER_CANDIDATES = ("trivia", "trivia_http", "remote_trivia", "quiz")

def _letters(n: int) -> List[str]:
    import string
    return list(string.ascii_uppercase[:max(0, n)])

def _fmt_question(q: str, choices: List[str]) -> str:
    letters = _letters(len(choices))
    lines = [f"❓ {q}", "Opciones:"]
    for L, opt in zip(letters, choices):
        lines.append(f"  {L}) {opt}")
    lines.append("Responde con:  trivia responder <letra|texto|#>  o  'responder A' / 'la respuesta es ...'")
    return "\n".join(lines)

def _extract_trivia_struct(reply: dict) -> Tuple[Optional[str], List[str], Optional[str]]:
    """Devuelve (question, choices, answer_token) tolerante a claves."""
    if not isinstance(reply, dict):
        return None, [], None
    # structuredContent → preferido
    sc = reply.get("structuredContent")
    body = sc if isinstance(sc, dict) else reply
    q = body.get("question") or body.get("q") or body.get("prompt")
    opts = body.get("choices") or body.get("options") or body.get("answers") or []
    tok = body.get("answer_token") or body.get("token") or body.get("id")
    # algunos servers envían dentro de 'content' un JSON textual; ignoramos aquí
    return q, list(opts), tok

async def _find_trivia_server(mcp: Any) -> Optional[str]:
    # 1) candidatos comunes
    for name in _TRIVIA_SERVER_CANDIDATES:
        if getattr(mcp, name, None) is not None:
            return name
    # 2) heurística: buscar atributos con tools típicos
    for attr in dir(mcp):
        if attr.startswith("_"): continue
        obj = getattr(mcp, attr, None)
        if obj is None: continue
        if any(hasattr(obj, n) for n in ("trivia_random", "trivia_check")):
            return attr
    # 3) último recurso: None
    return None

async def _trivia_new(mcp: Any) -> Dict[str, Any]:
    if _TRIVIA["server"] is None:
        _TRIVIA["server"] = await _find_trivia_server(mcp)
    if _TRIVIA["server"] is None:
        print("No encontré servidor de trivia. Verifica tu perfil 'servers' (remote HTTP) y vuelve a intentar.")
        return {"mode": "trivia", "printed": True, "error": "no-trivia-server"}

    reply = await _mcp_call(mcp, _TRIVIA["server"], "trivia_random", {})
    q, choices, token = _extract_trivia_struct(reply)
    if not q or not choices or not token:
        print("El servidor de trivia respondió en un formato inesperado.")
        return {"mode": "trivia", "printed": True, "error": "bad-payload", "raw": reply}

    letters = _letters(len(choices))
    letter_map = {L: c for L, c in zip(letters, choices)}

    _TRIVIA.update({
        "active": True,
        "question": q,
        "choices": choices,
        "answer_token": token,
        "letter_map": letter_map,
    })

    print(_fmt_question(q, choices))
    return {"mode": "trivia", "printed": True, "question": q, "choices": choices}

async def _trivia_answer(mcp: Any, user_ans: str) -> Dict[str, Any]:
    if not _TRIVIA.get("active") or not _TRIVIA.get("answer_token"):
        print("No hay una trivia activa. Escribe 'trivia' o 'trivia nueva' para obtener una pregunta.")
        return {"mode": "trivia", "printed": True, "error": "no-active"}

    token = _TRIVIA["answer_token"]
    choices = _TRIVIA.get("choices") or []
    letter_map = _TRIVIA.get("letter_map") or {}

    ans_text = None
    # casos: letra (A/B), índice (#), texto libre
    m_letter = re.match(r"^[A-Za-z]$", user_ans.strip())
    m_index  = re.match(r"^\d+$", user_ans.strip())

    if m_letter:
        L = user_ans.strip().upper()
        ans_text = letter_map.get(L)
    elif m_index:
        idx = int(user_ans.strip())
        if 1 <= idx <= len(choices):
            ans_text = choices[idx - 1]
    else:
        # texto tal cual; intentamos matchear exacto con opciones
        cand = user_ans.strip().lower()
        for opt in choices:
            if opt.lower() == cand:
                ans_text = opt
                break
        if ans_text is None:
            # como fallback, pasamos el texto al server
            ans_text = user_ans.strip()

    # Intentamos ambas firmas: answer_text y answer_index (si coincide)
    payloads = []
    payloads.append({"answer_token": token, "answer_text": ans_text})
    if m_index:
        payloads.append({"answer_token": token, "answer_index": int(user_ans)})

    reply = None
    err = None
    for pl in payloads:
        try:
            reply = await _mcp_call(mcp, _TRIVIA["server"], "trivia_check", pl)
            err = None
            break
        except Exception as e:
            err = e
            continue

    if err is not None and reply is None:
        print(f"No pude verificar la respuesta ({err}).")
        return {"mode": "trivia", "printed": True, "error": "check-failed"}

    # Interpretar resultado
    body = reply.get("structuredContent") if isinstance(reply, dict) else None
    body = body if isinstance(body, dict) else (reply if isinstance(reply, dict) else {})
    correct = body.get("correct") or body.get("is_correct") or body.get("ok") or False
    correct_ans = body.get("correct_answer") or body.get("answer") or None
    explanation = body.get("explanation") or body.get("why") or None

    if correct:
        print("✅ ¡Correcto!")
    else:
        print("❌ Incorrecto.")
        if correct_ans:
            print(f"Respuesta correcta: {correct_ans}")
    if explanation:
        print(f"Nota: {explanation}")

    # cerramos la ronda
    _TRIVIA["active"] = False
    return {"mode": "trivia", "printed": True, "correct": bool(correct), "answer": correct_ans}


# ---------- NL intents ----------
# PortHunter macro (ya existía)
_NL_PATH_RE   = re.compile(r"""analiza\s+("?)([^"\s]+\.pcap(?:ng)?)\1""", re.I)
_NL_REPO_RE   = re.compile(r"""repo(?:sitorio)?(?:\s+con\s+el\s+nombre)?\s+("?)([^"\s]+)\1""", re.I)
_NL_PORTS_RE  = re.compile(r"""puertos?\s+(\d{1,3})""", re.I)
_NL_RATE_RE   = re.compile(r"""tasa\s+(\d+(\.\d+)?)""", re.I)

def _nl_extract_macro(text: str) -> Optional[Tuple[str, str, int, float]]:
    if "analiza" not in text.lower(): return None
    if "readme" not in text.lower():  return None
    if "repo" not in text.lower():    return None
    m_path = _NL_PATH_RE.search(text);  m_repo = _NL_REPO_RE.search(text)
    if not (m_path and m_repo): return None
    path = m_path.group(2);  repo = m_repo.group(2)
    m_ports = _NL_PORTS_RE.search(text);  m_rate = _NL_RATE_RE.search(text)
    min_ports = int(m_ports.group(1)) if m_ports else 10
    min_rate  = float(m_rate.group(1)) if m_rate else 5.0
    return (path, repo, min_ports, min_rate)

# Trivia NL
_TRIVIA_START_RE = re.compile(r"""(jugar\s+trivia|trivia|pregunta\s+de\s+trivia|otra|siguiente|next)""", re.I)
_TRIVIA_ANSWER_RE = re.compile(r"""^(?:trivia\s+responder|responder|mi\s+respuesta\s+es|la\s+respuesta\s+es|opci[oó]n|letra)\s+(.+)$""", re.I)

def _nl_is_trivia_start(text: str) -> bool:
    return bool(_TRIVIA_START_RE.search(text))

def _nl_extract_trivia_answer(text: str) -> Optional[str]:
    m = _TRIVIA_ANSWER_RE.search(text.strip())
    if m:
        return m.group(1).strip()
    # aceptar “A/B/C/D” solos si hay una trivia activa
    if _TRIVIA.get("active") and re.match(r"^[A-Za-z]$", text.strip()):
        return text.strip()
    return None


# ---------- Punto de entrada ----------
async def run_once(cmd: str, mcp: Any) -> Dict[str, Any]:
    tokens = _tok(cmd)
    if not tokens:  return {"ok": True, "msg": "comando vacío"}

    # 0) INTENTS NL
    # 0.a) PortHunter macro NL
    nl = _nl_extract_macro(cmd)
    if nl:
        path, repo, mp, mr = nl
        return await _handle_analiza_y_repo(path, repo, mcp, min_ports=mp, min_rate_pps=mr)

    # 0.b) Trivia NL (start / next)
    if _nl_is_trivia_start(cmd):
        return await _trivia_new(mcp)

    # 0.c) Trivia NL (answer)
    ans = _nl_extract_trivia_answer(cmd)
    if ans is not None:
        return await _trivia_answer(mcp, ans)

    # 1) Comandos explícitos
    op = tokens[0].lower()

    # 1.a) Chat explícito
    if op == "chat":
        # Permitir “chat responder A …” y “chat jugar trivia …”
        inner_text = " ".join(tokens[1:]) if len(tokens) > 1 else ""
        if _nl_is_trivia_start(inner_text):
            return await _trivia_new(mcp)
        ans2 = _nl_extract_trivia_answer(inner_text)
        if ans2 is not None:
            return await _trivia_answer(mcp, ans2)
        await cmd_chat(tokens[1:])
        return {"mode": "chat", "printed": True}

    # 1.b) Macro explícita PortHunter
    if op == "analiza_y_repo":
        if len(tokens) < 3:
            return {"error": "Uso: analiza_y_repo <ruta.pcap> <ruta_repo> [puertos <N>] [tasa <PPS>]"}
        path, repo = tokens[1], tokens[2]
        mp = int(_get_flag(tokens, "puertos", "10") or "10")
        mr = float(_get_flag(tokens, "tasa", "5") or "5")
        return await _handle_analiza_y_repo(path, repo, mcp, min_ports=mp, min_rate_pps=mr)

    # 1.c) PortHunter clásicos
    if op == "analiza":        return await _handle_analiza(tokens, mcp)
    if op == "sospechosos":    return await _handle_suspechosos(tokens, mcp)
    if op == "primer_evento":  return await _handle_primer_evento(tokens, mcp)
    if op == "reporte":        return await _handle_reporte(tokens, mcp)

    # 1.d) Trivia explícitos
    if op == "trivia":
        # 'trivia' o 'trivia nueva'
        if len(tokens) == 1 or tokens[1].lower() in {"nueva", "pregunta", "jugar"}:
            return await _trivia_new(mcp)
        # 'trivia responder <...>'
        if tokens[1].lower() == "responder" and len(tokens) >= 3:
            return await _trivia_answer(mcp, " ".join(tokens[2:]))
        return {"error": "Uso: 'trivia' | 'trivia nueva' | 'trivia responder <A|texto|#>'"}

    if op in {"help", "ayuda"}:
        return {"mode": "help", "printed": True}

    # 2) Fallback: cualquier otra cosa → chat
    await cmd_chat([cmd])
    return {"mode": "chat", "printed": True}
