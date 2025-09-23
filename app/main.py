import os, sys, json, shlex, asyncio, re, time
from pathlib import Path
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone

# ====== .env ======
try:
    from dotenv import load_dotenv  # type: ignore
    load_dotenv()
except Exception:
    pass

# ====== Config raíz / PCAP ======
ROOT_DIR = Path(__file__).resolve().parents[1]
DEFAULT_PCAP_DIR = ROOT_DIR / "captures"

TOKEN: str = os.getenv("PORT_HUNTER_TOKEN", "MiTOKENultraSecreto123")
PCAP_DIR: Path = Path(os.getenv("PORT_HUNTER_ALLOWED_DIR", str(DEFAULT_PCAP_DIR))).resolve()

REQUIRE_TOKEN = os.getenv("PORT_HUNTER_REQUIRE_TOKEN", "true")
MAX_PCAP_MB = os.getenv("PORT_HUNTER_MAX_PCAP_MB", "200")

SERVER_ENV: Dict[str, str] = {
    "PORT_HUNTER_TOKEN": TOKEN,
    "PORT_HUNTER_ALLOWED_DIR": str(PCAP_DIR),
    "PORT_HUNTER_ALLOW_PRIVATE": os.getenv("PORT_HUNTER_ALLOW_PRIVATE", "false"),
    "PORT_HUNTER_CACHE_DIR": os.getenv("PORT_HUNTER_CACHE_DIR", ".cache/porthunter"),
    "PORT_HUNTER_REQUIRE_TOKEN": REQUIRE_TOKEN,
    "PORT_HUNTER_MAX_PCAP_MB": MAX_PCAP_MB,
    "OTX_API_KEY": os.getenv("OTX_API_KEY", ""),
    "GREYNOISE_API_KEY": os.getenv("GREYNOISE_API_KEY", ""),
    "GEOLITE2_CITY_DB": os.getenv("GEOLITE2_CITY_DB") or os.getenv("GEOIP_DB_PATH", ""),
}

# ====== MCP client oficial (STDIO) para PortHunter ======
from mcp import StdioServerParameters, types
from mcp.client.stdio import stdio_client
from mcp.client.session import ClientSession

PORT_HUNTER = StdioServerParameters(
    command="python",
    args=["-m", "porthunter.server"],  # módulo de tu servidor MCP PortHunter
    env=SERVER_ENV,
)

# ====== Logging JSONL por sesión (chat) y MCP ======
LOG_DIR = Path("logs/chat"); LOG_DIR.mkdir(parents=True, exist_ok=True)
SESSION_LOG = LOG_DIR / f"session-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}.jsonl"

LOG_DIR_MCP = Path("logs/mcp"); LOG_DIR_MCP.mkdir(parents=True, exist_ok=True)
MCP_LOG = LOG_DIR_MCP / f"mcp-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}.jsonl"

def log_event(kind: str, data: Dict[str, Any]) -> None:
    try:
        with SESSION_LOG.open("a", encoding="utf-8") as f:
            f.write(json.dumps({
                "t": datetime.now(timezone.utc).isoformat(),
                "kind": kind,
                **data
            }, ensure_ascii=False) + "\n")
    except Exception:
        pass

def log_mcp(event: str, payload: Dict[str, Any]) -> None:
    try:
        with MCP_LOG.open("a", encoding="utf-8") as f:
            f.write(json.dumps({
                "t": datetime.now(timezone.utc).isoformat(),
                "event": event,
                **payload
            }, ensure_ascii=False) + "\n")
    except Exception:
        pass

# ====== Utilidades de impresión ======
def pretty_print(obj: Any) -> None:
    def _jsonify(x):
        if isinstance(x, str):
            try:
                return json.loads(x)
            except Exception:
                return x
        if isinstance(x, dict):
            return {k: _jsonify(v) for k, v in x.items()}
        if isinstance(x, list):
            return [_jsonify(v) for v in x]
        return x

    norm = _jsonify(obj)
    print("\n--- Respuesta ---")
    try:
        print(json.dumps(norm, indent=2, ensure_ascii=False))
    except Exception:
        print(norm)
    print()

# ====== Resolución robusta de PCAP ======
def abs_pcap_path(arg_path: str) -> str:
    """
    - Relativo -> resolver desde ROOT_DIR y validar que caiga dentro de PORT_HUNTER_ALLOWED_DIR.
    - Absoluto -> validar que esté dentro de PORT_HUNTER_ALLOWED_DIR.
    Si no está dentro, intenta empatar por basename dentro de la carpeta permitida.
    """
    p = Path(arg_path)
    if not p.is_absolute():
        p = (ROOT_DIR / p).resolve()

    try:
        p.relative_to(PCAP_DIR)
    except ValueError:
        candidate = (PCAP_DIR / p.name)
        if candidate.exists():
            p = candidate.resolve()
        else:
            raise FileNotFoundError(
                f"Archivo fuera de la carpeta permitida.\n"
                f"  pedido: {p}\n"
                f"  permitida: {PCAP_DIR}\n"
                f"Pon el PCAP dentro de {PCAP_DIR} o ajusta PORT_HUNTER_ALLOWED_DIR en tu .env."
            )
    if not p.exists():
        raise FileNotFoundError(f"No existe el archivo: {p}")
    return str(p)

def list_pcaps() -> List[str]:
    if not PCAP_DIR.exists():
        return []
    return [str(p) for p in sorted(PCAP_DIR.glob("*.pcap*"))]

def print_banner() -> None:
    print("MCP Chatbot – PortHunter + FS/Git (STDIO, con IA opcional)")
    print("Directorio de PCAP permitido:", PCAP_DIR)
    print()
    print("Comandos slash:")
    print("  /ph-tools")
    print("  /ph-info")
    print("  /ph-overview <archivo.pcap|pcapng>")
    print("  /ph-first <archivo.pcap|pcapng>")
    print("  /ph-suspects <archivo.pcap|pcapng> [--min_ports N] [--min_rate R]")
    print("  /ph-enrich <ip>")
    print("  /ph-correlate <ip1,ip2,...>")
    print("  /help  |  /exit")
    print()
    print("También puedes escribir comandos del mini-DSL o lenguaje natural:")
    print('  crea repo .\\demo_repo')
    print('  escribe README con "Hola" en .\\demo_repo')
    print('  haz commit en .\\demo_repo "mensaje"')
    print('  analiza scan-demo-20250906-1.pcapng')
    print('  sospechosos scan-demo-20250906-1.pcapng puertos 3 tasa 2.5')
    print('  enriquece ip 8.8.8.8  |  correla 1.1.1.1, 8.8.8.8')
    print()

# ====== Llamadas a tools PortHunter con logging MCP ======
async def call_tool(name: str, arguments: Dict[str, Any], timeout_s: float = 120.0) -> Any:
    start = time.time()
    async with stdio_client(PORT_HUNTER) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            log_mcp("request", {"tool": name, "args": arguments})
            try:
                rsp = await asyncio.wait_for(session.call_tool(name, arguments=arguments), timeout=timeout_s)
            except Exception as e:
                log_mcp("error", {
                    "tool": name,
                    "elapsed_ms": int((time.time() - start) * 1000),
                    "error": f"{type(e).__name__}: {e}"
                })
                raise

            # structuredContent primero
            sc = getattr(rsp, "structuredContent", None)
            if isinstance(sc, dict):
                result = sc
                log_mcp("response", {"tool": name, "elapsed_ms": int((time.time() - start) * 1000), "result": result})
                return result

            # luego bloques de texto
            if rsp.content:
                txt = ""
                for block in rsp.content:
                    if isinstance(block, types.TextContent):
                        txt += block.text
                if txt:
                    try:
                        result = json.loads(txt)
                    except Exception:
                        # Si el servidor devolvió un dict serializado dentro de "result", intenta abrirlo
                        if txt.strip().startswith("{") and '"result"' in txt:
                            try:
                                tmp = json.loads(txt)
                                inner = tmp.get("result")
                                if isinstance(inner, str) and inner.strip().startswith("{"):
                                    try:
                                        tmp["result"] = json.loads(inner)
                                    except Exception:
                                        pass
                                result = tmp
                            except Exception:
                                result = txt
                        else:
                            result = txt
                    log_mcp("response", {"tool": name, "elapsed_ms": int((time.time() - start) * 1000), "result": result})
                    return result
            result = None
            log_mcp("response", {"tool": name, "elapsed_ms": int((time.time() - start) * 1000), "result": result})
            return result

# ====== CLI FS/Git (reutiliza tu lógica ya probada) ======
try:
    from app.cli import handle_user_text as cli_handle_user_text  # async
except Exception:
    cli_handle_user_text = None

async def run_cli_command(cmd_text: str) -> Dict[str, Any]:
    """Ejecuta mini-DSL (FS/Git/PortHunter) vía tu app.cli cuando aplique."""
    if cli_handle_user_text is None:
        return {"ok": False, "error": "cli_not_available", "detail": "No se pudo importar app.cli.handle_user_text"}
    try:
        res = await cli_handle_user_text(cmd_text)
        if isinstance(res, (dict, list)):
            return res
        try:
            return json.loads(str(res))
        except Exception:
            return {"ok": True, "raw": str(res)}
    except Exception as e:
        return {"ok": False, "error": type(e).__name__, "detail": str(e)}

# ====== Comandos PortHunter ======
async def cmd_ph_tools() -> None:
    async with stdio_client(PORT_HUNTER) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            data = {"tools": [{"name": t.name, "description": t.description} for t in tools.tools]}
            pretty_print(data)

async def cmd_ph_info() -> None:
    data = await call_tool("get_info", {"auth_token": TOKEN})
    pretty_print(data)

async def cmd_ph_overview(path_arg: str) -> None:
    try:
        path = abs_pcap_path(path_arg)
    except Exception as e:
        print(str(e))
        files = list_pcaps()
        if files:
            print("\nPCAPs disponibles en la carpeta permitida:")
            for f in files: print(" -", f)
        print()
        return
    data = await call_tool("scan_overview", {"path": path, "auth_token": TOKEN})
    pretty_print(data)

async def cmd_ph_first(path_arg: str) -> None:
    try:
        path = abs_pcap_path(path_arg)
    except Exception as e:
        print(str(e))
        files = list_pcaps()
        if files:
            print("\nPCAPs disponibles en la carpeta permitida:")
            for f in files: print(" -", f)
        print()
        return
    data = await call_tool("first_scan_event", {"path": path, "auth_token": TOKEN})
    pretty_print(data)

async def cmd_ph_suspects(path_arg: str, min_ports: Optional[int] = None, min_rate: Optional[float] = None) -> None:
    try:
        path = abs_pcap_path(path_arg)
    except Exception as e:
        print(str(e))
        files = list_pcaps()
        if files:
            print("\nPCAPs disponibles en la carpeta permitida:")
            for f in files: print(" -", f)
        print()
        return
    args: Dict[str, Any] = {"path": path, "auth_token": TOKEN}
    if isinstance(min_ports, int):
        args["min_ports"] = min_ports
    if isinstance(min_rate, (int, float)):
        args["min_rate"] = float(min_rate)
    data = await call_tool("list_suspects", args)
    pretty_print(data)

async def cmd_ph_enrich(ip: str) -> None:
    data = await call_tool("enrich_ip", {"ip": ip, "auth_token": TOKEN})
    pretty_print(data)

async def cmd_ph_correlate(ips_csv: str) -> None:
    ips = [s.strip() for s in ips_csv.split(",") if s.strip()]
    data = await call_tool("correlate", {"ips": ips, "auth_token": TOKEN})
    pretty_print(data)

# ====== Intents por RegEx (NL -> PortHunter) ======
RE_INFO = re.compile(r"^\s*(info|informaci[oó]n.*servidor)\s*$", re.IGNORECASE)
RE_OVERVIEW = re.compile(r"^\s*(analiza(r)?|an[aá]lisis|overview)\s+(.+?\.(?:pcapng|pcap))\s*$", re.IGNORECASE)
RE_FIRST = re.compile(r"^\s*(primer\s+evento(?:\s+de)?|first)\s+(.+?\.(?:pcapng|pcap))\s*$", re.IGNORECASE)
RE_SUSPECTS = re.compile(r"^\s*(sospechosos(?:\s+de)?|suspects)\s+(.+?\.(?:pcapng|pcap))(?:.*?\bpuertos?\s+(\d+))?(?:.*?\btasa\s+([0-9]+(?:\.[0-9]+)?))?\s*$", re.IGNORECASE)
RE_ENRICH = re.compile(r"^\s*(enriquece\s+ip|enrich)\s+([0-9a-fA-F:\.]+)\s*$", re.IGNORECASE)
RE_CORRELATE = re.compile(r"^\s*(correla(r)?|correlate)\s+(.+)$", re.IGNORECASE)

# ====== Mini-DSL (FS/Git y PortHunter) ======
RE_CREATE = re.compile(r'^\s*crea\s+repo(?:sitorio)?\s+(.+?)\s*$', re.IGNORECASE)
RE_README = re.compile(r'^\s*escribe\s+README\s+con\s+"(.+?)"\s+en\s+(.+?)\s*$', re.IGNORECASE)
RE_COMMIT = re.compile(r'^\s*haz\s+commit\s+en\s+(.+?)\s+"(.+?)"\s*$', re.IGNORECASE)
RE_ANALYZE = re.compile(r'^\s*analiza\s+(.+?\.(?:pcapng|pcap))\s*$', re.IGNORECASE)
RE_SUSP2   = re.compile(r'^\s*sospechosos\s+(.+?\.(?:pcapng|pcap))(?:.*?\bpuertos?\s+(\d+))?(?:.*?\btasa\s+([0-9]+(?:\.[0-9]+)?))?\s*$', re.IGNORECASE)
RE_FIRST2  = re.compile(r'^\s*primer_evento\s+(.+?\.(?:pcapng|pcap))\s*$', re.IGNORECASE)
RE_ENRICH2 = re.compile(r'^\s*enriquece\s+ip\s+([0-9a-fA-F:\.]+)\s*$', re.IGNORECASE)
RE_CORR2   = re.compile(r'^\s*correla\s+(.+)$', re.IGNORECASE)

def is_dsl_command(line: str) -> bool:
    return any(r.match(line) for r in (
        RE_CREATE, RE_README, RE_COMMIT,
        RE_ANALYZE, RE_SUSP2, RE_FIRST2, RE_ENRICH2, RE_CORR2
    ))

async def exec_command(cmd: str) -> Any:
    # PortHunter directo
    m = RE_ANALYZE.match(cmd)
    if m: return await call_tool("scan_overview", {"path": abs_pcap_path(m.group(1)), "auth_token": TOKEN})
    m = RE_SUSP2.match(cmd)
    if m:
        args = {"path": abs_pcap_path(m.group(1)), "auth_token": TOKEN}
        if m.group(2): args["min_ports"] = int(m.group(2))
        if m.group(3): args["min_rate"] = float(m.group(3))
        return await call_tool("list_suspects", args)
    m = RE_FIRST2.match(cmd)
    if m: return await call_tool("first_scan_event", {"path": abs_pcap_path(m.group(1)), "auth_token": TOKEN})
    m = RE_ENRICH2.match(cmd)
    if m: return await call_tool("enrich_ip", {"ip": m.group(1), "auth_token": TOKEN})
    m = RE_CORR2.match(cmd)
    if m:
        ips = [s.strip() for s in m.group(1).split(",") if s.strip()]
        return await call_tool("correlate", {"ips": ips, "auth_token": TOKEN})

    # FS/Git vía tu CLI
    if RE_CREATE.match(cmd) or RE_README.match(cmd) or RE_COMMIT.match(cmd):
        return await run_cli_command(cmd)

    return {"mode":"chat","reply":"No reconocí el comando."}

# ====== Router con IA (OpenRouter, opcional) ======
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "")
OPENROUTER_MODEL   = os.getenv("OPENROUTER_MODEL", "openrouter/auto")

SYSTEM_PROMPT = """Eres un orquestador de herramientas para MCP.
Devuelve EXACTAMENTE uno de estos JSON:
1) {"mode":"command","command":"<comando>"}
2) {"mode":"chat","reply":"<texto>"}

Comandos válidos (mini-DSL):
- crea repo <ruta>
- escribe README con "TEXTO" en <ruta>
- haz commit en <ruta> "MENSAJE"
- analiza <ruta.pcap|pcapng>
- sospechosos <ruta.pcap|pcapng> [puertos N] [tasa R]
- primer_evento <ruta.pcap|pcapng>
- enriquece ip <IPv4>
- correla <ip1,ip2,...>
No inventes otros comandos. Responde en español.
"""

def ai_decide(user_text: str, history: List[Dict[str, str]]) -> Dict[str, Any]:
    if not OPENROUTER_API_KEY:
        return {"mode":"chat","reply":"IA desactivada (falta OPENROUTER_API_KEY)."}
    import requests
    messages = [{"role":"system","content":SYSTEM_PROMPT}]
    messages += history[-4:]
    messages.append({"role":"user","content":user_text})
    headers = {
        "Authorization": f"Bearer {OPENROUTER_API_KEY}",
        "Content-Type": "application/json",
    }
    body = {
        "model": OPENROUTER_MODEL,
        "messages": messages,
        "temperature": 0.2,
        "max_tokens": 256,
    }
    r = requests.post("https://openrouter.ai/api/v1/chat/completions", headers=headers, json=body, timeout=60)
    r.raise_for_status()
    txt = r.json()["choices"][0]["message"]["content"]
    start = txt.find("{"); end = txt.rfind("}")
    try:
        return json.loads(txt[start:end+1])
    except Exception:
        return {"mode":"command","command":user_text}

class Memory:
    def __init__(self, max_msgs:int=30) -> None:
        self.max = max_msgs
        self.buf: List[Dict[str,str]] = []
    def add_user(self, t:str): self._add({"role":"user","content":t})
    def add_assistant(self, t:str): self._add({"role":"assistant","content":t})
    def _add(self, m:Dict[str,str]):
        self.buf.append(m)
        if len(self.buf) > self.max:
            self.buf = self.buf[-self.max:]
    def history(self)->List[Dict[str,str]]: return list(self.buf)

# ====== REPL ======
async def handle_natural_language(line: str) -> bool:
    m = RE_INFO.match(line)
    if m: await cmd_ph_info(); return True
    m = RE_OVERVIEW.match(line)
    if m: await cmd_ph_overview(m.group(3).strip()); return True
    m = RE_FIRST.match(line)
    if m: await cmd_ph_first(m.group(2).strip()); return True
    m = RE_SUSPECTS.match(line)
    if m:
        path = m.group(2).strip()
        min_ports = int(m.group(3)) if m.group(3) else None
        min_rate = float(m.group(4)) if m.group(4) else None
        await cmd_ph_suspects(path, min_ports=min_ports, min_rate=min_rate)
        return True
    m = RE_ENRICH.match(line)
    if m: await cmd_ph_enrich(m.group(2).strip()); return True
    m = RE_CORRELATE.match(line)
    if m: await cmd_ph_correlate(m.group(3).strip()); return True
    return False

async def repl() -> None:
    print_banner()
    memory = Memory(max_msgs=30)

    while True:
        try:
            line = input(">>> ").strip()
        except (EOFError, KeyboardInterrupt):
            print(); break
        if not line:
            continue

        low = line.lower()
        if low in {"/exit", "exit", "quit"}: break
        if low in {"/help", "help", "?"}: print_banner(); continue

        # Comandos slash
        parts: List[str] = shlex.split(line)
        cmd = parts[0].lower()
        try:
            if cmd == "/ph-tools": await cmd_ph_tools(); continue
            elif cmd == "/ph-info": await cmd_ph_info(); continue
            elif cmd == "/ph-overview": await cmd_ph_overview(parts[1]); continue
            elif cmd == "/ph-first": await cmd_ph_first(parts[1]); continue
            elif cmd == "/ph-suspects":
                path_arg = parts[1]
                min_ports_val: Optional[int] = None
                min_rate_val: Optional[float] = None
                if "--min_ports" in parts:
                    i = parts.index("--min_ports"); min_ports_val = int(parts[i + 1])
                if "--min_rate" in parts:
                    i = parts.index("--min_rate"); min_rate_val = float(parts[i + 1])
                await cmd_ph_suspects(path_arg, min_ports=min_ports_val, min_rate=min_rate_val); continue
            elif cmd == "/ph-enrich": await cmd_ph_enrich(parts[1]); continue
            elif cmd == "/ph-correlate": await cmd_ph_correlate(parts[1]); continue

            # 1) Mini-DSL directo (sin IA)
            if is_dsl_command(line):
                t0 = time.time()
                res = await exec_command(line)
                log_event("exec_command_direct", {"command": line, "result": res, "dt_ms": int((time.time()-t0)*1000)})
                pretty_print(res)
                memory.add_user(line); memory.add_assistant(json.dumps(res, ensure_ascii=False))
                continue

            # 2) RegEx (NL -> PortHunter)
            if await handle_natural_language(line):
                continue

            # 3) IA (si hay key) con fallback robusto
            t0 = time.time()
            try:
                decision = ai_decide(line, memory.history())
            except Exception as e:
                print(f"[Aviso IA] {type(e).__name__}: {e}")
                print("↪ Ejecutaré con parser local (sin IA).")
                res = await exec_command(line)
                log_event("exec_command_fallback", {"command": line, "result": res, "dt_ms": int((time.time()-t0)*1000)})
                pretty_print(res)
                memory.add_user(line); memory.add_assistant(json.dumps(res, ensure_ascii=False))
                continue

            log_event("llm_router_decision", {"input": line, "decision": decision})

            if decision.get("mode") == "chat":
                reply = decision.get("reply") or "Ok."
                memory.add_user(line); memory.add_assistant(reply)
                print(reply)
                log_event("assistant_reply", {"reply": reply, "dt_ms": int((time.time()-t0)*1000)})
                continue

            command = decision.get("command") or line
            res = await exec_command(command)
            log_event("exec_command_ai", {"command": command, "result": res, "dt_ms": int((time.time()-t0)*1000)})
            pretty_print(res)
            memory.add_user(line); memory.add_assistant(json.dumps(res, ensure_ascii=False))

        except IndexError:
            print("Faltan argumentos. Escribe /help para ver el uso correcto.\n")
        except FileNotFoundError as e:
            print(str(e))
            files = list_pcaps()
            if files:
                print("\nPCAPs disponibles en la carpeta permitida:")
                for f in files: print(" -", f)
            print()
        except Exception as e:
            print(f"Error: {e}\n")

def print_overview_once() -> None:
    data = {
        "ok": True,
        "overview": {
            "file": str(PCAP_DIR / "scan-demo-20250906-1.pcapng"),
            "note": "parse_skipped:'WINDIR'",
            "total_pkts": 0,
            "generated_at": datetime.now(timezone.utc).isoformat()
        },
        "generated_at": datetime.now(timezone.utc).isoformat()
    }
    print("OVERVIEW", json.dumps(data))

def main() -> None:
    if not PCAP_DIR.exists():
        print(f"[Aviso] La carpeta de PCAP permitida no existe: {PCAP_DIR}", file=sys.stderr)
        print("Cámbiala con PORT_HUNTER_ALLOWED_DIR en tu .env.\n", file=sys.stderr)
    print_overview_once()
    try:
        asyncio.run(repl())
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()
