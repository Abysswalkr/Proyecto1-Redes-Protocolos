# app/cli.py
# Mini-host MCP por STDIO (JSON-RPC 2.0) robusto para Windows.
# - No usa SDK.
# - No llama "initialize" (arranca con "tools/list").
# - Filtra ruido hasta hallar "Content-Length:" limpio.
# Ejecuta:  python -m app.cli

import os, sys, json, shlex, subprocess, time
from pathlib import Path
from typing import Any, Dict, List, Optional

# ------------ Config ------------
try:
    from dotenv import load_dotenv  # opcional
    load_dotenv()
except Exception:
    pass

ROOT_DIR = Path(__file__).resolve().parents[1]
DEFAULT_PCAP_DIR = ROOT_DIR / "captures"

TOKEN: str = os.getenv("PORT_HUNTER_TOKEN", "MiTOKENultraSecreto123")
PCAP_DIR: Path = Path(os.getenv("PORT_HUNTER_ALLOWED_DIR", str(DEFAULT_PCAP_DIR))).resolve()

ENV_BASE: Dict[str, str] = {
    "PORT_HUNTER_TOKEN": TOKEN,
    "PORT_HUNTER_ALLOWED_DIR": str(PCAP_DIR),
    "PORT_HUNTER_ALLOW_PRIVATE": os.getenv("PORT_HUNTER_ALLOW_PRIVATE", "false"),
    "PORT_HUNTER_CACHE_DIR": os.getenv("PORT_HUNTER_CACHE_DIR", ".cache/porthunter"),
    "OTX_API_KEY": os.getenv("OTX_API_KEY", ""),
    "GREYNOISE_API_KEY": os.getenv("GREYNOISE_API_KEY", ""),
    "GEOLITE2_CITY_DB": os.getenv("GEOLITE2_CITY_DB") or os.getenv("GEOIP_DB_PATH", ""),
    "PYTHONUNBUFFERED": "1",  # 🔧 fuerza flush en server
}

PY_EXE = sys.executable
SERVER_CMD = [PY_EXE, "-m", "porthunter.stdio_server"]

# ------------ Framing (LSP-like) ------------
def _write_msg(fout, payload: Dict[str, Any]) -> None:
    body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    headers = (
        f"Content-Length: {len(body)}\r\n"
        f"Content-Type: application/json; charset=utf-8\r\n"
        f"\r\n"
    ).encode("ascii")
    fout.write(headers)
    fout.write(body)
    fout.flush()

def _read_until_header(fin, deadline: float) -> Optional[int]:
    """
    Lee byte a byte descartando ruido hasta encontrar un bloque de headers con Content-Length válido.
    Devuelve el content-length, o None si vence el tiempo.
    """
    line = b""
    headers: Dict[str, str] = {}
    while time.time() < deadline:
        bch = fin.read(1)
        if not bch:
            time.sleep(0.005)
            continue
        line += bch
        # terminación de línea
        if line.endswith(b"\r\n"):
            s = line.decode("utf-8", "replace").strip("\r\n")
            line = b""
            if s == "":
                # fin de headers
                cl = headers.get("content-length")
                if cl and cl.isdigit() and int(cl) >= 0:
                    return int(cl)
                # si no había Content-Length, reset y seguimos filtrando
                headers = {}
                continue
            # parse header si tiene ':'
            if ":" in s:
                k, v = s.split(":", 1)
                headers[k.strip().lower()] = v.strip()
            else:
                # ruido no-header → ignorar y seguimos leyendo
                headers = {}
    return None

def _read_body(fin, nbytes: int, deadline: float) -> Optional[bytes]:
    buf = b""
    while len(buf) < nbytes and time.time() < deadline:
        chunk = fin.read(nbytes - len(buf))
        if not chunk:
            time.sleep(0.005); continue
        buf += chunk
    return buf if len(buf) == nbytes else None

def _rpc_once(method: str, params: Optional[Dict[str, Any]] = None, timeout: float = 20.0) -> Any:
    """
    Lanza el server, hace la llamada JSON-RPC indicada y devuelve el 'result'.
    Filtra cualquier salida extraña hasta ver un header válido.
    Cierra el proceso al terminar.
    """
    env = os.environ.copy()
    env.update(ENV_BASE)
    proc = subprocess.Popen(
        SERVER_CMD,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=None,      # deja stderr visible en la consola para tracebacks del server
        env=env,
        bufsize=0,        # I/O sin buffer (Windows)
    )
    try:
        if not proc.stdin or not proc.stdout:
            raise RuntimeError("No se pudieron abrir los pipes de STDIO.")

        # Enviamos el request (sin initialize)
        req_id = 1
        req = {"jsonrpc": "2.0", "id": req_id, "method": method}
        if params:
            req["params"] = params
        _write_msg(proc.stdin, req)

        deadline = time.time() + timeout
        # 1) buscar headers (saltando ruido)
        clen = _read_until_header(proc.stdout, deadline)
        if clen is None:
            raise RuntimeError("Timeout esperando headers MCP (¿el server imprimió algo por stdout?).")

        # 2) leer body
        body = _read_body(proc.stdout, clen, deadline)
        if body is None:
            raise RuntimeError("Timeout leyendo body MCP.")
        try:
            resp = json.loads(body.decode("utf-8"))
        except Exception:
            raise RuntimeError("Body no es JSON válido (framing roto).")

        # 3) validar respuesta
        if resp.get("id") != req_id:
            # si respondió algo previo (p.ej. a un request interno), intenta leer otro mensaje
            clen2 = _read_until_header(proc.stdout, deadline)
            if clen2 is None:
                raise RuntimeError("No llegó respuesta al id esperado.")
            body2 = _read_body(proc.stdout, clen2, deadline)
            if body2 is None:
                raise RuntimeError("Timeout leyendo body (2do mensaje).")
            resp = json.loads(body2.decode("utf-8"))

        if "error" in resp and resp["error"]:
            raise RuntimeError(f"RPC error: {resp['error']}")
        return resp.get("result")

    finally:
        try:
            proc.terminate()
        except Exception:
            pass
        try:
            proc.wait(timeout=2)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass

# ------------ API de alto nivel ------------
def list_tools_names() -> List[str]:
    res = _rpc_once("tools/list", {})
    tools = res.get("tools") if isinstance(res, dict) else res
    names: List[str] = []
    if isinstance(tools, list):
        for t in tools:
            if isinstance(t, dict) and t.get("name"):
                names.append(t["name"])
    return names

def call_tool(name: str, arguments: Dict[str, Any]) -> Any:
    tools = list_tools_names()
    if name not in tools:
        raise RuntimeError(f"La tool '{name}' no está publicada. Tools: {sorted(tools)}")
    res = _rpc_once("tools/call", {"name": name, "arguments": arguments})
    content = res.get("content") if isinstance(res, dict) else None
    if isinstance(content, list):
        for part in content:
            if isinstance(part, dict) and part.get("type") == "json":
                return part.get("data")
            if isinstance(part, dict) and part.get("type") == "text":
                txt = part.get("text", "")
                try:
                    return json.loads(txt)
                except Exception:
                    return txt
    return res

# ------------ Helpers CLI ------------
def abs_pcap_path(arg_path: str) -> str:
    p = Path(arg_path)
    if not p.is_absolute():
        p = (PCAP_DIR / p).resolve()
    return str(p)

def pretty_print(obj: Any) -> None:
    print("\n--- Respuesta ---")
    try:
        print(json.dumps(obj, indent=2, ensure_ascii=False))
    except Exception:
        print(obj)
    print()

def print_banner() -> None:
    print("MCP Chatbot – PortHunter (STDIO, JSON-RPC síncrono)")
    print("Directorio de PCAP permitido:", PCAP_DIR)
    print()
    print("Comandos disponibles:")
    print("  /ph-tools                    (listar tools del server)")
    print("  /ph-info")
    print("  /ph-overview <archivo.pcap|pcapng>")
    print("  /ph-first <archivo.pcap|pcapng>")
    print("  /ph-suspects <archivo.pcap|pcapng>")
    print("  /ph-enrich <ip>")
    print("  /ph-correlate <ip1,ip2,...>")
    print("  /help")
    print("  /exit")
    print()

# ------------ Comandos ------------
def cmd_ph_tools() -> None:
    pretty_print({"tools": list_tools_names()})

def cmd_ph_info() -> None:
    pretty_print(call_tool("get_info", {"auth_token": TOKEN}))

def cmd_ph_overview(path_arg: str) -> None:
    path = abs_pcap_path(path_arg)
    pretty_print(call_tool("scan_overview", {"path": path, "auth_token": TOKEN}))

def cmd_ph_first(path_arg: str) -> None:
    path = abs_pcap_path(path_arg)
    pretty_print(call_tool("first_scan_event", {"path": path, "auth_token": TOKEN}))

def cmd_ph_suspects(path_arg: str) -> None:
    path = abs_pcap_path(path_arg)
    pretty_print(call_tool("list_suspects", {"path": path, "auth_token": TOKEN}))

def cmd_ph_enrich(ip: str) -> None:
    pretty_print(call_tool("enrich_ip", {"ip": ip, "auth_token": TOKEN}))

def cmd_ph_correlate(ips_csv: str) -> None:
    ips = [s.strip() for s in ips_csv.split(",") if s.strip()]
    pretty_print(call_tool("correlate", {"ips": ips, "auth_token": TOKEN}))

# ------------ Loop ------------
def repl() -> None:
    print_banner()
    while True:
        try:
            line = input(">>> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not line:
            continue
        if line.lower() in {"/exit", "exit", "quit"}:
            break
        if line.lower() in {"/help", "help", "?"}:
            print_banner(); continue

        parts = shlex.split(line)
        cmd = parts[0].lower()
        try:
            if cmd == "/ph-tools":       cmd_ph_tools()
            elif cmd == "/ph-info":      cmd_ph_info()
            elif cmd == "/ph-overview":  cmd_ph_overview(parts[1])
            elif cmd == "/ph-first":     cmd_ph_first(parts[1])
            elif cmd == "/ph-suspects":  cmd_ph_suspects(parts[1])
            elif cmd == "/ph-enrich":    cmd_ph_enrich(parts[1])
            elif cmd == "/ph-correlate": cmd_ph_correlate(parts[1])
            else:
                print("Comando no reconocido. Escribe /help.\n")
        except IndexError:
            print("Faltan argumentos. Escribe /help.\n")
        except Exception as e:
            print(f"Error: {e}\n")

def main() -> None:
    if not PCAP_DIR.exists():
        print(f"[Aviso] La carpeta de PCAP permitida no existe: {PCAP_DIR}", file=sys.stderr)
        print("Cámbiala con PORT_HUNTER_ALLOWED_DIR en .env.\n", file=sys.stderr)
    repl()

if __name__ == "__main__":
    main()
