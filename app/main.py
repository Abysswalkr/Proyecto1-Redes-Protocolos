import os
import sys
import json
import shlex
import asyncio
import re
import asyncio
from app.intent_router import route_message
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from dotenv import load_dotenv  # type: ignore
    load_dotenv()
except Exception:
    pass

# ===================== Config =====================

ROOT_DIR = Path(__file__).resolve().parents[1]  # carpeta raíz del repo
DEFAULT_PCAP_DIR = ROOT_DIR / "captures"

TOKEN: str = os.getenv("PORT_HUNTER_TOKEN", "MiTOKENultraSecreto123")
PCAP_DIR: Path = Path(os.getenv("PORT_HUNTER_ALLOWED_DIR", str(DEFAULT_PCAP_DIR))).resolve()

# Límites/seguridad adicionales para el server MCP (se propagan por env)
REQUIRE_TOKEN = os.getenv("PORT_HUNTER_REQUIRE_TOKEN", "true")
MAX_PCAP_MB = os.getenv("PORT_HUNTER_MAX_PCAP_MB", "200")

# Variables que se inyectarán al proceso del servidor MCP
SERVER_ENV: Dict[str, str] = {
    "PORT_HUNTER_TOKEN": TOKEN,
    "PORT_HUNTER_ALLOWED_DIR": str(PCAP_DIR),
    "PORT_HUNTER_ALLOW_PRIVATE": os.getenv("PORT_HUNTER_ALLOW_PRIVATE", "false"),
    "PORT_HUNTER_CACHE_DIR": os.getenv("PORT_HUNTER_CACHE_DIR", ".cache/porthunter"),
    "PORT_HUNTER_REQUIRE_TOKEN": REQUIRE_TOKEN,
    "PORT_HUNTER_MAX_PCAP_MB": MAX_PCAP_MB,
    "OTX_API_KEY": os.getenv("OTX_API_KEY", ""),
    "GREYNOISE_API_KEY": os.getenv("GREYNOISE_API_KEY", ""),
    # Acepta ambos nombres para mayor compatibilidad:
    "GEOLITE2_CITY_DB": os.getenv("GEOLITE2_CITY_DB") or os.getenv("GEOIP_DB_PATH", ""),
}

# ===================== Cliente MCP (STDIO) =====================
# Usa SIEMPRE el SDK oficial `mcp`, no tu paquete `mcp_local`.

from mcp import StdioServerParameters, types
from mcp.client.stdio import stdio_client
from mcp.client.session import ClientSession

PORT_HUNTER = StdioServerParameters(
    command="python",
    args=["-m", "porthunter.server"],
    env=SERVER_ENV,
)

async def call_tool(name: str, arguments: Dict[str, Any], timeout_s: float = 120.0) -> Any:
    """
    Abre una sesión STDIO con el server MCP, llama una tool y devuelve el JSON si viene
    en structuredContent; si no, devuelve el texto concatenado.
    """
    async with stdio_client(PORT_HUNTER) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            rsp = await asyncio.wait_for(
                session.call_tool(name, arguments=arguments),
                timeout=timeout_s,
            )

            # 1) Si el SDK nos dio structuredContent (lo usual para "json"), úsalo.
            sc = getattr(rsp, "structuredContent", None)
            if isinstance(sc, dict):
                return sc

            # 2) Si vino en bloques de texto, concatenamos.
            if rsp.content:
                txt = ""
                for block in rsp.content:
                    if isinstance(block, types.TextContent):
                        txt += block.text
                if txt:
                    try:
                        return json.loads(txt)
                    except Exception:
                        return txt

            return None

async def handle_user_message(text: str):
    kind, data = await route_message(text)
    # Aquí formatea la salida (tarjeta/tabla). Por ahora imprime crudo:
    print(kind.upper(), data)

# ===================== Helpers =====================

def abs_pcap_path(arg_path: str) -> str:
    """Convierte una ruta a absoluta; si viene relativa, resuelve contra PCAP_DIR."""
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
    print("  /ph-suspects <archivo.pcap|pcapng> [--min_ports N] [--min_rate R]")
    print("  /ph-enrich <ip>")
    print("  /ph-correlate <ip1,ip2,...>")
    print("  /help")
    print("  /exit")
    print()
    print("También puedes escribir en lenguaje natural, por ejemplo:")
    print("  info")
    print("  analiza scan-demo-20250906-1.pcapng")
    print("  primer evento de scan-demo-20250906-1.pcapng")
    print("  sospechosos de scan-demo-20250906-1.pcapng puertos 3 tasa 2.5")
    print("  enriquece ip 8.8.8.8")
    print("  correla 1.1.1.1, 8.8.8.8, 192.168.0.1")
    print()

# ===================== Comandos (slash) =====================

async def cmd_ph_tools() -> None:
    # list_tools no requiere token
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
    path = abs_pcap_path(path_arg)
    data = await call_tool("scan_overview", {"path": path, "auth_token": TOKEN})
    pretty_print(data)

async def cmd_ph_first(path_arg: str) -> None:
    path = abs_pcap_path(path_arg)
    data = await call_tool("first_scan_event", {"path": path, "auth_token": TOKEN})
    pretty_print(data)

async def cmd_ph_suspects(path_arg: str, min_ports: Optional[int] = None, min_rate: Optional[float] = None) -> None:
    path = abs_pcap_path(path_arg)
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

# ===================== Intents NL → Tools =====================

RE_INFO = re.compile(r"^\s*(info|informaci[oó]n.*servidor)\s*$", re.IGNORECASE)
RE_OVERVIEW = re.compile(r"^\s*(analiza(r)?|an[aá]lisis|overview)\s+(.+?\.(?:pcapng|pcap))\s*$", re.IGNORECASE)
RE_FIRST = re.compile(r"^\s*(primer\s+evento(?:\s+de)?|first)\s+(.+?\.(?:pcapng|pcap))\s*$", re.IGNORECASE)
RE_SUSPECTS = re.compile(r"^\s*(sospechosos(?:\s+de)?|suspects)\s+(.+?\.(?:pcapng|pcap))(?:.*?\bpuertos?\s+(\d+))?(?:.*?\btasa\s+([0-9]+(?:\.[0-9]+)?))?\s*$", re.IGNORECASE)
RE_ENRICH = re.compile(r"^\s*(enriquece\s+ip|enrich)\s+([0-9a-fA-F:\.]+)\s*$", re.IGNORECASE)
RE_CORRELATE = re.compile(r"^\s*(correla(r)?|correlate)\s+(.+)$", re.IGNORECASE)

async def handle_natural_language(line: str) -> bool:
    m = RE_INFO.match(line)
    if m:
        await cmd_ph_info(); return True

    m = RE_OVERVIEW.match(line)
    if m:
        await cmd_ph_overview(m.group(3).strip()); return True

    m = RE_FIRST.match(line)
    if m:
        await cmd_ph_first(m.group(2).strip()); return True

    m = RE_SUSPECTS.match(line)
    if m:
        path = m.group(2).strip()
        min_ports = int(m.group(3)) if m.group(3) else None
        min_rate = float(m.group(4)) if m.group(4) else None
        await cmd_ph_suspects(path, min_ports=min_ports, min_rate=min_rate)
        return True

    m = RE_ENRICH.match(line)
    if m:
        await cmd_ph_enrich(m.group(2).strip()); return True

    m = RE_CORRELATE.match(line)
    if m:
        await cmd_ph_correlate(m.group(3).strip()); return True

    return False

# ===================== Loop interactivo =====================

async def repl() -> None:
    print_banner()
    while True:
        try:
            line = input(">>> ").strip()
        except (EOFError, KeyboardInterrupt):
            print(); break
        if not line:
            continue

        low = line.lower()
        if low in {"/exit", "exit", "quit"}:
            break
        if low in {"/help", "help", "?"}:
            print_banner(); continue

        parts: List[str] = shlex.split(line)
        cmd = parts[0].lower()

        try:
            if cmd == "/ph-tools":
                await cmd_ph_tools(); continue
            elif cmd == "/ph-info":
                await cmd_ph_info(); continue
            elif cmd == "/ph-overview":
                await cmd_ph_overview(parts[1]); continue
            elif cmd == "/ph-first":
                await cmd_ph_first(parts[1]); continue
            elif cmd == "/ph-suspects":
                path_arg = parts[1]
                min_ports_val: Optional[int] = None
                min_rate_val: Optional[float] = None
                if "--min_ports" in parts:
                    i = parts.index("--min_ports"); min_ports_val = int(parts[i + 1])
                if "--min_rate" in parts:
                    i = parts.index("--min_rate"); min_rate_val = float(parts[i + 1])
                await cmd_ph_suspects(path_arg, min_ports=min_ports_val, min_rate=min_rate_val); continue
            elif cmd == "/ph-enrich":
                await cmd_ph_enrich(parts[1]); continue
            elif cmd == "/ph-correlate":
                await cmd_ph_correlate(parts[1]); continue

            handled = await handle_natural_language(line)
            if not handled:
                print("Comando no reconocido. Escribe /help para ver opciones.\n")
        except IndexError:
            print("Faltan argumentos. Escribe /help para ver el uso correcto.\n")
        except Exception as e:
            print(f"Error: {e}\n")

def main() -> None:
    if not PCAP_DIR.exists():
        print(f"[Aviso] La carpeta de PCAP permitida no existe: {PCAP_DIR}", file=sys.stderr)
        print("Cámbiala con PORT_HUNTER_ALLOWED_DIR en tu .env.\n", file=sys.stderr)
    try:
        asyncio.run(repl())
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    asyncio.run(handle_user_message("analiza captures\\scan-demo-20250906-1.pcapng"))
    main()
