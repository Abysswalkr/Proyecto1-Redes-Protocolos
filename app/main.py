# app/cli.py
# CLI anfitrión (mini-host) para hablar con el servidor MCP de PortHunter por STDIO.
# Ejecuta:  python -m app.cli
# Requisitos:
#   pip install -e ./server/porthunter_mcp
#   (opcional) pip install python-dotenv

import os
import sys
import json
import shlex
import asyncio
from pathlib import Path
from typing import Any, Dict, List

# (Opcional) Cargar .env automáticamente si existe
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

# Variables que se inyectarán al proceso del servidor MCP
SERVER_ENV: Dict[str, str] = {
    "PORT_HUNTER_TOKEN": TOKEN,
    "PORT_HUNTER_ALLOWED_DIR": str(PCAP_DIR),
    "PORT_HUNTER_ALLOW_PRIVATE": os.getenv("PORT_HUNTER_ALLOW_PRIVATE", "false"),
    "PORT_HUNTER_CACHE_DIR": os.getenv("PORT_HUNTER_CACHE_DIR", ".cache/porthunter"),
    "OTX_API_KEY": os.getenv("OTX_API_KEY", ""),
    "GREYNOISE_API_KEY": os.getenv("GREYNOISE_API_KEY", ""),
    # Acepta ambos nombres para mayor compatibilidad:
    "GEOLITE2_CITY_DB": os.getenv("GEOLITE2_CITY_DB") or os.getenv("GEOIP_DB_PATH", ""),
}

# ===================== Cliente MCP (STDIO) =====================

# Compatibilidad con distintas versiones del SDK:
try:
    from mcp.client.stdio import StdioServerParameters as _StdParams  # >= algunas versiones
except ImportError:  # pragma: no cover
    from mcp.client.stdio import StdioServerParams as _StdParams      # otras versiones
try:
    from mcp.client.stdio import connect_stdio as _connect_stdio
except ImportError:  # pragma: no cover
    from mcp.client.stdio import connect as _connect_stdio

PORT_HUNTER = _StdParams(
    command="python",
    args=["-m", "porthunter.server"],
    env=SERVER_ENV,
)

async def call_tool(name: str, arguments: Dict[str, Any]) -> Any:
    """
    Abre una sesión STDIO con el server MCP, llama una tool y devuelve el primer content útil.
    Cerramos la sesión tras cada comando para simplificar la vida.
    """
    async with await _connect_stdio(PORT_HUNTER) as (client, _proc):
        rsp = await client.call_tool(name, arguments)
        if not rsp or not rsp.content:
            return None
        # Normalizamos respuesta: priorizamos JSON, luego texto
        for part in rsp.content:
            t = getattr(part, "type", None)
            if t == "json":
                return part.data
            if t == "text":
                try:
                    return json.loads(part.text)
                except Exception:
                    return part.text
        return None

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
    print("MCP Chatbot – PortHunter (STDIO)")
    print("Directorio de PCAP permitido:", PCAP_DIR)
    print()
    print("Comandos disponibles:")
    print("  /ph-info")
    print("  /ph-overview <archivo.pcap|pcapng>")
    print("  /ph-first <archivo.pcap|pcapng>")
    print("  /ph-suspects <archivo.pcap|pcapng>")
    print("  /ph-enrich <ip>")
    print("  /ph-correlate <ip1,ip2,...>")
    print("  /help")
    print("  /exit")
    print()

# ===================== Comandos =====================

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

async def cmd_ph_suspects(path_arg: str) -> None:
    path = abs_pcap_path(path_arg)
    data = await call_tool("list_suspects", {"path": path, "auth_token": TOKEN})
    pretty_print(data)

async def cmd_ph_enrich(ip: str) -> None:
    data = await call_tool("enrich_ip", {"ip": ip, "auth_token": TOKEN})
    pretty_print(data)

async def cmd_ph_correlate(ips_csv: str) -> None:
    ips = [s.strip() for s in ips_csv.split(",") if s.strip()]
    data = await call_tool("correlate", {"ips": ips, "auth_token": TOKEN})
    pretty_print(data)

# ===================== Loop interactivo =====================

async def repl() -> None:
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
            print_banner()
            continue

        parts: List[str] = shlex.split(line)
        cmd = parts[0].lower()

        try:
            if cmd == "/ph-info":
                await cmd_ph_info()
            elif cmd == "/ph-overview":
                await cmd_ph_overview(parts[1])
            elif cmd == "/ph-first":
                await cmd_ph_first(parts[1])
            elif cmd == "/ph-suspects":
                await cmd_ph_suspects(parts[1])
            elif cmd == "/ph-enrich":
                await cmd_ph_enrich(parts[1])
            elif cmd == "/ph-correlate":
                await cmd_ph_correlate(parts[1])
            else:
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
    main()
