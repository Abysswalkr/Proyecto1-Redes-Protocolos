# app/cli.py
# CLI para tu chatbot + cliente MCP que llama al servidor PortHunter por STDIO.
# Autodetección del server: módulo instalado o script por ruta en server/porthunter_mcp/porthunter/.
# Carga .env y añade auth_token automáticamente si existe PORT_HUNTER_TOKEN.

import os
import sys
import argparse
import asyncio
import json
import shlex
from pathlib import Path
from contextlib import AsyncExitStack
from datetime import datetime, UTC
import importlib.util

# --- NUEVO: carga variables del .env si existe
try:
    from dotenv import load_dotenv  # pip install python-dotenv
    load_dotenv()
except Exception:
    pass

# --- SDK MCP (cliente por STDIO)
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.shared.exceptions import McpError

# ============ LOG ============
LOG_PATH = Path("logs/mcp_interactions.jsonl")
LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

def _log_event(kind: str, payload: dict):
    try:
        with LOG_PATH.open("a", encoding="utf-8") as f:
            f.write(json.dumps({
                "t": datetime.now(UTC).isoformat(),
                "kind": kind,
                **payload
            }, ensure_ascii=False) + "\n")
    except Exception:
        pass

# ============ RESOLUCIÓN DEL SERVIDOR ============
CANDIDATE_MODULES = [
    "porthunter.stdio_server",
    "porthunter.server",
    "server.porthunter_mcp.porthunter.stdio_server",
    "server.porthunter_mcp.porthunter.server",
]

def _find_importable_module() -> str | None:
    for mod in CANDIDATE_MODULES:
        if importlib.util.find_spec(mod):
            return mod
    return None

def _find_script_path() -> Path | None:
    repo_root = Path(__file__).resolve().parents[1]  # .../Proyecto1-Redes-Protocolos
    candidates = [
        repo_root / "server" / "porthunter_mcp" / "porthunter" / "stdio_server.py",
        repo_root / "server" / "porthunter_mcp" / "porthunter" / "server.py",
    ]
    for p in candidates:
        if p.exists():
            return p
    return None

def _resolve_server_command() -> tuple[str, list[str]]:
    env_cmd = os.getenv("PORTHUNTER_CMD")
    env_args = os.getenv("PORTHUNTER_ARGS")
    if env_cmd:
        cmd = env_cmd
        args = shlex.split(env_args) if env_args else []
        return cmd, args

    mod = _find_importable_module()
    if mod:
        return sys.executable, ["-m", mod]

    script = _find_script_path()
    if script:
        return sys.executable, [str(script)]

    raise RuntimeError(
        "No encuentro el servidor PortHunter MCP.\n"
        "Opciones:\n"
        "  1) Instalar paquete:\n"
        "       cd server/porthunter_mcp\n"
        "       pip install -e .\n"
        "  2) Forzar por variables de entorno:\n"
        "       set PORTHUNTER_CMD=python\n"
        "       set PORTHUNTER_ARGS=server\\porthunter_mcp\\porthunter\\stdio_server.py\n"
    )

# ============ UTILIDADES ============
def _ensure_pcap_path(pcap: str) -> str:
    p = Path(pcap).expanduser().resolve()
    if not p.exists():
        raise FileNotFoundError(f"No encuentro el PCAP: {p}")
    return str(p)

# ============ CLIENTE MCP ============
async def _call_porthunter_tool(tool_name: str, args: dict) -> dict:
    """
    Abre una sesión MCP via STDIO, lista herramientas y ejecuta la solicitada.
    Inyecta auth_token si existe PORT_HUNTER_TOKEN.
    """
    cmd, cmd_args = _resolve_server_command()

    # --- NUEVO: añade el token al payload si existe
    token = os.getenv("PORT_HUNTER_TOKEN")
    if token and "auth_token" not in args:
        args = {**args, "auth_token": token}

    _log_event("connect_attempt", {
        "server_command": cmd,
        "server_args": cmd_args
    })

    # Pasamos todo el entorno actual (incluido PORT_HUNTER_TOKEN) al proceso hijo
    server_params = StdioServerParameters(
        command=cmd,
        args=cmd_args,
        env={"PYTHONUNBUFFERED": "1", **os.environ},
    )

    async with AsyncExitStack() as stack:
        read, write = await stack.enter_async_context(stdio_client(server_params))
        session = await stack.enter_async_context(ClientSession(read, write))

        try:
            await session.initialize()
        except McpError as e:
            _log_event("initialize_error", {"error": str(e)})
            raise RuntimeError(
                "No se pudo inicializar la sesión MCP (Connection closed?).\n"
                "Verifica ejecutando manualmente el server:\n"
                f"    {cmd} {' '.join(cmd_args)}\n"
                "Debe quedarse esperando (sin traza de error)."
            ) from e

        tools_resp = await session.list_tools()
        available = {t.name: t for t in tools_resp.tools}

        if tool_name not in available:
            _log_event("tool_missing", {"requested": tool_name, "available": list(available.keys())})
            raise RuntimeError(
                f"La herramienta '{tool_name}' no existe. Disponibles: {', '.join(available.keys()) or '(ninguna)'}"
            )

        _log_event("tool_call", {"tool": tool_name, "args": args})
        result = await session.call_tool(tool_name, args)

        payload = None
        try:
            if isinstance(result.content, list) and result.content and getattr(result.content[0], "type", None) == "text":
                payload = json.loads(result.content[0].text)
            elif getattr(result, "structured_content", None):
                payload = result.structured_content  # por si tu lib lo expone así
        except Exception:
            payload = None

        if payload is None:
            payload = {
                "raw": [
                    {"type": getattr(c, "type", "unknown"),
                     "text": getattr(c, "text", None),
                     "data": getattr(c, "data", None)}
                    for c in (result.content or [])
                ]
            }

        _log_event("tool_result", {"tool": tool_name, "result_sample": str(payload)[:1000]})
        return payload

# ============ INTENTS ============
def _parse_intent(user_text: str):
    text = user_text.strip()

    if text.lower().startswith("analiza "):
        path = text[8:].strip().strip('"')
        return {
            "action": "scan_overview",
            "args": {
                "path": _ensure_pcap_path(path),
                "time_window_s": 60,
                "top_k": 20
            }
        }

    if text.lower().startswith("sospechosos "):
        path = text[len("sospechosos "):].strip().strip('"')
        return {
            "action": "list_suspects",
            "args": {
                "path": _ensure_pcap_path(path),
                "min_ports": 10,
                "min_rate_pps": 5
            }
        }

    if text.lower().startswith("primer_evento "):
        path = text[len("primer_evento "):].strip().strip('"')
        return {
            "action": "first_scan_event",
            "args": {
                "path": _ensure_pcap_path(path)
            }
        }

    if text.lower().endswith(".pcap") or text.lower().endswith(".pcapng"):
        return {
            "action": "scan_overview",
            "args": {
                "path": _ensure_pcap_path(text),
                "time_window_s": 60,
                "top_k": 20
            }
        }

    raise ValueError(
        "No entendí el comando. Usa:\n"
        "  analiza <ruta.pcap>\n"
        "  sospechosos <ruta.pcap>\n"
        "  primer_evento <ruta.pcap>\n"
    )

async def handle_user_text(user_text: str) -> str:
    intent = _parse_intent(user_text)
    data = await _call_porthunter_tool(intent["action"], intent["args"])
    return json.dumps(data, ensure_ascii=False, indent=2)

async def _once(text: str):
    out = await handle_user_text(text)
    print(out)

def main():
    parser = argparse.ArgumentParser(description="Chatbot de consola + cliente MCP para PortHunter")
    parser.add_argument("--once", type=str, help='Ejecuta una sola consulta, p.ej.: --once "analiza .\\tiny.pcap"')
    args = parser.parse_args()

    if args.once:
        asyncio.run(_once(args.once))
    else:
        print("MCP Chat (escribe 'salir' para terminar)")
        try:
            while True:
                q = input("> ").strip()
                if q.lower() in ("salir", "exit", "quit"):
                    break
                if not q:
                    continue
                asyncio.run(_once(q))
        except (KeyboardInterrupt, EOFError):
            pass

if __name__ == "__main__":
    main()
