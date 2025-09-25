# apps/host/app/main.py
# propósito: REPL/--once con menú/banner, chat por defecto y salida JSON condicional
import argparse, json, anyio
from dotenv import load_dotenv
from .mcp.stdio_client import StdioClient
from .mcp.routers import Routers
from .commands import run_once, build_router

router = build_router(debug=True)
load_dotenv()  # Carga .env si existe en la raíz


def print_banner() -> None:
    print("""
============================================================
   Host MCP — Proyecto1-Redes-Protocolos (REPL)
   Comandos:
     analiza <ruta.pcap>
     sospechosos <ruta.pcap> puertos <N> tasa <PPS>
     primer_evento <ruta.pcap>

     chat <texto>        (o escribe texto libre: va al chat por defecto)
     chat show
     chat reset

   Ayuda: 'ayuda' / 'help' / 'salir'
============================================================
""".strip())


async def async_main():
    p = argparse.ArgumentParser()
    p.add_argument("--servers", required=True)
    p.add_argument("--once")
    args = p.parse_args()

    sc = StdioClient(args.servers)
    await sc.start_async()
    try:
        mcp = Routers(sc)
        print_banner()

        if args.once:
            out = await run_once(args.once.strip(), mcp)
            # Solo imprimimos JSON si el handler NO ya imprimió algo
            if not (isinstance(out, dict) and out.get("printed") is True):
                print(json.dumps(out, ensure_ascii=False))
            return

        print("Host MCP listo. Escribe comandos (exit/salir para terminar).")
        while True:
            try:
                cmd = input(">>> ").strip()
            except (EOFError, KeyboardInterrupt):
                break

            if not cmd:
                continue

            if cmd.lower() in {"exit", "salir"}:
                break

            if cmd.lower() in {"help", "ayuda"}:
                print_banner()
                continue

            out = await run_once(cmd, mcp)

            # Para chat/otros que ya imprimen en consola, no dupliques JSON
            if not (isinstance(out, dict) and out.get("printed") is True):
                print(json.dumps(out, ensure_ascii=False))
    finally:
        await sc.aclose()


if __name__ == "__main__":
    anyio.run(async_main)
