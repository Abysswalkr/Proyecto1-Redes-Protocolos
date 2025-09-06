import json
import time
from datetime import datetime
from pathlib import Path

from app.config import (
    OPENROUTER_API_KEY,
    OPENROUTER_MODEL,
    APP_TITLE,
    REQUEST_TIMEOUT_SECONDS,
)
from app.llm.openrouter_client import OpenRouterClient
from app.llm.memory import ConversationMemory

from app.mcp.logger import MCPLogger
from app.mcp.fs_client import run_demo_create_repo
from app.mcp.clients import porthunter_params, call_tool


# -------------------- utilidades locales --------------------

def ensure_dir(path: str) -> None:
    Path(path).mkdir(parents=True, exist_ok=True)

def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")

def _append_chat_log(path: Path, obj: dict) -> None:
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False) + "\n")


# -------------------- app principal --------------------

def run_chat_loop() -> None:
    # Cliente LLM y memoria
    client = OpenRouterClient(
        api_key=OPENROUTER_API_KEY,
        model=OPENROUTER_MODEL,
        app_title=APP_TITLE,
        timeout_seconds=REQUEST_TIMEOUT_SECONDS,
    )
    memory = ConversationMemory(max_messages=20)

    # Logs de chat y MCP
    ensure_dir("logs/chat")
    ensure_dir("logs/mcp")
    session_id = datetime.now().strftime("%Y%m%d-%H%M%S")
    chat_log_path = Path("logs/chat") / f"session-{session_id}.jsonl"
    mcp_logger = MCPLogger(log_dir="logs/mcp")

    system_prompt = (
        "Eres un asistente útil y conciso. Responde en español y conserva el contexto de la conversación."
    )

    print("Chat iniciado. Comandos:")
    print("  /reset, /exit")
    print("  /mcp-dryrun, /mcp-log")
    print("  /mcp-demo-git [ruta]")
    print("  /porthunter-overview <ruta.pcap>")
    print("  /porthunter-first <ruta.pcap>")
    print("  /porthunter-suspects <ruta.pcap>")
    print("  /porthunter-enrich <ip>")
    print("  /porthunter-correlate <ip1,ip2,...>")
    while True:
        user_in = input(">>> ").strip()
        if not user_in:
            continue

        # ---------- Comandos locales ----------
        if user_in.lower() in ("/exit", "/salir", "salir"):
            print("Saliendo. ¡Hasta luego!")
            break

        if user_in.lower() in ("/reset", "reset"):
            memory.reset()
            print("(Contexto borrado)")
            _append_chat_log(chat_log_path, {"event": "reset", "t": _now()})
            continue

        if user_in.lower().startswith("/mcp-dryrun"):
            corr_id = mcp_logger.log_request("filesystem", "list_dir", {"path": "."})
            mcp_logger.log_response(
                correlation_id=corr_id,
                server="filesystem",
                tool="list_dir",
                status="ok",
                result={"entries": ["README.md", "app/", "logs/"]},
            )
            print("(Dry-run MCP registrado en logs/mcp)")
            continue

        if user_in.lower().startswith("/mcp-log"):
            tail = mcp_logger.tail(10)
            print("\n--- MCP LOG (últimas 10) ---")
            for line in tail:
                print(line)
            print("--- fin ---\n")
            continue

        if user_in.lower().startswith("/mcp-demo-git"):
            # /mcp-demo-git  o  /mcp-demo-git C:\ruta\repo
            parts = user_in.split(maxsplit=1)
            repo = parts[1].strip() if len(parts) > 1 else "mcp_demo_repo"
            print(f"(Ejecutando demo MCP en: {repo})")
            try:
                steps = run_demo_create_repo(repo)
                print("\n--- Demo MCP (Git + Filesystem) ---")
                for s in steps:
                    print(s)
                print("--- fin ---\n")
            except Exception as e:
                print(f"(Error en demo MCP: {e})")
            continue

        # ---- PortHunter: overview ----
        if user_in.lower().startswith("/porthunter-overview"):
            parts = user_in.split(maxsplit=1)
            if len(parts) < 2:
                print("Uso: /porthunter-overview <ruta.pcap>")
                continue
            pcap_path = parts[1].strip()
            params = porthunter_params()
            corr = mcp_logger.log_request(
                "porthunter", "scan_overview",
                {"path": pcap_path, "time_window_s": 60, "top_k": 20},
            )
            try:
                text, data = call_tool(params, "scan_overview",
                                       {"path": pcap_path, "time_window_s": 60, "top_k": 20})
                mcp_logger.log_response(corr, "porthunter", "scan_overview", "ok",
                                        result={"text": text, "data": data})
                print("\n--- PortHunter: scan_overview ---")
                print(json.dumps(data or {"text": text}, indent=2, ensure_ascii=False))
                print("--- fin ---\n")
            except Exception as e:
                mcp_logger.log_response(corr, "porthunter", "scan_overview", "error", error=str(e))
                print(f"(Error PortHunter: {e})")
            continue

        # ---- PortHunter: primer evento ----
        if user_in.lower().startswith("/porthunter-first"):
            parts = user_in.split(maxsplit=1)
            if len(parts) < 2:
                print("Uso: /porthunter-first <ruta.pcap>")
                continue
            pcap_path = parts[1].strip()
            params = porthunter_params()
            corr = mcp_logger.log_request("porthunter", "first_scan_event", {"path": pcap_path})
            try:
                text, data = call_tool(params, "first_scan_event", {"path": pcap_path})
                mcp_logger.log_response(corr, "porthunter", "first_scan_event", "ok",
                                        result={"text": text, "data": data})
                print("\n--- PortHunter: first_scan_event ---")
                print(json.dumps(data or {"text": text}, indent=2, ensure_ascii=False))
                print("--- fin ---\n")
            except Exception as e:
                mcp_logger.log_response(corr, "porthunter", "first_scan_event", "error", error=str(e))
                print(f"(Error PortHunter: {e})")
            continue

        # ---- PortHunter: sospechosos ----
        if user_in.lower().startswith("/porthunter-suspects"):
            parts = user_in.split(maxsplit=1)
            if len(parts) < 2:
                print("Uso: /porthunter-suspects <ruta.pcap>")
                continue
            pcap_path = parts[1].strip()
            params = porthunter_params()
            corr = mcp_logger.log_request(
                "porthunter", "list_suspects",
                {"path": pcap_path, "min_ports": 10, "min_rate_pps": 5},
            )
            try:
                text, data = call_tool(params, "list_suspects",
                                       {"path": pcap_path, "min_ports": 10, "min_rate_pps": 5})
                mcp_logger.log_response(corr, "porthunter", "list_suspects", "ok",
                                        result={"text": text, "data": data})
                print("\n--- PortHunter: list_suspects ---")
                print(json.dumps(data or {"text": text}, indent=2, ensure_ascii=False))
                print("--- fin ---\n")
            except Exception as e:
                mcp_logger.log_response(corr, "porthunter", "list_suspects", "error", error=str(e))
                print(f"(Error PortHunter: {e})")
            continue

        # ---- PortHunter: enrich ----
        if user_in.lower().startswith("/porthunter-enrich"):
            parts = user_in.split(maxsplit=1)
            if len(parts) < 2:
                print("Uso: /porthunter-enrich <ip>")
                continue
            ip = parts[1].strip()
            params = porthunter_params()
            corr = mcp_logger.log_request("porthunter", "enrich_ip", {"ip": ip})
            try:
                text, data = call_tool(params, "enrich_ip", {"ip": ip})
                mcp_logger.log_response(corr, "porthunter", "enrich_ip", "ok",
                                        result={"text": text, "data": data})
                print("\n--- PortHunter: enrich_ip ---")
                print(json.dumps(data or {"text": text}, indent=2, ensure_ascii=False))
                print("--- fin ---\n")
            except Exception as e:
                mcp_logger.log_response(corr, "porthunter", "enrich_ip", "error", error=str(e))
                print(f"(Error PortHunter: {e})")
            continue

        # ---- PortHunter: correlate ----
        if user_in.lower().startswith("/porthunter-correlate"):
            parts = user_in.split(maxsplit=1)
            if len(parts) < 2:
                print("Uso: /porthunter-correlate <ip1,ip2,...>")
                continue
            ips = [s.strip() for s in parts[1].split(",") if s.strip()]
            params = porthunter_params()
            corr = mcp_logger.log_request("porthunter", "correlate", {"ips": ips})
            try:
                text, data = call_tool(params, "correlate", {"ips": ips})
                mcp_logger.log_response(corr, "porthunter", "correlate", "ok",
                                        result={"text": text, "data": data})
                print("\n--- PortHunter: correlate ---")
                print(json.dumps(data or {"text": text}, indent=2, ensure_ascii=False))
                print("--- fin ---\n")
            except Exception as e:
                mcp_logger.log_response(corr, "porthunter", "correlate", "error", error=str(e))
                print(f"(Error PortHunter: {e})")
            continue

        # ---------- Flujo normal con LLM ----------
        memory.add_user(user_in)
        messages = client.build_messages(
            user_prompt=user_in,
            system_prompt=system_prompt,
            history=memory.get_history()[:-1],  # evita duplicar el último input del usuario
        )
        t0 = time.time()
        try:
            answer = client.chat(messages, temperature=0.2)
        except Exception as e:
            answer = f"(Error al llamar al LLM: {e})"
        dt_ms = int((time.time() - t0) * 1000)

        memory.add_assistant(answer)

        print("\n--- Respuesta ---")
        print(answer)
        print(f"\n({dt_ms} ms)\n")

        _append_chat_log(chat_log_path, {
            "t": _now(),
            "user": user_in,
            "assistant": answer,
            "latency_ms": dt_ms,
            "model": OPENROUTER_MODEL,
        })


if __name__ == "__main__":
    run_chat_loop()
