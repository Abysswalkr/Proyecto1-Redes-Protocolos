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
from app.mcp.fs_client import run_demo_create_repo  # <-- NUEVO

def ensure_dir(path: str) -> None:
    Path(path).mkdir(parents=True, exist_ok=True)

def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")

def _append_chat_log(path: Path, obj: dict) -> None:
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False) + "\n")

def run_chat_loop() -> None:
    client = OpenRouterClient(
        api_key=OPENROUTER_API_KEY,
        model=OPENROUTER_MODEL,
        app_title=APP_TITLE,
        timeout_seconds=REQUEST_TIMEOUT_SECONDS,
    )
    memory = ConversationMemory(max_messages=20)

    ensure_dir("logs/chat")
    ensure_dir("logs/mcp")
    session_id = datetime.now().strftime("%Y%m%d-%H%M%S")
    chat_log_path = Path("logs/chat") / f"session-{session_id}.jsonl"
    mcp_logger = MCPLogger(log_dir="logs/mcp")

    system_prompt = (
        "Eres un asistente útil y conciso. Responde en español, mantén el contexto de la conversación."
    )

    print("Chat iniciado. Comandos: /reset, /exit, /mcp-dryrun, /mcp-log, /mcp-demo-git [ruta]")
    while True:
        user_in = input(">>> ").strip()
        if not user_in:
            continue

        # ---- Comandos locales ----
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
            mcp_logger.log_response(corr_id, "filesystem", "list_dir", "ok",
                                    result={"entries": ["README.md", "app/", "logs/"]})
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
            # Permite /mcp-demo-git o /mcp-demo-git C:\ruta\repo
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
        # ---- Fin comandos ----

        # Flujo normal con LLM
        memory.add_user(user_in)
        messages = client.build_messages(
            user_prompt=user_in,
            system_prompt=system_prompt,
            history=memory.get_history()[:-1],
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
