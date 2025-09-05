import os
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


def ensure_dir(path: str) -> None:
    Path(path).mkdir(parents=True, exist_ok=True)


def run_chat_loop() -> None:
    # Prep cliente y memoria
    client = OpenRouterClient(
        api_key=OPENROUTER_API_KEY,
        model=OPENROUTER_MODEL,
        app_title=APP_TITLE,
        timeout_seconds=REQUEST_TIMEOUT_SECONDS,
    )
    memory = ConversationMemory(max_messages=20)

    # Log de chat por sesión
    ensure_dir("logs/chat")
    session_id = datetime.now().strftime("%Y%m%d-%H%M%S")
    log_path = Path("logs/chat") / f"session-{session_id}.jsonl"

    system_prompt = (
        "Eres un asistente útil y conciso. Responde en español, mantén el contexto de la conversación."
    )

    print("Chat iniciado. Escribe tu mensaje. Comandos: /reset, /exit")
    while True:
        user_in = input(">>> ").strip()
        if not user_in:
            continue
        if user_in.lower() in ("/exit", "/salir", "salir"):
            print("Saliendo. ¡Hasta luego!")
            break
        if user_in.lower() in ("/reset", "reset"):
            memory.reset()
            print("(Contexto borrado)")
            _append_chat_log(log_path, {"event": "reset", "t": _now()})
            continue

        # Añadir turno del usuario a memoria
        memory.add_user(user_in)

        # Construir mensajes con historia
        messages = client.build_messages(
            user_prompt=user_in,
            system_prompt=system_prompt,
            history=memory.get_history()[:-1],  # history sin el último user_in duplicado
        )

        # Llamar al LLM
        t0 = time.time()
        try:
            answer = client.chat(messages, temperature=0.2)
        except Exception as e:
            answer = f"(Error al llamar al LLM: {e})"
        dt_ms = int((time.time() - t0) * 1000)

        # Añadir respuesta a memoria
        memory.add_assistant(answer)

        # Mostrar y loguear
        print("\n--- Respuesta ---")
        print(answer)
        print(f"\n({dt_ms} ms)\n")

        _append_chat_log(log_path, {
            "t": _now(),
            "user": user_in,
            "assistant": answer,
            "latency_ms": dt_ms,
            "model": OPENROUTER_MODEL,
        })


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _append_chat_log(path: Path, obj: dict) -> None:
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    run_chat_loop()
