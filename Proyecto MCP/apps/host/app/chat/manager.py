# apps/host/app/chat/manager.py
from __future__ import annotations
import asyncio, json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, Any, List

from .memory import ConversationMemory
# Usamos tu cliente ya existente en apps/host/app/llm.py
from ..llm import chat_sync

LOG_DIR = Path("apps/host/logs/chat")
LOG_DIR.mkdir(parents=True, exist_ok=True)


def _append_jsonl(path: Path, record: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


class ChatManager:
    """
    Orquesta memoria + LLM (OpenRouter vía llm.py) con logging en JSONL.
    """
    def __init__(
        self,
        memory: ConversationMemory,
        system_prompt: Optional[str] = None,
        log_file: Optional[Path] = None,
        model: Optional[str] = None,
    ) -> None:
        self.memory = memory
        self.system_prompt = system_prompt
        self.model = model
        ts = datetime.now(timezone.utc).strftime("%Y%m%d")
        self.log_file = log_file or LOG_DIR / f"chat-{ts}.jsonl"

    def history(self) -> List[Dict[str, str]]:
        return self.memory.get_history()

    def reset(self) -> None:
        self.memory.reset()
        _append_jsonl(self.log_file, {
            "t": datetime.now(timezone.utc).isoformat(),
            "event": "reset"
        })

    async def aask(self, user_text: str) -> str:
        """
        Llama al LLM en un hilo (chat_sync) y mantiene memoria de sesión.
        Para conservar contexto, serializamos el historial al 'system'.
        """
        # Registramos el turno del usuario primero
        self.memory.add_user(user_text)

        # Construir 'system' con el prompt base + resumen del historial
        hist = self.memory.get_history()[:-1]  # sin el último turno recién agregado
        hist_serialized = "\n".join(f"{m['role']}: {m['content']}" for m in hist[-18:])
        system_payload = (self.system_prompt or "").strip()
        if hist_serialized:
            system_payload = (system_payload + "\n\n[Contexto previo]\n" + hist_serialized).strip()

        # Ejecutamos el llamado sin bloquear el loop
        def _call_sync() -> str:
            return chat_sync(
                user_text,
                system=system_payload if system_payload else None,
                model=self.model,
            )

        try:
            answer: str = await asyncio.to_thread(_call_sync)
        except Exception as e:
            answer = f"[LLM error] {e}"

        # Guardamos respuesta
        self.memory.add_assistant(answer)

        _append_jsonl(self.log_file, {
            "t": datetime.now(timezone.utc).isoformat(),
            "event": "chat_turn",
            "request": user_text,
            "response": answer,
        })
        return answer


# Helpers sync convenientes
def ask_sync(cm: ChatManager, user_text: str) -> str:
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None
    if loop and loop.is_running():
        # Si alguien llama desde un loop activo, hacemos to_thread
        return asyncio.run(cm.aask(user_text))
    else:
        return asyncio.run(cm.aask(user_text))


# Factory por defecto que leerás desde el REPL
async def build_default_chat(
    max_messages: int = 20,
    system_prompt: Optional[str] = None,
    model: Optional[str] = None,
) -> ChatManager:
    memory = ConversationMemory(max_messages=max_messages)
    return ChatManager(memory=memory, system_prompt=system_prompt, model=model)
