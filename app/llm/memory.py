from typing import List, Dict, Optional

class ConversationMemory:
    """
    Guarda pares user/assistant y devuelve las N más recientes.
    """
    def __init__(self, max_messages: int = 20) -> None:
        # max_messages cuenta TODOS los mensajes (user/assistant), excluye el system
        self.max_messages = max_messages
        self._history: List[Dict[str, str]] = []

    def add_user(self, content: str) -> None:
        self._history.append({"role": "user", "content": content})
        self._trim()

    def add_assistant(self, content: str) -> None:
        self._history.append({"role": "assistant", "content": content})
        self._trim()

    def get_history(self) -> List[Dict[str, str]]:
        # Devuelve una copia para no mutarla accidentalmente
        return list(self._history)

    def reset(self) -> None:
        self._history.clear()

    def _trim(self) -> None:
        # Mantiene sólo las últimas N entradas
        excess = len(self._history) - self.max_messages
        if excess > 0:
            del self._history[0:excess]
