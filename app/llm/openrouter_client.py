import json
import time
from typing import List, Dict, Optional
import requests


class OpenRouterClient:
    """
    Cliente para OpenRouter /v1/chat/completions.
    - Usa 'messages': [{"role": "system|user|assistant", "content": "texto"}]
    """

    def __init__(
        self,
        api_key: str,
        model: str = "qwen/qwen3-coder:free",
        base_url: str = "https://openrouter.ai/api/v1",
        app_title: str = "MCP Chatbot",
        timeout_seconds: int = 30,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.timeout = timeout_seconds

        # Headers OpenRouter
        self.headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        # X-Title por OpenRouter
        if app_title:
            self.headers["X-Title"] = app_title

        self.session = requests.Session()

    def chat(
        self,
        messages: List[Dict[str, str]],
        temperature: float = 0.7,
        max_tokens: Optional[int] = None,
        top_p: Optional[float] = None,
        extra: Optional[Dict] = None,
        retries: int = 2,
        backoff_seconds: float = 1.5,
    ) -> str:
        """
        Envía un chat completion a OpenRouter y devuelve el texto de la primera elección.
        """
        url = f"{self.base_url}/chat/completions"
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
        }
        if max_tokens is not None:
            payload["max_tokens"] = max_tokens
        if top_p is not None:
            payload["top_p"] = top_p
        if extra:
            payload.update(extra)

        last_exc = None
        for attempt in range(retries + 1):
            try:
                resp = self.session.post(
                    url, headers=self.headers, data=json.dumps(payload), timeout=self.timeout
                )
                # Manejo simple de rate limits y errores 5xx
                if resp.status_code in (429,) or 500 <= resp.status_code < 600:
                    time.sleep(backoff_seconds * (attempt + 1))
                    continue
                resp.raise_for_status()
                data = resp.json()
                choices = data.get("choices", [])
                if not choices:
                    raise RuntimeError(f"Respuesta sin 'choices': {data}")
                content = choices[0].get("message", {}).get("content")
                if not content:
                    raise RuntimeError(f"Choice[0] sin 'message.content': {data}")
                return content
            except Exception as exc:  # noqa: BLE001
                last_exc = exc
                if attempt < retries:
                    time.sleep(backoff_seconds * (attempt + 1))
                else:
                    raise RuntimeError(f"Fallo al llamar OpenRouter: {exc}") from exc

    @staticmethod
    def build_messages(
        user_prompt: str,
        system_prompt: Optional[str] = "You are a helpful assistant.",
        history: Optional[List[Dict[str, str]]] = None,
    ) -> List[Dict[str, str]]:
        """
        Construye la lista de mensajes a enviar.
        - system_prompt va primero si existe
        - luego history (si se provee)
        - luego el mensaje del usuario
        """
        msgs: List[Dict[str, str]] = []
        if system_prompt:
            msgs.append({"role": "system", "content": system_prompt})
        if history:
            msgs.extend(history)
        msgs.append({"role": "user", "content": user_prompt})
        return msgs
