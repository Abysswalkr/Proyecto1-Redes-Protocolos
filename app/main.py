from app.config import (
    OPENROUTER_API_KEY,
    OPENROUTER_MODEL,
    APP_TITLE,
    REQUEST_TIMEOUT_SECONDS,
)
from app.llm.openrouter_client import OpenRouterClient


def ask_once(question: str) -> str:
    client = OpenRouterClient(
        api_key=OPENROUTER_API_KEY,
        model=OPENROUTER_MODEL,           # qwen/qwen3-coder
        app_title=APP_TITLE,
        timeout_seconds=REQUEST_TIMEOUT_SECONDS,
    )
    messages = client.build_messages(
        user_prompt=question,
        system_prompt="Responde en español, de forma clara y concisa.",
        history=None,  # memoria
    )
    return client.chat(messages, temperature=0.2)


if __name__ == "__main__":
    question = input("Pregunta (e.g., ¿Quién fue Alan Turing?): ").strip()
    answer = ask_once(question)
    print("\n--- Respuesta del LLM ---")
    print(answer)
