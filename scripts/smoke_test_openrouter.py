import time
from app.config import (
    OPENROUTER_API_KEY,
    OPENROUTER_MODEL,
    APP_TITLE,
    REQUEST_TIMEOUT_SECONDS,
)
from app.llm.openrouter_client import OpenRouterClient

def main():
    client = OpenRouterClient(
        api_key=OPENROUTER_API_KEY,
        model=OPENROUTER_MODEL,
        app_title=APP_TITLE,
        timeout_seconds=REQUEST_TIMEOUT_SECONDS,
    )
    prompt = "Responde únicamente con: OK"
    msgs = client.build_messages(
        user_prompt=prompt,
        system_prompt="Responde exactamente lo que se te pide, en español.",
        history=None,
    )
    t0 = time.time()
    out = client.chat(msgs, temperature=0.0, max_tokens=10)
    dt = (time.time() - t0) * 1000
    print(f"[SmokeTest] Modelo: {OPENROUTER_MODEL}")
    print(f"[SmokeTest] Tiempo: {dt:.0f} ms")
    print(f"[SmokeTest] Respuesta: {out!r}")

if __name__ == "__main__":
    main()
