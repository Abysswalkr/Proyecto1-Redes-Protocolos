from __future__ import annotations

import os
import time
from typing import Dict, Generator, Iterable, List, Optional

try:
    # Cargar .env si existe (sin requerir dependencia)
    from dotenv import load_dotenv  # type: ignore
    load_dotenv()
except Exception:
    pass

from openai import OpenAI
from openai import (
    APIConnectionError,
    APIStatusError,
    AuthenticationError,
    RateLimitError,
)


# -------------------------------
# Configuración desde variables
# -------------------------------

_BASE_URL = os.environ.get("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")
_API_KEY = os.environ.get("OPENROUTER_API_KEY", "")
_DEFAULT_MODEL = os.environ.get("OPENROUTER_MODEL", "openai/gpt-oss-120b:free")
_REQUEST_TIMEOUT = float(os.environ.get("REQUEST_TIMEOUT_SECONDS", "30"))
extra_headers={"HTTP-Referer": os.getenv("OPENROUTER_HTTP_REFERRER","http://localhost"),
               "X-Title": os.getenv("OPENROUTER_APP_TITLE","Proyecto MCP")}

# Cabeceras de atribución (opcionales, pero recomendadas)
_HTTP_REFERER = os.environ.get("OPENROUTER_HTTP_REFERRER") or os.environ.get(
    "HTTP_REFERER", "http://localhost"
)
_X_TITLE = os.environ.get("OPENROUTER_APP_TITLE", os.environ.get("APP_TITLE", "MCP Chatbot"))

# Fallback de modelos (coma-separado), opcional
_FALLBACK_MODELS: List[str] = [
    m.strip()
    for m in os.environ.get(
        "OPENROUTER_FALLBACK_MODELS",
        "openai/gpt-oss-120b:free,qwen/qwen2.5-7b-instruct:free",
    ).split(",")
    if m.strip()
]

# Singleton del cliente
_client: Optional[OpenAI] = None


def _default_headers() -> Dict[str, str]:
    """
    Cabeceras que OpenRouter reconoce para atribución/listados.
    (Son opcionales; si no están, igual funciona.)
    """
    return {
        "HTTP-Referer": _HTTP_REFERER,
        "X-Title": _X_TITLE,
    }


def _ensure_client() -> OpenAI:
    """
    Crea (o devuelve) el cliente OpenAI apuntando a OpenRouter.
    """
    global _client
    if _client is not None:
        return _client

    if not _API_KEY:
        raise RuntimeError(
            "OPENROUTER_API_KEY no está definido. Exporta la variable antes de usar el chat."
        )

    # El SDK permite headers por defecto a nivel de cliente.
    _client = OpenAI(
        base_url=_BASE_URL,
        api_key=_API_KEY,
        timeout=_REQUEST_TIMEOUT,
        default_headers=_default_headers(),
    )
    return _client


# ----------------------------------------
# Utilidades de diagnóstico (opcional)
# ----------------------------------------

def ping_openrouter() -> bool:
    """
    Intenta listar modelos para verificar conectividad/autenticación.
    Retorna True si responde; False si hay error.
    """
    try:
        client = _ensure_client()
        _ = client.models.list()  # /models (OpenAI-compatible, soportado por OpenRouter)
        return True
    except Exception:
        return False


# ----------------------------------------
# API pública usada por commands.py
# ----------------------------------------

def chat_sync(
    prompt: str,
    *,
    system: Optional[str] = None,
    model: Optional[str] = None,
    temperature: float = 0.3,
    max_tokens: int = 512,
) -> str:
    """
    Llama al modelo (chat.completions) de manera sincrónica y devuelve el texto.
    """
    client = _ensure_client()

    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})

    # Intento con modelo principal + posibles fallbacks
    models_to_try: Iterable[str] = [model or _DEFAULT_MODEL, *_FALLBACK_MODELS]

    last_err: Optional[Exception] = None
    for m in models_to_try:
        try:
            r = client.chat.completions.create(
                model=m,
                temperature=temperature,
                max_tokens=max_tokens,
                messages=messages,
                # Si no usas default_headers en el cliente, puedes pasar:
                # extra_headers=_default_headers(),
            )
            return (r.choices[0].message.content or "").strip()
        except AuthenticationError as e:
            # 401 típicamente significa key inválida o cuenta no válida en OR.
            last_err = e
            break  # no tiene sentido probar otros modelos si no hay auth
        except (RateLimitError, APIConnectionError, APIStatusError) as e:
            # Reintentar con siguiente modelo
            last_err = e
            continue
        except Exception as e:
            last_err = e
            continue

    # Si llegamos aquí, todos fallaron
    msg = f"Fallo al llamar al LLM. Último error: {type(last_err).__name__}: {last_err}"
    raise RuntimeError(msg)


def chat_stream(
    prompt: str,
    *,
    system: Optional[str] = None,
    model: Optional[str] = None,
    temperature: float = 0.3,
    max_tokens: int = 512,
) -> Generator[str, None, None]:
    """
    Versión stream (yield de fragmentos). Útil si luego deseas mostrar tokens en vivo.
    """
    client = _ensure_client()

    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})

    models_to_try: Iterable[str] = [model or _DEFAULT_MODEL, *_FALLBACK_MODELS]
    last_err: Optional[Exception] = None

    for m in models_to_try:
        try:
            with client.chat.completions.stream(
                model=m,
                temperature=temperature,
                max_tokens=max_tokens,
                messages=messages,
                # extra_headers=_default_headers(),
            ) as stream:
                for event in stream:
                    if event.type == "token":
                        yield event.token
                # asegurar fin de stream
                return
        except AuthenticationError as e:
            last_err = e
            break
        except (RateLimitError, APIConnectionError, APIStatusError) as e:
            last_err = e
            # probar siguiente modelo
            continue
        except Exception as e:
            last_err = e
            continue

    raise RuntimeError(f"Fallo en chat_stream. Último error: {type(last_err).__name__}: {last_err}")


# ----------------------------------------
# Modo script (diagnóstico local)
# ----------------------------------------

if __name__ == "__main__":
    print("[llm] base_url=", _BASE_URL)
    print("[llm] model=", _DEFAULT_MODEL)
    t0 = time.time()
    ok = ping_openrouter()
    dt = (time.time() - t0) * 1000
    print(f"[llm] ping_openrouter={ok} ({dt:.0f} ms)")
    if ok:
        out = chat_sync("Di 'ok' y nada más.")
        print("[llm] respuesta:", out)
