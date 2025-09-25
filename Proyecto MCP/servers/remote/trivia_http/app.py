# servers/remote/trivia_http/app.py
"""
Trivia MCP Server (HTTP) para despliegue en Railway.
Expose tools:
  - trivia_random(category?) -> {question, choices, answer_token}
  - trivia_check(answer_token, answer_text?, answer_index?) -> {correct, correct_answer, your_answer, explanation}

Además:
  - /health (HTTP GET) -> {"ok": true, ...}
  - ASGI app: FastAPI con MCP montado en /mcp

Seguridad:
  - TRIVIA_SECRET: HMAC para firmar tokens (answer_token).
  - El token expira (por defecto +3600 s).
"""

from __future__ import annotations
import os
import hmac
import json
import time
import base64
import hashlib
import random
from typing import Any, Dict, List, Optional, Tuple

from fastapi import FastAPI
from fastmcp import FastMCP


# ======================= Config =======================
SERVICE_NAME = "trivia_http"
TRIVIA_SECRET = os.getenv("TRIVIA_SECRET", "change-me")
TOKEN_TTL = int(os.getenv("TRIVIA_TOKEN_TTL", "3600"))  # 1 hora

# Banco sencillo de preguntas (puedes ampliar libremente)
_QUESTIONS = [
    {
        "qid": 1,
        "question": "¿Quién desarrolló la teoría de la relatividad?",
        "choices": ["Isaac Newton", "Albert Einstein", "Niels Bohr", "Galileo Galilei"],
        "correct_index": 1,
        "explanation": "La relatividad especial (1905) y general (1915-1916) fueron desarrolladas por Albert Einstein."
    },
    {
        "qid": 2,
        "question": "Capital de Guatemala",
        "choices": ["Antigua Guatemala", "Quetzaltenango", "Ciudad de Guatemala", "Cobán"],
        "correct_index": 2,
        "explanation": "La capital es la Ciudad de Guatemala."
    },
    {
        "qid": 3,
        "question": "¿Cuál es el puerto por defecto de HTTPS?",
        "choices": ["80", "21", "22", "443"],
        "correct_index": 3,
        "explanation": "HTTPS usa TCP/443 por convención IANA."
    },
]

_seed = os.getenv("TRIVIA_SEED")
if _seed is not None:
    try:
        random.seed(int(_seed))
    except Exception:
        random.seed(_seed)


# ======================= Utiles de token =======================
def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)

def _sign(payload: Dict[str, Any], secret: str) -> str:
    """Devuelve token 'b64(payload).b64(hmac)'."""
    body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    mac = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).digest()
    return _b64url(body) + "." + _b64url(mac)

def _verify(token: str, secret: str) -> Dict[str, Any]:
    """Valida HMAC y exp; devuelve payload dict o lanza ValueError."""
    try:
        part_body, part_sig = token.split(".", 1)
    except ValueError:
        raise ValueError("token malformado")
    body = _b64url_decode(part_body)
    sig = _b64url_decode(part_sig)
    mac = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).digest()
    if not hmac.compare_digest(sig, mac):
        raise ValueError("firma inválida")
    payload = json.loads(body.decode("utf-8"))
    exp = int(payload.get("exp", 0))
    if exp and time.time() > exp:
        raise ValueError("token expirado")
    return payload


# ======================= MCP Server =======================
mcp = FastMCP("trivia_http")

@mcp.tool()
def trivia_random(category: Optional[str] = None) -> Dict[str, Any]:
    """
    Devuelve una pregunta al azar con token firmado.
    structuredContent:
      question: str
      choices: [str]
      answer_token: str (HMAC con qid/correct_index/exp)
    """
    q = random.choice(_QUESTIONS)
    payload = {
        "qid": q["qid"],
        "correct_index": q["correct_index"],
        "exp": int(time.time()) + TOKEN_TTL,
    }
    token = _sign(payload, TRIVIA_SECRET)
    structured = {
        "question": q["question"],
        "choices": q["choices"],
        "answer_token": token,
    }
    return {
        "structuredContent": structured,
        "content": [{"type": "text", "text": json.dumps(structured, ensure_ascii=False)}],
    }

@mcp.tool()
def trivia_check(
    answer_token: str,
    answer_text: Optional[str] = None,
    answer_index: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Verifica respuesta. Acepta texto exacto o índice (1-based).
    structuredContent:
      correct: bool
      correct_answer: str
      your_answer: str|None
      explanation: str
    """
    try:
        payload = _verify(answer_token, TRIVIA_SECRET)
    except ValueError as e:
        structured = {"correct": False, "error": str(e)}
        return {"structuredContent": structured, "content": [{"type": "text", "text": json.dumps(structured, ensure_ascii=False)}]}

    qid = int(payload["qid"])
    correct_idx = int(payload["correct_index"])

    # busca la pregunta
    q = next((x for x in _QUESTIONS if x["qid"] == qid), None)
    if not q:
        structured = {"correct": False, "error": "qid desconocido"}
        return {"structuredContent": structured, "content": [{"type": "text", "text": json.dumps(structured, ensure_ascii=False)}]}

    choices: List[str] = q["choices"]
    correct_answer = choices[correct_idx]

    your_answer: Optional[str] = None
    if answer_index is not None:
        # índice 1-based
        if 1 <= int(answer_index) <= len(choices):
            your_answer = choices[int(answer_index) - 1]
        else:
            your_answer = None
    elif answer_text is not None:
        cand = answer_text.strip().lower()
        for opt in choices:
            if opt.lower() == cand:
                your_answer = opt
                break
        if your_answer is None:
            your_answer = answer_text.strip()

    is_correct = (your_answer == correct_answer)

    structured = {
        "correct": bool(is_correct),
        "correct_answer": correct_answer,
        "your_answer": your_answer,
        "explanation": q.get("explanation"),
    }
    return {
        "structuredContent": structured,
        "content": [{"type": "text", "text": json.dumps(structured, ensure_ascii=False)}],
    }


# ======================= ASGI app (FastAPI) =======================
app = FastAPI(title="MCP Trivia HTTP", version="1.0.0")

@app.get("/health")
def health() -> Dict[str, Any]:
    return {
        "ok": True,
        "service": SERVICE_NAME,
        "time": int(time.time()),
    }

# Monta el MCP en /mcp (ASGI)
app.mount("/mcp", mcp.http_app())


if __name__ == "__main__":
    # Ejecuta con: uvicorn servers.remote.trivia_http.app:app --host 0.0.0.0 --port 8000
    # Railway inyecta $PORT, el Dockerfile lo toma en CMD.
    import uvicorn
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run("servers.remote.trivia_http.app:app", host="0.0.0.0", port=port, reload=False)
