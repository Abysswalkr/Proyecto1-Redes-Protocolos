# apps/host/app/commands_chat.py
from __future__ import annotations
import asyncio
from typing import Optional
from apps.host.app.chat.manager import build_default_chat

# instancia única por proceso
_CHAT = None

async def _ensure_chat(system: Optional[str] = None, model: Optional[str] = None):
    global _CHAT
    if _CHAT is None:
        _CHAT = await build_default_chat(max_messages=20, system_prompt=system, model=model)
    return _CHAT

async def cmd_chat(args: list[str]) -> None:
    """
    chat <texto>     # envía turno con memoria
    chat show        # muestra historial
    chat reset       # limpia historial
    """
    if not args:
        print("Uso: chat <texto> | chat show | chat reset")
        return

    sub = args[0].lower()
    cm = await _ensure_chat()

    if sub == "show":
        hist = cm.history()
        if not hist:
            print("(historial vacío)")
            return
        for i, msg in enumerate(hist, 1):
            role = msg.get("role", "?")
            content = msg.get("content", "")
            print(f"[{i:02d}] {role}: {content}")
        return

    if sub == "reset":
        cm.reset()
        print("Memoria reiniciada.")
        return

    # caso normal: enviar texto
    text = " ".join(args)
    resp = await cm.aask(text)
    print(resp)
