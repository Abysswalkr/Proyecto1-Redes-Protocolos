# server/remote_mcp/remote_utils/server.py
from __future__ import annotations

import asyncio
import socket
from datetime import datetime, timezone
from contextlib import asynccontextmanager

from starlette.applications import Starlette
from starlette.responses import PlainTextResponse, JSONResponse
from starlette.routing import Mount, Route

from mcp.server.fastmcp import FastMCP

# Nota: stateless_http=True facilita pruebas en HTTP.
mcp = FastMCP("remote-utils", stateless_http=True)

@mcp.tool()
async def echo(text: str) -> str:
    """Devuelve exactamente lo recibido (eco)."""
    return text

@mcp.tool()
async def time() -> str:
    """Fecha/hora actual en UTC (ISO 8601)."""
    return datetime.now(timezone.utc).isoformat()

@mcp.tool()
async def dns_lookup(host: str) -> dict:
    """Resuelve A/AAAA de un host."""
    loop = asyncio.get_running_loop()

    def _resolve():
        return socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)

    infos = await loop.run_in_executor(None, _resolve)
    addrs = sorted({it[4][0] for it in infos if it and it[4]})
    return {"host": host, "addresses": addrs}

# Gestiona el ciclo de vida para el session manager de MCP
@asynccontextmanager
async def lifespan(app):
    async with mcp.session_manager.run():
        yield

# IMPORTANTE: montar streamable_http_app() en "/"
# El endpoint real de MCP queda en "/mcp" por defecto.
asgi = Starlette(
    lifespan=lifespan,
    routes=[
        Route("/health", lambda request: PlainTextResponse("ok")),
        # Puedes exponer una vista de spec simple (opcional):
        Route("/spec", lambda request: JSONResponse({"name": "remote-utils", "endpoint": "/mcp"})),
        Mount("/", app=mcp.streamable_http_app()),
    ],
)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(asgi, host="127.0.0.1", port=8080)
