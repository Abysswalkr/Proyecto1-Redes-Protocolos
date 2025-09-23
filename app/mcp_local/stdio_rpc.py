import asyncio, json, os, sys, time, uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

def _to_uri(path: str) -> str:
    p = Path(path).resolve()
    s = str(p).replace("\\", "/")
    if sys.platform.startswith("win") and not s.startswith("/"):
        s = "/" + s
    return "file://" + s

async def _read_headers(reader: asyncio.StreamReader) -> int:
    # Lee hasta CRLFCRLF y devuelve Content-Length
    buf = b""
    while True:
        chunk = await reader.readuntil(b"\r\n")
        buf += chunk
        if buf.endswith(b"\r\n\r\n"):
            break
    # parse content-length
    clen = 0
    for line in buf.decode("utf-8", errors="ignore").split("\r\n"):
        if line.lower().startswith("content-length:"):
            try:
                clen = int(line.split(":", 1)[1].strip())
            except Exception:
                pass
    if clen <= 0:
        raise RuntimeError(f"Content-Length inválido en headers: {buf!r}")
    return clen

async def _read_message(reader: asyncio.StreamReader) -> Dict[str, Any]:
    clen = await _read_headers(reader)
    body = await reader.readexactly(clen)
    try:
        return json.loads(body.decode("utf-8"))
    except Exception as e:
        raise RuntimeError(f"JSON inválido: {e} :: {body!r}")

async def _write_message(writer: asyncio.StreamWriter, payload: Dict[str, Any]):
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    writer.write(f"Content-Length: {len(data)}\r\n\r\n".encode("utf-8"))
    writer.write(data)
    await writer.drain()

class MCPError(Exception):
    pass

class _MCPProcess:
    def __init__(self, command: str, args: List[str], env: Optional[Dict[str, str]] = None):
        self.command = command
        self.args = list(args or [])
        self.env = {**os.environ, **(env or {})}
        self.proc: Optional[asyncio.subprocess.Process] = None
        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None
        self.allowed_roots: List[Dict[str, str]] = []

    async def start(self, allowed_dir: Optional[str], timeout: float = 25.0):
        self.proc = await asyncio.create_subprocess_exec(
            self.command, *self.args,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=self.env,
        )
        if not self.proc.stdin or not self.proc.stdout:
            raise MCPError("No se pudieron abrir pipes stdio")
        # ¡OJO! Aquí usamos directamente los streams del subprocess (Windows-friendly)
        self.reader = self.proc.stdout
        self.writer = self.proc.stdin

        if allowed_dir:
            self.allowed_roots = [{"uri": _to_uri(allowed_dir), "name": "project-root"}]

        init_req = {
            "jsonrpc":"2.0","id":str(uuid.uuid4()),"method":"initialize",
            "params":{
                "protocolVersion":"2024-11-05",
                "capabilities":{"roots":{"listChanged": False}},
                "clientInfo":{"name":"cli-stdio","version":"0.1.0"},
            }
        }
        await _write_message(self.writer, init_req)

        # Esperar initialize; responder a roots/list si llega antes
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            msg = await asyncio.wait_for(_read_message(self.reader), timeout=timeout)
            if msg.get("id") == init_req["id"]:
                if "error" in msg:
                    raise MCPError(f"initialize/error: {msg['error']}")
                return
            if msg.get("method") == "roots/list" and "id" in msg:
                await _write_message(self.writer, {"jsonrpc":"2.0","id":msg["id"],"result": self.allowed_roots})
                continue
            # otras notificaciones: ignorar
        raise MCPError("Timeout esperando initialize()")

    async def request(self, method: str, params: Dict[str, Any], timeout: float = 25.0) -> Any:
        req_id = str(uuid.uuid4())
        await _write_message(self.writer, {"jsonrpc":"2.0","id":req_id,"method":method,"params":params})
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            msg = await asyncio.wait_for(_read_message(self.reader), timeout=timeout)
            # respuestas a nuestras requests
            if msg.get("id") == req_id:
                if "error" in msg:
                    raise MCPError(f"{method}/error: {msg['error']}")
                return msg.get("result")
            # si el server llama a algo (roots/list), respondemos y seguimos esperando
            if msg.get("method") == "roots/list" and "id" in msg:
                await _write_message(self.writer, {"jsonrpc":"2.0","id":msg["id"],"result": self.allowed_roots})
                continue
        raise MCPError(f"Timeout esperando respuesta a {method}")

    async def close(self):
        try:
            if self.writer:
                try:
                    self.writer.close()
                    await self.writer.wait_closed()
                except Exception:
                    pass
        finally:
            if self.proc and self.proc.returncode is None:
                try:
                    self.proc.kill()
                except Exception:
                    pass

async def mcp_fs_list_tools(command: str, args: List[str], *, allowed_dir: Optional[str], timeout: float = 25.0) -> List[Dict[str, Any]]:
    p = _MCPProcess(command, args)
    try:
        await p.start(allowed_dir=allowed_dir, timeout=timeout)
        res = await p.request("tools/list", {}, timeout=timeout)
        tools = res.get("tools", res) if isinstance(res, dict) else res
        return tools if isinstance(tools, list) else []
    finally:
        await p.close()

async def mcp_fs_call_tool(
    command: str,
    args: List[str],
    *,
    tool: str,
    arguments: Dict[str, Any],
    allowed_dir: Optional[str],
    timeout: float = 25.0
) -> Dict[str, Any]:
    p = _MCPProcess(command, args)
    try:
        await p.start(allowed_dir=allowed_dir, timeout=timeout)
        res = await p.request("tools/call", {"name": tool, "arguments": arguments}, timeout=timeout)
        # Normaliza salida típica del FS: content[0].text con JSON
        if isinstance(res, dict) and isinstance(res.get("content"), list) and res["content"]:
            first = res["content"][0]
            if isinstance(first, dict) and first.get("type") == "text":
                txt = first.get("text") or ""
                try:
                    return json.loads(txt)
                except Exception:
                    return {"text": txt}
        return res if isinstance(res, dict) else {"result": res}
    finally:
        await p.close()
