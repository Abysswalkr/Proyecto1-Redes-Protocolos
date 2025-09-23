# app/cli.py
from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import yaml
except Exception:
    yaml = None

REPO_ROOT = Path(__file__).resolve().parents[1]
SERVERS_YAML = REPO_ROOT / "servers.yaml"
PROTOCOL_VERSION = "2025-03-26"  # MCP spec lifecycle rev. 2025-03-26

INIT_TIMEOUT = 25.0
REQ_TIMEOUT = 25.0

def _abs(p: str | Path) -> Path:
    return (REPO_ROOT / p).resolve() if not Path(p).is_absolute() else Path(p).resolve()

def _uri(p: str | Path) -> str:
    return _abs(p).as_uri()

def _load_servers_yaml() -> Dict[str, Any]:
    if not SERVERS_YAML.exists():
        raise FileNotFoundError(f"No existe servers.yaml en {SERVERS_YAML}")
    if yaml is None:
        raise RuntimeError("PyYAML no está instalado. Ejecuta: pip install pyyaml")
    with open(SERVERS_YAML, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}

def _get_server(cfg: Dict[str, Any], name: str) -> Tuple[str, List[str]]:
    if name not in cfg:
        raise KeyError(f"servers.yaml no define '{name}'")
    s = cfg[name] or {}
    cmd = s.get("command")
    args = s.get("args", [])
    if not cmd:
        raise KeyError(f"servers.yaml.{name}.command vacío")
    if not isinstance(args, list):
        raise KeyError(f"servers.yaml.{name}.args debe ser lista")
    return str(cmd), [str(a) for a in args]

def _norm(s: str) -> str:
    return re.sub(r"[_\\-\\s]", "", s).lower()

def _pick_tool(tools: List[Dict[str, Any]], candidates: List[str]) -> Optional[str]:
    cand_norm = [_norm(c) for c in candidates]
    for t in tools:
        name = t.get("name", "")
        if _norm(name) in cand_norm:
            return name
    for t in tools:
        nm = _norm(t.get("name", ""))
        if any(c in nm for c in cand_norm):
            return t.get("name", "")
    return None

# Reemplaza en app/cli.py la clase MCPStdioNDJSON COMPLETA por esta:

class MCPStdioNDJSON:
    """
    Cliente MCP (NDJSON): un mensaje JSON por línea.
    - initialize incluye protocolVersion (MCP 2025-03-26)
    - envía notifications/initialized tras initialize OK
    - responde a roots/list si el server lo pide
    - stop(): shutdown limpio de stdio (stdin->drain->wait->terminate/kill)
    """
    def __init__(self, command: str, args: List[str], roots: Optional[List[Dict[str, str]]] = None, env: Optional[Dict[str, str]] = None):
        self.command = command
        self.args = list(args or [])
        base_env = os.environ.copy()
        base_env.setdefault("PYTHONUNBUFFERED", "1")
        base_env.setdefault("NO_COLOR", "1")
        if env:
            base_env.update(env)
        self.env = base_env

        self.proc: Optional[asyncio.subprocess.Process] = None
        self.reader: Optional[asyncio.StreamReader] = None    # stdout del server
        self._stderr_reader: Optional[asyncio.StreamReader] = None  # stderr del server
        self.writer: Optional[asyncio.StreamWriter] = None    # stdin  del server
        self.roots = roots or []

    async def start(self, timeout: float = INIT_TIMEOUT):
        self.proc = await asyncio.create_subprocess_exec(
            self.command, *self.args,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=self.env,
        )
        if not self.proc.stdin or not self.proc.stdout:
            raise RuntimeError("No se pudieron abrir pipes stdio")
        self.reader = self.proc.stdout
        self._stderr_reader = self.proc.stderr
        self.writer = self.proc.stdin

        caps: Dict[str, Any] = {}
        if self.roots:
            caps["roots"] = {}

        # initialize con protocolVersion (obligatorio) + capabilities
        await self._send({
            "jsonrpc": "2.0",
            "id": "init-1",
            "method": "initialize",
            "params": {
                "protocolVersion": PROTOCOL_VERSION,  # 2025-03-26
                "capabilities": caps,
                "clientInfo": {"name": "cli-stdio", "version": "1.3.0"},
            },
        })
        await self._await_initialize_and_roots(timeout=timeout)

        # notificar que el cliente está listo (spec)
        await self._send({"jsonrpc": "2.0", "method": "notifications/initialized"})

    async def _await_initialize_and_roots(self, timeout: float):
        loop = asyncio.get_event_loop()
        deadline = loop.time() + timeout
        while True:
            remaining = max(0.05, deadline - loop.time())
            if remaining <= 0:
                raise TimeoutError("Timeout esperando initialize()")
            msg = await self._recv(timeout=remaining)
            if not msg:
                continue
            if msg.get("method") == "roots/list" and "id" in msg:
                await self._send({"jsonrpc": "2.0", "id": msg["id"], "result": self.roots})
                continue
            if msg.get("id") == "init-1":
                if "error" in msg:
                    raise RuntimeError(f"initialize/error: {msg['error']}")
                return

    async def list_tools(self) -> List[Dict[str, Any]]:
        await self._send({"jsonrpc": "2.0", "id": "tools-list-1", "method": "tools/list", "params": {}})
        msg = await self._await_response("tools-list-1")
        res = msg.get("result", {})
        return list(res.get("tools") or []) if isinstance(res, dict) else (res if isinstance(res, list) else [])

    async def call_tool(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        await self._send({"jsonrpc": "2.0", "id": "tools-call-1", "method": "tools/call", "params": {"name": name, "arguments": arguments}})
        msg = await self._await_response("tools-call-1")
        res = msg.get("result")
        return res if isinstance(res, dict) else {"result": res}

    async def _await_response(self, req_id: str, timeout: float = REQ_TIMEOUT) -> Dict[str, Any]:
        loop = asyncio.get_event_loop()
        deadline = loop.time() + timeout
        while True:
            remaining = max(0.05, deadline - loop.time())
            if remaining <= 0:
                raise TimeoutError(f"Timeout esperando respuesta a {req_id}")
            msg = await self._recv(timeout=remaining)
            if not msg:
                continue
            if msg.get("method") == "roots/list" and "id" in msg:
                await self._send({"jsonrpc": "2.0", "id": msg["id"], "result": self.roots})
                continue
            if msg.get("id") == req_id:
                if "error" in msg:
                    raise RuntimeError(f"{req_id}/error: {msg['error']}")
                return msg

    async def stop(self):
        """Apaga el server MCP por stdio de forma limpia:
           1) cerrar stdin
           2) esperar leyendo stdout/stderr (communicate)
           3) si no sale a tiempo -> terminate -> communicate
           4) si aún no sale -> kill -> communicate
        """
        try:
            # 1) Cerrar stdin del server (muchos servers salen al ver EOF en stdin)
            if self.writer:
                try:
                    try:
                        self.writer.write_eof()
                    except Exception:
                        pass
                    self.writer.close()
                    await self.writer.wait_closed()
                except Exception:
                    pass

            # 2) Esperar salida normal drenando stdout/stderr
            if self.proc and self.proc.returncode is None:
                try:
                    await asyncio.wait_for(self.proc.communicate(), timeout=2.5)
                except asyncio.TimeoutError:
                    # 3) Intento de cierre con gracia
                    try:
                        self.proc.terminate()
                    except Exception:
                        pass
                    try:
                        await asyncio.wait_for(self.proc.communicate(), timeout=2.5)
                    except asyncio.TimeoutError:
                        # 4) Último recurso
                        try:
                            self.proc.kill()
                        except Exception:
                            pass
                        try:
                            await asyncio.wait_for(self.proc.communicate(), timeout=2.0)
                        except Exception:
                            pass
        finally:
            # Soltar referencias para que no haya __del__ tardíos con el loop ya cerrado
            self.proc = None
            self.reader = None
            self._stderr_reader = None
            self.writer = None

    async def _send(self, payload: Dict[str, Any]):
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8") + b"\n"
        assert self.writer is not None
        self.writer.write(data)
        await self.writer.drain()

    async def _recv(self, timeout: float = REQ_TIMEOUT) -> Optional[Dict[str, Any]]:
        assert self.reader is not None
        try:
            line = await asyncio.wait_for(self.reader.readline(), timeout=timeout)
        except asyncio.TimeoutError:
            return None
        if not line:
            return None
        line = line.strip()
        if not line:
            return None
        try:
            return json.loads(line.decode("utf-8"))
        except Exception:
            return None

# ---------- helpers de extracción de errores de contenido ----------
def _content_text(res: Dict[str, Any]) -> str:
    out: List[str] = []
    for item in res.get("content", []) or []:
        if isinstance(item, dict) and item.get("type") == "text":
            out.append(item.get("text", ""))
    return "\n".join(out).strip()

# --------------------------- Filesystem wrappers -------------------------
def _fs_mkdir_args(dir_path: Path) -> Dict[str, Any]:
    p = str(dir_path)
    return {"path": p, "dirPath": p, "directory": p, "uri": _uri(p)}

def _fs_write_args(file_path: Path, content: str) -> Dict[str, Any]:
    p = str(file_path)
    return {"path": p, "filePath": p, "uri": _uri(p), "content": content, "text": content, "encoding": "utf-8"}

async def _fs_tools_and_call(action: str, args_payload: Dict[str, Any]) -> Dict[str, Any]:
    try:
        cfg = _load_servers_yaml()
        cmd, args = _get_server(cfg, "filesystem")
    except Exception as e:
        return {"ok": False, "error": "filesystem_config_failed", "detail": str(e)}

    roots = [{"uri": _uri(REPO_ROOT), "name": "repo"}]
    has_allowed = any(Path(a).exists() for a in args if isinstance(a, str))
    if not has_allowed:
        args = [*args, str(REPO_ROOT)]

    cli = MCPStdioNDJSON(cmd, args, roots=roots)
    try:
        await cli.start(timeout=INIT_TIMEOUT)
        tools = await cli.list_tools()
        if action == "mkdir":
            name = _pick_tool(tools, ["createDirectory", "makeDirectory", "mkdir"])
        elif action == "write":
            name = _pick_tool(tools, ["writeFile", "fileWrite", "createFile"])
        else:
            return {"ok": False, "error": "filesystem_unknown_action", "detail": action}
        if not name:
            return {"ok": False, "error": "filesystem_missing_tool", "available": [t.get("name") for t in tools]}
        res = await cli.call_tool(name, args_payload)
        if isinstance(res, dict) and res.get("isError"):
            return {"ok": False, "error": "filesystem_server_error", "detail": _content_text(res)}
        return {"ok": True, "result": res}
    except Exception as e:
        return {"ok": False, "error": f"filesystem_{action}_failed", "detail": str(e)}
    finally:
        await cli.stop()

# ------------------------------- Git wrappers ----------------------------
def _git_init_args(repo_dir: Path) -> Dict[str, Any]:
    # El Git MCP oficial exige repo_path (PyPI) :contentReference[oaicite:2]{index=2}
    return {"repo_path": str(repo_dir)}

def _git_add_args(repo_dir: Path, files: List[str]) -> Dict[str, Any]:
    # git_add(repo_path, files[]) (PyPI) :contentReference[oaicite:3]{index=3}
    return {"repo_path": str(repo_dir), "files": files}

def _git_commit_args(repo_dir: Path, message: str) -> Dict[str, Any]:
    # git_commit(repo_path, message) (PyPI) :contentReference[oaicite:4]{index=4}
    return {"repo_path": str(repo_dir), "message": message}

async def _git_tools_and_call(action: str, args_payload: Dict[str, Any]) -> Dict[str, Any]:
    try:
        cfg = _load_servers_yaml()
        cmd, args = _get_server(cfg, "git")
    except Exception as e:
        return {"ok": False, "error": "git_config_failed", "detail": str(e)}

    roots = [{"uri": _uri(REPO_ROOT), "name": "repo"}]
    cli = MCPStdioNDJSON(cmd, args, roots=roots)
    try:
        await cli.start(timeout=INIT_TIMEOUT)
        tools = await cli.list_tools()
        if action == "init":
            name = _pick_tool(tools, ["git_init", "init"])
        elif action == "add":
            name = _pick_tool(tools, ["git_add", "add", "stage"])
        elif action == "commit":
            name = _pick_tool(tools, ["git_commit", "commit"])
        else:
            return {"ok": False, "error": "git_unknown_action", "detail": action}
        if not name:
            return {"ok": False, "error": "git_missing_tool", "available": [t.get("name") for t in tools]}
        res = await cli.call_tool(name, args_payload)
        if isinstance(res, dict) and res.get("isError"):
            return {"ok": False, "error": "git_server_error", "detail": _content_text(res)}
        return {"ok": True, "result": res}
    except Exception as e:
        return {"ok": False, "error": f"git_{action}_failed", "detail": str(e)}
    finally:
        await cli.stop()

# ------------------------------- Intents ---------------------------------
def _parse_intent(text: str) -> Tuple[str, str, Dict[str, Any]]:
    t = text.strip()

    m = re.match(r'^\s*crea\s+repo(?:sitorio)?\s+(.+?)\s*$', t, re.IGNORECASE)
    if m:
        repo = _abs(m.group(1))
        return "combo", "create_repo", {"repo_dir": str(repo)}

    m = re.match(r'^\s*escribe\s+README\s+con\s+"(.+?)"\s+en\s+(.+?)\s*$', t, re.IGNORECASE)
    if m:
        txt = m.group(1)
        repo = _abs(m.group(2))
        return "fs", "write_readme", {"file_path": str((repo / "README.md")), "content": txt}

    m = re.match(r'^\s*haz\s+commit\s+en\s+(.+?)\s+"(.+?)"\s*$', t, re.IGNORECASE)
    if m:
        repo = _abs(m.group(1))
        msg = m.group(2)
        return "git", "commit_all", {"repo_dir": str(repo), "message": msg}

    raise ValueError('Comando no reconocido. Formatos:\n'
                     '  - crea repo <ruta>\n'
                     '  - escribe README con "TEXTO" en <ruta>\n'
                     '  - haz commit en <ruta> "mensaje"')

async def handle_user_text(text: str) -> Dict[str, Any]:
    try:
        kind, action, args = _parse_intent(text)
    except Exception as e:
        return {"ok": False, "error": "bad_intent", "detail": str(e)}

    if kind == "combo" and action == "create_repo":
        repo_dir = Path(args["repo_dir"])
        res_mkdir = await _fs_tools_and_call("mkdir", _fs_mkdir_args(repo_dir))
        if not res_mkdir.get("ok"):
            return {"ok": False, "step": "mkdir", "result": res_mkdir}
        res_init = await _git_tools_and_call("init", _git_init_args(repo_dir))
        if not res_init.get("ok"):
            return {"ok": False, "step": "git_init", "result": res_init}
        return {"ok": True, "steps": {"mkdir": res_mkdir, "git_init": res_init}}

    if kind == "fs" and action == "write_readme":
        res = await _fs_tools_and_call("write", _fs_write_args(Path(args["file_path"]), args["content"]))
        return res if res.get("ok") else {"ok": False, **res}

    if kind == "git" and action == "commit_all":
        repo_dir = Path(args["repo_dir"])
        res_add = await _git_tools_and_call("add", _git_add_args(repo_dir, files=["."]))
        if not res_add.get("ok"):
            return {"ok": False, "step": "git_add", "result": res_add}
        res_commit = await _git_tools_and_call("commit", _git_commit_args(repo_dir, args["message"]))
        if not res_commit.get("ok"):
            return {"ok": False, "step": "git_commit", "result": res_commit}
        return {"ok": True, "steps": {"git_add": res_add, "git_commit": res_commit}}

    return {"ok": False, "error": "not_implemented"}

async def _once(text: str):
    out = await handle_user_text(text)
    print(json.dumps(out, ensure_ascii=False, indent=2))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--once", type=str, help="Ejecuta un solo comando (string)")
    parser.add_argument("--once-env", type=str, help="Lee el comando desde una variable de entorno")
    args = parser.parse_args()

    if args.once_env:
        env_val = os.environ.get(args.once_env)
        if not env_val:
            print(json.dumps({"ok": False, "error": "missing_env", "detail": f"No existe variable {args.once_env}"}))
            return
        asyncio.run(_once(env_val))
        return

    if args.once:
        asyncio.run(_once(args.once))
        return

    print("Chatbot CLI (MCP stdio). Ctrl+C para salir.")
    try:
        while True:
            line = input("> ").strip()
            if not line:
                continue
            asyncio.run(_once(line))
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()
