import asyncio, json, os, sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from mcp.client.session import ClientSession
from mcp.client.stdio import stdio_client, StdioServerParameters

# ---------- Utilidades genéricas MCP ----------
async def _mcp_list_tools(cmd: str, args: List[str]) -> List[Dict[str, Any]]:
    params = StdioServerParameters(command=cmd, args=args)
    async with stdio_client(params) as (read, write):
        session = ClientSession(read, write)
        await session.initialize()
        tools = await session.list_tools()
        return [t.model_dump() for t in tools.tools]

async def _mcp_call(cmd: str, args: List[str], tool: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
    params = StdioServerParameters(command=cmd, args=args)
    async with stdio_client(params) as (read, write):
        session = ClientSession(read, write)
        await session.initialize()
        result = await session.call_tool(name=tool, arguments=arguments)
        out: Dict[str, Any] = {"isError": bool(getattr(result, "is_error", False))}
        parts = []
        for part in (result.content or []):
            # normalizamos a dict
            try:
                parts.append(part.model_dump())
            except Exception:
                parts.append({"type": getattr(part, "type", "unknown"),
                              "text": getattr(part, "text", None)})
        out["content"] = parts
        return out

def _find_tool(tools: List[Dict[str, Any]], candidates: List[str]) -> Optional[str]:
    names = [t.get("name", "") for t in tools]
    lower_map = {n.lower(): n for n in names}
    for c in candidates:
        if c.lower() in lower_map:
            return lower_map[c.lower()]
    for c in candidates:
        for n in names:
            if c.lower() in n.lower():
                return n
    return None

def _normalize_cfg(raw_cfg: Dict[str, Any]) -> Dict[str, Any]:
    """
    Acepta:
      - { "filesystem": {...}, "git": {...} }
      - { "servers": [ {name: filesystem, ...}, {name: git, ...}, ... ] }
    y combina múltiples documentos YAML si los hay.
    """
    out: Dict[str, Any] = {}
    if not raw_cfg:
        return out
    if "servers" in raw_cfg and isinstance(raw_cfg["servers"], list):
        for item in raw_cfg["servers"]:
            if not isinstance(item, dict):
                continue
            name = item.get("name")
            if not name:
                continue
            out[name] = {k: v for k, v in item.items() if k != "name"}
    else:
        out.update(raw_cfg)
    return out

def _load_servers_yaml(path: Path) -> Dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    # 1) Si viene en JSON puro, cargamos directo
    if text.strip().startswith("{"):
        return json.loads(text)
    # 2) Intentamos YAML real (recomendado)
    try:
        import yaml  # pip install pyyaml
    except Exception:
        print("ERROR: para YAML usa 'pip install pyyaml' o convierte servers.yaml a JSON.", file=sys.stderr)
        raise
    docs = list(yaml.safe_load_all(text))
    merged: Dict[str, Any] = {}
    for doc in docs:
        if not isinstance(doc, dict):
            continue
        # combinamos los documentos (lo último gana)
        merged.update(doc)
    return _normalize_cfg(merged)

def _get_server(cfg: Dict[str, Any], key: str) -> Dict[str, Any]:
    srv = cfg.get(key)
    if not srv:
        raise KeyError(f"'{key}' no está definido en servers.yaml. Claves disponibles: {list(cfg.keys())}")
    cmd = srv.get("command") or "npx"
    args = srv.get("args") or []
    if not isinstance(args, list):
        # Permite 'args: "-y @pkg"' como string; lo dividimos
        import shlex
        args = shlex.split(str(args))
    return {"command": cmd, "args": args}

# ---------- Flujo demo: README + init + add + commit ----------
async def demo(repo_dir: str, readme_text: str, commit_msg: str, servers_cfg: Dict[str, Any]) -> Dict[str, Any]:
    fs = _get_server(servers_cfg, "filesystem")
    gt = _get_server(servers_cfg, "git")

    fs_tools = await _mcp_list_tools(fs["command"], fs["args"])
    git_tools = await _mcp_list_tools(gt["command"], gt["args"])

    make_dir = _find_tool(fs_tools, ["makeDirectory", "mkdir", "createDirectory"])
    write_file = _find_tool(fs_tools, ["writeFile", "fileWrite", "createFile"])
    read_file = _find_tool(fs_tools, ["readFile", "fileRead"])  # opcional

    init_repo = _find_tool(git_tools, ["initRepo", "init", "gitInit"])
    add_file = _find_tool(git_tools, ["add", "gitAdd", "stage"])
    commit = _find_tool(git_tools, ["commit", "gitCommit"])

    missing = []
    for name, val in [
        ("filesystem.makeDirectory", make_dir),
        ("filesystem.writeFile", write_file),
        ("git.init", init_repo),
        ("git.add", add_file),
        ("git.commit", commit),
    ]:
        if not val:
            missing.append(name)
    if missing:
        return {
            "ok": False,
            "error": "missing_tools",
            "missing": missing,
            "fs_tools": [t["name"] for t in fs_tools],
            "git_tools": [t["name"] for t in git_tools],
        }

    repo_path = str(Path(repo_dir).resolve())
    readme_path = str(Path(repo_path, "README.md"))

    steps = []

    res1 = await _mcp_call(fs["command"], fs["args"], make_dir, {"path": repo_path, "recursive": True})
    steps.append({"makeDirectory": res1})

    res2 = await _mcp_call(fs["command"], fs["args"], write_file, {
        "path": readme_path,
        "content": readme_text,
        "encoding": "utf-8",
        "create": True,
        "overwrite": True
    })
    steps.append({"writeFile": res2})

    res3 = await _mcp_call(gt["command"], gt["args"], init_repo, {"path": repo_path})
    steps.append({"gitInit": res3})

    res4 = await _mcp_call(gt["command"], gt["args"], add_file, {"path": repo_path, "files": ["README.md"]})
    steps.append({"gitAdd": res4})

    res5 = await _mcp_call(gt["command"], gt["args"], commit, {"path": repo_path, "message": commit_msg})
    steps.append({"gitCommit": res5})

    verify = None
    if read_file:
        verify = await _mcp_call(fs["command"], fs["args"], read_file, {"path": readme_path, "encoding": "utf-8"})

    return {
        "ok": True,
        "repo": repo_path,
        "steps": steps,
        "verify": verify,
    }

def _print_json(d: Dict[str, Any]) -> None:
    print(json.dumps(d, ensure_ascii=False, indent=2))

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Uso: python -m scripts.mcp_fs_git_demo <repo_dir> <README_text> <commit_msg>", file=sys.stderr)
        sys.exit(2)
    repo_dir = sys.argv[1]
    readme_text = sys.argv[2]
    commit_msg = sys.argv[3]

    servers_file = Path("servers.yaml")
    if not servers_file.exists():
        print("ERROR: no se encontró servers.yaml", file=sys.stderr)
        sys.exit(2)
    servers_cfg = _load_servers_yaml(servers_file)

    out = asyncio.run(demo(repo_dir, readme_text, commit_msg, servers_cfg))
    _print_json(out)
