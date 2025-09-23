import os, sys, asyncio, json, shlex, shutil
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

def _flatten_exc(e: BaseException) -> list[str]:
    msgs = []
    try:
        if hasattr(e, "exceptions"):  # ExceptionGroup (3.11+)
            for sub in e.exceptions:
                msgs.extend(_flatten_exc(sub))
        else:
            from traceback import TracebackException
            te = TracebackException.from_exception(e)
            msgs.append(f"{type(e).__name__}: {''.join(te.format_exception_only()).strip()}")
    except Exception:
        msgs.append(f"{type(e).__name__}: {e}")
    return msgs

async def main():
    # Usa servers.yaml por defecto
    servers_yaml = os.path.join(os.path.dirname(os.path.dirname(__file__)), "servers.yaml")
    import yaml
    cfg = yaml.safe_load(open(servers_yaml, "r", encoding="utf-8"))
    fs = cfg["filesystem"]

    cmd = fs.get("command") or "node"
    args = fs.get("args") or []
    if shutil.which(cmd) is None:
        print(json.dumps({"ok": False, "error": "command_not_found", "detail": f"{cmd} no está en PATH"}))
        return

    params = StdioServerParameters(
        command=cmd,
        args=args,
        env={**os.environ, "FORCE_COLOR":"0", "NO_COLOR":"1"}  # minimiza banners
    )

    try:
        async with stdio_client(params) as (read, write):
            session = ClientSession(read, write)
            await asyncio.wait_for(session.initialize(), timeout=15)
            tools = await session.list_tools()
            print(json.dumps({"ok": True, "tools": [t.name for t in tools.tools]}, ensure_ascii=False, indent=2))
    except BaseException as e:
        print(json.dumps({"ok": False, "error": "stdio_start_failed", "detail": " | ".join(_flatten_exc(e))}, ensure_ascii=False, indent=2))

if __name__ == "__main__":
    asyncio.run(main())
