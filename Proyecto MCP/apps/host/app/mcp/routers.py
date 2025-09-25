# propósito: wrappers async hacia Filesystem, Git y PortHunter.
from typing import Dict, Any, List

class Routers:
    def __init__(self, sc):
        self.sc = sc  # StdioClient

    # Filesystem
    async def fs_write_file(self, path: str, text: str) -> Dict[str, Any]:
        return await self.sc.call_tool_async("filesystem", "write_file", {"path": path, "content": text})

    # Git
    async def _git_tools(self) -> List[str]:
        try:
            return await self.sc.list_tools_async("git")
        except Exception:
            return []

    async def git_init(self, path: str) -> Dict[str, Any]:
        tools = await self._git_tools()
        if "init" in tools:
            return await self.sc.call_tool_async("git", "init", {"path": path})
        if "git_init" in tools:
            return await self.sc.call_tool_async("git", "git_init", {"repo_path": path})
        if "create_repo" in tools:
            return await self.sc.call_tool_async("git", "create_repo", {"path": path})
        return {"error": f"No encuentro tool de init en Git. Tools: {tools}"}

    async def git_commit(self, path: str, message: str) -> Dict[str, Any]:
        tools = await self._git_tools()
        if "add" in tools:
            await self.sc.call_tool_async("git", "add", {"path": path, "pattern": "."})
        elif "git_add" in tools:
            await self.sc.call_tool_async("git", "git_add", {"repo_path": path, "files": ["."]})
        if "commit" in tools:
            return await self.sc.call_tool_async("git", "commit", {"path": path, "message": message})
        if "git_commit" in tools:
            return await self.sc.call_tool_async("git", "git_commit", {"repo_path": path, "message": message})
        return {"error": f"No encuentro tool de commit en Git. Tools: {tools}"}

    # PortHunter
    async def ph_scan_overview(self, path: str, time_window_s: int = 1, top_k: int = 10):
        return await self.sc.call_tool_async("porthunter", "scan_overview",
                                             {"path": path, "time_window_s": time_window_s, "top_k": top_k})

    async def ph_list_suspects(self, path: str, min_ports: int = 10, min_rate_pps: float = 5.0):
        return await self.sc.call_tool_async("porthunter", "list_suspects",
                                             {"path": path, "min_ports": min_ports, "min_rate_pps": min_rate_pps})

    async def ph_first_event(self, path: str):
        return await self.sc.call_tool_async("porthunter", "first_scan_event", {"path": path})
