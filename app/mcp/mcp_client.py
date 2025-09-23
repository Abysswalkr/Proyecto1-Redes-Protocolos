import asyncio
import os
from app.mcp.mcp_client import MCPMuxClient


async def run(repo_dir: str):
    client = MCPMuxClient(fs_roots=["."])
    await client.start()
    try:
        # 1) Crear carpeta del repo (Filesystem)
        if not os.path.exists(repo_dir):
            os.makedirs(repo_dir, exist_ok=True)

        # 2) Crear README.md (Filesystem)
        readme_path = os.path.join(repo_dir, "README.md")
        res = await client.filesystem_write_file(readme_path, "# Demo MCP\n\nHola desde MCP.\n")
        print("WRITE:", res["data"]["content"][0]["text"] if res.get("success") else res["error"])

        # 3) git init (Git)
        res = await client.git_init(repo_dir)
        print("INIT:", res["data"]["content"][0]["text"] if res.get("success") else res["error"])

        # 4) git add README.md (Git)
        res = await client.git_add(repo_dir, ["README.md"])
        print("ADD:", res["data"]["content"][0]["text"] if res.get("success") else res["error"])

        # 5) git commit (Git)
        res = await client.git_commit(repo_dir, "Initial commit desde MCP")
        print("COMMIT:", res["data"]["content"][0]["text"] if res.get("success") else res["error"])

        # 6) Mostrar log (Git)
        res = await client.git_log(repo_dir, 5)
        print("LOG:\n", res["data"]["content"][0]["text"] if res.get("success") else res["error"])

    finally:
        await client.close()

if __name__ == "__main__":
    import sys
    repo = sys.argv[1] if len(sys.argv) > 1 else "./demo_repo"
    asyncio.run(run(repo))
