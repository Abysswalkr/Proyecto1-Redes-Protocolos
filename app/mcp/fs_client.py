from pathlib import Path
from typing import List, Dict, Any

from app.mcp.logger import MCPLogger
from app.mcp.clients import filesystem_params, git_params, call_tool

def run_demo_create_repo(base_dir: str = "mcp_demo_repo") -> List[str]:
    """
    Demostración Punto 4:
      1) Filesystem.create_directory <base_dir>
      2) Git.git_init <base_dir>
      3) Filesystem.write_file <base_dir>/README.md
      4) Git.git_add [<base_dir>/README.md]
      5) Git.git_commit "Initial commit"
    Devuelve un resumen de pasos ejecutados.
    """
    out_lines: List[str] = []
    logger = MCPLogger(log_dir="logs/mcp")

    repo_path = Path(base_dir).resolve()
    fs_allowed = [str(repo_path.parent)]  # permitimos como mínimo el padre

    fs_params = filesystem_params(fs_allowed)
    git_srv   = git_params()

    # 1) create_directory
    args = {"path": str(repo_path)}
    corr = logger.log_request("filesystem", "create_directory", args)
    try:
        text, data = call_tool(fs_params, "create_directory", args)
        logger.log_response(corr, "filesystem", "create_directory", "ok", result={"text": text, "data": data})
        out_lines.append(f"✔ Carpeta creada: {repo_path}")
    except Exception as e:
        logger.log_response(corr, "filesystem", "create_directory", "error", error=str(e))
        raise

    # 2) git_init
    args = {"repo_path": str(repo_path)}
    corr = logger.log_request("git", "git_init", args)
    try:
        text, data = call_tool(git_srv, "git_init", args)
        logger.log_response(corr, "git", "git_init", "ok", result={"text": text, "data": data})
        out_lines.append("✔ Repo inicializado con git_init")
    except Exception as e:
        logger.log_response(corr, "git", "git_init", "error", error=str(e))
        raise

    # 3) write_file README.md
    readme_path = repo_path / "README.md"
    args = {"path": str(readme_path), "content": "# Demo MCP\n\nRepo creado por tools MCP.\n"}
    corr = logger.log_request("filesystem", "write_file", args)
    try:
        text, data = call_tool(fs_params, "write_file", args)
        logger.log_response(corr, "filesystem", "write_file", "ok", result={"text": text, "data": data})
        out_lines.append(f"✔ README.md creado en {readme_path}")
    except Exception as e:
        logger.log_response(corr, "filesystem", "write_file", "error", error=str(e))
        raise

    # 4) git_add
    args = {"repo_path": str(repo_path), "files": [str(readme_path)]}
    corr = logger.log_request("git", "git_add", args)
    try:
        text, data = call_tool(git_srv, "git_add", args)
        logger.log_response(corr, "git", "git_add", "ok", result={"text": text, "data": data})
        out_lines.append("✔ git add README.md")
    except Exception as e:
        logger.log_response(corr, "git", "git_add", "error", error=str(e))
        raise

    # 5) git_commit
    args = {"repo_path": str(repo_path), "message": "Initial commit (via MCP)"}
    corr = logger.log_request("git", "git_commit", args)
    try:
        text, data = call_tool(git_srv, "git_commit", args)
        logger.log_response(corr, "git", "git_commit", "ok", result={"text": text, "data": data})
        out_lines.append("✔ git commit -m \"Initial commit (via MCP)\"")
    except Exception as e:
        logger.log_response(corr, "git", "git_commit", "error", error=str(e))
        raise

    # muestra log de commits brevemente
    try:
        args = {"repo_path": str(repo_path), "max_count": 3}
        corr = logger.log_request("git", "git_log", args)
        text, data = call_tool(git_srv, "git_log", args)
        logger.log_response(corr, "git", "git_log", "ok", result={"text": text, "data": data})
        out_lines.append(f"ℹ Últimos commits: {text or data}")
    except Exception:
        pass

    return out_lines
