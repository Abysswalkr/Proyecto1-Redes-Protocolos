# Proyecto1 – Chatbot MCP (Filesystem + Git + PortHunter) with optional AI Router

> **One-liner:** A terminal chatbot that orchestrates **official MCP servers** (Filesystem & Git) and a **custom MCP server** (PortHunter) from a single REPL. It can use an **LLM (OpenRouter)** to transform natural language into commands, with **robust fallback** that works even if the LLM is unavailable (rate limits, no key, etc.).

* **Runs fully in terminal:** `python -m app.main`
* **Scenario required by the assignment:** create repo → write README → commit (via official MCP Filesystem & Git servers) — already implemented and demonstrated.
* **Non-trivial custom MCP server:** **PortHunter** (pcap/cyber analysis): overview, first event, suspects, enrich IP, correlate.
* **Logs included:**

  * Conversation/session logs: `logs/chat/session-*.jsonl`
  * MCP request/response logs: `logs/mcp/mcp-*.jsonl`

---

## Table of Contents

* [Repository Structure](#repository-structure)
* [Prerequisites](#prerequisites)
* [Installation](#installation)
* [Configuration (.env)](#configuration-env)
* [Run](#run)
* [Usage – Commands](#usage--commands)

  * [Filesystem + Git (official servers)](#filesystem--git-official-servers)
  * [PortHunter (custom MCP server)](#porthunter-custom-mcp-server)
* [Logs](#logs)
* [How classmates can test their MCP servers (Point 6)](#how-classmates-can-test-their-mcp-servers-point-6)
* [Remote MCP server + Wireshark (Points 7 & 8)](#remote-mcp-server--wireshark-points-7--8)
* [Troubleshooting (Windows-friendly)](#troubleshooting-windows-friendly)
* [Spanish Quickstart](#spanish-quickstart)

---

## Repository Structure

```
Proyecto1-Redes-Protocolos/
├─ app/
│  ├─ main.py                 # REPL: PortHunter + Filesystem/Git + optional AI router + logs
│  ├─ cli.py                  # One-shot executor for the mini-DSL (used internally by main.py)
│  ├─ llm/
│  │  ├─ openrouter_client.py # LLM client (already used by earlier versions; main.py now does a direct call)
│  │  └─ memory.py            # Conversation memory (short-term)
│  └─ ...                     # (Keep only files actually used)
│
├─ server/
│  ├─ porthunter_mcp/         # Custom MCP server (PortHunter)
│  │  ├─ porthunter/server.py
│  │  └─ porthunter/utils/...
│  └─ remote_mcp/             # (template to run a remote MCP server; optional for point 7)
│
├─ captures/                  # Put your .pcap / .pcapng test files here
├─ logs/
│  ├─ chat/                   # Session logs (jsonl)
│  └─ mcp/                    # MCP request/response logs (jsonl)
├─ servers.yaml               # (If present) config for server commands (Windows paths quoted)
├─ requirements.txt
├─ pyproject.toml (optional)
└─ README.md  (this file)
```

> **Keep the repo lean:** remove legacy folders you don’t use (e.g. any `mcp_local/**`, old “intent” modules, old `main.py` variants). The current `app/main.py` is your **single entrypoint**.

---

## Prerequisites

* **Python** ≥ 3.11 (tested on 3.12)
* **pip** (and optionally a venv)
* **Node.js** ≥ 20.x (recommended **≥ 20.17**)

  * You do **not** need to install the Filesystem/Git servers globally. You can run them via `npm exec --yes ...` on demand, but having a recent Node helps.
* **(Optional) OpenRouter** account + API key if you want AI routing from natural language.

---

## Installation

```bash
# 1) (Recommended) Create and activate a virtualenv
python -m venv .venv
# Windows PowerShell:
. .venv\Scripts\Activate.ps1
# Linux/macOS:
# source .venv/bin/activate

# 2) Install Python deps
pip install -r requirements.txt
```

> If you plan to run the official MCP servers manually (not required), install Node packages:
>
> ```bash
> npm exec --yes @modelcontextprotocol/server-filesystem -- --help
> npm exec --yes @modelcontextprotocol/server-git -- --help
> ```
>
> (The project will spawn servers by itself; these commands are just to verify availability.)

---

## Configuration (.env)

Create a `.env` file in the repo root. Minimal example:

```dotenv
# ============ PortHunter (custom MCP) ============
PORT_HUNTER_TOKEN=MiTOKENultraSecreto123
PORT_HUNTER_ALLOWED_DIR=./captures
PORT_HUNTER_REQUIRE_TOKEN=true
PORT_HUNTER_MAX_PCAP_MB=200

# Optional threat intel keys (if you have them)
OTX_API_KEY=
GREYNOISE_API_KEY=
# Optional local GeoLite2 (if any)
GEOLITE2_CITY_DB=

# ============ AI Router (optional) ============
# If absent, the REPL still works with direct commands & RegEx:
OPENROUTER_API_KEY=
OPENROUTER_MODEL=openrouter/auto
```

> **Important:** Place your `.pcap/.pcapng` test files inside the folder set in `PORT_HUNTER_ALLOWED_DIR` (default is `./captures`). The REPL validates that paths are **inside** this folder.

---

## Run

```bash
python -m app.main
```

You’ll see a banner with commands. You can:

* Use **slash** commands (PortHunter only)
* Use the **mini-DSL** (Filesystem/Git + PortHunter)
* Write **natural language** (AI router will convert to commands if `OPENROUTER_API_KEY` is set; otherwise parser fallbacks kick in)

---

## Usage – Commands

### Filesystem + Git (official servers)

**Scenario required by the assignment:**

```text
>>> crea repo .\demo_repo
>>> escribe README con "Hola desde mi chatbot MCP" en .\demo_repo
>>> haz commit en .\demo_repo "Initial commit desde MCP"
```

What it does:

* Creates a directory (`demo_repo`) via Filesystem MCP.
* Writes `README.md` via Filesystem MCP.
* Stages & commits via Git MCP.

> The REPL calls your internal `app.cli` for these steps, which itself orchestrates the official servers. Results appear in the terminal and are logged to `logs/mcp/…`.

### PortHunter (custom MCP server)

**Slash commands (always available):**

```
/ph-tools
/ph-info
/ph-overview <file.pcap|pcapng>
/ph-first <file.pcap|pcapng>
/ph-suspects <file.pcap|pcapng> [--min_ports N] [--min_rate R]
/ph-enrich <ip>
/ph-correlate <ip1,ip2,...>
```

**Mini-DSL equivalents:**

```
analiza <file.pcap|pcapng>
primer_evento <file.pcap|pcapng>
sospechosos <file.pcap|pcapng> puertos 5 tasa 2.5
enriquece ip 8.8.8.8
correla 1.1.1.1, 8.8.8.8, 192.168.0.1
```

Notes:

* The REPL will resolve relative paths and ensure they are **inside** `PORT_HUNTER_ALLOWED_DIR`. If not, it will list available pcaps in that folder and ask you to move the file.
* Example:

  ```
  >>> analiza .\captures\scan-demo-20250906-1.pcapng
  ```

---

## Logs

* **Conversation/session:** `logs/chat/session-YYYYMMDD-HHMMSS.jsonl`

  * User input, decisions, command executed, latency, summarized results.
* **MCP requests/responses:** `logs/mcp/mcp-YYYYMMDD-HHMMSS.jsonl`

  * One line per **request** and **response** with `tool`, `args`, `elapsed_ms`, and `result` (normalized to JSON when possible).

These logs are what the assignment means by “keep and show a log of the interactions with MCP servers”.

---

## How classmates can test their MCP servers (Point 6)

You need to integrate **two classmates’ local MCP servers** and show **a scenario** with each.

**Option A (recommended, zero code changes in your repo):**

Ask your classmate for:

* The **start command** for their stdio MCP server (e.g., `python -m teammate.server` or `node dist/index.js`).
* The **tool name** and **arguments** to call.

Then, create a **temporary helper** script (outside your repo if you prefer), for example:

```python
# call_thirdparty.py (temporary helper)
import json, asyncio
from mcp import StdioServerParameters, types
from mcp.client.stdio import stdio_client
from mcp.client.session import ClientSession

async def call_tool(cmd, args, tool, arguments):
    params = StdioServerParameters(command=cmd, args=args)
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            rsp = await session.call_tool(tool, arguments=arguments)
            sc = getattr(rsp, "structuredContent", None)
            if isinstance(sc, dict): return sc
            txt = "".join([b.text for b in rsp.content if isinstance(b, types.TextContent)])
            try: return json.loads(txt)
            except: return {"raw": txt}

async def main():
    # Example: change to your classmate's server + tool + args
    result = await call_tool("python", ["-m","teammate.server"], "ping_host", {"host":"1.1.1.1"})
    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    asyncio.run(main())
```

Run it:

```bash
python call_thirdparty.py
```

Take a **screenshot** + keep the output, and describe briefly the scenario (what tool did, what inputs and outputs were).

**Option B (if you want it inside your REPL):**

* Add a small REPL command like `/tp <cmd> <tool> <json_args>` that wraps the same logic above. Only do this if you will actually use it (avoid adding unused components).

> Either option satisfies Point 6: **two different classmates’ servers** tested with **one or two tools each**, with **evidence** (output/screen).

---

## Remote MCP server + Wireshark (Points 7 & 8)

**Point 7 (Remote MCP server):**
Deploy a simple MCP server (HTTP/SSE or similar) to a cloud platform (Cloud Run, Cloudflare, Railway, etc.). It can be **trivial** (e.g., a time or echo tool), as long as it’s **remote**. Add a small calling snippet in your project (or a script like in Option A) to show a **scenario** calling that remote server. Keep screenshots and copy/paste of outputs.

**Point 8 (Traffic capture & analysis):**
With the remote server running:

1. Start Wireshark and capture while you run your scenario.
2. Filter by port/protocol your server uses (e.g., `tcp.port == 443` if HTTPS).
3. In the **report**, explain:

   * Which packets are **synchronization/initialize** (MCP/JSON-RPC handshake).
   * Which are **request** (call\_tool) and **response** (result/error).
   * What happens at **Application (JSON-RPC/MCP)**, **Transport (TCP)**, **Network (IP)**, **Link (Ethernet/Wi-Fi)** layers.

---

## Troubleshooting (Windows-friendly)

* **OpenRouter 429 (Too Many Requests):** The REPL catches it and **falls back** to local parsing. You can always type the **mini-DSL** directly (e.g., `crea repo ...`, `analiza ...`) and it will work without the LLM.
* **Paths for pcaps:** The REPL will enforce pcaps to be **inside** `PORT_HUNTER_ALLOWED_DIR`. If a path fails, it prints a helpful list of available files there.
* **Async “Event loop is closed” warnings on exit:** Benign on Windows when subprocess stdio closes — they do not affect functionality.
* **Node/npm engine warnings:** Use **Node ≥ 20.17** if you plan to run official servers manually. The project itself can spawn them via `npm exec` without global installs.
* **Tokens/keys:** If `PORT_HUNTER_REQUIRE_TOKEN=true`, ensure `PORT_HUNTER_TOKEN` is set in `.env`. Threat intel keys are optional.

---

## Spanish Quickstart

1. **Instalar dependencias**

   ```powershell
   python -m venv .venv
   . .venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   ```
2. **Crear `.env`** (mínimo):

   ```dotenv
   PORT_HUNTER_TOKEN=MiTOKENultraSecreto123
   PORT_HUNTER_ALLOWED_DIR=./captures
   # Opcional IA:
   OPENROUTER_API_KEY=
   ```
3. **Poner PCAPs** dentro de `./captures`.
4. **Ejecutar**:

   ```powershell
   python -m app.main
   ```
5. **Probar**:

   ```
   >>> crea repo .\demo_repo
   >>> escribe README con "Hola desde mi chatbot MCP" en .\demo_repo
   >>> haz commit en .\demo_repo "Commit inicial"
   >>> analiza .\captures\mi_captura.pcapng
   ```
6. **Ver logs**:

   * Conversación: `logs/chat/session-*.jsonl`
   * Llamadas MCP: `logs/mcp/mcp-*.jsonl`

---

### License

Academic/educational use for the Redes project. Adapt as needed.

---

If you want, I can also add a concise **Tool Spec table** for PortHunter (args/returns, short examples) to this README so your custom server spec is crystal clear for reviewers.
