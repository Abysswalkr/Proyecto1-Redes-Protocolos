# Proyecto MCP

**Propósito:** Un host MCP en consola que orquesta un LLM y múltiples servidores MCP (Filesystem, Git, PortHunter y un servidor remoto HTTP) para analizar PCAPs, generar reportes reproducibles y versionarlos en un repositorio.

## Resumen del proyecto

Este host implementa:

* **Chat con LLM** (OpenRouter/OpenAI SDK) con memoria de sesión.
* **Servidores MCP locales**:

  * **Filesystem** (npx @modelcontextprotocol/server-filesystem) para lectura/escritura.
  * **Git** (mcp-server-git) para `init / add / commit`.
  * **PortHunter** (servidor propio) para **análisis de PCAP** (SYN/FIN/NULL/Xmas, vertical vs. horizontal, primer evento).
* **Servidor MCP remoto (HTTP/SSE)**: **Trivia**, utilizado desde el chat.

### ¿Por qué MCP?

Porque separa responsabilidades: el **host** enruta intents y llama **tools** vía JSON-RPC; los **servers** ejecutan funciones y devuelven resultados estructurados. En remoto (HTTP) se observan respuestas **HTTP/1.1 200 OK** con **content-type: text/event-stream (SSE)**; en nuestra evidencia capturada puede verse exactamente ese patrón. 
El informe técnico adjunto documenta handshake (`initialize`), `tools/list` y `tools/call` con filtros reproducibles de Wireshark y análisis por capas (L2–L7). 

## Arquitectura (MCP)

```
                ┌──────────────────────────┐
                │        LLM (OpenRouter)  │
                └──────────────┬───────────┘
                               │
                  (host/chat + orquestación)
                               │  JSON-RPC
┌───────────────────────────────┼──────────────────────────────────────┐
│                               │                                      │
│                          STDIO│                                 HTTP/SSE
│                               │                                      │
│                    ┌──────────▼───────────┐                 ┌────────▼─────────┐
│                    │  PortHunter (local)  │                 │  Trivia (remoto) │
│                    │  scan/list/first     │                 │  random/check    │
│                    └──────────┬───────────┘                 └────────┬─────────┘
│                               │ STDIO                                  │ HTTP/1.1 200 OK
│           ┌───────────────────▼───────────┐            text/event-stream (SSE)  │
│           │ Filesystem (local, Node/npx)  │<───────────────┐                    │
│           └───────────────────┬───────────┘                │                    │
│                               │                            │                    │
│                    ┌──────────▼────────┐                   │                    │
│                    │     Git (local)   │                   │                    │
│                    └────────────────────┘                   └────────────────────┘
└──────────────────────────────────────────────────────────────────────────────────┘
```

## Quickstart (5 minutos)

### 0) Prerrequisitos

* **Python** ≥ 3.11 (recomendado 3.12)
* **Node.js + npx** (para el servidor Filesystem)
* **pip** / **pipx** instalados

### 1) Instalación

```bash
git clone <este-repo>
cd <este-repo>
pip install -e .
# Opcional (recomendado para servidores):
pip install fastmcp scapy mcp-server-git
```

### 2) Variables de entorno mínimas

Crea `.env` en la raíz (o usa `.env.example`):

```env
# LLM
OPENROUTER_API_KEY=sk-or-...

# PortHunter (seguridad)
PORT_HUNTER_ALLOWED_DIR=.
PORT_HUNTER_REQUIRE_TOKEN=false
PORT_HUNTER_TOKEN=changeme
```

### 3) Arranque del host con servidores locales (perfil)

```bash
python -m apps.host.app.main --servers apps/host/profiles/servers.full_local.yaml
```

Al iniciar verás el inventario de tools MCP (filesystem/git/porthunter). El REPL acepta comandos y también frases en lenguaje natural para la macro (“analiza … readme … repo …”).

## Demos rápidas (copiar/pegar)

### 1) Análisis de PCAP (PortHunter)

```bash
# Resumen
analiza ./servers/porthunter/samples/nmap_syn_scan.pcap

# Sospechosos con impresión de pattern/scores/flag_stats
sospechosos ./servers/porthunter/samples/nmap_syn_scan.pcap puertos 5 tasa 0.1

# Primer evento enriquecido (ISO/patrón/detalle)
primer_evento ./servers/porthunter/samples/nmap_syn_scan.pcap
```

### 2) Flujo FS + Git oficiales (orquestado por la macro)

```bash
# Analiza → detecta sospechosos → genera README → init+add+commit (Git)
analiza ./servers/porthunter/samples/nmap_syn_scan.pcap y en base a ese análisis dime si hay puertos sospechosos y cuáles son. Luego escribe un README y crea un repositorio con el nombre ./repo-porthunter-demo

# (equivalente explícito)
analiza_y_repo ./servers/porthunter/samples/nmap_syn_scan.pcap ./repo-porthunter-demo puertos 10 tasa 0.1
```

La macro usa **Filesystem** para escribir `README.md` y **Git** para `init/add/commit`, dejando todo trazado en los **logs MCP**.

### 3) Llamada al servidor **remoto** (Trivia, HTTP/SSE)

> Una vez desplegado (Railway/Cloud Run), añade su URL en tu perfil `profiles/local+remote.yaml`.

```bash
# Iniciar pregunta
trivia
# Responder (letra, índice o texto exacto)
trivia responder A
```

Tu captura marcada muestra una respuesta **HTTP/1.1 200 OK** con **`text/event-stream`**, típico de SSE para resultados de `tools/call` en servidores MCP HTTP. 
El **informe técnico** describe filtros reproducibles para `initialize`, `tools/list` y `tools/call` (echo/dns/time), así como el análisis por capas de red. 

## Rutas de logs y trazabilidad

* **MCP (JSONL):** `apps/host/logs/mcp/*.jsonl`
  Cada `tools/call` queda registrado (request/response JSON-RPC).
* **Host/Chat:** `apps/host/logs/host/` y `apps/host/logs/chat/`
  Historial conversacional por sesión y salidas del host.

Ejemplos: verás eventos `tools/list`, `tools/call` y consolidado de decisiones (qué comando invocaste, con qué argumentos).

## Enlaces MCP (obligatorios)

* Intro: [https://modelcontextprotocol.io/docs/getting-started/intro](https://modelcontextprotocol.io/docs/getting-started/intro)
* Arquitectura: [https://modelcontextprotocol.io/docs/learn/architecture](https://modelcontextprotocol.io/docs/learn/architecture)
* Server concepts: [https://modelcontextprotocol.io/docs/learn/server-concepts](https://modelcontextprotocol.io/docs/learn/server-concepts)
* Client concepts: [https://modelcontextprotocol.io/docs/learn/client-concepts](https://modelcontextprotocol.io/docs/learn/client-concepts)
* Quickstarts/SDKs: [https://modelcontextprotocol.io/quickstart/server](https://modelcontextprotocol.io/quickstart/server)
* Especificación vigente: [https://modelcontextprotocol.io/specification](https://modelcontextprotocol.io/specification)
* Ejemplos/repos oficiales: [https://github.com/modelcontextprotocol/servers](https://github.com/modelcontextprotocol/servers)

> Estas referencias sustentan el modelo Host↔Servers, el transporte STDIO/HTTP y la mensajería **JSON-RPC** que tu proyecto implementa de extremo a extremo.

## Estructura del repo (resumen)

```
.
├─ apps/host/                 # Host MCP (REPL, comandos, chat con memoria)
│  ├─ app/
│  │  ├─ main.py              # entrypoint (REPL)
│  │  ├─ commands.py          # orquestador (analiza/sospechosos/reporte/trivia/...)
│  │  ├─ llm.py               # cliente LLM (OpenRouter)
│  │  └─ chat/                # memoria y manager del chat
│  ├─ logs/                   # logs host + MCP (JSONL)
│  └─ profiles/               # perfiles YAML (full_local, local+remote)
├─ servers/
│  ├─ official/               # wrappers para Filesystem/Git locales
│  ├─ porthunter/             # servidor MCP propio (PCAP)
│  │  ├─ server.py            # tools: scan_overview/list_suspects/first_scan_event
│  │  └─ samples/             # PCAPs de prueba (nmap SYN, etc.)
│  └─ remote/trivia_http/     # servidor remoto (FastMCP HTTP/SSE)
├─ profiles/                  # perfiles alternos (ej. local+remote.yaml)
├─ captures/                  # capturas Wireshark de referencia
└─ scripts/                   # diagnósticos e integración (diag_mcp, demo_end2end)
```

* **`servers/porthunter`**: Detecta **SYN/FIN/NULL/Xmas**, clasifica **vertical**/**horizontal** (scores), y expone **evidencia** (`flag_stats`, `pps`, `unique_ports/targets`, `t_first` ISO).
* **Evidencia Wireshark (SSE/HTTP)**: ver `captures/*` y anexos marcados.  

## Roadmap / Estado

* ✅ Host REPL + FS/Git + PortHunter + Trivia local
* ✅ Logs MCP (JSONL) + memoria de chat
* ✅ Detecciones PortHunter (SYN/FIN/NULL/Xmas; vertical/horizontal + evidence)
* 🔜 Despliegue remoto (Railway/Cloud Run) del servidor Trivia
* 🔜 Captura y análisis HTTP/SSE en nube (Wireshark/tcpdump)
* 🔜 README de cada submódulo y pruebas extendidas

**Versión:** `v0.9.0` — **Fecha:** 2025-09-25

## Licencia

MIT © 2025 — Proyecto académico (UVG). Créditos: equipo del curso Redes (ver commits).

---

### Anexos (referencias internas)

* **HTTP/SSE 200 OK (evento):** extracto de `remote_mcp-20250917-0933-marked.txt` (Wireshark “Follow TCP stream”) con `HTTP/1.1 200 OK` y `content-type: text/event-stream`. 
* **Informe técnico (P10):** metodología, filtros reproducibles (`initialize`, `tools/list`, `tools/call`) y análisis por capas (L2–L7). 
