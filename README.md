# Proyecto 1 — Chatbot con MCP + Servidor MCP propio (PortHunter)

> **Resumen**: Este repositorio implementa un **chatbot** que se conecta a un **LLM vía OpenRouter**, mantiene **contexto de conversación**, registra un **log JSONL** de todas las interacciones con **servidores MCP**, integra servidores MCP **oficiales** (Filesystem y Git), y expone un **servidor MCP propio** llamado **PortHunter**, que analiza **PCAP/PCAPNG** para detectar **port scans** (SYN/FIN/NULL/Xmas), reporta **primer evento**, calcula **sospechosos** (vertical/horizontal) y realiza **enriquecimiento TI** (OTX/GreyNoise/ASN/Geo) con **caché local**.

---

## Tabla de contenidos

* [Objetivos de la entrega](#objetivos-de-la-entrega)
* [Arquitectura](#arquitectura)
* [Estructura del repositorio](#estructura-del-repositorio)
* [Requisitos](#requisitos)
* [Instalación y configuración](#instalación-y-configuración)

  * [.env: variables](#env-variables)
  * [Dependencias](#dependencias)
* [Ejecución](#ejecución)

  * [Smoke test LLM (punto 1)](#smoke-test-llm-punto-1)
  * [Chat con memoria (punto 2)](#chat-con-memoria-punto-2)
  * [Logs MCP (punto 3)](#logs-mcp-punto-3)
  * [MCP oficiales: Filesystem + Git (punto 4)](#mcp-oficiales-filesystem--git-punto-4)
* [Servidor MCP propio: PortHunter (punto 5)](#servidor-mcp-propio-porthunter-punto-5)

  * [Qué hace PortHunter](#qué-hace-porthunter)
  * [Instalación del server MCP](#instalación-del-server-mcp)
  * [Especificación de herramientas (tools)](#especificación-de-herramientas-tools)
  * [Generar un PCAP con Wireshark](#generar-un-pcap-con-wireshark)
  * [Comandos de uso (desde el chatbot)](#comandos-de-uso-desde-el-chatbot)
  * [Enriquecimiento (OTX, GreyNoise, ASN, Geo)](#enriquecimiento-otx-greynoise-asn-geo)
  * [Caché local](#caché-local)
* [Logs y evidencia](#logs-y-evidencia)
* [Solución de problemas](#solución-de-problemas)
* [Seguridad y privacidad](#seguridad-y-privacidad)
* [Mapa de calificación (1–5)](#mapa-de-calificación-1–5)
* [Trabajo futuro](#trabajo-futuro)

---

## Objetivos de la entrega

**Parte 1 (esta entrega)** demuestra:

1. **Conexión a LLM** por API (OpenRouter) y respuesta a preguntas generales.
2. **Memoria de sesión**: mantiene contexto entre turnos.
3. **Log JSONL** de interacciones con **MCP**.
4. **Uso de MCP oficiales (Anthropic)**: Filesystem MCP y Git MCP.
5. **Servidor MCP propio** ejecutándose localmente (**PortHunter**), con especificación, uso y ejemplos.

---

## Arquitectura

* **app/**: CLI del chatbot (Python) + cliente LLM, memoria y cliente MCP.
* **server/porthunter\_mcp/**: paquete instalable del servidor MCP **PortHunter** (stdio via FastMCP).
* **MCP oficiales**: se consumen vía cliente stdio (filesystem/git) para tareas de demo.
* **Logs**: `logs/chat/*.jsonl` y `logs/mcp/mcp-YYYYMMDD.jsonl`.

Flujo principal:

1. `app/main.py` levanta la CLI, muestra comandos y gestiona el estado de conversación.
2. Mensajes al LLM se envían a través de **OpenRouter** (modelo configurable).
3. Comandos `/mcp-*` llaman tools de MCP (oficiales y propio) y registran en **MCP logger**.

---

## Estructura del repositorio

```text
Proyecto1-Redes-Protocolos/
├─ app/
│  ├─ config.py                     # Configuración (LLM, timeouts, etc.)
│  ├─ main.py                       # CLI del chatbot (comandos y flujo)
│  ├─ llm/
│  │  ├─ openrouter_client.py       # Cliente OpenRouter (requests)
│  │  └─ memory.py                  # Memoria de conversación (pila de mensajes)
│  └─ mcp/
│     ├─ clients.py                 # Conexión stdio a MCP (filesystem, git, porthunter)
│     ├─ fs_client.py               # Demo Filesystem+Git (init repo, write README, commit)
│     └─ logger.py                  # MCPLogger → logs/mcp/*.jsonl
├─ server/porthunter_mcp/
│  ├─ pyproject.toml                # Paquete instalable (mcp, scapy, requests, ipwhois)
│  ├─ porthunter/
│  │  ├─ server.py                  # FastMCP server (stdio) con tools reales
│  │  └─ utils/
│  │     ├─ pcap.py                 # Análisis PCAP/PCAPNG con Scapy
│  │     ├─ cache.py                # Caché JSON con TTL para enriquecimiento
│  │     └─ intel/
│  │        ├─ otx.py               # Enriquecimiento OTX (IPv4/IPv6)
│  │        ├─ greynoise.py         # Enriquecimiento GreyNoise (Community)
│  │        ├─ asn.py               # ASN/Org (RDAP con ipwhois)
│  │        └─ geo.py               # (Opcional) GeoLite2 City/Country
│  └─ mcp.json                      # Especificación MCP de PortHunter
├─ captures/                        # Carpeta sugerida para tus PCAP/PCAPNG
└─ logs/
   ├─ chat/
   └─ mcp/
```

---

## Requisitos

* **Python ≥ 3.10** (Windows/macOS/Linux)
* Cuenta **OpenRouter** + **API key**
* (Opcional) **Wireshark** para generar PCAP/PCAPNG
* (Opcional) **nmap** para generar tráfico tipo escaneo (`-sS`)
* (Opcional) **MaxMind GeoLite2-City.mmdb** si quieres país/ciudad offline
* (Opcional) Llaves **OTX** y **GreyNoise Community** para enriquecimiento TI

---

## Instalación y configuración

Clona el repo y crea un entorno virtual (opcional).

### .env: variables

Crea un archivo **`.env`** en la raíz del proyecto con (solo ejemplos; *no* subas keys reales):

```ini
# LLM (OpenRouter)
OPENROUTER_API_KEY=sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
OPENROUTER_MODEL=qwen/qwen3-coder:free
APP_TITLE=Proyecto1-Redes-Protocolos
REQUEST_TIMEOUT_SECONDS=60

# Enriquecimiento (opcionales)
OTX_API_KEY=
GREYNOISE_API_KEY=
GEOIP_DB_PATH=C:\Data\GeoLite2\GeoLite2-City.mmdb
PORT_HUNTER_CACHE_TTL_DAYS=7
```

### Dependencias

Instala el servidor MCP **PortHunter** (editable):

```bash
cd server/porthunter_mcp
pip install -e .
```

> Esto instala `mcp`, `scapy`, `requests`, `ipwhois` y opcionalmente `geoip2` (si activas el extra `geo`).

---

## Ejecución

Desde la raíz del proyecto:

```bash
python -m app.main
```

La CLI mostrará los comandos disponibles.

### Smoke test LLM (punto 1)

* Escribe: `¿Quién fue Alan Turing?`
* Debe responder. También puedes ejecutar `python -m app.smoke_test_openrouter` si el script está incluido.

### Chat con memoria (punto 2)

* `¿Quién fue Alan Turing?`
* `¿En qué fecha nació?`
* Debe entender que la **segunda** se refiere a Turing (mismo contexto de sesión).

### Logs MCP (punto 3)

* `/mcp-dryrun` → escribe una entrada en `logs/mcp/mcp-YYYYMMDD.jsonl`.
* `/mcp-log` → imprime el tail (últimas 10 líneas) del log MCP.

### MCP oficiales: Filesystem + Git (punto 4)

* `/mcp-demo-git` → crea carpeta `mcp_demo_repo`, `README.md`, añade y hace *commit*.
* `/mcp-log` → verás `git_init`, `write_file`, `git_add`, `git_commit`, `git_log`.

---

## Servidor MCP propio: PortHunter (punto 5)

### Qué hace PortHunter

Analiza **PCAP/PCAPNG** con **Scapy** para identificar patrones de escaneo:

* **SYN scan** (SYN sin ACK),
* **FIN scan**, **NULL scan**, **Xmas scan**.

Genera:

* **Overview**: top *scanners*, *targets*, distribución de puertos y patrones detectados.
* **Primer evento**: primera ocurrencia cronológica con `scanner/target/port/flags`.
* **Sospechosos**: ranking con **vertical score** (muchos **puertos**) y **horizontal score** (muchos **hosts**).
* **Enriquecimiento TI** (opcional): OTX, GreyNoise, ASN/RDAP, GeoLite2.
* **Correlación**: `threat_score` 0–100 combinando señales externas y ASN.

> PortHunter corre como servidor **MCP stdio** vía **FastMCP** y es invocado por la CLI con `/porthunter-*`.

### Instalación del server MCP

Ya cubierta por `pip install -e .` en `server/porthunter_mcp`. Para probarlo solo:

```bash
python -m porthunter.server   # (queda a la escucha por STDIO; opcional, el cliente lo lanza)
```

### Especificación de herramientas (tools)

(Ver `server/porthunter_mcp/mcp.json`). Resumen:

* **scan\_overview** `{ path, time_window_s=60, top_k=20 } → { total_pkts, interval_s, scanners[], targets[], port_distribution[], suspected_patterns[] }`
* **first\_scan\_event** `{ path } → { t_first, scanner, pattern, target, port, detail }`
* **list\_suspects** `{ path, min_ports=10, min_rate_pps=5 } → { suspects[] }`
* **enrich\_ip** `{ ip } → { otx, greynoise, asn, geo }` *(omite IPs no globales: privadas, loopback, test-net)*
* **correlate** `{ ips[] } → { results[] }`

### Generar un PCAP con Wireshark

1. Abre **Wireshark** y selecciona la interfaz de red.
2. (Opcional) *Capture filter*: `tcp`
3. Inicia captura.
4. Genera tráfico (ejemplos):

   * Con **nmap**: `nmap -sS -p 22,80,443 127.0.0.1` y `nmap -sS --top-ports 50 127.0.0.1`
   * Sin nmap (PowerShell):

     ```powershell
     for ($p=20; $p -le 30; $p++) { Test-NetConnection 127.0.0.1 -Port $p -InformationLevel Quiet | Out-Null }
     Test-NetConnection 1.1.1.1 -Port 53 | Out-Null
     Test-NetConnection 8.8.8.8 -Port 443 | Out-Null
     ```
5. Detén captura.
6. **Guarda** como **pcapng** (o pcap) en `./captures/`, p. ej.: `captures/scan-demo.pcapng`.
7. (Validación opcional en Wireshark) *Display filter* para ver SYN iniciales:

   * `tcp.flags.syn == 1 && tcp.flags.ack == 0`

### Comandos de uso (desde el chatbot)

Ejecuta la CLI:

```bash
python -m app.main
```

Luego en el prompt del chat:

```text
/porthunter-overview .\captures\scan-demo.pcapng
/porthunter-first .\captures\scan-demo.pcapng
/porthunter-suspects .\captures\scan-demo.pcapng
/porthunter-enrich 8.8.8.8
/porthunter-correlate 8.8.8.8,1.1.1.1
/mcp-log
```

**Notas**:

* Rutas con espacios → usa comillas.
* Extensiones válidas: `.pcap` y `.pcapng`.
* Si pasas un directorio (p. ej. `.`) las tools devuelven estructura vacía (solo para demo).

### Enriquecimiento (OTX, GreyNoise, ASN, Geo)

* **OTX**: usa `X-OTX-API-KEY`. Para IPv6 se llama al endpoint `…/IPv6/{ip}/general`.
* **GreyNoise (Community)**: `GET /v3/community/{ip}`. Para IPv6 puede no haber datos; se devuelve `note`.
* **ASN**: `ipwhois` (RDAP) sin llaves → `asn` y `org`.
* **Geo**: si `GEOIP_DB_PATH` apunta a **GeoLite2-City.mmdb**, devuelve `country` y a veces `city`. Si no, `enabled:false`.
* **IPs no globales** (privadas, loopback, test-net) → `skipped:true`.

### Caché local

* Archivo JSON `_cache.json` junto a `porthunter/server.py`.
* TTL configurable con `PORT_HUNTER_CACHE_TTL_DAYS`.

---

## Logs y evidencia

* **MCP**: `logs/mcp/mcp-YYYYMMDD.jsonl` (cada línea = request/response con `server`, `tool`, `args`, `status`, `result`).
* **Chat**: `logs/chat/session-*.jsonl` (intercambios usuario/asistente, latencia, modelo).

Para ver el log MCP reciente:

```bash
python -m app.main
/mcp-log
```

O abrir manualmente el archivo del día con tu editor.

---

## Trabajo futuro

* Detección avanzada (técnicas híbridas, umbrales adaptativos, ráfagas temporales, UDP scans).
* UI web para visualizar timelines, heatmaps de puertos y comparativas entre PCAPs.
* Persistencia de resultados (SQLite) y reportes en PDF/HTML.
* Integración de más fuentes TI (AbuseIPDB, Shodan, VirusTotal) con *rate limiting* y cachés separados.
* Tests unitarios para `pcap.py` con PCAPs sintéticos pequeños.

---
