# Especificación de Servidores MCP del Proyecto

1. **PortHunter MCP (local, análisis de PCAP)** – servidor MCP orientado a seguridad que analiza capturas (`.pcap / .pcapng`) y entrega hallazgos (scanners, patrones, sospechosos, enriquecimiento de IPs, correlación).
2. **Remote Utils MCP (HTTP/SSE)** – servidor MCP remoto (HTTP) con herramientas de demostración (`echo`, `dns_lookup`, `time`) usado para instrumentar y capturar el flujo MCP con Wireshark.

Incluye especificación de **endpoints**, **métodos**, **parámetros**, **formatos de respuesta**, variables de entorno y ejemplos de uso (CLI y HTTP).

---

## Arquitectura (resumen)

```
[Chatbot CLI] --(MCP stdio)--> [PortHunter MCP local]
       |
       +--(HTTP POST + Server-Sent Events)--> [Remote Utils MCP /mcp]
```

* **Protocolo MCP**: JSON-RPC 2.0 sobre transporte MCP.
* **Transporte local**: `stdio` (el chatbot invoca el servidor local como subproceso).
* **Transporte remoto**: HTTP 1.1 con **Server-Sent Events** (SSE) en el endpoint `/mcp`.

---

## 1) PortHunter MCP (Local)

### Propósito

Analizar capturas de red para detectar **patrones de escaneo**, listar **sospechosos**, identificar **primer evento de escaneo**, enriquecer **IPs** con inteligencia externa y **correlacionar** IPs.

### Transporte

* **Tipo**: MCP por **STDIO** (el cliente MCP abre el servidor por stdio).
* Se usa desde el chatbot (no expone HTTP).

### Variables de entorno

Colócalas en `.env` o en tu entorno de sistema (todas opcionales, pero recomendadas para enriquecer resultados):

```
OTX_API_KEY=           # AlienVault OTX 
GREYNOISE_API_KEY=     # GreyNoise (Community/Enterprise key)
GEOIP_DB_PATH=         # Ruta a GeoLite2-City.mmdb (MaxMind)
PORT_HUNTER_CACHE_TTL_DAYS=7
```

> **GeoLite2**: descarga `GeoLite2-City.mmdb` desde MaxMind y apunta `GEOIP_DB_PATH` al archivo.
> Si no hay claves/API/DB, las funciones de enriquecimiento se omiten con un “skipped” controlado.

### Herramientas (tools) expuestas

#### `scan_overview`

* **Descripción**: Resumen de tráfico y posibles patrones de escaneo.
* **Parámetros**:

  * `path: string` – Ruta a la captura (`.pcap/.pcapng`) o carpeta con capturas.
  * `time_window_s?: number` – Ventana de agregación (default: `60`).
  * `top_k?: number` – Límite de resultados por categoría (default: `20`).
* **Respuesta (ejemplo)**:

```json
{
  "result": {
    "total_pkts": 7638,
    "interval_s": 87,
    "scanners": [
      {
        "ip": "192.168.1.7",
        "pkts": 369,
        "distinct_ports": 2,
        "distinct_hosts": 10,
        "flag_stats": {"SYN": 369, "FIN": 0, "PSH": 0, "URG": 0, "RST": 0, "ACK": 0},
        "first_t": "2025-09-06T22:40:41",
        "pattern": "syn_scan"
      }
    ],
    "targets": [{"ip": "8.8.8.8", "hits": 1}],
    "port_distribution": [{"port": 53, "hits": 622}, {"port": 443, "hits": 51}],
    "suspected_patterns": ["syn_scan"],
    "generated_at": "2025-09-06T22:44:23"
  }
}
```

#### `first_scan_event`

* **Descripción**: Primer evento de escaneo detectado.
* **Parámetros**:

  * `path: string`
* **Respuesta (ejemplo)**:

```json
{
  "result": {
    "t_first": "2025-09-06T22:40:41",
    "scanner": "192.168.1.7",
    "pattern": "syn_scan",
    "target": "216.230.139.8",
    "port": 53,
    "detail": "TCP flags=2"
  }
}
```

#### `list_suspects`

* **Descripción**: Lista de IPs sospechosas con evidencia (vertical/horizontal scan).
* **Parámetros**:

  * `path: string`
  * `min_ports?: number` (default: `10`)
  * `min_rate_pps?: number` (default: `5`)
* **Respuesta (ejemplo)**:

```json
{
  "result": {
    "suspects": [
      {
        "scanner": "192.168.1.7",
        "pattern": "syn_scan",
        "vertical_score": 0.17,
        "horizontal_score": 0.83,
        "evidence": {
          "first_t": "2025-09-06T22:40:41",
          "pkts": 369,
          "unique_ports": 2,
          "unique_targets": 10,
          "flag_stats": {"SYN": 369, "FIN": 0, "PSH": 0, "URG": 0, "RST": 0, "ACK": 0}
        }
      }
    ],
    "generated_at": "2025-09-06T22:45:21"
  }
}
```

#### `enrich_ip`

* **Descripción**: Enriquecimiento de IP con ASN/Geo/OTX/GreyNoise (si hay claves y DB).
* **Parámetros**:

  * `ip: string`
* **Respuesta (ejemplos)**:

  * Caso omitido (IP privada o no enrutable):

    ```json
    {"result":{"ip":"203.0.113.5","skipped":true,"reason":"private_or_local","generated_at":"..."}}
    ```
  * Caso enriquecido: incluye campos `asn`, `geo`, `otx`, `greynoise` (según disponibilidad).

#### `correlate`

* **Descripción**: Correlaciona varias IPs y calcula un `threat_score` simplificado.
* **Parámetros**:

  * `ips: string[]`
* **Respuesta (ejemplo)**:

```json
{
  "result": {
    "results": [
      {"ip": "203.0.113.5", "threat_score": 0, "rationale": []},
      {"ip": "198.51.100.10", "threat_score": 0, "rationale": []}
    ],
    "generated_at": "2025-09-06T22:45:55"
  }
}
```

### Uso desde el chatbot (CLI)

* `python -m app.main`
* Comandos:

  * `/porthunter-overview <ruta.pcap>`
  * `/porthunter-first <ruta.pcap>`
  * `/porthunter-suspects <ruta.pcap>`
  * `/porthunter-enrich <ip>`
  * `/porthunter-correlate <ip1,ip2,...>`

---

## 2) Remote Utils MCP (HTTP / SSE)

### Propósito

Servidor MCP remoto minimalista para demostrar el **handshake MCP** (`initialize`), **tools/list** y **tools/call** vía **HTTP POST** con **SSE**. Útil para instrumentación con Wireshark.

### Arranque

```bash
cd server/remote_mcp
python -m remote_utils.server
# Uvicorn en http://127.0.0.1:8080
```

### Endpoints

#### `GET /health`

* **200 OK** si el servicio está vivo.

#### `POST /mcp`

* **Contenido**: `application/json`
* **Respuesta**: **SSE** (`text/event-stream`) con eventos `event: message` que contienen objetos JSON-RPC.
* **Protocolo**: JSON-RPC 2.0 con los métodos MCP:

  * `initialize`
  * `tools/list`
  * `tools/call`

> **Nota**: La conexión es de petición-respuesta “larga” con SSE. Cada POST produce uno o más `event: message` hasta terminar.

### Herramientas expuestas

* `echo(text: string)` → repite el mismo texto.
* `dns_lookup(host: string)` → resuelve el host a una lista de `addresses`.
* `time()` → retorna fecha/hora UTC en ISO-8601.

### Ejemplos de intercambio MCP (HTTP/SSE)

#### 2.1 `initialize`

**Request**

```json
{
  "jsonrpc": "2.0",
  "id": 0,
  "method": "initialize",
  "params": {
    "protocolVersion": "2025-06-18",
    "capabilities": {},
    "clientInfo": { "name":"mcp_local", "version":"0.1.0" }
  }
}
```

**Respuesta (SSE, evento `message`)**

```json
{
  "jsonrpc": "2.0",
  "id": 0,
  "result": {
    "protocolVersion": "2025-06-18",
    "capabilities": {"experimental": {}},
    "prompts": {"listChanged": false},
    "resources": {"subscribe": false, "listChanged": false},
    "tools": {"listChanged": false},
    "serverInfo": {"name": "remote-utils", "version": "1.13.1"}
  }
}
```

#### 2.2 `tools/list`

**Request**

```json
{ "jsonrpc":"2.0", "id": 1, "method":"tools/list", "params": {} }
```

**Respuesta (SSE)**
Devuelve el inventario de herramientas (al menos `echo`, `dns_lookup`, `time`) con su firma/argumentos.

#### 2.3 `tools/call` → `echo`

**Request**

```json
{
  "jsonrpc":"2.0",
  "id": 1,
  "method":"tools/call",
  "params":{
    "name":"echo",
    "arguments":{"text":"hola"}
  }
}
```

**Respuesta (SSE)**

```json
{
  "jsonrpc":"2.0",
  "id": 1,
  "result": {
    "content": [{"type":"text", "text":"hola"}],
    "structuredContent": {"result":"hola"},
    "isError": false
  }
}
```

#### 2.4 `tools/call` → `dns_lookup`

**Request**

```json
{
  "jsonrpc":"2.0",
  "id": 1,
  "method":"tools/call",
  "params":{
    "name":"dns_lookup",
    "arguments":{"host":"uvg.edu.gt"}
  }
}
```

**Respuesta (SSE)**

```json
{
  "jsonrpc":"2.0",
  "id": 1,
  "result": {
    "content": [
      {"type":"text", "text":"{\n  \"host\": \"uvg.edu.gt\",\n  \"addresses\": [\n    \"45.223.155.41\",\n    \"45.223.56.41\"\n  ]\n}"}
    ],
    "isError": false
  }
}
```

#### 2.5 `tools/call` → `time`

**Request**

```json
{ "jsonrpc":"2.0", "id": 1, "method":"tools/call", "params":{ "name":"time", "arguments":{} } }
```

**Respuesta (SSE)**

```json
{
  "jsonrpc":"2.0",
  "id": 1,
  "result": {
    "content": [{"type":"text", "text":"2024-12-19T15:30:45Z"}],
    "isError": false
  }
}
```

### Prueba con `curl`

> `-N` evita el buffering y permite ver los eventos SSE.

```bash
# initialize
curl -N -H "content-type: application/json" \
  --data '{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"curl","version":"0.1"}}}' \
  http://127.0.0.1:8080/mcp

# tools/list
curl -N -H "content-type: application/json" \
  --data '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' \
  http://127.0.0.1:8080/mcp

# tools/call echo
curl -N -H "content-type: application/json" \
  --data '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hola"}}}' \
  http://127.0.0.1:8080/mcp
```

### Uso desde el chatbot (CLI)

* Arranca el servidor remoto: `python -m remote_utils.server`
* En el chatbot:

  ```text
  /remote-set http://127.0.0.1:8080/mcp
  /remote-list
  /remote-echo hola
  /remote-dns uvg.edu.gt
  /remote-time
  ```

---

## Carpeta de evidencia (Wireshark)

* **Capturas**: `captures/remote_mcp/remote_mcp-YYYYMMDD-HHMM.pcapng`
* **Marcados**: exporta los paquetes marcados a `*-marked.pcapng`.
* **Streams**: opcionalmente guarda los **Follow TCP Stream** de `echo`, `dns_lookup`, `time` en `docs/evidence/`.

Filtros útiles:

* Solicitudes MCP: `tcp.port == 8080 && http.request.method == "POST" && frame contains "\"method\":\"tools/call\""`
* Respuestas SSE: `tcp.port == 8080 && http.response.code == 200 && http.content_type contains "event-stream"`
* Por `tcp.stream`: añade `&& tcp.stream == <N>` para aislar cada intercambio.

---

## Instalación / Desarrollo

### Requisitos

* Python 3.12+
* `pip install -r requirements.txt`
* (Opcional) GeoLite2 y claves OTX / GreyNoise.

### PortHunter MCP (local)

```bash
cd server/porthunter_mcp
pip install -e .
# Se usa automáticamente desde el chatbot (stdio). No requiere puerto.
```

### Remote Utils MCP (HTTP)

```bash
cd server/remote_mcp
python -m remote_utils.server
# 127.0.0.1:8080
```

---

## Notas de diseño

* **SSE**: las respuestas se entregan como `event: message` con `data: <json>`.
* **JSON-RPC**: todos los métodos usan `jsonrpc: "2.0"` y un `id` correlacionable.
* **Robustez**: el servidor local omite enriquecimientos si faltan claves/DB y retorna banderas `skipped`/`reason`.
* **Privacidad**: IPs privadas o no enroutables no se envían a servicios externos.

---

## Licencia y créditos

* Geo datos: **MaxMind GeoLite2** (requiere cuenta gratuita y aceptación de licencia).
* OTX y GreyNoise: requieren **API keys** y respetar sus términos de uso.
* Este proyecto es educativo y para fines académicos.

---

### Apéndice: Tabla rápida de métodos y parámetros

| Servidor   | Método                    | Parámetros                                                    | Respuesta (resumen)                                  |
| ---------- | ------------------------- | ------------------------------------------------------------- | ---------------------------------------------------- |
| PortHunter | `scan_overview`           | `path: string`, `time_window_s?: number`, `top_k?: number`    | Totales, scanners, targets, puertos, patrones        |
| PortHunter | `first_scan_event`        | `path: string`                                                | `t_first`, `scanner`, `pattern`, `target`, `port`    |
| PortHunter | `list_suspects`           | `path: string`, `min_ports?: number`, `min_rate_pps?: number` | Lista de sospechosos con evidencia                   |
| PortHunter | `enrich_ip`               | `ip: string`                                                  | ASN/Geo/OTX/GreyNoise (o `skipped` con `reason`)     |
| PortHunter | `correlate`               | `ips: string[]`                                               | `results[] {ip, threat_score, rationale[]}`          |
| Remote     | `tools/list`              | —                                                             | Inventario de herramientas                           |
| Remote     | `tools/call`→`echo`       | `name:"echo"`, `arguments:{text:string}`                      | Texto eco                                            |
| Remote     | `tools/call`→`dns_lookup` | `name:"dns_lookup"`, `arguments:{host:string}`                | `{host, addresses[]}`                                |
| Remote     | `tools/call`→`time`       | `name:"time"`, `arguments:{}`                                 | ISO UTC                                              |
| Remote     | `initialize`              | `protocolVersion, capabilities, clientInfo`                   | `serverInfo`, `capabilities`, banderas `listChanged` |
