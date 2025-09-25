# PortHunter — Reporte

- Fecha de reporte (UTC): 2025-09-25T08:33:59+00:00

- Archivo analizado: `./captures/remote_mcp-20250917-0933.pcapng`

- Paquetes totales: **550** (TCP 545 / UDP 0)

## Puertos más activos

- tcp/8080: 127
- tcp/1042: 36
- tcp/52315: 27
- tcp/52321: 27
- tcp/52327: 27
- tcp/52316: 26
- tcp/52322: 26
- tcp/52328: 26
- tcp/50100: 20
- tcp/49692: 20

## Primer evento

- ISO: n/a
- Patrón: n/a


## Sospechosos

_Sin sospechosos con los umbrales actuales._

---
### Comandos utilizados

- `porthunter.scan_overview("./captures/remote_mcp-20250917-0933.pcapng")`
- `porthunter.list_suspects("./captures/remote_mcp-20250917-0933.pcapng", min_ports=10, min_rate_pps=5.0)`
- `porthunter.first_scan_event("./captures/remote_mcp-20250917-0933.pcapng")`
