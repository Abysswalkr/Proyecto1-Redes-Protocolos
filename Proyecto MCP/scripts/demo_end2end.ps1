# propósito: demo reproducible del flujo obligatorio (FS + Git + PortHunter).
param(
  [string]$PROFILE_PATH = "apps/host/profiles/servers.full_local.yaml",
  [string]$PCAP = "servers/porthunter/samples/nmap_syn_scan.pcap",
  [string]$OUT = "evidencias"
)

Write-Host "1) Analiza PCAP"
python -m apps.host.app.main --servers "$PROFILE_PATH" --once "analiza ./$PCAP" | Out-Host

Write-Host "2) Sospechosos"
python -m apps.host.app.main --servers "$PROFILE_PATH" --once "sospechosos ./$PCAP puertos 10 tasa 0.1" | Out-Host

Write-Host "3) Genera README"
python -m apps.host.app.main --servers "$PROFILE_PATH" --once "reporte ./$PCAP out ./$OUT" | Out-Host

Write-Host "4) Inicializa repo si no existe"
python -m apps.host.app.main --servers "$PROFILE_PATH" --once "crea repo ./$OUT" | Out-Host

Write-Host "5) Commit"
python -m apps.host.app.main --servers "$PROFILE_PATH" --once "haz commit ./$OUT chore: reporte PortHunter inicial" | Out-Host

Write-Host "Listo. Revisa $OUT/README.md y logs en apps/host/logs/mcp/."
