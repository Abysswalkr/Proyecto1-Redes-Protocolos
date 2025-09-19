import os
from pathlib import Path
import pytest
from ._mcp_client import call_tool, TOKEN

@pytest.mark.asyncio
async def test_overview_rejects_bad_extension(allowed_dir):
    bad = allowed_dir / "malicioso.zip"
    bad.write_bytes(b"not a pcap")
    data = await call_tool("scan_overview", {"path": str(bad), "auth_token": TOKEN})
    assert isinstance(data, dict)
    assert data.get("ok") is False
    assert "unsupported_file_type" in (data.get("error") or "")

@pytest.mark.asyncio
async def test_overview_accepts_small_pcap(allowed_dir):
    # Se crea un archivo .pcap vacío (solo para pasar validaciones de ruta/ext/tamaño)
    good = allowed_dir / "tiny.pcap"
    good.write_bytes(b"")  # tamaño 0MB < MAX_PCAP_MB
    data = await call_tool("scan_overview", {"path": str(good), "auth_token": TOKEN})
    # Puede fallar el parser por contenido vacío; se valida que no sea error de policies
    assert isinstance(data, dict)
    # Acepta ok True/False; lo importante es que NO sea "unsupported_file_type" ni "path_*"
    assert "unsupported_file_type" not in (data.get("error") or "")
