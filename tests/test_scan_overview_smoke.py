import os
from pathlib import Path
import pytest
from ._mcp_client import call_tool, TOKEN

@pytest.mark.asyncio
async def test_smoke_overview_if_sample_exists():
    # Si existe un demo en captures/, corremos smoke; si no, lo omitimos.
    root = Path(__file__).resolve().parents[1]
    sample = root / "captures" / "scan-demo-20250906-1.pcapng"
    if not sample.exists():
        pytest.skip("No hay PCAP de demo disponible; prueba omitida.")
    data = await call_tool("scan_overview", {"path": str(sample), "auth_token": TOKEN})
    assert isinstance(data, dict)
    assert data.get("ok") is True
    ov = data.get("overview", {})
    assert "total_pkts" in ov and "generated_at" in ov
