import pytest
from tests._mcp_client import call_tool, TOKEN

@pytest.mark.asyncio
async def test_correlate_marks_invalid_and_private():
    ips = ["abc", "192.168.0.10", "8.8.8.8"]
    data = await call_tool("correlate", {"ips": ips, "auth_token": TOKEN})
    assert isinstance(data, dict)
    assert data.get("ok") is True
    results = data.get("results", [])
    # Debe haber 3 entradas
    assert len(results) == 3
    # abc -> invalid
    r0 = results[0]
    assert r0.get("ip") == "abc" and r0.get("ok") is False and r0.get("error") == "invalid_ip"
    # 192.168.0.10 -> skipped (private)
    r1 = results[1]
    assert r1.get("skipped") is True
