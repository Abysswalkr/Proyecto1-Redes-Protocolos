# tests/conftest.py
import os
import tempfile
from pathlib import Path
import pytest
import sys

TESTS = Path(__file__).resolve().parent
if str(TESTS) not in sys.path:
    sys.path.insert(0, str(TESTS))

@pytest.fixture(scope="session", autouse=True)
def _ensure_env():
    # Carpeta temporal permitida para pruebas (para sanitize_path)
    tmpdir = tempfile.mkdtemp(prefix="ph_allowed_")
    os.environ.setdefault("PORT_HUNTER_ALLOWED_DIR", tmpdir)
    os.environ.setdefault("PORT_HUNTER_TOKEN", "TEST_TOKEN")
    os.environ.setdefault("PORT_HUNTER_REQUIRE_TOKEN", "true")
    os.environ.setdefault("PORT_HUNTER_MAX_PCAP_MB", "50")
    return tmpdir

@pytest.fixture()
def allowed_dir():
    return Path(os.environ["PORT_HUNTER_ALLOWED_DIR"]).resolve()
