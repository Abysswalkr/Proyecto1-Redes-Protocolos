.PHONY: install run-stdio test bench docker-build docker-run

PYTHON ?= python

install:
	$(PYTHON) -m pip install --upgrade pip
	$(PYTHON) -m pip install -e . pytest

run-stdio:
	@echo "== Iniciando PortHunter MCP stdio =="
	PORT_HUNTER_TOKEN=$${PORT_HUNTER_TOKEN:-MiTOKENultraSecreto123} \
	PORT_HUNTER_ALLOWED_DIR=$${PORT_HUNTER_ALLOWED_DIR:-$$PWD/captures} \
	$(PYTHON) -m porthunter.server

test:
	pytest -q

bench:
	@if [ -z "$$PCAP" ]; then echo "Uso: make bench PCAP=scan-demo-20250906-1.pcapng"; exit 1; fi
	$(PYTHON) scripts/benchmark_porthunter.py "$$PCAP"

docker-build:
	docker build -t porthunter-mcp:latest server/porthunter_mcp

docker-run:
	@if [ -z "$$PORT_HUNTER_TOKEN" ]; then echo "Definir PORT_HUNTER_TOKEN en el entorno"; exit 1; fi
	docker run --rm -it \
		-e PORT_HUNTER_TOKEN=$$PORT_HUNTER_TOKEN \
		-v "$${PORT_HUNTER_ALLOWED_DIR:-$$PWD/captures}":/captures \
		porthunter-mcp:latest
