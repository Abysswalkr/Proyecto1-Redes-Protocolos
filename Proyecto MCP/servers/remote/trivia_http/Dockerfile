# servers/remote/trivia_http/Dockerfile
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Dependencias de runtime
RUN pip install --no-cache-dir fastapi uvicorn fastmcp

# Copiamos TODO el paquete "servers" para mantener la ruta de import
COPY servers /app/servers

# Puerto (Railway define $PORT en runtime)
ENV PORT=8000

# Ejecuta FastAPI+FastMCP en /mcp
CMD ["sh", "-c", "uvicorn servers.remote.trivia_http.app:app --host 0.0.0.0 --port ${PORT}"]
