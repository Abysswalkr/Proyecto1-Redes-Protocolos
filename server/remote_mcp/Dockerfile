FROM python:3.12-slim
WORKDIR /app
COPY remote_utils /app/remote_utils
COPY pyproject.toml /app/pyproject.toml
RUN pip install --no-cache-dir "mcp>=1.13.0" "uvicorn>=0.31" "starlette>=0.40"
EXPOSE 8080
ENV PORT=8080
CMD ["python", "-m", "remote_utils.server"]
