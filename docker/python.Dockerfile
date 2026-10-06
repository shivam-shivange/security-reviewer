# Verify-stage sandbox for Python projects.
FROM python:3.11-slim
ENV PYTHONDONTWRITEBYTECODE=1 PIP_NO_CACHE_DIR=1 PYTHONUNBUFFERED=1
WORKDIR /work
# Harness dependencies + common web frameworks so the app imports and the in-process client works.
RUN pip install --no-cache-dir flask fastapi "starlette" httpx "uvicorn" django pytest pyyaml requests
# Project requirements are installed at build time from the copied requirements file, when present.
COPY requirements*.txt ./
RUN for f in requirements*.txt; do [ -f "$f" ] && pip install --no-cache-dir -r "$f" || true; done
CMD ["python", "--version"]
