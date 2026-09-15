# Vollteam API — production image.
# Multi-stage: deps wheel-build in builder, slim runtime with non-root user.

# Stage 1: build dependencies as wheels (no compilers needed in final image)
FROM python:3.11-slim AS builder
WORKDIR /build

RUN pip install --no-cache-dir --upgrade pip wheel

COPY apps/api/pyproject.toml ./
RUN pip wheel --no-cache-dir --wheel-dir /wheels .

# Stage 2: runtime — smallest attack surface
FROM python:3.11-slim AS runtime

# Non-root user; no shell needed for the API process
RUN useradd --create-home --shell /usr/sbin/nologin vollteam
WORKDIR /app

COPY --from=builder /wheels /wheels
RUN pip install --no-cache-dir --no-index --find-links /wheels . \
    && rm -rf /wheels

COPY --chown=vollteam:vollteam apps/api/vollteam_api ./vollteam_api

USER vollteam

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2)" || exit 1

CMD ["uvicorn", "vollteam_api.main:app", "--host", "0.0.0.0", "--port", "8000"]
