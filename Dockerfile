# Vollteam API — production image.
# Multi-stage: the app + deps are built as wheels in the builder stage, so the
# slim runtime image never needs compilers or the build toolchain.

# Stage 1: build everything into wheels
FROM python:3.11-slim AS builder
WORKDIR /build

RUN pip install --no-cache-dir --upgrade pip wheel

# Build dependency wheels first (cached independently of app code)
COPY apps/api/pyproject.toml ./
RUN pip wheel --no-cache-dir --wheel-dir /wheels .

# Build the app's own wheel (needs the package sources)
COPY apps/api/pyproject.toml ./app-src/
COPY apps/api/vollteam_api ./app-src/vollteam_api
RUN cd app-src && pip wheel --no-cache-dir --wheel-dir /wheels .

# Stage 2: runtime — smallest attack surface
FROM python:3.11-slim AS runtime

# Non-root user; no shell for the API process
RUN useradd --create-home --shell /usr/sbin/nologin vollteam
WORKDIR /app

COPY --from=builder /wheels /wheels
RUN pip install --no-cache-dir --no-index --find-links /wheels vollteam_api \
    && rm -rf /wheels

USER vollteam

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2)" || exit 1

CMD ["uvicorn", "vollteam_api.main:app", "--host", "0.0.0.0", "--port", "8000"]
