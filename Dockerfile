# ── Build stage ───────────────────────────────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM python:3.11-slim

# Dépendances système minimales
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpq5 \
        iputils-ping \
        libcap2-bin \
    && setcap cap_net_raw+ep /bin/ping \
    && apt-get remove -y libcap2-bin && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copie des packages installés depuis le builder
COPY --from=builder /install /usr/local

# Code source
COPY . .

# Utilisateur non-root
RUN useradd -m appuser \
    && mkdir -p /app/instance \
    && chown -R appuser /app \
    && chmod +x /app/entrypoint.sh
USER appuser

EXPOSE 5000

ENTRYPOINT ["/app/entrypoint.sh"]

# Gunicorn — 1 worker (APScheduler tourne dans le même process)
CMD ["gunicorn", \
     "--bind", "0.0.0.0:5000", \
     "--workers", "1", \
     "--threads", "4", \
     "--timeout", "60", \
     "--access-logfile", "-", \
     "--error-logfile", "-", \
     "app:app"]
