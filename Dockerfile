# =============================================================================
#  CyberDyne — Dockerfile (Leve, ~300MB)
#  Inclui Go Turbo Recon + Python. SEM Playwright.
#  Para versao completa com Playwright: use Dockerfile.full
# =============================================================================

# ── Stage 1: Compilar Go binary ──────────────────────────────────────────────
FROM golang:1.22-alpine AS go-builder
WORKDIR /build
COPY recon_go/ .
RUN go build -ldflags="-s -w" -o cyberdyne-recon .

# ── Stage 2: Python runtime ──────────────────────────────────────────────────
FROM python:3.12-slim

# Dependencias do sistema
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libffi-dev libssl-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /cyberdyne

# Instalar dependencias Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiar Go binary do stage 1
COPY --from=go-builder /build/cyberdyne-recon /cyberdyne/cyberdyne-recon
RUN chmod +x /cyberdyne/cyberdyne-recon

# Copiar codigo e payloads
COPY CyberDyneWeb.py .
COPY Payloads_CY/ Payloads_CY/

# Porta do dashboard --live
EXPOSE 5000

# Volume para outputs
VOLUME ["/cyberdyne/outputs"]

ENTRYPOINT ["python", "CyberDyneWeb.py"]
CMD ["--help"]
