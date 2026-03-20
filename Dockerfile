# =============================================================================
#  CyberDyne — Dockerfile (Leve, ~250MB)
#  Inclui tudo EXCETO Playwright (--browser-mimic)
#  Para versão completa com Playwright: use Dockerfile.full
# =============================================================================
FROM python:3.12-slim

# Dependências do sistema para cryptography e dnspython
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libffi-dev libssl-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /cyberdyne

# Instalar dependências Python (sem playwright)
COPY requirements.txt .
RUN pip install --no-cache-dir \
    requests urllib3 beautifulsoup4 colorama python-dotenv \
    reportlab PyJWT cryptography dnspython packaging flask \
    fake-useragent

# Copiar código e payloads
COPY CyberDyneWeb.py .
COPY Payloads_CY/ Payloads_CY/

# Porta do dashboard --live
EXPOSE 5000

# Volume para outputs e .env
VOLUME ["/cyberdyne/outputs"]

ENTRYPOINT ["python", "CyberDyneWeb.py"]
CMD ["--help"]
