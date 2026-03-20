<div align="center">

<img src="Img_vid/Logo_CY.png" alt="CyberDyne" width="100"/>

```
 ██████╗██╗   ██╗██████╗ ███████╗██████╗ ██████╗ ██╗   ██╗███╗   ██╗███████╗
██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔══██╗╚██╗ ██╔╝████╗  ██║██╔════╝
██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝██║  ██║ ╚████╔╝ ██╔██╗ ██║█████╗
██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██║  ██║  ╚██╔╝  ██║╚██╗██║██╔══╝
╚██████╗   ██║   ██████╔╝███████╗██║  ██║██████╔╝   ██║   ██║ ╚████║███████╗
 ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═════╝    ╚═╝   ╚═╝  ╚═══╝╚══════╝
```

**v4.5 — Web Vulnerability Scanner & Recon Suite**

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Checks](https://img.shields.io/badge/Vulnerability%20Checks-113%2B-red?style=flat-square)]()
[![Zero Binaries](https://img.shields.io/badge/External%20Binaries-Zero-brightgreen?style=flat-square)]()

> *"O codigo que voce nao testou e o ataque que voce nao viu vir."*

</div>

---

## O que e o CyberDyne

CyberDyne e um scanner de seguranca web completo em Python puro. Um unico arquivo, zero binarios externos, zero Docker. Voce aponta para um alvo e ele faz tudo sozinho: reconhecimento, analise de 111+ vulnerabilidades, e entrega relatorios prontos para acao.

Nasceu como resposta ao **Vibe Coding** — desenvolvimento acelerado por IA que produz codigo funcional mas inseguro. Se voce ou sua equipe usa IA para codar, o CyberDyne testa se o resultado e seguro.

---

## Visao Geral

```
python CyberDyneWeb.py --url https://alvo.com --all
```

```
┌───────────────────────────────────────────────────────────────────┐
│                     CyberDyneWeb.py                               │
│                  ~11.000 linhas · Python puro                     │
│                                                                   │
│  FASE 1           FASE 2           FASE 3 (FINAL)                │
│  ┌───────┐        ┌───────┐        ┌───────────────────┐         │
│  │ RECON │──────▶│ VULNS │──────▶│ RELATORIOS         │         │
│  │Engine │        │ 111+  │        │ PDF + Recon.pdf   │         │
│  │13 step│        │checks │        │ prompt_recall.md  │         │
│  └───────┘        └───────┘        │ Recon.md + JSON   │         │
│                                    └───────────────────┘         │
│                                                                   │
│  CLI completa · --stealth · --ai-payloads · --live dashboard     │
│  8 APIs OSINT · Gemini AI · Scan autenticado · 29 pastas payload │
└───────────────────────────────────────────────────────────────────┘
```

---

## Principais Recursos

| Recurso | Descricao |
|---|---|
| **CLI Completa** | `--url`, `--login`, `-ul`, `-pl`, `--all`, `--recon`, `--vuln`, `--stealth`, `--ai-payloads`, `--live` |
| **Modo Stealth** | Delay aleatorio entre requests + rotacao automatica de User-Agent para evitar bloqueio por WAFs |
| **AI Payloads** | Gemini analisa o HTML do alvo e gera 15 payloads especificos por contexto (XSS, SQLi, LFI, RCE, SSTI, SSRF) |
| **Live Dashboard** | Servidor Flask local (`localhost:5000`) com dashboard visual em tempo real — progresso, subdomínios, vulns |
| **Scan Autenticado** | Login automatico, crawl da area logada, cookies injetados em todos os 111+ checks |
| **Gemini AI** | Sumario executivo no PDF + prompt_recall.md com fixes tecnicos gerados por IA |
| **PDF Elegante** | Capa dark, risk gauge, severity badges, vulnerability cards coloridos, paginacao |
| **8 APIs OSINT** | Gemini, Shodan, VirusTotal, SecurityTrails, Chaos, Hunter.io, HIBP, GitHub |
| **33 Pastas Payload** | SQLi, XSS, LFI, SSRF, SSTI, NoSQL, LDAP, XPath, CRLF, WAF-Bypass, XXE, Open-Redirect, User-Agents, Kubernetes, IaC, AWS, Firebase, GraphQL, AI-LLM, Business-Logic e mais |
| **8 Grupos Paralelos** | 8-16 workers dinamicos por intensity level |
| **Intensity Levels** | `--medium` (30% rapido) · `--hard` (60% padrao) · `--insane` (100% arsenal completo ~32K payloads) |
| **Crypto Audit** | TLS + rainbow table MD5/SHA1/SHA256 + base64 decode + ROT13 + hex encoding + entropia de tokens + connection strings + cookies sequenciais |
| **Retire.js Scanner** | 27 bibliotecas JS monitoradas (jQuery, Angular, Vue, React, Lodash, Moment, Bootstrap...) com CVE correlation |

---

## Fases de Execucao

### Fase 1 — Reconhecimento (13 etapas)

Coleta maxima de inteligencia antes de qualquer teste.

- Enumeracao de subdominios (6 fontes: crt.sh, HackerTarget, Wayback, VirusTotal, SecurityTrails, Chaos)
- Coleta de URLs com parametros (ParamSpider, OTX, Common Crawl)
- Validacao de URLs ativas (HEAD+GET, 30 threads)
- Deteccao de subdomain takeover (fingerprints + CNAME dangling)
- WHOIS raw socket (registrar, datas, nameservers, DNSSEC)
- Fingerprint de 62 tecnologias em 15 categorias (8 vetores de deteccao por tech)
- Coleta de emails (scraping + Hunter.io + HIBP)
- Port scan top-1000 portas
- GitHub Dorking (secrets em commits publicos + 80 dorks extras)
- Deteccao de endpoints AI/BaaS
- Fuzzing de paths sensiveis (12 wordlists + K8s + IaC, 15 threads)
- Descoberta de endpoints em JS (5 regex patterns + 13 patterns de secrets)
- Shodan intelligence (portas, CVEs, org, hostnames)

### Fase 2 — 111+ Vulnerability Checks

8 grupos paralelos, cada check com timeout de 45s. Com `--ai-payloads`, o Gemini gera 15 payloads extras por contexto em tempo real.

**OWASP Top 10 + Extended (001-020)**
SQL Injection error-based (140 patterns, 30+ DBMS) · SQL Injection time-based (multi-DBMS) · XSS Reflected (filter check + context-aware + 80+ payloads + WAF bypass) · XSS Stored (multi-page forms) · XSS DOM (source-to-sink tracking) · CSRF · SSRF (23 param names + cloud metadata) · LFI/Path Traversal (30 param names) · RFI (canary + baseline) · Command Injection · XXE · Open Redirect (44 payloads) · Insecure Deserialization · Security Misconfiguration · Broken Access Control · Cryptographic Failures · Vulnerable Components · Insufficient Logging · IDOR · Mass Assignment

**IA / JWT / Auth (021-035)**
JWT Signature Bypass (alg:none 4 variantes + null sig + psychic ECDSA CVE-2022-21449 + blank password) · JWT Weak Secret Cracking (330+ senhas, HS256/384/512) · JWT Advanced (JWKS exposure + KID injection/SQLi + claim tampering) · Prompt Injection (35 payloads, 8 categorias, homoglyph + base64 mutations) · LLM Data Leakage · Race Condition · Prototype Pollution · GraphQL Security (introspection + suggestions + trace + IDE) · GraphQL DoS (5 testes) · API Rate Limit · Stack Trace · Debug Mode · Metrics Exposed · CORS Misconfiguration · WebSocket Auth

**BaaS / Cloud (036-045)**
Supabase RLS Audit (60+ tabelas + storage + auth + RPC + service_role JWT decode) · Firebase Rules + API key + Storage · S3 Bucket · Cognito · AWS Credentials · Stripe/SendGrid/Twilio/Google keys

**Recon / DNS (046-055)**
Subdomain Takeover · DNS Zone Transfer · SPF/DMARC · Git/SVN exposed · Backups · DS_Store · Source Maps · Wayback JS Leakage

**Infra / Headers (056-075)**
Host Header Injection · HTTP Smuggling · HTTP Splitting · Cache Poisoning · Web Cache Deception · CORS · Clickjacking · MIME Sniffing · CSP · HSTS · Referrer-Policy · Permissions-Policy · Server Version · X-Powered-By · Dangerous HTTP Methods · Directory Listing · Admin Panels · API Auth · GraphQL Playground · Swagger

**Logica / Autenticacao (076-100)**
Broken Auth · File Upload · Insecure Cookies · Account Enumeration · Password Reset · Session Fixation · Function-Level Auth · OAuth · 2FA Bypass · IDOR · Business Logic · NoSQL Injection · ReDoS · XML Bomb · ZIP Slip · LDAP Injection · XPath Injection · SSTI · HPP · Default Credentials · TLS/SSL · Certificate Transparency · Mixed Content · Sensitive Data in URL · Error Messages · Security.txt

**Advanced (101-113)**
Sensitive Paths (250+) · Swagger/API Docs · HPP · Default Credentials · Deserialization RCE · Web Cache Deception · JS Secrets (14 tipos + 13 patterns) · SQL Injection Boolean Blind · SQL Injection UNION · GraphQL CSRF · WAF Bypass (120 payloads x 5 zones x 5 encodings + vendor detection) · 403 Bypass (path, header, method mutation) · **JS Libraries Vulneraveis (Retire.js-style, 27 libs, CVE correlation)**

### Fase 2.5 — Browser Mimic (`--browser-mimic`)

> Opcional. Requer `pip install playwright playwright-stealth fake-useragent && playwright install chromium`

Abre um Chromium real com anti-fingerprinting, mouse em curvas Bezier e digitacao humana. Testa vulnerabilidades **client-side** invisiveis para HTTP puro:

| Vuln | O que testa |
|---|---|
| **DOM XSS Real (201)** | Injeta payloads em params e forms, monitora `console.error` — confirma execucao JS real |
| **AI-Output Injection (202)** | Envia prompt com HTML malicioso para chat endpoints, verifica se renderiza no DOM |
| **Prototype Pollution (203)** | `?__proto__[polluted]=X` + `page.evaluate()` verifica se Object.prototype foi alterado |
| **Storage Leak (204)** | Extrai localStorage + sessionStorage, busca JWT, Stripe keys, AWS keys, passwords |
| **SPA Hidden Routes (205)** | Detecta React/Next/Vue/Angular, extrai rotas de JS bundles, testa acesso a rotas admin |
| **Clickjacking Real (206)** | Carrega o site em iframe real — se renderiza, X-Frame-Options/CSP nao esta funcionando |

Evidencia visual: screenshots PNG embedados no PDF + console logs salvos em JSON + DOM dumps.

### Fase 3 — Relatorios (fase final)

| Arquivo | Descricao |
|---|---|
| `CyberDyneWeb_Report.pdf` | Relatorio executivo com capa, risk gauge, vulnerability cards, sumario AI |
| `Recon.pdf` | Relatorio de reconhecimento consolidado (WHOIS, portas, Shodan, emails, subdomínios, fuzzing, LinkFinder) |
| `prompt_recall.md` | Prompt direto para agente de IA corrigir as vulns — gerado por Gemini quando disponível |
| `Recon.md` | Mesmos dados do Recon.pdf em Markdown |
| `raw_results.json` | Dados brutos de todos os 111+ checks |

---

## API Keys (Opcionais)

Copie `.env.example` para `.env`. Sem chaves, o script roda normalmente.

| API | Variavel | O que ativa |
|---|---|---|
| Gemini | `GEMINI_API_KEY` | Sumario executivo AI + prompt_recall + `--ai-payloads` |
| Shodan | `SHODAN_API_KEY` | Portas/servicos/CVEs pelo IP |
| VirusTotal | `VIRUSTOTAL_API_KEY` | Subdominios indexados |
| SecurityTrails | `SECURITYTRAILS_API_KEY` | Historico DNS + subdominios |
| Chaos | `CHAOS_API_KEY` | Subdominios (ProjectDiscovery) |
| Hunter.io | `HUNTER_API_KEY` | Emails corporativos |
| HIBP | `HIBP_API_KEY` | Emails vazados |
| GitHub | `GITHUB_TOKEN` | Dorking por secrets |

---

## Instalacao

### Windows / Linux / macOS

```bash
git clone https://github.com/seu-usuario/CyberDyne
cd CyberDyne
pip install -r requirements.txt
playwright install chromium
cp .env.example .env     # configure suas API keys
```

### Android — Termux

```bash
pkg update && pkg upgrade -y
pkg install -y python build-essential libffi openssl git
git clone https://github.com/seu-usuario/CyberDyne
cd CyberDyne
pip install -r requirements.txt
cp .env.example .env
nano .env
termux-wake-lock
python CyberDyneWeb.py --url https://alvo.com --all
```

> Se `reportlab` falhar: `pip install --no-build-isolation reportlab`
> Se ainda falhar, o script roda sem PDF.

### Docker

**Versao leve (sem Playwright, ~250MB):**
```bash
docker build -t cyberdyne .
docker run --rm -v $(pwd)/outputs:/cyberdyne/outputs -v $(pwd)/.env:/cyberdyne/.env:ro \
  cyberdyne --url https://alvo.com --all -o outputs/scan01
```

**Versao completa com Playwright (~1.5GB):**
```bash
docker build -f Dockerfile.full -t cyberdyne-full .
docker run --rm -v $(pwd)/outputs:/cyberdyne/outputs -v $(pwd)/.env:/cyberdyne/.env:ro \
  cyberdyne-full --url https://alvo.com --all --browser-mimic -o outputs/scan01
```

**Com docker-compose:**
```bash
# Scan leve
docker compose run cyberdyne --url https://alvo.com --all -o outputs/scan01

# Scan completo com Playwright
docker compose run cyberdyne-full --url https://alvo.com --all --browser-mimic -o outputs/scan01

# Com dashboard --live
docker compose run -p 5000:5000 cyberdyne --url https://alvo.com --all --live -o outputs/scan01

# Retomar de checkpoint
docker compose run cyberdyne --resume outputs/scan01/.checkpoint.cyb
```

> Resultados salvos em `./outputs/` no host. API keys lidas do `.env` em modo read-only.

---

## Execucao

### Modo CLI (recomendado)

```bash
# Scan completo
python CyberDyneWeb.py --url https://alvo.com --all -o meu_projeto

# Apenas reconhecimento
python CyberDyneWeb.py --url https://alvo.com --recon -o recon_alvo

# Apenas vulnerabilidades
python CyberDyneWeb.py --url https://alvo.com --vuln -o vuln_alvo

# Scan autenticado
python CyberDyneWeb.py --url https://alvo.com --login https://alvo.com/login -ul admin@email.com -pl minhaSenha --all -o projeto_auth

# Modo stealth (anti-WAF)
python CyberDyneWeb.py --url https://alvo.com --all --stealth -o stealth_scan

# AI payloads contextuais (requer GEMINI_API_KEY)
python CyberDyneWeb.py --url https://alvo.com --all --ai-payloads -o ai_scan

# Dashboard visual em tempo real
python CyberDyneWeb.py --url https://alvo.com --all --live -o live_scan

# Browser Mimic — testes client-side com Chromium real
python CyberDyneWeb.py --url https://alvo.com --all --browser-mimic-ns -o browser_scan

# Tudo junto — o scan mais completo possivel
python CyberDyneWeb.py --url https://alvo.com --login https://alvo.com/login -ul admin -pl senha --all --stealth --ai-payloads --live --browser-mimic-s -o full_scan
```

### Modo Interativo

```bash
python CyberDyneWeb.py
```

O script pergunta tudo interativamente: URL, login, credenciais, tipo de scan.

### Flags

| Flag | Descricao |
|---|---|
| `--url URL` | URL alvo |
| `--login URL` | URL do painel de login (opcional) |
| `-ul` / `--userlogin` | Email ou usuario para login |
| `-pl` / `--passlogin` | Senha para login |
| `--all` | Executa tudo: recon + vuln + relatorios |
| `--recon` | Apenas reconhecimento |
| `--vuln` | Apenas scan de vulnerabilidades |
| `--stealth` | Delay aleatorio (0.3-1.5s) + rotacao de User-Agent |
| `--ai-payloads` | Gemini gera 15 payloads especificos por alvo (XSS, SQLi, LFI, RCE, SSTI, SSRF) |
| `--live` | Dashboard Flask em `localhost:5000` |
| `--browser-mimic-s` | Browser Mimic **SHOW**: abre Chromium visivel — mouse mexendo, digitando, tudo ao vivo |
| `--browser-mimic-ns` | Browser Mimic **NO-SHOW**: roda em background (headless, mais rapido) |
| `--wp` | WordPress Security Audit (plugins, themes, users, xmlrpc, CVEs) |
| `--medium` | 30% dos payloads — scan rapido, ideal para reconhecimento inicial |
| `--hard` | 60% dos payloads — balanceado (padrao se nenhum nivel for especificado) |
| `--insane` | 100% dos payloads — completo, sem piedade, arsenal total (~32K payloads) |
| `--go` | Reconhecimento via Go (10-50x mais rapido que Python). Requer compilacao do binario |
| `--resume FILE` | Retomar scan de checkpoint (`.cyb`) — scans longos podem ser pausados e retomados |
| `-o NOME` / `--output` | Nome da pasta de output (ex: `-o meu_projeto`) |

### Go Turbo Recon (`--go`)

Reconhecimento **10-50x mais rapido** usando goroutines do Go. Essa feature e **opcional** — sem ela o script roda normalmente com Python.

#### 1. Instalar o Go

Baixe e instale em [https://go.dev/dl/](https://go.dev/dl/) (escolha o instalador do seu sistema).

Apos instalar, **feche e abra o terminal** para o Go entrar no PATH. Confirme com:

```bash
go version
# deve mostrar algo como: go version go1.22.0 windows/amd64
```

#### 2. Compilar o binario (uma unica vez)

Abra o terminal na pasta do CyberDyne e execute:

**Windows (CMD ou PowerShell):**
```bash
cd recon_go
go build -o ../cyberdyne-recon.exe .
cd ..
```

**Linux / macOS:**
```bash
cd recon_go
go build -o ../cyberdyne-recon .
cd ..
```

Isso gera o arquivo `cyberdyne-recon.exe` (ou `cyberdyne-recon` no Linux) na raiz do projeto. Esse passo so precisa ser feito **uma vez**.

#### 3. Verificar se compilou

```bash
# Windows
dir cyberdyne-recon.exe

# Linux/Mac
ls -la cyberdyne-recon
```

Deve mostrar o arquivo (~9MB). Se aparecer, esta pronto.

#### 4. Usar

Adicione `--go` em qualquer comando:

```bash
# Scan completo com Go Recon
python CyberDyneWeb.py --url https://alvo.com --all --go -o meu_scan

# Apenas recon com Go
python CyberDyneWeb.py --url https://alvo.com --recon --go -o recon_rapido

# Scan completo + stealth + Go
python CyberDyneWeb.py --url https://alvo.com --all --go --stealth --hard -o full_scan
```

O terminal vai mostrar:

```
══════════════════════════════════════════════════════════
  FASE 1 — RECONHECIMENTO (Go Turbo)
══════════════════════════════════════════════════════════
  [GO] Usando binário: cyberdyne-recon.exe
  [GO-RECON] Alvo: https://alvo.com | Dominio: alvo.com
  [GO-RECON] Enumerando subdomínios (4 fontes paralelas)...
  [GO-RECON] 47 subdomínios encontrados
  [GO-RECON] Coletando URLs (Wayback CDX)...
  [GO-RECON] 312 URLs coletadas | 89 com params (FUZZ)
  [GO-RECON] Validando URLs ativas (100 goroutines)...
  [GO-RECON] 23 URLs ativas confirmadas
  [GO-RECON] Port scan (37 portas)...
  [GO-RECON] 3 portas abertas encontradas
  [GO] Completo em 12.3s | 47 subs | 312 URLs | 89 FUZZ | 3 portas
```

#### Se o Go nao estiver instalado ou o binario nao existir

O script **nao quebra** — ele mostra um aviso e usa o Python automaticamente:

```
  [GO] Binário não encontrado. Compile com: cd recon_go && go build -o cyberdyne-recon .
  [GO] Usando Python para reconhecimento...
```

#### Comparativo de performance

| Etapa | Python | Go |
|-------|--------|-----|
| Subdominios (4 fontes) | ~15s | ~2s |
| Coleta de URLs | ~20s | ~3s |
| Validacao de URLs | ~30s | ~3s |
| Port scan (37 portas) | ~20s | ~2s |
| Crawl HTML (depth=2) | ~25s | ~5s |
| **Total** | **~2-5 min** | **~15-30s** |

---

## Aviso Legal

> **USE EXCLUSIVAMENTE EM SISTEMAS COM AUTORIZACAO EXPLICITA.**
>
> Uso nao autorizado e crime (Lei 12.737/2012 — Brasil / CFAA — USA).
> Indicado para: pentest autorizado, bug bounty, laboratorio, desenvolvimento seguro.

---

<div align="center">

**CyberDyne** — Construido para proteger o que importa.

*"Seguranca nao e um produto. E um processo."* — Bruce Schneier

*v4.5 — 20/03/2026*

</div>
