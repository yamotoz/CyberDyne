<div align="center">

<img src="Img_vid/cyoff.png" alt="CyberDyne" width="400"/>

**v5.0 — Web Vulnerability Scanner & Recon Suite**

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python)](https://python.org)
[![Go](https://img.shields.io/badge/Go-1.22%2B-00ADD8?style=flat-square&logo=go)](https://go.dev)
[![Flask](https://img.shields.io/badge/Flask-Dashboard-black?style=flat-square&logo=flask)](https://flask.palletsprojects.com)
[![Playwright](https://img.shields.io/badge/Playwright-Chromium-2EAD33?style=flat-square&logo=playwright)](https://playwright.dev)
[![Gemini](https://img.shields.io/badge/Gemini_AI-Payloads-8E75B2?style=flat-square&logo=google)](https://ai.google.dev)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=flat-square&logo=docker)](https://docker.com)
[![Checks](https://img.shields.io/badge/Vuln_Checks-113%2B-red?style=flat-square)]()
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)

> *"O codigo que voce nao testou e o ataque que voce nao viu vir."*

</div>

---

## O que e o CyberDyne

Scanner de seguranca web completo. Um unico arquivo Python, zero binarios obrigatorios. Aponte para um alvo e ele faz tudo: reconhecimento, 113+ testes de vulnerabilidade e entrega relatorios prontos para acao.

Nasceu como resposta ao **Vibe Coding** — desenvolvimento acelerado por IA que produz codigo funcional mas inseguro.

```
python CyberDyneWeb.py --url https://alvo.com --all -o meu_projeto
```

---

<div align="center">

## Reconhecimento — Fase 1

<img src="Img_vid/recon.png" alt="Reconhecimento" width="500"/>

</div>

13 etapas automaticas de coleta de inteligencia antes de qualquer teste:

| # | Etapa | O que faz |
|---|---|---|
| 1 | **Subdominios** | 6 fontes: crt.sh, HackerTarget, Wayback, VirusTotal, SecurityTrails, Chaos |
| 2 | **Coleta de URLs** | ParamSpider + OTX AlienVault + Common Crawl + Crawl HTML depth=2 |
| 3 | **Validacao de URLs** | HEAD+GET em 30 threads, filtra ativas (200-399) |
| 4 | **Subdomain Takeover** | Fingerprints EdOverflow + CNAME dangling detection |
| 5 | **WHOIS** | Raw socket 2-fases (IANA → TLD): registrar, datas, nameservers, DNSSEC |
| 6 | **Fingerprint** | 62 tecnologias, 15 categorias, 8 vetores de deteccao (Wappalyzer-style) |
| 7 | **Emails** | Scraping + Hunter.io + HIBP (vazamentos) |
| 8 | **Port Scan** | Top-1000 portas via socket (ou nmap se instalado) |
| 9 | **GitHub Dorking** | Secrets em commits publicos + 80 dorks extras |
| 10 | **AI Fingerprint** | Detecta endpoints de IA/BaaS (OpenAI, Supabase, Firebase) |
| 11 | **Fuzzing Paths** | 12 wordlists + K8s + IaC, 15 threads (~1000+ paths) |
| 12 | **LinkFinder** | Endpoints e secrets em arquivos JS (5 regex + 13 patterns) |
| 13 | **Shodan** | Portas, CVEs, organizacao, hostnames pelo IP |

---

<div align="center">

## Vulnerabilidades — Fase 2

<img src="Img_vid/vulns.png" alt="Vulnerabilidades" width="500"/>

</div>

113+ checks em 8 grupos paralelos. Cada check com timeout de 45s e evidencia obrigatoria.

### OWASP Top 10 + Extended (001-020)

| # | Vulnerabilidade | Severidade | CVSS |
|---|---|---|---|
| 001 | SQL Injection Error-based (140 patterns, 30+ DBMS) | CRITICO | 9.8 |
| 002 | SQL Injection Time-based Blind (multi-DBMS) | CRITICO | 9.8 |
| 003 | XSS Reflected (8 fases, 80+ payloads, WAF bypass) | ALTO | 6.1 |
| 004 | XSS Stored (POST + GET verification) | ALTO | 6.1 |
| 005 | XSS DOM-based (13 sources x 19 sinks) | ALTO | 6.1 |
| 006 | CSRF (ausencia de token em forms POST) | MEDIO | 4.3 |
| 007 | SSRF (23 param names + cloud metadata 169.254.169.254) | CRITICO | 9.1 |
| 008 | LFI / Path Traversal (30 param names, /etc/passwd) | CRITICO | 9.8 |
| 009 | RFI (canary + baseline) | CRITICO | 9.8 |
| 010 | Command Injection (commix-style, 65+ payloads) | CRITICO | 9.8 |
| 011 | XXE (XML entity injection) | ALTO | 7.5 |
| 012 | Open Redirect (44 payloads bypass) | MEDIO | 6.1 |
| 013 | Insecure Deserialization (magic bytes Java/Python/PHP) | CRITICO | 9.8 |
| 014 | Security Misconfiguration | MEDIO | 5.3 |
| 015 | Broken Access Control | ALTO | 8.2 |
| 016 | Cryptographic Failures (TLS fraco, HTTP sem redirect) | ALTO | 7.5 |
| 017 | Vulnerable Components (versoes desatualizadas) | ALTO | 7.5 |
| 018 | Insufficient Logging | MEDIO | 4.0 |
| 019 | IDOR (IDs sequenciais em APIs) | ALTO | 7.5 |
| 020 | Mass Assignment (campos extras aceitos) | ALTO | 7.5 |

### IA / JWT / Auth (021-035)

| # | Vulnerabilidade | Severidade | CVSS |
|---|---|---|---|
| 021 | JWT Signature Bypass (alg:none + null sig + psychic ECDSA CVE-2022-21449) | CRITICO | 9.8 |
| 022 | JWT Weak Secret (330+ senhas, HS256/384/512) | CRITICO | 9.8 |
| 023 | JWT Advanced (JWKS + KID injection/SQLi + claim tampering) | CRITICO | 9.8 |
| 024 | Prompt Injection (35 payloads, homoglyph + base64 mutations) | ALTO | 8.1 |
| 025 | LLM Data Leakage | ALTO | 7.5 |
| 026 | Race Condition (concurrent requests) | ALTO | 8.1 |
| 027 | Prototype Pollution | ALTO | 7.5 |
| 028-029 | GraphQL Security (introspection + DoS + suggestions + trace) | ALTO | 7.5 |
| 030 | API Rate Limit ausente | MEDIO | 5.3 |
| 031 | Stack Trace / Debug Mode | MEDIO | 5.3 |
| 032 | Metrics expostos (/metrics, /actuator) | MEDIO | 5.3 |
| 033 | CORS Misconfiguration | ALTO | 7.5 |
| 034 | WebSocket sem autenticacao | ALTO | 7.5 |
| 035 | SSTI (Jinja2, Twig, Freemarker, ERB, Pug — 100+ payloads) | CRITICO | 9.8 |

### BaaS / Cloud (036-045)

| # | Vulnerabilidade | Severidade | CVSS |
|---|---|---|---|
| 036 | Supabase RLS Audit (60+ tabelas + storage + RPC + JWT decode) | CRITICO | 9.8 |
| 037 | Firebase Rules abertas + API key + Storage | CRITICO | 9.1 |
| 038 | S3 Bucket publico | CRITICO | 9.1 |
| 039 | Cognito Misconfiguration | ALTO | 7.5 |
| 040-045 | AWS/Stripe/SendGrid/Twilio/Google keys expostas | CRITICO | 9.1 |

### Recon / DNS (046-055)

| # | Vulnerabilidade | Severidade | CVSS |
|---|---|---|---|
| 046 | Subdomain Takeover | ALTO | 8.2 |
| 047 | DNS Zone Transfer (AXFR) | ALTO | 7.5 |
| 048-049 | SPF/DMARC ausente ou fraco | MEDIO | 5.3 |
| 050-054 | Git/SVN/.DS_Store/Backups/Source Maps expostos | ALTO | 7.5 |
| 055 | Wayback JS Leakage (secrets em JS historico) | ALTO | 7.5 |

### Infra / Headers (056-075)

| # | Vulnerabilidade | Severidade | CVSS |
|---|---|---|---|
| 056 | Host Header Injection | ALTO | 7.5 |
| 057 | HTTP Request Smuggling (CL.TE) | CRITICO | 9.8 |
| 058-060 | HTTP Splitting + Cache Poisoning + Cache Deception | ALTO | 7.5 |
| 061-067 | Headers ausentes (CORS, Clickjacking, CSP, HSTS, MIME, Referrer, Permissions) | MEDIO | 4.3-6.1 |
| 068-069 | Server/X-Powered-By versionados | BAIXO | 2.6 |
| 070-075 | HTTP Methods perigosos + Directory Listing + Admin Panels + API Auth + Swagger | MEDIO-ALTO | 5.3-7.5 |

### Logica / Autenticacao (076-100)

| # | Vulnerabilidade | Severidade | CVSS |
|---|---|---|---|
| 076 | Broken Auth (credenciais comuns + deteccao de dashboard) | CRITICO | 9.8 |
| 077 | File Upload sem restricao (canary + acesso ao arquivo) | CRITICO | 9.8 |
| 078-082 | Cookies inseguros + Account Enum + Password Reset + Session Fixation + OAuth | ALTO | 7.5 |
| 083-085 | 2FA Bypass + IDOR API + Business Logic (preco negativo) | ALTO | 7.5-8.1 |
| 086-090 | ReDoS + XML Bomb + ZIP Slip + LDAP Injection + XPath Injection | ALTO | 7.5 |
| 091 | NoSQL Injection (15+ payloads) | CRITICO | 9.8 |
| 092-100 | HPP + Default Creds + TLS/SSL + Cert Transparency + Mixed Content + Error Messages + Security.txt | MEDIO-ALTO | 4.3-7.5 |

### Advanced (101-113)

| # | Vulnerabilidade | Severidade | CVSS |
|---|---|---|---|
| 101 | Sensitive Paths (250+ paths paralelos) | ALTO | 7.5 |
| 102 | Swagger/API Docs expostos | MEDIO | 5.3 |
| 103 | HTTP Parameter Pollution | MEDIO | 5.3 |
| 104 | Default Credentials (20 pares em forms) | CRITICO | 9.8 |
| 105 | Deserialization RCE (magic bytes + endpoints RPC) | CRITICO | 9.8 |
| 106 | Web Cache Deception (.css/.js em URLs privadas) | ALTO | 7.5 |
| 107 | JS Secrets (14 tipos + 13 patterns regex) | ALTO | 7.5 |
| 108 | SQL Injection Boolean Blind | CRITICO | 9.8 |
| 109 | SQL Injection UNION | CRITICO | 9.8 |
| 110 | GraphQL CSRF | ALTO | 8.1 |
| 111 | WAF Bypass (120 payloads x 5 zones x 5 encodings) | ALTO | 7.5 |
| 112 | 403 Bypass (path + header + method mutation) | ALTO | 7.5 |
| 113 | JS Libraries Vulneraveis (Retire.js-style, 27 libs, CVE correlation) | ALTO | 7.5 |

### Fase 2.5 — Browser Mimic (opcional)

Chromium real com anti-fingerprinting, mouse Bezier e digitacao humana. Testa vulnerabilidades **client-side**:

| # | Vulnerabilidade | Severidade | CVSS |
|---|---|---|---|
| 201 | DOM XSS Real (execucao JS confirmada via console) | CRITICO | 9.6 |
| 202 | AI-Output Injection (HTML malicioso em chat bots) | ALTO | 8.1 |
| 203 | Prototype Pollution (page.evaluate confirma Object.prototype alterado) | ALTO | 7.5 |
| 204 | Storage Leak (JWT, AWS, Stripe em localStorage/sessionStorage) | ALTO | 7.5 |
| 205 | SPA Hidden Routes (rotas admin em React/Next/Vue/Angular) | ALTO | 8.2 |
| 206 | Clickjacking Real (iframe real — X-Frame-Options testado na pratica) | MEDIO | 6.1 |

---

<div align="center">

## Relatorios — Fase 3 (Final)

<img src="Img_vid/relatorios.png" alt="Relatorios" width="500"/>

</div>

| Arquivo | Descricao |
|---|---|
| `CyberDyneWeb_Report.pdf` | Relatorio executivo: capa dark, risk gauge, severity badges, vuln cards, sumario Gemini AI |
| `Recon.pdf` | Reconhecimento consolidado: WHOIS, portas, Shodan, emails, subdominios, fuzzing, LinkFinder |
| `prompt_recall.md` | Prompt direto para agente de IA corrigir as vulnerabilidades (gerado por Gemini) |
| `Recon.md` | Mesmos dados do Recon.pdf em Markdown |
| `raw_results.json` | Dados brutos de todos os 113+ checks |

---

<div align="center">

## API Keys (Opcionais)

<img src="Img_vid/keys.png" alt="API Keys" width="500"/>

</div>

Copie `.env.example` para `.env`. Sem chaves, o script roda normalmente — apenas pula os modulos que dependem de API.

| API | Variavel | O que ativa |
|---|---|---|
| **Gemini** | `GEMINI_API_KEY` | Sumario executivo AI + prompt_recall + `--ai-payloads` |
| **Shodan** | `SHODAN_API_KEY` | Portas, servicos, CVEs pelo IP |
| **VirusTotal** | `VIRUSTOTAL_API_KEY` | Subdominios indexados |
| **SecurityTrails** | `SECURITYTRAILS_API_KEY` | Historico DNS + subdominios |
| **Chaos** | `CHAOS_API_KEY` | Subdominios (ProjectDiscovery) |
| **Hunter.io** | `HUNTER_API_KEY` | Emails corporativos |
| **HIBP** | `HIBP_API_KEY` | Emails vazados em breaches |
| **GitHub** | `GITHUB_TOKEN` | Dorking por secrets em commits |
| **NVD** | `NVD_API_KEY` | CVEs do NIST (correlation de versoes) |
| **Vulners** | `VULNERS_API_KEY` | CVE lookup por software/versao |

---

<div align="center">

## Instalacao e Execucao

<img src="Img_vid/instalacao.png" alt="Instalacao" width="400"/>

</div>

### Instalacao Rapida

```bash
git clone https://github.com/seu-usuario/CyberDyne
cd CyberDyne
pip install -r requirements.txt
cp .env.example .env     # configure suas API keys
```

> **Playwright (opcional):** `pip install playwright playwright-stealth fake-useragent && playwright install chromium`
>
> **Go Turbo (opcional):** `cd recon_go && go build -o ../cyberdyne-recon.exe . && cd ..`

### Termux (Android)

```bash
pkg update && pkg upgrade -y
pkg install -y python build-essential libffi openssl git
git clone https://github.com/seu-usuario/CyberDyne && cd CyberDyne
pip install -r requirements.txt
cp .env.example .env && nano .env
termux-wake-lock
python CyberDyneWeb.py --url https://alvo.com --all
```

### Exemplos de Uso

```bash
# Scan completo
python CyberDyneWeb.py --url https://alvo.com --all -o meu_projeto

# Scan autenticado (login + crawl area logada)
python CyberDyneWeb.py --url https://alvo.com --login https://alvo.com/login -ul admin@email.com -pl senha --all -o auth_scan

# Modo stealth (anti-WAF) + AI payloads contextuais
python CyberDyneWeb.py --url https://alvo.com --all --stealth --ai-payloads -o stealth_scan

# Dashboard visual em tempo real
python CyberDyneWeb.py --url https://alvo.com --all --live -o live_scan

# Browser Mimic visivel (assista o Chromium ao vivo)
python CyberDyneWeb.py --url https://alvo.com --all --browser-mimic-s -o browser_scan

# Arsenal maximo — tudo ligado
python CyberDyneWeb.py --url https://alvo.com --login https://alvo.com/login -ul admin -pl senha --all --stealth --ai-payloads --live --browser-mimic-s --insane --go -o full_scan

# Retomar scan interrompido
python CyberDyneWeb.py --resume meu_projeto/.checkpoint.cyb
```

### Todas as Flags

| Flag | Descricao |
|---|---|
| `--url URL` | URL alvo (obrigatorio) |
| `-o NOME` | Nome da pasta de output |
| `--all` | Executa tudo: recon + vuln + relatorios |
| `--recon` | Apenas reconhecimento |
| `--vuln` | Apenas vulnerabilidades |
| `--login URL` | URL do painel de login |
| `-ul` / `-pl` | Credenciais de login (usuario / senha) |
| `--stealth` | Delay aleatorio + rotacao de User-Agent |
| `--ai-payloads` | Gemini gera 15 payloads por contexto (XSS, SQLi, LFI, RCE, SSTI, SSRF) |
| `--live` | Dashboard Flask em `localhost:5000` |
| `--browser-mimic-s` | Chromium visivel — mouse, digitacao, tudo ao vivo |
| `--browser-mimic-ns` | Chromium headless (background, mais rapido) |
| `--wp` | WordPress Audit (plugins, temas, users, xmlrpc, CVEs) |
| `--go` | Fuzzing via Go (200 goroutines, 10-50x mais rapido) |
| `--medium` | 30% dos payloads — scan rapido |
| `--hard` | 60% dos payloads — balanceado (padrao) |
| `--insane` | 100% dos payloads — arsenal completo (~32K payloads) |
| `--resume FILE` | Retomar de checkpoint `.cyb` |

---

<div align="center">

## Docker

<img src="Img_vid/dockeroff.webp" alt="Docker" width="400"/>

</div>

```bash
# Build leve (~300MB) — Python + Go, sem Playwright
docker compose build cyberdyne

# Scan completo com Go Turbo
docker compose run cyberdyne --url https://alvo.com --all --go -o outputs/scan01

# Build completo (~1.6GB) — Python + Go + Playwright
docker compose build cyberdyne-full

# Scan com Browser Mimic
docker compose run cyberdyne-full --url https://alvo.com --all --go --browser-mimic-ns -o outputs/scan01

# Dashboard --live
docker compose run -p 5000:5000 cyberdyne --url https://alvo.com --all --live -o outputs/scan01
```

> Resultados em `./outputs/`. API keys lidas do `.env` (read-only). Go compila automaticamente no build.

---

## Aviso Legal

> **USE EXCLUSIVAMENTE EM SISTEMAS COM AUTORIZACAO EXPLICITA.**
>
> Uso não autorizado e crime (Lei 12.737/2012 — Brasil / CFAA — USA).
> Indicado para: pentest autorizado, bug bounty, laboratorio, desenvolvimento seguro.

---

<div align="center">

**CyberDyne** — Construido para proteger o que importa.

*"Seguranca nao é um produto. É um processo."* — Bruce Schneier

*v5.0 — 21/03/2026*

</div>
