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

**v4.0 — Web Vulnerability Scanner & Recon Suite**

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Checks](https://img.shields.io/badge/Vulnerability%20Checks-111%2B-red?style=flat-square)]()
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
| **29 Pastas Payload** | SQLi, XSS, LFI, SSRF, SSTI, NoSQL, LDAP, XPath, CRLF, WAF-Bypass, Kubernetes, IaC, AWS, Firebase, GraphQL, AI-LLM, Business-Logic e mais |
| **8 Grupos Paralelos** | ~14 min vs ~80 min sequencial |

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

**Advanced (101-111)**
Sensitive Paths (250+) · Swagger/API Docs · HPP · Default Credentials · Deserialization RCE · Web Cache Deception · JS Secrets (14 tipos + 13 patterns) · SQL Injection Boolean Blind · SQL Injection UNION · GraphQL CSRF · WAF Bypass (120 payloads x 5 zones x 5 encodings + vendor detection)

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
python CyberDyneWeb.py --url https://alvo.com --all --browser-mimic -o browser_scan

# Tudo junto — o scan mais completo possivel
python CyberDyneWeb.py --url https://alvo.com --login https://alvo.com/login -ul admin -pl senha --all --stealth --ai-payloads --live --browser-mimic -o full_scan
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
| `--browser-mimic` | Playwright: DOM XSS real, clickjacking iframe, storage leaks, SPA routes |
| `-o NOME` / `--output` | Nome da pasta de output (ex: `-o meu_projeto`) |

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

*v4.0 — 19/03/2026*

</div>
