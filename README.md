<div align="center">

<img src="cyber.png" alt="CyberDyne" width="180"/>

```
 ██████╗██╗   ██╗██████╗ ███████╗██████╗ ██████╗ ██╗   ██╗███╗   ██╗███████╗
██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔══██╗╚██╗ ██╔╝████╗  ██║██╔════╝
██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝██║  ██║ ╚████╔╝ ██╔██╗ ██║█████╗
██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██║  ██║  ╚██╔╝  ██║╚██╗██║██╔══╝
╚██████╗   ██║   ██████╔╝███████╗██║  ██║██████╔╝   ██║   ██║ ╚████║███████╗
 ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═════╝    ╚═╝   ╚═╝  ╚═══╝╚══════╝
```

**v2.0 — Web Vulnerability Scanner & Recon Suite**

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Dependencies](https://img.shields.io/badge/Dependencies-9%20packages-orange?style=flat-square)](requirements.txt)
[![Checks](https://img.shields.io/badge/Vulnerability%20Checks-107-red?style=flat-square)]()
[![Zero Binaries](https://img.shields.io/badge/External%20Binaries-Zero%20Required-brightgreen?style=flat-square)]()

> *"O código que você não testou é o ataque que você não viu vir."*

**CyberDyne** é uma suíte de segurança ofensiva/defensiva em Python puro para encontrar vulnerabilidades em aplicações web sem dependência de ferramentas externas, sem Docker, sem configuração complexa.

> **v2.0** — Adicionado: Gemini AI para sumário executivo e prompt_recall inteligente · PDF elegante com cards, risk gauge e numeração de páginas · Payloads_CY com 16 categorias integradas · 8 APIs OSINT conectadas · VulnScanner paralelo (8 grupos × 8 workers)

</div>

---

## Índice

- [Visão Geral](#visão-geral)
- [Stack e Tecnologias](#stack-e-tecnologias)
- [Instalação](#instalação)
- [Como Usar](#como-usar)
- [Fases de Execução](#fases-de-execução)
  - [Fase 1 — Recon](#fase-1--recon)
  - [Fase 2 — 107 Vulnerability Checks](#fase-2--107-vulnerability-checks)
  - [Fase 3 — Relatórios](#fase-3--relatórios)
  - [Fase 4 — Brute Force Probe](#fase-4--brute-force-probe-opcional)
- [Categorias de Vulnerabilidades](#categorias-de-vulnerabilidades)
- [Fingerprinting de Tecnologias](#fingerprinting-de-tecnologias)
- [API Keys Opcionais](#api-keys-opcionais)
- [Arquivos Gerados](#arquivos-gerados)
- [Aviso Legal](#aviso-legal)

---

## Visão Geral

CyberDyne nasce como resposta ao **"Vibe Coding"** — desenvolvimento acelerado por IA que produz código funcional mas inseguro. É um scanner completo, de recon ao relatório, construído com zero dependências binárias obrigatórias.

```
┌─────────────────────────────────────────────────────────────────┐
│                        CyberDyneWeb.py                          │
│                                                                  │
│  FASE 1          FASE 2          FASE 3          FASE 4          │
│  ┌──────┐        ┌──────┐        ┌──────┐        ┌──────┐       │
│  │RECON │──────▶│VULNS │──────▶│RELAT.│──────▶│BRUTE │       │
│  │Engine│        │107   │        │PDF + │        │Force │       │
│  │      │        │checks│        │MD    │        │Probe │       │
│  └──────┘        └──────┘        └──────┘        └──────┘       │
│                                                                  │
│  Single file • Python 3.10+ • 9 pip packages • 0 binários       │
└─────────────────────────────────────────────────────────────────┘
```

---

## Stack e Tecnologias

### Linguagem & Runtime

| Componente | Versão | Uso |
|---|---|---|
| Python | 3.10+ | Runtime principal |
| stdlib `socket` | — | Port scan, WHOIS raw queries |
| stdlib `threading` | — | ThreadPoolExecutor para paralelismo |
| stdlib `ssl` | — | Análise de certificados TLS |
| stdlib `dns.resolver` | via dnspython | Resolução DNS sem timeout bloqueante |

### Dependências Python (`requirements.txt`)

| Pacote | Versão Mínima | Função no Script |
|---|---|---|
| `requests` | 2.31.0 | Todas as requisições HTTP |
| `beautifulsoup4` | 4.12.0 | Parsing HTML (forms, hidden inputs, links) |
| `colorama` | 0.4.6 | Terminal colorido (Verde/Vermelho/Amarelo) |
| `reportlab` | 4.0.0 | Geração do relatório executivo em PDF |
| `PyJWT` | 2.8.0 | Decodificação e análise de tokens JWT |
| `dnspython` | 2.4.0 | DNS queries (subdomain takeover, zone transfer) |
| `cryptography` | 42.0.0 | Análise de certificados TLS/SSL |
| `packaging` | 24.0 | Comparação de versões de dependências |
| `python-dotenv` | 1.0.0 | Carregamento de API keys via `.env` |

### Ferramentas Portadas para Python Puro

Nenhuma ferramenta externa é obrigatória. Todas foram reimplementadas internamente:

| Ferramenta Original | Substituto Interno | Localização |
|---|---|---|
| `subfinder` | crt.sh + HackerTarget + Wayback CDX | `_crtsh_enum`, `_hackertarget_enum`, `_wayback_enum` |
| `httpx` | `validate_live_urls()` com HEAD+GET | `ReconEngine.validate_live_urls()` |
| `nmap` | socket scan em 32 portas comuns | `ReconEngine._python_port_scan()` |
| `theHarvester` | scraping multi-fonte + HackerTarget API | `ReconEngine._python_harvester()` |
| `gau` | OTX AlienVault + Common Crawl | `ReconEngine._python_gau()` |
| `subzy` | EdOverflow fingerprints + NXDOMAIN+CNAME | `ReconEngine.subdomain_takeover_recon()` |
| `ParamSpider` | Wayback CDX + limpeza de parâmetros | `ReconEngine._paramspider_collect()` |
| `OpenRedireX` | 44 payloads de bypass | `VulnScanner.check_open_redirect()` |
| `dalfox` | 7-phase XSS pipeline, 60+ payloads | `VulnScanner.check_xss_reflected()` |
| `nuclei` | 6 checks portados (paths, swagger, cache...) | `VulnScanner.check_nuclei_paths()` + 5 outros |
| `Wappalyzer` | 62 tecnologias, 8 vetores de detecção | `detect_technologies()` (inline) |
| `whois` CLI | WHOIS raw socket 2-fases (IANA → TLD) | `ReconEngine.run_whois()` |

---

## Instalação

### Windows / Linux / macOS

```bash
git clone https://github.com/seu-usuario/CyberDyne
cd CyberDyne
pip install -r requirements.txt
```

> Python 3.10+ recomendado.

---

### Android — Termux

> Funciona no celular via [Termux](https://termux.dev). Siga os passos abaixo na ordem.

**1. Instale o Termux**
Baixe pelo [F-Droid](https://f-droid.org/packages/com.termux/) (recomendado) ou pela Play Store.

**2. Atualize os pacotes e instale as dependências do sistema**
```bash
pkg update && pkg upgrade -y
pkg install -y python build-essential libffi openssl git
```

**3. Clone o repositório**
```bash
git clone https://github.com/seu-usuario/CyberDyne
cd CyberDyne
```

**4. Instale as dependências Python**
```bash
pip install -r requirements.txt
```

> Se o `reportlab` falhar na compilação, instale separado com:
> ```bash
> pip install --no-build-isolation reportlab
> ```
> Se ainda falhar, o script roda normalmente sem PDF — apenas esse módulo é pulado.

**5. Configure o `.env` com suas API keys**
```bash
cp .env.example .env
nano .env   # edite com suas chaves
```

**6. Ative o wake lock para evitar que o Android mate o processo durante o scan**
```bash
termux-wake-lock
```

**7. Execute**
```bash
python CyberDyneWeb.py
```

**Dicas para Termux:**
- Use `termux-wake-lock` sempre antes de scans longos (14~40 min)
- Se o processo for kilado por falta de RAM, reduza os workers no `.env`: `SCAN_MAX_THREADS=4`
- Os resultados parciais em `.json` são salvos durante o scan — se interrompido, os dados não se perdem
- Para rodar em background: `nohup python CyberDyneWeb.py > scan.log 2>&1 &`

### API Keys Opcionais

Copie `.env.example` para `.env` e preencha as chaves desejadas:

```bash
cp .env.example .env
```

```env
GITHUB_TOKEN=ghp_...          # Ativa GitHub Dorking
SHODAN_API_KEY=...             # Ativa Shodan lookup
VIRUSTOTAL_API_KEY=...         # Ativa VirusTotal reputation
HUNTER_API_KEY=...             # Ativa coleta de emails via Hunter.io
HIBP_API_KEY=...               # Ativa HaveIBeenPwned check
```

Sem chaves: o script roda normalmente, apenas pulando esses módulos.

---

## Como Usar

```bash
python CyberDyneWeb.py
```

O script pergunta interativamente:

```
[?] URL alvo (ex: https://exemplo.com): https://alvo.com
[?] Nome do projeto (pasta de resultados): meu_projeto
[?] URL de login (opcional — ativa Brute Force Probe): https://alvo.com/login
[?] Executar recon completo? [S/n]: S
```

---

## Fases de Execução

### Fase 1 — Recon

> Coleta máxima de inteligência antes de qualquer teste de vulnerabilidade.

```
ReconEngine.run_full_recon()
│
├── 1. enumerate_subdomains()
│     ├── crt.sh (SSL certificate transparency logs)
│     ├── HackerTarget API
│     └── Wayback Machine CDX API
│
├── 2. crawl_urls_gau()
│     ├── ParamSpider (Wayback CDX — URLs com parâmetros)
│     ├── OTX AlienVault
│     ├── Common Crawl
│     └── Regex crawl na página principal
│
├── 3. validate_live_urls()
│     └── HEAD + GET, 30 threads paralelas, progress ao vivo
│
├── 4. subdomain_takeover_recon()
│     ├── EdOverflow fingerprints (body match)
│     └── NXDOMAIN + CNAME dangling detection
│
├── 5. run_whois()
│     └── WHOIS raw socket 2-fases (IANA → TLD server)
│           Extrai: Registrar, Datas, Name Servers, DNSSEC, País
│
├── 6. analyze_headers() — WhatWeb + Wappalyzer
│     ├── Fingerprint de 62 tecnologias (8 vetores cada)
│     ├── Audit de 8 security headers
│     ├── CORS wildcard detection
│     └── Hidden inputs suspeitos (is_admin, role, permission...)
│
├── 7. run_theharvester()
│     └── scraping de emails + HackerTarget (ou theHarvester se instalado)
│
├── 8. run_nmap()
│     └── nmap (se instalado) ou socket scan 32 portas
│
├── 9. github_dorking()         [requer GITHUB_TOKEN]
├── 10. ai_fingerprinting()     [detecta endpoints AI/BaaS]
├── 11. fuzz_paths()            [paths sensíveis nos targets vivos]
├── 12. shodan_lookup()         [requer SHODAN_API_KEY]
└── _cleanup_output_dir()       [remove temporários, mantém úteis]
```

---

### Fase 2 — 107 Vulnerability Checks

> 107 checks em **8 grupos paralelos** (max_workers=8 por grupo). Cada check tem timeout de 45s. Tempo estimado: ~14 min vs ~80 min sequencial.

```
VulnScanner.run_all()
│
├── [001–020] OWASP Top 10
├── [021–035] IA-Induced Vulnerabilities
├── [036–045] BaaS / Cloud Misconfigurations
├── [046–055] Recon / DNS
├── [056–075] Infra / Headers
├── [076–100] Lógica / Autenticação
└── [101–107] Nuclei+ (paths, swagger, HPP, credentials, deserialização, cache)
```

Cada check exibe em tempo real:

```
[001/107] ▶ SQL Injection
  [VULN] SQL Injection detectado em https://alvo.com/api/users?id=1
  Evidência: Resposta atrasada 5.2s com payload: ' OR SLEEP(5)--
```

---

### Fase 3 — Relatórios

```
├── CyberDyneWeb_Report.pdf          ← Relatório executivo elegante
│     ├── Capa: header escuro, metadados, risk gauge, severity badges
│     ├── Sumário executivo (Gemini AI quando configurado)
│     ├── Tabela de métricas do scan
│     ├── WHOIS do domínio
│     ├── Stack Tecnológica (Wappalyzer-style, 62 techs)
│     ├── Subdomínios com status ATIVO/INATIVO
│     ├── Vulnerability cards agrupados por severidade
│     │     → card colorido: URL, evidência, técnica, recomendação
│     ├── Checks aprovados (tabela verde)
│     ├── Disclaimer legal
│     └── Numeração de páginas em todas as páginas
│
├── prompt_recall.md                 ← Prompt direto para agente de IA
│     ├── Gerado por Gemini (quando configurado): fix técnico específico por vuln
│     └── Fallback: lista mínima — endpoint + evidência + fix — sem rodeios
│
└── raw_results.json
      └── Dados brutos de todos os checks (UTF-8)
```

---

### Fase 4 — Brute Force Probe (Opcional)

> Executada **apenas** se uma URL de login foi fornecida. Não realiza brute force real.

Testa se o sistema aceita **50 requisições em < 60s** sem:
- Rate limiting
- Account lockout
- CAPTCHA
- 429 Too Many Requests

```python
BruteForceProbe.run()
├── Detecta o formulário de login (action, campos)
├── Preserva CSRF tokens
├── Envia 50 requisições com 20 pares de credenciais comuns
└── Reporta se nenhum mecanismo de proteção foi detectado
```

---

## Categorias de Vulnerabilidades

### OWASP Top 10 (Checks 001–020)

| # | Vulnerabilidade | Método de Detecção |
|---|---|---|
| 001 | SQL Injection (Error-based) | Payload + regex de erro |
| 002 | SQL Injection (Time-based Blind) | Latência real > 4.5s |
| 003 | XSS Reflected | 7-phase pipeline (dalfox-style), 60+ payloads |
| 004 | XSS Stored | POST + GET verification, BeautifulSoup form detection |
| 005 | XSS DOM | 13 sources × 19 sinks, análise de JS externo |
| 006 | CSRF | Ausência de token em formulários POST |
| 007 | SSRF | Payload para metadata cloud (169.254.169.254) |
| 008 | LFI / Path Traversal | 20+ payloads de traversal |
| 009 | Remote Code Execution | eval/exec em parâmetros |
| 010 | Command Injection | ; && \| com sleep/id |
| 011 | XXE | XML com entidade externa |
| 012 | Open Redirect | 44 payloads de bypass (portado do OpenRedireX) |
| 013 | Insecure Deserialization | Magic bytes + endpoints RPC |
| 014 | Security Misconfiguration | Headers ausentes, métodos HTTP |
| 015 | Broken Access Control | Path traversal para admin |
| 016 | Cryptographic Failures | TLS fraco, HTTP sem redirect |
| 017 | Vulnerable Components | Versões desatualizadas em headers |
| 018 | Insufficient Logging | Sem logs em erro 500 |
| 019 | IDOR | IDs sequenciais em APIs |
| 020 | Mass Assignment | Campos extras aceitos por APIs |

### IA-Induced (Checks 021–035)

| # | Vulnerabilidade |
|---|---|
| 021 | JWT sem assinatura (alg: none) |
| 022 | JWT com chave fraca |
| 023 | Prompt Injection (campos de texto) |
| 024 | Race Condition (concurrent requests) |
| 025 | Prototype Pollution |
| 026 | GraphQL Introspection aberta |
| 027 | GraphQL Batch Attack |
| 028 | API Rate Limit ausente |
| 029 | Exposição de stack trace |
| 030 | Debug mode ativo (Flask/Django) |
| 031 | Endpoints de métricas expostos (/metrics, /actuator) |
| 032 | Variáveis de ambiente expostas |
| 033 | CORS misconfiguration (credenciais + wildcard) |
| 034 | WebSocket sem autenticação |
| 035 | Server-Side Template Injection (SSTI) |

### BaaS / Cloud (Checks 036–045)

| # | Vulnerabilidade |
|---|---|
| 036 | Supabase RLS desabilitado |
| 037 | Firebase Rules abertas |
| 038 | S3 Bucket público |
| 039 | Cognito misconfiguration |
| 040 | Exposed Supabase anon key |
| 041 | Firebase API key exposta |
| 042 | AWS credentials em JS |
| 043 | Stripe secret key exposta |
| 044 | SendGrid / Twilio key em JS |
| 045 | Google AI / Mapbox key exposta |

### Recon / DNS (Checks 046–055)

| # | Vulnerabilidade |
|---|---|
| 046 | Subdomain Takeover |
| 047 | DNS Zone Transfer |
| 048 | SPF record ausente/fraco |
| 049 | DMARC ausente |
| 050 | Git exposto (.git/HEAD) |
| 051 | SVN exposto (.svn/) |
| 052 | Backup files expostos |
| 053 | DS_Store exposto |
| 054 | Source maps expostos (.map) |
| 055 | Wayback JS Leakage (secrets em JS histórico) |

### Infra / Headers (Checks 056–075)

| # | Vulnerabilidade |
|---|---|
| 056 | Host Header Injection |
| 057 | HTTP Request Smuggling (CL.TE) |
| 058 | HTTP Splitting |
| 059 | Cache Poisoning |
| 060 | Web Cache Deception |
| 061 | CORS Access-Control-Allow-Origin: * |
| 062 | Clickjacking (X-Frame-Options ausente) |
| 063 | MIME sniffing (X-Content-Type-Options ausente) |
| 064 | CSP ausente ou fraco |
| 065 | HSTS ausente |
| 066 | Referrer-Policy ausente |
| 067 | Permissions-Policy ausente |
| 068 | Server header versionado |
| 069 | X-Powered-By exposto |
| 070 | HTTP Methods perigosos (PUT, DELETE, TRACE) |
| 071 | Directory listing ativo |
| 072 | Admin panels expostos |
| 073 | API endpoints sem autenticação |
| 074 | GraphQL playground exposto |
| 075 | Swagger/OpenAPI exposto |

### Lógica / Autenticação (Checks 076–100)

| # | Vulnerabilidade |
|---|---|
| 076 | File Upload sem restrição |
| 077 | Insecure cookies (sem HttpOnly/Secure/SameSite) |
| 078 | Account enumeration (timing attack) |
| 079 | Password reset flaws |
| 080 | Session fixation |
| 081 | Broken function-level authorization |
| 082 | OAuth misconfiguration |
| 083 | 2FA bypass |
| 084 | Insecure direct object reference (IDOR) na API |
| 085 | Business logic bypass (preço negativo) |
| 086 | Regex DoS (ReDoS) |
| 087 | XML Bomb (Billion laughs) |
| 088 | ZIP Slip |
| 089 | LDAP Injection |
| 090 | XPath Injection |
| 091 | NoSQL Injection |
| 092 | HTTP Parameter Pollution |
| 093 | Default credentials em painéis |
| 094 | TLS/SSL fraco (TLS 1.0/1.1, RC4, NULL) |
| 095 | Certificate transparency issues |
| 096 | Subdomain wildcard certificate |
| 097 | Mixed content (HTTP em HTTPS) |
| 098 | Sensitive data in URL |
| 099 | Error messages detalhadas |
| 100 | Security.txt ausente |

### Nuclei+ (Checks 101–107)

| # | Vulnerabilidade | Método |
|---|---|---|
| 101 | Paths sensíveis expostos | 250+ paths em paralelo (15 threads) |
| 102 | Swagger/API docs expostos | 35 API doc paths |
| 103 | HTTP Parameter Pollution | Parâmetros duplicados com valores diferentes |
| 104 | Default credentials | 20 pares comuns em formulários detectados |
| 105 | Deserialization RCE | Magic bytes Java/Python/PHP + endpoints RPC |
| 106 | Web Cache Deception | .css/.js em URLs privadas + headers de cache |
| 107 | JS Secrets (14 tipos) | Regex para anon keys, AWS, Stripe, GitHub, etc. |

---

## Fingerprinting de Tecnologias

O CyberDyne inclui um motor **Wappalyzer-style** integrado com:

- **62 tecnologias** em **15 categorias**
- **8 vetores de detecção** por tecnologia

| Vetor | O que detecta |
|---|---|
| `headers` | Padrões em HTTP response headers |
| `html` | Padrões no body HTML |
| `cookies` | Nomes de cookies específicos |
| `js_globals` | Variáveis globais JavaScript |
| `meta_generator` | Tag `<meta name="generator">` |
| `script_src` | URLs de `<script src="">` |
| `css_classes` | Classes CSS características |
| `response_body` | Catch-all no body completo |

### Categorias Detectadas

| Categoria | Tecnologias |
|---|---|
| CMS | WordPress, Joomla, Drupal, Ghost, Magento, PrestaShop, Shopify, Strapi |
| JavaScript Framework | React, Vue.js, Angular, AngularJS, Svelte, Ember.js, Backbone.js, jQuery, Alpine.js |
| SSR Framework | Next.js, Nuxt.js, Gatsby, Astro |
| Backend (Python) | Django, FastAPI, Flask |
| Backend (PHP) | Laravel, Symfony |
| Backend (Node.js) | Express.js, Fastify |
| Backend (Java/.NET) | Spring Boot, ASP.NET, ASP.NET Core, ColdFusion |
| Backend (Ruby) | Ruby on Rails |
| Web Server | Apache, Nginx, IIS, LiteSpeed, Caddy, Gunicorn, Uvicorn, OpenResty, Phusion Passenger |
| CDN / Cloud | Cloudflare, AWS CloudFront, AWS General, Azure, GCP, Fastly, Akamai, Varnish |
| WAF | Sucuri, Imperva/Incapsula, ModSecurity, AWS WAF, Cloudflare WAF |
| Analytics | Google Analytics, GTM, Segment, Mixpanel, Hotjar, Facebook Pixel |
| Support/Chat | Intercom, Zendesk |
| Search | Algolia, Elasticsearch |
| CSS Framework | Bootstrap, Tailwind CSS, Bulma |
| Database | MySQL, PostgreSQL, MongoDB, Redis |
| Payment | Stripe, PayPal |
| Headless CMS | Contentful, Sanity |
| Hosting | Vercel, Netlify, Heroku |
| Monitoring | Sentry |
| Bot Detection | reCAPTCHA, hCaptcha |
| Bundler | Webpack, Vite |
| Programming Language | PHP, Node.js |

---

## API Keys Opcionais

Copie `.env.example` para `.env` e preencha as chaves. Sem chaves, o script roda normalmente — apenas pula os módulos que dependem delas.

### Integradas e Funcionais

| API | Variável `.env` | O que ativa |
|---|---|---|
| **Gemini (Google AI)** | `GEMINI_API_KEY` | Sumário executivo IA no PDF + prompt_recall inteligente |
| **GitHub** | `GITHUB_TOKEN` | Dorking automático por secrets em commits públicos |
| **Shodan** | `SHODAN_API_KEY` | Lookup de portas/serviços expostos pelo IP |
| **VirusTotal** | `VIRUSTOTAL_API_KEY` | Subdomínios indexados + reputação de domínio |
| **SecurityTrails** | `SECURITYTRAILS_API_KEY` | Histórico de DNS e subdomínios (melhor do mercado) |
| **Chaos (ProjectDiscovery)** | `CHAOS_API_KEY` | Base massiva de subdomínios pré-resolvidos |
| **Hunter.io** | `HUNTER_API_KEY` | Coleta de emails corporativos via OSINT |
| **HaveIBeenPwned** | `HIBP_API_KEY` | Verifica se emails do alvo foram vazados |

### Carregadas (Integração Pendente)

| API | Variável `.env` | Planejado para |
|---|---|---|
| NVD (NIST) | `NVD_API_KEY` | CVE lookup pela stack tecnológica detectada |
| Vulners | `VULNERS_API_KEY` | CVE lookup alternativo |
| URLScan.io | `URLSCAN_API_KEY` | Screenshot e análise visual do alvo |
| BinaryEdge | `BINARYEDGE_API_KEY` | Alternativa ao Shodan para ativos expostos |
| HackerOne | `HACKERONE_API_KEY` | Verificar escopo de bug bounty do alvo |

---

## Arquivos Gerados

Após o scan, a pasta do projeto contém **apenas os arquivos úteis** (temporários são removidos automaticamente):

| Arquivo | Conteúdo |
|---|---|
| `cyberdyne_report.pdf` | Relatório executivo completo em PDF |
| `prompt_recall.md` | Prompt para IA corrigir as vulnerabilidades encontradas |
| `raw_results.json` | Dados brutos de todos os 107 checks |
| `subdomains_validated.json` | Subdomínios com URL viva confirmada |
| `urls_live_200.json` | URLs com status 2xx/3xx |
| `fuzzing_urls.json` | URLs com parâmetros para testes (formato FUZZ) |
| `recon_summary.json` | Resumo completo do reconhecimento |
| `recon_subdomain_takeover.json` | Vulnerabilidades de subdomain takeover |
| `recon_emails.json` | Emails encontrados via OSINT |
| `recon_nmap.json` | Portas abertas por host |
| `recon_headers.json` | Headers e fingerprint por URL |
| `recon_fingerprint.json` | Stack tecnológica detectada por categoria |
| `recon_whois.json` | Dados WHOIS do domínio |
| `bruteforce_probe.json` | Resultado do probe de rate limit (se executado) |
| `paramspider/` | URLs brutas por domínio (subpasta) |

---

## Regras de Ouro (para Contribuidores)

1. **Nunca usar `socket.gethostbyname()`** — trava o Windows sem timeout. Usar apenas `dns.resolver` com `timeout=1.5`.
2. **Nunca chamar `log()` dentro de `with lock:`** — deadlock garantido. Construa a string antes de entrar no lock.
3. **Ferramentas externas são sempre opcionais** — sempre há fallback Python. O script nunca morre por falta de binário.
4. **Timeout em tudo** — `requests` com `timeout=6`, checks com timeout de 45s via `ThreadPoolExecutor`.
5. **Evidência obrigatória** — cada vuln deve reportar onde ocorreu + o que foi encontrado. Sem falsos positivos genéricos.
6. **APIs são silenciosamente opcionais** — toda chamada de API deve ter `try/except` que retorna vazio, nunca levanta exceção para o scan principal.
7. **Não reintroduzir DNS BF** — wordlist de prefixos gera centenas de 404s em produção, sem valor diagnóstico. Usar Chaos API como substituto.

---

## Aviso Legal

> **USE EXCLUSIVAMENTE EM SISTEMAS COM AUTORIZAÇÃO EXPLÍCITA.**
>
> Uso não autorizado é crime (Lei 12.737/2012 — Brasil / CFAA — USA).
> O CyberDyne não assume responsabilidade pelo mau uso desta ferramenta.
>
> Indicado para: pentest autorizado, bug bounty, ambientes de laboratório, desenvolvimento seguro.

---

<div align="center">

**CyberDyne** — Construído para proteger o que importa.

*"Segurança não é um produto. É um processo."* — Bruce Schneier

*Andamento: v2.0 — Em desenvolvimento ativo (17/03/2026)*

---

## Changelog

### v2.0 — 17/03/2026
- **Gemini AI**: sumário executivo inteligente no PDF + `prompt_recall.md` gerado por IA
- **PDF elegante**: cover com header dark, risk gauge, severity badges, vulnerability cards coloridos, page numbers
- **Payloads_CY**: 16 pastas conectadas ao script (SQLi, XSS, LFI, SSRF, SSTI, DNS, AI-LLM, etc.)
- **VulnScanner paralelo**: 8 grupos × max_workers=8 (~80min → ~14min)
- **Chaos API**: substituiu DNS BF por wordlist (que gerava 404s massivos)
- **API integradas**: Gemini, Shodan, VirusTotal, SecurityTrails, Chaos, Hunter.io, HIBP, GitHub
- **`.gitignore`** e **`.env.example`** adicionados ao repositório
- **`BASE_DELAY`**: reduzido de 0.5s para 0.1s
- **`prompt_recall.md`**: reescrito — direto, curto, focado em fixes técnicos

</div>
