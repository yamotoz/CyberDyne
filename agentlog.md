# Diario de Bordo -- CyberDyne (Agente Principal)

## Status Atual: v7.0 -- Em Desenvolvimento Ativo

* **Ultima atualizacao:** 22/03/2026
* **Scripts ativos:** `CyberDyneWeb.py` (scanner web) + `recon_go/main.go` (Go turbo fuzzer v2)
* **Total de linhas:** ~18.500+
* **Total de checks de vulnerabilidade:** 118+ (core) + 17 browser-mimic + WP Audit (15)
* **Pastas de payload:** 40+ (Payloads_CY/)
* **Total de payloads:** ~3.8M linhas unicas
* **APIs integradas:** Gemini + OpenAI (fallback) + Shodan + VirusTotal + SecurityTrails + Chaos + Hunter + HIBP + GitHub + NVD + Vulners + Interactsh (OOB)
* **Tecnologias no fingerprint:** 114+ (com implies/excludes/version extraction)

### Novidades v7.0 (22/03/2026)
* **Confidence Score:** Cada finding agora tem 0-100% de confianca (auto-calculado ou explícito via OOB)
* **OOB Detection (--oob):** Interactsh integration -- confirma SSRF/XXE/RCE/Log4Shell/SSTI blind via callback DNS/HTTP. Confidence=95% quando callback recebido.
* **WAF Detection Antecipada:** detect_waf_early() identifica 11 WAFs antes da Fase 2 e adapta delay/encoding/rate automaticamente
* **Auth Refresh:** _maybe_refresh_auth() re-loga automaticamente a cada 30min durante scans longos
* **Ban Detection:** 5+ 403 consecutivos pausa todas threads 60s para evitar blacklist
* **Fuzzy Soft-404:** SequenceMatcher similarity ratio alem do hash MD5 exato. SPA detection (React/Next/Vue/Astro) reduz threshold.
* **Evidence Capture:** curl command + request/response raw nos top checks (SQLi, XSS, LFI, CMD, SSRF)
* **PDF Melhorado:** Badge de confianca, curl reproduzivel, request/response, prova manual para 118+ IDs, XML escape no texto
* **Go Engine v2:** Port scan, JS mining, takeover checker, param discovery -- todos com output sequencial limpo
* **--easy mode:** 10% dos payloads para scans rapidos
* **UI Fase 2:** Barra de progresso visual, box destaque para vulns, header estilizado por grupo, resumo final com severidades

---

## Modus Operandi (Filosofia de Trabalho)

Para agentes assistentes que derem continuidade a esse projeto:

1. **UI Terminal Premium:**
   Use `colorama`. Verde = OK, Vermelho = VULN, Amarelo = AVISO. Progress bars ao vivo com `\r`. Nunca deixe o terminal parado sem feedback.

2. **Sem Deadlocks -- Regra de Ouro:**
   `log()` usa `with lock:` internamente. **NUNCA chame `log()` dentro de outro `with lock:`.** Use `print()` direto fora do lock, ou construa a string antes de entrar no lock e imprima depois. Isso ja causou travamentos em `validate_live_urls`, `subdomain_takeover_recon` e `fuzz_paths`.

3. **Sem Ferramentas Externas Obrigatorias:**
   Tudo deve funcionar em Python puro. Ferramentas externas (nmap, theHarvester, gau) sao opcionais -- sempre ha fallback Python implementado. Nao deixe o script morrer por ausencia de binario.

4. **Timeouts Sempre:**
   `socket.gethostbyname()` congela no Windows -- usar apenas `dns.resolver` com `timeout=1.5, lifetime=2.0`. Requests com `timeout=6` como padrao. Nunca confia no OS para resolver timeout.

5. **Testes Reais, Nao Falsos Positivos:**
   Evidencia obrigatoria: onde a falha ocorreu + o que foi encontrado. Time-based SQLi: verifica latencia real. Open Redirect: segue redirect e verifica netloc final. Subdomain Takeover: regex no body + NXDOMAIN+CNAME dangling.

6. **API Keys -- padrao de uso:**
   Toda API opcional deve seguir o padrao: `if API_KEY: try: ... except: log(warning)`. Nunca quebrar o fluxo por ausencia de chave.

7. **Gemini -- nao bloquear o scan:**
   A chamada `_call_gemini()` tem `timeout=30`. Se falhar (sem chave, sem internet, API down), retorna `""` silenciosamente. O PDF e o prompt_recall.md sao gerados normalmente sem o sumario AI.

8. **Import correto do urllib3:**
   Usar `import urllib3` diretamente, NUNCA `requests.packages.urllib3`. O segundo quebra em versoes mais novas do requests.

---

## Arquitetura do CyberDyneWeb.py

### Fluxo de Execucao
```
main()
  +-- FASE 1: ReconEngine.run_full_recon()
  |     +-- 1. enumerate_subdomains()      -> crt.sh + HackerTarget + Wayback CDX
  |     |                                  + VirusTotal (se chave) + SecurityTrails (se chave)
  |     |                                  + Chaos/ProjectDiscovery (se chave)
  |     +-- 2. crawl_urls_gau()            -> ParamSpider + gau/OTX/Common Crawl + regex crawl
  |     +-- 3. validate_live_urls()        -> HEAD+GET, ThreadPoolExecutor(30)
  |     +-- 4. subdomain_takeover_recon()  -> EdOverflow fingerprints + NXDOMAIN+CNAME
  |     +-- 5. analyze_headers()           -> stack fingerprint, security headers
  |     +-- 6. run_theharvester()          -> theHarvester ou _python_harvester()
  |     |                                  + Hunter.io emails (se chave) + HIBP (se chave)
  |     +-- 7. run_nmap()                  -> nmap ou _python_port_scan() (top-1000 via Payloads_CY)
  |     +-- 8. github_dorking()            -> requer GITHUB_TOKEN no .env
  |     +-- 9. ai_fingerprinting()         -> AI/BaaS endpoints + prompt injection probe (AI-LLM/)
  |     +-- 10. fuzz_paths()               -> paths sensiveis + 12 wordlists do Payloads_CY
  |     +-- 11. run_whois()                -> WHOIS raw socket 2-fases (IANA -> TLD)
  |     +-- 12. linkfinder_scan()          -> [NOVO v3.0] JS endpoint discovery + API key/secret patterns
  |     +-- 13. shodan_lookup()            -> requer SHODAN_API_KEY no .env
  |     +-- _cleanup_output_dir()          -> limpa temp, gera arquivos finais
  |
  +-- SCAN AUTENTICADO (OPCIONAL): AuthenticatedCrawler
  |     +-- So executa se login_url + credenciais foram fornecidas
  |           +-- login()  -> detecta form (BeautifulSoup), posta credenciais + CSRF
  |           +-- crawl()  -> rastreia area autenticada (depth=2, max=100 paginas)
  |           |     +-- Extrai: <a href>, <form action>, <iframe src>
  |           |     +-- Detecta: fetch()/axios/ajax patterns em JS
  |           |     +-- Armazena: URLs, formularios com campos
  |           +-- Cookies -> _auth_cookies global -> injetado em safe_get()/safe_head()
  |                         -> TODOS os 111+ checks rodam autenticados automaticamente
  |
  +-- FASE 2: VulnScanner.run_all()
  |     +-- 113+ checks em 8 GRUPOS PARALELOS (workers dinamicos: 8/12/16 por intensity)
  |           -> cada check individual tem timeout=45s via ThreadPoolExecutor(1)
  |           -> OWASP Top 10, IA, BaaS/Cloud, Recon/DNS, Infra, Logica, Advanced
  |           -> [NOVO v4.5] Spinner animado + percentual + ETA recalculado por check
  |           -> [NOVO v4.5] check_js_vulnerable_libs (vuln 113) — Retire.js-style 27 libs
  |           -> se _auth_cookies esta preenchido, testa TAMBEM a area logada
  |           -> Grupos incluem: check_sqli_boolean_blind (108), check_sqli_union (109),
  |              check_graphql_csrf (110), check_waf_bypass (111),
  |              check_js_vulnerable_libs (113 — Retire.js-style)
  |           -> [NOVO v4.5] Spinner animado + percentual + ETA recalculado
  |           -> [NOVO v4.5] Workers dinamicos: medium=8, hard=12, insane=16
  |
  +-- FASE 3: Relatorios
  |     +-- [Gemini] _call_gemini() -> sumario executivo + prompt recall inteligente
  |     +-- ReportGenerator -> CyberDyneWeb_Report.pdf (PDF elegante v2)
  |     +-- PromptRecallGenerator -> prompt_recall.md (direto e curto)
  |     +-- raw_results.json
  |
  +-- FASE 4 (OPCIONAL): BruteForceProbe
        +-- So executa se login_url foi fornecida
              50 requests -> detecta ausencia de rate limit/lockout/CAPTCHA
```

---

## Step 12: linkfinder_scan() -- Novo na v3.0

Descoberta de endpoints JavaScript inspirada no LinkFinder:

- **5 regex patterns** para extrair endpoints de arquivos JS (URLs relativas, absolutas, API paths)
- **13 API key/secret patterns** para detectar chaves vazadas em JS (AWS, Stripe, Google, Firebase, etc.)
- Endpoints extraidos sao injetados em `all_urls` e `fuzzing_urls` para uso nos checks de vulnerabilidade
- Funciona em Python puro, sem dependencia do LinkFinder original

---

## Ferramentas Integradas na v3.0

Na v3.0, tecnicas de 7 ferramentas open-source foram extraidas, adaptadas ao codigo do CyberDyne, e as pastas-fonte originais foram deletadas. Abaixo o detalhamento:

### 1. sqlmap -> SQLi Enhanced

- **140 error patterns** cobrindo 30+ DBMS (MySQL, PostgreSQL, Oracle, MSSQL, SQLite, DB2, Sybase, Informix, etc.)
- **Time-based payloads multi-DBMS**: 48 payloads com `SLEEP()`, `WAITFOR DELAY`, `pg_sleep()`, `DBMS_LOCK.SLEEP()`, etc.
- **Boolean blind check** (vuln 108): 27 pares true/false para inferencia binaria
- **UNION-based check** (vuln 109): deteccao de numero de colunas + extracao
- **`_sqli_tamper(payload, technique)`**: 4 tecnicas de WAF bypass:
  - `space2comment`: substitui espacos por `/**/`
  - `randomcase`: aleatoriza maiusculas/minusculas
  - `between`: substitui `>` por `NOT BETWEEN 0 AND`
  - `charencode`: converte caracteres para `CHAR()`
- Fonte dos payloads: `Payloads_CY/SQLi/sqlmap-errors.txt`, `sqlmap-time-payloads.txt`, `sqlmap-boolean-payloads.txt`
- Tabelas e colunas para UNION: `Payloads_CY/SQLi/common-tables.txt` (3.422), `common-columns.txt` (2.854)

### 2. XSStrike -> XSS Enhanced

- **Filter checking**: testa `<>"'` antes de enviar payloads -- se todos sao filtrados, pula o alvo (economia massiva de requests)
- **Comment/bad-tag context detection**: detecta se o input cai dentro de comentario HTML ou tag invalida
- **Similarity matching**: compara resposta com/sem payload para detectar reflexao real
- **XSStrike WAF bypass payloads**: 25 payloads especializados em `Payloads_CY/XSS/xsstrike-payloads.txt`
- **Fuzz strings**: 21 strings em `Payloads_CY/XSS/xsstrike-fuzz-strings.txt`
- **DOM XSS variable tracking**: analise source->var->sink (rastreia variaveis desde a fonte ate o sink perigoso)

### 3. LinkFinder -> linkfinder_scan()

- Nova funcao em `ReconEngine` (step 12 do recon)
- Regex extrai endpoints de arquivos JS encontrados durante o crawl
- 13 patterns de API keys/secrets
- Endpoints alimentam `all_urls` e `fuzzing_urls`

### 4. graphql-cop -> GraphQL Reescrito

- **Vuln 61**: introspection + field suggestions + trace mode + IDE exposure (GraphiQL, Playground, Voyager)
- **Vuln 62**: 5 testes de DoS (deep nesting, wide query, batch, alias overload, fragment cycle)
- **Vuln 110**: CSRF audit -- testa se mutations GraphQL aceitam requests sem token CSRF

### 5. supabase-rls-checker -> Supabase Reescrito

- **Vuln 36**: teste de RLS em 60+ tabelas, storage buckets publicos, auth endpoints expostos, RPC functions
- **Vuln 37**: decode de JWT service_role para verificar permissoes elevadas
- Testa `rest/v1/`, `storage/v1/`, `auth/v1/`, `rpc/` endpoints

### 6. waf-bypass -> WAF Bypass Audit (Vuln 111)

- **120 payloads** em 16 categorias (XSS, SQLi, RCE, LFI, SSRF, etc.)
- **`_waf_encode(payload, method)`**: 5 metodos de encoding:
  - `base64`: payload em base64
  - `utf16`: encoding UTF-16
  - `htmlentity`: entidades HTML numericas
  - `double_url`: duplo URL encoding
  - `mixed_case`: alternancia maiuscula/minuscula
- **5 HTTP zones testadas**: URL param, header, body, cookie, path
- **Vendor detection**: identifica WAF especifico (Cloudflare, AWS WAF, Akamai, Imperva, ModSecurity, Sucuri)
- Fonte: `Payloads_CY/WAF-Bypass/waf-bypass-payloads.json`

### 7. prompt-inject-fuzzer -> AI Checks Reescritos

- **35 payloads** em 8 categorias (jailbreak, data extraction, role play, encoding bypass, instruction override, etc.)
- **Mutacoes**: homoglyphs (caracteres Unicode visualmente identicos) + base64 encoding
- **Deteccao**: string matching + analise comportamental (respostas longas demais, mudanca de tom, data leak)
- Vulns 26 e 27 reescritas com os novos payloads
- Fonte: `Payloads_CY/AI-LLM/prompt-inject-payloads.json`

---

## Payloads_CY -- Integracao Completa

Pasta com 35+ subpastas, todas conectadas ao script via `_load_payload(relative_path, limit)`:

| Pasta | Usada em |
|---|---|
| `SQLi/` | `check_sqli_classic()`, `check_nosql_injection()`, `check_sqli_boolean_blind()` (108), `check_sqli_union()` (109) |
| `SQLi/sqlmap-errors.txt` | 140 patterns de erro para 30+ DBMS |
| `SQLi/sqlmap-time-payloads.txt` | 48 payloads time-based multi-DBMS |
| `SQLi/sqlmap-boolean-payloads.txt` | 27 pares true/false |
| `SQLi/common-tables.txt` | 3.422 nomes de tabelas para UNION |
| `SQLi/common-columns.txt` | 2.854 nomes de colunas para UNION |
| `XSS/` | `check_xss_reflected()` (polyglots + Jhaddix + naughty strings + XSStrike payloads) |
| `XSS/xsstrike-payloads.txt` | 25 WAF bypass payloads do XSStrike |
| `XSS/xsstrike-fuzz-strings.txt` | 21 fuzz strings |
| `LFI/` | `check_lfi()` -- filtro de parametros expandido (30 nomes) |
| `Command-Injection/` | `check_cmd_injection()` |
| `SSRF/` | `check_ssrf()` -- filtro de parametros expandido (23 nomes) |
| `SSRF/ssrf-cloud-metadata.json` | GCP/Azure/DO/K8s metadata endpoints (30+ payloads) |
| `SSRF/ssrf-dns-rebinding.json` | DNS rebinding techniques, fast flux, protocol switch |
| `SSRF/ssrf-bypass-techniques.json` | IPv6, IP encoding, protocol smuggling (100+ payloads) |
| `Injection-Other/` | `check_ssti()` (template engines) |
| `Injection-Other/XXE/xxe-payloads.json` | XXE: OOB, SVG, SOAP, DTD attacks (50 payloads) |
| `Passwords/` | `check_jwt_weak_secret()`, `check_broken_auth()` |
| `Usernames/` | `check_broken_auth()` -- agora usa `self.login_url` quando fornecido |
| `Web-Discovery/` | `fuzz_paths()` (Directories, API, CMS, Web-Servers) |
| `Web-Discovery/Directories/directory-listing-wordlist.txt` | 350 paths para fuzzing |
| `Fuzzing-General/` | `fuzz_paths()`, `check_xss_reflected()`, `check_open_redirect()` |
| `Recon-Secrets/` | `github_dorking()`, `check_env_files()` |
| `Pattern-Matching/` | `check_env_files()` (sensitive keywords) |
| `Infrastructure/` | `_python_port_scan()` (nmap-ports-top1000.txt) |
| `DNS-Wordlists/` | removido -- DNS BF eliminado (substituido por Chaos API) |
| `AI-LLM/` | `ai_fingerprinting()` (jailbreaks + data leakage probes) |
| `AI-LLM/prompt-inject-payloads.json` | 35 payloads em 8 categorias (prompt-inject-fuzzer) |
| `WAF-Bypass/` | `check_waf_bypass()` (vuln 111) |
| `WAF-Bypass/waf-bypass-payloads.json` | 120 payloads em 16 categorias |
| `Open-Redirect/` | `check_open_redirect()` |
| `Open-Redirect/open-redirect-bypass-payloads.json` | URL encoding, backslash, tab/newline, protocol (30 payloads) |
| `CORS/cors-bypass-payloads.json` | Null origin, subdomain bypass, TLD confusion, IP tricks (20 payloads) |
| `JavaScript/prototype-pollution-payloads.json` | Lodash, jQuery, Vue, Axios, Angular, React gadgets (30 payloads) |
| `CRLF/crlf-injection-payloads.json` | HTTP desync, TE.CL/TE.TE, H2.CE, cache poisoning (100+ payloads) |
| `NoSQL/nosql-injection-payloads.json` | MongoDB, CouchDB, Elasticsearch (45 payloads) |
| `LDAP/ldap-injection-payloads.json` | LDAP injection basic/advance/blind (45 payloads) |
| `XPath/xpath-injection-payloads.json` | XPath injection (40 payloads) |
| `Upload/file-upload-bypass-payloads.json` | Extension, MIME, content bypass (70 payloads) |
| `Upload/zip-slip-payloads.json` | Zip slip path traversal (25 payloads) |
| `Kubernetes/k8s-endpoints-paths.json` | K8s API endpoints, secrets, pods (60 endpoints) |
| `IaC/iac-sensitive-files.json` | Terraform, K8s, Docker, AWS configs (80 files) |
| `AWS/aws-attack-vectors.json` | S3, IAM, EC2, Lambda attacks (100+ vectors) |
| `Firebase/firebase-attack-vectors.json` | Firestore, Auth, Storage rules (60 vectors) |
| `GitHub/github-dorks.json` | Sensitive data dorking (80 dorks) |
| `GraphQL/graphql-attack-vectors.json` | Introspection, batching, DoS (40 vectors) |
| `GraphQL/graphql-dangerous-mutations.json` | Privilege escalation, data destruction (60 mutations) |
| `Business-Logic/` | Account takeover, privilege escalation, price manipulation (165 vectors) |

---

## APIs Externas -- Status de Integracao

| API | Variavel `.env` | Status | Onde e usado |
|---|---|---|---|
| **Gemini (Google)** | `GEMINI_API_KEY` ou `GEMINI-API` | Integrado | `_call_gemini()` -> PDF sumario + prompt_recall |
| **Shodan** | `SHODAN_API_KEY` | Integrado | `shodan_lookup()` -> portas/vulns por IP |
| **SecurityTrails** | `SECURITYTRAILS_API_KEY` | Integrado | `_securitytrails_subdomains()` |
| **VirusTotal** | `VIRUSTOTAL_API_KEY` | Integrado | `_vt_subdomains()` |
| **Chaos (ProjectDiscovery)** | `CHAOS_API_KEY` | Integrado | `enumerate_subdomains()` |
| **Hunter.io** | `HUNTER_API_KEY` | Integrado | `_python_harvester()` -> emails |
| **HaveIBeenPwned** | `HIBP_API_KEY` | Integrado | `_python_harvester()` -> email leaks |
| **GitHub** | `GITHUB_TOKEN` | Integrado | `github_dorking()` |
| **OpenAI** | `OPENAI_API_KEY` | Integrado (v6.0) | Fallback para `_ai_generate_payloads()` quando Gemini falha |
| **NVD** | `NVD_API_KEY` | Integrado (v4.5) | `_query_nvd()` -> CVE lookup por tech/versao |
| **Vulners** | `VULNERS_API_KEY` | Integrado (v4.5) | `_query_vulners()` -> CVE lookup primario |
| **URLScan.io** | `URLSCAN_API_KEY` | Carregado, nao usado | Pendente: scan visual/screenshot |
| **BinaryEdge** | `BINARYEDGE_API_KEY` | Carregado, nao usado | Pendente: alternativa ao Shodan |
| **HackerOne** | `HACKERONE_API_KEY` | Carregado, nao usado | Pendente: verificar bug bounty scope |

> APIs marcadas como "Carregado, nao usado" tem a variavel carregada mas nenhuma funcao as chama ainda.
> Nao quebram o scan -- sao simplesmente ignoradas.

---

## Bugs Conhecidos e Corrigidos

### Historico (v1.0 - v2.0)

| Bug | Causa | Fix |
|---|---|---|
| `validate_live_urls` congela | `log()` dentro de `with lock:` -> deadlock reentrante | `print()` direto fora do lock |
| `subdomain_takeover_recon` congela | Mesmo deadlock | Construir string antes, imprimir depois do lock |
| `fuzz_paths` congela | Mesmo deadlock | `print()` fora do lock |
| `run_all` congela | Check individual sem timeout | `ThreadPoolExecutor(1).submit().result(timeout=45)` |
| DNS brute-force -> 404s em massa | Wordlist gera centenas de falsos positivos | **DNS BF removido** -- substituido por Chaos API |
| `nmap-ports-top1000.txt` retorna 1 entrada | Arquivo tem todos os 1000 portas em 1 linha CSV | Parser proprio com split por `,` e range expansion |
| `socket.gethostbyname()` trava Windows | Sem timeout no nivel do SO | Removido -- so usa `dns.resolver` |
| `httpx` ausente congela | `done[0]` nunca incrementava | Reescrito como `validate_live_urls` |
| `BASE_DELAY=0.5` lento | 0.5s por request, 107 checks | Reduzido para `0.1s` via env var |
| crt.sh timeout longo | timeout=25s sem retry | 12s + 1 retry de 20s |

### Corrigidos na v3.0

| Bug | Causa | Fix |
|---|---|---|
| RFI detection quebrado | Nao comparava resposta com baseline | Agora usa canary + comparacao com baseline |
| XSS Stored so testava root page | Scaneava apenas `/` | Agora scanneia `self.urls[:10]` |
| Broken Auth nao usava login_url | Sempre testava a root | Agora usa `self.login_url` quando fornecido |
| LFI filtro de parametros fraco | Apenas 7 nomes de parametros | Expandido para 30 nomes |
| SSRF filtro de parametros fraco | Apenas 9 nomes de parametros | Expandido para 23 nomes |
| NoSQL detection falsos positivos | Keyword matching no body inteiro | Agora usa comparacao com baseline |
| CSRF so testava root page | Scaneava apenas `/` | Agora scanneia `self.urls[:8]` |
| SSTI expected values incorretos | Checava valores fixos sem verificar presenca de `7*7` | Agora condicional na presenca de `7*7` |
| Import quebrado em requests novos | `requests.packages.urllib3` deprecated | Mudado para `import urllib3` direto |

---

## PDF Report -- Evolucao

### v1 (original)
- Cover simples com titulo e tabela de metadados
- Vulnerabilidades listadas em tabelas planas
- Sem page numbers
- Sem separacao visual por severidade

### v2 (atual)
- **Cover** com header escuro (`#0f172a`), metadados, risk gauge colorido, severity badges
- **Sumario executivo** com texto Gemini (quando disponivel) em box azul
- **Section headers** -- barras coloridas `#1e40af` entre secoes
- **Vulnerability cards** -- cada vuln tem card colorido por severidade (borda + fundo tonal)
- **Page numbers** -- footer em todas as paginas via `onLaterPages=_page_footer`
- **Vulns agrupadas por severidade** -- Critico -> Alto -> Medio -> Baixo, com contador
- **Subdominios** -- status ATIVO/INATIVO colorido individualmente

---

## Prompt Recall -- Evolucao

### v1 (original)
- Verboso, com secoes de "como usar", "exemplo de prompt", "prioridade de remediacao"
- Incluia subdominios, timestamps, instrucoes longas
- Nao util para copiar/colar diretamente

### v2 (atual)
- **Cabecalho de 2 linhas** com target, data e contagem de vulns
- **Conteudo Gemini** quando disponivel (prompt direto gerado por IA)
- **Fallback**: lista minima por severidade -- endpoint + evidencia + fix -- sem rodeios
- Formato: pode ser colado direto em qualquer agente de IA

---

## Ferramentas Portadas para Python Puro

| Ferramenta | Substituto Python | Localizacao |
|---|---|---|
| `subfinder` | crt.sh + HackerTarget + Wayback CDX + Chaos + VT + SecurityTrails | `enumerate_subdomains()` |
| `httpx` | `validate_live_urls()` com requests HEAD+GET | Metodo em `ReconEngine` |
| `nmap` | `_python_port_scan()` com socket (top-1000 via Payloads_CY) | Metodo em `ReconEngine` |
| `theHarvester` | `_python_harvester()` -- scraping + HackerTarget + Hunter.io | Metodo em `ReconEngine` |
| `gau` | `_python_gau()` -- OTX AlienVault + Common Crawl | Metodo em `ReconEngine` |
| `subzy` | `subdomain_takeover_recon()` -- EdOverflow fingerprints | Metodo em `ReconEngine` |
| `ParamSpider` | `_paramspider_collect()` -- Wayback CDX + limpeza | Metodo em `ReconEngine` |
| `LinkFinder` | `linkfinder_scan()` -- regex endpoint extraction + API key detection | Metodo em `ReconEngine` |
| `OpenRedireX` | `check_open_redirect()` -- 44+ payloads de bypass | Metodo em `VulnScanner` |
| `dalfox` | `check_xss_reflected()` -- 7-phase pipeline, 60+ payloads + XSStrike filter check | Metodo em `VulnScanner` |
| `nuclei` | 6 checks portados (paths, swagger, cache, HPP, deser, js) | `check_nuclei_paths()` + outros |
| `Wappalyzer` | `detect_technologies()` -- 62 techs, 8 vetores | inline em `analyze_headers()` |
| `whois` CLI | WHOIS raw socket 2-fases (IANA -> TLD) | `run_whois()` |
| `Passcrack` | `BruteForceProbe` -- deteccao de ausencia de rate limit | Classe propria |
| `sqlmap` | 140 error patterns, time-based multi-DBMS, boolean blind, UNION, tamper | `check_sqli_*()` + `_sqli_tamper()` |
| `XSStrike` | Filter check, context detection, similarity, WAF bypass payloads | `check_xss_reflected()` + DOM XSS |
| `graphql-cop` | Introspection, field suggestions, DoS, CSRF audit | `check_graphql_*()` |
| `supabase-rls-checker` | 60+ table RLS, storage, auth, RPC, JWT decode | `check_supabase_*()` |
| `waf-bypass` | 120 payloads, 5 encodings, 5 zones, vendor detection | `check_waf_bypass()` |
| `prompt-inject-fuzzer` | 35 payloads, 8 categorias, mutations, behavioral detection | `check_prompt_injection()` |

---

## Funcoes Utilitarias Novas (v3.0)

### `_sqli_tamper(payload, technique)`
Aplica uma das 4 tecnicas de WAF bypass ao payload SQLi:
- `space2comment`: `SELECT * FROM` -> `SELECT/**/*/FROM`
- `randomcase`: `SELECT` -> `sElEcT`
- `between`: `> 0` -> `NOT BETWEEN 0 AND 0`
- `charencode`: caracteres -> `CHAR(n)`

### `_waf_encode(payload, method)`
Aplica um dos 5 metodos de encoding ao payload:
- `base64`: payload em base64
- `utf16`: encoding UTF-16
- `htmlentity`: entidades HTML numericas (`&#60;` etc.)
- `double_url`: duplo URL encoding (`%253C` etc.)
- `mixed_case`: alternancia maiuscula/minuscula

---

## Authenticated Crawler -- Decisoes de Design

1. **Cookies globais** -- `_auth_cookies` e um dict global preenchido pelo `AuthenticatedCrawler.login()`. Injetado automaticamente em `safe_get()` e `safe_head()` via parametro `cookies=`. Isso garante que **todos os 111+ checks** rodem autenticados sem precisar alterar cada check individual.
2. **Deteccao de formulario** -- reutiliza a mesma logica do `BruteForceProbe._detect_form()` (BeautifulSoup + heuristicas de campo). Detecta CSRF tokens automaticamente.
3. **Verificacao de login** -- heuristicas: (a) cookies foram setados, (b) body nao contem "incorrect/invalid/wrong", (c) nao redirecionou de volta para a mesma login_url com erro.
4. **Profundidade de crawl** -- default `depth=2`, `max_pages=100`. Segue links `<a>`, forms `<form>`, iframes, e padroes JS (`fetch`, `axios`, `.ajax`).
5. **Filtro de assets** -- ignora `.png,.jpg,.css,.woff,.mp4,.pdf,.zip` etc para nao poluir.
6. **Totalmente opcional** -- se o usuario nao fornecer credenciais, nenhum codigo autenticado roda. `_auth_cookies` fica `{}` e `safe_get()` passa `cookies=None`.
7. **Senha oculta** -- usa `getpass.getpass()` para nao mostrar a senha no terminal.

---

## Coisas Para Nao Mudar

- **Nunca** adicionar `socket.gethostbyname()` -- trava Windows
- **Nunca** chamar `log()` dentro de `with lock:` -- deadlock garantido
- **Nao** tornar ferramentas externas obrigatorias -- deve rodar em Python puro
- **Nao** reintroduzir DNS BF por wordlist -- gera 404s em massa, sem valor pratico
- **Nao** bloquear o scan por falha de API -- `_call_gemini()` e todas as APIs devem ser `try/except` silencioso
- **Nao** committar o `.env` no git -- `.gitignore` ja protege, mas nunca remover essa entrada
- **Nao** remover `.checkpoint.cyb` da `.gitignore` -- contem estado do scan com URLs e cookies
- **Nao** usar `safe_get()` dentro de `_regex_crawl()` ou `analyze_headers()` -- usar `requests.get()` direto para evitar stealth delay no crawl
- **Nunca** remover WAF bypass payloads de `Payloads_CY/WAF-Bypass/` -- sao a fonte para `check_waf_bypass()` (vuln 111). Sem eles o check nao funciona.
- **Nunca** simplificar os checks de SQLi de volta para keyword matching simples -- os 140 patterns do sqlmap sao criticos para deteccao precisa em 30+ DBMS. Keyword matching gera falsos positivos massivos.
- **Nunca** remover o filter checking do XSS (`<>"'` test antes dos payloads) -- e o principal ganho de eficiencia vindo do XSStrike. Sem ele, o scanner gasta requests desnecessarios em alvos que filtram tudo.
- **Nunca** usar `requests.packages.urllib3` -- usar `import urllib3` diretamente

---

## Sessao v6.0 — Mega Update (21/03/2026)

### FASE 1: AI Payloads v2 + Fingerprint v2

**AI Payloads v2:**
- OpenAI fallback (`gpt-4o-mini`) quando Gemini falha — `OPENAI_API_KEY` no `.env`
- Prompt profissional com contexto rico: tech stack, WAF detectado, form fields, URL params
- Expandido de 6 para 12 checks com AI payloads (adicionado: NoSQL, XXE, Open Redirect, CRLF, WAF Bypass, LDAP)
- `_ai_feedback_round()` — round 2 de payloads bypass quando WAF bloqueia (so em --insane)
- Token tracking para ambos provedores (`_gemini_tokens_used` + `_openai_tokens_used`)

**Fingerprint v2:**
- 114+ tecnologias (de 89) — adicionadas 25: Remix, SvelteKit, HTMX, Qwik, Auth0, Clerk, NextAuth.js, Keycloak, PocketBase, Appwrite, Cloudflare Pages, Railway, Render, Fly.io, PostHog, Plausible, Apollo GraphQL, tRPC, Zustand, Pinia, Vercel AI SDK, LangChain, Directus, Payload CMS
- Categorias normalizadas de 60+ para ~20 padronizadas
- Campos `implies`/`excludes` em 18 techs (ex: Next.js implies React + Node.js, excludes Nuxt.js)
- `version_pattern` em 9 techs (jQuery, Bootstrap, Tailwind, etc.)
- `_detect_dns_hosting()` — deteccao por CNAME (14 provedores)
- `_detect_tls_issuer()` — deteccao por certificado TLS (7 issuers)
- Post-processing em `detect_technologies()`: implies adiciona techs inferidas, excludes remove conflitos, version extraction

### FASE 2: 14 Checks Melhorados

| Check | Melhoria |
|---|---|
| CSRF (014) | Testa se token e VALIDADO (request sem token + token invalido) |
| IDOR (015) | Compara CONTEUDO entre usuarios (regex email/nome), nao so status |
| Rate Limit (033) | Burst de 50 requests com ThreadPoolExecutor, mede degradacao |
| XSS Reflected (005) | 11 mutation payloads (double URL encode, null byte, unicode, CharCode) |
| SSRF (011) | 10 bypass payloads (IPv6, decimal IP, DNS rebinding, GCP/Azure metadata) |
| SSTI (020) | Blind timing (Jinja2 range, Spring EL sleep, ERB Thread.sleep) |
| NoSQL (013) | Timing attack ($where sleep, $regex catastrophic) |
| HPP (078) | Identifica QUAL valor o server usa (first/last/both) |
| Broken Auth (024) | Compara response valida vs invalida (size, redirect, status) |
| Mass Assignment (031) | POST + GET para verificar persistencia |
| Session Fixation (115) | Testa sem login — cookie arbitrario mantido? |
| Security.txt (114) | Valida RFC 9116: Contact, Expires, formato |
| Sensitive Data URL (097) | Shannon entropy em param values (>3.5 + >20 chars = leak) |
| Logging (019) | 20 requests com SQLi payload, detecta falta de rate-limit |

### FASE 3: Login v2

- `--auth-header "Bearer TOKEN"` — injeta em toda request via `safe_get()`
- `analyze_session()` — JWT decode (alg, exp, claims), cookie entropy, flags (HttpOnly/Secure/SameSite)
- Session refresh a cada 30min (`_maybe_refresh_session()`)
- Deteccao de logout (`_check_auth_alive()`) — 401/403/redirect/body keywords
- `test_concurrent_sessions()` — 2 logins, verifica se sessao anterior invalida
- `verify_logout()` — testa se cookie antigo funciona apos logout
- `enumerate_roles()` — 12 rotas admin + bypass headers (X-Forwarded-For, X-Original-URL)
- Tudo integrado no `run()` do AuthenticatedCrawler

### FASE 4: Browser Mimic Expandido (6 → 16 checks)

Novos checks (207-216):
| # | Check | Tecnica |
|---|---|---|
| 207 | WebSocket Hijacking | WS connection test + endpoint enum |
| 208 | Service Worker Spy | SW registration + scope + script analysis |
| 209 | Clipboard Hijacking | copy/cut/paste event listener detection |
| 210 | Form Autofill Theft | Hidden inputs com autocomplete sensivel |
| 211 | CSP Bypass Real | Inline script injection + eval() test real |
| 212 | Cookie Theft via JS | document.cookie — session cookies sem HttpOnly |
| 213 | Keylogger Detection | keydown/keypress listeners + exfiltration patterns |
| 214 | Redirect Chain | Full chain analysis, HTTP downgrade, external domains |
| 215 | Shadow DOM Leak | Open shadow roots com dados sensiveis |
| 216 | Network Interception | page.route — auth tokens externos, mixed content |

### FASE 5: --tor Support

- `--tor` flag — SOCKS5 proxy so na Fase 2 (vulnerabilidades)
- `_check_tor_running()` — verifica via `check.torproject.org/api/ip`
- `_refresh_tor_circuit()` — NEWNYM signal a cada 50 requests
- `safe_get()` e `adaptive_request()` usam `_TOR_PROXIES` quando ativo
- `PySocks>=1.7.1` adicionado ao requirements.txt

### FASE 6: Live Dashboard v2

- Redesign completo: Tailwind CDN + Chart.js
- Paleta: preto (#000000), vermelho (#dc2626), branco
- Cards de severidade animados
- Progress bar com gradiente vermelho
- Timeline chart (linha vermelha vulns + branca checks)
- Recon stats panel
- Vuln feed com slide-in animation
- Subdomain grid com indicadores
- Responsivo mobile

---

## Mapa de Vulnerabilidades (115+ checks)

### OWASP Top 10 (001-020)

| # | Vulnerabilidade | Metodo de Deteccao |
|---|---|---|
| 001 | SQL Injection (Error-based) | 140 error patterns (sqlmap), 30+ DBMS |
| 002 | SQL Injection (Time-based Blind) | 48 payloads multi-DBMS + latencia real > 4.5s |
| 003 | XSS Reflected | 7-phase pipeline + XSStrike filter check + WAF bypass payloads |
| 004 | XSS Stored | POST + GET verification, scanneia `self.urls[:10]` |
| 005 | XSS DOM | 13 sources x 19 sinks + variable tracking (source->var->sink) |
| 006 | CSRF | Ausencia de token em formularios POST, scanneia `self.urls[:8]` |
| 007 | SSRF | Payload para metadata cloud, 23 nomes de parametros |
| 008 | LFI / Path Traversal | 20+ payloads, 30 nomes de parametros |
| 009 | Remote Code Execution | eval/exec em parametros |
| 010 | Command Injection | ; && | com sleep/id |
| 011 | XXE | XML com entidade externa |
| 012 | Open Redirect | 44 payloads de bypass (portado do OpenRedireX) |
| 013 | Insecure Deserialization | Magic bytes + endpoints RPC |
| 014 | Security Misconfiguration | Headers ausentes, metodos HTTP |
| 015 | Broken Access Control | Path traversal para admin |
| 016 | Cryptographic Failures | TLS fraco, HTTP sem redirect |
| 017 | Vulnerable Components | Versoes desatualizadas em headers |
| 018 | Insufficient Logging | Sem logs em erro 500 |
| 019 | IDOR | IDs sequenciais em APIs |
| 020 | Mass Assignment | Campos extras aceitos por APIs |
| -- | RFI (Remote File Inclusion) | Canary + comparacao com baseline (corrigido v3.0) |

### IA-Induced (021-035)

| # | Vulnerabilidade |
|---|---|
| 021 | JWT sem assinatura (alg: none) |
| 022 | JWT com chave fraca |
| 023 | Prompt Injection (campos de texto) |
| 024 | Race Condition (concurrent requests) |
| 025 | Prototype Pollution |
| 026 | Prompt Injection avancado (35 payloads, 8 categorias, homoglyph + base64 mutations) |
| 027 | AI Data Extraction (behavioral detection + string match) |
| 028 | API Rate Limit ausente |
| 029 | Exposicao de stack trace |
| 030 | Debug mode ativo (Flask/Django) |
| 031 | Endpoints de metricas expostos (/metrics, /actuator) |
| 032 | Variaveis de ambiente expostas |
| 033 | CORS misconfiguration (credenciais + wildcard) |
| 034 | WebSocket sem autenticacao |
| 035 | Server-Side Template Injection (SSTI) -- expected values condicionais |

### BaaS / Cloud (036-045)

| # | Vulnerabilidade |
|---|---|
| 036 | Supabase RLS desabilitado (60+ tabelas, storage buckets, auth endpoints, RPC functions) |
| 037 | Supabase service_role JWT decode (permissoes elevadas) |
| 038 | S3 Bucket publico |
| 039 | Cognito misconfiguration |
| 040 | Exposed Supabase anon key |
| 041 | Firebase API key exposta |
| 042 | AWS credentials em JS |
| 043 | Stripe secret key exposta |
| 044 | SendGrid / Twilio key em JS |
| 045 | Google AI / Mapbox key exposta |

### Recon / DNS (046-055)

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
| 055 | Wayback JS Leakage (secrets em JS historico) |

### Infra / Headers (056-075)

| # | Vulnerabilidade |
|---|---|
| 056 | Host Header Injection |
| 057 | HTTP Request Smuggling (CL.TE) |
| 058 | HTTP Splitting |
| 059 | Cache Poisoning |
| 060 | Web Cache Deception |
| 061 | GraphQL Introspection + Field Suggestions + Trace + IDE (reescrito com graphql-cop) |
| 062 | GraphQL DoS (5 testes: deep nesting, wide query, batch, alias overload, fragment cycle) |
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
| 073 | API endpoints sem autenticacao |
| 074 | GraphQL playground exposto |
| 075 | Swagger/OpenAPI exposto |

### Logica / Autenticacao (076-100)

| # | Vulnerabilidade |
|---|---|
| 076 | File Upload sem restricao |
| 077 | Insecure cookies (sem HttpOnly/Secure/SameSite) |
| 078 | Account enumeration (timing attack) |
| 079 | Password reset flaws |
| 080 | Session fixation |
| 081 | Broken function-level authorization (usa login_url quando fornecido) |
| 082 | OAuth misconfiguration |
| 083 | 2FA bypass |
| 084 | Insecure direct object reference (IDOR) na API |
| 085 | Business logic bypass (preco negativo) |
| 086 | Regex DoS (ReDoS) |
| 087 | XML Bomb (Billion laughs) |
| 088 | ZIP Slip |
| 089 | LDAP Injection |
| 090 | XPath Injection |
| 091 | NoSQL Injection (comparacao com baseline, nao keyword matching) |
| 092 | HTTP Parameter Pollution |
| 093 | Default credentials em paineis |
| 094 | TLS/SSL fraco (TLS 1.0/1.1, RC4, NULL) |
| 095 | Certificate transparency issues |
| 096 | Subdomain wildcard certificate |
| 097 | Mixed content (HTTP em HTTPS) |
| 098 | Sensitive data in URL |
| 099 | Error messages detalhadas |
| 100 | Security.txt ausente |

### Nuclei+ (101-107)

| # | Vulnerabilidade | Metodo |
|---|---|---|
| 101 | Paths sensiveis expostos | 250+ paths em paralelo (15 threads) |
| 102 | Swagger/API docs expostos | 35 API doc paths |
| 103 | HTTP Parameter Pollution | Parametros duplicados com valores diferentes |
| 104 | Default credentials | 20 pares comuns em formularios detectados |
| 105 | Deserialization RCE | Magic bytes Java/Python/PHP + endpoints RPC |
| 106 | Web Cache Deception | .css/.js em URLs privadas + headers de cache |
| 107 | JS Secrets (14 tipos) | Regex para anon keys, AWS, Stripe, GitHub, etc. |

### Advanced (108-111) -- Novos na v3.0

| # | Vulnerabilidade | Metodo |
|---|---|---|
| 108 | SQLi Boolean Blind | 27 pares true/false, inferencia binaria, tamper bypass |
| 109 | SQLi UNION-based | Deteccao de numero de colunas + extracao de dados |
| 110 | GraphQL CSRF | Mutations sem token CSRF (graphql-cop) |
| 111 | WAF Bypass Audit | 120 payloads, 5 encodings, 5 zones, vendor detection |

---

## Novas Features v4.0

### CLI com argparse (substituiu modo interativo como padrao)

O `main()` agora usa `argparse` completo. O modo interativo (perguntas no terminal) continua funcionando como fallback quando nenhum `--url` e passado.

**Flags disponiveis:**
| Flag | Descricao |
|---|---|
| `--url URL` | URL alvo (se omitido, entra no modo interativo) |
| `--login URL` | URL do painel de login |
| `-ul` / `--userlogin` | Email ou usuario para scan autenticado |
| `-pl` / `--passlogin` | Senha para scan autenticado |
| `--all` | Executa tudo: recon + vuln + relatorios (default se nenhum modo especificado) |
| `--recon` | Apenas reconhecimento |
| `--vuln` | Apenas scan de vulnerabilidades |
| `--stealth` | Modo fantasma |
| `--ai-payloads` | Gemini gera payloads contextuais |
| `--live` | Dashboard Flask em localhost:5000 |
| `--browser-mimic` | Playwright: DOM XSS real, clickjacking iframe, storage leaks, SPA routes |
| `--project NOME` | Nome da pasta de output |

**Decisao de design:** Se nem `--all`, `--recon` ou `--vuln` forem passados, o padrao e `--all` (faz tudo). Isso mantem a experiencia simples para quem so quer `python CyberDyneWeb.py --url X`.

### --browser-mimic (Playwright Browser Testing)

**Classe:** `CyberBrowser` (~400 linhas)
**Dependencias:** `playwright`, `playwright-stealth`, `fake-useragent` (opcionais — try/except)
**Fase:** 2.5 — roda DEPOIS dos 111+ checks, ANTES dos relatorios
**Lifecycle:** 1 browser + 1 context + N pages (1 por check)

**Anti-Fingerprinting:**
- `playwright-stealth` mascara `navigator.webdriver: true`
- `--disable-blink-features=AutomationControlled`
- User-Agent randomico via `fake-useragent`

**Interacao Humana:**
- `_bezier_move()`: mouse em curva cubica (2 control points aleatorios, 20-35 steps, delay 5-12ms)
- `_human_type()`: char-by-char com delay 50-150ms, fallback para `.fill()` se seletor falhar

**6 Checks Browser-Based:**

| Vuln ID | Check | Tecnica |
|---------|-------|---------|
| 201 | DOM XSS Real | Injeta payloads com marker `CYBERDYNE_XSS_201` em params + forms. `page.on("console")` monitora. Se marker aparece → XSS confirmado + screenshot |
| 202 | AI-Output Injection | Navega a 8 AI endpoints. Envia prompt com HTML malicioso via human typing. Se console.error dispara → output renderizado como HTML |
| 203 | Prototype Pollution | URL com `?__proto__[polluted]=MARKER`. `page.evaluate("({}).polluted")` verifica. Se retorna marker → pollution confirmada |
| 204 | Storage Leak | `page.evaluate()` extrai localStorage+sessionStorage. 8 regex patterns (JWT, Stripe, AWS, GitHub, Slack, Supabase). Dump salvo em `browser_storage_dump.json` |
| 205 | SPA Hidden Routes | Detecta framework (Next/Nuxt/Vue/Angular/React). Extrai routes de JS bundles. Tenta acessar routes admin sem auth |
| 206 | Clickjacking Real | `page.set_content()` com iframe apontando pro alvo. Se renderiza → X-Frame-Options/CSP nao bloqueia |

**Evidencia Visual:**
- Screenshots PNG em `output_dir/screenshots/` — embedados no PDF via `RLImage`
- Console logs em `browser_console_logs.json`
- DOM dumps no campo evidence do VulnResult
- `VulnResult.screenshot_path` = caminho do PNG (novo atributo)
- `ReportGenerator._vuln_card()` detecta screenshot_path e embeda imagem no card do PDF

**Coisas Para Nao Mudar:**
- **Nunca** tornar playwright obrigatorio — `HAS_PLAYWRIGHT` controla tudo
- **Nunca** rodar CyberBrowser dentro do ThreadPoolExecutor dos grupos — roda sequencial na main()
- **Nunca** usar async playwright — tudo sync para consistencia com o resto do codebase

### --stealth (Modo Fantasma)

**Global:** `_STEALTH_MODE` (bool)
**Funcao:** `_stealth_delay()` — chamada automaticamente em `safe_get()`, `safe_head()` e `adaptive_request()`

Quando ativo:
1. Aplica delay aleatorio entre 0.3s e 1.5s antes de cada request
2. Rotaciona User-Agent entre 8 UAs reais (Chrome/Firefox/Safari/Edge, desktop+mobile)
3. Altera `HEADERS_BASE["User-Agent"]` a cada request

**Integrado em:** `safe_get()`, `safe_head()`, `adaptive_request()` — afeta TODOS os requests do sistema automaticamente.

### --ai-payloads (Gemini Payloads Contextuais)

**Global:** `_AI_PAYLOADS_MODE` (bool), `_gemini_tokens_used` (int)
**Funcao:** `_ai_generate_payloads(vuln_type, context_html, url="")`
**Modelo:** `gemini-2.0-flash-lite` (mais barato, free tier de 1M tokens/min)

Fluxo:
1. No inicio de cada check, se `_AI_PAYLOADS_MODE` esta ativo, o check faz `safe_get(self.target)` para capturar o HTML
2. O HTML (primeiros 2000 chars) e enviado ao Gemini junto com o tipo de vulnerabilidade
3. Gemini retorna 15 payloads especificos para aquele contexto
4. Payloads sao **somados** aos existentes (nao substituem)
5. No final do scan, imprime quantos tokens foram usados e quantos restam no free tier

**Checks com AI payloads:**
- `check_xss_reflected()` — XSS contextuais
- `check_sqli_classic()` — SQLi contextuais
- `check_lfi()` — LFI/Path Traversal
- `check_cmd_injection()` — Command Injection / RCE
- `check_ssti()` — SSTI
- `check_ssrf()` — SSRF

**Decisao:** Escolhemos esses 6 porque sao os que mais se beneficiam de payloads adaptados ao contexto (campos de form, nomes de variaveis, frameworks detectados). Checks como JWT, GraphQL, WAF Bypass ja tem payloads especializados que nao ganham com contexto HTML.

### --live (Dashboard Visual em Tempo Real)

**Dependencia:** Flask (opcional — `pip install flask`)
**Funcao:** `_start_live_dashboard(port=5000)`
**Data store:** `_live_data` (dict global)
**Update:** `_live_update(phase, progress, total, vuln)` — chamado do `main()` e de `VulnScanner._add()`

O dashboard:
- Roda como thread daemon (nao bloqueia o scan)
- Serve HTML+CSS+JS inline (sem arquivos externos)
- UI dark com cards de severidade (Critico/Alto/Medio/Baixo/Seguro)
- Barra de progresso animada
- Lista de vulns encontradas em tempo real (ultimas 30, scroll)
- Polling a cada 2s via fetch() no browser
- API endpoint: `GET /api/status` retorna JSON com estado atual

Apos o scan finalizar, o dashboard fica ativo para consulta ate o usuario dar Ctrl+C.

### jwt_tool Integration (v3.0 -> v4.0)

**Tecnicas extraidas do jwt_tool v2.3.0:**

| Ataque | CVE | Vuln ID | Descricao |
|---|---|---|---|
| alg:none (4 variantes) | CVE-2015-2951 | 21 | none, None, NONE, nOnE — testa aceitacao sem assinatura |
| Null signature | CVE-2020-28042 | 21 | Assinatura vazia aceita |
| Psychic ECDSA | CVE-2022-21449 | 21 | Assinatura fixa `MAYCAQACAQA` aceita |
| Blank password HMAC | — | 21 | HMAC com key vazia aceita |
| Weak secret cracking | — | 22 | 330+ senhas (jwt-tool-common.txt + scraped) × HS256/384/512 |
| JWKS endpoint exposure | — | 23 | 7 paths de JWKS |
| KID path traversal | — | 23 | `../../dev/null`, blank kid |
| KID SQL injection | — | 23 | `x' UNION SELECT '1';--` com key=`1` |
| Claim tampering | — | 23 | 6 claims de escalacao (role=admin, is_admin=True, etc.) |

**Payload copiado:** `Payloads_CY/Passwords/JWT-Secrets/jwt-tool-common.txt` (130 senhas)

### ReconReportGenerator (Recon.md + Recon.pdf)

Classe nova que consolida todos os dados de reconhecimento em 2 arquivos unicos. Substitui a necessidade de abrir 10+ JSONs individuais.

**Dados incluidos:** WHOIS, stack tecnologica, subdominios com status, takeover, portas abertas, Shodan, emails, GitHub dorking, fuzzing paths, LinkFinder endpoints/secrets, AI/BaaS endpoints, URLs com parametros, brute force probe.

**Integrado no main():** Chamado na Fase 3 (Relatorios), depois do prompt_recall.md.

### GitHub Dorking Bug Fix

**Problema:** Rate-limit sem retry → query perdida → 0 findings.
**Fix:** Agora le `X-RateLimit-Reset` header, calcula espera exata, e faz **retry automatico** da query que falhou.
**Bonus:** Conectou `GitHub/github-dorks.json` (80 dorks extras).

### Payloads_CY — 29 pastas totais

Novos payloads conectados na v4.0:
- `NoSQL/nosql-injection-payloads.json` (45 payloads) → `check_nosql_injection()`
- `LDAP/ldap-injection-payloads.json` (45 payloads) → `check_ldap_injection()`
- `XPath/xpath-injection-payloads.json` (40 payloads) → `check_xpath_injection()`
- `CRLF/crlf-injection-payloads.json` (40 payloads) → `check_crlf_injection()`
- `Upload/` (file-upload-bypass + zip-slip) → `check_file_upload()`
- `Kubernetes/k8s-endpoints-paths.json` (60 endpoints) → `fuzz_paths()`
- `IaC/iac-sensitive-files.json` (80 files) → `fuzz_paths()`
- `AWS/aws-attack-vectors.json` (100+ vectors) → ja conectado
- `Firebase/firebase-attack-vectors.json` (60 vectors) → `check_firebase_rules()`
- `GitHub/github-dorks.json` (80 dorks) → `github_dorking()`
- `GraphQL/graphql-attack-vectors.json` (40 vectors) → `check_graphql_introspection()`
- `Business-Logic/` (3 JSONs, 165 vectors) → `check_business_logic_errors()`
- `Web-Discovery/Directories/directory-listing-wordlist.txt` (350 paths) → `check_directory_listing()` + `fuzz_paths()`

---

## Changelog Resumido

### v4.1 -- 20/03/2026
- **~13.900 linhas** (era ~12.000 na v4.0)
- **Checkpoint/Resume**: Auto-save `.checkpoint.cyb` apos cada grupo de vulns. `--resume FILE` retoma scan de onde parou.
  - `_save_checkpoint()`: serializa estado completo (target, URLs, recon, results, cookies, modos)
  - `_load_checkpoint()`: reconstitui VulnResults e restaura estado
  - Auto-remove `.checkpoint.cyb` quando scan finaliza com sucesso
  - `run_all(skip_ids=, resume_group=)`: pula checks ja completados
- **Docker**: Dockerfile (leve ~250MB), Dockerfile.full (com Playwright ~1.5GB), docker-compose.yml, .dockerignore
  - Volume monta `./outputs` e `.env` (read-only)
  - `network_mode: host` para acesso direto a rede
  - Porta 5000 exposta para --live dashboard
- **WordPress Security Audit (--wp)**: classe WPAudit com 12 checks especializados
  - Deteccao de versao WP (5 metodos: meta generator, feed, readme.html, login page, hash comparison)
  - Enumeracao de plugins (top-500 wordlist, 20 threads, deteccao de versao via readme.txt)
  - Enumeracao de temas (style.css version extraction)
  - Enumeracao de usuarios (REST API /wp-json/wp/v2/users + author ID enumeration)
  - xmlrpc.php testes (system.listMethods, pingback.ping, multicall amplification)
  - wp-cron.php DoS check
  - Debug log exposure (wp-content/debug.log)
  - Config backup discovery (wp-config.php.bak, .old, .save, ~, .swp)
  - REST API auth bypass
  - Upload directory listing
  - WP-Login brute force protection check
  - CVE correlation via Vulners/NVD APIs para versoes detectadas
  - Roda automaticamente se --all + WordPress detectado, ou com --wp explicito
- **Crawl fix**: `_regex_crawl()` e `analyze_headers()` agora usam `requests.get()` direto em vez de `safe_get()` para evitar stealth delay no crawl
- **Pylance fix**: `from concurrent.futures import ThreadPoolExecutor` adicionado para resolver warning

### v4.0 -- 19/03/2026
- **~12.000 linhas** (era ~10.000 na v3.0)
- **CLI completa com argparse**: `--url`, `--login`, `-ul`, `-pl`, `--all`, `--recon`, `--vuln`, `--stealth`, `--ai-payloads`, `--live`, `--project`
- **--stealth**: delay random 0.3-1.5s + rotacao de 8 User-Agents reais em safe_get/safe_head/adaptive_request
- **--ai-payloads**: Gemini 2.0 Flash Lite gera 15 payloads contextuais por alvo (XSS, SQLi, LFI, RCE, SSTI, SSRF)
- **--live**: Dashboard Flask em localhost:5000 — progresso, severidades, vulns em tempo real
- **jwt_tool integrado**: alg:none 4 variantes, null sig, psychic ECDSA (CVE-2022-21449), blank password, 330+ weak secrets, JWKS exposure, KID injection/SQLi, claim tampering
- **ReconReportGenerator**: Recon.md + Recon.pdf consolidam todos os dados de reconhecimento
- **29 pastas de payloads**: +12 novos JSONs conectados (NoSQL, LDAP, XPath, K8s, IaC, Firebase, GraphQL, Business-Logic, GitHub dorks, directory-listing)
- **GitHub Dorking fix**: retry automatico apos rate-limit + X-RateLimit-Reset header
- **--browser-mimic**: CyberBrowser com Playwright — 6 checks client-side (DOM XSS real, AI-Output Injection, Prototype Pollution, Storage Leak, SPA Hidden Routes, Clickjacking Real)
- **Evidencia visual**: screenshots PNG embedados no PDF via RLImage + console logs + DOM dumps
- **Anti-fingerprinting**: playwright-stealth + Bezier mouse + human typing + fake UA
- **README.md reescrito**: novo formato curto e direto, sem nomes de ferramentas, sem regras de contribuicao

### v3.0 -- 18/03/2026
- ~10.000 linhas, 111+ checks, 7 ferramentas integradas
- SQLi/XSS/GraphQL/Supabase/WAF/AI checks reescritos com tecnicas avancadas
- linkfinder_scan() como step 12 do recon

### v4.5 -- 20/03/2026
- **Payload Intensity Levels**: --medium (30%), --hard (60%), --insane (100%)
- **Crypto Audit Avancado**: ROT13, hex encoding, rainbow table expandida (30 hashes), cookies sequenciais, double-base64
- **Retire.js Scanner** (vuln 113): 27 bibliotecas JS monitoradas com CVE correlation
- **Progress Display**: spinner animado, percentual, ETA recalculado por check
- **Threads Dinamicos**: 8/12/16 workers vinculados ao intensity level
- **Extracao de Payloads**: +31.972 payloads de 5 pastas externas (kali, FUZZING, etc.)
- **Go Turbo Recon** (--go): modulo Go para reconhecimento 10-50x mais rapido
- **Deduplicacao**: 10.432 linhas duplicadas removidas, 65 arquivos vazios limpos
- Pastas deletadas: payloads_diversos, Black-Hat-Python-main, PenTest-Scripts, FUZZING, payloadsallthethings

### v4.6 -- 21/03/2026 (Payload Enhancement Sprint)
- **Novas pastas Payloads_CY**: XXE, SSRF Cloud Metadata, SSRF DNS Rebinding, SSRF Bypass Techniques, CORS Bypass, JavaScript Prototype Pollution, GraphQL Dangerous Mutations
- **CRLF Enhancement**: HTTP desync (TE.CL, TE.TE, H2.CE), request smuggling, pipeline contamination
- **SSRF Enhancement**: 150+ payloads including GCP, Azure, DigitalOcean, Oracle, Kubernetes, IPv6 bypass, DNS rebinding
- **XXE Payloads**: 50 payloads covering OOB FTP/HTTP, SVG, SOAP, RSS, PDF, billion laughs, DTD attacks
- **Prototype Pollution**: 30 payloads for Lodash, jQuery, Vue, Axios, Angular, React, Express gadgets
- **CORS Bypass**: 20 payloads including null origin, subdomain bypass, TLD confusion, special chars, IP tricks
- **Open Redirect Bypass**: 30 payloads with URL encoding, backslash, null byte, tab/newline, protocol tricks
- **GraphQL Mutations**: 60 dangerous mutations for privilege escalation, data destruction, financial tampering

### v2.0 -- 17/03/2026
- Gemini AI, PDF elegante, Payloads_CY, VulnScanner paralelo, Chaos API, 8 APIs

### v1.0 -- Criacao inicial
- Primeira estrutura, checks basicos, relatorio simples

---

## Notas Tecnicas para Futuros Agentes

### _PAYLOAD_INTENSITY (v4.5)
- Global float: 0.3 (medium), 0.6 (hard), 1.0 (insane)
- Afeta TODAS as chamadas de `_load_payload()` automaticamente
- Tambem controla threads: 8/12/16 workers por grupo
- Para adicionar novo check com payloads, basta usar `_load_payload("caminho", limit)` — o intensity ja se aplica

### _JS_VULN_DB (v4.5)
- Dict de class em VulnScanner com 27 bibliotecas JS
- Para adicionar nova lib: `"nome": [{"below": "X.Y.Z", "cves": [...], "severity": "...", "desc": "..."}]`
- Helper `_version_lt(v1, v2)` compara semver (split por . e compara ints)

### Crypto Audit (v4.5 expansion)
- `_KNOWN_HASHES`: dict com ~30 hashes MD5/SHA1/SHA256 de senhas comuns
- 10 checks: TLS, HTTP redirect, plaintext creds, base64 decode, MD5/SHA1 rainbow, entropia, timestamps, connection strings, ROT13, hex encoding, cookies sequenciais
- Para expandir rainbow table: adicionar entrada `"hash_hex": "plaintext"` no dict

---

### Go Turbo Recon (v4.5)
- Binario Go em `recon_go/main.go` — compile com `go build -o cyberdyne-recon .`
- Recebe target URL como argumento, output JSON para stdout, progress para stderr
- Python chama via `subprocess.run()` com timeout 300s
- Se binario nao encontrado ou falhar, fallback automatico para Python
- 4 fontes de subdominio em paralelo (crt.sh, HackerTarget, Wayback, OTX)
- 100 goroutines para validacao de URLs, 50 para port scan
- NÃO substitui steps do Python que requerem API keys (Shodan, VirusTotal, etc.)

---

*Agente responsavel pela ultima atualizacao: opencode/big-pickle -- 21/03/2026*
