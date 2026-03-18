# Diario de Bordo -- CyberDyne (Agente Principal)

## Status Atual: v3.0 -- Em Desenvolvimento Ativo

* **Ultima atualizacao:** 18/03/2026
* **Scripts ativos:** `CyberDyneWeb.py` (scanner web)
* **Total de linhas:** ~10.000
* **Total de checks de vulnerabilidade:** 111+

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
  |     +-- 111+ checks em 8 GRUPOS PARALELOS (max_workers=8 por grupo)
  |           -> cada check individual tem timeout=45s via ThreadPoolExecutor(1)
  |           -> OWASP Top 10, IA, BaaS/Cloud, Recon/DNS, Infra, Logica, Advanced
  |           -> se _auth_cookies esta preenchido, testa TAMBEM a area logada
  |           -> Grupos incluem: check_sqli_boolean_blind (108), check_sqli_union (109),
  |              check_graphql_csrf (110), check_waf_bypass (111)
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

Pasta com 17 subpastas, todas conectadas ao script via `_load_payload(relative_path, limit)`:

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
| `Injection-Other/` | `check_ssti()` (template engines) |
| `Passwords/` | `check_jwt_weak_secret()`, `check_broken_auth()` |
| `Usernames/` | `check_broken_auth()` -- agora usa `self.login_url` quando fornecido |
| `Web-Discovery/` | `fuzz_paths()` (Directories, API, CMS, Web-Servers) |
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
| **NVD** | `NVD_API_KEY` | Carregado, nao usado | Pendente: CVE lookup por tech stack |
| **Vulners** | `VULNERS_API_KEY` | Carregado, nao usado | Pendente: CVE lookup alternativo |
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
- **Nunca** remover WAF bypass payloads de `Payloads_CY/WAF-Bypass/` -- sao a fonte para `check_waf_bypass()` (vuln 111). Sem eles o check nao funciona.
- **Nunca** simplificar os checks de SQLi de volta para keyword matching simples -- os 140 patterns do sqlmap sao criticos para deteccao precisa em 30+ DBMS. Keyword matching gera falsos positivos massivos.
- **Nunca** remover o filter checking do XSS (`<>"'` test antes dos payloads) -- e o principal ganho de eficiencia vindo do XSStrike. Sem ele, o scanner gasta requests desnecessarios em alvos que filtram tudo.
- **Nunca** usar `requests.packages.urllib3` -- usar `import urllib3` diretamente

---

## Mapa de Vulnerabilidades (111+ checks)

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

## Changelog Resumido

### v3.0 -- 18/03/2026
- **~10.000 linhas** (era ~8.100 na v2.0)
- **111+ checks** (era 107)
- **7 ferramentas integradas**: sqlmap, XSStrike, LinkFinder, graphql-cop, supabase-rls-checker, waf-bypass, prompt-inject-fuzzer
- **linkfinder_scan()**: novo step 12 no recon (JS endpoint discovery + API key detection)
- **SQLi reescrito**: 140 error patterns, time-based multi-DBMS, boolean blind (108), UNION (109), tamper bypass
- **XSS reescrito**: filter checking, context detection, similarity, XSStrike WAF bypass, DOM variable tracking
- **GraphQL reescrito**: introspection+suggestions+trace+IDE (61), DoS 5 testes (62), CSRF audit (110)
- **Supabase reescrito**: 60+ tabelas RLS, storage, auth, RPC, JWT decode (36, 37)
- **WAF Bypass Audit** (111): 120 payloads, 5 encodings, 5 zones, vendor detection
- **AI checks reescritos**: 35 payloads, 8 categorias, mutations, behavioral detection (26, 27)
- **9 bug fixes**: RFI, XSS Stored, Broken Auth, LFI params, SSRF params, NoSQL, CSRF, SSTI, urllib3 import
- **Novos Payloads_CY**: WAF-Bypass/, XSS/xsstrike-*, SQLi/sqlmap-*, SQLi/common-*, AI-LLM/prompt-inject-payloads.json

### v2.0 -- 17/03/2026
- Gemini AI: sumario executivo inteligente no PDF + prompt_recall.md gerado por IA
- PDF elegante: cover com header dark, risk gauge, severity badges, vulnerability cards coloridos, page numbers
- Payloads_CY: 16 pastas conectadas ao script
- VulnScanner paralelo: 8 grupos x max_workers=8 (~80min -> ~14min)
- Chaos API: substituiu DNS BF por wordlist
- 8 APIs integradas: Gemini, Shodan, VirusTotal, SecurityTrails, Chaos, Hunter.io, HIBP, GitHub
- `.gitignore` e `.env.example` adicionados
- `BASE_DELAY` reduzido de 0.5s para 0.1s

### v1.0 -- Criacao inicial
- Primeira estrutura do scanner
- Checks basicos de vulnerabilidade
- Relatorio simples

---

*Agente responsavel pela ultima atualizacao: Claude Opus 4.6 -- 18/03/2026*
