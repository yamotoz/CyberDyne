# Diário de Bordo — CyberDyne (Agente Principal)

## Status Atual: v2.0 — Em Desenvolvimento Ativo

* **Última atualização:** 17/03/2026
* **Scripts ativos:** `CyberDyneWeb.py` (scanner web)

---

## Modus Operandi (Filosofia de Trabalho)

Para agentes assistentes que derem continuidade a esse projeto:

1. **UI Terminal Premium:**
   Use `colorama`. Verde = OK, Vermelho = VULN, Amarelo = AVISO. Progress bars ao vivo com `\r`. Nunca deixe o terminal parado sem feedback.

2. **Sem Deadlocks — Regra de Ouro:**
   `log()` usa `with lock:` internamente. **NUNCA chame `log()` dentro de outro `with lock:`.** Use `print()` direto fora do lock, ou construa a string antes de entrar no lock e imprima depois. Isso já causou travamentos em `validate_live_urls`, `subdomain_takeover_recon` e `fuzz_paths`.

3. **Sem Ferramentas Externas Obrigatórias:**
   Tudo deve funcionar em Python puro. Ferramentas externas (nmap, theHarvester, gau) são opcionais — sempre há fallback Python implementado. Não deixe o script morrer por ausência de binário.

4. **Timeouts Sempre:**
   `socket.gethostbyname()` congela no Windows — usar apenas `dns.resolver` com `timeout=1.5, lifetime=2.0`. Requests com `timeout=6` como padrão. Nunca confia no OS para resolver timeout.

5. **Testes Reais, Não Falsos Positivos:**
   Evidência obrigatória: onde a falha ocorreu + o que foi encontrado. Time-based SQLi: verifica latência real. Open Redirect: segue redirect e verifica netloc final. Subdomain Takeover: regex no body + NXDOMAIN+CNAME dangling.

6. **API Keys — padrão de uso:**
   Toda API opcional deve seguir o padrão: `if API_KEY: try: ... except: log(warning)`. Nunca quebrar o fluxo por ausência de chave.

7. **Gemini — não bloquear o scan:**
   A chamada `_call_gemini()` tem `timeout=30`. Se falhar (sem chave, sem internet, API down), retorna `""` silenciosamente. O PDF e o prompt_recall.md são gerados normalmente sem o sumário AI.

---

## Arquitetura do CyberDyneWeb.py

### Fluxo de Execução
```
main()
  ├── FASE 1: ReconEngine.run_full_recon()
  │     ├── 1. enumerate_subdomains()      → crt.sh + HackerTarget + Wayback CDX
  │     │                                  + VirusTotal (se chave) + SecurityTrails (se chave)
  │     │                                  + Chaos/ProjectDiscovery (se chave)
  │     ├── 2. crawl_urls_gau()            → ParamSpider + gau/OTX/Common Crawl + regex crawl
  │     ├── 3. validate_live_urls()        → HEAD+GET, ThreadPoolExecutor(30)
  │     ├── 4. subdomain_takeover_recon()  → EdOverflow fingerprints + NXDOMAIN+CNAME
  │     ├── 5. analyze_headers()           → stack fingerprint, security headers
  │     ├── 6. run_theharvester()          → theHarvester ou _python_harvester()
  │     │                                  + Hunter.io emails (se chave) + HIBP (se chave)
  │     ├── 7. run_nmap()                  → nmap ou _python_port_scan() (top-1000 via Payloads_CY)
  │     ├── 8. github_dorking()            → requer GITHUB_TOKEN no .env
  │     ├── 9. ai_fingerprinting()         → AI/BaaS endpoints + prompt injection probe (AI-LLM/)
  │     ├── 10. fuzz_paths()              → paths sensíveis + 12 wordlists do Payloads_CY
  │     ├── 11. shodan_lookup()            → requer SHODAN_API_KEY no .env
  │     └── _cleanup_output_dir()          → limpa temp, gera arquivos finais
  │
  ├── FASE 2: VulnScanner.run_all()
  │     └── 107 checks em 8 GRUPOS PARALELOS (max_workers=8 por grupo)
  │           → cada check individual tem timeout=45s via ThreadPoolExecutor(1)
  │           → OWASP Top 10, IA, BaaS/Cloud, Recon/DNS, Infra, Lógica, Advanced
  │
  ├── FASE 3: Relatórios
  │     ├── [Gemini] _call_gemini() → sumário executivo + prompt recall inteligente
  │     ├── ReportGenerator → CyberDyneWeb_Report.pdf (PDF elegante v2)
  │     ├── PromptRecallGenerator → prompt_recall.md (direto e curto)
  │     └── raw_results.json
  │
  └── FASE 4 (OPCIONAL): BruteForceProbe
        └── Só executa se login_url foi fornecida
              50 requests → detecta ausência de rate limit/lockout/CAPTCHA
```

---

## Payloads_CY — Integração Completa

Pasta com 16 subpastas, todas conectadas ao script via `_load_payload(relative_path, limit)`:

| Pasta | Usada em |
|---|---|
| `SQLi/` | `check_sqli_classic()`, `check_nosql_injection()` |
| `XSS/` | `check_xss_reflected()` (polyglots + Jhaddix + naughty strings) |
| `LFI/` | `check_lfi()` |
| `Command-Injection/` | `check_cmd_injection()` |
| `SSRF/` | `check_ssrf()` |
| `Injection-Other/` | `check_ssti()` (template engines) |
| `Passwords/` | `check_jwt_weak_secret()`, `check_broken_auth()` |
| `Usernames/` | `check_broken_auth()` |
| `Web-Discovery/` | `fuzz_paths()` (Directories, API, CMS, Web-Servers) |
| `Fuzzing-General/` | `fuzz_paths()`, `check_xss_reflected()`, `check_open_redirect()` |
| `Recon-Secrets/` | `github_dorking()`, `check_env_files()` |
| `Pattern-Matching/` | `check_env_files()` (sensitive keywords) |
| `Infrastructure/` | `_python_port_scan()` (nmap-ports-top1000.txt) |
| `DNS-Wordlists/` | removido — DNS BF eliminado (ver abaixo) |
| `AI-LLM/` | `ai_fingerprinting()` (jailbreaks + data leakage probes) |

---

## APIs Externas — Status de Integração

| API | Variável `.env` | Status | Onde é usado |
|---|---|---|---|
| **Gemini (Google)** | `GEMINI_API_KEY` ou `GEMINI-API` | ✅ Integrado | `_call_gemini()` → PDF sumário + prompt_recall |
| **Shodan** | `SHODAN_API_KEY` | ✅ Integrado | `shodan_lookup()` → portas/vulns por IP |
| **SecurityTrails** | `SECURITYTRAILS_API_KEY` | ✅ Integrado | `_securitytrails_subdomains()` |
| **VirusTotal** | `VIRUSTOTAL_API_KEY` | ✅ Integrado | `_vt_subdomains()` |
| **Chaos (ProjectDiscovery)** | `CHAOS_API_KEY` | ✅ Integrado | `enumerate_subdomains()` |
| **Hunter.io** | `HUNTER_API_KEY` | ✅ Integrado | `_python_harvester()` → emails |
| **HaveIBeenPwned** | `HIBP_API_KEY` | ✅ Integrado | `_python_harvester()` → email leaks |
| **GitHub** | `GITHUB_TOKEN` | ✅ Integrado | `github_dorking()` |
| **NVD** | `NVD_API_KEY` | ⏳ Carregado, não usado | Pendente: CVE lookup por tech stack |
| **Vulners** | `VULNERS_API_KEY` | ⏳ Carregado, não usado | Pendente: CVE lookup alternativo |
| **URLScan.io** | `URLSCAN_API_KEY` | ⏳ Carregado, não usado | Pendente: scan visual/screenshot |
| **BinaryEdge** | `BINARYEDGE_API_KEY` | ⏳ Carregado, não usado | Pendente: alternativa ao Shodan |
| **HackerOne** | `HACKERONE_API_KEY` | ⏳ Carregado, não usado | Pendente: verificar bug bounty scope |

> APIs marcadas ⏳ têm a variável carregada mas nenhuma função as chama ainda.
> Não quebram o scan — são simplesmente ignoradas.

---

## Bugs Conhecidos e Corrigidos

| Bug | Causa | Fix |
|---|---|---|
| `validate_live_urls` congela | `log()` dentro de `with lock:` → deadlock reentrante | `print()` direto fora do lock |
| `subdomain_takeover_recon` congela | Mesmo deadlock | Construir string antes, imprimir depois do lock |
| `fuzz_paths` congela | Mesmo deadlock | `print()` fora do lock |
| `run_all` congela | Check individual sem timeout | `ThreadPoolExecutor(1).submit().result(timeout=45)` |
| DNS brute-force → 404s em massa | Wordlist gera centenas de falsos positivos | **DNS BF removido** — substituído por Chaos API |
| `nmap-ports-top1000.txt` retorna 1 entrada | Arquivo tem todos os 1000 portas em 1 linha CSV | Parser próprio com split por `,` e range expansion |
| `socket.gethostbyname()` trava Windows | Sem timeout no nível do SO | Removido — só usa `dns.resolver` |
| `httpx` ausente congela | `done[0]` nunca incrementava | Reescrito como `validate_live_urls` |
| `BASE_DELAY=0.5` lento | 0.5s por request, 107 checks | Reduzido para `0.1s` via env var |
| crt.sh timeout longo | timeout=25s sem retry | 12s + 1 retry de 20s |

---

## PDF Report — Evolução

### v1 (original)
- Cover simples com título e tabela de metadados
- Vulnerabilidades listadas em tabelas planas
- Sem page numbers
- Sem separação visual por severidade

### v2 (atual)
- **Cover** com header escuro (`#0f172a`), metadados, risk gauge colorido, severity badges
- **Sumário executivo** com texto Gemini (quando disponível) em box azul
- **Section headers** — barras coloridas `#1e40af` entre seções
- **Vulnerability cards** — cada vuln tem card colorido por severidade (borda + fundo tonal)
- **Page numbers** — footer em todas as páginas via `onLaterPages=_page_footer`
- **Vulns agrupadas por severidade** — Crítico → Alto → Médio → Baixo, com contador
- **Subdomínios** — status ATIVO/INATIVO colorido individualmente

---

## Prompt Recall — Evolução

### v1 (original)
- Verboso, com seções de "como usar", "exemplo de prompt", "prioridade de remediação"
- Incluía subdomínios, timestamps, instruções longas
- Não útil para copiar/colar diretamente

### v2 (atual)
- **Cabeçalho de 2 linhas** com target, data e contagem de vulns
- **Conteúdo Gemini** quando disponível (prompt direto gerado por IA)
- **Fallback**: lista mínima por severidade — endpoint + evidência + fix — sem rodeios
- Formato: pode ser colado direto em qualquer agente de IA

---

## Ferramentas Portadas para Python Puro

| Ferramenta | Substituto Python | Localização |
|---|---|---|
| `subfinder` | crt.sh + HackerTarget + Wayback CDX + Chaos + VT + SecurityTrails | `enumerate_subdomains()` |
| `httpx` | `validate_live_urls()` com requests HEAD+GET | Método em `ReconEngine` |
| `nmap` | `_python_port_scan()` com socket (top-1000 via Payloads_CY) | Método em `ReconEngine` |
| `theHarvester` | `_python_harvester()` — scraping + HackerTarget + Hunter.io | Método em `ReconEngine` |
| `gau` | `_python_gau()` — OTX AlienVault + Common Crawl | Método em `ReconEngine` |
| `subzy` | `subdomain_takeover_recon()` — EdOverflow fingerprints | Método em `ReconEngine` |
| `ParamSpider` | `_paramspider_collect()` — Wayback CDX + limpeza | Método em `ReconEngine` |
| `OpenRedireX` | `check_open_redirect()` — 44+ payloads de bypass | Método em `VulnScanner` |
| `dalfox` | `check_xss_reflected()` — 7-phase pipeline, 60+ payloads | Método em `VulnScanner` |
| `nuclei` | 6 checks portados (paths, swagger, cache, HPP, deser, js) | `check_nuclei_paths()` + outros |
| `Wappalyzer` | `detect_technologies()` — 62 techs, 8 vetores | inline em `analyze_headers()` |
| `whois` CLI | WHOIS raw socket 2-fases (IANA → TLD) | `run_whois()` |
| `Passcrack` | `BruteForceProbe` — detecção de ausência de rate limit | Classe própria |

---

## Coisas Para Não Mudar

- **Nunca** adicionar `socket.gethostbyname()` — trava Windows
- **Nunca** chamar `log()` dentro de `with lock:` — deadlock garantido
- **Não** tornar ferramentas externas obrigatórias — deve rodar em Python puro
- **Não** reintroduzir DNS BF por wordlist — gera 404s em massa, sem valor prático
- **Não** bloquear o scan por falha de API — `_call_gemini()` e todas as APIs devem ser `try/except` silencioso
- **Não** committar o `.env` no git — `.gitignore` já protege, mas nunca remover essa entrada

---

*Agente responsável pela última atualização: Claude Sonnet 4.6 — 17/03/2026*
