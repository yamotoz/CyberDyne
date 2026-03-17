# Payloads_CY — Índice de Payloads para CyberDyneWeb.py

> Seleção curada do SecLists para uso direto no CyberDyneWeb.py
> **165 arquivos | 24 MB** — excluídos arquivos desnecessários (zip bombs, web shells, dicionários de idiomas, wordlists 100M+ linhas)

---

## Mapeamento: Payload → Check do CyberDyneWeb.py

| Categoria | Arquivos Principais | Check / Módulo Beneficiado |
|---|---|---|
| `SQLi/` | `Generic-SQLi.txt`, `quick-SQLi.txt`, `SQLi-Polyglots.txt`, `Generic-BlindSQLi.fuzzdb.txt` | `check_sqli()`, `check_blind_sqli()`, `check_nosql_injection()` |
| `SQLi/` | `MySQL.fuzzdb.txt`, `MSSQL.fuzzdb.txt`, `Oracle.fuzzdb.txt` | `check_sqli()` (database-specific payloads) |
| `SQLi/` | `sqli.auth.bypass.txt`, `MySQL-SQLi-Login-Bypass.fuzzdb.txt` | `check_sqli()` + `BruteForceProbe` (login bypass) |
| `XSS/Polyglots/` | `XSS-Polyglots.txt`, `XSS-Polyglot-Ultimate-0xsobky.txt` | `check_xss()` (poliglotas — 1 payload testa múltiplos contextos) |
| `XSS/Robot-Friendly/` | `XSS-Jhaddix.txt`, `XSS-RSNAKE.txt`, `XSS-Fuzzing.txt` | `check_xss()` (scanner automático — sem prompt visual) |
| `XSS/Human-Friendly/` | `XSS-Cheat-Sheet-PortSwigger.txt`, `XSS-BruteLogic.txt` | `check_xss()` (payloads legíveis para análise manual) |
| `LFI/` | `LFI-Jhaddix.txt`, `LFI-linux-and-windows_by-1N3@CrowdShield.txt` | `check_lfi()` |
| `LFI/Linux/` | `LFI-gracefulsecurity-linux.txt` | `check_lfi()` (Linux paths: `/etc/passwd`, `/proc/self/environ`) |
| `Command-Injection/` | `command-injection-commix.txt` | `check_command_injection()` (928 payloads — Unix + Windows) |
| `Command-Injection/` | `UnixAttacks.fuzzdb.txt`, `Windows-Attacks.fuzzdb.txt` | `check_command_injection()` (separado por OS) |
| `Fuzzing-General/` | `big-list-of-naughty-strings.txt` | Fuzzing genérico — todos os injection checks |
| `Fuzzing-General/` | `login_bypass.txt` | `BruteForceProbe`, `check_sqli()` (auth bypass) |
| `Fuzzing-General/` | `JSON.Fuzzing.txt` | `check_sqli()`, `check_xss()` em APIs JSON |
| `Fuzzing-General/` | `fuzz-Bo0oM.txt` | `fuzz_paths()` (paths sensíveis) |
| `Fuzzing-General/` | `HTML5sec-Injections-Jhaddix.txt` | `check_xss()` (HTML5 vetores) |
| `Web-Discovery/Directories/` | `DirBuster-2007_directory-list-2.3-small.txt` | `fuzz_paths()` (rápido, 2k+ paths) |
| `Web-Discovery/Directories/` | `DirBuster-2007_directory-list-2.3-medium.txt` | `fuzz_paths()` (completo, 20k+ paths) |
| `Web-Discovery/Directories/` | `combined_directories.txt`, `combined_words.txt` | `fuzz_paths()` (merged wordlist) |
| `Web-Discovery/Directories/` | `Common-DB-Backups.txt` | `fuzz_paths()` (backups: `.sql`, `.bak`, `.dump`) |
| `Web-Discovery/Directories/` | `Logins.fuzz.txt` | `fuzz_paths()` (paineis de login) |
| `Web-Discovery/Directories/` | `UnixDotfiles.fuzz.txt` | `fuzz_paths()` (`.env`, `.git`, `.htpasswd`) |
| `Web-Discovery/Directories/` | `versioning_metafiles.txt` | `fuzz_paths()` (`.git/config`, `.svn/entries`) |
| `Web-Discovery/Directories/` | `common-api-endpoints-mazen160.txt` | `fuzz_paths()` (endpoints REST comuns) |
| `Web-Discovery/API/` | `api-endpoints.txt`, `api-seen-in-wild.txt` | `fuzz_paths()` + `ai_fingerprinting()` (APIs REST/GraphQL) |
| `Web-Discovery/API/` | `actions.txt`, `objects.txt` | `fuzz_paths()` (fuzzing de verbos/recursos REST) |
| `Web-Discovery/CMS/` | `wordpress.fuzz.txt`, `wp-plugins.fuzz.txt` | `fuzz_paths()` (WordPress) |
| `Web-Discovery/CMS/` | `Drupal.txt`, `joomla-plugins.fuzz.txt` | `fuzz_paths()` (Drupal, Joomla) |
| `Web-Discovery/CMS/` | `cms-configuration-files.txt` | `fuzz_paths()` (arquivos de config de CMS) |
| `Web-Discovery/CMS/` | `Django.txt`, `ColdFusion.fuzz.txt`, `SAP.fuzz.txt` | `fuzz_paths()` (paths específicos por framework) |
| `Web-Discovery/Web-Servers/` | `Apache.txt`, `nginx.txt`, `IIS.txt` | `fuzz_paths()` (paths default por web server) |
| `Web-Discovery/Web-Servers/` | `Apache-Tomcat.txt`, `JBoss.txt` | `fuzz_paths()` (Java app servers) |
| `Web-Discovery/Parameters/` | `burp-parameter-names.txt` | `check_xss()`, `check_sqli()`, `check_open_redirect()` (nomes de params) |
| `Web-Discovery/Parameters/` | `lowercase-headers`, `uppercase-headers` | `analyze_headers()` (header injection) |
| `DNS-Wordlists/` | `subdomains-top1million-20000.txt` | `enumerate_subdomains()` (DNS brute-force — 20k subdomínios) |
| `DNS-Wordlists/` | `fierce-hostlist.txt` | `enumerate_subdomains()` (lista clássica do Fierce) |
| `DNS-Wordlists/` | `deepmagic.com-prefixes-top500.txt` | `enumerate_subdomains()` (rápido, 500 prefixos) |
| `DNS-Wordlists/` | `deepmagic.com-prefixes-top50000.txt` | `enumerate_subdomains()` (completo, 50k prefixos) |
| `DNS-Wordlists/` | `services-names.txt` | `enumerate_subdomains()` (subdomínios de serviços: `api.`, `mail.`, `vpn.`) |
| `Passwords/Common/` | `best110.txt`, `best1050.txt` | `BruteForceProbe` (listas pequenas e rápidas) |
| `Passwords/Common/` | `Pwdb_top-1000.txt`, `Pwdb_top-10000.txt` | `BruteForceProbe` (senhas mais usadas globalmente) |
| `Passwords/Common/` | `darkweb2017_top-10000.txt` | `BruteForceProbe` (senhas de leaks da dark web) |
| `Passwords/Common/` | `100k-most-used-passwords-NCSC.txt` | `BruteForceProbe` (100k senhas, NCSC UK) |
| `Passwords/Common/` | `probable-v2_top-12000.txt` | `BruteForceProbe` (modelo probabilístico) |
| `Passwords/Default-Credentials/` | `default-passwords.txt`, `default-passwords.csv` | `BruteForceProbe`, `check_default_credentials()` |
| `Passwords/Default-Credentials/` | `ssh-betterdefaultpasslist.txt`, `ftp-betterdefaultpasslist.txt` | Checks de infra (SSH, FTP, porta aberta) |
| `Passwords/Default-Credentials/` | `tomcat-betterdefaultpasslist.txt` | `fuzz_paths()` + Tomcat manager detection |
| `Passwords/Default-Credentials/` | `mysql-betterdefaultpasslist.txt`, `mssql-betterdefaultpasslist.txt` | `check_sqli()` (autenticação DB direta) |
| `Passwords/JWT-Secrets/` | `scraped-JWT-secrets.txt` | `check_jwt_algnone()`, `check_weak_jwt_secret()` |
| `Usernames/` | `top-usernames-shortlist.txt` | `BruteForceProbe` (lista curta de admin usernames) |
| `Usernames/` | `cirt-default-usernames.txt` | `BruteForceProbe` + `check_default_credentials()` |
| `Usernames/` | `CommonAdminBase64.txt` | `BruteForceProbe` (usernames codificados em Base64) |
| `AI-LLM/` | `jailbreak_prompts_2023_*.csv` | `ai_fingerprinting()` — testes de jailbreak em endpoints de IA |
| `AI-LLM/` | `forbidden_question_set.csv` | `ai_fingerprinting()` — perguntas proibidas |
| `AI-LLM/` | `Data_Leakage/` | `ai_fingerprinting()` — vazamento de dados via prompt |
| `AI-LLM/` | `Divergence_attack/` | `ai_fingerprinting()` — ataques de divergência |
| `Pattern-Matching/` | `php-magic-hashes.txt` | `check_php_type_juggling()` |
| `Pattern-Matching/` | `malicious.txt`, `errors.txt` | Detecção de padrões em responses |
| `Pattern-Matching/` | `repo-scan.txt` | `github_dorking()` — padrões em repositórios |
| `Open-Redirect/` | `urls-Drupal-7.20.txt`, `urls-joomla-3.0.3.txt` | `check_open_redirect()` (URLs reais de CMS) |
| `Open-Redirect/` | `urls-wordpress-3.3.1.txt`, `urls-SAP.txt` | `check_open_redirect()` |
| `SSRF/` | `reverse-proxy-inconsistencies.txt` | `check_ssrf()` (bypass de proxy reverso) |
| `SSRF/` | `http-request-headers-common-ip-address.txt` | `check_ssrf()`, `check_host_header_injection()` |
| `SSRF/` | `http-request-headers-common-non-standard-fields.txt` | `analyze_headers()` (headers não-padrão) |

---

## Estrutura de Diretórios

```
Payloads_CY/
├── SQLi/                         # 10 arquivos — MySQL, MSSQL, Oracle, NoSQL, Polyglots
├── XSS/
│   ├── Polyglots/                # 4 arquivos — poliglotas XSS (1 payload, N contextos)
│   ├── Robot-Friendly/           # 15 arquivos — otimizados para scanners automáticos
│   └── Human-Friendly/           # 12 arquivos — legíveis, para análise manual
├── LFI/
│   ├── Linux/                    # 1 arquivo — paths Linux
│   ├── LFI-Jhaddix.txt           # Lista curada do Jhaddix
│   ├── LFI-linux-and-windows_by-1N3@CrowdShield.txt
│   └── LFI-LFISuite-pathtotest.txt
├── Command-Injection/            # 3 arquivos — commix + Unix/Windows attacks
├── Fuzzing-General/              # 5 arquivos — naughty strings, login bypass, JSON, HTML5
├── Web-Discovery/
│   ├── Directories/              # 10 arquivos — DirBuster, combined, dotfiles, backups
│   ├── API/                      # 11 arquivos — endpoints REST, verbos, objetos
│   ├── CMS/                      # 10 arquivos — WordPress, Drupal, Joomla, Django, SAP
│   ├── Web-Servers/              # 11 arquivos — Apache, nginx, IIS, Tomcat, JBoss
│   └── Parameters/               # 3 arquivos — BurpMiner headers, param names
├── DNS-Wordlists/                # 6 arquivos — subdomains top20k, fierce, deepmagic
├── Passwords/
│   ├── Common/                   # 10 arquivos — best, darkweb, NCSC, Pwdb
│   ├── Default-Credentials/      # 12 arquivos — SSH, FTP, MySQL, Tomcat, SCADA
│   └── JWT-Secrets/              # 1 arquivo — scraped JWT secrets
├── Usernames/                    # 4 arquivos — top-shortlist, cirt, admin, SAP
├── AI-LLM/                       # 12 arquivos — jailbreaks, data leakage, divergence
├── Pattern-Matching/             # 9 arquivos — PHP hashes, malicious patterns
├── Open-Redirect/                # 4 arquivos — URLs reais de CMS para redirect
└── SSRF/                         # 7 arquivos — proxy bypass, IP headers, non-standard
```

---

## Como Integrar no CyberDyneWeb.py

Para carregar qualquer lista no script, use o padrão:

```python
import os

PAYLOADS_DIR = os.path.join(os.path.dirname(__file__), "Payloads_CY")

def _load_payload(relative_path: str) -> list[str]:
    """Carrega um arquivo de payload, retornando linhas não-vazias e não-comentadas."""
    full_path = os.path.join(PAYLOADS_DIR, relative_path)
    try:
        with open(full_path, encoding="utf-8", errors="ignore") as f:
            return [l.strip() for l in f if l.strip() and not l.startswith("#")]
    except FileNotFoundError:
        return []

# Exemplos de uso:
sqli_payloads   = _load_payload("SQLi/quick-SQLi.txt")
xss_polyglots   = _load_payload("XSS/Polyglots/XSS-Polyglots.txt")
lfi_payloads    = _load_payload("LFI/LFI-Jhaddix.txt")
cmd_payloads    = _load_payload("Command-Injection/command-injection-commix.txt")
dns_wordlist    = _load_payload("DNS-Wordlists/subdomains-top1million-20000.txt")
passwords       = _load_payload("Passwords/Common/best1050.txt")
jwt_secrets     = _load_payload("Passwords/JWT-Secrets/scraped-JWT-secrets.txt")
fuzz_dirs       = _load_payload("Web-Discovery/Directories/DirBuster-2007_directory-list-2.3-small.txt")
```

---

*Curado para CyberDyneWeb.py — Seleção de 165/5194 arquivos do SecLists (apenas os relevantes para os 107 checks do scanner)*
