#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║               CyberDyne Web Scanner — v1.0                                 ║
║         Varredura de vulnerabilidades em aplicações web                     ║
║  USE APENAS EM SISTEMAS QUE VOCÊ TEM AUTORIZAÇÃO EXPLÍCITA PARA TESTAR     ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import sys
import os
import time
import re
import json
import socket
import ssl
import datetime
import urllib.parse
from typing import Optional

try:
    import requests
    from bs4 import BeautifulSoup
    from colorama import init, Fore, Back, Style
    from tqdm import tqdm
    from fpdf import FPDF
except ImportError:
    print("\n[!] Dependências ausentes. Execute:")
    print("    pip install requests beautifulsoup4 colorama tqdm fpdf2\n")
    sys.exit(1)

init(autoreset=True)

# ─────────────────────────────────────────
#  BANNER & BOAS-VINDAS
# ─────────────────────────────────────────

BANNER = r"""
{}
 ██████╗██╗   ██╗██████╗ ███████╗██████╗ ██████╗ ██╗   ██╗███╗   ██╗███████╗
██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔══██╗╚██╗ ██╔╝████╗  ██║██╔════╝
██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝██║  ██║ ╚████╔╝ ██╔██╗ ██║█████╗  
██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██║  ██║  ╚██╔╝  ██║╚██╗██║██╔══╝  
╚██████╗   ██║   ██████╔╝███████╗██║  ██║██████╔╝   ██║   ██║ ╚████║███████╗
 ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═════╝    ╚═╝   ╚═╝  ╚═══╝╚══════╝
{}
{}               🌐  W E B   S C A N N E R   M O D U L E  🌐{}
{}          Varredura de 40 Vulnerabilidades em Aplicações Web{}
{}                      Versão 1.0  |  CyberDyne{}
""".format(
    Fore.CYAN, Style.RESET_ALL,
    Fore.YELLOW, Style.RESET_ALL,
    Fore.WHITE, Style.RESET_ALL,
    Fore.WHITE, Style.RESET_ALL,
)

WELCOME_MSG = [
    f"{Fore.CYAN}{'═'*70}",
    f"{Fore.WHITE}  Bem-vindo ao {Fore.CYAN}CyberDyne Web Scanner{Fore.WHITE} — a ferramenta de segurança",
    f"{Fore.WHITE}  ofensiva ética projetada para encontrar o que outros deixam passar.",
    f"",
    f"{Fore.YELLOW}  🎯 Este módulo testa 40 vulnerabilidades web incluindo:",
    f"{Fore.WHITE}     • OWASP Top 10 completo",
    f"{Fore.WHITE}     • Falhas comuns geradas por Vibe Coding (IA)",
    f"{Fore.WHITE}     • Exposição de chaves de API e tokens",
    f"{Fore.WHITE}     • Injeções, CORS, JWT, CSRF e muito mais",
    f"",
    f"{Fore.GREEN}  📄 Ao final, um relatório PDF completo será gerado automaticamente.",
    f"{Fore.RED}  ⚠️  Use somente em sistemas com autorização explícita.",
    f"{Fore.CYAN}{'═'*70}",
]

# ─────────────────────────────────────────
#  RESULTADO DE CADA TESTE
# ─────────────────────────────────────────

class TestResult:
    def __init__(self, name: str, category: str):
        self.name = name
        self.category = category
        self.status = "PENDENTE"      # APROVADO | REPROVADO | AVISO | ERRO
        self.severity = "N/A"         # CRÍTICA | ALTA | MÉDIA | BAIXA | INFO
        self.where = ""               # Onde foi encontrado
        self.how_tested = ""          # Como foi testado
        self.why_failed = ""          # Por que reprovou
        self.manual_repro = ""        # Como reproduzir manualmente
        self.recommendation = ""      # Como corrigir
        self.evidence = ""            # Evidência bruta (payload, resposta)

    def passed(self, how_tested: str):
        self.status = "APROVADO"
        self.severity = "INFO"
        self.how_tested = how_tested

    def failed(self, severity: str, where: str, how_tested: str, why_failed: str,
                manual_repro: str, recommendation: str, evidence: str = ""):
        self.status = "REPROVADO"
        self.severity = severity
        self.where = where
        self.how_tested = how_tested
        self.why_failed = why_failed
        self.manual_repro = manual_repro
        self.recommendation = recommendation
        self.evidence = evidence

    def warn(self, where: str, how_tested: str, why_failed: str):
        self.status = "AVISO"
        self.severity = "BAIXA"
        self.where = where
        self.how_tested = how_tested
        self.why_failed = why_failed

    def error(self, msg: str):
        self.status = "ERRO"
        self.how_tested = msg

# ─────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────

SESSION = requests.Session()
SESSION.headers.update({
    "User-Agent": "Mozilla/5.0 (CyberDyne-Scanner/1.0)",
    "Accept": "*/*",
})
SESSION.timeout = 10

def safe_get(url: str, **kwargs) -> Optional[requests.Response]:
    try:
        return SESSION.get(url, timeout=10, verify=False, allow_redirects=True, **kwargs)
    except Exception:
        return None

def safe_post(url: str, **kwargs) -> Optional[requests.Response]:
    try:
        return SESSION.post(url, timeout=10, verify=False, **kwargs)
    except Exception:
        return None

def print_status(name: str, status: str, severity: str = ""):
    icons = {"APROVADO": "✅", "REPROVADO": "❌", "AVISO": "⚠️ ", "ERRO": "💥", "PENDENTE": "⏳"}
    colors = {"APROVADO": Fore.GREEN, "REPROVADO": Fore.RED, "AVISO": Fore.YELLOW, "ERRO": Fore.MAGENTA}
    sev_colors = {"CRÍTICA": Fore.RED, "ALTA": Fore.RED, "MÉDIA": Fore.YELLOW, "BAIXA": Fore.CYAN, "INFO": Fore.GREEN}
    icon = icons.get(status, "?")
    col = colors.get(status, Fore.WHITE)
    sev_str = f" [{sev_colors.get(severity, Fore.WHITE)}{severity}{col}]" if severity and severity != "N/A" and severity != "INFO" else ""
    print(f"  {icon} {col}{name:<52}{sev_str}{Style.RESET_ALL}")

# ─────────────────────────────────────────
#  OS 40 TESTES
# ─────────────────────────────────────────

def test_sql_injection(base_url: str) -> TestResult:
    t = TestResult("SQL Injection (GET)", "OWASP A03")
    payloads = ["' OR '1'='1", "' OR 1=1--", "'; DROP TABLE users--", "1' AND SLEEP(3)--"]
    error_signs = ["sql syntax", "mysql_fetch", "ora-", "sqlite", "pg_query",
                   "syntax error", "unclosed quotation", "microsoft ole db"]
    tested_url = f"{base_url}?id={urllib.parse.quote(payloads[0])}"
    r = safe_get(tested_url)
    if r:
        body = r.text.lower()
        for sign in error_signs:
            if sign in body:
                t.failed("CRÍTICA", tested_url,
                         f"GET {tested_url}",
                         f"A aplicação retornou erro SQL ao receber o payload '{payloads[0]}'. Isso indica que o parâmetro é concatenado diretamente na query.",
                         "1. Acesse: " + tested_url + "\n2. Observe erros SQL na resposta.",
                         "Use Prepared Statements. Ex: cursor.execute('SELECT * FROM t WHERE id=%s',(id,))",
                         f"Sinal encontrado: '{sign}'")
                return t
        t.passed(f"GET {tested_url} — sem erro SQL detectado")
    else:
        t.error("Falha na requisição")
    return t

def test_xss_reflected(base_url: str) -> TestResult:
    t = TestResult("XSS Refletido", "OWASP A03")
    payload = "<script>alert('CyberDyne-XSS')</script>"
    url = f"{base_url}?q={urllib.parse.quote(payload)}"
    r = safe_get(url)
    if r and payload in r.text:
        t.failed("ALTA", url,
                 f"GET {url}",
                 "O payload XSS foi refletido sem sanitização no corpo da resposta HTML.",
                 f"1. Acesse: {url}\n2. Observe se um alert aparece ou se o script está no HTML.",
                 "Sanitize output com html.escape() ou use Content-Security-Policy.",
                 f"Payload refletido: {payload}")
    elif r:
        t.passed(f"Payload não refletido em {url}")
    else:
        t.error("Sem resposta")
    return t

def test_csrf(base_url: str) -> TestResult:
    t = TestResult("CSRF — Token Ausente em Formulários", "OWASP A01")
    r = safe_get(base_url)
    if not r:
        t.error("Sem resposta")
        return t
    soup = BeautifulSoup(r.text, "html.parser")
    forms = soup.find_all("form", method=re.compile("post", re.I))
    if not forms:
        t.passed("Nenhum formulário POST encontrado na página principal")
        return t
    for form in forms:
        csrf_fields = form.find_all("input", attrs={"name": re.compile(r"csrf|token|_token|authenticity", re.I)})
        if not csrf_fields:
            action = form.get("action", base_url)
            t.failed("ALTA", f"Formulário em {base_url} action={action}",
                     "Análise do HTML da página — busca por inputs com nome csrf/token",
                     "Formulário POST sem campo de token CSRF. Qualquer site externo pode forjar requisições.",
                     f"1. Abra o código-fonte de {base_url}\n2. Localize o <form method='post'>\n3. Verifique ausência de input hidden com token CSRF.",
                     "Adicione tokens CSRF únicos por sessão em todos os formulários POST.")
            return t
    t.passed("Todos os formulários POST possuem token CSRF")
    return t

def test_security_headers(base_url: str) -> list:
    results = []
    headers_to_check = {
        "X-Frame-Options":         ("Clickjacking",             "MÉDIA", "X-Frame-Options: DENY"),
        "Content-Security-Policy": ("CSP Ausente",              "ALTA",  "Content-Security-Policy: default-src 'self'"),
        "Strict-Transport-Security": ("HSTS Ausente",           "MÉDIA", "Strict-Transport-Security: max-age=31536000"),
        "X-Content-Type-Options":  ("MIME Sniffing",            "BAIXA", "X-Content-Type-Options: nosniff"),
        "Referrer-Policy":         ("Referrer Policy Ausente",  "BAIXA", "Referrer-Policy: no-referrer"),
    }
    r = safe_get(base_url)
    for header, (vuln_name, severity, fix) in headers_to_check.items():
        t = TestResult(f"Header: {vuln_name}", "Security Headers")
        if not r:
            t.error("Sem resposta ao verificar headers")
        elif header not in r.headers:
            t.failed(severity, f"Response headers de {base_url}",
                     f"HEAD/GET {base_url} — verificação de header '{header}'",
                     f"O header de segurança '{header}' está ausente, permitindo ataques de {vuln_name}.",
                     f"1. Abra DevTools > Network\n2. Acesse {base_url}\n3. Inspecione os Response Headers.",
                     f"Adicione ao servidor: {fix}")
        else:
            t.passed(f"Header '{header}' presente: {r.headers[header]}")
        results.append(t)
    return results

def test_exposed_paths(base_url: str) -> TestResult:
    t = TestResult("Diretórios/Arquivos Sensíveis Expostos", "OWASP A05")
    sensitive = [
        "/.env", "/.git/HEAD", "/backup.zip", "/config.php",
        "/admin/", "/wp-admin/", "/phpinfo.php", "/.htpasswd",
        "/swagger-ui.html", "/api-docs", "/actuator/health",
        "/server-status", "/web.config",
    ]
    found = []
    for path in sensitive:
        url = base_url.rstrip("/") + path
        r = safe_get(url)
        if r and r.status_code in (200, 403) and len(r.text) > 50:
            found.append(f"{url} [{r.status_code}]")
    if found:
        t.failed("ALTA", "\n".join(found),
                 f"GET para cada caminho sensível em {base_url}",
                 "Caminhos/arquivos sensíveis retornaram código 200 ou 403, indicando existência.",
                 "1. Acesse cada URL listada abaixo no navegador:\n" + "\n".join(found),
                 "Bloqueie acesso via servidor web. Nunca suba .env, .git ou backups ao servidor.")
    else:
        t.passed(f"Nenhum dos {len(sensitive)} caminhos sensíveis foi encontrado acessível")
    return t

def test_server_info_disclosure(base_url: str) -> TestResult:
    t = TestResult("Exposição de Informações do Servidor", "OWASP A05")
    r = safe_get(base_url)
    if not r:
        t.error("Sem resposta")
        return t
    risky_headers = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"]
    found = {h: r.headers[h] for h in risky_headers if h in r.headers}
    if found:
        details = ", ".join(f"{k}: {v}" for k, v in found.items())
        t.warn(f"Headers: {details}",
               f"GET {base_url} — análise de response headers",
               f"Headers revelam tecnologias: {details}. Isso facilita ataques direcionados.")
    else:
        t.passed("Nenhum header de tecnologia revelado")
    return t

def test_cors_misconfig(base_url: str) -> TestResult:
    t = TestResult("CORS Misconfiguration", "OWASP A05")
    r = safe_get(base_url, headers={"Origin": "https://evil-hacker.com"})
    if not r:
        t.error("Sem resposta")
        return t
    acao = r.headers.get("Access-Control-Allow-Origin", "")
    acac = r.headers.get("Access-Control-Allow-Credentials", "")
    if acao == "*" and "true" in acac.lower():
        t.failed("CRÍTICA", f"Response headers de {base_url}",
                 f"GET {base_url} com header Origin: https://evil-hacker.com",
                 "CORS permite qualquer origem (*) com credenciais. Qualquer site pode fazer requisições autenticadas.",
                 f"1. Faça fetch de {base_url} a partir de outro domínio\n2. Inclua credentials: 'include'",
                 "Nunca combine Allow-Origin: * com Allow-Credentials: true. Especifique origens confiáveis.")
    elif acao == "https://evil-hacker.com":
        t.failed("ALTA", f"Response headers de {base_url}",
                 f"GET {base_url} com Origin: https://evil-hacker.com",
                 "Servidor refletiu a origem do atacante sem validação da whitelist.",
                 "Qualquer origem enviada é aceita — sem validação real.",
                 "Implemente whitelist de origens confiáveis no servidor.")
    else:
        t.passed(f"CORS configurado adequadamente (Allow-Origin: '{acao}')")
    return t

def test_open_redirect(base_url: str) -> TestResult:
    t = TestResult("Open Redirect", "OWASP A01")
    payloads = [
        ("redirect", "https://evil-hacker.com"),
        ("next", "https://evil-hacker.com"),
        ("url", "https://evil-hacker.com"),
        ("return", "https://evil-hacker.com"),
    ]
    for param, val in payloads:
        url = f"{base_url}?{param}={urllib.parse.quote(val)}"
        r = safe_get(url)
        if r and "evil-hacker.com" in r.url:
            t.failed("MÉDIA", url,
                     f"GET {url}",
                     f"A aplicação redirecionou para URL externa via parâmetro '{param}'.",
                     f"1. Acesse: {url}\n2. Observe redirecionamento para evil-hacker.com",
                     "Valide destinos de redirect contra whitelist interna. Nunca redirecione para URLs externas arbitrárias.")
            return t
    t.passed("Nenhum parâmetro de redirect aceitou URL externa")
    return t

def test_directory_traversal(base_url: str) -> TestResult:
    t = TestResult("Path/Directory Traversal", "OWASP A01")
    payloads = ["../../../etc/passwd", "..\\..\\..\\windows\\win.ini", "%2e%2e%2f%2e%2e%2fetc%2fpasswd"]
    for p in payloads:
        url = f"{base_url}?file={urllib.parse.quote(p)}&path={urllib.parse.quote(p)}"
        r = safe_get(url)
        if r and ("root:x:" in r.text or "[extensions]" in r.text):
            t.failed("CRÍTICA", url,
                     f"GET {url}",
                     "A aplicação leu e retornou conteúdo de arquivos do sistema via path traversal.",
                     f"1. Acesse: {url}\n2. Leia o conteúdo de /etc/passwd na resposta",
                     "Sanitize caminhos de arquivo. Use os.path.realpath e valide que está dentro do diretório permitido.")
            return t
    t.passed("Nenhum arquivo de sistema lido via path traversal")
    return t

def test_jwt_vulnerabilities(base_url: str) -> TestResult:
    t = TestResult("JWT — Algoritmo 'none' / Chave Fraca", "OWASP A07")
    import base64
    weak_token_none = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0IiwicGF0Ijoic2VjcmV0In0."
    r = safe_get(base_url, headers={"Authorization": f"Bearer {weak_token_none}"})
    if r and r.status_code == 200 and "unauthorized" not in r.text.lower():
        t.failed("CRÍTICA", base_url,
                 f"GET {base_url} com JWT alg=none",
                 "Servidor aceitou token JWT com algoritmo 'none' (sem assinatura), concedendo acesso.",
                 f"1. Gere um JWT com alg=none e payload desejado\n2. Envie como Bearer token para {base_url}",
                 "Rejeite tokens com alg=none. Force HS256/RS256 com chave forte.")
    else:
        t.passed("JWT com alg=none foi rejeitado pelo servidor")
    return t

def test_ssrf(base_url: str) -> TestResult:
    t = TestResult("SSRF (Server-Side Request Forgery)", "OWASP A10")
    internal_urls = ["http://localhost/", "http://127.0.0.1/", "http://169.254.169.254/latest/meta-data/"]
    for internal in internal_urls:
        url = f"{base_url}?url={urllib.parse.quote(internal)}&uri={urllib.parse.quote(internal)}"
        r = safe_get(url)
        if r and ("ami-id" in r.text or "localhost" in r.text or r.status_code == 200 and len(r.text) > 100):
            t.failed("CRÍTICA", url,
                     f"GET {url}",
                     "Servidor fez requisição para URL interna fornecida pelo atacante.",
                     f"1. Acesse: {url}\n2. Observe conteúdo de rede interna na resposta",
                     "Bloqueie requisições para IPs internos/metadados. Use allowlist de domínios externos.")
            return t
    t.passed("Nenhum parâmetro URL aceitou endereços internos")
    return t

def test_command_injection(base_url: str) -> TestResult:
    t = TestResult("Command Injection (OS)", "OWASP A03")
    payloads = ["; whoami", "| whoami", "& whoami", "`whoami`", "$(whoami)"]
    for p in payloads:
        url = f"{base_url}?cmd={urllib.parse.quote(p)}&host={urllib.parse.quote(p)}"
        r = safe_get(url)
        if r and re.search(r"\b(root|administrator|www-data|nt authority)\b", r.text, re.I):
            t.failed("CRÍTICA", url,
                     f"GET {url} com payload '{p}'",
                     "A aplicação executou comando do sistema e retornou a saída na resposta.",
                     f"1. Acesse: {url}\n2. Observe nome de usuário do servidor na resposta",
                     "NUNCA passe input do usuário para funções de shell. Use subprocess com lista de args.")
            return t
    t.passed("Nenhum sinal de command injection detectado")
    return t

def test_ssti(base_url: str) -> TestResult:
    t = TestResult("SSTI — Server-Side Template Injection", "OWASP A03")
    payload = "{{7*7}}"
    url = f"{base_url}?name={urllib.parse.quote(payload)}&q={urllib.parse.quote(payload)}"
    r = safe_get(url)
    if r and "49" in r.text:
        t.failed("CRÍTICA", url,
                 f"GET {url} com payload '{{{{7*7}}}}'",
                 "Template executou expressão matemática — indica SSTI. Atacante pode executar código arbitrário.",
                 f"1. Acesse: {url}\n2. Se '49' aparecer na resposta, há SSTI",
                 "Nunca renderize input do usuário com engines de template. Use autoescape.")
    else:
        t.passed("Payload SSTI não foi executado")
    return t

def test_xxe(base_url: str) -> TestResult:
    t = TestResult("XXE — XML External Entity Injection", "OWASP A05")
    xxe_payload = """<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><data>&xxe;</data>"""
    r = safe_post(base_url, data=xxe_payload, headers={"Content-Type": "application/xml"})
    if r and "root:x:" in r.text:
        t.failed("CRÍTICA", base_url,
                 f"POST {base_url} com payload XXE",
                 "Servidor processou entidade XML externa e retornou conteúdo de /etc/passwd.",
                 "1. Envie o payload XML acima como POST para o endpoint\n2. Observe conteúdo de arquivos na resposta",
                 "Desabilite processamento de DTD externo no parser XML.")
    else:
        t.passed("Servidor não processou entidade XML externa")
    return t

def test_sensitive_in_url(base_url: str) -> TestResult:
    t = TestResult("Dados Sensíveis em URL / Query String", "OWASP A02")
    r = safe_get(base_url)
    if not r:
        t.error("Sem resposta")
        return t
    patterns = [r"token=[A-Za-z0-9+/=]{10,}", r"api_key=\w{10,}", r"password=\w+", r"secret=\w+"]
    found = []
    for link in re.findall(r'href=["\']([^"\']+)["\']', r.text):
        for pat in patterns:
            if re.search(pat, link, re.I):
                found.append(link)
    if found:
        t.failed("ALTA", "\n".join(found),
                 f"Análise do HTML de {base_url} — busca por padrões de credenciais em links",
                 "Tokens/senhas/chaves expostos em URLs aparecem em logs de servidor, histórico do browser e referer.",
                 "1. Visualize código-fonte da página\n2. Procure por href com token=, api_key=, password=",
                 "Use corpo POST para credenciais. Nunca exponha segredos em GET/URL.")
    else:
        t.passed("Nenhum dado sensível detectado em URLs da página")
    return t

def test_robots_disclosure(base_url: str) -> TestResult:
    t = TestResult("Robots.txt — Exposição de Caminhos", "OWASP A05")
    url = base_url.rstrip("/") + "/robots.txt"
    r = safe_get(url)
    if r and r.status_code == 200 and "disallow" in r.text.lower():
        lines = [l for l in r.text.splitlines() if "disallow" in l.lower()]
        t.warn(url,
               f"GET {url}",
               f"Robots.txt expõe {len(lines)} caminhos proibidos: {', '.join(lines[:3])}. Serve como mapa para atacantes.")
    else:
        t.passed("robots.txt ausente ou sem caminhos sensíveis listados")
    return t

def test_cookie_security(base_url: str) -> TestResult:
    t = TestResult("Cookies — Flags HttpOnly/Secure/SameSite", "OWASP A07")
    r = safe_get(base_url)
    if not r:
        t.error("Sem resposta")
        return t
    issues = []
    for cookie in r.cookies:
        if not cookie.has_nonstandard_attr("HttpOnly"):
            issues.append(f"Cookie '{cookie.name}' sem HttpOnly")
        if not cookie.secure:
            issues.append(f"Cookie '{cookie.name}' sem Secure flag")
        if not cookie.has_nonstandard_attr("SameSite"):
            issues.append(f"Cookie '{cookie.name}' sem SameSite")
    if issues:
        t.failed("MÉDIA", f"Cookies de {base_url}",
                 f"GET {base_url} — análise dos Set-Cookie headers",
                 "\n".join(issues),
                 "1. DevTools > Application > Cookies\n2. Verifique colunas HttpOnly, Secure, SameSite",
                 "Set-Cookie: session=X; HttpOnly; Secure; SameSite=Strict")
    else:
        t.passed("Todos os cookies possuem flags de segurança adequadas")
    return t

def test_log4shell(base_url: str) -> TestResult:
    t = TestResult("Log4Shell (CVE-2021-44228)", "CVE")
    payload = "${jndi:ldap://cyberdyne-test.invalid/a}"
    headers_to_fuzz = {
        "User-Agent": payload, "X-Forwarded-For": payload,
        "X-Api-Version": payload, "Referer": payload,
    }
    r = safe_get(base_url, headers=headers_to_fuzz)
    # Sem servidor JNDI real para capturar callback — marcamos como aviso
    t.warn(base_url,
           f"GET {base_url} com payload Log4Shell em User-Agent, X-Forwarded-For, Referer, X-Api-Version",
           "Payload enviado. Sem servidor JNDI para capturar callback — valide manualmente com Burp Collaborator ou interactsh.")
    return t

def test_http_methods(base_url: str) -> TestResult:
    t = TestResult("Métodos HTTP Inseguros (TRACE/PUT)", "OWASP A05")
    dangerous = ["TRACE", "PUT", "DELETE"]
    found = []
    for method in dangerous:
        try:
            r = SESSION.request(method, base_url, timeout=8, verify=False)
            if r.status_code not in (405, 501, 403):
                found.append(f"{method} → {r.status_code}")
        except Exception:
            pass
    if found:
        t.failed("MÉDIA", base_url,
                 f"Requisições {', '.join(dangerous)} para {base_url}",
                 f"Métodos perigosos habilitados: {', '.join(found)}",
                 f"1. curl -X TRACE {base_url}\n2. Observe se 200 é retornado",
                 "Desabilite métodos desnecessários no servidor web (Apache/Nginx).")
    else:
        t.passed("Métodos HTTP perigosos retornaram 405/501/403")
    return t

def test_api_key_exposure(base_url: str) -> TestResult:
    t = TestResult("Chaves de API Expostas na Resposta", "Vibe Coding")
    r = safe_get(base_url)
    if not r:
        t.error("Sem resposta")
        return t
    patterns = {
        "OpenAI API Key": r"sk-[A-Za-z0-9]{20,}",
        "AWS Access Key": r"AKIA[0-9A-Z]{16}",
        "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
        "Stripe Secret": r"sk_live_[0-9a-zA-Z]{24,}",
        "GitHub Token": r"ghp_[A-Za-z0-9]{36}",
        "Generic Token": r"[Tt]oken['\": ]+[A-Za-z0-9+/]{20,}",
    }
    found = []
    for name, pattern in patterns.items():
        matches = re.findall(pattern, r.text)
        if matches:
            found.append(f"{name}: {matches[0][:10]}...")
    if found:
        t.failed("CRÍTICA", base_url,
                 f"GET {base_url} — análise do corpo da resposta",
                 "Chaves de API detectadas no HTML/JSON da resposta pública.",
                 "1. Visualize o código-fonte da página\n2. Busque pelos padrões de API Key",
                 "NUNCA exponha chaves no frontend. Use variáveis de ambiente no servidor.")
    else:
        t.passed("Nenhuma API Key detectada no corpo da resposta")
    return t

def test_graphql_introspection(base_url: str) -> TestResult:
    t = TestResult("GraphQL Introspection em Produção", "OWASP A05")
    endpoints = ["/graphql", "/api/graphql", "/v1/graphql"]
    query = {"query": "{ __schema { types { name } } }"}
    for ep in endpoints:
        url = base_url.rstrip("/") + ep
        r = safe_post(url, json=query)
        if r and "__schema" in r.text:
            t.failed("MÉDIA", url,
                     f"POST {url} com query de introspection",
                     "GraphQL com introspection habilitado revela todo o schema da API em produção.",
                     f"1. POST {url}\n2. Body: {{\"query\":\"{{ __schema {{ types {{ name }} }} }}\"}}\n3. Observe schema completo na resposta",
                     "Desabilite introspection em produção. Habilite apenas em desenvolvimento.")
            return t
    t.passed("Nenhum endpoint GraphQL com introspection encontrado")
    return t

def test_idor(base_url: str) -> TestResult:
    t = TestResult("IDOR — Insecure Direct Object Reference", "OWASP A01")
    test_urls = [f"{base_url}/api/users/1", f"{base_url}/api/orders/1",
                 f"{base_url}/user/profile?id=1", f"{base_url}/account/1"]
    for url in test_urls:
        r = safe_get(url)
        if r and r.status_code == 200 and len(r.text) > 50:
            try:
                data = r.json()
                sensitive_keys = ["email", "password", "cpf", "ssn", "phone", "address"]
                found_keys = [k for k in sensitive_keys if k in str(data).lower()]
                if found_keys:
                    t.failed("ALTA", url,
                             f"GET {url} sem token de autenticação",
                             f"Endpoint retornou dados sensíveis ({', '.join(found_keys)}) sem autenticação por ID direto.",
                             f"1. Acesse {url}\n2. Troque o ID por 2, 3... e observe dados de outros usuários",
                             "Implemente verificação de ownership: usuário autenticado só acessa seus próprios recursos.")
                    return t
            except Exception:
                pass
    t.passed("Nenhum endpoint IDOR óbvio detectado sem autenticação")
    return t

def test_brute_force_protection(base_url: str) -> TestResult:
    t = TestResult("Proteção contra Brute Force (Rate Limit)", "OWASP A07")
    login_candidates = ["/login", "/auth", "/api/login", "/signin", "/api/auth"]
    for ep in login_candidates:
        url = base_url.rstrip("/") + ep
        blocked = False
        for i in range(10):
            r = safe_post(url, data={"username": "testuser", "password": f"wrongpass{i}"})
            if r and r.status_code in (429, 423, 403):
                blocked = True
                break
        if not blocked:
            t.warn(url,
                   f"10 tentativas POST em {url}",
                   "Nenhum rate limiting detectado — 10 tentativas sem bloqueio ou captcha.")
            return t
    t.passed("Rate limiting ativo — requisições bloqueadas após falhas")
    return t

def test_swagger_exposed(base_url: str) -> TestResult:
    t = TestResult("Swagger / API Docs Públicos", "OWASP A05")
    paths = ["/swagger", "/swagger-ui", "/swagger-ui.html", "/api-docs",
             "/openapi.json", "/v2/api-docs", "/docs"]
    for path in paths:
        url = base_url.rstrip("/") + path
        r = safe_get(url)
        if r and r.status_code == 200 and ("swagger" in r.text.lower() or "openapi" in r.text.lower()):
            t.failed("MÉDIA", url,
                     f"GET {url}",
                     "Documentação de API pública exposta sem autenticação. Fornece mapa completo de endpoints ao atacante.",
                     f"1. Acesse: {url}\n2. Explore os endpoints documentados",
                     "Proteja docs de API com autenticação ou remova-os em produção.")
            return t
    t.passed("Nenhuma documentação de API pública encontrada")
    return t

def test_ssl_certificate(base_url: str) -> TestResult:
    t = TestResult("Certificado TLS/SSL — Validade e Configuração", "OWASP A02")
    if not base_url.startswith("https"):
        t.failed("ALTA", base_url,
                 "Verificação do schema da URL",
                 "A aplicação usa HTTP sem TLS. Todo tráfego é transmitido em texto claro.",
                 "1. Observe que a URL inicia com http:// (sem S)\n2. Dados são interceptáveis em redes locais",
                 "Implemente HTTPS com certificado válido. Force redirect de HTTP para HTTPS.")
        return t
    try:
        host = urllib.parse.urlparse(base_url).hostname
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
            s.settimeout(8)
            s.connect((host, 443))
            cert = s.getpeercert()
            expire = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
            days_left = (expire - datetime.datetime.utcnow()).days
            if days_left < 30:
                t.warn(base_url,
                       f"Conexão SSL com {host}",
                       f"Certificado expira em {days_left} dias ({expire.date()}). Renove imediatamente.")
            else:
                t.passed(f"Certificado TLS válido — expira em {days_left} dias")
    except ssl.SSLError as e:
        t.failed("ALTA", base_url, "Conexão TLS",
                 f"Erro SSL: {e}", "Tente acessar o site e observe o aviso de certificado no browser",
                 "Instale um certificado válido (ex: Let's Encrypt).")
    except Exception as e:
        t.error(f"Erro ao verificar certificado: {e}")
    return t

def test_user_enumeration(base_url: str) -> TestResult:
    t = TestResult("Enumeração de Usuários", "OWASP A07")
    login_eps = ["/login", "/api/login", "/auth"]
    for ep in login_eps:
        url = base_url.rstrip("/") + ep
        r_invalid = safe_post(url, data={"username": "usuario_que_nao_existe_xyzabc", "password": "senha123"})
        r_valid_wrong = safe_post(url, data={"username": "admin", "password": "senha_errada_12345"})
        if r_invalid and r_valid_wrong:
            if r_invalid.text != r_valid_wrong.text:
                t.warn(url,
                       f"POST {url} com usuário inexistente vs. usuário comum com senha errada",
                       "Respostas diferentes para usuário inexistente vs. senha errada permitem confirmar usuários válidos.")
                return t
    t.passed("Mensagens de erro genéricas — sem enumeração detectada")
    return t

# ─────────────────────────────────────────
#  RELATÓRIO PDF
# ─────────────────────────────────────────

def generate_pdf(results: list, target_url: str, output_path: str):
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    # Capa
    pdf.set_fill_color(15, 15, 30)
    pdf.rect(0, 0, 210, 297, "F")
    pdf.set_font("Helvetica", "B", 28)
    pdf.set_text_color(0, 200, 255)
    pdf.set_y(60)
    pdf.cell(0, 15, "CyberDyne", ln=True, align="C")
    pdf.set_font("Helvetica", "B", 16)
    pdf.set_text_color(255, 255, 255)
    pdf.cell(0, 10, "Web Security Scanner Report", ln=True, align="C")
    pdf.set_font("Helvetica", "", 11)
    pdf.set_text_color(150, 150, 180)
    pdf.cell(0, 8, f"Alvo: {target_url}", ln=True, align="C")
    pdf.cell(0, 8, f"Data: {datetime.datetime.now().strftime('%d/%m/%Y %H:%M:%S')}", ln=True, align="C")

    # Contadores
    total = len(results)
    passed = sum(1 for r in results if r.status == "APROVADO")
    failed = sum(1 for r in results if r.status == "REPROVADO")
    warns  = sum(1 for r in results if r.status == "AVISO")
    errors = sum(1 for r in results if r.status == "ERRO")

    pdf.set_y(140)
    for label, val, color in [
        ("Total de Testes", str(total), (200, 200, 200)),
        ("Aprovados ✔", str(passed), (50, 205, 50)),
        ("Reprovados ✖", str(failed), (220, 50, 50)),
        ("Avisos ▲", str(warns), (255, 180, 0)),
        ("Erros", str(errors), (180, 100, 255)),
    ]:
        pdf.set_font("Helvetica", "B", 13)
        pdf.set_text_color(*color)
        pdf.cell(0, 10, f"{label}: {val}", ln=True, align="C")

    # Página de resultados
    def add_result_block(r: TestResult):
        pdf.add_page()
        status_color = {
            "APROVADO": (50, 205, 50), "REPROVADO": (220, 50, 50),
            "AVISO": (255, 180, 0), "ERRO": (180, 100, 255),
        }.get(r.status, (200, 200, 200))
        sev_color = {
            "CRÍTICA": (220, 50, 50), "ALTA": (255, 100, 0),
            "MÉDIA": (255, 200, 0), "BAIXA": (100, 200, 255), "INFO": (50, 205, 50),
        }.get(r.severity, (200, 200, 200))

        pdf.set_fill_color(20, 20, 40)
        pdf.rect(0, 0, 210, 297, "F")

        pdf.set_font("Helvetica", "B", 14)
        pdf.set_text_color(*status_color)
        pdf.cell(0, 12, f"[{r.status}] {r.name}", ln=True)
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(150, 150, 180)
        pdf.cell(0, 6, f"Categoria: {r.category}   |   Severidade: {r.severity}", ln=True)
        pdf.ln(3)

        sections = [
            ("Onde foi encontrado", r.where),
            ("Como foi testado",    r.how_tested),
            ("Por que reprovou",    r.why_failed),
            ("Como reproduzir manualmente", r.manual_repro),
            ("Recomendação de correção", r.recommendation),
            ("Evidência",           r.evidence),
        ]
        for title, content in sections:
            if content:
                pdf.set_font("Helvetica", "B", 11)
                pdf.set_text_color(0, 200, 255)
                pdf.cell(0, 8, title + ":", ln=True)
                pdf.set_font("Helvetica", "", 10)
                pdf.set_text_color(220, 220, 220)
                for line in content.splitlines():
                    pdf.multi_cell(0, 6, line)
                pdf.ln(2)

    for r in sorted(results, key=lambda x: {"REPROVADO": 0, "AVISO": 1, "ERRO": 2, "APROVADO": 3}.get(x.status, 4)):
        add_result_block(r)

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    pdf.output(output_path)

# ─────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────

def run_all_tests(target: str) -> list:
    all_results = []

    tests_single = [
        test_sql_injection,
        test_xss_reflected,
        test_csrf,
        test_open_redirect,
        test_directory_traversal,
        test_jwt_vulnerabilities,
        test_ssrf,
        test_command_injection,
        test_ssti,
        test_xxe,
        test_sensitive_in_url,
        test_robots_disclosure,
        test_cookie_security,
        test_log4shell,
        test_http_methods,
        test_api_key_exposure,
        test_graphql_introspection,
        test_idor,
        test_brute_force_protection,
        test_swagger_exposed,
        test_ssl_certificate,
        test_user_enumeration,
        test_cors_misconfig,
        test_server_info_disclosure,
        test_exposed_paths,
    ]

    print(f"\n{Fore.CYAN}{'─'*68}")
    print(f"  🔍 Iniciando varredura de {len(tests_single) + 5} testes em: {Fore.YELLOW}{target}")
    print(f"{Fore.CYAN}{'─'*68}\n")

    for fn in tests_single:
        r = fn(target)
        print_status(r.name, r.status, r.severity)
        all_results.append(r)
        time.sleep(0.2)

    # Security Headers retorna lista
    for r in test_security_headers(target):
        print_status(r.name, r.status, r.severity)
        all_results.append(r)
        time.sleep(0.1)

    return all_results

def main():
    print(BANNER)
    for line in WELCOME_MSG:
        print(line)
        time.sleep(0.05)

    print(f"\n{Fore.YELLOW}  ⚠️  AVISO LEGAL:{Fore.WHITE} Use APENAS em sistemas com autorização explícita.")
    print(f"{Fore.WHITE}  O uso não autorizado é crime (Lei 12.737/2012 — Brasil).\n")

    target = input(f"{Fore.CYAN}  🌐 URL alvo (ex: https://minha-app.com): {Fore.WHITE}").strip()
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    target = target.rstrip("/")

    confirm = input(f"\n{Fore.RED}  [!] Você confirma que tem AUTORIZAÇÃO para testar '{target}'? (sim/não): {Fore.WHITE}").strip().lower()
    if confirm not in ("sim", "s", "yes", "y"):
        print(f"\n{Fore.RED}  Execução cancelada. Autorização não confirmada.")
        sys.exit(0)

    print(f"\n{Fore.GREEN}  ✅ Autorização registrada. Iniciando scanner...\n")
    import urllib3
    urllib3.disable_warnings()

    results = run_all_tests(target)

    passed = sum(1 for r in results if r.status == "APROVADO")
    failed = sum(1 for r in results if r.status == "REPROVADO")
    warns  = sum(1 for r in results if r.status == "AVISO")

    print(f"\n{Fore.CYAN}{'═'*68}")
    print(f"  📊  RESUMO FINAL")
    print(f"{Fore.CYAN}{'─'*68}")
    print(f"  {Fore.GREEN}✅ Aprovados : {passed}")
    print(f"  {Fore.RED}❌ Reprovados: {failed}")
    print(f"  {Fore.YELLOW}⚠️  Avisos   : {warns}")
    print(f"{Fore.CYAN}{'═'*68}\n")

    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    pdf_path = os.path.join(os.path.dirname(__file__), "reports", f"cyberdyne_web_{ts}.pdf")
    print(f"  📄 Gerando relatório PDF...")
    generate_pdf(results, target, pdf_path)
    print(f"  {Fore.GREEN}✅ Relatório salvo em: {Fore.WHITE}{pdf_path}\n")

if __name__ == "__main__":
    main()
