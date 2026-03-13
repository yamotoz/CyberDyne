#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║               CyberDyne Local Scanner — v1.0                               ║
║         Varredura de vulnerabilidades em código-fonte e sistema local       ║
║  USE APENAS EM SISTEMAS QUE VOCÊ TEM AUTORIZAÇÃO EXPLÍCITA PARA TESTAR     ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import sys
import os
import re
import json
import time
import stat
import datetime
import subprocess
from pathlib import Path
from typing import Optional, List, Dict, Tuple

try:
    from colorama import init, Fore, Back, Style
    from fpdf import FPDF
except ImportError:
    print("\n[!] Dependências ausentes. Execute:")
    print("    pip install colorama fpdf2\n")
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
{}               🖥️   L O C A L   S C A N N E R   M O D U L E  🖥️{}
{}          Varredura de 20 Vulnerabilidades em Código-Fonte & Sistema{}
{}                       Versão 1.0  |  CyberDyne{}
""".format(
    Fore.MAGENTA, Style.RESET_ALL,
    Fore.YELLOW, Style.RESET_ALL,
    Fore.WHITE, Style.RESET_ALL,
    Fore.WHITE, Style.RESET_ALL,
)

WELCOME_MSG = [
    f"{Fore.MAGENTA}{'═'*70}",
    f"{Fore.WHITE}  Bem-vindo ao {Fore.MAGENTA}CyberDyne Local Scanner{Fore.WHITE} — análise profunda de",
    f"{Fore.WHITE}  código-fonte, segredos, configurações e dependências vulneráveis.",
    f"",
    f"{Fore.YELLOW}  🎯 Este módulo testa 20 vulnerabilidades locais incluindo:",
    f"{Fore.WHITE}     • Chaves de API e tokens hardcoded (OpenAI, AWS, GCP, Stripe...)",
    f"{Fore.WHITE}     • Senhas em código-fonte e comentários",
    f"{Fore.WHITE}     • Arquivos .env expostos e .git públicos",
    f"{Fore.WHITE}     • Dependências com CVEs conhecidos",
    f"{Fore.WHITE}     • Funções inseguras (eval, exec, pickle, os.system...)",
    f"{Fore.WHITE}     • Configurações de debug ativas, criptografia fraca e muito mais",
    f"",
    f"{Fore.GREEN}  📄 Ao final, um relatório PDF completo será gerado automaticamente.",
    f"{Fore.RED}  ⚠️  Use somente em projetos que você tem autorização para analisar.",
    f"{Fore.MAGENTA}{'═'*70}",
]

# ─────────────────────────────────────────
#  RESULTADO
# ─────────────────────────────────────────

class TestResult:
    def __init__(self, name: str, category: str):
        self.name = name
        self.category = category
        self.status = "PENDENTE"
        self.severity = "N/A"
        self.where = ""
        self.how_tested = ""
        self.why_failed = ""
        self.manual_repro = ""
        self.recommendation = ""
        self.evidence = ""

    def passed(self, how_tested: str):
        self.status = "APROVADO"
        self.severity = "INFO"
        self.how_tested = how_tested

    def failed(self, severity, where, how_tested, why_failed, manual_repro, recommendation, evidence=""):
        self.status = "REPROVADO"
        self.severity = severity
        self.where = where
        self.how_tested = how_tested
        self.why_failed = why_failed
        self.manual_repro = manual_repro
        self.recommendation = recommendation
        self.evidence = evidence

    def warn(self, where, how_tested, why_failed):
        self.status = "AVISO"
        self.severity = "BAIXA"
        self.where = where
        self.how_tested = how_tested
        self.why_failed = why_failed

    def error(self, msg):
        self.status = "ERRO"
        self.how_tested = msg

# ─────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────

def print_status(name: str, status: str, severity: str = ""):
    icons = {"APROVADO": "✅", "REPROVADO": "❌", "AVISO": "⚠️ ", "ERRO": "💥"}
    colors = {"APROVADO": Fore.GREEN, "REPROVADO": Fore.RED, "AVISO": Fore.YELLOW, "ERRO": Fore.MAGENTA}
    sev_colors = {"CRÍTICA": Fore.RED, "ALTA": Fore.RED, "MÉDIA": Fore.YELLOW, "BAIXA": Fore.CYAN}
    icon = icons.get(status, "?")
    col = colors.get(status, Fore.WHITE)
    sev_str = f" [{sev_colors.get(severity, Fore.WHITE)}{severity}{col}]" if severity and severity not in ("N/A", "INFO") else ""
    print(f"  {icon} {col}{name:<52}{sev_str}{Style.RESET_ALL}")

def get_all_files(root: str, extensions: Optional[List[str]] = None) -> List[Path]:
    """Retorna todos os arquivos do projeto filtrados por extensão."""
    result = []
    skip_dirs = {".git", "node_modules", "__pycache__", ".venv", "venv", "env",
                 "dist", "build", ".next", "vendor", "target"}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs]
        for fname in filenames:
            if extensions is None or Path(fname).suffix.lstrip(".") in extensions:
                result.append(Path(dirpath) / fname)
    return result

def search_pattern_in_files(files: List[Path], pattern: str, flags=0) -> List[Tuple[str, int, str]]:
    """Busca padrão regex em lista de arquivos. Retorna (filepath, line_num, line)."""
    compiled = re.compile(pattern, flags)
    hits = []
    for fpath in files:
        try:
            lines = fpath.read_text(errors="ignore").splitlines()
            for i, line in enumerate(lines, 1):
                if compiled.search(line):
                    hits.append((str(fpath), i, line.strip()))
        except Exception:
            pass
    return hits

# ─────────────────────────────────────────
#  OS 20 TESTES LOCAIS
# ─────────────────────────────────────────

def test_api_keys_hardcoded(root: str) -> TestResult:
    t = TestResult("Chaves de API Hardcoded no Código", "Vibe Coding")
    code_exts = ["py", "js", "ts", "php", "java", "rb", "go", "env", "yaml", "yml", "json", "env.example"]
    files = get_all_files(root, code_exts)
    patterns = {
        "OpenAI":   r"sk-[A-Za-z0-9]{20,}",
        "AWS Key":  r"AKIA[0-9A-Z]{16}",
        "Google":   r"AIza[0-9A-Za-z\-_]{35}",
        "Stripe":   r"sk_live_[0-9a-zA-Z]{24,}",
        "GitHub":   r"ghp_[A-Za-z0-9]{36}",
        "Twilio":   r"SK[a-f0-9]{32}",
        "SendGrid": r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}",
    }
    found = []
    for name, pat in patterns.items():
        hits = search_pattern_in_files(files, pat)
        for fpath, line_num, line in hits:
            found.append(f"[{name}] {fpath}:{line_num} → {line[:80]}")
    if found:
        t.failed("CRÍTICA",
                 "\n".join(found[:10]),
                 f"Varredura regex de {len(files)} arquivos de código em '{root}'",
                 "Chaves de API encontradas hardcoded no código-fonte. Qualquer pessoa com acesso ao repositório pode usá-las.",
                 "1. Abra os arquivos listados acima\n2. Localize a linha indicada\n3. Copie a chave e verifique se é válida",
                 "Mova para variáveis de ambiente (.env). Revogue as chaves expostas imediatamente.",
                 "\n".join(found[:5]))
    else:
        t.passed(f"{len(files)} arquivos analisados — nenhuma API Key hardcoded encontrada")
    return t

def test_passwords_hardcoded(root: str) -> TestResult:
    t = TestResult("Senhas Hardcoded no Código-Fonte", "Vibe Coding")
    files = get_all_files(root, ["py","js","ts","php","java","rb","go","env","yaml","yml","config","ini","toml"])
    pattern = r'(?i)(password|passwd|senha|pwd|secret|db_pass|database_password)\s*[=:]\s*["\'](?!.*\{)[^"\']{4,}'
    hits = search_pattern_in_files(files, pattern)
    # Exclui placeholders comuns
    exclude = ["your_password", "change_me", "xxxx", "****", "placeholder", "example", "env.get", "os.environ"]
    real_hits = [(f, n, l) for f, n, l in hits if not any(e in l.lower() for e in exclude)]
    if real_hits:
        evidence = "\n".join(f"{f}:{n} → {l[:80]}" for f, n, l in real_hits[:8])
        t.failed("CRÍTICA",
                 "\n".join(f"{f}:{n}" for f, n, l in real_hits[:5]),
                 f"Varredura regex por padrões de senha em {len(files)} arquivos",
                 "Senhas encontradas em texto limpo no código. Comprometem banco de dados e outros serviços.",
                 "1. Abra os arquivos indicados\n2. Localize as linhas\n3. Verifique se são senhas reais",
                 "Substitua por: os.environ.get('DB_PASSWORD'). Nunca hardcode senhas.",
                 evidence)
    else:
        t.passed(f"{len(files)} arquivos analisados — nenhuma senha hardcoded detectada")
    return t

def test_env_file_committed(root: str) -> TestResult:
    t = TestResult("Arquivo .env Commitado no Git", "Vibe Coding")
    env_file = Path(root) / ".env"
    gitignore = Path(root) / ".gitignore"
    if not env_file.exists():
        t.passed("Arquivo .env não encontrado no projeto")
        return t
    # Verifica se está no .gitignore
    if gitignore.exists():
        content = gitignore.read_text(errors="ignore")
        if ".env" in content:
            t.passed(".env existe mas está listado no .gitignore")
            return t
    # Verifica se está trackeado no git
    try:
        result = subprocess.run(["git", "ls-files", ".env"], capture_output=True, text=True, cwd=root, timeout=10)
        if result.stdout.strip():
            t.failed("CRÍTICA", str(env_file),
                     "git ls-files .env — verifica se .env está sendo trackeado",
                     ".env está commitado no repositório Git. Todas as credenciais ficam no histórico permanentemente.",
                     "1. Execute: git log --all --full-history -- .env\n2. Veja o conteúdo em commits antigos",
                     "git rm --cached .env && echo '.env' >> .gitignore\nRevogue todas as credenciais expostas.")
            return t
    except Exception:
        pass
    t.warn(str(env_file),
           "Arquivo .env encontrado sem .gitignore adequado",
           ".env existe mas não foi confirmado se está no .gitignore — risco de commit acidental.")
    return t

def test_git_exposed(root: str) -> TestResult:
    t = TestResult("Pasta .git com Dados Sensíveis", "OWASP A05")
    git_dir = Path(root) / ".git"
    if not git_dir.exists():
        t.passed("Pasta .git não encontrada no diretório analisado")
        return t
    # Verifica se há senhas ou tokens no histórico git
    try:
        log = subprocess.run(
            ["git", "log", "--all", "-p", "--diff-filter=A", "-S", "password"],
            capture_output=True, text=True, cwd=root, timeout=20
        )
        if "password" in log.stdout.lower() and len(log.stdout) > 100:
            t.failed("ALTA", str(git_dir),
                     "git log --all -p -S password — busca senha no histórico",
                     "Histórico Git contém commits com credenciais. Mesmo após remoção do arquivo, o histórico permanece.",
                     "1. Execute: git log --all -p -S password\n2. Veja commits com credenciais no histórico",
                     "Use git filter-branch ou BFG Repo Cleaner para reescrever o histórico. Revogue credenciais.")
            return t
    except Exception:
        pass
    t.passed("Histórico Git analisado — nenhuma credencial óbvia encontrada")
    return t

def test_unsafe_functions(root: str) -> TestResult:
    t = TestResult("Funções Inseguras (eval/exec/pickle/os.system)", "OWASP A03")
    code_files = get_all_files(root, ["py", "js", "php", "rb"])
    patterns_by_ext = {
        "py":  r'\b(eval|exec|pickle\.loads|os\.system|subprocess\.call\(.+shell=True|yaml\.load\([^,]+\))\b',
        "js":  r'\b(eval\(|Function\(|innerHTML\s*=|document\.write\()\b',
        "php": r'\b(eval\(|exec\(|system\(|passthru\(|shell_exec\()\b',
        "rb":  r'\b(eval\(|`[^`]+`|Kernel\.exec)\b',
    }
    found = []
    for fpath in code_files:
        ext = fpath.suffix.lstrip(".")
        if ext in patterns_by_ext:
            hits = search_pattern_in_files([fpath], patterns_by_ext[ext])
            for path, num, line in hits:
                found.append(f"{path}:{num} → {line[:80]}")
    if found:
        t.failed("ALTA",
                 "\n".join(found[:10]),
                 f"Varredura de funções inseguras em {len(code_files)} arquivos de código",
                 "Funções como eval/exec/pickle aceitam input arbitrário e podem executar código malicioso.",
                 "1. Localize as linhas indicadas\n2. Verifique se o argumento vem de input externo",
                 "Substitua eval() por ast.literal_eval(). Não use pickle com dados externos. Use subprocess com lista.")
    else:
        t.passed(f"{len(code_files)} arquivos analisados — nenhuma função insegura detectada")
    return t

def test_debug_mode_enabled(root: str) -> TestResult:
    t = TestResult("Debug Ativo em Produção", "OWASP A05")
    config_files = get_all_files(root, ["py", "js", "ts", "env", "yaml", "yml", "toml", "ini", "config", "json"])
    patterns = [r'(?i)DEBUG\s*[=:]\s*(True|1|true|"true")', r'(?i)app\.run\(.*debug\s*=\s*True',
                r'(?i)NODE_ENV\s*=\s*development', r'(?i)APP_ENV\s*=\s*development']
    found = []
    for pat in patterns:
        hits = search_pattern_in_files(config_files, pat)
        for path, num, line in hits:
            if ".example" not in path and "test" not in path.lower():
                found.append(f"{path}:{num} → {line[:80]}")
    if found:
        t.failed("MÉDIA",
                 "\n".join(found[:8]),
                 f"Varredura de configurações de debug em {len(config_files)} arquivos",
                 "Debug ativo expõe stack traces, variáveis internas e possibilita o Werkzeug Debugger RCE.",
                 "1. Localize os arquivos indicados\n2. Veja se DEBUG=True está configurado",
                 "Defina DEBUG=False em produção. Use variáveis de ambiente para controlar o ambiente.")
    else:
        t.passed("Nenhuma configuração de debug ativa encontrada")
    return t

def test_private_keys_in_repo(root: str) -> TestResult:
    t = TestResult("Chaves Privadas no Repositório", "OWASP A02")
    all_files = get_all_files(root)
    key_extensions = {".pem", ".key", ".p12", ".pfx", ".pkcs12", ".cer"}
    key_content_pattern = r"-----BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY-----"
    found = []
    for fpath in all_files:
        if fpath.suffix in key_extensions:
            found.append(f"Arquivo de chave: {fpath}")
    # Busca conteúdo de chave privada em qualquer arquivo
    hits = search_pattern_in_files(all_files, key_content_pattern)
    for path, num, line in hits:
        found.append(f"Chave privada em: {path}:{num}")
    if found:
        t.failed("CRÍTICA",
                 "\n".join(found[:8]),
                 f"Busca por arquivos .pem/.key e padrão '-----BEGIN PRIVATE KEY-----' em {len(all_files)} arquivos",
                 "Chaves privadas no repositório comprometem toda a infraestrutura criptográfica.",
                 "1. Localize os arquivos listados\n2. Verifique se contêm chaves reais",
                 "Remova do repositório imediatamente. Adicione ao .gitignore. Revogue e gere novas chaves.")
    else:
        t.passed("Nenhuma chave privada encontrada no repositório")
    return t

def test_weak_crypto(root: str) -> TestResult:
    t = TestResult("Criptografia Fraca (MD5/SHA1 para Senhas)", "OWASP A02")
    code_files = get_all_files(root, ["py", "php", "js", "rb", "java"])
    pattern = r'(?i)(md5|sha1|sha-1)\s*\('
    hits = search_pattern_in_files(code_files, pattern)
    # Filtra contextos de senha/hash
    sensitive = [h for h in hits if any(k in h[2].lower() for k in ["password", "passwd", "senha", "hash", "token", "secret"])]
    if sensitive:
        evidence = "\n".join(f"{f}:{n} → {l[:80]}" for f, n, l in sensitive[:6])
        t.failed("ALTA",
                 "\n".join(f"{f}:{n}" for f, n, l in sensitive[:5]),
                 f"Varredura de funções MD5/SHA1 em contexto de senha em {len(code_files)} arquivos",
                 "MD5 e SHA1 são quebrados para uso de senhas. Rainbow tables crackam hashes instantaneamente.",
                 "1. Localize as linhas indicadas\n2. Veja se MD5/SHA1 é usado para hash de senha",
                 "Use bcrypt, argon2 ou pbkdf2. Ex: bcrypt.hashpw(password, bcrypt.gensalt())",
                 evidence)
    elif hits:
        t.warn("\n".join(f"{f}:{n}" for f, n, l in hits[:3]),
               f"MD5/SHA1 encontrados em {len(hits)} ocorrências",
               "MD5/SHA1 usados (possivelmente para checksum, não senha). Valide o contexto real.")
    else:
        t.passed("Nenhum uso de MD5/SHA1 em contexto sensível detectado")
    return t

def test_vulnerable_dependencies(root: str) -> TestResult:
    t = TestResult("Dependências Desatualizadas / CVEs Conhecidos", "OWASP A06")
    dep_files = {
        "requirements.txt": Path(root) / "requirements.txt",
        "package.json":     Path(root) / "package.json",
    }

    known_vulnerable = {
        # Python
        "django": {"<2.2.28": "CVE-2022-28347", "<3.2.13": "CVE-2022-28347"},
        "flask":  {"<2.2.5":  "CVE-2023-30861"},
        "pillow": {"<9.3.0":  "CVE-2022-45199"},
        "cryptography": {"<41.0.0": "CVE-2023-49083"},
        "pyyaml": {"<6.0":    "CVE-2022-1471"},
        "requests": {"<2.28.0": "CVE-2023-32681"},
        # JS
        "lodash":  {"<4.17.21": "CVE-2021-23337"},
        "axios":   {"<1.6.0":   "CVE-2023-45857"},
        "moment":  {"<2.29.4":  "CVE-2022-31129"},
        "express": {"<4.18.2":  "CVE-2022-24999"},
        "jsonwebtoken": {"<9.0.0": "CVE-2022-23529"},
    }

    found = []

    # requirements.txt
    req_file = dep_files["requirements.txt"]
    if req_file.exists():
        for line in req_file.read_text(errors="ignore").splitlines():
            line = line.strip()
            match = re.match(r"([a-zA-Z0-9_\-]+)[=<>!~]+([0-9.]+)", line)
            if match:
                pkg, ver = match.group(1).lower(), match.group(2)
                if pkg in known_vulnerable:
                    for constraint, cve in known_vulnerable[pkg].items():
                        found.append(f"{pkg}=={ver} pode ser vulnerável — {cve} ({constraint})")

    # package.json
    pkg_file = dep_files["package.json"]
    if pkg_file.exists():
        try:
            data = json.loads(pkg_file.read_text(errors="ignore"))
            deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
            for pkg, ver in deps.items():
                pkg_lower = pkg.lower()
                if pkg_lower in known_vulnerable:
                    found.append(f"{pkg}@{ver} — verificar contra CVEs de {pkg_lower}")
        except Exception:
            pass

    if found:
        t.failed("ALTA",
                 "\n".join(found[:8]),
                 "Análise de requirements.txt e package.json contra lista de CVEs conhecidos",
                 "Dependências com vulnerabilidades conhecidas podem ser exploradas por atacantes.",
                 "1. Execute: pip-audit (Python) ou npm audit (Node.js)\n2. Veja os pacotes listados",
                 "Atualize os pacotes. Execute regularmente: pip-audit e npm audit fix.")
    else:
        t.passed("Nenhuma dependência com CVE imediato detectada (verifique também pip-audit / npm audit)")
    return t

def test_debug_endpoints_in_code(root: str) -> TestResult:
    t = TestResult("Endpoints de Debug/Admin Sem Proteção no Código", "OWASP A01")
    code_files = get_all_files(root, ["py", "js", "ts", "php", "rb"])
    pattern = r'(?i)(route|app\.(get|post|route)|@app\.(route|get|post))\s*[\(\'"](\/admin|\/debug|\/test|\/internal|\/dev|\/secret|\/backdoor)'
    hits = search_pattern_in_files(code_files, pattern)
    if hits:
        evidence = "\n".join(f"{f}:{n} → {l[:80]}" for f, n, l in hits[:6])
        t.failed("ALTA",
                 "\n".join(f"{f}:{n}" for f, n, l in hits[:5]),
                 f"Varredura de definição de rotas em {len(code_files)} arquivos",
                 "Rotas de admin/debug/test definidas no código sem middleware de autenticação evidente.",
                 "1. Localize as rotas nas linhas indicadas\n2. Verifique se há verificação de autenticação antes",
                 "Adicione middleware de autenticação em todas as rotas admin. Remova rotas de debug em produção.",
                 evidence)
    else:
        t.passed("Nenhuma rota de admin/debug sem proteção evidente no código")
    return t

def test_sensitive_logs(root: str) -> TestResult:
    t = TestResult("Logs com Dados Sensíveis (Senhas/Tokens)", "OWASP A09")
    code_files = get_all_files(root, ["py", "js", "ts", "php", "java", "rb"])
    pattern = r'(?i)(print|console\.log|logger\.(info|debug|error)|log)\s*\([^)]*?(password|token|secret|api_key|senha|credencial)[^)]*\)'
    hits = search_pattern_in_files(code_files, pattern)
    if hits:
        evidence = "\n".join(f"{f}:{n} → {l[:80]}" for f, n, l in hits[:6])
        t.failed("MÉDIA",
                 "\n".join(f"{f}:{n}" for f, n, l in hits[:5]),
                 f"Varredura de chamadas de log em {len(code_files)} arquivos",
                 "Logs registram dados sensíveis que ficam persistidos em arquivos de log legíveis.",
                 "1. Localize as linhas indicadas\n2. Execute o código e verifique o arquivo de log",
                 "NUNCA logue senhas, tokens ou dados pessoais. Filtre campos sensíveis antes do log.",
                 evidence)
    else:
        t.passed("Nenhum log de dados sensíveis detectado")
    return t

def test_credentials_in_comments(root: str) -> TestResult:
    t = TestResult("Credenciais em Comentários de Código", "Vibe Coding")
    code_files = get_all_files(root, ["py", "js", "ts", "php", "java", "rb", "go"])
    pattern = r'(?i)(#|//|/\*|\*)\s*(password|senha|token|api.?key|secret)\s*[=:]\s*\S+'
    hits = search_pattern_in_files(code_files, pattern)
    exclude = ["your", "example", "placeholder", "xxxx", "change"]
    real_hits = [(f, n, l) for f, n, l in hits if not any(e in l.lower() for e in exclude)]
    if real_hits:
        evidence = "\n".join(f"{f}:{n} → {l[:80]}" for f, n, l in real_hits[:6])
        t.failed("ALTA",
                 "\n".join(f"{f}:{n}" for f, n, l in real_hits[:5]),
                 f"Varredura de comentários com padrões de credenciais em {len(code_files)} arquivos",
                 "Credenciais em comentários permanecem no código mesmo se a linha de código for removida.",
                 "1. Abra os arquivos nas linhas indicadas\n2. Veja os comentários com credenciais",
                 "Remova credenciais de comentários. Nunca documente senhas reais no código.",
                 evidence)
    else:
        t.passed("Nenhuma credencial detectada em comentários de código")
    return t

def test_insecure_deserialization(root: str) -> TestResult:
    t = TestResult("Deserialização Insegura (pickle/yaml.load)", "OWASP A08")
    py_files = get_all_files(root, ["py"])
    patterns = [
        r'pickle\.loads?\(',
        r'yaml\.load\([^,)]+\)',          # yaml.load sem Loader=
        r'marshal\.loads?\(',
        r'jsonpickle\.decode\(',
    ]
    found = []
    for pat in patterns:
        hits = search_pattern_in_files(py_files, pat)
        for path, num, line in hits:
            found.append(f"{path}:{num} → {line[:80]}")
    if found:
        t.failed("CRÍTICA",
                 "\n".join(found[:8]),
                 f"Varredura de funções de deserialização insegura em {len(py_files)} arquivos Python",
                 "pickle.loads() com dados não confiáveis permite execução arbitrária de código Python.",
                 "1. Localize as linhas indicadas\n2. Verifique se os dados vêm de fonte não confiável",
                 "Substitua pickle por json para dados simples. Use yaml.safe_load() no lugar de yaml.load().")
    else:
        t.passed("Nenhuma deserialização insegura detectada")
    return t

def test_file_permissions(root: str) -> TestResult:
    t = TestResult("Permissões Excessivas de Arquivo (777/666)", "OWASP A05")
    if os.name == "nt":  # Windows não tem chmod da mesma forma
        t.warn(root, "Verificação de permissões (SO Windows)",
               "Verificação de permissões UNIX (chmod 777) não aplicável no Windows. Verifique manualmente.")
        return t
    found = []
    for fpath in get_all_files(root):
        try:
            mode = fpath.stat().st_mode
            if bool(mode & stat.S_IWOTH):  # world-writable
                found.append(str(fpath))
        except Exception:
            pass
    if found:
        t.failed("ALTA",
                 "\n".join(found[:10]),
                 f"Verificação de permissões em {sum(1 for _ in get_all_files(root))} arquivos",
                 "Arquivos com permissão world-writable (o bit 'outros' tem escrita) podem ser modificados por qualquer usuário.",
                 "1. Execute: ls -la nos arquivos listados\n2. Veja as permissões na primeira coluna",
                 "chmod 644 para arquivos comuns. chmod 600 para chaves privadas. Nunca use 777.")
    else:
        t.passed("Nenhum arquivo com permissões excessivas encontrado")
    return t

def test_sql_in_code_concatenation(root: str) -> TestResult:
    t = TestResult("SQL por Concatenação de Strings (Potencial SQLi)", "OWASP A03")
    code_files = get_all_files(root, ["py", "php", "java", "rb", "js"])
    pattern = r'(?i)(execute|query|cursor\.execute)\s*\(\s*["\']?\s*(SELECT|INSERT|UPDATE|DELETE|DROP).*\+\s*'
    hits = search_pattern_in_files(code_files, pattern)
    if hits:
        evidence = "\n".join(f"{f}:{n} → {l[:80]}" for f, n, l in hits[:6])
        t.failed("CRÍTICA",
                 "\n".join(f"{f}:{n}" for f, n, l in hits[:5]),
                 f"Varredura de queries SQL por concatenação em {len(code_files)} arquivos",
                 "SQL construído por concatenação de strings é a causa raiz mais comum de SQL Injection.",
                 "1. Abra os arquivos nas linhas indicadas\n2. Veja se o input do usuário é concatenado na query",
                 "Use Prepared Statements: cursor.execute('SELECT * FROM t WHERE id=%s', (user_id,))",
                 evidence)
    else:
        t.passed("Nenhuma concatenação de SQL direta detectada")
    return t

def test_upload_validation(root: str) -> TestResult:
    t = TestResult("Upload de Arquivo Sem Validação de Tipo", "OWASP A01")
    code_files = get_all_files(root, ["py", "php", "js", "ts", "rb"])
    upload_pattern = r'(?i)(file\.save|move_uploaded_file|multer\(|FileField|upload|request\.files)'
    type_check_pattern = r'(?i)(allowedExtensions|whitelist|mimetype|content.?type|filename\.endswith)'
    upload_hits = search_pattern_in_files(code_files, upload_pattern)
    found = []
    for fpath, num, line in upload_hits:
        try:
            content = Path(fpath).read_text(errors="ignore")
            if not re.search(type_check_pattern, content, re.I):
                found.append(f"{fpath}:{num} — upload sem validação de tipo")
        except Exception:
            pass
    if found:
        t.failed("ALTA",
                 "\n".join(found[:6]),
                 f"Análise de código de upload em arquivos com lógica de upload",
                 "Upload sem validação permite envio de arquivos .php/.py executáveis — Remote Code Execution.",
                 "1. Localize o código de upload\n2. Verifique ausência de checagem de extensão/mimetype",
                 "Implemente whitelist: ['jpg','png','gif']. Valide mimetype real com python-magic. Renomeie arquivos.")
    else:
        t.passed("Uploads com validação de tipo encontrados ou nenhum upload detectado")
    return t

def test_sqlite_no_password(root: str) -> TestResult:
    t = TestResult("Banco de Dados SQLite Sem Criptografia", "OWASP A02")
    db_files = list(Path(root).rglob("*.db")) + list(Path(root).rglob("*.sqlite")) + list(Path(root).rglob("*.sqlite3"))
    if db_files:
        sensitive_content = []
        for db in db_files:
            try:
                content = db.read_bytes()
                if content[:6] == b"SQLite":
                    sensitive_content.append(str(db))
            except Exception:
                pass
        if sensitive_content:
            t.warn("\n".join(sensitive_content),
                   f"Detecção de arquivos *.db/*.sqlite no projeto",
                   f"{len(sensitive_content)} banco(s) SQLite sem criptografia. Dados legíveis por qualquer processo com acesso ao arquivo.")
            return t
    t.passed("Nenhum arquivo SQLite desprotegido encontrado")
    return t

def test_env_variables_with_fallback(root: str) -> TestResult:
    t = TestResult("Variáveis de Ambiente com Fallback Inseguro", "Vibe Coding")
    py_files = get_all_files(root, ["py", "js", "ts"])
    pattern = r'(?i)os\.environ\.get\s*\(["\'][^"\']+["\']\s*,\s*["\'][^"\']{4,}["\']\s*\)'
    hits = search_pattern_in_files(py_files, pattern)
    sensitive_hits = [h for h in hits if any(k in h[2].lower() for k in ["password","secret","key","token","api"])]
    if sensitive_hits:
        evidence = "\n".join(f"{f}:{n} → {l[:80]}" for f, n, l in sensitive_hits[:6])
        t.failed("MÉDIA",
                 "\n".join(f"{f}:{n}" for f, n, l in sensitive_hits[:5]),
                 f"Varredura de os.environ.get() com fallback em {len(py_files)} arquivos",
                 "Variáveis sensíveis têm valor padrão hardcoded. Se a variável não for definida, o fallback inseguro é usado.",
                 "1. Localize as linhas\n2. Veja o segundo argumento do get() — é o valor padrão",
                 "Remova o fallback. Lance erro se a variável não estiver definida: os.environ['SECRET_KEY']",
                 evidence)
    else:
        t.passed("Nenhum fallback inseguro em variáveis de ambiente detectado")
    return t

# ─────────────────────────────────────────
#  GERAÇÃO DE PDF
# ─────────────────────────────────────────

def generate_pdf(results: list, project_path: str, output_path: str):
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    # Capa
    pdf.set_fill_color(15, 10, 30)
    pdf.rect(0, 0, 210, 297, "F")
    pdf.set_font("Helvetica", "B", 26)
    pdf.set_text_color(180, 0, 255)
    pdf.set_y(60)
    pdf.cell(0, 15, "CyberDyne", ln=True, align="C")
    pdf.set_font("Helvetica", "B", 15)
    pdf.set_text_color(255, 255, 255)
    pdf.cell(0, 10, "Local Security Scanner Report", ln=True, align="C")
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(140, 130, 180)
    proj_name = os.path.basename(project_path.rstrip("/\\"))
    pdf.cell(0, 8, f"Projeto: {proj_name}", ln=True, align="C")
    pdf.cell(0, 8, f"Caminho: {project_path}", ln=True, align="C")
    pdf.cell(0, 8, f"Data: {datetime.datetime.now().strftime('%d/%m/%Y %H:%M:%S')}", ln=True, align="C")

    total,passed,failed,warns,errors = len(results),0,0,0,0
    for r in results:
        if r.status=="APROVADO": passed+=1
        elif r.status=="REPROVADO": failed+=1
        elif r.status=="AVISO": warns+=1
        else: errors+=1

    pdf.set_y(145)
    for label, val, color in [
        ("Total de Testes", str(total), (200,200,200)),
        ("Aprovados ✔",     str(passed), (80,220,100)),
        ("Reprovados ✖",    str(failed), (220,60,60)),
        ("Avisos ▲",        str(warns),  (255,180,0)),
        ("Erros",           str(errors), (180,100,255)),
    ]:
        pdf.set_font("Helvetica","B",13)
        pdf.set_text_color(*color)
        pdf.cell(0, 10, f"{label}: {val}", ln=True, align="C")

    def add_block(r: TestResult):
        pdf.add_page()
        pdf.set_fill_color(18, 12, 35)
        pdf.rect(0, 0, 210, 297, "F")
        stat_col = {"APROVADO":(80,220,100),"REPROVADO":(220,60,60),"AVISO":(255,180,0),"ERRO":(160,80,255)}.get(r.status,(200,200,200))
        pdf.set_font("Helvetica","B",14)
        pdf.set_text_color(*stat_col)
        pdf.cell(0, 12, f"[{r.status}] {r.name}", ln=True)
        pdf.set_font("Helvetica","",10)
        pdf.set_text_color(140,130,175)
        pdf.cell(0, 6, f"Categoria: {r.category}   |   Severidade: {r.severity}", ln=True)
        pdf.ln(3)
        for title, content in [
            ("Onde foi encontrado",          r.where),
            ("Como foi testado",             r.how_tested),
            ("Por que reprovou",             r.why_failed),
            ("Como reproduzir manualmente",  r.manual_repro),
            ("Recomendação de correção",     r.recommendation),
            ("Evidência",                    r.evidence),
        ]:
            if content:
                pdf.set_font("Helvetica","B",11)
                pdf.set_text_color(180,80,255)
                pdf.cell(0, 8, title+":", ln=True)
                pdf.set_font("Helvetica","",10)
                pdf.set_text_color(220,210,240)
                for line in content.splitlines():
                    pdf.multi_cell(0, 6, line)
                pdf.ln(2)

    for r in sorted(results, key=lambda x: {"REPROVADO":0,"AVISO":1,"ERRO":2,"APROVADO":3}.get(x.status,4)):
        add_block(r)

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    pdf.output(output_path)

# ─────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────

def run_all_tests(root: str) -> list:
    tests = [
        ("Chaves de API Hardcoded",              test_api_keys_hardcoded),
        ("Senhas Hardcoded",                     test_passwords_hardcoded),
        (".env Commitado no Git",                test_env_file_committed),
        ("Pasta .git com Credenciais",           test_git_exposed),
        ("Funções Inseguras (eval/exec/pickle)", test_unsafe_functions),
        ("Debug Ativo em Produção",              test_debug_mode_enabled),
        ("Chaves Privadas no Repositório",       test_private_keys_in_repo),
        ("Criptografia Fraca (MD5/SHA1)",        test_weak_crypto),
        ("Dependências com CVEs",                test_vulnerable_dependencies),
        ("Endpoints Admin Sem Proteção",         test_debug_endpoints_in_code),
        ("Logs com Dados Sensíveis",             test_sensitive_logs),
        ("Credenciais em Comentários",           test_credentials_in_comments),
        ("Deserialização Insegura",              test_insecure_deserialization),
        ("Permissões de Arquivo Excessivas",     test_file_permissions),
        ("SQL por Concatenação",                 test_sql_in_code_concatenation),
        ("Upload Sem Validação de Tipo",         test_upload_validation),
        ("SQLite Sem Criptografia",              test_sqlite_no_password),
        ("Variáveis de Ambiente com Fallback",   test_env_variables_with_fallback),
    ]

    print(f"\n{Fore.MAGENTA}{'─'*68}")
    print(f"  🔍 Iniciando varredura de {len(tests)} testes locais em:")
    print(f"     {Fore.YELLOW}{root}")
    print(f"{Fore.MAGENTA}{'─'*68}\n")

    results = []
    for name, fn in tests:
        try:
            r = fn(root)
        except Exception as e:
            r = TestResult(name, "Sistema")
            r.error(f"Exceção inesperada: {e}")
        print_status(r.name, r.status, r.severity)
        results.append(r)
        time.sleep(0.15)
    return results

def main():
    print(BANNER)
    for line in WELCOME_MSG:
        print(line)
        time.sleep(0.05)

    print(f"\n{Fore.YELLOW}  ⚠️  AVISO LEGAL:{Fore.WHITE} Analise apenas projetos com autorização explícita.")
    print(f"{Fore.WHITE}  O uso não autorizado e/ou mal-intencionado é crime.\n")

    root = input(f"{Fore.MAGENTA}  📁 Caminho do projeto a analisar: {Fore.WHITE}").strip().strip('"')
    if not os.path.isdir(root):
        print(f"\n{Fore.RED}  [!] Caminho inválido ou não é um diretório: {root}")
        sys.exit(1)

    confirm = input(f"\n{Fore.RED}  [!] Você confirma autorização para analisar '{os.path.basename(root)}'? (sim/não): {Fore.WHITE}").strip().lower()
    if confirm not in ("sim", "s", "yes", "y"):
        print(f"\n{Fore.RED}  Execução cancelada. Autorização não confirmada.")
        sys.exit(0)

    print(f"\n{Fore.GREEN}  ✅ Autorização registrada. Iniciando scanner local...\n")

    results = run_all_tests(root)

    passed = sum(1 for r in results if r.status == "APROVADO")
    failed = sum(1 for r in results if r.status == "REPROVADO")
    warns  = sum(1 for r in results if r.status == "AVISO")

    print(f"\n{Fore.MAGENTA}{'═'*68}")
    print(f"  📊  RESUMO FINAL")
    print(f"{Fore.MAGENTA}{'─'*68}")
    print(f"  {Fore.GREEN}✅ Aprovados : {passed}")
    print(f"  {Fore.RED}❌ Reprovados: {failed}")
    print(f"  {Fore.YELLOW}⚠️  Avisos   : {warns}")
    print(f"{Fore.MAGENTA}{'═'*68}\n")

    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    pdf_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports", f"cyberdyne_local_{ts}.pdf")
    print(f"  📄 Gerando relatório PDF...")
    generate_pdf(results, root, pdf_path)
    print(f"  {Fore.GREEN}✅ Relatório salvo em: {Fore.WHITE}{pdf_path}\n")

if __name__ == "__main__":
    main()
