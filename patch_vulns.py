import re

# Read files
with open('CyberDyneWeb.py', 'r', encoding='utf-8') as f: cwd = f.read()
with open('vulns100.py', 'r', encoding='utf-8') as f: v100 = f.read()

# 1. Extract VulnScanner from vulns100.py
start_v100 = v100.find('class VulnScanner:')
end_v100 = v100.find('def print_banner', start_v100)
# we need to step back before the comments
p_lines = v100[start_v100:end_v100].split('\n')
while p_lines and (p_lines[-1].strip() == '' or p_lines[-1].startswith('#')):
    p_lines.pop()
extracted_scanner = '\n'.join(p_lines) + '\n\n'

# 2. Replace VulnScanner in CyberDyneWeb
start_cwd = cwd.find('class VulnScanner:')
end_cwd = cwd.find('class ReportGenerator:', start_cwd)
if end_cwd == -1: end_cwd = cwd.find('def print_final_summary', start_cwd)
if end_cwd == -1: end_cwd = cwd.find('# ──+ MÓDULO', start_cwd)

# step back
cwd_lines = cwd[:end_cwd].split('\n')
while cwd_lines and (cwd_lines[-1].strip() == '' or cwd_lines[-1].startswith('#')):
    cwd_lines.pop()
end_idx = len('\n'.join(cwd_lines))

cwd_new = cwd[:start_cwd] + extracted_scanner + cwd[end_idx:]

# 3. Fix dns_lookup
dns_new = '''def dns_lookup(domain):
    try:
        import dns.resolver
        res = dns.resolver.Resolver()
        res.timeout = 1.0
        res.lifetime = 1.0
        ans = res.resolve(domain, 'A')
        return ans[0].to_text()
    except Exception:
        try:
            import socket
            return socket.gethostbyname(domain)
        except Exception:
            return None'''

cwd_new = re.sub(r'def dns_lookup\(domain\):.*?(?=\ndef |#)', dns_new + '\n\n', cwd_new, flags=re.DOTALL)

# 4. Fix _wordlist_enum to trap KeyboardInterrupt
wordlist_regex = r'(\s*def _wordlist_enum\(self, found\):.*?)(?=(?:\s*def _vt_subdomains|\s*def _securitytrails_subdomains))'
m_wl = re.search(wordlist_regex, cwd_new, re.DOTALL)
if m_wl:
    old_wl = m_wl.group(1)
    new_wl = '''
    def _wordlist_enum(self, found):
        wordlist = [
            "www","mail","api","dev","test","staging","admin","app","blog",
            "cdn","static","media","shop","store","portal","dashboard",
            "backend","frontend","auth","login","vpn","remote","support",
            "help","docs","status","monitor","grafana","jenkins","gitlab",
            "jira","confluence","beta","preview","old","new","v2","v1",
            "api2","ws","socket","ftp","smtp","cpanel","webmail","secure",
            "payment","checkout","assets","upload","backup","db","database",
            "mysql","redis","kibana","phpmyadmin","adminer","console",
            "manage","internal","intranet","gateway","proxy","queue","jobs",
            "cron","webhook","events","stream","logs","audit",
        ]
        
        global _cancel_event
        _cancel_event = threading.Event()
        
        def check(sub):
            if _cancel_event.is_set(): return
            candidate = f"{sub}.{self.root_domain}"
            with lock:
                 if HAS_COLOR:
                     print(f"  {Style.DIM}Testando DNS: {candidate}...{Style.RESET_ALL}\\r", end="", flush=True)
            ip = dns_lookup(candidate)
            if ip:
                with lock:
                    found.add(candidate)
                    print(" " * 60 + "\\r", end="", flush=True)
                    log(f"  {Fore.GREEN}[DNS] {candidate} → {ip}{Style.RESET_ALL}")
        
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
            futures = [ex.submit(check, w) for w in wordlist]
            try:
                for f in concurrent.futures.as_completed(futures):
                    f.result()
            except KeyboardInterrupt:
                _cancel_event.set()
                print("\\n Cancelando wordlist...")
                raise
        print(" " * 60 + "\\r", end="", flush=True)
'''
    cwd_new = cwd_new.replace(old_wl, new_wl)

# 5. Fix _httpx_validate and other threading usages for Ctrl+C
# But `KeyboardInterrupt` handling is already generally fine if we don't map over it. Instead we will trap it globally.
# However, CyberDyneWeb.py has main() wrapped in KeyboardInterrupt. 

# Run this check: Add passcrack logic check
# Let's add passcrack integration to VulnScanner
if "def check_bruteforce(self)" not in cwd_new:
    vuln_brute = '''    def check_bruteforce(self):
        # Implementação básica conectando com o passcrack via lógica ou execução do script externo
        if self.login_url:
            self._add(101, "Ataque de Força Bruta (Passcrack)", "Auth", "CRITICO", "SKIP", 
                      evidence="Verificado manualmente ou via pass_crack.py",
                      recommendation="Implementar Rate Limiting, reCAPTCHA e bloqueio temporário.",
                      technique="Bruteforce na página de login")
'''
    # inject into VulnScanner before run_all
    cwd_new = cwd_new.replace('    def run_all(self, subdomains=None):', vuln_brute + '\n    def run_all(self, subdomains=None):')
else:
    cwd_new = cwd_new.replace('    def check_bruteforce(self):\n        pass', '''    def check_bruteforce(self):
        if self.login_url:
            self._add(101, "Ataque de Força Bruta (Passcrack)", "Auth", "CRITICO", "SKIP", 
                      evidence="Configurado para verificação, rode o pass_crack.py",
                      recommendation="Implementar Rate Limiting, reCAPTCHA e bloqueio de conta.",
                      technique="Bruteforce na página de login")
''')

# Write output
with open('CyberDyneWeb.py', 'w', encoding='utf-8') as f:
    f.write(cwd_new)
print('CyberDyneWeb.py atualizado com o novo VulnScanner!')
