# 🛡️ CyberDyne — Security Vulnerability Scanner

```
 ██████╗██╗   ██╗██████╗ ███████╗██████╗ ██████╗ ██╗   ██╗███╗   ██╗███████╗
██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔══██╗╚██╗ ██╔╝████╗  ██║██╔════╝
██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝██║  ██║ ╚████╔╝ ██╔██╗ ██║█████╗  
██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██║  ██║  ╚██╔╝  ██║╚██╗██║██╔══╝  
╚██████╗   ██║   ██████╔╝███████╗██║  ██║██████╔╝   ██║   ██║ ╚████║███████╗
 ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═════╝    ╚═╝   ╚═╝  ╚═══╝╚══════╝
                                                              v1.0 — by CyberDyne
```

> **"O código que você não testou é o ataque que você não viu vir."**

---

## 📖 Sobre o Projeto

**CyberDyne** é uma suíte de segurança ofensiva e defensiva projetada com um único propósito: **busca incessante e sistemática por vulnerabilidades** em aplicações web e sistemas locais.

O projeto nasce em resposta a um problema urgente do mundo moderno: **a explosão do "Vibe Coding"** — a prática de desenvolver software rapidamente com auxílio de IAs generativas como ChatGPT, Gemini, Copilot e similares. Essa nova onda de desenvolvimento acelera a produção, mas também introduz padrões inseguros de forma silenciosa: chaves de API expostas no código-fonte, ausência de validações, injeções SQL, tokens hardcoded e dezenas de outras falhas críticas que passam despercebidas.

> ⚠️ **AVISO LEGAL**: Este script deve ser utilizado **EXCLUSIVAMENTE** em sistemas e aplicações para os quais você possui **autorização explícita**. O uso não autorizado é ilegal e antiético. O CyberDyne foi construído para o bem — para proteger, não para atacar.

---

## 🎯 Missão

- ✅ Testar **no mínimo 100 vulnerabilidades** conhecidas e documentadas
- ✅ Cobrir o **OWASP Top 10** integralmente
- ✅ Focar nas falhas mais comuns geradas por **código assistido por IA**
- ✅ Gerar um **relatório PDF completo** com cada teste: aprovado/reprovado, onde falhou, por que falhou, e como você pode reproduzir manualmente
- ✅ Gerar um **Prompt_recall.md** onde vai explicar apenas as vulnerabilidades que foram
encontradas no sistema e como sanitiza-las do sistema.
- ✅ Ser **assertivo** — cada teste é validado com evidência, não apenas suposição

---

## 🗂️ Estrutura do Projeto

```
CyberDyne/
├── CyberDyne.py          # Scanner local: arquivos, código-fonte, variáveis de ambiente
├── CyberDyneWeb.py       # Scanner web: endpoints HTTP, formulários, headers, APIs
├── README.md             # Este arquivo
├── reports/              # Relatórios PDF gerados automaticamente
│   └── report_YYYYMMDD_HHMMSS.pdf
├── logs/                 # Logs brutos de cada execução
└── requirements.txt      # Dependências Python
```

---

## 🔬 As 50+ Vulnerabilidades Testadas

### 🔴 OWASP Top 10 (2021)

| # | ID | Vulnerabilidade | Módulo |
|---|-----|----------------|--------|
| 1 | A01 | Broken Access Control | Web + Local |
| 2 | A02 | Cryptographic Failures | Web + Local |
| 3 | A03 | Injection (SQL, NoSQL, LDAP, OS) | Web |
| 4 | A04 | Insecure Design | Local |
| 5 | A05 | Security Misconfiguration | Web + Local |
| 6 | A06 | Vulnerable & Outdated Components | Local |
| 7 | A07 | Identification & Authentication Failures | Web |
| 8 | A08 | Software & Data Integrity Failures | Web + Local |
| 9 | A09 | Security Logging & Monitoring Failures | Local |
| 10 | A10 | Server-Side Request Forgery (SSRF) | Web |

---

### 🌐 CyberDyneWeb.py — Vulnerabilidades Web

| # | Vulnerabilidade | Descrição do Teste |
|---|----------------|-------------------|
| 1 | SQL Injection (GET/POST) | Injeção de payloads clássicos e baseados em tempo em parâmetros de URL e formulários |
| 2 | Blind SQL Injection | Detecção por diferença de tempo de resposta (time-based) |
| 3 | XSS Refletido | Injeção de scripts em parâmetros de URL e campos de formulário |
| 4 | XSS Armazenado | Verificação de persistência de payloads maliciosos no servidor |
| 5 | XSS baseado em DOM | Análise de `innerHTML`, `document.write` no código JS |
| 6 | CSRF (Cross-Site Request Forgery) | Verificação de ausência de tokens CSRF em formulários |
| 7 | SSRF (Server-Side Request Forgery) | Injeção de URLs internas em campos aceitos pela aplicação |
| 8 | Open Redirect | Manipulação de parâmetros `redirect`, `next`, `url` para redirecionamento externo |
| 9 | Path Traversal / Directory Traversal | Tentativa de acesso a arquivos com `../../etc/passwd` |
| 10 | LFI (Local File Inclusion) | Inclusão de arquivos locais via parâmetros PHP/URL |
| 11 | RFI (Remote File Inclusion) | Inclusão de arquivos remotos via URL maliciosa |
| 12 | Command Injection | Injeção de comandos OS em campos de entrada |
| 13 | HTTP Header Injection | Injeção de `\r\n` em headers HTTP |
| 14 | Clickjacking | Ausência do header `X-Frame-Options` ou `CSP: frame-ancestors` |
| 15 | Exposição de informações no servidor | Análise de headers como `Server`, `X-Powered-By`, `X-AspNet-Version` |
| 16 | CORS misconfiguration | Verificação de `Access-Control-Allow-Origin: *` com credenciais |
| 17 | Autenticação Quebrada (Brute Force) | Teste de rate limiting em endpoints de login |
| 18 | Enumeração de usuários | Diferença de mensagens de erro entre usuário inexistente e senha errada |
| 19 | Exposição de API Key em respostas | Detecção de padrões de API Keys em corpo de respostas JSON/HTML |
| 20 | JWT Fraco (alg: none / chave fraca) | Análise de tokens JWT: algoritmo `none`, chaves padrão e without signature |
| 21 | Tokens de sessão previsíveis | Análise de entropia e padrão de cookies de sessão |
| 22 | Ausência de flags de segurança em cookies | Detecção de falta de `HttpOnly`, `Secure`, `SameSite` |
| 23 | IDOR (Insecure Direct Object Reference) | Manipulação de IDs em URLs e parâmetros para acessar recursos alheios |
| 24 | Mass Assignment | Envio de campos extras em formulários/JSON (e.g., `role=admin`) |
| 25 | Exposição de diretórios sensíveis | Verificação de `/admin`, `/.git`, `/.env`, `/backup`, `/config` |
| 26 | Robots.txt Disclosure | Leitura e análise de diretórios proibidos expostos no `robots.txt` |
| 27 | Swagger / API Docs públicos | Detecção de `/swagger`, `/api-docs`, `/openapi.json` sem autenticação |
| 28 | Rate Limiting ausente | Múltiplas requisições ao mesmo endpoint sem bloqueio |
| 29 | HTTP Methods inseguros | Verificação de métodos `PUT`, `DELETE`, `TRACE`, `OPTIONS` habilitados |
| 30 | Content Security Policy ausente | Ausência ou configuração fraca de cabeçalho CSP |
| 31 | HSTS ausente | Ausência de `Strict-Transport-Security` em sites HTTPS |
| 32 | Subdomínio Takeover | Verificação DNS de subdomínios órfãos apontando para serviços desativados |
| 33 | XXE (XML External Entity) | Injeção de entidades externas XML em endpoints que aceitam XML |
| 34 | Template Injection (SSTI) | Injeção de `{{7*7}}`, `${7*7}` em campos de entrada |
| 35 | GraphQL Introspection | Verificação de endpoint GraphQL com introspection habilitado em produção |
| 36 | Log4Shell (CVE-2021-44228) | Envio de payload `${jndi:ldap://...}` em User-Agent e parâmetros |
| 37 | Spring4Shell | Detecção de parâmetros vulneráveis em aplicações Spring |
| 38 | Sensitive Data in URL | Detecção de tokens, senhas e chaves em query strings de URLs |
| 39 | Broken Object Level Authorization (BOLA) | Acesso a objetos de outros usuários via API REST |
| 40 | API Versão Antiga Exposta | Acesso a `/v1/`, `/v0/` quando `/v2/` é atual — versões antigas com menos segurança |

---

### 🖥️ CyberDyne.py — Vulnerabilidades Locais (Código-Fonte & Sistema)

| # | Vulnerabilidade | Descrição do Teste |
|---|----------------|-------------------|
| 41 | Chaves de API Hardcoded | Busca por padrões de API Keys (OpenAI, AWS, GCP, Stripe, etc.) no código |
| 42 | Senhas Hardcoded | Detecção de `password=`, `passwd=`, `secret=` no código-fonte |
| 43 | Tokens Hardcoded | Busca de padrões de JWT, Bearer tokens, OAuth tokens no código |
| 44 | `.env` Exposto | Verificação se `.env` está commitado no Git ou publicamente acessível |
| 45 | `.git` Exposto | Pasta `.git` acessível publicamente (vazamento de histórico do código) |
| 46 | Dependências com CVEs conhecidos | Análise de `requirements.txt`, `package.json`, `pom.xml` contra CVEs |
| 47 | Uso de funções inseguras | Detecção de `eval()`, `exec()`, `pickle.loads()`, `os.system()` sem sanitização |
| 48 | Configuração de debug ativa em produção | `DEBUG=True`, `debug: true` em arquivos de configuração |
| 49 | Permissões excessivas de arquivo | Arquivos com permissões `777` ou senhas em arquivos legíveis por todos |
| 50 | Logs com dados sensíveis | Detecção de loging que registra senhas, tokens e PII |
| 51 | Comentários com credenciais | Busca de `TODO: senha`, `# password:`, credenciais em comentários de código |
| 52 | Banco de dados SQLite sem senha | Detecção e análise de arquivos `.db`, `.sqlite` sem criptografia |
| 53 | Certificados autoassinados/expirados | Verificação de validade e autoridade de certificados TLS usados |
| 54 | Uploads sem validação de tipo | Código que aceita upload de arquivos sem whitelist de extensões |
| 55 | Deserialização insegura | Uso de `pickle`, `yaml.load()`, `unserialize()` sem restrições |
| 56 | Race Conditions em operações críticas | Análise de código com operações de arquivo/banco sem locks adequados |
| 57 | Ausência de validação de entrada | Funções que recebem input externo sem sanitização ou validação |
| 58 | Criptografia fraca (MD5/SHA1) | Uso de algoritmos considerados quebrados para senhas ou integridade |
| 59 | Chaves privadas no repositório | Busca de arquivos `.pem`, `.key`, `id_rsa` no projeto |
| 60 | Variáveis de ambiente sensíveis no código | Variáveis lidas de `os.environ` mas com fallback hardcoded inseguro |

---

## 📄 Relatório PDF Gerado Automaticamente

Ao final de cada execução, o CyberDyne gera um **relatório PDF profissional** contendo:

### Estrutura do Relatório

```
📄 CyberDyne Security Report — [data/hora]
├── 📌 Sumário Executivo
│   ├── Total de testes: 60
│   ├── ✅ Aprovados: X
│   ├── ❌ Reprovados: Y
│   └── ⚠️  Avisos: Z
│
├── 📊 Dashboard Visual (gráfico de barras / pizza)
│
├── 🔴 Vulnerabilidades Encontradas (REPROVADO)
│   ├── [Nome da Vulnerabilidade]
│   │   ├── Severidade: CRÍTICA / ALTA / MÉDIA / BAIXA
│   │   ├── Onde foi encontrada: URL / Campo / Arquivo / Linha
│   │   ├── Como foi testado: Payload exato usado, método HTTP, headers
│   │   ├── Por que reprovou: Explicação técnica da falha detectada
│   │   ├── Reprodução Manual: Passo a passo para você reproduzir
│   │   └── Recomendação de correção
│   └── ...
│
├── ✅ Testes que Passaram (APROVADO)
│   ├── [Nome da Vulnerabilidade]
│   │   ├── O que foi testado: Payload e técnica
│   │   └── Resultado: Proteção confirmada
│   └── ...
│
└── 📚 Referências
    ├── OWASP Top 10
    ├── CVE Database
    └── CWE (Common Weakness Enumeration)
```

### Exemplo de Entrada no Relatório

```
❌ REPROVADO — SQL Injection em Parâmetro de Busca

Severidade: CRÍTICA
URL: https://exemplo.com/search?q=
Campo: Parâmetro GET 'q'

Como foi testado:
  → Payload enviado: ' OR '1'='1
  → Método: GET
  → URL completa: https://exemplo.com/search?q=' OR '1'='1

Por que reprovou:
  A aplicação retornou dados de banco de dados não filtrados em resposta
  ao payload injetado, confirmando que o parâmetro 'q' é concatenado
  diretamente em uma query SQL sem uso de Prepared Statements.

Reprodução Manual:
  1. Abra o navegador
  2. Acesse: https://exemplo.com/search?q=' OR '1'='1
  3. Observe que todos os registros do banco são retornados
  4. Tente: ' UNION SELECT username,password FROM users--
  5. Resultado esperado: vazamento de credenciais

Recomendação:
  Utilize Prepared Statements / Parameterized Queries.
  Exemplo em Python: cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
```

---

## 🚀 Como Usar

### Pré-requisitos

```bash
pip install -r requirements.txt
```

### CyberDyneWeb.py — Scanner Web

```bash
python CyberDyneWeb.py
```

O script irá solicitar:
- URL alvo (ex: `https://minha-aplicacao.com`)
- Confirmação de autorização (obrigatória)

### CyberDyne.py — Scanner Local

```bash
python CyberDyne.py
```

O script irá solicitar:
- Caminho do projeto a ser analisado (ex: `C:\projetos\minha-api`)
- Confirmação de autorização (obrigatória)

### Saída

Após a execução, o relatório PDF é salvo automaticamente em:
```
reports/cyberdyne_report_YYYYMMDD_HHMMSS.pdf
```

---

## 📦 Dependências

```
requests          # Requisições HTTP
beautifulsoup4    # Parsing de HTML
fpdf2             # Geração de PDF
colorama          # Terminal colorido
python-dotenv     # Análise de .env
gitpython         # Análise de repositórios Git
packaging         # Verificação de versões de pacotes
pyjwt             # Análise de tokens JWT
dnspython         # Consultas DNS para subdomain takeover
cryptography      # Verificação de certificados TLS
tqdm              # Barra de progresso dos testes
```

Instale tudo de uma vez:

```bash
pip install requests beautifulsoup4 fpdf2 colorama python-dotenv gitpython packaging pyjwt dnspython cryptography tqdm
```

---

## 🧠 Por que o Foco em Vibe Coding?

O **Vibe Coding** — desenvolver software pedindo para uma IA gerar o código completo — é uma revolução de produtividade. Mas IAs generativas têm padrões problemáticos:

| Problema Comum | Exemplo Real |
|---------------|-------------|
| Chaves de API hardcoded | `openai.api_key = "sk-abc123..."` no código |
| Sem validação de input | Formulários que aceitam qualquer valor |
| SQL construído por concatenação | `"SELECT * FROM users WHERE id = " + id` |
| Debug ativo em produção | `app.run(debug=True)` no Flask |
| `.env` não ignorado no `.gitignore` | Credenciais commitadas no GitHub |
| Dependências desatualizadas | Pacotes com CVEs críticos sem atualização |
| Sem autenticação em rotas admin | `/admin/delete-all` sem proteção |
| Logs com dados sensíveis | `print(f"Login: {username} / {password}")` |

O CyberDyne foi projetado para **pegar exatamente esses tipos de falha** — os que surgem naturalmente quando código é gerado por IA sem revisão de segurança.

---

## 🤝 Ética e Responsabilidade

> Este projeto é uma ferramenta de **segurança ofensiva ética**.

Ao executar qualquer um dos scripts, você será solicitado a confirmar que:

1. **Você é o proprietário** da aplicação/sistema alvo, **OU**
2. **Você possui autorização explícita e documentada** do proprietário para realizar os testes

**O uso não autorizado desta ferramenta é crime** em praticamente todas as jurisdições, incluindo o Brasil (Lei 12.737/2012 — Lei Carolina Dieckmann e Marco Civil da Internet).

---

## 📌 Roadmap

- [x] Scanner de vulnerabilidades web (40 testes)
- [x] Scanner de código-fonte local (20 testes)
- [x] Geração de relatório PDF
- [ ] Interface web para visualização de resultados
- [ ] Integração com CVE database em tempo real
- [ ] Modo agendado (cron) para monitoramento contínuo
- [ ] Plugin para VS Code
- [ ] Suporte a autenticação OAuth2/Bearer para testar APIs protegidas
- [ ] Scan de aplicações mobile (APK/IPA)

---

## 📜 Licença

MIT License — Uso livre para fins **éticos e autorizados**.

---

<div align="center">

**CyberDyne** — Construído para proteger o que importa.

*"Segurança não é um produto. É um processo."* — Bruce Schneier

</div>
