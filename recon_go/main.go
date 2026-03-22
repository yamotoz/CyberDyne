// CyberDyne Go Engine v2 — Multi-Module Security Scanner
//
// Módulos ativos quando --go é chamado:
//   • Fuzzing de Paths     — sempre (200 goroutines, anti-soft404, wordlists)
//   • Port Scanner         — --portscan  (500 goroutines, top-280 portas)
//   • URL Validation       — --validate  (500 goroutines, HEAD+GET)
//   • JS Secret Mining     — --jsmine    (200 goroutines, 30 regex patterns)
//   • Takeover Checker     — --takeover  (200 goroutines, DNS + 22 fingerprints)
//   • Parameter Discovery  — --paramdiscovery (200 goroutines, 320 params)
//
// Uso:
//   cyberdyne-recon <target_url> <payloads_dir> [flags] [url1 url2 ...] [sub:domain1 ...]
//
//   Flags: --portscan  --validate  --jsmine  --takeover  --paramdiscovery
//   sub:<domain>  → subdomínio para takeover check
//   (outros args) → URLs para fuzzing, validação e JS mining
//
// Output: JSON unificado em stdout | Progress em stderr
//
// Build:
//   go build -o cyberdyne-recon.exe .   (Windows)
//   go build -o cyberdyne-recon .       (Linux/Mac)

package main

import (
	"crypto/md5"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ─── HTTP Client (otimizado para velocidade) ─────────────────────────────────

var httpClient = &http.Client{
	Timeout: 6 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:          800,
		MaxIdleConnsPerHost:   200,
		MaxConnsPerHost:       200,
		IdleConnTimeout:       30 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
		DisableKeepAlives:     false,
	},
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
}

var uaIdx int64

func nextUA() string {
	idx := atomic.AddInt64(&uaIdx, 1)
	return userAgents[int(idx)%len(userAgents)]
}

func makeRequest(rawURL string) (statusCode int, bodyBytes []byte, finalURL string) {
	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return 0, nil, ""
	}
	req.Header.Set("User-Agent", nextUA())
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Connection", "keep-alive")
	resp, err := httpClient.Do(req)
	if err != nil {
		return 0, nil, ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 100*1024))
	return resp.StatusCode, body, resp.Request.URL.String()
}

// ─── Structures ──────────────────────────────────────────────────────────────

type FuzzResult struct {
	URL    string `json:"url"`
	Status int    `json:"status"`
	Length int    `json:"length"`
}

type PortResult struct {
	Port    int    `json:"port"`
	Service string `json:"service"`
	Banner  string `json:"banner,omitempty"`
}

type URLValidResult struct {
	URL         string `json:"url"`
	Status      int    `json:"status"`
	Length      int    `json:"length"`
	ContentType string `json:"content_type,omitempty"`
	Server      string `json:"server,omitempty"`
}

type JSFinding struct {
	FileURL string   `json:"file_url"`
	Type    string   `json:"type"`
	Matches []string `json:"matches"`
}

type TakeoverResult struct {
	Subdomain   string `json:"subdomain"`
	CNAME       string `json:"cname,omitempty"`
	IPs         string `json:"ips,omitempty"`
	Service     string `json:"service,omitempty"`
	Vulnerable  bool   `json:"vulnerable"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Status      int    `json:"status,omitempty"`
}

type ParamFinding struct {
	URL      string `json:"url"`
	Param    string `json:"param"`
	Evidence string `json:"evidence"`
	Status   int    `json:"status"`
}

type GoOutput struct {
	Target      string `json:"target"`
	StartTime   string `json:"start_time"`
	EndTime     string `json:"end_time"`
	DurationSec float64 `json:"duration_sec"`
	// Fuzzing (original)
	TotalPaths int          `json:"total_paths"`
	TotalReqs  int          `json:"total_requests"`
	ReqPerSec  float64      `json:"req_per_sec"`
	Found      []FuzzResult `json:"found"`
	Targets    []string     `json:"targets"`
	// Novos módulos
	OpenPorts      []PortResult     `json:"open_ports,omitempty"`
	LiveURLs       []URLValidResult `json:"live_urls,omitempty"`
	JSFindings     []JSFinding      `json:"js_findings,omitempty"`
	TakeoverChecks []TakeoverResult `json:"takeover_checks,omitempty"`
	ParamFindings  []ParamFinding   `json:"param_findings,omitempty"`
}

// ─── Payload Loader ──────────────────────────────────────────────────────────

func loadPayloadFile(payloadsDir, relativePath string, limit int) []string {
	data, err := os.ReadFile(payloadsDir + "/" + relativePath)
	if err != nil {
		return nil
	}
	var lines []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	if limit > 0 && len(lines) > limit {
		lines = lines[:limit]
	}
	return lines
}

// ─────────────────────────────────────────────────────────────────────────────
// MÓDULO 1 — FUZZING DE PATHS (original, expandido)
// ─────────────────────────────────────────────────────────────────────────────

type fuzzResp struct {
	status   int
	bodyLen  int
	bodyHash string
	finalURL string
}

func fuzzRequest(rawURL string) fuzzResp {
	status, body, finalURL := makeRequest(rawURL)
	if status == 0 {
		return fuzzResp{}
	}
	h := md5.Sum(body)
	return fuzzResp{
		status:   status,
		bodyLen:  len(body),
		bodyHash: fmt.Sprintf("%x", h),
		finalURL: finalURL,
	}
}

func runFuzzing(targetURL, payloadsDir string, targets []string) ([]FuzzResult, int, int, float64) {
	pathSet := map[string]bool{}

	basePaths := []string{
		"/.env", "/.env.local", "/.env.production", "/.env.backup", "/.env.staging", "/.env.dev",
		"/.git/config", "/.git/HEAD", "/.git/logs/HEAD", "/.svn/entries", "/.svn/wc.db",
		"/config.json", "/config.yml", "/config.yaml", "/appsettings.json", "/appsettings.Development.json",
		"/web.config", "/phpinfo.php", "/info.php", "/admin", "/dashboard", "/login",
		"/panel", "/cpanel", "/phpmyadmin", "/adminer.php", "/wp-admin", "/wp-login.php",
		"/robots.txt", "/sitemap.xml", "/sitemap_index.xml", "/.well-known/security.txt",
		"/api/swagger.json", "/api/openapi.json", "/api/openapi.yaml", "/swagger-ui.html", "/swagger-ui/",
		"/graphql", "/graphiql", "/playground", "/__debug__", "/debug", "/trace",
		"/server-status", "/server-info", "/nginx_status", "/.DS_Store", "/.htaccess", "/.htpasswd",
		"/backup.zip", "/backup.tar.gz", "/backup.sql", "/db.sql", "/dump.sql", "/database.sql",
		"/package.json", "/package-lock.json", "/composer.json", "/composer.lock",
		"/wp-config.php.bak", "/wp-config.php~", "/wp-config.php.old", "/xmlrpc.php",
		"/.dockerenv", "/Dockerfile", "/docker-compose.yml", "/docker-compose.yaml",
		"/actuator", "/actuator/health", "/actuator/env", "/actuator/beans", "/actuator/mappings",
		"/metrics", "/prometheus", "/health", "/healthz", "/readyz", "/livez",
		"/api/v1", "/api/v2", "/api/v3", "/api/health", "/api/status", "/api/config",
		"/.well-known/openid-configuration", "/oauth/token", "/oauth/authorize",
		"/crossdomain.xml", "/clientaccesspolicy.xml", "/elmah.axd",
		"/wp-content/debug.log", "/error.log", "/errors.log", "/debug.log", "/access.log",
		"/console", "/admin/console", "/manager/html", "/jmx-console",
		"/_profiler", "/_debugbar", "/telescope", "/horizon",
		"/api-docs", "/docs", "/redoc", "/api/docs", "/openapi",
		"/cgi-bin/", "/cgi-bin/test.cgi", "/test", "/test.php", "/test.html",
		"/.aws/credentials", "/.ssh/authorized_keys", "/id_rsa", "/.ssh/id_rsa",
		"/wp-json/wp/v2/users", "/wp-json/wp/v2/posts", "/wp-json/",
		"/.well-known/apple-app-site-association",
		"/feed", "/feed/atom", "/rss", "/rss.xml",
		"/admin/login", "/admin/dashboard", "/admin/users", "/admin/config",
		"/_next/static/", "/.nuxt/", "/static/", "/assets/", "/public/",
		"/api/admin", "/api/users", "/api/user", "/api/auth", "/api/login",
		"/socket.io/", "/websocket", "/ws",
		"/.well-known/acme-challenge/", "/sitemap-index.xml",
		"/server.js", "/app.js", "/index.js", "/main.js",
		"/k8s/", "/kubernetes/", "/.kube/config",
		"/terraform.tfstate", "/terraform.tfvars", "/.terraform/",
	}
	for _, p := range basePaths {
		pathSet[p] = true
	}

	wordlists := []struct {
		path  string
		limit int
	}{
		{"Web-Discovery/Directories/UnixDotfiles.fuzz.txt", 200},
		{"Web-Discovery/Directories/versioning_metafiles.txt", 150},
		{"Web-Discovery/Directories/Common-DB-Backups.txt", 150},
		{"Web-Discovery/Directories/Logins.fuzz.txt", 150},
		{"Web-Discovery/Directories/directory-listing-wordlist.txt", 300},
		{"Web-Discovery/API/api-endpoints.txt", 200},
		{"Web-Discovery/API/api-seen-in-wild.txt", 200},
		{"Web-Discovery/CMS/cms-configuration-files.txt", 150},
		{"Web-Discovery/CMS/wordpress.fuzz.txt", 150},
		{"Web-Discovery/Web-Servers/Apache.txt", 100},
		{"Web-Discovery/Web-Servers/nginx.txt", 100},
		{"Web-Discovery/Web-Servers/IIS.txt", 100},
		{"Fuzzing-General/fuzz-Bo0oM.txt", 300},
	}
	loadedFromFiles := 0
	for _, wl := range wordlists {
		for _, line := range loadPayloadFile(payloadsDir, wl.path, wl.limit) {
			p := line
			if !strings.HasPrefix(p, "/") {
				p = "/" + p
			}
			if !pathSet[p] {
				pathSet[p] = true
				loadedFromFiles++
			}
		}
	}

	var paths []string
	for p := range pathSet {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	totalPaths := len(paths)
	totalReqs := totalPaths * len(targets)

	fmt.Fprintf(os.Stderr, "  [FUZZ] %d paths (%d hardcoded + %d wordlists) × %d targets = %d requests\n",
		totalPaths, len(basePaths), loadedFromFiles, len(targets), totalReqs)

	// Baseline anti-soft-404
	type baseline struct{ status, bodyLen int; bodyHash, redirect string }
	bl1 := fuzzRequest(strings.TrimRight(targetURL, "/") + "/cyberdyne_nonexistent_7f3a9b2e")
	bl2 := fuzzRequest(strings.TrimRight(targetURL, "/") + "/xz_fake_path_404_check_e8c1d2")
	baselineFP := baseline{bl1.status, bl1.bodyLen, bl1.bodyHash, bl1.finalURL}
	isSoft404 := bl1.status > 0 && bl1.status == bl2.status && (func() bool {
		diff := bl1.bodyLen - bl2.bodyLen
		if diff < 0 { diff = -diff }
		return diff < 500 || bl1.bodyHash == bl2.bodyHash
	})()
	var soft404Count int64
	if isSoft404 {
		fmt.Fprintf(os.Stderr, "  [FUZZ] Soft-%d detectado — baseline fingerprint ativo\n", baselineFP.status)
	}

	var results []FuzzResult
	var mu sync.Mutex
	sem := make(chan struct{}, 200)
	var wg sync.WaitGroup
	var done int64
	fuzzStart := time.Now()

	for _, base := range targets {
		for _, path := range paths {
			wg.Add(1)
			sem <- struct{}{}
			go func(b, p string) {
				defer wg.Done()
				defer func() { <-sem }()
				u := strings.TrimRight(b, "/") + p
				fr := fuzzRequest(u)
				if fr.status == 0 { return }
				if fr.status == 404 || fr.status == 410 { return }
				if fr.status == 301 || fr.status == 302 || fr.status == 307 || fr.status == 308 {
					atomic.AddInt64(&soft404Count, 1); return
				}
				if fr.bodyLen < 50 { return }
				if isSoft404 && fr.bodyHash == baselineFP.bodyHash { atomic.AddInt64(&soft404Count, 1); return }
				if isSoft404 && fr.status == baselineFP.status {
					diff := fr.bodyLen - baselineFP.bodyLen
					if diff < 0 { diff = -diff }
					if diff < 150 { atomic.AddInt64(&soft404Count, 1); return }
				}
				if isSoft404 && baselineFP.redirect != "" && fr.finalURL == baselineFP.redirect {
					atomic.AddInt64(&soft404Count, 1); return
				}
				mu.Lock()
				results = append(results, FuzzResult{URL: u, Status: fr.status, Length: fr.bodyLen})
				mu.Unlock()
			}(base, path)

			current := atomic.AddInt64(&done, 1)
			if current%100 == 0 || current == int64(totalReqs) {
				elapsed := time.Since(fuzzStart).Seconds()
				if elapsed > 0 {
					rate := float64(current) / elapsed
					remaining := float64(int64(totalReqs)-current) / rate
					pct := float64(current) / float64(totalReqs) * 100
					mu.Lock()
					found := len(results)
					mu.Unlock()
					fmt.Fprintf(os.Stderr, "\r  [FUZZ] %d/%d (%.0f%%) | achados: %d | %.0f req/s | ETA: %.0fs   ",
						current, totalReqs, pct, found, rate, remaining)
				}
			}
		}
	}
	wg.Wait()

	elapsed := time.Since(fuzzStart).Seconds()
	reqPerSec := float64(totalReqs) / elapsed
	fmt.Fprintf(os.Stderr, "\r%s\r", strings.Repeat(" ", 90))
	sc := atomic.LoadInt64(&soft404Count)
	fmt.Fprintf(os.Stderr, "  [FUZZ] Completo: %d paths encontrados | %.0f req/s | %d soft-404 filtrados\n",
		len(results), reqPerSec, sc)

	sort.Slice(results, func(i, j int) bool { return results[i].Status < results[j].Status })
	return results, totalPaths, totalReqs, reqPerSec
}

// ─────────────────────────────────────────────────────────────────────────────
// MÓDULO 2 — PORT SCANNER (substitui Python socket scan, 10-40x mais rápido)
// ─────────────────────────────────────────────────────────────────────────────

var portServices = map[int]string{
	20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
	53: "dns", 80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc",
	137: "netbios-ns", 138: "netbios-dgm", 139: "netbios-ssn", 143: "imap",
	161: "snmp", 162: "snmp-trap", 389: "ldap", 443: "https", 445: "smb",
	465: "smtps", 512: "rexec", 513: "rlogin", 514: "rsh", 587: "smtp-sub",
	593: "msrpc-http", 636: "ldaps", 873: "rsync", 990: "ftps",
	993: "imaps", 995: "pop3s", 1080: "socks", 1099: "rmi",
	1194: "openvpn", 1433: "mssql", 1521: "oracle-db", 1701: "l2tp",
	1723: "pptp", 2049: "nfs", 2181: "zookeeper", 2375: "docker",
	2376: "docker-tls", 2377: "docker-swarm", 2379: "etcd", 2380: "etcd-peer",
	2525: "smtp-alt", 3000: "web-dev", 3001: "web-dev", 3100: "loki",
	3268: "ldap-gc", 3269: "ldaps-gc", 3306: "mysql", 3307: "mysql-alt",
	3389: "rdp", 4000: "web-dev", 4001: "etcd-alt", 4149: "docker-stats",
	4194: "cadvisor", 4200: "angular-dev", 4369: "epmd",
	4443: "https-alt", 4500: "ipsec-nat", 4848: "glassfish",
	5000: "flask-dev", 5001: "web-dev", 5432: "postgresql",
	5601: "kibana", 5671: "amqps", 5672: "amqp",
	5900: "vnc", 5901: "vnc-1", 5984: "couchdb",
	6379: "redis", 6380: "redis-alt", 6443: "kubernetes-api",
	7000: "web-dev", 7001: "weblogic", 7002: "weblogic-ssl",
	7070: "web-dev", 7071: "web-dev", 7443: "https-alt",
	7474: "neo4j-http", 7687: "neo4j-bolt",
	7777: "web-dev", 8000: "http-alt", 8001: "web-dev",
	8008: "http-alt", 8080: "http-proxy", 8081: "http-alt",
	8082: "http-alt", 8083: "http-alt", 8085: "jenkins-alt",
	8086: "influxdb", 8088: "http-alt", 8090: "http-alt",
	8161: "activemq-web", 8181: "web-dev", 8200: "vault",
	8300: "consul-rpc", 8301: "consul-lan", 8302: "consul-wan",
	8400: "consul-client", 8443: "https-alt", 8472: "flannel",
	8500: "consul-http", 8529: "arangodb", 8600: "consul-dns",
	8649: "ganglia", 8686: "activemq-mqtt", 8787: "web-dev",
	8888: "jupyter", 8900: "web-dev", 8983: "solr",
	9000: "php-fpm", 9001: "supervisord", 9042: "cassandra",
	9090: "prometheus", 9091: "prometheus-push", 9092: "kafka",
	9093: "kafka-ssl", 9160: "cassandra-thrift", 9200: "elasticsearch",
	9300: "elasticsearch-transport", 9411: "zipkin",
	9418: "git", 9443: "https-alt", 9999: "web-dev",
	10000: "webmin", 10250: "kubelet", 10255: "kubelet-readonly",
	10256: "kube-proxy", 11211: "memcached", 15672: "rabbitmq-mgmt",
	16379: "redis-cluster", 16443: "microk8s", 16686: "jaeger-ui",
	25672: "rabbitmq-cluster", 27017: "mongodb", 27018: "mongodb-shard",
	28017: "mongodb-http", 50000: "db2-or-jenkins",
}

var topPorts = func() []int {
	ports := make([]int, 0, len(portServices))
	for p := range portServices {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	return ports
}()

func runPortScan(host string) []PortResult {
	fmt.Fprintf(os.Stderr, "  [PORTSCAN] Escaneando %s (%d portas, 500 goroutines)...\n", host, len(topPorts))
	start := time.Now()

	var results []PortResult
	var mu sync.Mutex
	sem := make(chan struct{}, 500)
	var wg sync.WaitGroup
	var done int64

	for _, port := range topPorts {
		wg.Add(1)
		sem <- struct{}{}
		go func(p int) {
			defer wg.Done()
			defer func() { <-sem }()

			addr := net.JoinHostPort(host, fmt.Sprintf("%d", p))
			conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
			if err != nil {
				atomic.AddInt64(&done, 1)
				return
			}
			banner := ""
			// Banner grab rápido para portas HTTP/banner conhecidas
			if p == 80 || p == 8080 || (p >= 8000 && p <= 9999) {
				conn.SetDeadline(time.Now().Add(500 * time.Millisecond))
				conn.Write([]byte("HEAD / HTTP/1.0\r\nHost: " + host + "\r\n\r\n"))
				buf := make([]byte, 256)
				n, _ := conn.Read(buf)
				if n > 0 {
					line := strings.TrimSpace(strings.Split(string(buf[:n]), "\r\n")[0])
					if len(line) > 80 { line = line[:80] }
					banner = line
				}
			} else if p == 22 {
				conn.SetDeadline(time.Now().Add(500 * time.Millisecond))
				buf := make([]byte, 128)
				n, _ := conn.Read(buf)
				if n > 0 {
					line := strings.TrimSpace(string(buf[:n]))
					if len(line) > 60 { line = line[:60] }
					banner = line
				}
			}
			conn.Close()

			service := portServices[p]
			if service == "" {
				service = "unknown"
			}
			mu.Lock()
			results = append(results, PortResult{Port: p, Service: service, Banner: banner})
			mu.Unlock()
			atomic.AddInt64(&done, 1)
		}(port)
	}
	wg.Wait()

	sort.Slice(results, func(i, j int) bool { return results[i].Port < results[j].Port })
	elapsed := time.Since(start).Seconds()
	fmt.Fprintf(os.Stderr, "  [PORTSCAN] %d portas abertas em %.1fs\n", len(results), elapsed)
	for _, r := range results {
		fmt.Fprintf(os.Stderr, "  [PORTSCAN] %s:%d (%s) %s\n", host, r.Port, r.Service, r.Banner)
	}
	return results
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ─────────────────────────────────────────────────────────────────────────────
// MÓDULO 3 — URL VALIDATOR (substitui Python ThreadPoolExecutor 30 threads)
// ─────────────────────────────────────────────────────────────────────────────

func runURLValidation(urls []string) []URLValidResult {
	fmt.Fprintf(os.Stderr, "  [VALIDATE] Validando %d URLs (500 goroutines)...\n", len(urls))
	start := time.Now()

	var results []URLValidResult
	var mu sync.Mutex
	sem := make(chan struct{}, 500)
	var wg sync.WaitGroup
	var done int64

	for _, rawURL := range urls {
		wg.Add(1)
		sem <- struct{}{}
		go func(u string) {
			defer wg.Done()
			defer func() { <-sem }()
			defer atomic.AddInt64(&done, 1)

			// Tentar HEAD primeiro
			req, err := http.NewRequest("HEAD", u, nil)
			if err != nil {
				return
			}
			req.Header.Set("User-Agent", nextUA())
			req.Header.Set("Accept", "*/*")
			resp, err := httpClient.Do(req)
			var status int
			var body []byte
			var contentType, server string
			if err != nil || resp == nil {
				return
			}
			status = resp.StatusCode
			contentType = resp.Header.Get("Content-Type")
			server = resp.Header.Get("Server")
			if server == "" {
				server = resp.Header.Get("X-Powered-By")
			}
			resp.Body.Close()

			// Fallback GET se HEAD retornar 405
			if status == 405 {
				req2, _ := http.NewRequest("GET", u, nil)
				if req2 != nil {
					req2.Header.Set("User-Agent", nextUA())
					resp2, err2 := httpClient.Do(req2)
					if err2 == nil && resp2 != nil {
						status = resp2.StatusCode
						contentType = resp2.Header.Get("Content-Type")
						server = resp2.Header.Get("Server")
						body, _ = io.ReadAll(io.LimitReader(resp2.Body, 10*1024))
						resp2.Body.Close()
					}
				}
			}

			// Só registrar URLs vivas (2xx ou 3xx)
			if status >= 200 && status < 400 {
				mu.Lock()
				results = append(results, URLValidResult{
					URL:         u,
					Status:      status,
					Length:      len(body),
					ContentType: contentType,
					Server:      server,
				})
				mu.Unlock()
			}

			current := atomic.LoadInt64(&done)
			if current%200 == 0 {
				mu.Lock()
				live := len(results)
				mu.Unlock()
				pct := float64(current) / float64(len(urls)) * 100
				fmt.Fprintf(os.Stderr, "\r  [VALIDATE] %d/%d (%.0f%%) | vivas: %d   ",
					current, len(urls), pct, live)
			}
		}(rawURL)
	}
	wg.Wait()

	fmt.Fprintf(os.Stderr, "\r%s\r", strings.Repeat(" ", 80))
	elapsed := time.Since(start).Seconds()
	fmt.Fprintf(os.Stderr, "  [VALIDATE] %d URLs vivas de %d em %.1fs\n", len(results), len(urls), elapsed)
	sort.Slice(results, func(i, j int) bool { return results[i].Status < results[j].Status })
	return results
}

// ─────────────────────────────────────────────────────────────────────────────
// MÓDULO 4 — JS SECRET MINING (LinkFinder-style com 30 regex patterns)
// ─────────────────────────────────────────────────────────────────────────────

type jsPattern struct {
	name    string
	pattern *regexp.Regexp
}

var jsPatterns = []jsPattern{
	{"AWS Access Key", regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{"AWS Secret Key", regexp.MustCompile(`(?i)aws[_\-.]?secret[_\-.]?(?:access)?[_\-.]?key\s*[:=]\s*["']?([a-zA-Z0-9/+]{40})`)},
	{"Google API Key", regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`)},
	{"Google OAuth", regexp.MustCompile(`[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com`)},
	{"Stripe Secret", regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24,}`)},
	{"Stripe Public", regexp.MustCompile(`pk_live_[0-9a-zA-Z]{24,}`)},
	{"GitHub Token", regexp.MustCompile(`gh[pors]_[a-zA-Z0-9]{36}`)},
	{"Slack Token", regexp.MustCompile(`xox[baprs]-[0-9a-zA-Z\-]{10,48}`)},
	{"Slack Webhook", regexp.MustCompile(`https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+`)},
	{"JWT Token", regexp.MustCompile(`eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}`)},
	{"Private Key", regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----`)},
	{"Generic Secret", regexp.MustCompile(`(?i)(?:secret|password|passwd|pwd)\s*[:=]\s*["']([^"'\s]{8,})`)},
	{"Generic API Key", regexp.MustCompile(`(?i)(?:api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*["']([a-zA-Z0-9_\-]{16,})`)},
	{"Generic Token", regexp.MustCompile(`(?i)(?:token|auth[_-]?token|access[_-]?token|bearer)\s*[:=]\s*["']([a-zA-Z0-9_\-.]{16,})`)},
	{"Firebase URL", regexp.MustCompile(`[a-z0-9.-]+-default-rtdb\.firebaseio\.com`)},
	{"Firebase API", regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`)},
	{"Supabase Key", regexp.MustCompile(`(?i)supabase[._-]?(?:anon|service)[._-]?key\s*[:=]\s*["']?([a-zA-Z0-9._-]{80,})`)},
	{"SendGrid Key", regexp.MustCompile(`SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}`)},
	{"Twilio SID", regexp.MustCompile(`AC[a-zA-Z0-9]{32}`)},
	{"Mapbox Token", regexp.MustCompile(`pk\.eyJ1[a-zA-Z0-9_.]+\.eyJ[a-zA-Z0-9_-]+`)},
	{"NPM Token", regexp.MustCompile(`npm_[a-zA-Z0-9]{36}`)},
	{"Internal URL", regexp.MustCompile(`https?://(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)[^\s"']*`)},
	{"API Endpoint", regexp.MustCompile(`["'](/api/v[0-9]+/[a-zA-Z0-9_/\-]+)["']`)},
	{"GraphQL Endpoint", regexp.MustCompile(`["']((?:/graphql|/gql|/__graphql)[a-zA-Z0-9_/\-]*)["']`)},
	{"Cloudinary URL", regexp.MustCompile(`cloudinary://[0-9]+:[a-zA-Z0-9_-]+@[a-zA-Z0-9_-]+`)},
	{"Mailgun Key", regexp.MustCompile(`key-[a-zA-Z0-9]{32}`)},
	{"Heroku API Key", regexp.MustCompile(`[hH]eroku[^"'\s]{0,20}["'\s][0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`)},
	{"Hardcoded Password", regexp.MustCompile(`(?i)(?:password|passwd|pwd)\s*=\s*["']([^"']{6,})["']`)},
	{"Database URL", regexp.MustCompile(`(?i)(?:mysql|postgresql|mongodb|redis|sqlite)://[^"'\s]{10,}`)},
	{"Basic Auth in URL", regexp.MustCompile(`https?://[a-zA-Z0-9_-]+:[a-zA-Z0-9_!@#$%^&*-]+@[a-zA-Z0-9.-]+`)},
}

func runJSMining(urls []string) []JSFinding {
	// Filtrar e coletar URLs de arquivos JS
	jsURLSet := map[string]bool{}
	for _, u := range urls {
		lower := strings.ToLower(u)
		if strings.Contains(lower, ".js") {
			jsURLSet[u] = true
		}
	}
	jsURLs := make([]string, 0, len(jsURLSet))
	for u := range jsURLSet {
		jsURLs = append(jsURLs, u)
	}

	if len(jsURLs) == 0 {
		fmt.Fprintf(os.Stderr, "  [JSMINE] Nenhum arquivo .js encontrado nas URLs\n")
		return nil
	}

	fmt.Fprintf(os.Stderr, "  [JSMINE] Minerando %d arquivos JS (200 goroutines, 30 patterns)...\n", len(jsURLs))
	start := time.Now()

	var results []JSFinding
	var mu sync.Mutex
	sem := make(chan struct{}, 200)
	var wg sync.WaitGroup
	var analyzed int64

	for _, jsURL := range jsURLs {
		wg.Add(1)
		sem <- struct{}{}
		go func(u string) {
			defer wg.Done()
			defer func() { <-sem }()
			defer atomic.AddInt64(&analyzed, 1)

			req, err := http.NewRequest("GET", u, nil)
			if err != nil {
				return
			}
			req.Header.Set("User-Agent", nextUA())
			resp, err := httpClient.Do(req)
			if err != nil || resp == nil {
				return
			}
			defer resp.Body.Close()
			if resp.StatusCode != 200 {
				return
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024)) // 1MB max
			content := string(body)

			// Aplicar todos os patterns
			for _, pat := range jsPatterns {
				matches := pat.pattern.FindAllString(content, 10)
				if len(matches) == 0 {
					continue
				}
				// Dedup matches
				seen := map[string]bool{}
				var unique []string
				for _, m := range matches {
					// Truncar matches muito longos
					if len(m) > 120 {
						m = m[:120] + "..."
					}
					if !seen[m] {
						seen[m] = true
						unique = append(unique, m)
					}
				}
				mu.Lock()
				results = append(results, JSFinding{
					FileURL: u,
					Type:    pat.name,
					Matches: unique,
				})
				mu.Unlock()
			}

			current := atomic.LoadInt64(&analyzed)
			if current%20 == 0 {
				fmt.Fprintf(os.Stderr, "\r  [JSMINE] %d/%d JS analisados...   ", current, len(jsURLs))
			}
		}(jsURL)
	}
	wg.Wait()

	fmt.Fprintf(os.Stderr, "\r%s\r", strings.Repeat(" ", 70))
	elapsed := time.Since(start).Seconds()
	fmt.Fprintf(os.Stderr, "  [JSMINE] %d findings em %d arquivos JS (%.1fs)\n",
		len(results), len(jsURLs), elapsed)
	return results
}

// ─────────────────────────────────────────────────────────────────────────────
// MÓDULO 5 — SUBDOMAIN TAKEOVER CHECKER
// ─────────────────────────────────────────────────────────────────────────────

type takeoverFP struct {
	service   string
	cnames    []string
	bodyMatch string
}

var takeoverFingerprints = []takeoverFP{
	{"GitHub Pages", []string{"github.io", "github.com"}, "There isn't a GitHub Pages site here"},
	{"Heroku", []string{"herokuapp.com", "heroku.com", "herokudns.com"}, "No such app"},
	{"AWS S3", []string{"s3.amazonaws.com", "s3-website"}, "NoSuchBucket"},
	{"Azure", []string{"azurewebsites.net", "azure.com", "cloudapp.azure.com"}, "404 Web Site not found"},
	{"Netlify", []string{"netlify.com", "netlify.app"}, "Not Found - Request ID:"},
	{"Shopify", []string{"myshopify.com"}, "Sorry, this shop is currently unavailable"},
	{"Tumblr", []string{"tumblr.com"}, "There's nothing here"},
	{"Ghost", []string{"ghost.io"}, "The thing you were looking for is no longer here"},
	{"Surge.sh", []string{"surge.sh"}, "project not found"},
	{"Unbounce", []string{"unbouncepages.com"}, "The requested URL was not found"},
	{"Readme.io", []string{"readme.io", "readme.com"}, "Project doesnt exist"},
	{"Statuspage", []string{"statuspage.io"}, "Better luck next time"},
	{"Fastly", []string{"fastly.net"}, "Fastly error: unknown domain"},
	{"Pantheon", []string{"pantheonsite.io"}, "404 error unknown site"},
	{"Fly.io", []string{"fly.dev", "fly.io"}, "404 not found"},
	{"Vercel", []string{"vercel.app", "now.sh"}, "The deployment you are looking for"},
	{"Cargo", []string{"cargocollective.com"}, "If you're moving your domain away from Cargo"},
	{"Webflow", []string{"webflow.io"}, "The page you are looking for doesn't exist"},
	{"HubSpot", []string{"hubspot.net", "hs-sites.com"}, "Domain not configured"},
	{"Squarespace", []string{"squarespace.com"}, "No Such Account"},
	{"GitLab Pages", []string{"gitlab.io"}, "404 Not Found"},
	{"Wix", []string{"wixdns.net", "wix.com"}, "Error ConnectYourDomain"},
}

func runTakeoverCheck(subdomains []string) []TakeoverResult {
	if len(subdomains) == 0 {
		return nil
	}
	fmt.Fprintf(os.Stderr, "  [TAKEOVER] Verificando %d subdomínios (200 goroutines, 22 fingerprints)...\n", len(subdomains))
	start := time.Now()

	var results []TakeoverResult
	var mu sync.Mutex
	sem := make(chan struct{}, 200)
	var wg sync.WaitGroup

	for _, sub := range subdomains {
		wg.Add(1)
		sem <- struct{}{}
		go func(s string) {
			defer wg.Done()
			defer func() { <-sem }()

			result := TakeoverResult{Subdomain: s}

			// DNS CNAME lookup
			cname, err := net.LookupCNAME(s)
			if err == nil && cname != "" {
				result.CNAME = strings.TrimSuffix(cname, ".")
			}

			// IP lookup
			ips, err := net.LookupHost(s)
			if err == nil && len(ips) > 0 {
				result.IPs = strings.Join(ips[:min(3, len(ips))], ", ")
			}

			// Se não resolve → pode ser dangling CNAME
			if result.IPs == "" && result.CNAME != "" {
				result.Vulnerable = true
				result.Fingerprint = "CNAME dangling — domínio CNAME não resolve"
				for _, fp := range takeoverFingerprints {
					for _, cnameMatch := range fp.cnames {
						if strings.Contains(strings.ToLower(result.CNAME), cnameMatch) {
							result.Service = fp.service
							result.Fingerprint = fmt.Sprintf("Dangling CNAME para %s (%s)", fp.service, cnameMatch)
							break
						}
					}
					if result.Service != "" {
						break
					}
				}
				mu.Lock()
				results = append(results, result)
				mu.Unlock()
				return
			}

			// HTTP fingerprint — tentar GET e verificar body
			if result.IPs != "" || result.CNAME != "" {
				for _, scheme := range []string{"https", "http"} {
					testURL := scheme + "://" + s
					status, body, _ := makeRequest(testURL)
					if status == 0 {
						continue
					}
					result.Status = status
					bodyStr := strings.ToLower(string(body))
					// Verificar CNAME contra fingerprints
					for _, fp := range takeoverFingerprints {
						cnameMatch := false
						if result.CNAME != "" {
							for _, c := range fp.cnames {
								if strings.Contains(strings.ToLower(result.CNAME), c) {
									cnameMatch = true
									break
								}
							}
						}
						bodyMatch := fp.bodyMatch != "" && strings.Contains(bodyStr, strings.ToLower(fp.bodyMatch))
						if (cnameMatch && bodyMatch) || (cnameMatch && status == 404) {
							result.Vulnerable = true
							result.Service = fp.service
							result.Fingerprint = fp.bodyMatch
							break
						}
					}
					if result.Vulnerable {
						break
					}
					// Só registra resultados suspeitos (CNAME apontando para serviço externo)
					if result.CNAME != "" {
						for _, fp := range takeoverFingerprints {
							for _, c := range fp.cnames {
								if strings.Contains(strings.ToLower(result.CNAME), c) {
									result.Service = fp.service
									result.Fingerprint = fmt.Sprintf("CNAME → %s (status %d)", fp.service, status)
								}
							}
						}
					}
					break
				}
			}

			if result.Vulnerable || result.Service != "" {
				mu.Lock()
				results = append(results, result)
				mu.Unlock()
			}
		}(sub)
	}
	wg.Wait()

	elapsed := time.Since(start).Seconds()
	vulnCount := 0
	for _, r := range results {
		if r.Vulnerable {
			vulnCount++
		}
	}
	fmt.Fprintf(os.Stderr, "  [TAKEOVER] %d suspeitos, %d vulneráveis em %.1fs\n",
		len(results), vulnCount, elapsed)
	for _, r := range results {
		if r.Vulnerable {
			fmt.Fprintf(os.Stderr, "  [TAKEOVER] ⚠ %s → %s (%s)\n", r.Subdomain, r.Service, r.Fingerprint)
		}
	}
	return results
}

// ─────────────────────────────────────────────────────────────────────────────
// MÓDULO 6 — PARAMETER DISCOVERY
// ─────────────────────────────────────────────────────────────────────────────

var paramList = []string{
	// Identifiers
	"id", "user", "username", "uid", "userid", "user_id", "account", "account_id",
	"email", "name", "first_name", "last_name", "fname", "lname", "fullname",
	// File/path
	"file", "path", "dir", "directory", "folder", "filename", "filepath",
	"include", "load", "read", "require", "template", "view", "layout",
	"document", "doc", "page", "pdf", "img", "image", "photo", "src", "source",
	// URL/redirect
	"url", "link", "href", "redirect", "return", "returnUrl", "return_url",
	"next", "goto", "destination", "dest", "redir", "ref", "referer", "continue",
	"callback", "callbackUrl", "callback_url", "forward", "target",
	// Search/filter
	"q", "query", "search", "s", "keyword", "keywords", "term", "terms",
	"filter", "sort", "order", "orderby", "order_by", "sortby", "sort_by",
	"category", "cat", "tag", "tags", "type", "format", "status", "state",
	// Auth/security
	"token", "key", "api_key", "apikey", "auth", "auth_token", "access_token",
	"secret", "password", "pass", "passwd", "pwd", "hash",
	"session", "session_id", "sessionid", "sid", "csrf", "csrf_token",
	"code", "otp", "pin", "verification_code", "confirm", "nonce",
	// Action/method
	"action", "method", "cmd", "command", "exec", "execute", "run",
	"op", "operation", "do", "task", "func", "function", "mode", "handler",
	// Data/content
	"data", "content", "body", "message", "text", "value", "val",
	"input", "output", "param", "parameter", "payload", "xml", "json",
	// API/version
	"version", "v", "api_version", "ver", "release",
	"lang", "language", "locale", "region", "country",
	// Date/time
	"date", "time", "from", "to", "start", "end", "since", "until",
	// Pagination
	"limit", "offset", "skip", "count", "per_page", "perpage", "size", "p", "pg",
	// Admin/role
	"admin", "role", "permission", "access", "level", "group", "privilege",
	// Injection-prone
	"debug", "test", "dev", "verbose", "trace", "log", "config", "settings",
	"host", "domain", "site", "port", "ip", "proxy", "endpoint",
	"xml", "json", "csv", "format", "output", "ext", "extension",
	// Legacy/PHP/Java
	"PHPSESSID", "jsessionid", "ASP.NET_SessionId", "viewstate",
	// Cloud/API
	"bucket", "key_id", "region", "tenant", "org", "workspace", "project",
}

func runParamDiscovery(fuzzResults []FuzzResult, targetURL string) []ParamFinding {
	// Selecionar paths interessantes dos resultados do fuzzing
	var candidateURLs []string
	seen := map[string]bool{}
	for _, r := range fuzzResults {
		if r.Status == 200 || r.Status == 302 || r.Status == 301 {
			u := r.URL
			if !seen[u] {
				seen[u] = true
				candidateURLs = append(candidateURLs, u)
			}
			if len(candidateURLs) >= 50 {
				break
			}
		}
	}
	// Sempre incluir o target principal
	if !seen[targetURL] {
		candidateURLs = append([]string{targetURL}, candidateURLs...)
	}

	if len(candidateURLs) == 0 {
		return nil
	}

	totalTests := len(candidateURLs) * len(paramList)
	fmt.Fprintf(os.Stderr, "  [PARAMDISCOVERY] %d URLs × %d params = %d testes (200 goroutines)...\n",
		len(candidateURLs), len(paramList), totalTests)
	start := time.Now()

	// Baseline por URL
	type urlBaseline struct{ status int; bodyLen int; bodyHash string }
	baselineMap := map[string]urlBaseline{}
	var blMu sync.Mutex
	var blWg sync.WaitGroup
	blSem := make(chan struct{}, 50)

	for _, u := range candidateURLs {
		blWg.Add(1)
		blSem <- struct{}{}
		go func(url string) {
			defer blWg.Done()
			defer func() { <-blSem }()
			status, body, _ := makeRequest(url)
			h := md5.Sum(body)
			blMu.Lock()
			baselineMap[url] = urlBaseline{status, len(body), fmt.Sprintf("%x", h)}
			blMu.Unlock()
		}(u)
	}
	blWg.Wait()

	var results []ParamFinding
	var mu sync.Mutex
	sem := make(chan struct{}, 200)
	var wg sync.WaitGroup
	var done int64

	testVal := "cyberdyne7749"

	for _, baseURL := range candidateURLs {
		bl, ok := baselineMap[baseURL]
		if !ok {
			continue
		}
		for _, param := range paramList {
			wg.Add(1)
			sem <- struct{}{}
			go func(burl, p string, b urlBaseline) {
				defer wg.Done()
				defer func() { <-sem }()
				defer atomic.AddInt64(&done, 1)

				sep := "?"
				if strings.Contains(burl, "?") {
					sep = "&"
				}
				testURL := burl + sep + p + "=" + testVal

				status, body, _ := makeRequest(testURL)
				if status == 0 {
					return
				}
				bodyStr := string(body)
				h := md5.Sum(body)
				bodyHash := fmt.Sprintf("%x", h)

				var evidence string
				// 1. Parâmetro refletido na resposta
				if strings.Contains(bodyStr, testVal) {
					evidence = fmt.Sprintf("Parâmetro '%s' refletido na resposta (reflection)", p)
				}
				// 2. Status code diferente do baseline
				if status != b.status && status != 404 && b.status != 0 {
					evidence = fmt.Sprintf("Status mudou: baseline=%d → com param=%d", b.status, status)
				}
				// 3. Tamanho de resposta significativamente diferente
				diff := len(body) - b.bodyLen
				if diff < 0 { diff = -diff }
				if diff > 500 && bodyHash != b.bodyHash {
					if evidence == "" {
						evidence = fmt.Sprintf("Resposta diferente: baseline=%d bytes → com param=%d bytes (Δ%d)", b.bodyLen, len(body), diff)
					}
				}
				// 4. Erro de aplicação com o param (SQL, path, etc)
				if evidence == "" {
					lowerBody := strings.ToLower(bodyStr)
					for _, errSig := range []string{"sql syntax", "mysql error", "warning: ", "fatal error",
						"undefined variable", "no such file", "stack trace", "exception"} {
						if strings.Contains(lowerBody, errSig) {
							evidence = fmt.Sprintf("Erro de aplicação com param '%s': '%s'", p, errSig)
							break
						}
					}
				}

				if evidence != "" {
					mu.Lock()
					results = append(results, ParamFinding{
						URL:      burl,
						Param:    p,
						Evidence: evidence,
						Status:   status,
					})
					mu.Unlock()
				}

				current := atomic.LoadInt64(&done)
				if current%500 == 0 {
					pct := float64(current) / float64(totalTests) * 100
					mu.Lock()
					found := len(results)
					mu.Unlock()
					fmt.Fprintf(os.Stderr, "\r  [PARAMDISCOVERY] %d/%d (%.0f%%) | encontrados: %d   ",
						current, totalTests, pct, found)
				}
			}(baseURL, param, bl)
		}
	}
	wg.Wait()

	fmt.Fprintf(os.Stderr, "\r%s\r", strings.Repeat(" ", 80))
	elapsed := time.Since(start).Seconds()
	fmt.Fprintf(os.Stderr, "  [PARAMDISCOVERY] %d parâmetros interessantes em %.1fs\n", len(results), elapsed)
	return results
}

// ─────────────────────────────────────────────────────────────────────────────
// MAIN
// ─────────────────────────────────────────────────────────────────────────────

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "Uso: cyberdyne-recon <target_url> <payloads_dir> [--flags] [url1 url2 ...] [sub:domain1 ...]\n")
		fmt.Fprintf(os.Stderr, "Flags: --portscan --validate --jsmine --takeover --paramdiscovery\n")
		os.Exit(1)
	}

	targetURL := os.Args[1]
	payloadsDir := os.Args[2]

	// Parse args: flags, URLs e subdomínios
	var (
		doPortScan       bool
		doValidate       bool
		doJSMine         bool
		doTakeover       bool
		doParamDiscovery bool
	)
	targetSet := map[string]bool{targetURL: true}
	targets := []string{targetURL}
	var allURLs []string
	var subdomains []string

	for _, arg := range os.Args[3:] {
		arg = strings.TrimSpace(arg)
		if arg == "" {
			continue
		}
		switch arg {
		case "--portscan":
			doPortScan = true
		case "--validate":
			doValidate = true
		case "--jsmine":
			doJSMine = true
		case "--takeover":
			doTakeover = true
		case "--paramdiscovery":
			doParamDiscovery = true
		default:
			if strings.HasPrefix(arg, "sub:") {
				sub := strings.TrimPrefix(arg, "sub:")
				if sub != "" {
					subdomains = append(subdomains, sub)
				}
			} else if strings.HasPrefix(arg, "http://") || strings.HasPrefix(arg, "https://") {
				allURLs = append(allURLs, arg)
				if !targetSet[arg] {
					targetSet[arg] = true
					targets = append(targets, arg)
				}
			}
		}
	}

	startTime := time.Now()

	// ── Header ──────────────────────────────────────────────────────────────
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "  ╔══════════════════════════════════════════════════════════╗\n")
	fmt.Fprintf(os.Stderr, "  ║         CyberDyne Go Engine v2 — Multi-Module           ║\n")
	fmt.Fprintf(os.Stderr, "  ╚══════════════════════════════════════════════════════════╝\n\n")
	fmt.Fprintf(os.Stderr, "  Alvo:       %s\n", targetURL)
	fmt.Fprintf(os.Stderr, "  URLs:       %d | Subdomínios: %d\n", len(allURLs), len(subdomains))
	modules := []string{"Fuzzing"}
	if doPortScan        { modules = append(modules, "PortScan") }
	if doValidate        { modules = append(modules, "URLValidation") }
	if doJSMine          { modules = append(modules, "JSMining") }
	if doTakeover        { modules = append(modules, "TakeoverCheck") }
	if doParamDiscovery  { modules = append(modules, "ParamDiscovery") }
	fmt.Fprintf(os.Stderr, "  Módulos:    %s\n\n", strings.Join(modules, " • "))

	// ── Extrair hostname para port scan ─────────────────────────────────────
	var targetHost string
	if strings.Contains(targetURL, "://") {
		parts := strings.SplitN(strings.SplitN(targetURL, "://", 2)[1], "/", 2)
		targetHost = strings.Split(parts[0], ":")[0]
	}

	// ── Executar módulos em paralelo onde possível ───────────────────────────
	// Stage 1: Port Scan + URL Validation (independentes)
	var openPorts []PortResult
	var liveURLs []URLValidResult
	var stage1WG sync.WaitGroup

	if doPortScan && targetHost != "" {
		stage1WG.Add(1)
		go func() {
			defer stage1WG.Done()
			openPorts = runPortScan(targetHost)
		}()
	}

	if doValidate && len(allURLs) > 0 {
		stage1WG.Add(1)
		go func() {
			defer stage1WG.Done()
			liveURLs = runURLValidation(allURLs)
		}()
	}

	stage1WG.Wait()

	// Usar URLs validadas como targets de fuzzing (se disponíveis)
	fuzzTargets := targets
	if doValidate && len(liveURLs) > 0 {
		// Pegar bases únicas das URLs vivas para fuzzing
		baseSet := map[string]bool{targetURL: true}
		for _, lu := range liveURLs {
			// Extrair base URL (scheme + host)
			if strings.Contains(lu.URL, "://") {
				parts := strings.SplitN(lu.URL, "://", 2)
				hostPart := strings.SplitN(parts[1], "/", 2)[0]
				base := parts[0] + "://" + hostPart
				if !baseSet[base] {
					baseSet[base] = true
					fuzzTargets = append(fuzzTargets, base)
				}
			}
		}
	}

	// Stage 2: Fuzzing + Takeover Check (independentes)
	var fuzzResults []FuzzResult
	var totalPaths, totalReqs int
	var reqPerSec float64
	var takeoverResults []TakeoverResult
	var stage2WG sync.WaitGroup

	stage2WG.Add(1)
	go func() {
		defer stage2WG.Done()
		fuzzResults, totalPaths, totalReqs, reqPerSec = runFuzzing(targetURL, payloadsDir, fuzzTargets)
	}()

	if doTakeover && len(subdomains) > 0 {
		stage2WG.Add(1)
		go func() {
			defer stage2WG.Done()
			takeoverResults = runTakeoverCheck(subdomains)
		}()
	}

	stage2WG.Wait()

	// Stage 3: JS Mining + Param Discovery (dependem de resultados anteriores)
	var jsFindings []JSFinding
	var paramFindings []ParamFinding
	var stage3WG sync.WaitGroup

	if doJSMine {
		// URLs para JS mining: validated live URLs + original URLs
		jsSourceURLs := allURLs
		if len(liveURLs) > 0 {
			for _, lu := range liveURLs {
				jsSourceURLs = append(jsSourceURLs, lu.URL)
			}
		}
		stage3WG.Add(1)
		go func() {
			defer stage3WG.Done()
			jsFindings = runJSMining(jsSourceURLs)
		}()
	}

	if doParamDiscovery {
		stage3WG.Add(1)
		go func() {
			defer stage3WG.Done()
			paramFindings = runParamDiscovery(fuzzResults, targetURL)
		}()
	}

	stage3WG.Wait()

	// ── Output JSON ──────────────────────────────────────────────────────────
	endTime := time.Now()
	elapsed := endTime.Sub(startTime).Seconds()

	output := GoOutput{
		Target:         targetURL,
		StartTime:      startTime.Format("2006-01-02T15:04:05"),
		EndTime:        endTime.Format("2006-01-02T15:04:05"),
		DurationSec:    elapsed,
		TotalPaths:     totalPaths,
		TotalReqs:      totalReqs,
		ReqPerSec:      reqPerSec,
		Found:          fuzzResults,
		Targets:        fuzzTargets,
		OpenPorts:      openPorts,
		LiveURLs:       liveURLs,
		JSFindings:     jsFindings,
		TakeoverChecks: takeoverResults,
		ParamFindings:  paramFindings,
	}

	// Resumo final
	fmt.Fprintf(os.Stderr, "\n  ══════════════════════════════════════════════════════════\n")
	fmt.Fprintf(os.Stderr, "  GO ENGINE v2 — Concluído em %.1fs\n", elapsed)
	fmt.Fprintf(os.Stderr, "    Fuzzing:    %d paths encontrados (%d req, %.0f req/s)\n", len(fuzzResults), totalReqs, reqPerSec)
	if doPortScan    { fmt.Fprintf(os.Stderr, "    PortScan:   %d portas abertas\n", len(openPorts)) }
	if doValidate    { fmt.Fprintf(os.Stderr, "    URLValid:   %d URLs vivas\n", len(liveURLs)) }
	if doJSMine      { fmt.Fprintf(os.Stderr, "    JSMining:   %d findings\n", len(jsFindings)) }
	if doTakeover    {
		vuln := 0
		for _, t := range takeoverResults { if t.Vulnerable { vuln++ } }
		fmt.Fprintf(os.Stderr, "    Takeover:   %d suspeitos (%d vulneráveis)\n", len(takeoverResults), vuln)
	}
	if doParamDiscovery { fmt.Fprintf(os.Stderr, "    ParamDisc:  %d parâmetros encontrados\n", len(paramFindings)) }
	fmt.Fprintf(os.Stderr, "  ══════════════════════════════════════════════════════════\n\n")

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(output)
}
