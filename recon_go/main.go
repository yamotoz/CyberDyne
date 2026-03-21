// CyberDyne Go Fuzzer — Turbo Fuzzing com 200 goroutines
//
// Uso: cyberdyne-recon <target_url> <payloads_dir> [url1] [url2] ...
//
// - target_url:   URL principal do alvo
// - payloads_dir: caminho da pasta Payloads_CY
// - url1, url2:   URLs extras (live URLs do Python recon)
//
// Output: JSON para stdout | Progress para stderr
//
// Build: go build -o cyberdyne-recon.exe .   (Windows)
//        go build -o cyberdyne-recon .       (Linux/Mac)

package main

import (
	"crypto/md5"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ─── Structures ─────────────────────────────────────────────────────────────

type FuzzResult struct {
	URL    string `json:"url"`
	Status int    `json:"status"`
	Length int    `json:"length"`
}

type FuzzOutput struct {
	Target      string       `json:"target"`
	StartTime   string       `json:"start_time"`
	EndTime     string       `json:"end_time"`
	DurationSec float64      `json:"duration_sec"`
	TotalPaths  int          `json:"total_paths"`
	TotalReqs   int          `json:"total_requests"`
	ReqPerSec   float64      `json:"req_per_sec"`
	Found       []FuzzResult `json:"found"`
	Targets     []string     `json:"targets"`
}

// ─── HTTP Client (otimizado para velocidade) ────────────────────────────────

var httpClient = &http.Client{
	Timeout: 6 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:          500,
		MaxIdleConnsPerHost:   100,
		MaxConnsPerHost:       100,
		IdleConnTimeout:       30 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
		DisableKeepAlives:     false,
	},
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse // Não seguir redirects
	},
}

var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
}
var uaIdx int64

type fuzzResp struct {
	status   int
	bodyLen  int
	bodyHash string
	finalURL string
}

func fuzzRequest(rawURL string) fuzzResp {
	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return fuzzResp{}
	}
	idx := atomic.AddInt64(&uaIdx, 1)
	req.Header.Set("User-Agent", userAgents[int(idx)%len(userAgents)])
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Connection", "keep-alive")

	resp, err := httpClient.Do(req)
	if err != nil {
		return fuzzResp{}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 50*1024)) // 50KB max
	h := md5.Sum(body)
	return fuzzResp{
		status:   resp.StatusCode,
		bodyLen:  len(body),
		bodyHash: fmt.Sprintf("%x", h),
		finalURL: resp.Request.URL.String(),
	}
}

// ─── Payload Loader ────────────────────────────────────────────────────────

func loadPayloadFile(payloadsDir, relativePath string, limit int) []string {
	fullPath := payloadsDir + "/" + relativePath
	data, err := os.ReadFile(fullPath)
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

// ─── Main ───────────────────────────────────────────────────────────────────

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "Uso: cyberdyne-recon <target_url> <payloads_dir> [url1] [url2] ...\n")
		os.Exit(1)
	}

	targetURL := os.Args[1]
	payloadsDir := os.Args[2]

	// Coletar targets (principal + live URLs extras)
	targetSet := map[string]bool{targetURL: true}
	targets := []string{targetURL}
	for _, arg := range os.Args[3:] {
		arg = strings.TrimSpace(arg)
		if arg != "" && !targetSet[arg] {
			targetSet[arg] = true
			targets = append(targets, arg)
		}
	}

	startTime := time.Now()

	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "  ╔══════════════════════════════════════════════════════╗\n")
	fmt.Fprintf(os.Stderr, "  ║        GO TURBO FUZZER — 200 goroutines             ║\n")
	fmt.Fprintf(os.Stderr, "  ╚══════════════════════════════════════════════════════╝\n\n")
	fmt.Fprintf(os.Stderr, "  Alvo: %s\n", targetURL)
	fmt.Fprintf(os.Stderr, "  Targets: %d URLs\n", len(targets))

	// ── Construir lista de paths ────────────────────────────────────────
	pathSet := map[string]bool{}

	// Paths base (hardcoded — sempre testados)
	basePaths := []string{
		"/.env", "/.env.local", "/.env.production", "/.env.backup", "/.env.staging",
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
		"/actuator", "/actuator/health", "/actuator/env", "/actuator/beans",
		"/metrics", "/prometheus", "/health", "/healthz", "/readyz",
		"/api/v1", "/api/v2", "/api/health", "/api/status", "/api/config",
		"/.well-known/openid-configuration", "/oauth/token", "/oauth/authorize",
		"/crossdomain.xml", "/clientaccesspolicy.xml", "/elmah.axd",
		"/wp-content/debug.log", "/error.log", "/errors.log", "/debug.log",
		"/console", "/admin/console", "/manager/html", "/jmx-console",
		"/_profiler", "/_debugbar", "/telescope",
		"/api-docs", "/docs", "/redoc", "/api/docs",
		"/cgi-bin/", "/cgi-bin/test.cgi", "/test", "/test.php",
		"/.aws/credentials", "/.ssh/authorized_keys", "/id_rsa",
		"/wp-json/wp/v2/users", "/wp-json/wp/v2/posts",
		"/.well-known/apple-app-site-association",
		"/feed", "/feed/atom", "/rss",
	}
	for _, p := range basePaths {
		pathSet[p] = true
	}

	// Wordlists do Payloads_CY
	wordlists := []struct {
		path  string
		limit int
	}{
		{"Web-Discovery/Directories/UnixDotfiles.fuzz.txt", 150},
		{"Web-Discovery/Directories/versioning_metafiles.txt", 100},
		{"Web-Discovery/Directories/Common-DB-Backups.txt", 100},
		{"Web-Discovery/Directories/Logins.fuzz.txt", 100},
		{"Web-Discovery/Directories/directory-listing-wordlist.txt", 200},
		{"Web-Discovery/API/api-endpoints.txt", 150},
		{"Web-Discovery/API/api-seen-in-wild.txt", 150},
		{"Web-Discovery/CMS/cms-configuration-files.txt", 100},
		{"Web-Discovery/CMS/wordpress.fuzz.txt", 100},
		{"Web-Discovery/Web-Servers/Apache.txt", 80},
		{"Web-Discovery/Web-Servers/nginx.txt", 80},
		{"Web-Discovery/Web-Servers/IIS.txt", 80},
		{"Fuzzing-General/fuzz-Bo0oM.txt", 200},
	}

	loadedFromFiles := 0
	for _, wl := range wordlists {
		lines := loadPayloadFile(payloadsDir, wl.path, wl.limit)
		for _, line := range lines {
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

	// Build final list
	var paths []string
	for p := range pathSet {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	totalPaths := len(paths)
	totalReqs := totalPaths * len(targets)

	fmt.Fprintf(os.Stderr, "  Paths: %d (%d hardcoded + %d de wordlists)\n", totalPaths, len(basePaths), loadedFromFiles)
	fmt.Fprintf(os.Stderr, "  Requests: %d (%d paths × %d targets)\n", totalReqs, totalPaths, len(targets))
	fmt.Fprintf(os.Stderr, "  Workers: 200 goroutines\n\n")

	// ── Fuzzing com 200 goroutines ──────────────────────────────────────
	var results []FuzzResult
	var mu sync.Mutex
	sem := make(chan struct{}, 200)
	var wg sync.WaitGroup
	var done int64
	fuzzStart := time.Now()

	// ── Baseline Fingerprint (anti-soft-404) ────────────────────────────
	// Captura a "impressão digital" de 2 URLs que sabemos que não existem.
	// Se ambas retornam response similar → site tem catch-all (soft-404).
	// Usa 5 critérios: status, body size, body hash, redirect URL, title.
	type baseline struct {
		status   int
		bodyLen  int
		bodyHash string
		redirect string
	}
	bl1 := fuzzRequest(strings.TrimRight(targetURL, "/") + "/cyberdyne_nonexistent_7f3a9b2e")
	bl2 := fuzzRequest(strings.TrimRight(targetURL, "/") + "/xz_fake_path_404_check_e8c1d2")

	baselineFP := baseline{status: bl1.status, bodyLen: bl1.bodyLen, bodyHash: bl1.bodyHash, redirect: bl1.finalURL}
	isSoft404 := false
	if bl1.status > 0 && bl1.status == bl2.status {
		diff := bl1.bodyLen - bl2.bodyLen
		if diff < 0 { diff = -diff }
		if diff < 500 || bl1.bodyHash == bl2.bodyHash {
			isSoft404 = true
		}
	}
	soft404Count := int64(0)
	if isSoft404 {
		fmt.Fprintf(os.Stderr, "  [Baseline] Soft-%d detectado (hash=%s, %d bytes, redirect=%s)\n",
			baselineFP.status, baselineFP.bodyHash[:8], baselineFP.bodyLen, baselineFP.redirect)
		fmt.Fprintf(os.Stderr, "  [Baseline] Respostas identicas serao filtradas automaticamente\n\n")
	} else {
		fmt.Fprintf(os.Stderr, "\n")
	}

	for _, base := range targets {
		for _, path := range paths {
			wg.Add(1)
			sem <- struct{}{}
			go func(b, p string) {
				defer wg.Done()
				defer func() { <-sem }()

				u := strings.TrimRight(b, "/") + p
				fr := fuzzRequest(u)
				if fr.status == 0 {
					return
				}

				// ── Filtros inteligentes (5 critérios) ──────────────────
				// 1. Ignorar 404, 410 (não existe)
				if fr.status == 404 || fr.status == 410 {
					return
				}
				// 2. Ignorar redirects puros (301/302 para home)
				if fr.status == 301 || fr.status == 302 || fr.status == 307 || fr.status == 308 {
					atomic.AddInt64(&soft404Count, 1)
					return
				}
				// 3. Ignorar respostas muito pequenas (erro genérico)
				if fr.bodyLen < 50 {
					return
				}
				// 4. Hash idêntico ao baseline → soft-404 (mesma página exata)
				if isSoft404 && fr.bodyHash == baselineFP.bodyHash {
					atomic.AddInt64(&soft404Count, 1)
					return
				}
				// 5. Mesmo status + tamanho similar ao baseline → soft-404
				if isSoft404 && fr.status == baselineFP.status {
					diff := fr.bodyLen - baselineFP.bodyLen
					if diff < 0 { diff = -diff }
					if diff < 150 {
						atomic.AddInt64(&soft404Count, 1)
						return
					}
				}
				// 6. Redirect para mesma URL que o baseline → catch-all
				if isSoft404 && baselineFP.redirect != "" && fr.finalURL == baselineFP.redirect {
					atomic.AddInt64(&soft404Count, 1)
					return
				}

				mu.Lock()
				results = append(results, FuzzResult{URL: u, Status: fr.status, Length: fr.bodyLen})
				mu.Unlock()
			}(base, path)

			// Progress a cada 100 requests
			current := atomic.AddInt64(&done, 1)
			if current%100 == 0 || current == int64(totalReqs) {
				elapsed := time.Since(fuzzStart).Seconds()
				if elapsed > 0 {
					rate := float64(current) / elapsed
					remaining := float64(int64(totalReqs)-current) / rate
					pct := float64(current) / float64(totalReqs) * 100
					fmt.Fprintf(os.Stderr, "\r  [FUZZ] %d/%d (%.0f%%) | %d achados | %.0f req/s | ETA: %.0fs   ",
						current, totalReqs, pct, len(results), rate, remaining)
				}
			}
		}
	}
	wg.Wait()

	elapsed := time.Since(fuzzStart).Seconds()
	reqPerSec := float64(totalReqs) / elapsed

	fmt.Fprintf(os.Stderr, "\r%s\r", strings.Repeat(" ", 90))
	fmt.Fprintf(os.Stderr, "\n  ──────────────────────────────────────────────────────\n")
	fmt.Fprintf(os.Stderr, "  [GO FUZZER] Completo em %.1fs\n", elapsed)
	fmt.Fprintf(os.Stderr, "    %d requests | %.0f req/s | %d paths reais encontrados\n", totalReqs, reqPerSec, len(results))
	sc := atomic.LoadInt64(&soft404Count)
	if sc > 0 {
		fmt.Fprintf(os.Stderr, "    %d soft-404 filtrados (baseline fingerprint)\n", sc)
	}
	fmt.Fprintf(os.Stderr, "  ──────────────────────────────────────────────────────\n\n")

	// Sort results by status
	sort.Slice(results, func(i, j int) bool { return results[i].Status < results[j].Status })

	// Output JSON
	output := FuzzOutput{
		Target:      targetURL,
		StartTime:   startTime.Format("2006-01-02T15:04:05"),
		EndTime:     time.Now().Format("2006-01-02T15:04:05"),
		DurationSec: elapsed,
		TotalPaths:  totalPaths,
		TotalReqs:   totalReqs,
		ReqPerSec:   reqPerSec,
		Found:       results,
		Targets:     targets,
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(output)
}
