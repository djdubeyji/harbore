package asset

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"strings"
	"time"

	"harbore.dev/worker/modules"
)

// Module performs network asset discovery:
// - Port scanning via Nmap
// - Service/version detection
// - OS fingerprinting
// - HTTP technology fingerprinting
// - DNS resolution and ASN lookup
type Module struct{}

func New() *Module {
	return &Module{}
}

func (m *Module) Name() string {
	return "asset"
}

func (m *Module) Run(ctx context.Context, job *modules.Job) ([]modules.Finding, error) {
	var findings []modules.Finding

	// Parse target to extract hostname/IP
	host, err := extractHost(job.Target)
	if err != nil {
		return nil, fmt.Errorf("invalid target: %w", err)
	}

	// 1. DNS resolution
	dnsFindings := m.checkDNS(ctx, host, job.Target)
	findings = append(findings, dnsFindings...)

	// 2. Port scan (Nmap if available, fallback to TCP probe)
	portFindings := m.scanPorts(ctx, host, job)
	findings = append(findings, portFindings...)

	// 3. HTTP/S fingerprinting
	httpFindings := m.fingerprintHTTP(ctx, job.Target, job)
	findings = append(findings, httpFindings...)

	// 4. TLS basic check (cert presence, not full analysis — cert module does that)
	tlsFindings := m.checkTLSPresence(ctx, host)
	findings = append(findings, tlsFindings...)

	return findings, nil
}

// ─── DNS resolution ───────────────────────────────────────────────────────────

func (m *Module) checkDNS(ctx context.Context, host, target string) []modules.Finding {
	var findings []modules.Finding

	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, "udp", "8.8.8.8:53")
		},
	}

	// A records
	addrs, err := resolver.LookupHost(ctx, host)
	if err != nil {
		findings = append(findings, modules.Finding{
			Module:      "asset",
			Title:       "DNS resolution failed",
			Description: fmt.Sprintf("Could not resolve %s: %v", host, err),
			Severity:    modules.Info,
			Endpoint:    target,
		})
		return findings
	}

	// Check for private IP exposure
	for _, addr := range addrs {
		if isPrivateIP(addr) {
			findings = append(findings, modules.Finding{
				Module:      "asset",
				Title:       "Private IP address exposed via DNS",
				Description: fmt.Sprintf("Host %s resolves to private IP %s — may indicate misconfigured DNS or internal system exposure", host, addr),
				Severity:    modules.Medium,
				Endpoint:    target,
				OWASPRef:    "A05:2021 - Security Misconfiguration",
				CVSSScore:   modules.CVSSPtr(4.3),
			})
		}
	}

	// Multiple A records (load balancer detection)
	if len(addrs) > 3 {
		findings = append(findings, modules.Finding{
			Module:      "asset",
			Title:       "Multiple DNS A records detected",
			Description: fmt.Sprintf("%s resolves to %d addresses (%s) — likely load-balanced", host, len(addrs), strings.Join(addrs, ", ")),
			Severity:    modules.Info,
			Endpoint:    target,
		})
	}

	// MX record check
	mxs, _ := resolver.LookupMX(ctx, host)
	if len(mxs) > 0 {
		findings = append(findings, modules.Finding{
			Module:      "asset",
			Title:       "MX records found",
			Description: fmt.Sprintf("%s has %d MX record(s) — mail server is co-located with API", host, len(mxs)),
			Severity:    modules.Info,
			Endpoint:    target,
		})
	}

	// TXT records (SPF, DKIM, domain verification)
	txts, _ := resolver.LookupTXT(ctx, host)
	for _, txt := range txts {
		lower := strings.ToLower(txt)
		if strings.Contains(lower, "v=spf1") {
			if strings.Contains(lower, "+all") || strings.Contains(lower, "?all") {
				findings = append(findings, modules.Finding{
					Module:      "asset",
					Title:       "Permissive SPF record",
					Description: fmt.Sprintf("SPF record uses permissive qualifier (+all or ?all): %s", txt),
					Severity:    modules.Medium,
					Endpoint:    host,
					OWASPRef:    "A05:2021 - Security Misconfiguration",
					CVSSScore:   modules.CVSSPtr(5.3),
				})
			}
		}
	}

	return findings
}

// ─── Port scanning ────────────────────────────────────────────────────────────

func (m *Module) scanPorts(ctx context.Context, host string, job *modules.Job) []modules.Finding {
	// Try Nmap first
	nmapFindings, err := m.runNmap(ctx, host, job)
	if err == nil {
		return nmapFindings
	}

	// Fallback: TCP probe common ports
	return m.tcpProbePorts(ctx, host, job.Target)
}

func (m *Module) runNmap(ctx context.Context, host string, job *modules.Job) ([]modules.Finding, error) {
	// Check if nmap is available
	if _, err := exec.LookPath("nmap"); err != nil {
		return nil, fmt.Errorf("nmap not found")
	}

	var findings []modules.Finding

	// Run nmap: service detection + script scan
	args := []string{
		"-sV",               // version detection
		"--version-intensity", "7",
		"-O",                // OS detection
		"--osscan-guess",
		"-sC",               // default scripts
		"--script=banner,http-headers,http-title,ssl-cert",
		"-p", "21,22,23,25,53,80,110,143,443,445,3306,3389,5432,5900,6379,8080,8443,8888,9200,27017",
		"--host-timeout", "90s",
		"-T4",               // aggressive timing
		"--open",            // only show open ports
		host,
	}

	timeoutCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()

	cmd := exec.CommandContext(timeoutCtx, "nmap", args...)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("nmap execution: %w", err)
	}

	output := string(out)

	// Parse nmap output for dangerous services
	dangerousServices := map[string]struct {
		severity modules.Severity
		desc     string
		owasp    string
		cvss     float64
	}{
		"telnet":   {modules.High, "Telnet transmits credentials in plaintext", "A02:2021 - Cryptographic Failures", 7.5},
		"ftp":      {modules.High, "FTP transmits credentials and data in plaintext", "A02:2021 - Cryptographic Failures", 7.5},
		"smtp":     {modules.Medium, "SMTP service detected — check relay configuration", "A05:2021 - Security Misconfiguration", 5.3},
		"vnc":      {modules.High, "VNC remote desktop exposed — high risk if unauthenticated", "A01:2021 - Broken Access Control", 8.8},
		"rdp":      {modules.Medium, "RDP exposed — ensure NLA is enforced and patched", "A05:2021 - Security Misconfiguration", 6.5},
		"mongodb":  {modules.Critical, "MongoDB port exposed — verify authentication is required", "A07:2021 - ID and Auth Failures", 9.8},
		"redis":    {modules.Critical, "Redis port exposed — often unauthenticated by default", "A07:2021 - ID and Auth Failures", 9.8},
		"mysql":    {modules.High, "MySQL port exposed — should not be internet-facing", "A05:2021 - Security Misconfiguration", 7.5},
		"postgres": {modules.High, "PostgreSQL port exposed — should not be internet-facing", "A05:2021 - Security Misconfiguration", 7.5},
		"elasticsearch": {modules.Critical, "Elasticsearch port exposed — often unauthenticated", "A07:2021 - ID and Auth Failures", 9.8},
	}

	for svc, info := range dangerousServices {
		if strings.Contains(strings.ToLower(output), svc) {
			score := info.cvss
			findings = append(findings, modules.Finding{
				Module:      "asset",
				Title:       fmt.Sprintf("Dangerous service exposed: %s", strings.ToUpper(svc)),
				Description: info.desc,
				Severity:    info.severity,
				Endpoint:    host,
				OWASPRef:    info.owasp,
				CVSSScore:   &score,
				Response:    output,
			})
		}
	}

	// Check for SSH version (old versions are vulnerable)
	if strings.Contains(output, "OpenSSH") {
		if strings.Contains(output, "OpenSSH_5.") || strings.Contains(output, "OpenSSH_6.") || strings.Contains(output, "OpenSSH_7.") {
			findings = append(findings, modules.Finding{
				Module:      "asset",
				Title:       "Outdated SSH server detected",
				Description: "An older version of OpenSSH was detected which may be vulnerable to known exploits. Upgrade to OpenSSH 8.x or later.",
				Severity:    modules.Medium,
				Endpoint:    host,
				CVSSScore:   modules.CVSSPtr(5.9),
				CWEID:       "CWE-1104",
				Response:    output,
			})
		}
	}

	// Generic info finding with full Nmap output
	findings = append(findings, modules.Finding{
		Module:      "asset",
		Title:       "Network asset scan completed",
		Description: fmt.Sprintf("Nmap scan of %s completed. Open ports and services discovered.", host),
		Severity:    modules.Info,
		Endpoint:    host,
		Response:    output,
	})

	return findings, nil
}

func (m *Module) tcpProbePorts(ctx context.Context, host, target string) []modules.Finding {
	var findings []modules.Finding

	commonPorts := map[int]string{
		21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
		80: "http", 443: "https", 3306: "mysql", 3389: "rdp",
		5432: "postgres", 6379: "redis", 8080: "http-alt",
		8443: "https-alt", 9200: "elasticsearch", 27017: "mongodb",
	}

	openPorts := []string{}
	for port, service := range commonPorts {
		addr := fmt.Sprintf("%s:%d", host, port)
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err == nil {
			conn.Close()
			openPorts = append(openPorts, fmt.Sprintf("%d/%s", port, service))
		}
	}

	if len(openPorts) > 0 {
		findings = append(findings, modules.Finding{
			Module:      "asset",
			Title:       "Open TCP ports discovered",
			Description: fmt.Sprintf("TCP probe found %d open port(s) on %s: %s", len(openPorts), host, strings.Join(openPorts, ", ")),
			Severity:    modules.Info,
			Endpoint:    target,
		})
	}

	return findings
}

// ─── HTTP fingerprinting ─────────────────────────────────────────────────────

func (m *Module) fingerprintHTTP(ctx context.Context, target string, job *modules.Job) []modules.Finding {
	var findings []modules.Finding

	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return findings
	}

	// Apply auth headers
	for k, v := range job.Auth.Headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("User-Agent", "Harbore-Scanner/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return findings
	}
	defer resp.Body.Close()

	// Server header disclosure
	if server := resp.Header.Get("Server"); server != "" {
		findings = append(findings, modules.Finding{
			Module:      "asset",
			Title:       "Server header discloses technology",
			Description: fmt.Sprintf("The Server response header reveals: %q — this assists attacker reconnaissance", server),
			Severity:    modules.Low,
			Endpoint:    target,
			Method:      "GET",
			OWASPRef:    "A05:2021 - Security Misconfiguration",
			CVSSScore:   modules.CVSSPtr(3.7),
			Response:    fmt.Sprintf("Server: %s", server),
		})
	}

	// X-Powered-By disclosure
	if poweredBy := resp.Header.Get("X-Powered-By"); poweredBy != "" {
		findings = append(findings, modules.Finding{
			Module:      "asset",
			Title:       "X-Powered-By header discloses technology",
			Description: fmt.Sprintf("X-Powered-By reveals: %q — remove this header to reduce fingerprinting surface", poweredBy),
			Severity:    modules.Low,
			Endpoint:    target,
			Method:      "GET",
			OWASPRef:    "A05:2021 - Security Misconfiguration",
			CVSSScore:   modules.CVSSPtr(3.1),
		})
	}

	// Missing security headers
	securityHeaders := map[string]struct {
		description string
		severity    modules.Severity
		cvss        float64
	}{
		"Strict-Transport-Security": {"HSTS header missing — browsers may connect over HTTP", modules.Medium, 6.5},
		"X-Content-Type-Options":    {"X-Content-Type-Options missing — allows MIME sniffing attacks", modules.Low, 4.3},
		"X-Frame-Options":           {"X-Frame-Options missing — page may be vulnerable to clickjacking", modules.Medium, 5.4},
		"Content-Security-Policy":   {"Content-Security-Policy missing — XSS protection weakened", modules.Medium, 6.1},
		"Referrer-Policy":           {"Referrer-Policy missing — sensitive URLs may leak to third parties", modules.Low, 3.7},
		"Permissions-Policy":        {"Permissions-Policy missing — browser feature abuse not restricted", modules.Low, 3.1},
	}

	for header, info := range securityHeaders {
		if resp.Header.Get(header) == "" {
			score := info.cvss
			findings = append(findings, modules.Finding{
				Module:      "asset",
				Title:       fmt.Sprintf("Missing security header: %s", header),
				Description: info.description,
				Severity:    info.severity,
				Endpoint:    target,
				Method:      "GET",
				OWASPRef:    "A05:2021 - Security Misconfiguration",
				CVSSScore:   &score,
				CWEID:       "CWE-693",
			})
		}
	}

	// Check for debug/admin paths
	debugPaths := []string{
		"/debug", "/.env", "/api/debug", "/actuator", "/actuator/health",
		"/actuator/env", "/swagger", "/swagger-ui", "/api-docs",
		"/graphql", "/.git/config", "/phpinfo.php", "/admin",
	}

	for _, path := range debugPaths {
		u, _ := url.Parse(target)
		u.Path = path
		probeReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		probeResp, err := client.Do(probeReq)
		if err != nil {
			continue
		}
		probeResp.Body.Close()

		if probeResp.StatusCode == 200 || probeResp.StatusCode == 403 {
			sev := modules.Medium
			if path == "/.env" || path == "/.git/config" {
				sev = modules.Critical
			}
			findings = append(findings, modules.Finding{
				Module:      "asset",
				Title:       fmt.Sprintf("Sensitive path accessible: %s", path),
				Description: fmt.Sprintf("Path %s returned HTTP %d — verify it does not expose sensitive information", path, probeResp.StatusCode),
				Severity:    sev,
				Endpoint:    u.String(),
				Method:      "GET",
				OWASPRef:    "A05:2021 - Security Misconfiguration",
				CVSSScore:   modules.CVSSPtr(7.5),
				CWEID:       "CWE-538",
			})
		}
	}

	return findings
}

// ─── TLS presence ─────────────────────────────────────────────────────────────

func (m *Module) checkTLSPresence(ctx context.Context, host string) []modules.Finding {
	var findings []modules.Finding

	// Try connecting over HTTP to check if HTTPS redirect exists
	httpClient := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	httpURL := fmt.Sprintf("http://%s", host)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, httpURL, nil)
	if err == nil {
		resp, err := httpClient.Do(req)
		if err == nil {
			defer resp.Body.Close()
			if resp.StatusCode < 300 || resp.StatusCode >= 400 {
				// HTTP is accessible and NOT redirecting to HTTPS
				findings = append(findings, modules.Finding{
					Module:      "asset",
					Title:       "Service accessible over plaintext HTTP",
					Description: fmt.Sprintf("HTTP port 80 is accessible on %s and does not redirect to HTTPS — all traffic is unencrypted", host),
					Severity:    modules.High,
					Endpoint:    httpURL,
					OWASPRef:    "A02:2021 - Cryptographic Failures",
					CVSSScore:   modules.CVSSPtr(7.5),
					CWEID:       "CWE-319",
				})
			}
		}
	}

	return findings
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func extractHost(target string) (string, error) {
	u, err := url.Parse(target)
	if err != nil {
		return "", err
	}
	host := u.Hostname()
	if host == "" {
		// Target might be just a host
		host = target
	}
	return host, nil
}

func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"::1/128",
		"fc00::/7",
	}
	for _, cidr := range privateRanges {
		_, network, _ := net.ParseCIDR(cidr)
		if network != nil && network.Contains(ip) {
			return true
		}
	}
	return false
}
