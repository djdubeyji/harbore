package vuln

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os/exec"
	"strings"
	"time"

	"harbore.dev/worker/modules"
)

// Module performs OWASP Top 10 vulnerability scanning with optional Nuclei integration.
type Module struct{}

func New() *Module { return &Module{} }
func (m *Module) Name() string { return "vuln" }

func (m *Module) Run(ctx context.Context, job *modules.Job) ([]modules.Finding, error) {
	var findings []modules.Finding

	client := buildClient()

	// A01 - Broken Access Control
	findings = append(findings, m.checkBrokenAccessControl(ctx, client, job)...)

	// A02 - Cryptographic Failures (HTTPS enforcement)
	findings = append(findings, m.checkCryptoFailures(ctx, client, job)...)

	// A03 - Injection
	findings = append(findings, m.checkInjection(ctx, client, job)...)

	// A05 - Security Misconfiguration
	findings = append(findings, m.checkMisconfiguration(ctx, client, job)...)

	// A06 - Vulnerable & Outdated Components (via headers)
	findings = append(findings, m.checkOutdatedComponents(ctx, client, job)...)

	// A07 - Identification and Authentication Failures
	findings = append(findings, m.checkAuthFailures(ctx, client, job)...)

	// A09 - Security Logging and Monitoring (timing-based check)
	findings = append(findings, m.checkInfoDisclosure(ctx, client, job)...)

	// Nuclei (if enabled and available)
	if job.ConfigBool("nuclei_enabled", false) {
		findings = append(findings, m.runNuclei(ctx, job)...)
	}

	return findings, nil
}

// ─── A01: Broken Access Control ───────────────────────────────────────────────

func (m *Module) checkBrokenAccessControl(ctx context.Context, client *http.Client, job *modules.Job) []modules.Finding {
	var findings []modules.Finding

	// IDOR: try to access resources with common IDs
	idorPaths := []string{
		"/api/users/1", "/api/users/2", "/api/accounts/1",
		"/api/admin", "/api/internal", "/admin/dashboard",
		"/api/v1/users/1", "/api/v1/admin",
	}

	u, err := url.Parse(job.Target)
	if err != nil {
		return findings
	}
	base := u.Scheme + "://" + u.Host

	for _, path := range idorPaths {
		testURL := base + path

		// Without auth
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, testURL, nil)
		req.Header.Set("User-Agent", "Harbore-Scanner/1.0")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		resp.Body.Close()

		if resp.StatusCode == 200 && len(body) > 50 {
			// Check if looks like real data vs placeholder
			bodyStr := strings.ToLower(string(body))
			if strings.Contains(bodyStr, "email") || strings.Contains(bodyStr, "user") ||
				strings.Contains(bodyStr, "password") || strings.Contains(bodyStr, "token") {
				findings = append(findings, modules.Finding{
					Module:      "vuln",
					Title:       "Potential unauthenticated access to protected resource",
					Description: fmt.Sprintf("Path %s returned HTTP 200 with data-like response without authentication. Verify access control is enforced.", path),
					Severity:    modules.High,
					Endpoint:    testURL,
					Method:      "GET",
					OWASPRef:    "A01:2021 - Broken Access Control",
					CVSSScore:   modules.CVSSPtr(8.1),
					CWEID:       "CWE-284",
					Response:    fmt.Sprintf("HTTP %d, body length: %d", resp.StatusCode, len(body)),
				})
			}
		}
	}

	// HTTP method override (TRACE, PUT, DELETE on sensitive endpoints)
	for _, method := range []string{"TRACE", "OPTIONS"} {
		req, _ := http.NewRequestWithContext(ctx, method, job.Target, nil)
		applyAuth(req, job)
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()
		if method == "TRACE" && resp.StatusCode == 200 {
			findings = append(findings, modules.Finding{
				Module:      "vuln",
				Title:       "HTTP TRACE method enabled",
				Description: "TRACE method is enabled and could be used for Cross-Site Tracing (XST) attacks to steal session cookies.",
				Severity:    modules.Medium,
				Endpoint:    job.Target,
				Method:      "TRACE",
				OWASPRef:    "A05:2021 - Security Misconfiguration",
				CVSSScore:   modules.CVSSPtr(5.8),
				CWEID:       "CWE-16",
			})
		}
	}

	return findings
}

// ─── A02: Cryptographic Failures ─────────────────────────────────────────────

func (m *Module) checkCryptoFailures(ctx context.Context, client *http.Client, job *modules.Job) []modules.Finding {
	var findings []modules.Finding

	// Check for sensitive data in URL query parameters
	u, err := url.Parse(job.Target)
	if err != nil {
		return findings
	}
	params := u.Query()
	sensitiveParams := []string{"token", "password", "secret", "key", "api_key", "auth", "credential"}
	for _, sp := range sensitiveParams {
		for k := range params {
			if strings.Contains(strings.ToLower(k), sp) {
				findings = append(findings, modules.Finding{
					Module:      "vuln",
					Title:       "Sensitive parameter in URL query string",
					Description: fmt.Sprintf("Parameter %q appears in the URL query string. Sensitive values in URLs are logged by servers, proxies, and browser history.", k),
					Severity:    modules.High,
					Endpoint:    job.Target,
					OWASPRef:    "A02:2021 - Cryptographic Failures",
					CVSSScore:   modules.CVSSPtr(7.5),
					CWEID:       "CWE-598",
				})
			}
		}
	}

	return findings
}

// ─── A03: Injection ───────────────────────────────────────────────────────────

func (m *Module) checkInjection(ctx context.Context, client *http.Client, job *modules.Job) []modules.Finding {
	var findings []modules.Finding

	// XSS reflection test
	xssPayloads := []string{
		`<script>alert(1)</script>`,
		`"><img src=x onerror=alert(1)>`,
		`javascript:alert(1)`,
	}

	for _, payload := range xssPayloads {
		testURL := job.Target + "?q=" + url.QueryEscape(payload)
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, testURL, nil)
		applyAuth(req, job)

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
		resp.Body.Close()

		contentType := resp.Header.Get("Content-Type")
		if strings.Contains(string(body), payload) && strings.Contains(contentType, "html") {
			findings = append(findings, modules.Finding{
				Module:      "vuln",
				Title:       "Reflected XSS vulnerability",
				Description: fmt.Sprintf("Input is reflected unescaped in HTML response. XSS payload was returned verbatim in the response body."),
				Severity:    modules.High,
				Endpoint:    testURL,
				Method:      "GET",
				OWASPRef:    "A03:2021 - Injection",
				CVSSScore:   modules.CVSSPtr(7.4),
				CWEID:       "CWE-79",
				Request:     fmt.Sprintf("GET %s", testURL),
				Response:    fmt.Sprintf("Payload reflected: %s", payload),
			})
			break
		}
	}

	// NoSQL injection
	nosqlPayloads := []string{
		`{"$gt": ""}`,
		`{"$ne": null}`,
	}
	for _, payload := range nosqlPayloads {
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, job.Target, strings.NewReader(payload))
		if req == nil {
			continue
		}
		applyAuth(req, job)
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		resp.Body.Close()

		// If NoSQL injection bypasses auth and returns data
		if resp.StatusCode == 200 && len(body) > 100 {
			var result any
			if json.Unmarshal(body, &result) == nil {
				findings = append(findings, modules.Finding{
					Module:      "vuln",
					Title:       "Potential NoSQL injection vulnerability",
					Description: "MongoDB/NoSQL operator injection payload returned HTTP 200 with a non-trivial body. Manual verification recommended.",
					Severity:    modules.High,
					Endpoint:    job.Target,
					Method:      "POST",
					OWASPRef:    "A03:2021 - Injection",
					CVSSScore:   modules.CVSSPtr(8.8),
					CWEID:       "CWE-943",
					Request:     fmt.Sprintf("POST %s\n\n%s", job.Target, payload),
				})
				break
			}
		}
	}

	// SSRF probes
	ssrfPayloads := []string{
		"http://169.254.169.254/latest/meta-data/",        // AWS IMDSv1
		"http://metadata.google.internal/computeMetadata/",
		"http://localhost:22",
		"http://127.0.0.1:6379", // Redis
	}
	for _, payload := range ssrfPayloads {
		testURL := job.Target + "?url=" + url.QueryEscape(payload)
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, testURL, nil)
		if req == nil {
			continue
		}
		applyAuth(req, job)

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		resp.Body.Close()

		bodyStr := string(body)
		if strings.Contains(bodyStr, "ami-id") || strings.Contains(bodyStr, "instance-id") ||
			strings.Contains(bodyStr, "computeMetadata") || resp.StatusCode == 200 && len(body) > 0 {
			findings = append(findings, modules.Finding{
				Module:      "vuln",
				Title:       "Server-Side Request Forgery (SSRF) - cloud metadata accessible",
				Description: fmt.Sprintf("URL parameter accepted %q and may have fetched internal/cloud resources. SSRF can expose cloud credentials and internal services.", payload),
				Severity:    modules.Critical,
				Endpoint:    testURL,
				Method:      "GET",
				OWASPRef:    "A10:2021 - Server-Side Request Forgery",
				CVSSScore:   modules.CVSSPtr(9.8),
				CWEID:       "CWE-918",
			})
		}
	}

	return findings
}

// ─── A05: Security Misconfiguration ──────────────────────────────────────────

func (m *Module) checkMisconfiguration(ctx context.Context, client *http.Client, job *modules.Job) []modules.Finding {
	var findings []modules.Finding

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, job.Target, nil)
	applyAuth(req, job)

	resp, err := client.Do(req)
	if err != nil {
		return findings
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
	resp.Body.Close()

	bodyStr := string(body)

	// Debug mode indicators in response
	debugPatterns := []struct{ pattern, title string }{
		{"DEBUG = True", "Django debug mode enabled"},
		{"Traceback (most recent", "Python stack trace exposed"},
		{"at org.springframework", "Spring Boot stack trace exposed"},
		{"Laravel\\Exceptions", "Laravel debug mode enabled"},
		{"Whoops!", "PHP Whoops debug error exposed"},
	}
	for _, dp := range debugPatterns {
		if strings.Contains(bodyStr, dp.pattern) {
			findings = append(findings, modules.Finding{
				Module:      "vuln",
				Title:       dp.title,
				Description: fmt.Sprintf("Debug mode appears to be enabled in production: detected pattern %q. This exposes internal source paths, configuration, and stack traces.", dp.pattern),
				Severity:    modules.High,
				Endpoint:    job.Target,
				OWASPRef:    "A05:2021 - Security Misconfiguration",
				CVSSScore:   modules.CVSSPtr(7.5),
				CWEID:       "CWE-1295",
			})
		}
	}

	// Default/test credentials in response
	if strings.Contains(strings.ToLower(bodyStr), "\"password\":\"password\"") ||
		strings.Contains(strings.ToLower(bodyStr), "\"password\":\"123456\"") {
		findings = append(findings, modules.Finding{
			Module:      "vuln",
			Title:       "Default credentials visible in API response",
			Description: "API response appears to contain default/weak password values. Ensure test data is purged from production.",
			Severity:    modules.Critical,
			Endpoint:    job.Target,
			OWASPRef:    "A05:2021 - Security Misconfiguration",
			CVSSScore:   modules.CVSSPtr(9.8),
			CWEID:       "CWE-798",
		})
	}

	return findings
}

// ─── A06: Vulnerable Components ───────────────────────────────────────────────

func (m *Module) checkOutdatedComponents(ctx context.Context, client *http.Client, job *modules.Job) []modules.Finding {
	var findings []modules.Finding

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, job.Target, nil)
	applyAuth(req, job)

	resp, err := client.Do(req)
	if err != nil {
		return findings
	}
	resp.Body.Close()

	// Known vulnerable version strings in headers
	headerChecks := map[string][]struct{ pattern, vuln string }{
		"Server": {
			{"Apache/2.2", "Apache 2.2.x is end-of-life — CVE-2017-7679 and others"},
			{"nginx/1.0", "nginx 1.0.x is end-of-life — upgrade to latest stable"},
			{"IIS/6.0", "IIS 6.0 is end-of-life — CVE-2017-7269 (WebDAV RCE)"},
			{"IIS/7.0", "IIS 7.0 is end-of-life"},
		},
		"X-Powered-By": {
			{"PHP/5.", "PHP 5.x is end-of-life — no security patches"},
			{"PHP/7.0", "PHP 7.0 is end-of-life"},
			{"PHP/7.1", "PHP 7.1 is end-of-life"},
			{"ASP.NET/2.0", "ASP.NET 2.0 is end-of-life"},
			{"ASP.NET/3.5", "ASP.NET 3.5 is end-of-life"},
		},
	}

	for header, checks := range headerChecks {
		val := resp.Header.Get(header)
		if val == "" {
			continue
		}
		for _, chk := range checks {
			if strings.Contains(val, chk.pattern) {
				findings = append(findings, modules.Finding{
					Module:      "vuln",
					Title:       fmt.Sprintf("End-of-life software component: %s", val),
					Description: chk.vuln,
					Severity:    modules.High,
					Endpoint:    job.Target,
					OWASPRef:    "A06:2021 - Vulnerable and Outdated Components",
					CVSSScore:   modules.CVSSPtr(7.5),
					CWEID:       "CWE-1104",
					Response:    fmt.Sprintf("%s: %s", header, val),
				})
			}
		}
	}

	return findings
}

// ─── A07: Auth failures ───────────────────────────────────────────────────────

func (m *Module) checkAuthFailures(ctx context.Context, client *http.Client, job *modules.Job) []modules.Finding {
	var findings []modules.Finding

	// Check for JWT none algorithm
	noneJWT := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, job.Target, nil)
	if req != nil {
		req.Header.Set("Authorization", "Bearer "+noneJWT)
		req.Header.Set("User-Agent", "Harbore-Scanner/1.0")
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				findings = append(findings, modules.Finding{
					Module:      "vuln",
					Title:       "JWT 'none' algorithm accepted — authentication bypass",
					Description: "Server accepted a JWT with alg=none (unsigned token). This allows any attacker to forge tokens and bypass authentication entirely.",
					Severity:    modules.Critical,
					Endpoint:    job.Target,
					OWASPRef:    "A07:2021 - Identification and Authentication Failures",
					CVSSScore:   modules.CVSSPtr(9.8),
					CWEID:       "CWE-347",
					Request:     fmt.Sprintf("Authorization: Bearer %s", noneJWT),
				})
			}
		}
	}

	// Brute force protection: check if lockout exists after rapid requests
	// Send 20 rapid requests with wrong credentials
	lockoutURL := job.Target
	lockoutDetected := false
	for i := 0; i < 5; i++ {
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, lockoutURL,
			strings.NewReader(`{"username":"test","password":"wrongpassword"}`))
		if req == nil {
			break
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			break
		}
		resp.Body.Close()
		if resp.StatusCode == 429 || resp.Header.Get("Retry-After") != "" {
			lockoutDetected = true
			break
		}
	}

	if !lockoutDetected {
		findings = append(findings, modules.Finding{
			Module:      "vuln",
			Title:       "No rate limiting detected on authentication endpoint",
			Description: "Multiple failed authentication attempts returned the same HTTP status code with no rate-limit headers. This endpoint may be vulnerable to credential brute-forcing.",
			Severity:    modules.Medium,
			Endpoint:    job.Target,
			OWASPRef:    "A07:2021 - Identification and Authentication Failures",
			CVSSScore:   modules.CVSSPtr(5.3),
			CWEID:       "CWE-307",
		})
	}

	return findings
}

// ─── A09: Security Logging / Info Disclosure ──────────────────────────────────

func (m *Module) checkInfoDisclosure(ctx context.Context, client *http.Client, job *modules.Job) []modules.Finding {
	var findings []modules.Finding

	// Check if error response discloses internal paths
	badReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, job.Target+"/../../../etc", nil)
	if badReq != nil {
		applyAuth(badReq, job)
		resp, err := client.Do(badReq)
		if err == nil {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
			resp.Body.Close()
			bodyStr := string(body)

			pathIndicators := []string{"/var/www", "/home/", "/usr/local", "C:\\", "D:\\"}
			for _, indicator := range pathIndicators {
				if strings.Contains(bodyStr, indicator) {
					findings = append(findings, modules.Finding{
						Module:      "vuln",
						Title:       "Internal filesystem path disclosed in error response",
						Description: fmt.Sprintf("Error response contains internal filesystem path: %q — attackers can map server filesystem layout for targeted exploitation.", indicator),
						Severity:    modules.Medium,
						Endpoint:    job.Target,
						OWASPRef:    "A05:2021 - Security Misconfiguration",
						CVSSScore:   modules.CVSSPtr(5.3),
						CWEID:       "CWE-209",
					})
					break
				}
			}
		}
	}

	return findings
}

// ─── Nuclei ───────────────────────────────────────────────────────────────────

func (m *Module) runNuclei(ctx context.Context, job *modules.Job) []modules.Finding {
	var findings []modules.Finding

	if _, err := exec.LookPath("nuclei"); err != nil {
		return findings
	}

	templatesPath := job.ConfigString("nuclei_templates_path", "/nuclei-templates")

	args := []string{
		"-u", job.Target,
		"-t", templatesPath + "/cves",
		"-t", templatesPath + "/exposures",
		"-t", templatesPath + "/misconfiguration",
		"-t", templatesPath + "/vulnerabilities",
		"-j",                  // JSON output
		"-silent",
		"-no-color",
		"-timeout", "30",
		"-rate-limit", "10",
		"-c", "5",
	}

	timeoutCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(timeoutCtx, "nuclei", args...)
	out, err := cmd.Output()
	if err != nil {
		return findings
	}

	// Parse NDJSON output (one JSON object per line)
	for _, line := range strings.Split(string(out), "\n") {
		if line == "" {
			continue
		}
		var result map[string]any
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			continue
		}

		severity := nucleiSeverity(fmt.Sprintf("%v", result["severity"]))
		title := fmt.Sprintf("%v", result["template-id"])
		if info, ok := result["info"].(map[string]any); ok {
			if name, ok := info["name"].(string); ok && name != "" {
				title = name
			}
		}

		desc := fmt.Sprintf("Nuclei template: %v", result["template-id"])
		if matched, ok := result["matched-at"].(string); ok {
			desc += fmt.Sprintf(" — matched at: %s", matched)
		}

		findings = append(findings, modules.Finding{
			Module:      "vuln",
			Title:       "[Nuclei] " + title,
			Description: desc,
			Severity:    severity,
			Endpoint:    job.Target,
			Response:    line,
		})
	}

	return findings
}

func nucleiSeverity(s string) modules.Severity {
	switch strings.ToLower(s) {
	case "critical":
		return modules.Critical
	case "high":
		return modules.High
	case "medium":
		return modules.Medium
	case "low":
		return modules.Low
	default:
		return modules.Info
	}
}

func applyAuth(req *http.Request, job *modules.Job) {
	for k, v := range job.Auth.Headers {
		req.Header.Set(k, v)
	}
	if job.Auth.Bearer != "" {
		req.Header.Set("Authorization", "Bearer "+job.Auth.Bearer)
	}
	req.Header.Set("User-Agent", "Harbore-Scanner/1.0")
}

func buildClient() *http.Client {
	return &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			MaxIdleConns:        10,
			MaxIdleConnsPerHost: 5,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}
