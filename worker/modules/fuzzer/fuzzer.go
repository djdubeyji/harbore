package fuzzer

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"harbore.dev/worker/modules"
)

// Module performs active fuzzing of API parameters.
type Module struct{}

func New() *Module { return &Module{} }
func (m *Module) Name() string { return "fuzzer" }

func (m *Module) Run(ctx context.Context, job *modules.Job) ([]modules.Finding, error) {
	var findings []modules.Finding
	client := buildClient()

	findings = append(findings, m.fuzzQueryParams(ctx, client, job)...)
	findings = append(findings, m.fuzzPathParams(ctx, client, job)...)
	findings = append(findings, m.fuzzJSONBody(ctx, client, job)...)
	findings = append(findings, m.fuzzHeaders(ctx, client, job)...)
	findings = append(findings, m.checkMassAssignment(ctx, client, job)...)

	return findings, nil
}

// ─── Query parameter fuzzing ──────────────────────────────────────────────────

func (m *Module) fuzzQueryParams(ctx context.Context, client *http.Client, job *modules.Job) []modules.Finding {
	var findings []modules.Finding

	u, err := url.Parse(job.Target)
	if err != nil {
		return findings
	}

	params := u.Query()
	if len(params) == 0 {
		// No query params — inject test ones
		params.Set("id", "1")
		params.Set("q", "test")
	}

	for paramName := range params {
		for _, payload := range getAllPayloads() {
			testURL := *u
			q := testURL.Query()
			q.Set(paramName, payload.value)
			testURL.RawQuery = q.Encode()

			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, testURL.String(), nil)
			if req == nil {
				continue
			}
			applyAuth(req, job)

			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
			resp.Body.Close()
			bodyStr := string(body)

			if finding := checkResponse(job.Target, "GET", paramName, payload, resp.StatusCode, bodyStr); finding != nil {
				findings = append(findings, *finding)
			}
		}
	}

	return findings
}

// ─── Path parameter fuzzing ───────────────────────────────────────────────────

func (m *Module) fuzzPathParams(ctx context.Context, client *http.Client, job *modules.Job) []modules.Finding {
	var findings []modules.Finding

	pathTraversalPayloads := []string{
		"../../../etc/passwd",
		"..%2F..%2F..%2Fetc%2Fpasswd",
		"....//....//....//etc/passwd",
		"%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
		"/etc/passwd",
		"C:\\Windows\\System32\\drivers\\etc\\hosts",
	}

	u, _ := url.Parse(job.Target)
	base := u.Scheme + "://" + u.Host

	for _, payload := range pathTraversalPayloads {
		testURL := base + "/" + payload
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

		if strings.Contains(bodyStr, "root:") || strings.Contains(bodyStr, "bin/bash") ||
			strings.Contains(bodyStr, "[boot loader]") {
			findings = append(findings, modules.Finding{
				Module:      "fuzzer",
				Title:       "Path traversal vulnerability — filesystem read",
				Description: fmt.Sprintf("Path traversal payload %q read server filesystem content: %s", payload, bodyStr[:min(200, len(bodyStr))]),
				Severity:    modules.Critical,
				Endpoint:    testURL,
				Method:      "GET",
				OWASPRef:    "A01:2021 - Broken Access Control",
				CVSSScore:   modules.CVSSPtr(9.1),
				CWEID:       "CWE-22",
				Response:    bodyStr[:min(500, len(bodyStr))],
			})
		}
	}

	return findings
}

// ─── JSON body fuzzing ────────────────────────────────────────────────────────

func (m *Module) fuzzJSONBody(ctx context.Context, client *http.Client, job *modules.Job) []modules.Finding {
	var findings []modules.Finding

	// Type confusion attacks
	typeConfusionPayloads := []struct {
		name    string
		payload any
		desc    string
	}{
		{"array_instead_of_string", []string{"admin", "user"}, "Array instead of string"},
		{"object_instead_of_string", map[string]any{"$gt": ""}, "Object with operator instead of string"},
		{"negative_int", -1, "Negative integer"},
		{"very_large_int", 99999999999, "Integer overflow candidate"},
		{"null_value", nil, "Null value"},
		{"boolean_true", true, "Boolean true instead of string"},
		{"empty_string", "", "Empty string"},
		{"sql_in_json", "' OR '1'='1", "SQL injection in JSON value"},
		{"xss_in_json", `<script>alert(1)</script>`, "XSS in JSON value"},
	}

	// Common field names to fuzz
	fieldNames := []string{"id", "user_id", "role", "email", "username", "password", "token", "data", "input", "query"}

	for _, field := range fieldNames {
		for _, tc := range typeConfusionPayloads {
			payload := map[string]any{field: tc.payload}
			bodyBytes, _ := json.Marshal(payload)

			req, _ := http.NewRequestWithContext(ctx, http.MethodPost, job.Target, bytes.NewReader(bodyBytes))
			if req == nil {
				continue
			}
			applyAuth(req, job)
			req.Header.Set("Content-Type", "application/json")

			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
			resp.Body.Close()
			bodyStr := string(body)

			// Check for error indicators
			errorIndicators := []string{
				"undefined", "NaN", "Infinity",
				"TypeError", "ValueError", "AttributeError",
				"cannot read property", "is not a function",
				"stack overflow", "recursion",
			}

			for _, indicator := range errorIndicators {
				if strings.Contains(strings.ToLower(bodyStr), strings.ToLower(indicator)) {
					findings = append(findings, modules.Finding{
						Module:      "fuzzer",
						Title:       fmt.Sprintf("Type confusion error: field=%s payload=%s", field, tc.name),
						Description: fmt.Sprintf("%s: Sending %q caused a runtime error (%q) — indicates insufficient input validation and potential for type confusion attacks.", tc.desc, field, indicator),
						Severity:    modules.Medium,
						Endpoint:    job.Target,
						Method:      "POST",
						OWASPRef:    "A03:2021 - Injection",
						CVSSScore:   modules.CVSSPtr(5.3),
						CWEID:       "CWE-843",
						Request:     fmt.Sprintf("POST %s\n\n%s", job.Target, string(bodyBytes)),
						Response:    bodyStr[:min(500, len(bodyStr))],
					})
					break
				}
			}
		}
	}

	return findings
}

// ─── Header fuzzing ───────────────────────────────────────────────────────────

func (m *Module) fuzzHeaders(ctx context.Context, client *http.Client, job *modules.Job) []modules.Finding {
	var findings []modules.Finding

	// HTTP request smuggling indicators
	smugglingTests := []struct {
		header string
		value  string
	}{
		{"Transfer-Encoding", "chunked"},
		{"Content-Length", "0"},
		{"Transfer-Encoding", "identity"},
		{"X-Forwarded-Host", "evil.com"},
		{"X-Forwarded-For", "127.0.0.1"},
		{"X-Originating-IP", "127.0.0.1"},
		{"X-Remote-IP", "127.0.0.1"},
		{"X-Remote-Addr", "127.0.0.1"},
		{"X-Client-IP", "127.0.0.1"},
	}

	for _, test := range smugglingTests {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, job.Target, nil)
		if req == nil {
			continue
		}
		applyAuth(req, job)
		req.Header.Set(test.header, test.value)

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		resp.Body.Close()
		bodyStr := string(body)

		// IP spoofing via headers might expose admin functionality
		if test.value == "127.0.0.1" && resp.StatusCode == 200 {
			if strings.Contains(strings.ToLower(bodyStr), "admin") ||
				strings.Contains(strings.ToLower(bodyStr), "internal") {
				findings = append(findings, modules.Finding{
					Module:      "fuzzer",
					Title:       fmt.Sprintf("IP-based access control bypass via %s header", test.header),
					Description: fmt.Sprintf("Setting %s: 127.0.0.1 returned HTTP 200 with content suggesting privileged access. Server may trust client-supplied IP headers for access control.", test.header, test.value),
					Severity:    modules.High,
					Endpoint:    job.Target,
					OWASPRef:    "A01:2021 - Broken Access Control",
					CVSSScore:   modules.CVSSPtr(8.1),
					CWEID:       "CWE-290",
					Request:     fmt.Sprintf("%s: %s", test.header, test.value),
				})
			}
		}
	}

	return findings
}

// ─── Mass assignment ──────────────────────────────────────────────────────────

func (m *Module) checkMassAssignment(ctx context.Context, client *http.Client, job *modules.Job) []modules.Finding {
	var findings []modules.Finding

	// Try to set privileged fields in PUT/PATCH requests
	privilegedPayloads := []map[string]any{
		{"role": "admin"},
		{"is_admin": true},
		{"admin": true},
		{"privilege": "superuser"},
		{"verified": true},
		{"balance": 999999},
		{"credit": 99999},
	}

	for _, methods := range []string{http.MethodPut, http.MethodPatch} {
		for _, payload := range privilegedPayloads {
			bodyBytes, _ := json.Marshal(payload)
			req, _ := http.NewRequestWithContext(ctx, methods, job.Target, bytes.NewReader(bodyBytes))
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
			bodyStr := string(body)

			if resp.StatusCode == 200 || resp.StatusCode == 204 {
				// Check if the privileged field appears in response
				for k, v := range payload {
					valStr := fmt.Sprintf("%v", v)
					if strings.Contains(bodyStr, valStr) {
						findings = append(findings, modules.Finding{
							Module:      "fuzzer",
							Title:       fmt.Sprintf("Mass assignment: privileged field %q accepted", k),
							Description: fmt.Sprintf("%s request accepted field %q=%v and it appears reflected in the response. Mass assignment may allow privilege escalation.", methods, k, v),
							Severity:    modules.High,
							Endpoint:    job.Target,
							Method:      methods,
							OWASPRef:    "A03:2021 - Injection",
							CVSSScore:   modules.CVSSPtr(8.1),
							CWEID:       "CWE-915",
							Request:     fmt.Sprintf("%s %s\n\n%s", methods, job.Target, string(bodyBytes)),
							Response:    bodyStr[:min(500, len(bodyStr))],
						})
						break
					}
				}
			}
		}
	}

	return findings
}

// ─── Payload library ──────────────────────────────────────────────────────────

type fuzzPayload struct {
	name     string
	value    string
	checkFor []string
	title    string
	severity modules.Severity
	owasp    string
	cwe      string
	cvss     float64
}

func getAllPayloads() []fuzzPayload {
	return []fuzzPayload{
		// SQL injection
		{name: "sqli_basic", value: "'", checkFor: []string{"sql syntax", "ora-", "mysql_fetch", "you have an error"}, title: "SQL injection", severity: modules.Critical, owasp: "A03:2021 - Injection", cwe: "CWE-89", cvss: 9.8},
		{name: "sqli_comment", value: "1 OR 1=1--", checkFor: []string{"sql syntax", "syntax error"}, title: "SQL injection (comment bypass)", severity: modules.Critical, owasp: "A03:2021 - Injection", cwe: "CWE-89", cvss: 9.8},
		{name: "sqli_union", value: "1 UNION SELECT NULL,NULL--", checkFor: []string{"sql", "column"}, title: "SQL injection (UNION)", severity: modules.Critical, owasp: "A03:2021 - Injection", cwe: "CWE-89", cvss: 9.8},

		// XSS
		{name: "xss_script", value: `<script>alert(1)</script>`, checkFor: []string{"<script>alert(1)</script>"}, title: "Reflected XSS", severity: modules.High, owasp: "A03:2021 - Injection", cwe: "CWE-79", cvss: 7.4},
		{name: "xss_img", value: `"><img src=x onerror=alert(1)>`, checkFor: []string{"onerror=alert(1)"}, title: "Reflected XSS (img)", severity: modules.High, owasp: "A03:2021 - Injection", cwe: "CWE-79", cvss: 7.4},

		// Command injection
		{name: "cmdi_basic", value: "; id", checkFor: []string{"uid=", "gid=", "root"}, title: "OS command injection", severity: modules.Critical, owasp: "A03:2021 - Injection", cwe: "CWE-78", cvss: 9.8},
		{name: "cmdi_pipe", value: "| whoami", checkFor: []string{"root", "www-data", "nobody"}, title: "OS command injection (pipe)", severity: modules.Critical, owasp: "A03:2021 - Injection", cwe: "CWE-78", cvss: 9.8},

		// Template injection
		{name: "ssti", value: "{{7*7}}", checkFor: []string{"49"}, title: "Server-side template injection", severity: modules.Critical, owasp: "A03:2021 - Injection", cwe: "CWE-94", cvss: 9.8},
		{name: "ssti_jinja", value: "${7*7}", checkFor: []string{"49"}, title: "Server-side template injection (EL)", severity: modules.Critical, owasp: "A03:2021 - Injection", cwe: "CWE-94", cvss: 9.8},

		// Buffer overflow indicators
		{name: "overflow", value: strings.Repeat("A", 10000), checkFor: []string{"500", "error", "exception"}, title: "Input length validation issue", severity: modules.Medium, owasp: "A03:2021 - Injection", cwe: "CWE-120", cvss: 5.3},
	}
}

func checkResponse(endpoint, method, param string, payload fuzzPayload, statusCode int, body string) *modules.Finding {
	bodyLower := strings.ToLower(body)
	for _, check := range payload.checkFor {
		if strings.Contains(bodyLower, strings.ToLower(check)) {
			score := payload.cvss
			return &modules.Finding{
				Module:      "fuzzer",
				Title:       fmt.Sprintf("%s via parameter: %s", payload.title, param),
				Description: fmt.Sprintf("Parameter %q accepted payload %q and error/confirmation pattern %q was detected in response.", param, payload.value, check),
				Severity:    payload.severity,
				Endpoint:    endpoint,
				Method:      method,
				OWASPRef:    payload.owasp,
				CVSSScore:   &score,
				CWEID:       payload.cwe,
				Request:     fmt.Sprintf("%s %s?%s=%s", method, endpoint, param, payload.value),
				Response:    body[:min(500, len(body))],
			}
		}
	}
	return nil
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
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
