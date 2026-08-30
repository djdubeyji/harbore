package pci

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"harbore.dev/worker/modules"
)

// Module performs PCI DSS v4.0 compliance scanning.
// Maps every finding directly to a PCI DSS requirement number.
type Module struct{}

func New() *Module { return &Module{} }
func (m *Module) Name() string { return "pci" }

// PCI DSS requirement categories we check
const (
	Req4_2_1  = "Req 4.2.1 - Strong cryptography in transit"
	Req6_2_4  = "Req 6.2.4 - Injection attack prevention"
	Req6_3_2  = "Req 6.3.2 - Inventory of bespoke software"
	Req6_4_1  = "Req 6.4.1 - Web-facing app protection"
	Req6_4_2  = "Req 6.4.2 - Automated technical solution for web apps"
	Req7_2_1  = "Req 7.2.1 - Access control model"
	Req8_2_1  = "Req 8.2.1 - All user IDs uniquely identified"
	Req8_3_6  = "Req 8.3.6 - Minimum password complexity"
	Req10_3_3 = "Req 10.3.3 - Audit log protection"
	Req12_3_1 = "Req 12.3.1 - Targeted risk analysis for each requirement"
)

// Regexes for cardholder data detection
var (
	// PAN patterns (Visa, MC, Amex, Discover)
	panPatterns = []*regexp.Regexp{
		regexp.MustCompile(`\b4[0-9]{12}(?:[0-9]{3})?\b`),                     // Visa
		regexp.MustCompile(`\b5[1-5][0-9]{14}\b`),                              // Mastercard
		regexp.MustCompile(`\b3[47][0-9]{13}\b`),                               // Amex
		regexp.MustCompile(`\b6(?:011|5[0-9]{2})[0-9]{12}\b`),                  // Discover
		regexp.MustCompile(`\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14})\b`), // Generic
	}

	// CVV/CVC patterns
	cvvPattern = regexp.MustCompile(`(?i)(?:cvv|cvc|cvv2|cvc2|cid)[\s:="']+\d{3,4}\b`)

	// Expiry date patterns
	expiryPattern = regexp.MustCompile(`(?i)(?:exp|expiry|expiration)[\s:="']+(?:0[1-9]|1[0-2])[\s/\\-]+(?:20)?[0-9]{2}`)

	// Track data patterns
	trackPattern = regexp.MustCompile(`%B[0-9]{13,19}\^[A-Z/\s]{2,26}\^[0-9]{4}`)

	// Sensitive field names in JSON
	sensitiveFields = []string{
		"card_number", "pan", "credit_card", "cc_number",
		"cvv", "cvc", "cvv2", "security_code",
		"card_expiry", "expiry_date", "exp_date",
		"track_data", "track1", "track2",
		"card_holder", "cardholder_name",
	}
)

func (m *Module) Run(ctx context.Context, job *modules.Job) ([]modules.Finding, error) {
	var findings []modules.Finding

	client := buildHTTPClient()

	// 1. Check TLS/encryption requirements (Req 4.2.1)
	tlsFindings := m.checkEncryption(ctx, client, job)
	findings = append(findings, tlsFindings...)

	// 2. Scan response bodies for cardholder data exposure (Req 3.x)
	panFindings := m.checkCardholderDataExposure(ctx, client, job)
	findings = append(findings, panFindings...)

	// 3. Injection vulnerability checks (Req 6.2.4)
	injectionFindings := m.checkInjection(ctx, client, job)
	findings = append(findings, injectionFindings...)

	// 4. Authentication strength checks (Req 8.x)
	authFindings := m.checkAuthentication(ctx, client, job)
	findings = append(findings, authFindings...)

	// 5. Error handling and information disclosure (Req 6.x)
	errorFindings := m.checkErrorHandling(ctx, client, job)
	findings = append(findings, errorFindings...)

	// 6. Security headers for CDE (Req 6.4.1)
	headerFindings := m.checkSecurityHeaders(ctx, client, job)
	findings = append(findings, headerFindings...)

	return findings, nil
}

// ─── 1. Encryption checks (PCI DSS Req 4.2.1) ────────────────────────────────

func (m *Module) checkEncryption(ctx context.Context, client *http.Client, job *modules.Job) []modules.Finding {
	var findings []modules.Finding

	// Must use HTTPS
	if strings.HasPrefix(strings.ToLower(job.Target), "http://") {
		findings = append(findings, modules.Finding{
			Module:         "pci",
			Title:          "PCI DSS: Cardholder data transmitted over HTTP",
			Description:    "PCI DSS Req 4.2.1 requires strong cryptography for all CHD transmission. This endpoint is HTTP-only.",
			Severity:       modules.Critical,
			Endpoint:       job.Target,
			OWASPRef:       "A02:2021 - Cryptographic Failures",
			PCIRequirement: Req4_2_1,
			CVSSScore:      modules.CVSSPtr(9.1),
			CWEID:          "CWE-319",
		})
	}

	// Check TLS version via direct connection
	host := extractHostname(job.Target)
	conn, err := tls.Dial("tcp", host+":443", &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
	})
	if err == nil {
		ver := conn.ConnectionState().Version
		conn.Close()
		if ver < tls.VersionTLS12 {
			findings = append(findings, modules.Finding{
				Module:         "pci",
				Title:          "PCI DSS: TLS version below 1.2 detected",
				Description:    "PCI DSS Req 4.2.1 prohibits SSL and early TLS (before TLS 1.2). Immediately disable deprecated protocols.",
				Severity:       modules.Critical,
				Endpoint:       job.Target,
				PCIRequirement: Req4_2_1,
				CVSSScore:      modules.CVSSPtr(9.1),
				CWEID:          "CWE-326",
			})
		}
	}

	return findings
}

// ─── 2. Cardholder data exposure (PCI DSS Req 3.x) ───────────────────────────

func (m *Module) checkCardholderDataExposure(ctx context.Context, client *http.Client, job *modules.Job) []modules.Finding {
	var findings []modules.Finding

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, job.Target, nil)
	if err != nil {
		return findings
	}
	applyAuth(req, job)

	resp, err := client.Do(req)
	if err != nil {
		return findings
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024)) // 2MB limit
	if err != nil {
		return findings
	}
	bodyStr := string(body)

	// Check for PAN in response
	for _, re := range panPatterns {
		if matches := re.FindAllString(bodyStr, -1); len(matches) > 0 {
			// Validate with Luhn
			for _, match := range matches {
				if luhnCheck(match) {
					findings = append(findings, modules.Finding{
						Module:         "pci",
						Title:          "PCI DSS: Primary Account Number (PAN) exposed in API response",
						Description:    fmt.Sprintf("A valid PAN was detected in the API response body. PCI DSS Req 3.3.1 prohibits storing or exposing full PANs. Truncate or tokenize all PANs. Found: %s", maskPAN(match)),
						Severity:       modules.Critical,
						Endpoint:       job.Target,
						Method:         "GET",
						PCIRequirement: "Req 3.3.1 - SAD not retained after authorisation",
						CVSSScore:      modules.CVSSPtr(9.1),
						OWASPRef:       "A02:2021 - Cryptographic Failures",
						CWEID:          "CWE-312",
						Response:       fmt.Sprintf("PAN detected: %s", maskPAN(match)),
					})
					break
				}
			}
		}
	}

	// Check for CVV/CVC in response
	if cvvPattern.MatchString(bodyStr) {
		findings = append(findings, modules.Finding{
			Module:         "pci",
			Title:          "PCI DSS: CVV/CVC data exposed in API response",
			Description:    "CVV/CVC security code detected in response. PCI DSS Req 3.3.2 strictly prohibits storing or transmitting SAD including CVV/CVC after authorisation.",
			Severity:       modules.Critical,
			Endpoint:       job.Target,
			PCIRequirement: "Req 3.3.2 - SAD not stored after authorisation",
			CVSSScore:      modules.CVSSPtr(9.8),
			CWEID:          "CWE-312",
		})
	}

	// Check for track data
	if trackPattern.MatchString(bodyStr) {
		findings = append(findings, modules.Finding{
			Module:         "pci",
			Title:          "PCI DSS: Magnetic stripe track data exposed",
			Description:    "Full magnetic stripe track data detected in API response. This is a critical PCI DSS violation — track data must never be stored or transmitted post-authorisation.",
			Severity:       modules.Critical,
			Endpoint:       job.Target,
			PCIRequirement: "Req 3.3.2 - SAD not stored after authorisation",
			CVSSScore:      modules.CVSSPtr(9.8),
			CWEID:          "CWE-312",
		})
	}

	// Check JSON response for sensitive field names with values
	var jsonBody map[string]any
	if err := json.Unmarshal(body, &jsonBody); err == nil {
		for _, field := range sensitiveFields {
			if val, ok := findNestedField(jsonBody, field); ok && val != "" && val != "null" {
				findings = append(findings, modules.Finding{
					Module:         "pci",
					Title:          fmt.Sprintf("PCI DSS: Sensitive field %q present in response", field),
					Description:    fmt.Sprintf("Response contains field %q with a non-null value. Verify this field does not expose raw CHD — use tokenization or masking.", field),
					Severity:       modules.High,
					Endpoint:       job.Target,
					PCIRequirement: "Req 3.3.1 - SAD not retained after authorisation",
					CVSSScore:      modules.CVSSPtr(7.5),
					CWEID:          "CWE-312",
				})
			}
		}
	}

	return findings
}

// ─── 3. Injection checks (PCI DSS Req 6.2.4) ─────────────────────────────────

func (m *Module) checkInjection(ctx context.Context, client *http.Client, job *modules.Job) []modules.Finding {
	var findings []modules.Finding

	// SQL injection probes
	sqlPayloads := []string{"'", `"`, `' OR '1'='1`, `1;DROP TABLE users--`, `' UNION SELECT NULL--`}

	for _, payload := range sqlPayloads {
		testURL := job.Target + payload
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, testURL, nil)
		if err != nil {
			continue
		}
		applyAuth(req, job)

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
		resp.Body.Close()
		bodyStr := strings.ToLower(string(body))

		// Check for SQL error strings in response
		sqlErrors := []string{
			"sql syntax", "mysql_fetch", "ora-", "postgresql",
			"sqlite_", "syntax error", "unclosed quotation",
			"you have an error in your sql", "warning: mysql",
			"sqlexception", "sqlstate",
		}

		for _, sqlErr := range sqlErrors {
			if strings.Contains(bodyStr, sqlErr) {
				findings = append(findings, modules.Finding{
					Module:         "pci",
					Title:          "PCI DSS: SQL injection vulnerability detected",
					Description:    fmt.Sprintf("SQL error message exposed in response to injection payload %q — strong evidence of SQL injection vulnerability. PCI DSS Req 6.2.4 requires prevention of injection attacks.", payload),
					Severity:       modules.Critical,
					Endpoint:       testURL,
					Method:         "GET",
					PCIRequirement: Req6_2_4,
					CVSSScore:      modules.CVSSPtr(9.8),
					OWASPRef:       "A03:2021 - Injection",
					CWEID:          "CWE-89",
					Request:        fmt.Sprintf("GET %s", testURL),
					Response:       fmt.Sprintf("SQL error detected: %s", sqlErr),
				})
				break
			}
		}
	}

	return findings
}

// ─── 4. Authentication checks (PCI DSS Req 8.x) ──────────────────────────────

func (m *Module) checkAuthentication(ctx context.Context, client *http.Client, job *modules.Job) []modules.Finding {
	var findings []modules.Finding

	// Check for basic auth over HTTP
	if strings.HasPrefix(job.Target, "http://") && job.Auth.Bearer != "" {
		findings = append(findings, modules.Finding{
			Module:         "pci",
			Title:          "PCI DSS: Authentication token sent over HTTP",
			Description:    "Bearer token is being sent over unencrypted HTTP. PCI DSS Req 8.2.1 requires unique IDs and Req 4.2.1 requires encryption of CHD in transit.",
			Severity:       modules.Critical,
			Endpoint:       job.Target,
			PCIRequirement: Req8_2_1,
			CVSSScore:      modules.CVSSPtr(9.1),
			CWEID:          "CWE-523",
		})
	}

	// Check if unauthenticated access works
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, job.Target, nil)
	if err == nil {
		resp, err := client.Do(req)
		if err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == 200 && job.Auth.Bearer != "" {
				findings = append(findings, modules.Finding{
					Module:         "pci",
					Title:          "PCI DSS: Endpoint accessible without authentication",
					Description:    "Endpoint returns HTTP 200 without authentication credentials. PCI DSS Req 7.2.1 requires access control for all system components.",
					Severity:       modules.Critical,
					Endpoint:       job.Target,
					Method:         "GET",
					PCIRequirement: Req7_2_1,
					CVSSScore:      modules.CVSSPtr(9.1),
					OWASPRef:       "A01:2021 - Broken Access Control",
					CWEID:          "CWE-306",
				})
			}
		}
	}

	return findings
}

// ─── 5. Error handling (PCI DSS Req 6.x) ─────────────────────────────────────

func (m *Module) checkErrorHandling(ctx context.Context, client *http.Client, job *modules.Job) []modules.Finding {
	var findings []modules.Finding

	// Send malformed request
	malformedURLs := []string{
		job.Target + "/../../../../etc/passwd",
		job.Target + "?id=<script>alert(1)</script>",
		job.Target + "?param=" + strings.Repeat("A", 10000),
	}

	for _, u := range malformedURLs {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
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

		// Check for stack traces
		stackIndicators := []string{
			"stack trace", "stacktrace", "at com.", "at java.", "at org.",
			"at net.", "Traceback (most recent", "File \"", "line ",
			"panic:", "runtime error", "goroutine ", "NullPointerException",
			"SQLException", "Exception in thread",
		}
		for _, indicator := range stackIndicators {
			if strings.Contains(bodyStr, indicator) {
				findings = append(findings, modules.Finding{
					Module:         "pci",
					Title:          "PCI DSS: Application stack trace exposed in error response",
					Description:    fmt.Sprintf("Error response reveals internal stack trace — exposes technology stack, file paths, and internal logic. PCI DSS Req 6.2.4 requires generic error messages.", indicator),
					Severity:       modules.High,
					Endpoint:       u,
					Method:         "GET",
					PCIRequirement: Req6_2_4,
					CVSSScore:      modules.CVSSPtr(5.3),
					OWASPRef:       "A05:2021 - Security Misconfiguration",
					CWEID:          "CWE-209",
				})
				break
			}
		}
	}

	return findings
}

// ─── 6. Security headers for CDE (PCI DSS Req 6.4.1) ─────────────────────────

func (m *Module) checkSecurityHeaders(ctx context.Context, client *http.Client, job *modules.Job) []modules.Finding {
	var findings []modules.Finding

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, job.Target, nil)
	if err != nil {
		return findings
	}
	applyAuth(req, job)

	resp, err := client.Do(req)
	if err != nil {
		return findings
	}
	defer resp.Body.Close()

	// PCI-critical headers
	pciHeaders := map[string]struct {
		desc string
		req  string
		cvss float64
	}{
		"Strict-Transport-Security": {
			"HSTS missing — browsers may use HTTP in the CDE",
			Req4_2_1,
			6.5,
		},
		"Content-Security-Policy": {
			"CSP missing — XSS attacks in the payment page may capture card data",
			Req6_4_1,
			6.1,
		},
		"X-Frame-Options": {
			"Clickjacking protection missing — payment form may be embedded in malicious iframes",
			Req6_4_1,
			5.4,
		},
	}

	for header, info := range pciHeaders {
		if resp.Header.Get(header) == "" {
			score := info.cvss
			findings = append(findings, modules.Finding{
				Module:         "pci",
				Title:          fmt.Sprintf("PCI DSS: Missing security header: %s", header),
				Description:    info.desc,
				Severity:       modules.Medium,
				Endpoint:       job.Target,
				PCIRequirement: info.req,
				CVSSScore:      &score,
				OWASPRef:       "A05:2021 - Security Misconfiguration",
				CWEID:          "CWE-693",
			})
		}
	}

	return findings
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func luhnCheck(number string) bool {
	number = strings.ReplaceAll(number, " ", "")
	number = strings.ReplaceAll(number, "-", "")
	if len(number) < 13 || len(number) > 19 {
		return false
	}
	sum := 0
	nDigits := len(number)
	parity := nDigits % 2
	for i := 0; i < nDigits; i++ {
		digit := int(number[i] - '0')
		if digit < 0 || digit > 9 {
			return false
		}
		if i%2 == parity {
			digit *= 2
			if digit > 9 {
				digit -= 9
			}
		}
		sum += digit
	}
	return sum%10 == 0
}

func maskPAN(pan string) string {
	if len(pan) < 8 {
		return strings.Repeat("*", len(pan))
	}
	return pan[:6] + strings.Repeat("*", len(pan)-10) + pan[len(pan)-4:]
}

func findNestedField(m map[string]any, field string) (string, bool) {
	for k, v := range m {
		if strings.EqualFold(k, field) {
			return fmt.Sprintf("%v", v), true
		}
		if nested, ok := v.(map[string]any); ok {
			if val, found := findNestedField(nested, field); found {
				return val, true
			}
		}
	}
	return "", false
}

func extractHostname(target string) string {
	if idx := strings.Index(target, "://"); idx >= 0 {
		target = target[idx+3:]
	}
	if idx := strings.Index(target, "/"); idx >= 0 {
		target = target[:idx]
	}
	if idx := strings.Index(target, ":"); idx >= 0 {
		target = target[:idx]
	}
	return target
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

func buildHTTPClient() *http.Client {
	return &http.Client{
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
}
