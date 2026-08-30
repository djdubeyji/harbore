package passive

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"

	"harbore.dev/worker/modules"
)

// Module performs passive analysis of captured traffic (HAR files, imported traffic).
type Module struct{}

func New() *Module { return &Module{} }
func (m *Module) Name() string { return "passive" }

// PII detection patterns
var piiPatterns = map[string]*regexp.Regexp{
	"email":         regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`),
	"phone_us":      regexp.MustCompile(`\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b`),
	"ssn":           regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
	"ipv4":          regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b`),
	"aws_key":       regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	"aws_secret":    regexp.MustCompile(`(?i)aws.{0,20}(?:secret|key).{0,20}['"]\s*:\s*['"][a-zA-Z0-9/+]{40}['"]\s`),
	"jwt_token":     regexp.MustCompile(`eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}`),
	"private_key":   regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----`),
	"github_token":  regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}`),
	"slack_token":   regexp.MustCompile(`xox[baprs]-[a-zA-Z0-9-]+`),
	"google_api":    regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`),
	"stripe_key":    regexp.MustCompile(`sk_(?:live|test)_[a-zA-Z0-9]{24,}`),
	"basic_auth":    regexp.MustCompile(`(?i)authorization:\s*basic\s+[a-zA-Z0-9+/]+=*`),
	"bearer_in_url": regexp.MustCompile(`[?&](?:token|access_token|api_key|apikey|key)=[a-zA-Z0-9_\-\.]{10,}`),
}

// HAR file structure
type HARFile struct {
	Log HARLog `json:"log"`
}
type HARLog struct {
	Entries []HAREntry `json:"entries"`
}
type HAREntry struct {
	Request  HARRequest  `json:"request"`
	Response HARResponse `json:"response"`
}
type HARRequest struct {
	Method  string       `json:"method"`
	URL     string       `json:"url"`
	Headers []HARHeader  `json:"headers"`
	PostData *HARPostData `json:"postData"`
}
type HARResponse struct {
	Status  int         `json:"status"`
	Headers []HARHeader `json:"headers"`
	Content HARContent  `json:"content"`
}
type HARHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
type HARPostData struct {
	MimeType string `json:"mimeType"`
	Text     string `json:"text"`
}
type HARContent struct {
	MimeType string `json:"mimeType"`
	Text     string `json:"text"`
}

func (m *Module) Run(ctx context.Context, job *modules.Job) ([]modules.Finding, error) {
	var findings []modules.Finding

	// If target is a HAR file path, analyze it
	if strings.HasSuffix(strings.ToLower(job.Target), ".har") {
		harFindings, err := m.analyzeHAR(ctx, job)
		if err == nil {
			findings = append(findings, harFindings...)
		}
		return findings, nil
	}

	// Otherwise analyze the live target for PII leakage
	findings = append(findings, m.checkLiveEndpoint(ctx, job)...)

	return findings, nil
}

func (m *Module) analyzeHAR(ctx context.Context, job *modules.Job) ([]modules.Finding, error) {
	data, err := os.ReadFile(job.Target)
	if err != nil {
		return nil, fmt.Errorf("read HAR file: %w", err)
	}

	var har HARFile
	if err := json.Unmarshal(data, &har); err != nil {
		return nil, fmt.Errorf("parse HAR file: %w", err)
	}

	var findings []modules.Finding
	seenPatterns := map[string]bool{}

	for _, entry := range har.Log.Entries {
		entryFindings := m.analyzeHAREntry(entry, seenPatterns)
		findings = append(findings, entryFindings...)
	}

	// Summary finding
	findings = append(findings, modules.Finding{
		Module:      "passive",
		Title:       fmt.Sprintf("HAR analysis complete: %d requests analyzed", len(har.Log.Entries)),
		Description: fmt.Sprintf("Passive traffic analysis of %s completed. %d unique PII patterns checked across %d HTTP transactions.", job.Target, len(piiPatterns), len(har.Log.Entries)),
		Severity:    modules.Info,
		Endpoint:    job.Target,
	})

	return findings, nil
}

func (m *Module) analyzeHAREntry(entry HAREntry, seen map[string]bool) []modules.Finding {
	var findings []modules.Finding

	// Combine all text content to scan
	var corpus strings.Builder
	corpus.WriteString(entry.Request.URL)
	corpus.WriteString("\n")

	for _, h := range entry.Request.Headers {
		corpus.WriteString(h.Name + ": " + h.Value + "\n")
	}
	if entry.Request.PostData != nil {
		corpus.WriteString(entry.Request.PostData.Text)
	}
	for _, h := range entry.Response.Headers {
		corpus.WriteString(h.Name + ": " + h.Value + "\n")
	}
	corpus.WriteString(entry.Response.Content.Text)

	text := corpus.String()

	// Scan for PII/secrets
	for patternName, re := range piiPatterns {
		match := re.FindString(text)
		if match == "" {
			continue
		}

		// Deduplicate by pattern type + endpoint
		key := patternName + "|" + entry.Request.URL
		if seen[key] {
			continue
		}
		seen[key] = true

		severity, desc, owasp, cwe, cvss := categorizePattern(patternName, match)

		findings = append(findings, modules.Finding{
			Module:      "passive",
			Title:       fmt.Sprintf("PII/Secret detected in traffic: %s", patternName),
			Description: fmt.Sprintf("%s — detected in %s %s. %s", desc, entry.Request.Method, entry.Request.URL, owasp),
			Severity:    severity,
			Endpoint:    entry.Request.URL,
			Method:      entry.Request.Method,
			OWASPRef:    owasp,
			CVSSScore:   modules.CVSSPtr(cvss),
			CWEID:       cwe,
			Response:    fmt.Sprintf("Pattern: %s, Sample: %s", patternName, maskSensitive(patternName, match)),
		})
	}

	// Check for HTTP (not HTTPS) with sensitive data
	if strings.HasPrefix(entry.Request.URL, "http://") {
		if entry.Request.PostData != nil && len(entry.Request.PostData.Text) > 0 {
			findings = append(findings, modules.Finding{
				Module:      "passive",
				Title:       "Sensitive POST data transmitted over HTTP",
				Description: fmt.Sprintf("POST request to %s with body data transmitted over unencrypted HTTP.", entry.Request.URL),
				Severity:    modules.High,
				Endpoint:    entry.Request.URL,
				Method:      "POST",
				OWASPRef:    "A02:2021 - Cryptographic Failures",
				CVSSScore:   modules.CVSSPtr(7.5),
				CWEID:       "CWE-319",
			})
		}
	}

	// Check for sensitive headers in requests
	sensitiveRequestHeaders := []string{"authorization", "x-api-key", "x-auth-token", "cookie"}
	for _, h := range entry.Request.Headers {
		for _, sensitive := range sensitiveRequestHeaders {
			if strings.EqualFold(h.Name, sensitive) && strings.HasPrefix(entry.Request.URL, "http://") {
				key := "sensitive_header|" + entry.Request.URL
				if !seen[key] {
					seen[key] = true
					findings = append(findings, modules.Finding{
						Module:      "passive",
						Title:       fmt.Sprintf("Sensitive header %q sent over HTTP", h.Name),
						Description: fmt.Sprintf("Header %q transmitted to %s over plaintext HTTP — vulnerable to MITM interception.", h.Name, entry.Request.URL),
						Severity:    modules.Critical,
						Endpoint:    entry.Request.URL,
						OWASPRef:    "A02:2021 - Cryptographic Failures",
						CVSSScore:   modules.CVSSPtr(9.1),
						CWEID:       "CWE-523",
					})
				}
			}
		}
	}

	return findings
}

func (m *Module) checkLiveEndpoint(ctx context.Context, job *modules.Job) []modules.Finding {
	// For live endpoints without a HAR, return guidance
	return []modules.Finding{
		{
			Module:      "passive",
			Title:       "Passive analysis: provide HAR file for full traffic analysis",
			Description: fmt.Sprintf("Passive analysis of %s completed. For deeper traffic analysis, provide a HAR file captured from the browser DevTools.", job.Target),
			Severity:    modules.Info,
			Endpoint:    job.Target,
		},
	}
}

func categorizePattern(name, match string) (modules.Severity, string, string, string, float64) {
	switch name {
	case "private_key":
		return modules.Critical, "Private cryptographic key exposed in traffic", "A02:2021 - Cryptographic Failures", "CWE-312", 9.8
	case "aws_key", "aws_secret":
		return modules.Critical, "AWS credentials exposed in traffic — immediate rotation required", "A02:2021 - Cryptographic Failures", "CWE-312", 9.8
	case "stripe_key":
		return modules.Critical, "Stripe API key exposed — payment processing at risk", "A02:2021 - Cryptographic Failures", "CWE-312", 9.8
	case "github_token":
		return modules.Critical, "GitHub personal access token exposed", "A02:2021 - Cryptographic Failures", "CWE-312", 9.8
	case "jwt_token":
		return modules.High, "JWT token visible in traffic — if in URL, it may be logged", "A02:2021 - Cryptographic Failures", "CWE-598", 7.5
	case "ssn":
		return modules.Critical, "Social Security Number (SSN) detected — PII exposure", "A02:2021 - Cryptographic Failures", "CWE-312", 9.8
	case "basic_auth":
		return modules.High, "HTTP Basic Auth credentials visible in traffic", "A02:2021 - Cryptographic Failures", "CWE-523", 8.1
	case "bearer_in_url":
		return modules.High, "Authentication token in URL — will be logged by proxies and servers", "A02:2021 - Cryptographic Failures", "CWE-598", 7.5
	case "email":
		return modules.Medium, "Email address exposed in API traffic", "A02:2021 - Cryptographic Failures", "CWE-200", 4.3
	case "google_api":
		return modules.High, "Google API key exposed", "A02:2021 - Cryptographic Failures", "CWE-312", 7.5
	case "slack_token":
		return modules.High, "Slack API token exposed", "A02:2021 - Cryptographic Failures", "CWE-312", 7.5
	default:
		return modules.Medium, fmt.Sprintf("Potentially sensitive data pattern detected: %s", name), "A02:2021 - Cryptographic Failures", "CWE-200", 5.3
	}
}

func maskSensitive(patternName, value string) string {
	if len(value) <= 8 {
		return strings.Repeat("*", len(value))
	}
	switch patternName {
	case "email":
		parts := strings.Split(value, "@")
		if len(parts) == 2 {
			return parts[0][:1] + "***@" + parts[1]
		}
	case "private_key", "aws_secret", "stripe_key", "github_token":
		return value[:4] + strings.Repeat("*", len(value)-8) + value[len(value)-4:]
	}
	return value[:4] + strings.Repeat("*", len(value)-4)
}
