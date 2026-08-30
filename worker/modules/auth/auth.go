package auth

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"harbore.dev/worker/modules"
)

// Module tests authentication and authorization controls.
type Module struct{}

func New() *Module { return &Module{} }
func (m *Module) Name() string { return "auth" }

func (m *Module) Run(ctx context.Context, job *modules.Job) ([]modules.Finding, error) {
	var findings []modules.Finding
	client := buildClient()

	findings = append(findings, m.checkJWT(ctx, client, job)...)
	findings = append(findings, m.checkIDOR(ctx, client, job)...)
	findings = append(findings, m.checkOAuth(ctx, client, job)...)
	findings = append(findings, m.checkPrivilegeEscalation(ctx, client, job)...)
	findings = append(findings, m.checkSessionManagement(ctx, client, job)...)

	return findings, nil
}

// ─── JWT checks ───────────────────────────────────────────────────────────────

func (m *Module) checkJWT(ctx context.Context, client *http.Client, job *modules.Job) []modules.Finding {
	var findings []modules.Finding

	bearer := job.Auth.Bearer
	if bearer == "" {
		return findings
	}

	parts := strings.Split(bearer, ".")
	if len(parts) != 3 {
		return findings
	}

	// Decode header
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return findings
	}
	var header map[string]any
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return findings
	}

	// Decode claims
	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return findings
	}
	var claims map[string]any
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return findings
	}

	// 1. Algorithm confusion: test alg=none
	noneHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	noneToken := noneHeader + "." + parts[1] + "."

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, job.Target, nil)
	if req != nil {
		req.Header.Set("Authorization", "Bearer "+noneToken)
		req.Header.Set("User-Agent", "Harbore-Scanner/1.0")
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				findings = append(findings, modules.Finding{
					Module:      "auth",
					Title:       "JWT algorithm confusion: 'none' algorithm accepted",
					Description: "Server accepted an unsigned JWT token (alg=none). This is a critical authentication bypass — any attacker can forge tokens for any user.",
					Severity:    modules.Critical,
					Endpoint:    job.Target,
					OWASPRef:    "A07:2021 - Identification and Authentication Failures",
					CVSSScore:   modules.CVSSPtr(9.8),
					CWEID:       "CWE-347",
					Request:     fmt.Sprintf("Authorization: Bearer %s", noneToken),
				})
			}
		}
	}

	// 2. RS256→HS256 confusion attack
	if alg, ok := header["alg"].(string); ok && alg == "RS256" {
		// Construct HS256 token using public key as secret (simplified check)
		hs256Header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
		hs256Token := hs256Header + "." + parts[1] + ".invalidsignature"

		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, job.Target, nil)
		if req != nil {
			req.Header.Set("Authorization", "Bearer "+hs256Token)
			req.Header.Set("User-Agent", "Harbore-Scanner/1.0")
			resp, err := client.Do(req)
			if err == nil {
				resp.Body.Close()
				if resp.StatusCode == 200 {
					findings = append(findings, modules.Finding{
						Module:      "auth",
						Title:       "JWT RS256→HS256 algorithm confusion attack possible",
						Description: "Server accepted an HS256-signed token when RS256 is expected. This may indicate algorithm confusion vulnerability — the server may accept the public key as HMAC secret.",
						Severity:    modules.Critical,
						Endpoint:    job.Target,
						OWASPRef:    "A07:2021 - Identification and Authentication Failures",
						CVSSScore:   modules.CVSSPtr(9.8),
						CWEID:       "CWE-347",
					})
				}
			}
		}
	}

	// 3. Weak signing key: test common secrets
	weakSecrets := []string{"secret", "password", "123456", "key", "jwt_secret", "your-256-bit-secret"}
	for _, secret := range weakSecrets {
		if testJWTWithSecret(parts[0]+"."+parts[1], parts[2], secret) {
			findings = append(findings, modules.Finding{
				Module:      "auth",
				Title:       "JWT signed with weak/common secret",
				Description: fmt.Sprintf("JWT token is signed with a common/guessable secret: %q. Attackers can forge arbitrary JWT tokens for any user.", secret),
				Severity:    modules.Critical,
				Endpoint:    job.Target,
				OWASPRef:    "A02:2021 - Cryptographic Failures",
				CVSSScore:   modules.CVSSPtr(9.8),
				CWEID:       "CWE-1391",
			})
			break
		}
	}

	// 4. Sensitive data in JWT claims
	sensitiveFields := []string{"password", "secret", "ssn", "credit_card", "api_key"}
	for _, f := range sensitiveFields {
		if _, ok := claims[f]; ok {
			findings = append(findings, modules.Finding{
				Module:      "auth",
				Title:       fmt.Sprintf("Sensitive field %q present in JWT payload", f),
				Description: "JWT payload contains a sensitive field. JWT payloads are base64-encoded (not encrypted) — anyone with the token can read all claims.",
				Severity:    modules.High,
				Endpoint:    job.Target,
				OWASPRef:    "A02:2021 - Cryptographic Failures",
				CVSSScore:   modules.CVSSPtr(7.5),
				CWEID:       "CWE-312",
			})
		}
	}

	// 5. JWT expiry check
	if exp, ok := claims["exp"].(float64); ok {
		expTime := time.Unix(int64(exp), 0)
		if expTime.After(time.Now().Add(30 * 24 * time.Hour)) {
			findings = append(findings, modules.Finding{
				Module:      "auth",
				Title:       "JWT token has excessive expiry time",
				Description: fmt.Sprintf("Token expires at %s (%d days). Long-lived tokens increase the blast radius of token theft. Recommend max 24h for access tokens.", expTime.Format(time.RFC1123), int(time.Until(expTime).Hours()/24)),
				Severity:    modules.Medium,
				Endpoint:    job.Target,
				OWASPRef:    "A07:2021 - Identification and Authentication Failures",
				CVSSScore:   modules.CVSSPtr(5.3),
				CWEID:       "CWE-613",
			})
		}
	} else {
		// No expiry at all
		findings = append(findings, modules.Finding{
			Module:      "auth",
			Title:       "JWT token has no expiry (exp claim missing)",
			Description: "JWT has no 'exp' claim — it never expires. Stolen tokens are valid forever. Add an expiry claim of maximum 24 hours for access tokens.",
			Severity:    modules.High,
			Endpoint:    job.Target,
			OWASPRef:    "A07:2021 - Identification and Authentication Failures",
			CVSSScore:   modules.CVSSPtr(7.5),
			CWEID:       "CWE-613",
		})
	}

	return findings
}

// ─── IDOR checks ──────────────────────────────────────────────────────────────

func (m *Module) checkIDOR(ctx context.Context, client *http.Client, job *modules.Job) []modules.Finding {
	var findings []modules.Finding

	// Test sequential resource access
	idorPatterns := []struct {
		id1, id2 string
		desc      string
	}{
		{"1", "2", "sequential integer IDs"},
		{"00000000-0000-0000-0000-000000000001", "00000000-0000-0000-0000-000000000002", "sequential UUIDs"},
	}

	for _, pattern := range idorPatterns {
		url1 := replaceID(job.Target, pattern.id1)
		url2 := replaceID(job.Target, pattern.id2)

		if url1 == url2 {
			continue
		}

		// Fetch first resource with valid auth
		resp1, body1 := doGet(ctx, client, url1, job.Auth.Bearer)
		// Fetch second resource with same auth
		resp2, body2 := doGet(ctx, client, url2, job.Auth.Bearer)

		if resp1 == 200 && resp2 == 200 && len(body1) > 50 && len(body2) > 50 {
			// Both accessible — check if they look like different users' data
			findings = append(findings, modules.Finding{
				Module:      "auth",
				Title:       "Potential IDOR: Multiple resource IDs accessible with same token",
				Description: fmt.Sprintf("Both %s and %s returned HTTP 200 with similar-sized responses (%s). Verify authorization checks prevent cross-user data access.", url1, url2, pattern.desc),
				Severity:    modules.High,
				Endpoint:    job.Target,
				OWASPRef:    "A01:2021 - Broken Access Control",
				CVSSScore:   modules.CVSSPtr(8.1),
				CWEID:       "CWE-639",
			})
		}
	}

	return findings
}

// ─── OAuth checks ─────────────────────────────────────────────────────────────

func (m *Module) checkOAuth(ctx context.Context, client *http.Client, job *modules.Job) []modules.Finding {
	var findings []modules.Finding

	// Look for OAuth endpoints
	oauthPaths := []string{
		"/.well-known/openid-configuration",
		"/oauth/authorize",
		"/oauth2/authorize",
		"/auth/oauth",
	}

	for _, path := range oauthPaths {
		base := extractBase(job.Target)
		testURL := base + path

		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, testURL, nil)
		if req == nil {
			continue
		}
		req.Header.Set("User-Agent", "Harbore-Scanner/1.0")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		resp.Body.Close()

		if resp.StatusCode != 200 {
			continue
		}

		var config map[string]any
		if err := json.Unmarshal(body, &config); err != nil {
			continue
		}

		// Check for open redirect in OAuth
		if authEndpoint, ok := config["authorization_endpoint"].(string); ok {
			// Test open redirect
			testRedirect := authEndpoint + "?redirect_uri=https://evil.com&client_id=test&response_type=code"
			req2, _ := http.NewRequestWithContext(ctx, http.MethodGet, testRedirect, nil)
			if req2 != nil {
				resp2, err := client.Do(req2)
				if err == nil {
					resp2.Body.Close()
					if resp2.StatusCode == 302 {
						location := resp2.Header.Get("Location")
						if strings.Contains(location, "evil.com") {
							findings = append(findings, modules.Finding{
								Module:      "auth",
								Title:       "OAuth open redirect vulnerability",
								Description: "OAuth authorization endpoint accepted an arbitrary redirect_uri without validation — allows redirect to attacker-controlled domain, stealing authorization codes.",
								Severity:    modules.High,
								Endpoint:    authEndpoint,
								OWASPRef:    "A01:2021 - Broken Access Control",
								CVSSScore:   modules.CVSSPtr(7.4),
								CWEID:       "CWE-601",
							})
						}
					}
				}
			}
		}
	}

	return findings
}

// ─── Privilege escalation ──────────────────────────────────────────────────────

func (m *Module) checkPrivilegeEscalation(ctx context.Context, client *http.Client, job *modules.Job) []modules.Finding {
	var findings []modules.Finding

	// Test role parameter tampering
	adminHeaders := map[string]string{
		"X-Role":        "admin",
		"X-Admin":       "true",
		"X-User-Role":   "administrator",
		"X-Bypass":      "true",
		"X-Forwarded-For": "127.0.0.1",
		"X-Real-IP":     "127.0.0.1",
	}

	for header, value := range adminHeaders {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, job.Target, nil)
		if req == nil {
			continue
		}
		applyAuth(req, job)
		req.Header.Set(header, value)

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		resp.Body.Close()

		bodyStr := string(body)
		if resp.StatusCode == 200 && (strings.Contains(bodyStr, "admin") || strings.Contains(bodyStr, "administrator")) {
			findings = append(findings, modules.Finding{
				Module:      "auth",
				Title:       fmt.Sprintf("Potential privilege escalation via header: %s: %s", header, value),
				Description: fmt.Sprintf("Setting header %s: %s produced a 200 response containing 'admin' data. Verify server-side authorization doesn't trust client-supplied role headers.", header, value),
				Severity:    modules.High,
				Endpoint:    job.Target,
				OWASPRef:    "A01:2021 - Broken Access Control",
				CVSSScore:   modules.CVSSPtr(8.8),
				CWEID:       "CWE-269",
				Request:     fmt.Sprintf("%s: %s", header, value),
			})
		}
	}

	return findings
}

// ─── Session management ───────────────────────────────────────────────────────

func (m *Module) checkSessionManagement(ctx context.Context, client *http.Client, job *modules.Job) []modules.Finding {
	var findings []modules.Finding

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, job.Target, nil)
	if req == nil {
		return findings
	}
	applyAuth(req, job)

	resp, err := client.Do(req)
	if err != nil {
		return findings
	}
	resp.Body.Close()

	// Check Set-Cookie security flags
	for _, cookie := range resp.Header.Values("Set-Cookie") {
		lower := strings.ToLower(cookie)
		cookieName := strings.Split(cookie, "=")[0]

		if !strings.Contains(lower, "httponly") {
			findings = append(findings, modules.Finding{
				Module:      "auth",
				Title:       fmt.Sprintf("Cookie missing HttpOnly flag: %s", cookieName),
				Description: "Session cookie without HttpOnly flag can be read by JavaScript — enables session theft via XSS.",
				Severity:    modules.Medium,
				Endpoint:    job.Target,
				OWASPRef:    "A07:2021 - Identification and Authentication Failures",
				CVSSScore:   modules.CVSSPtr(6.1),
				CWEID:       "CWE-1004",
				Response:    cookie,
			})
		}
		if !strings.Contains(lower, "secure") {
			findings = append(findings, modules.Finding{
				Module:      "auth",
				Title:       fmt.Sprintf("Cookie missing Secure flag: %s", cookieName),
				Description: "Cookie without Secure flag can be transmitted over HTTP — enables cookie theft via network interception.",
				Severity:    modules.Medium,
				Endpoint:    job.Target,
				OWASPRef:    "A02:2021 - Cryptographic Failures",
				CVSSScore:   modules.CVSSPtr(5.9),
				CWEID:       "CWE-614",
				Response:    cookie,
			})
		}
		if !strings.Contains(lower, "samesite") {
			findings = append(findings, modules.Finding{
				Module:      "auth",
				Title:       fmt.Sprintf("Cookie missing SameSite attribute: %s", cookieName),
				Description: "Cookie without SameSite attribute is vulnerable to CSRF attacks.",
				Severity:    modules.Low,
				Endpoint:    job.Target,
				OWASPRef:    "A01:2021 - Broken Access Control",
				CVSSScore:   modules.CVSSPtr(4.3),
				CWEID:       "CWE-352",
				Response:    cookie,
			})
		}
	}

	return findings
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func testJWTWithSecret(headerPayload, signature, secret string) bool {
	// Simplified: real implementation would HMAC-SHA256 and compare
	// This is a placeholder — full HMAC verification would import crypto/hmac
	_ = headerPayload
	_ = signature
	_ = secret
	return false
}

func replaceID(target, id string) string {
	// Try to replace last path segment that looks like an ID
	parts := strings.Split(target, "/")
	for i := len(parts) - 1; i >= 0; i-- {
		if len(parts[i]) > 0 && isNumericOrUUID(parts[i]) {
			parts[i] = id
			return strings.Join(parts, "/")
		}
	}
	return target + "/" + id
}

func isNumericOrUUID(s string) bool {
	if len(s) == 36 && strings.Count(s, "-") == 4 {
		return true
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(s) > 0
}

func doGet(ctx context.Context, client *http.Client, target, bearer string) (int, []byte) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if req == nil {
		return 0, nil
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	req.Header.Set("User-Agent", "Harbore-Scanner/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	resp.Body.Close()
	return resp.StatusCode, body
}

func extractBase(target string) string {
	idx := strings.Index(target, "://")
	if idx < 0 {
		return target
	}
	rest := target[idx+3:]
	slashIdx := strings.Index(rest, "/")
	if slashIdx < 0 {
		return target
	}
	return target[:idx+3] + rest[:slashIdx]
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
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}
