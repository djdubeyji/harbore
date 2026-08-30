package crawler

import (
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

// Module crawls and maps API endpoints from spec files or direct discovery.
type Module struct{}

func New() *Module { return &Module{} }
func (m *Module) Name() string { return "crawler" }

func (m *Module) Run(ctx context.Context, job *modules.Job) ([]modules.Finding, error) {
	var findings []modules.Finding

	client := buildClient()

	// Try spec endpoints first
	findings = append(findings, m.discoverSpecFiles(ctx, client, job)...)

	// OpenAPI/Swagger discovery
	findings = append(findings, m.crawlOpenAPIEndpoints(ctx, client, job)...)

	// GraphQL introspection
	findings = append(findings, m.checkGraphQL(ctx, client, job)...)

	// Common API path discovery
	findings = append(findings, m.discoverCommonPaths(ctx, client, job)...)

	return findings, nil
}

// ─── Spec file discovery ──────────────────────────────────────────────────────

func (m *Module) discoverSpecFiles(ctx context.Context, client *http.Client, job *modules.Job) []modules.Finding {
	var findings []modules.Finding

	u, _ := url.Parse(job.Target)
	base := u.Scheme + "://" + u.Host

	specPaths := []string{
		"/swagger.json", "/swagger.yaml", "/swagger/v1/swagger.json",
		"/api-docs", "/api-docs.json", "/api/swagger.json",
		"/v1/swagger.json", "/v2/swagger.json", "/v3/swagger.json",
		"/openapi.json", "/openapi.yaml",
		"/api/openapi.json", "/api/v1/openapi.json",
		"/.well-known/openapi.json",
	}

	for _, path := range specPaths {
		specURL := base + path
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, specURL, nil)
		if req == nil {
			continue
		}
		applyAuth(req, job)

		resp, err := client.Do(req)
		if err != nil || resp.StatusCode != 200 {
			if resp != nil {
				resp.Body.Close()
			}
			continue
		}

		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
		resp.Body.Close()

		// Check if it's actually a spec file
		var specObj map[string]any
		if err := json.Unmarshal(body, &specObj); err != nil {
			continue
		}

		specType := "unknown"
		endpointCount := 0

		// OpenAPI 3.x
		if openapi, ok := specObj["openapi"].(string); ok && strings.HasPrefix(openapi, "3.") {
			specType = "OpenAPI 3.x"
			if paths, ok := specObj["paths"].(map[string]any); ok {
				endpointCount = len(paths)
			}
		}
		// Swagger 2.x
		if swagger, ok := specObj["swagger"].(string); ok && strings.HasPrefix(swagger, "2.") {
			specType = "Swagger 2.x"
			if paths, ok := specObj["paths"].(map[string]any); ok {
				endpointCount = len(paths)
			}
		}

		findings = append(findings, modules.Finding{
			Module:      "crawler",
			Title:       fmt.Sprintf("API specification file exposed: %s", specType),
			Description: fmt.Sprintf("%s spec found at %s — %d endpoint paths mapped. Public spec exposure assists attacker reconnaissance.", specType, specURL, endpointCount),
			Severity:    modules.Medium,
			Endpoint:    specURL,
			Method:      "GET",
			OWASPRef:    "A05:2021 - Security Misconfiguration",
			CVSSScore:   modules.CVSSPtr(5.3),
			Response:    fmt.Sprintf("Spec type: %s, paths: %d", specType, endpointCount),
		})

		// Parse and test discovered endpoints for auth
		if paths, ok := specObj["paths"].(map[string]any); ok {
			authFindings := m.testSpecEndpoints(ctx, client, job, base, paths)
			findings = append(findings, authFindings...)
		}
	}

	return findings
}

func (m *Module) testSpecEndpoints(ctx context.Context, client *http.Client, job *modules.Job, base string, paths map[string]any) []modules.Finding {
	var findings []modules.Finding

	tested := 0
	for path := range paths {
		if tested >= 20 { // limit to avoid over-scanning
			break
		}
		// Replace path parameters with test values
		testPath := path
		testPath = strings.ReplaceAll(testPath, "{id}", "1")
		testPath = strings.ReplaceAll(testPath, "{userId}", "1")
		testPath = strings.ReplaceAll(testPath, "{uuid}", "00000000-0000-0000-0000-000000000001")

		testURL := base + testPath

		// Test without auth
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, testURL, nil)
		if req == nil {
			continue
		}
		req.Header.Set("User-Agent", "Harbore-Scanner/1.0")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()
		tested++

		// If auth is configured but endpoint responds 200 without it
		if resp.StatusCode == 200 && job.Auth.Bearer != "" {
			findings = append(findings, modules.Finding{
				Module:      "crawler",
				Title:       "API endpoint accessible without authentication",
				Description: fmt.Sprintf("Spec-defined endpoint %s returns HTTP 200 without credentials. Expected 401 or 403 when authentication is configured.", testPath),
				Severity:    modules.High,
				Endpoint:    testURL,
				Method:      "GET",
				OWASPRef:    "A01:2021 - Broken Access Control",
				CVSSScore:   modules.CVSSPtr(8.1),
				CWEID:       "CWE-306",
			})
		}
	}

	return findings
}

// ─── OpenAPI crawl ────────────────────────────────────────────────────────────

func (m *Module) crawlOpenAPIEndpoints(ctx context.Context, client *http.Client, job *modules.Job) []modules.Finding {
	var findings []modules.Finding

	// Already handled in spec discovery — placeholder for deep endpoint testing
	return findings
}

// ─── GraphQL introspection ────────────────────────────────────────────────────

func (m *Module) checkGraphQL(ctx context.Context, client *http.Client, job *modules.Job) []modules.Finding {
	var findings []modules.Finding

	u, _ := url.Parse(job.Target)
	base := u.Scheme + "://" + u.Host

	graphqlPaths := []string{"/graphql", "/api/graphql", "/v1/graphql", "/query"}

	introspectionQuery := `{"query":"{ __schema { types { name fields { name } } } }"}`

	for _, path := range graphqlPaths {
		testURL := base + path

		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, testURL, strings.NewReader(introspectionQuery))
		if req == nil {
			continue
		}
		applyAuth(req, job)
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
		resp.Body.Close()

		var result map[string]any
		if err := json.Unmarshal(body, &result); err != nil {
			continue
		}

		// Check for introspection data in response
		if data, ok := result["data"].(map[string]any); ok {
			if schema, ok := data["__schema"].(map[string]any); ok && schema != nil {
				findings = append(findings, modules.Finding{
					Module:      "crawler",
					Title:       "GraphQL introspection enabled in production",
					Description: fmt.Sprintf("GraphQL introspection query succeeded at %s — full schema exposed. Attackers can enumerate all types, queries, mutations, and field names. Disable introspection in production.", path),
					Severity:    modules.Medium,
					Endpoint:    testURL,
					Method:      "POST",
					OWASPRef:    "A05:2021 - Security Misconfiguration",
					CVSSScore:   modules.CVSSPtr(5.3),
					CWEID:       "CWE-200",
					Request:     introspectionQuery,
				})
			}
		}

		// Check for GraphQL errors that disclose info
		if errors, ok := result["errors"].([]any); ok && len(errors) > 0 {
			for _, e := range errors {
				errStr := fmt.Sprintf("%v", e)
				if strings.Contains(errStr, "syntax") || strings.Contains(errStr, "field") {
					findings = append(findings, modules.Finding{
						Module:      "crawler",
						Title:       "GraphQL endpoint discovered",
						Description: fmt.Sprintf("GraphQL endpoint found at %s. Returned error messages may disclose schema structure.", path),
						Severity:    modules.Info,
						Endpoint:    testURL,
					})
					break
				}
			}
		}
	}

	return findings
}

// ─── Common path discovery ────────────────────────────────────────────────────

func (m *Module) discoverCommonPaths(ctx context.Context, client *http.Client, job *modules.Job) []modules.Finding {
	var findings []modules.Finding

	u, _ := url.Parse(job.Target)
	base := u.Scheme + "://" + u.Host

	// Sensitive API paths that should not be publicly accessible
	sensitivePaths := []struct {
		path string
		desc string
		sev  modules.Severity
		cvss float64
	}{
		{"/api/v1/admin/users", "Admin user management endpoint exposed", modules.Critical, 9.1},
		{"/api/admin", "Admin API endpoint accessible", modules.Critical, 9.1},
		{"/api/internal", "Internal API endpoint accessible", modules.High, 8.1},
		{"/api/debug", "Debug endpoint exposed", modules.High, 7.5},
		{"/actuator/env", "Spring Boot environment endpoint exposed", modules.Critical, 9.8},
		{"/actuator/beans", "Spring Boot beans endpoint exposed", modules.High, 7.5},
		{"/actuator/heapdump", "Spring Boot heap dump exposed", modules.Critical, 9.1},
		{"/.env", "Environment config file exposed", modules.Critical, 9.8},
		{"/config.json", "Config file exposed", modules.High, 8.1},
		{"/api/keys", "API keys endpoint", modules.Critical, 9.8},
		{"/api/v1/health", "Health check (info exposure)", modules.Info, 0.0},
		{"/metrics", "Prometheus metrics exposed", modules.Medium, 5.3},
	}

	for _, sp := range sensitivePaths {
		testURL := base + sp.path
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, testURL, nil)
		if req == nil {
			continue
		}
		req.Header.Set("User-Agent", "Harbore-Scanner/1.0")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 32*1024))
		resp.Body.Close()

		if resp.StatusCode == 200 && len(body) > 10 {
			score := sp.cvss
			var scorePtr *float64
			if score > 0 {
				scorePtr = &score
			}
			findings = append(findings, modules.Finding{
				Module:      "crawler",
				Title:       sp.desc,
				Description: fmt.Sprintf("Path %s returned HTTP 200 with %d bytes of content. This path should be protected or removed from public access.", sp.path, len(body)),
				Severity:    sp.sev,
				Endpoint:    testURL,
				Method:      "GET",
				OWASPRef:    "A05:2021 - Security Misconfiguration",
				CVSSScore:   scorePtr,
				CWEID:       "CWE-200",
			})
		}
	}

	return findings
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
