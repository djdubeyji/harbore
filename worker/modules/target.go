package modules

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// This mirrors orchestrator/models.NormalizeTarget. The worker and orchestrator
// are separate Go modules, so the logic is intentionally duplicated (kept small)
// rather than shared. Targets normally arrive already normalized from the
// orchestrator; this is a defensive layer plus a reachability probe that the
// orchestrator (which does no network I/O) cannot perform.

var schemeRe = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.\-]*://`)

// HasScheme reports whether s already begins with a URL scheme.
func HasScheme(s string) bool {
	return schemeRe.MatchString(strings.TrimSpace(s))
}

// NormalizeTarget ensures a target is an absolute URL with a scheme. See
// orchestrator/models.NormalizeTarget for the full rationale.
func NormalizeTarget(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return s
	}
	if schemeRe.MatchString(s) {
		return s
	}
	s = strings.TrimPrefix(s, "//")

	scheme := "https"
	if port := schemelessPort(s); port != "" && port != "443" && port != "8443" {
		scheme = "http"
	}
	return scheme + "://" + s
}

func schemelessPort(s string) string {
	u, err := url.Parse("//" + s)
	if err != nil {
		return ""
	}
	return u.Port()
}

// ResolveScheme verifies that an http(s) target is reachable on its current
// scheme and, if not, falls back to the other scheme. It is meant for targets
// whose scheme was *inferred* (schemeless input): a bare hostname is assumed to
// be https, but many internal APIs and test targets are http-only. If neither
// scheme responds, the original target is returned unchanged so the module runs
// and reports the real failure.
func ResolveScheme(ctx context.Context, target string) string {
	u, err := url.Parse(target)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return target
	}

	if reachable(ctx, target) {
		return target
	}

	alt := *u
	if u.Scheme == "https" {
		alt.Scheme = "http"
	} else {
		alt.Scheme = "https"
	}
	altStr := alt.String()
	if reachable(ctx, altStr) {
		return altStr
	}
	return target
}

// reachable performs a fast, best-effort request to check that a target answers
// on its scheme. Any HTTP response (including 4xx/5xx) counts as reachable; only
// transport-level failures (connection refused, TLS handshake error) count as
// unreachable. TLS verification is skipped because this is a liveness check, not
// a certificate check (that is the cert module's job).
func reachable(ctx context.Context, target string) bool {
	probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequestWithContext(probeCtx, http.MethodHead, target, nil)
	if err != nil {
		return false
	}
	resp, err := client.Do(req)
	if err != nil {
		// Some servers reject HEAD — retry once with GET before giving up.
		req2, e2 := http.NewRequestWithContext(probeCtx, http.MethodGet, target, nil)
		if e2 != nil {
			return false
		}
		resp, err = client.Do(req2)
		if err != nil {
			return false
		}
	}
	resp.Body.Close()
	return true
}
