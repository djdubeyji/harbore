package models

import (
	"net/url"
	"regexp"
	"strings"
)

// schemeRe matches a leading URL scheme, e.g. "https://", "http://", "ftp://".
var schemeRe = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.\-]*://`)

// NormalizeTarget ensures a scan target is an absolute URL with a scheme.
//
// Scan modules call url.Parse(target) and http.NewRequest(..., target, ...).
// Both misbehave on schemeless input: url.Parse("example.com:4280") treats
// "example.com" as the scheme and leaves Host empty, and http.NewRequest rejects
// it with "unsupported protocol scheme". The result is that every HTTP/TLS module
// silently produces no findings. Normalizing at ingest and at job-build time
// guarantees modules always receive a parseable absolute URL.
//
// Rules (no network I/O — deterministic):
//   - Input already carrying a scheme is returned unchanged.
//   - A protocol-relative prefix ("//host") is treated as schemeless.
//   - Scheme is inferred from an explicit port: 443/8443 -> https, else http.
//   - With no explicit port, https is assumed. The worker performs a reachability
//     probe (see worker resolveScheme) to fall back to http for http-only hosts.
func NormalizeTarget(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return s
	}
	if schemeRe.MatchString(s) {
		return s // already has a scheme — honor it
	}
	s = strings.TrimPrefix(s, "//") // handle protocol-relative form

	scheme := "https"
	if port := schemelessPort(s); port != "" && port != "443" && port != "8443" {
		scheme = "http"
	}
	return scheme + "://" + s
}

// NormalizeTargets normalizes each target in place and returns the slice.
func NormalizeTargets(targets []string) []string {
	for i, t := range targets {
		targets[i] = NormalizeTarget(t)
	}
	return targets
}

// schemelessPort extracts the port from a schemeless authority (e.g.
// "host:4280/path" -> "4280"). Parsing with a "//" prefix lets url.Parse treat
// the string as an authority and correctly handles IPv6 literals like
// "[::1]:8080".
func schemelessPort(s string) string {
	u, err := url.Parse("//" + s)
	if err != nil {
		return ""
	}
	return u.Port()
}
