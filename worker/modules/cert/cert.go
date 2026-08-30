package cert

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"harbore.dev/worker/modules"
)

type Module struct{}

func New() *Module { return &Module{} }
func (m *Module) Name() string { return "cert" }

func (m *Module) Run(ctx context.Context, job *modules.Job) ([]modules.Finding, error) {
	var findings []modules.Finding

	host, port, err := extractHostPort(job.Target)
	if err != nil {
		return nil, fmt.Errorf("invalid target: %w", err)
	}

	findings = append(findings, m.analyzeTLS(ctx, host, port, job.Target)...)
	findings = append(findings, m.checkCipherSuites(ctx, host, port, job.Target)...)

	return findings, nil
}

func (m *Module) analyzeTLS(ctx context.Context, host, port, target string) []modules.Finding {
	var findings []modules.Finding

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	addr := net.JoinHostPort(host, port)

	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: false,
	})
	if err != nil {
		// TLS connection failed — check if it's a cert error or no TLS at all
		if strings.Contains(err.Error(), "certificate") || strings.Contains(err.Error(), "x509") {
			findings = append(findings, modules.Finding{
				Module:      "cert",
				Title:       "TLS certificate validation error",
				Description: fmt.Sprintf("TLS handshake failed with certificate error: %v", err),
				Severity:    modules.High,
				Endpoint:    target,
				OWASPRef:    "A02:2021 - Cryptographic Failures",
				CVSSScore:   modules.CVSSPtr(7.4),
				CWEID:       "CWE-295",
			})
		}
		return findings
	}
	defer conn.Close()

	state := conn.ConnectionState()

	// ─── Certificate checks ───────────────────────────────────────────────────
	for _, cert := range state.PeerCertificates {
		now := time.Now()

		// Expired certificate
		if now.After(cert.NotAfter) {
			findings = append(findings, modules.Finding{
				Module:      "cert",
				Title:       "Certificate is expired",
				Description: fmt.Sprintf("Certificate for %s expired on %s", cert.Subject.CommonName, cert.NotAfter.Format(time.RFC3339)),
				Severity:    modules.Critical,
				Endpoint:    target,
				OWASPRef:    "A02:2021 - Cryptographic Failures",
				CVSSScore:   modules.CVSSPtr(9.1),
				CWEID:       "CWE-298",
			})
		}

		// Expiring within 30 days
		if now.Before(cert.NotAfter) && cert.NotAfter.Before(now.Add(30*24*time.Hour)) {
			days := int(cert.NotAfter.Sub(now).Hours() / 24)
			sev := modules.Medium
			if days <= 7 {
				sev = modules.High
			}
			findings = append(findings, modules.Finding{
				Module:      "cert",
				Title:       fmt.Sprintf("Certificate expiring in %d days", days),
				Description: fmt.Sprintf("Certificate for %s expires on %s (%d days remaining)", cert.Subject.CommonName, cert.NotAfter.Format(time.RFC1123), days),
				Severity:    sev,
				Endpoint:    target,
				CVSSScore:   modules.CVSSPtr(5.9),
				CWEID:       "CWE-298",
			})
		}

		// Self-signed (no valid chain)
		if cert.Issuer.CommonName == cert.Subject.CommonName {
			findings = append(findings, modules.Finding{
				Module:      "cert",
				Title:       "Self-signed certificate detected",
				Description: fmt.Sprintf("Certificate issued by itself (%s) — browsers will show security warnings", cert.Subject.CommonName),
				Severity:    modules.High,
				Endpoint:    target,
				OWASPRef:    "A02:2021 - Cryptographic Failures",
				CVSSScore:   modules.CVSSPtr(6.5),
				CWEID:       "CWE-295",
			})
		}

		// Weak key size
		keySize := cert.PublicKey
		_ = keySize
		if cert.SignatureAlgorithm == x509.SHA1WithRSA || cert.SignatureAlgorithm == x509.ECDSAWithSHA1 {
			findings = append(findings, modules.Finding{
				Module:      "cert",
				Title:       "Certificate uses weak SHA-1 signature algorithm",
				Description: "SHA-1 is cryptographically broken. Replace with SHA-256 or stronger.",
				Severity:    modules.High,
				Endpoint:    target,
				OWASPRef:    "A02:2021 - Cryptographic Failures",
				CVSSScore:   modules.CVSSPtr(7.4),
				CWEID:       "CWE-327",
			})
		}

		// Wildcard cert
		for _, name := range cert.DNSNames {
			if strings.HasPrefix(name, "*.") {
				findings = append(findings, modules.Finding{
					Module:      "cert",
					Title:       "Wildcard certificate in use",
					Description: fmt.Sprintf("Wildcard certificate %s — compromise of any subdomain exposes all subdomains", name),
					Severity:    modules.Low,
					Endpoint:    target,
					CVSSScore:   modules.CVSSPtr(3.1),
				})
				break
			}
		}
	}

	// ─── Protocol version checks ──────────────────────────────────────────────
	tlsVersion := tlsVersionName(state.Version)
	if state.Version < tls.VersionTLS12 {
		findings = append(findings, modules.Finding{
			Module:      "cert",
			Title:       fmt.Sprintf("Deprecated TLS version in use: %s", tlsVersion),
			Description: fmt.Sprintf("Server negotiated %s which is deprecated and vulnerable. Require TLS 1.2 minimum, prefer TLS 1.3.", tlsVersion),
			Severity:    modules.Critical,
			Endpoint:    target,
			OWASPRef:    "A02:2021 - Cryptographic Failures",
			CVSSScore:   modules.CVSSPtr(9.1),
			PCIRequirement: "Req 4.2.1",
			CWEID:       "CWE-326",
		})
	} else if state.Version == tls.VersionTLS12 {
		findings = append(findings, modules.Finding{
			Module:      "cert",
			Title:       "TLS 1.2 in use — upgrade to TLS 1.3 recommended",
			Description: "TLS 1.2 is still acceptable but TLS 1.3 provides stronger security and better performance.",
			Severity:    modules.Info,
			Endpoint:    target,
			PCIRequirement: "Req 4.2.1",
		})
	}

	// ─── HSTS check ───────────────────────────────────────────────────────────
	// (Handled by asset module HTTP check, flagged here for cert context)

	return findings
}

func (m *Module) checkCipherSuites(ctx context.Context, host, port, target string) []modules.Finding {
	var findings []modules.Finding
	addr := net.JoinHostPort(host, port)
	dialer := &net.Dialer{Timeout: 5 * time.Second}

	weakCiphers := []uint16{
		tls.TLS_RSA_WITH_RC4_128_SHA,
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
	}

	for _, cipher := range weakCiphers {
		conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: true,
			CipherSuites:       []uint16{cipher},
			MinVersion:         tls.VersionTLS10,
		})
		if err == nil {
			cipherName := tls.CipherSuiteName(cipher)
			conn.Close()
			findings = append(findings, modules.Finding{
				Module:      "cert",
				Title:       fmt.Sprintf("Weak cipher suite accepted: %s", cipherName),
				Description: fmt.Sprintf("Server accepts the weak cipher %s — this cipher is considered insecure and should be disabled", cipherName),
				Severity:    modules.High,
				Endpoint:    target,
				OWASPRef:    "A02:2021 - Cryptographic Failures",
				CVSSScore:   modules.CVSSPtr(7.4),
				PCIRequirement: "Req 4.2.1",
				CWEID:       "CWE-327",
			})
		}
	}

	// Check if TLS 1.0 is accepted
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
		MaxVersion:         tls.VersionTLS10,
	})
	if err == nil {
		conn.Close()
		findings = append(findings, modules.Finding{
			Module:      "cert",
			Title:       "TLS 1.0 accepted",
			Description: "Server accepts TLS 1.0 which is deprecated (RFC 8996). Disable TLS 1.0 and 1.1 completely.",
			Severity:    modules.High,
			Endpoint:    target,
			OWASPRef:    "A02:2021 - Cryptographic Failures",
			CVSSScore:   modules.CVSSPtr(7.5),
			PCIRequirement: "Req 4.2.1",
			CWEID:       "CWE-326",
		})
	}

	return findings
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionSSL30:
		return "SSLv3"
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("unknown (0x%04x)", v)
	}
}

func extractHostPort(target string) (string, string, error) {
	u, err := url.Parse(target)
	if err != nil {
		return "", "", err
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "443" // default for cert scanning
		}
	}
	return host, port, nil
}
