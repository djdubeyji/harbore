package handlers

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"harbore.dev/orchestrator/api/middleware"
	"harbore.dev/orchestrator/db"
	"harbore.dev/orchestrator/models"
)

type TLSHandler struct {
	db *db.DB
}

func NewTLSHandler(database *db.DB) *TLSHandler {
	return &TLSHandler{db: database}
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	}
	return "unknown"
}

func (h *TLSHandler) resolveOrg(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	userID, ok := middleware.GetUserID(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return uuid.Nil, false
	}
	orgID, ok := activeOrgID(r)
	if !ok {
		jsonError(w, "missing or invalid X-Org-Id header", http.StatusBadRequest)
		return uuid.Nil, false
	}
	if member, err := h.db.IsOrgMember(r.Context(), userID, orgID); err != nil || !member {
		jsonError(w, "forbidden", http.StatusForbidden)
		return uuid.Nil, false
	}
	return orgID, true
}

// Check probes a host's live TLS certificate and stores the result.
func (h *TLSHandler) Check(w http.ResponseWriter, r *http.Request) {
	orgID, ok := h.resolveOrg(w, r)
	if !ok {
		return
	}
	var req struct {
		Host string `json:"host"`
		Port int    `json:"port"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Host == "" {
		jsonError(w, "host is required", http.StatusBadRequest)
		return
	}
	if req.Port == 0 {
		req.Port = 443
	}
	cert := probeTLS(req.Host, req.Port, &models.Certificate{OrgID: orgID, Host: req.Host, Port: req.Port})
	saved, err := h.db.UpsertCertificate(r.Context(), cert)
	if err != nil {
		jsonError(w, "failed to save certificate", http.StatusInternalServerError)
		return
	}
	jsonResponse(w, saved, http.StatusOK)
}

func probeTLS(host string, port int, cert *models.Certificate) *models.Certificate {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	dialer := &net.Dialer{Timeout: 8 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true, // still read expired / self-signed / mismatched certs
		MinVersion:         tls.VersionTLS10,
	})
	if err != nil {
		cert.Error = err.Error()
		return cert
	}
	defer conn.Close()

	st := conn.ConnectionState()
	cert.TLSVersion = tlsVersionName(st.Version)
	if len(st.PeerCertificates) == 0 {
		cert.Error = "no certificate presented"
		return cert
	}
	leaf := st.PeerCertificates[0]
	nb, na := leaf.NotBefore, leaf.NotAfter
	cert.CommonName = leaf.Subject.CommonName
	cert.Issuer = leaf.Issuer.CommonName
	cert.SANs = leaf.DNSNames
	cert.NotBefore = &nb
	cert.NotAfter = &na
	cert.SigAlg = leaf.SignatureAlgorithm.String()
	switch pk := leaf.PublicKey.(type) {
	case *rsa.PublicKey:
		cert.KeyType, cert.KeyBits = "RSA", pk.N.BitLen()
	case *ecdsa.PublicKey:
		cert.KeyType, cert.KeyBits = "ECDSA", pk.Curve.Params().BitSize
	default:
		cert.KeyType = fmt.Sprintf("%T", pk)
	}
	cert.Error = ""
	return cert
}

func (h *TLSHandler) List(w http.ResponseWriter, r *http.Request) {
	orgID, ok := h.resolveOrg(w, r)
	if !ok {
		return
	}
	certs, err := h.db.ListCertificates(r.Context(), orgID)
	if err != nil {
		jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}
	if certs == nil {
		certs = []*models.Certificate{}
	}
	jsonResponse(w, certs, http.StatusOK)
}

func (h *TLSHandler) Delete(w http.ResponseWriter, r *http.Request) {
	orgID, ok := h.resolveOrg(w, r)
	if !ok {
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, "invalid id", http.StatusBadRequest)
		return
	}
	if err := h.db.DeleteCertificate(r.Context(), id, orgID); err != nil {
		jsonError(w, "failed to delete", http.StatusInternalServerError)
		return
	}
	jsonResponse(w, map[string]string{"message": "deleted"}, http.StatusOK)
}
