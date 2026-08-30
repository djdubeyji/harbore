package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"harbore.dev/orchestrator/api/middleware"
	"harbore.dev/orchestrator/config"
	"harbore.dev/orchestrator/db"
	"harbore.dev/orchestrator/models"
)

type ReportHandler struct {
	db         *db.DB
	cfg        *config.Config
	reportURL  string
	aiURL      string
	httpClient *http.Client
}

func NewReportHandler(database *db.DB, cfg *config.Config) *ReportHandler {
	return &ReportHandler{
		db:         database,
		cfg:        cfg,
		reportURL:  getEnvOrDefault("REPORT_URL", "http://report:8091"),
		aiURL:      getEnvOrDefault("AI_URL", "http://ai:8090"),
		httpClient: &http.Client{Timeout: 5 * time.Minute},
	}
}

// GenerateReport builds and streams a Word or PDF report for a scan.
func (h *ReportHandler) GenerateReport(w http.ResponseWriter, r *http.Request) {
	scanID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, "invalid scan id", http.StatusBadRequest)
		return
	}

	format := r.URL.Query().Get("format")
	if format != "pdf" {
		format = "docx"
	}

	ctx := r.Context()

	// Load scan
	scan, err := h.db.GetScan(ctx, scanID)
	if err != nil || scan == nil {
		jsonError(w, "scan not found", http.StatusNotFound)
		return
	}

	// Load findings + failures
	findings, err := h.db.ListFindings(ctx, scanID)
	if err != nil {
		jsonError(w, "failed to load findings", http.StatusInternalServerError)
		return
	}
	failures, err := h.db.ListFailures(ctx, scanID)
	if err != nil {
		failures = []*models.FailureLog{}
	}
	stats, _ := h.db.GetScanFindingStats(ctx, scanID)

	// Try AI narration if enabled
	var execSummary, critSection, remPriorities, pciNarrative string
	if h.cfg.AIEnabled {
		narration := h.callAINarration(ctx, scan, findings, stats)
		execSummary = narration["executive_summary"]
		critSection = narration["critical_section"]
		remPriorities = narration["remediation_priorities"]
		pciNarrative = narration["pci_narrative"]
	}

	// Build report request
	reportReq := buildReportRequest(scan, findings, failures, stats, format, execSummary, critSection, remPriorities, pciNarrative)

	body, err := json.Marshal(reportReq)
	if err != nil {
		jsonError(w, "failed to build report request", http.StatusInternalServerError)
		return
	}

	// Call report engine
	resp, err := h.httpClient.Post(h.reportURL+"/report/generate", "application/json", bytes.NewReader(body))
	if err != nil {
		jsonError(w, fmt.Sprintf("report engine unavailable: %v", err), http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		jsonError(w, "report engine returned error", http.StatusInternalServerError)
		return
	}

	// Stream the response
	contentType := "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
	if format == "pdf" {
		contentType = "application/pdf"
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="harbore-%s.%s"`, scanID.String()[:8], format))

	_, _ = io.Copy(w, resp.Body)
}

func (h *ReportHandler) callAINarration(ctx context.Context, scan *models.Scan, findings []*models.Finding, stats map[string]int) map[string]string {
	result := map[string]string{}

	// Build top findings list for AI (limit to 20)
	topFindings := make([]map[string]interface{}, 0)
	for i, f := range findings {
		if i >= 20 {
			break
		}
		tf := map[string]interface{}{
			"title":       f.Title,
			"severity":    f.Severity,
			"description": f.Description,
			"endpoint":    f.Endpoint,
		}
		if f.CVSSScore != nil {
			tf["cvss_score"] = *f.CVSSScore
		}
		topFindings = append(topFindings, tf)
	}

	pciCount := 0
	for _, f := range findings {
		if f.PCIRequirement != "" {
			pciCount++
		}
	}

	payload := map[string]interface{}{
		"scan_id": scan.ID.String(),
		"summary": map[string]interface{}{
			"scan_name":          scan.Name,
			"target_count":       len(scan.Config.Targets),
			"modules_run":        scan.Modules,
			"stats":              stats,
			"pci_findings_count": pciCount,
			"failure_count":      scan.FailedJobs,
		},
		"top_findings": topFindings,
	}

	body, _ := json.Marshal(payload)
	resp, err := h.httpClient.Post(h.aiURL+"/ai/narrate", "application/json", bytes.NewReader(body))
	if err != nil || resp.StatusCode != http.StatusOK {
		return result
	}
	defer resp.Body.Close()

	var narration struct {
		ExecutiveSummary      string `json:"executive_summary"`
		CriticalSection       string `json:"critical_section"`
		RemediationPriorities string `json:"remediation_priorities"`
		PCINarrative          string `json:"pci_narrative"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&narration); err == nil {
		result["executive_summary"] = narration.ExecutiveSummary
		result["critical_section"] = narration.CriticalSection
		result["remediation_priorities"] = narration.RemediationPriorities
		result["pci_narrative"] = narration.PCINarrative
	}

	return result
}

func buildReportRequest(
	scan *models.Scan,
	findings []*models.Finding,
	failures []*models.FailureLog,
	stats map[string]int,
	format string,
	execSummary, critSection, remPriorities, pciNarrative string,
) map[string]interface{} {
	findingsList := make([]map[string]interface{}, 0, len(findings))
	for _, f := range findings {
		if f.IsFalsePositive {
			continue
		}
		ff := map[string]interface{}{
			"title":       f.Title,
			"severity":    string(f.Severity),
			"module":      f.Module,
			"description": f.Description,
		}
		if f.CVSSScore != nil {
			ff["cvss_score"] = *f.CVSSScore
		}
		if f.CVSSVector != "" {
			ff["cvss_vector"] = f.CVSSVector
		}
		if f.Endpoint != "" {
			ff["endpoint"] = f.Endpoint
		}
		if f.Method != "" {
			ff["method"] = f.Method
		}
		if f.OWASPRef != "" {
			ff["owasp_ref"] = f.OWASPRef
		}
		if f.PCIRequirement != "" {
			ff["pci_requirement"] = f.PCIRequirement
		}
		if f.CWEID != "" {
			ff["cwe_id"] = f.CWEID
		}
		if f.AISummary != "" {
			ff["ai_summary"] = f.AISummary
		}
		if f.AIRemediation != "" {
			ff["ai_remediation"] = f.AIRemediation
		}
		if f.Request != "" {
			ff["request"] = f.Request[:min(2000, len(f.Request))]
		}
		if f.Response != "" {
			ff["response"] = f.Response[:min(2000, len(f.Response))]
		}
		findingsList = append(findingsList, ff)
	}

	failuresList := make([]map[string]interface{}, 0, len(failures))
	for _, fail := range failures {
		failuresList = append(failuresList, map[string]interface{}{
			"target":      fail.Target,
			"module":      fail.Module,
			"attempts":    fail.Attempts,
			"final_error": fail.FinalError,
		})
	}

	req := map[string]interface{}{
		"scan_id":      scan.ID.String(),
		"scan_name":    scan.Name,
		"target_count": len(scan.Config.Targets),
		"modules_run":  scan.Modules,
		"stats":        stats,
		"findings":     findingsList,
		"failures":     failuresList,
		"format":       format,
	}
	if execSummary != "" {
		req["executive_summary"] = execSummary
	}
	if critSection != "" {
		req["critical_section"] = critSection
	}
	if remPriorities != "" {
		req["remediation_priorities"] = remPriorities
	}
	if pciNarrative != "" {
		req["pci_narrative"] = pciNarrative
	}
	if scan.StartedAt != nil && scan.FinishedAt != nil {
		mins := scan.FinishedAt.Sub(*scan.StartedAt).Minutes()
		req["duration_mins"] = mins
	}

	return req
}

func getEnvOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// GenerateGovernanceReport fills the CB-Advisory ISMS template with the
// governance fields supplied in the request body plus this scan's findings.
func (h *ReportHandler) GenerateGovernanceReport(w http.ResponseWriter, r *http.Request) {
	scanID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, "invalid scan id", http.StatusBadRequest)
		return
	}
	ctx := r.Context()

	scan, err := h.db.GetScan(ctx, scanID)
	if err != nil || scan == nil {
		jsonError(w, "scan not found", http.StatusNotFound)
		return
	}
	userID, ok := middleware.GetUserID(ctx)
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if member, _ := h.db.IsOrgMember(ctx, userID, scan.OrgID); !member {
		jsonError(w, "scan not found", http.StatusNotFound)
		return
	}

	var gov map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&gov); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if gov == nil {
		gov = map[string]interface{}{}
	}

	findings, _ := h.db.ListFindings(ctx, scanID)
	gf := make([]map[string]interface{}, 0, len(findings))
	for _, f := range findings {
		gf = append(gf, map[string]interface{}{
			"title":       f.Title,
			"severity":    f.Severity,
			"module":      f.Module,
			"endpoint":    f.Endpoint,
			"description": f.Description,
			"cwe_id":      f.CWEID,
			"owasp_ref":   f.OWASPRef,
		})
	}
	gov["scan_id"] = scanID.String()
	gov["findings"] = gf
	if t, _ := gov["document_title"].(string); t == "" {
		gov["document_title"] = scan.Name
	}

	body, err := json.Marshal(gov)
	if err != nil {
		jsonError(w, "failed to build request", http.StatusInternalServerError)
		return
	}
	resp, err := h.httpClient.Post(h.reportURL+"/report/governance", "application/json", bytes.NewReader(body))
	if err != nil {
		jsonError(w, fmt.Sprintf("report engine unavailable: %v", err), http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		jsonError(w, "report engine returned error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/vnd.openxmlformats-officedocument.wordprocessingml.document")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="harbore-isms-%s.docx"`, scanID.String()[:8]))
	_, _ = io.Copy(w, resp.Body)
}
