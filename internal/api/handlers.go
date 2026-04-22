package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/penanamtomat/supplychain-kit/internal/agenticsast"
	"github.com/penanamtomat/supplychain-kit/internal/ingestion"
	"github.com/penanamtomat/supplychain-kit/internal/models"
	"github.com/penanamtomat/supplychain-kit/internal/quality"
	"github.com/penanamtomat/supplychain-kit/internal/storage"
)

// Handlers groups every HTTP handler so dependencies are injected once.
type Handlers struct {
	Store          *storage.Store
	Queue          *ingestion.Queue
	Gate           *quality.Evaluator
	AgenticAgent   *agenticsast.Agent
	RemediationURL string
}

// Health is the readiness/liveness endpoint used by orchestrators.
func (h *Handlers) Health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// CreateScan enqueues a new scan job.
func (h *Handlers) CreateScan(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AssetID string `json:"asset_id"`
		RepoURL string `json:"repo_url"`
		Ref     string `json:"ref"`
		Trigger string `json:"trigger"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	if req.RepoURL == "" {
		writeError(w, http.StatusBadRequest, "repo_url required")
		return
	}
	scanReq := models.ScanRequest{
		ID:        uuid.NewString(),
		AssetID:   req.AssetID,
		RepoURL:   req.RepoURL,
		Ref:       defaultStr(req.Ref, "HEAD"),
		Trigger:   defaultStr(req.Trigger, "manual"),
		CreatedAt: time.Now().UTC(),
	}
	if err := h.Queue.Enqueue(r.Context(), scanReq); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, scanReq)
}

// GetScan returns a scan run record by id.
func (h *Handlers) GetScan(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	writeJSON(w, http.StatusOK, map[string]string{"id": id, "status": "see /findings?scan_run_id=..."})
}

// ListFindings is a paginated, filterable view over findings.
func (h *Handlers) ListFindings(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	filter := storage.FindingFilter{
		AssetID:      q.Get("asset_id"),
		Severity:     models.Severity(q.Get("severity")),
		Reachability: models.Reachability(q.Get("reachability")),
	}
	findings, err := h.Store.ListFindings(r.Context(), filter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, findings)
}

// GetFinding returns a single finding (placeholder; storage method elided for brevity).
func (h *Handlers) GetFinding(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"id": chi.URLParam(r, "id")})
}

// UpsertAsset accepts an Asset payload and persists it.
func (h *Handlers) UpsertAsset(w http.ResponseWriter, r *http.Request) {
	var a models.Asset
	if err := json.NewDecoder(r.Body).Decode(&a); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	if a.ID == "" {
		a.ID = uuid.NewString()
	}
	if err := h.Store.UpsertAsset(r.Context(), &a); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, a)
}

// GetAsset fetches an asset by id.
func (h *Handlers) GetAsset(w http.ResponseWriter, r *http.Request) {
	a, err := h.Store.GetAsset(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, a)
}

// AssetRisk returns a rolled-up risk summary for the asset.
func (h *Handlers) AssetRisk(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	findings, err := h.Store.ListFindings(r.Context(), storage.FindingFilter{AssetID: id, Limit: 500})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	summary := struct {
		AssetID         string  `json:"asset_id"`
		FindingCount    int     `json:"finding_count"`
		MaxRiskScore    float64 `json:"max_risk_score"`
		AvgRiskScore    float64 `json:"avg_risk_score"`
		ReachableCount  int     `json:"reachable_count"`
		CriticalCount   int     `json:"critical_count"`
	}{AssetID: id}

	var sum float64
	for _, f := range findings {
		summary.FindingCount++
		sum += f.RiskScore
		if f.RiskScore > summary.MaxRiskScore {
			summary.MaxRiskScore = f.RiskScore
		}
		if f.Reachability == models.ReachReachable || f.Reachability == models.ReachConfirmed {
			summary.ReachableCount++
		}
		if f.Severity == models.SeverityCritical {
			summary.CriticalCount++
		}
	}
	if summary.FindingCount > 0 {
		summary.AvgRiskScore = sum / float64(summary.FindingCount)
	}
	writeJSON(w, http.StatusOK, summary)
}

// EvaluateGate runs the quality gate against a supplied finding set (typically
// produced by `aspm-cli scan` and POSTed during CI).
func (h *Handlers) EvaluateGate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Findings []*models.Finding `json:"findings"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	result := h.Gate.Evaluate(req.Findings)
	writeJSON(w, http.StatusOK, result)
}

// RequestVEX delegates VEX generation to the Python remediation service.
func (h *Handlers) RequestVEX(w http.ResponseWriter, r *http.Request) {
	if h.RemediationURL == "" {
		writeError(w, http.StatusServiceUnavailable, "remediation service not configured")
		return
	}
	// Forward verbatim to the Python service. In production this would also
	// add tracing headers and an auth token.
	proxyURL := h.RemediationURL + "/vex"
	proxyRequest(r.Context(), w, r, proxyURL)
}

// GithubWebhook accepts push and PR events from GitHub.
func (h *Handlers) GithubWebhook(w http.ResponseWriter, r *http.Request) {
	if err := ingestion.HandleGitHubWebhook(r, h.Queue); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// GitlabWebhook accepts Push Hook and Merge Request Hook events from GitLab.
func (h *Handlers) GitlabWebhook(w http.ResponseWriter, r *http.Request) {
	if err := ingestion.HandleGitLabWebhook(r, h.Queue); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// BitbucketWebhook accepts repo:push and pullrequest events from Bitbucket Cloud.
func (h *Handlers) BitbucketWebhook(w http.ResponseWriter, r *http.Request) {
	if err := ingestion.HandleBitbucketWebhook(r, h.Queue); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// AgenticSAST analyses a raw code snippet posted by an IDE extension or AI
// coding assistant and returns findings immediately.
func (h *Handlers) AgenticSAST(w http.ResponseWriter, r *http.Request) {
	if h.AgenticAgent == nil {
		writeError(w, http.StatusServiceUnavailable, "agentic SAST not configured")
		return
	}
	h.AgenticAgent.Handler()(w, r)
}

func defaultStr(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

func proxyRequest(ctx context.Context, w http.ResponseWriter, r *http.Request, url string) {
	req, err := http.NewRequestWithContext(ctx, r.Method, url, r.Body)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	req.Header.Set("Content-Type", r.Header.Get("Content-Type"))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	defer resp.Body.Close()

	w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}
