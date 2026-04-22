// Package agenticsast implements "Agentic SAST" as described in PRD §3.2:
// scanning AI-generated code snippets before they are committed. It exposes
// an HTTP handler that IDE extensions and AI coding assistant hooks (GitHub
// Copilot, Claude Code) can call with a raw code fragment. The handler runs
// Semgrep in-process on a temp file and returns findings immediately so the
// assistant can surface feedback to the developer without a full CI cycle.
package agenticsast

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"

	"github.com/penanamtomat/supplychain-kit/internal/models"
	"github.com/penanamtomat/supplychain-kit/internal/scanner"
	"github.com/penanamtomat/supplychain-kit/internal/scanner/semgrep"
)

// SnippetRequest is the payload posted by an IDE extension or AI assistant.
type SnippetRequest struct {
	// AssetID ties the finding to a tracked repository (optional; can be empty
	// for anonymous pre-commit checks).
	AssetID  string `json:"asset_id,omitempty"`
	// Language hint passed as a file extension (e.g. "go", "py", "js").
	Language string `json:"language"`
	// Code is the raw source snippet to analyse.
	Code     string `json:"code"`
}

// SnippetResponse wraps the findings produced for the snippet.
type SnippetResponse struct {
	Findings []*models.Finding `json:"findings"`
	Duration string            `json:"duration_ms"`
}

// Agent holds the Semgrep adapter used for in-line scanning.
type Agent struct {
	semgrep *semgrep.Adapter
}

// New returns an Agent using the supplied Semgrep rule config.
// Pass an empty string to use the default OWASP rule pack.
func New(semgrepConfig string) *Agent {
	a := semgrep.New()
	if semgrepConfig != "" {
		a = a.WithConfig(semgrepConfig)
	}
	return &Agent{semgrep: a}
}

// Analyse scans a raw code snippet and returns any findings immediately.
// It writes the snippet to a temporary file, runs Semgrep, then cleans up.
func (ag *Agent) Analyse(ctx context.Context, req SnippetRequest) ([]*models.Finding, error) {
	if req.Code == "" {
		return nil, fmt.Errorf("agenticsast: code snippet is empty")
	}
	lang := req.Language
	if lang == "" {
		lang = "txt"
	}

	tmpDir, err := os.MkdirTemp("", "agenticsast-*")
	if err != nil {
		return nil, fmt.Errorf("agenticsast: create temp dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	snippetFile := filepath.Join(tmpDir, "snippet."+lang)
	if err := os.WriteFile(snippetFile, []byte(req.Code), 0600); err != nil {
		return nil, fmt.Errorf("agenticsast: write snippet: %w", err)
	}

	scanReq := scanner.Request{
		AssetID:     req.AssetID,
		ScanRunID:   uuid.NewString(),
		CheckoutDir: tmpDir,
	}
	result, err := ag.semgrep.Scan(ctx, scanReq)
	if err != nil {
		return nil, fmt.Errorf("agenticsast: semgrep: %w", err)
	}

	// Re-fingerprint relative to the snippet content so identical snippets
	// produce the same fingerprint regardless of the temp path.
	for _, f := range result.Findings {
		f.Fingerprint = snippetFingerprint(req.Code, f.RuleID, f.Line)
	}
	return result.Findings, nil
}

// Handler returns an http.HandlerFunc suitable for mounting on the API router.
// POST /api/v1/agentic-sast
func (ag *Agent) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req SnippetRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid json")
			return
		}
		start := time.Now()
		findings, err := ag.Analyse(r.Context(), req)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		resp := SnippetResponse{
			Findings: findings,
			Duration: fmt.Sprintf("%d", time.Since(start).Milliseconds()),
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}

func snippetFingerprint(code, ruleID string, line int) string {
	h := sha1.New()
	_, _ = fmt.Fprintf(h, "%s|%s|%d", ruleID, code, line)
	return hex.EncodeToString(h.Sum(nil))
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
