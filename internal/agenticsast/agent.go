// Package agenticsast implements snippet-level SAST for AI-generated code.
// It scans a raw code fragment with Semgrep and returns findings immediately,
// enabling pre-commit or IDE-level feedback without a full CI cycle.
// The HTTP transport layer is added in v0.8 (Claude Code / MCP integration).
package agenticsast

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/uuid"

	"github.com/penanamtomat/supplychain-kit/internal/models"
	"github.com/penanamtomat/supplychain-kit/internal/scanner"
	"github.com/penanamtomat/supplychain-kit/internal/scanner/semgrep"
)

// SnippetRequest describes a code snippet to analyse.
type SnippetRequest struct {
	AssetID  string `json:"asset_id,omitempty"`
	Language string `json:"language"`
	Code     string `json:"code"`
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

	for _, f := range result.Findings {
		f.Fingerprint = snippetFingerprint(req.Code, f.RuleID, f.Line)
	}
	return result.Findings, nil
}

func snippetFingerprint(code, ruleID string, line int) string {
	h := sha1.New()
	_, _ = fmt.Fprintf(h, "%s|%s|%d", ruleID, code, line)
	return hex.EncodeToString(h.Sum(nil))
}
