// Package semgrep wraps the semgrep CLI and converts its SARIF-ish JSON
// output into normalized Finding records.
package semgrep

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/penanamtomat/supplychain-kit/internal/models"
	"github.com/penanamtomat/supplychain-kit/internal/scanner"
)

// Adapter wraps the semgrep CLI.
type Adapter struct {
	binary string
	config string // e.g. "p/owasp-top-ten" or a path to a custom rule pack
}

// New returns an Adapter that loads the OWASP top-ten rule pack by default.
func New() *Adapter { return &Adapter{binary: "semgrep", config: "p/owasp-top-ten"} }

// WithConfig overrides the rule pack used at scan time.
func (a *Adapter) WithConfig(cfg string) *Adapter { a.config = cfg; return a }

func (a *Adapter) Name() string                  { return "semgrep" }
func (a *Adapter) Source() models.FindingSource { return models.SourceSemgrep }

// Scan runs `semgrep --json` against the checkout directory.
func (a *Adapter) Scan(ctx context.Context, req scanner.Request) (scanner.Result, error) {
	out := scanner.Result{Source: a.Source()}

	cmd := exec.CommandContext(ctx, a.binary, "--config", a.config, "--json", "--quiet", req.CheckoutDir)
	stdout, err := cmd.Output()
	if err != nil {
		// Semgrep returns non-zero when findings exist; treat exit error 1
		// as "findings present" rather than a hard failure.
		if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() > 1 {
			return out, fmt.Errorf("semgrep: %w", err)
		}
	}

	var report semgrepReport
	if err := json.Unmarshal(stdout, &report); err != nil {
		return out, fmt.Errorf("parse semgrep json: %w", err)
	}

	now := time.Now().UTC()
	for _, r := range report.Results {
		f := &models.Finding{
			ID:          uuid.NewString(),
			AssetID:     req.AssetID,
			ScanRunID:   req.ScanRunID,
			Sources:     []models.FindingSource{models.SourceSemgrep},
			RuleID:      r.CheckID,
			Title:       firstLine(r.Extra.Message),
			Description: r.Extra.Message,
			Severity:    mapSeverity(r.Extra.Severity),
			FilePath:    relPath(req.CheckoutDir, r.Path),
			Line:        r.Start.Line,
			Reachability: models.ReachUnknown,
			FirstSeen:    now,
			LastSeen:     now,
		}
		f.Fingerprint = fingerprint(f)
		out.Findings = append(out.Findings, f)
	}
	return out, nil
}

// --- Semgrep JSON shape (subset) ---

type semgrepReport struct {
	Results []struct {
		CheckID string `json:"check_id"`
		Path    string `json:"path"`
		Start   struct {
			Line int `json:"line"`
			Col  int `json:"col"`
		} `json:"start"`
		Extra struct {
			Message  string `json:"message"`
			Severity string `json:"severity"` // ERROR / WARNING / INFO
		} `json:"extra"`
	} `json:"results"`
}

func mapSeverity(s string) models.Severity {
	switch strings.ToUpper(s) {
	case "ERROR":
		return models.SeverityHigh
	case "WARNING":
		return models.SeverityMedium
	case "INFO":
		return models.SeverityLow
	}
	return models.SeverityInfo
}

func relPath(base, abs string) string {
	if strings.HasPrefix(abs, base) {
		return strings.TrimPrefix(strings.TrimPrefix(abs, base), "/")
	}
	return abs
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func fingerprint(f *models.Finding) string {
	h := sha1.New()
	fmt.Fprintf(h, "%s|%s|%s|%d", f.RuleID, f.Package, f.FilePath, f.Line)
	return hex.EncodeToString(h.Sum(nil))
}
