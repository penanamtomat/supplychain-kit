// Package gitleaks wraps the gitleaks CLI to surface secret-scanning findings
// out of the repository's working tree (and optionally its git history).
package gitleaks

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/google/uuid"

	"github.com/penanamtomat/supplychain-kit/internal/models"
	"github.com/penanamtomat/supplychain-kit/internal/scanner"
)

// Adapter wraps the gitleaks CLI.
type Adapter struct{ binary string }

// New returns a new gitleaks Adapter.
func New() *Adapter { return &Adapter{binary: "gitleaks"} }

func (a *Adapter) Name() string                  { return "gitleaks" }
func (a *Adapter) Source() models.FindingSource { return models.SourceGitleaks }

func (a *Adapter) Scan(ctx context.Context, req scanner.Request) (scanner.Result, error) {
	out := scanner.Result{Source: a.Source()}

	report := filepath.Join(req.CheckoutDir, ".aspm", "gitleaks.json")
	if err := os.MkdirAll(filepath.Dir(report), 0o755); err != nil {
		return out, err
	}

	cmd := exec.CommandContext(ctx, a.binary, "detect", "--source", req.CheckoutDir, "--no-git",
		"--report-format", "json", "--report-path", report, "--exit-code", "0")
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return out, fmt.Errorf("gitleaks: %w", err)
	}

	raw, err := os.ReadFile(report)
	if err != nil {
		return out, err
	}
	var leaks []gitleakLeak
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &leaks); err != nil {
			return out, err
		}
	}

	now := time.Now().UTC()
	for _, l := range leaks {
		f := &models.Finding{
			ID:          uuid.NewString(),
			AssetID:     req.AssetID,
			ScanRunID:   req.ScanRunID,
			Sources:     []models.FindingSource{models.SourceGitleaks},
			RuleID:      "gitleaks." + l.RuleID,
			Title:       fmt.Sprintf("Secret detected: %s", l.Description),
			Description: l.Match,
			Severity:    models.SeverityHigh,
			FilePath:    l.File,
			Line:        l.StartLine,
			// Secrets are always treated as reachable: presence is the risk.
			Reachability: models.ReachReachable,
			FirstSeen:    now,
			LastSeen:     now,
		}
		f.Fingerprint = fingerprint(f)
		out.Findings = append(out.Findings, f)
	}
	return out, nil
}

type gitleakLeak struct {
	Description string `json:"Description"`
	StartLine   int    `json:"StartLine"`
	File        string `json:"File"`
	Match       string `json:"Match"`
	RuleID      string `json:"RuleID"`
}

func fingerprint(f *models.Finding) string {
	h := sha1.New()
	fmt.Fprintf(h, "%s|%s|%d", f.RuleID, f.FilePath, f.Line)
	return hex.EncodeToString(h.Sum(nil))
}
