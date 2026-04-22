// Package grype consumes a CycloneDX SBOM produced by Syft and emits
// normalized vulnerability findings. SBOM-first matching avoids re-walking
// the source tree on every CI invocation.
package grype

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os/exec"
	"time"

	"github.com/google/uuid"

	"github.com/penanamtomat/supplychain-kit/internal/models"
	"github.com/penanamtomat/supplychain-kit/internal/scanner"
	syftadapter "github.com/penanamtomat/supplychain-kit/internal/scanner/syft"
)

// Adapter wraps the grype CLI.
type Adapter struct {
	binary string
}

// New returns a new Grype Adapter.
func New() *Adapter { return &Adapter{binary: "grype"} }

func (a *Adapter) Name() string                  { return "grype" }
func (a *Adapter) Source() models.FindingSource { return models.SourceGrype }

// Scan reads the SBOM produced by syft (Request.SBOMPath or Artifact in a
// preceding step) and parses grype's JSON output into Finding records.
func (a *Adapter) Scan(ctx context.Context, req scanner.Request) (scanner.Result, error) {
	out := scanner.Result{Source: a.Source()}

	sbom := req.SBOMPath
	if sbom == "" {
		sbom = req.CheckoutDir + "/.aspm/sbom.cdx.json"
	}

	cmd := exec.CommandContext(ctx, a.binary, "sbom:"+sbom, "-o", "json", "--quiet")
	stdout, err := cmd.Output()
	if err != nil {
		return out, fmt.Errorf("grype: %w", err)
	}

	var report grypeReport
	if err := json.Unmarshal(stdout, &report); err != nil {
		return out, fmt.Errorf("parse grype json: %w", err)
	}

	now := time.Now().UTC()
	for _, m := range report.Matches {
		f := &models.Finding{
			ID:           uuid.NewString(),
			AssetID:      req.AssetID,
			ScanRunID:    req.ScanRunID,
			Sources:      []models.FindingSource{models.SourceGrype},
			RuleID:       m.Vulnerability.ID,
			Title:        fmt.Sprintf("%s in %s@%s", m.Vulnerability.ID, m.Artifact.Name, m.Artifact.Version),
			Description:  m.Vulnerability.Description,
			Severity:     mapSeverity(m.Vulnerability.Severity),
			CVSS:         pickCVSS(m.Vulnerability.CVSS),
			Package:      m.Artifact.Name,
			Version:      m.Artifact.Version,
			FixedVersion: pickFixVersion(m.Vulnerability.Fix),
			Reachability: models.ReachUnknown,
			FirstSeen:    now,
			LastSeen:     now,
		}
		f.Fingerprint = fingerprint(f)
		out.Findings = append(out.Findings, f)
	}

	// Make the SBOM artifact discoverable for downstream stages even when
	// grype is invoked standalone (e.g., in `aspm-cli scan-sbom`).
	out.Artifacts = map[string]string{syftadapter.ArtifactSBOMPath: sbom}
	return out, nil
}

// --- Grype JSON shape (subset) ---

type grypeReport struct {
	Matches []struct {
		Vulnerability struct {
			ID          string  `json:"id"`
			Severity    string  `json:"severity"`
			Description string  `json:"description"`
			CVSS        []cvss  `json:"cvss"`
			Fix         grypeFix `json:"fix"`
		} `json:"vulnerability"`
		Artifact struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			PURL    string `json:"purl"`
		} `json:"artifact"`
	} `json:"matches"`
}

type cvss struct {
	Version string `json:"version"`
	Metrics struct {
		BaseScore float64 `json:"baseScore"`
	} `json:"metrics"`
}

type grypeFix struct {
	Versions []string `json:"versions"`
	State    string   `json:"state"`
}

func mapSeverity(s string) models.Severity {
	switch s {
	case "Critical":
		return models.SeverityCritical
	case "High":
		return models.SeverityHigh
	case "Medium":
		return models.SeverityMedium
	case "Low":
		return models.SeverityLow
	}
	return models.SeverityInfo
}

func pickCVSS(scores []cvss) float64 {
	var best float64
	for _, c := range scores {
		if c.Metrics.BaseScore > best {
			best = c.Metrics.BaseScore
		}
	}
	return best
}

func pickFixVersion(f grypeFix) string {
	if len(f.Versions) == 0 {
		return ""
	}
	return f.Versions[0]
}

func fingerprint(f *models.Finding) string {
	h := sha1.New()
	fmt.Fprintf(h, "%s|%s|%s|%s|%d", f.RuleID, f.Package, f.Version, f.FilePath, f.Line)
	return hex.EncodeToString(h.Sum(nil))
}
