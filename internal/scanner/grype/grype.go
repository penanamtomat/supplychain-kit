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
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/penanamtomat/supplychain-kit/internal/models"
	"github.com/penanamtomat/supplychain-kit/internal/scanner"
)

// Adapter wraps the grype CLI.
type Adapter struct {
	binary string
}

// New returns a new Grype Adapter.
func New() *Adapter { return &Adapter{binary: "grype"} }

// NewWithBinary returns an Adapter using the supplied binary path — useful in tests.
func NewWithBinary(bin string) *Adapter { return &Adapter{binary: bin} }

func (a *Adapter) Name() string                  { return "grype" }
func (a *Adapter) Source() models.FindingSource { return models.SourceGrype }

// Scan reads the SBOM produced by syft (Request.SBOMPath or Artifact in a
// preceding step) and parses grype's JSON output into Finding records.
func (a *Adapter) Scan(ctx context.Context, req scanner.Request) (scanner.Result, error) {
	out := scanner.Result{Source: a.Source()}
	if err := scanner.CheckBinary(a.binary); err != nil {
		return out, err
	}

	sbom := req.SBOMPath
	if sbom == "" {
		sbom = req.CheckoutDir + "/.aspm/sbom.cdx.json"
	}

	cmd := exec.CommandContext(ctx, a.binary, "sbom:"+sbom, "-o", "json", "--quiet")
	cmd.Stderr = os.Stderr
	stdout, err := cmd.Output()
	if err != nil {
		return out, fmt.Errorf("grype: %w", err)
	}

	findings, err := ParseReport(stdout, req.AssetID, req.ScanRunID)
	if err != nil {
		return out, err
	}
	out.Findings = findings
	out.Artifacts = map[string]string{scanner.ArtifactSBOMPath: sbom}
	return out, nil
}

// ParseReport converts raw grype JSON output into Finding records.
// Extracted so tests can exercise parsing logic without invoking the binary.
func ParseReport(raw []byte, assetID, scanRunID string) ([]*models.Finding, error) {
	var report grypeReport
	if err := json.Unmarshal(raw, &report); err != nil {
		return nil, fmt.Errorf("parse grype json: %w", err)
	}
	now := time.Now().UTC()
	out := make([]*models.Finding, 0, len(report.Matches))
	for _, m := range report.Matches {
		f := &models.Finding{
			ID:           uuid.NewString(),
			AssetID:      assetID,
			ScanRunID:    scanRunID,
			Sources:      []models.FindingSource{models.SourceGrype},
			RuleID:       m.Vulnerability.ID,
			Title:        fmt.Sprintf("%s in %s@%s", m.Vulnerability.ID, m.Artifact.Name, m.Artifact.Version),
			Description:  m.Vulnerability.Description,
			Severity:     mapSeverity(m.Vulnerability.Severity),
			CVSS:         pickCVSS(m.Vulnerability.CVSS),
			Package:      m.Artifact.Name,
			Version:      m.Artifact.Version,
			FixedVersion: pickFixVersion(m.Vulnerability.Fix),
			AdvisoryURL:  advisoryURL(m.Vulnerability.ID),
			Reachability: models.ReachUnknown,
			FirstSeen:    now,
			LastSeen:     now,
		}
		f.Fingerprint = fingerprint(f)
		out = append(out, f)
	}
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

func advisoryURL(id string) string {
	switch {
	case strings.HasPrefix(id, "CVE-"):
		return "https://nvd.nist.gov/vuln/detail/" + id
	case strings.HasPrefix(id, "GHSA-"):
		return "https://github.com/advisories/" + id
	}
	return ""
}

func fingerprint(f *models.Finding) string {
	h := sha1.New()
	_, _ = fmt.Fprintf(h, "%s|%s|%s|%s|%d", f.RuleID, f.Package, f.Version, f.FilePath, f.Line)
	return hex.EncodeToString(h.Sum(nil))
}
