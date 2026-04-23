// Package osvscanner wraps the osv-scanner CLI to produce normalized vulnerability
// findings from Google's OSV database — broader Go/Rust/Python coverage than NVD.
package osvscanner

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

// Adapter wraps the osv-scanner CLI.
type Adapter struct {
	binary string
}

// New returns a new OSV Scanner Adapter.
func New() *Adapter { return &Adapter{binary: "osv-scanner"} }

// NewWithBinary returns an Adapter using the supplied binary path — useful in tests.
func NewWithBinary(bin string) *Adapter { return &Adapter{binary: bin} }

func (a *Adapter) Name() string                  { return "osv-scanner" }
func (a *Adapter) Source() models.FindingSource { return models.SourceOSVScanner }

// Scan runs osv-scanner against the checkout directory (or SBOM if available).
func (a *Adapter) Scan(ctx context.Context, req scanner.Request) (scanner.Result, error) {
	out := scanner.Result{Source: a.Source()}
	if err := scanner.CheckBinary(a.binary); err != nil {
		return out, err
	}

	var args []string
	if req.SBOMPath != "" {
		args = []string{"--format", "json", "--sbom", req.SBOMPath}
	} else {
		args = []string{"--format", "json", "--recursive", req.CheckoutDir}
	}

	cmd := exec.CommandContext(ctx, a.binary, args...)
	cmd.Stderr = os.Stderr
	stdout, err := cmd.Output()
	if err != nil {
		// osv-scanner exits 1 when vulnerabilities are found — still parse
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			if len(stdout) == 0 {
				return out, fmt.Errorf("osv-scanner: %w", err)
			}
		} else if err != nil && len(stdout) == 0 {
			return out, fmt.Errorf("osv-scanner: %w", err)
		}
	}

	findings, err := ParseReport(stdout, req.AssetID, req.ScanRunID)
	if err != nil {
		return out, err
	}
	out.Findings = findings
	return out, nil
}

// ParseReport converts raw osv-scanner JSON output into Finding records.
func ParseReport(raw []byte, assetID, scanRunID string) ([]*models.Finding, error) {
	var report osvReport
	if err := json.Unmarshal(raw, &report); err != nil {
		return nil, fmt.Errorf("parse osv-scanner json: %w", err)
	}
	now := time.Now().UTC()
	var out []*models.Finding
	for _, result := range report.Results {
		for _, pkg := range result.Packages {
			for _, vuln := range pkg.Vulnerabilities {
				sev := pickOSVSeverity(vuln)
				f := &models.Finding{
					ID:        uuid.NewString(),
					AssetID:   assetID,
					ScanRunID: scanRunID,
					Sources:   []models.FindingSource{models.SourceOSVScanner},
					RuleID:    vuln.ID,
					Title:     fmt.Sprintf("%s in %s@%s", vuln.ID, pkg.Package.Name, pkg.Package.Version),
					Severity:  sev,
					Package:   pkg.Package.Name,
					Version:   pkg.Package.Version,
					AdvisoryURL: osvAdvisoryURL(vuln.ID),
					FilePath:  result.Source.Path,
					Reachability: models.ReachUnknown,
					FirstSeen: now,
					LastSeen:  now,
				}
				f.Fingerprint = fingerprint(f)
				out = append(out, f)
			}
		}
	}
	return out, nil
}

// --- osv-scanner JSON shape (subset) ---

type osvReport struct {
	Results []osvResult `json:"results"`
}

type osvResult struct {
	Source   osvSource    `json:"source"`
	Packages []osvPackage `json:"packages"`
}

type osvSource struct {
	Path string `json:"path"`
	Type string `json:"type"`
}

type osvPackage struct {
	Package       osvPkgInfo  `json:"package"`
	Vulnerabilities []osvVuln `json:"vulnerabilities"`
}

type osvPkgInfo struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"`
}

type osvVuln struct {
	ID       string           `json:"id"`
	Aliases  []string         `json:"aliases"`
	Summary  string           `json:"summary"`
	Severity []osvSeverity    `json:"severity"`
}

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

func pickOSVSeverity(v osvVuln) models.Severity {
	for _, s := range v.Severity {
		if s.Type == "CVSS_V3" || s.Type == "CVSS_V2" {
			score := parseCVSSScore(s.Score)
			return cvssToSeverity(score)
		}
	}
	// Fall back to alias-based detection (CVE aliases sometimes carry severity context)
	return models.SeverityInfo
}

func parseCVSSScore(vector string) float64 {
	// CVSS vector strings encode base score as "CVSS:3.1/AV:.../..." — score not embedded.
	// osv-scanner severity score field may be a raw float string in some versions.
	var score float64
	_, _ = fmt.Sscanf(vector, "%f", &score)
	return score
}

func cvssToSeverity(score float64) models.Severity {
	switch {
	case score >= 9.0:
		return models.SeverityCritical
	case score >= 7.0:
		return models.SeverityHigh
	case score >= 4.0:
		return models.SeverityMedium
	case score > 0:
		return models.SeverityLow
	}
	return models.SeverityInfo
}

func osvAdvisoryURL(id string) string {
	switch {
	case strings.HasPrefix(id, "CVE-"):
		return "https://nvd.nist.gov/vuln/detail/" + id
	case strings.HasPrefix(id, "GHSA-"):
		return "https://github.com/advisories/" + id
	case strings.HasPrefix(id, "GO-"):
		return "https://pkg.go.dev/vuln/" + id
	}
	return "https://osv.dev/vulnerability/" + id
}

func fingerprint(f *models.Finding) string {
	h := sha1.New()
	_, _ = fmt.Fprintf(h, "%s|%s|%s|%s|%d", f.RuleID, f.Package, f.Version, f.FilePath, f.Line)
	return hex.EncodeToString(h.Sum(nil))
}
