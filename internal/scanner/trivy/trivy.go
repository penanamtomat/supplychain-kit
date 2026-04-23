// Package trivy wraps the trivy CLI to produce normalized vulnerability findings.
// It scans a directory with `trivy fs --format json` or an SBOM with `trivy sbom`.
package trivy

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

// Adapter wraps the trivy CLI.
type Adapter struct {
	binary string
}

// New returns a new Trivy Adapter.
func New() *Adapter { return &Adapter{binary: "trivy"} }

// NewWithBinary returns an Adapter using the supplied binary path — useful in tests.
func NewWithBinary(bin string) *Adapter { return &Adapter{binary: bin} }

func (a *Adapter) Name() string                  { return "trivy" }
func (a *Adapter) Source() models.FindingSource { return models.SourceTrivy }

// Scan runs trivy against the checkout directory (or SBOM if available).
func (a *Adapter) Scan(ctx context.Context, req scanner.Request) (scanner.Result, error) {
	out := scanner.Result{Source: a.Source()}
	if err := scanner.CheckBinary(a.binary); err != nil {
		return out, err
	}

	var args []string
	if req.SBOMPath != "" {
		args = []string{"sbom", "--format", "json", "--quiet", req.SBOMPath}
	} else {
		args = []string{"fs", "--format", "json", "--quiet", req.CheckoutDir}
	}

	cmd := exec.CommandContext(ctx, a.binary, args...)
	cmd.Stderr = os.Stderr
	stdout, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() != 0 {
			// trivy exits non-zero when vulnerabilities are found; still parse output
			if len(stdout) == 0 {
				return out, fmt.Errorf("trivy: %w", err)
			}
		} else if err != nil && len(stdout) == 0 {
			return out, fmt.Errorf("trivy: %w", err)
		}
	}

	findings, err := ParseReport(stdout, req.AssetID, req.ScanRunID)
	if err != nil {
		return out, err
	}
	out.Findings = findings
	return out, nil
}

// ParseReport converts raw trivy JSON output into Finding records.
func ParseReport(raw []byte, assetID, scanRunID string) ([]*models.Finding, error) {
	var report trivyReport
	if err := json.Unmarshal(raw, &report); err != nil {
		return nil, fmt.Errorf("parse trivy json: %w", err)
	}
	now := time.Now().UTC()
	var out []*models.Finding
	for _, result := range report.Results {
		for _, v := range result.Vulnerabilities {
			f := &models.Finding{
				ID:           uuid.NewString(),
				AssetID:      assetID,
				ScanRunID:    scanRunID,
				Sources:      []models.FindingSource{models.SourceTrivy},
				RuleID:       v.VulnerabilityID,
				Title:        fmt.Sprintf("%s in %s@%s", v.VulnerabilityID, v.PkgName, v.InstalledVersion),
				Description:  v.Description,
				Severity:     mapSeverity(v.Severity),
				CVSS:         pickCVSS(v.CVSS),
				Package:      v.PkgName,
				Version:      v.InstalledVersion,
				FixedVersion: v.FixedVersion,
				AdvisoryURL:  advisoryURL(v.VulnerabilityID),
				FilePath:     result.Target,
				Reachability: models.ReachUnknown,
				FirstSeen:    now,
				LastSeen:     now,
			}
			f.Fingerprint = fingerprint(f)
			out = append(out, f)
		}
	}
	return out, nil
}

// --- Trivy JSON shape (subset) ---

type trivyReport struct {
	Results []trivyResult `json:"Results"`
}

type trivyResult struct {
	Target          string           `json:"Target"`
	Vulnerabilities []trivyVuln      `json:"Vulnerabilities"`
}

type trivyVuln struct {
	VulnerabilityID  string              `json:"VulnerabilityID"`
	PkgName          string              `json:"PkgName"`
	InstalledVersion string              `json:"InstalledVersion"`
	FixedVersion     string              `json:"FixedVersion"`
	Severity         string              `json:"Severity"`
	Description      string              `json:"Description"`
	CVSS             map[string]trivyCVSS `json:"CVSS"`
}

type trivyCVSS struct {
	V3Score float64 `json:"V3Score"`
	V2Score float64 `json:"V2Score"`
}

func mapSeverity(s string) models.Severity {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return models.SeverityCritical
	case "HIGH":
		return models.SeverityHigh
	case "MEDIUM":
		return models.SeverityMedium
	case "LOW":
		return models.SeverityLow
	}
	return models.SeverityInfo
}

func pickCVSS(scores map[string]trivyCVSS) float64 {
	var best float64
	for _, c := range scores {
		if c.V3Score > best {
			best = c.V3Score
		}
	}
	return best
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
