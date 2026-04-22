// Package syft wraps the syft CLI to produce a CycloneDX 1.5 SBOM for a
// checkout directory. The SBOM file path is exposed via Result.Artifacts so
// that the Grype adapter can consume it without re-walking the filesystem.
package syft

import (
	"context"
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

// ArtifactSBOMPath re-exports the canonical key from the parent scanner package
// so callers that only import this subpackage can still reference it.
const ArtifactSBOMPath = scanner.ArtifactSBOMPath

// Adapter is the syft scanner adapter.
type Adapter struct {
	binary string // override for tests; defaults to "syft" on PATH
	format string // "cyclonedx-json" or "spdx-json"
}

// New returns a new syft Adapter using CycloneDX 1.5 output.
func New() *Adapter { return &Adapter{binary: "syft", format: "cyclonedx-json"} }

// NewWithBinary returns an Adapter using the supplied binary path — useful in tests.
func NewWithBinary(bin string) *Adapter { return &Adapter{binary: bin, format: "cyclonedx-json"} }

// NewWithFormat returns an Adapter that emits the requested SBOM format.
// Accepted values: "cyclonedx" / "cyclonedx-json" (default) and "spdx" / "spdx-json".
func NewWithFormat(fmt string) *Adapter {
	f := "cyclonedx-json"
	if fmt == "spdx" || fmt == "spdx-json" {
		f = "spdx-json"
	}
	return &Adapter{binary: "syft", format: f}
}

func (a *Adapter) Name() string                  { return "syft" }
func (a *Adapter) Source() models.FindingSource { return models.SourceSyft }

// Scan invokes `syft <dir> -o cyclonedx-json` and persists the SBOM under the
// scanner's working directory. Findings list is empty (syft is informational).
func (a *Adapter) Scan(ctx context.Context, req scanner.Request) (scanner.Result, error) {
	out := scanner.Result{Source: a.Source(), Artifacts: map[string]string{}}
	if err := scanner.CheckBinary(a.binary); err != nil {
		return out, err
	}

	ext := "cdx.json"
	if a.format == "spdx-json" {
		ext = "spdx.json"
	}
	sbomPath := filepath.Join(req.CheckoutDir, ".aspm", "sbom."+ext)
	if err := os.MkdirAll(filepath.Dir(sbomPath), 0o755); err != nil {
		return out, fmt.Errorf("mkdir: %w", err)
	}

	cmd := exec.CommandContext(ctx, a.binary, "dir:"+req.CheckoutDir, "-o", a.format+"="+sbomPath, "--quiet")
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return out, fmt.Errorf("syft: %w", err)
	}

	out.Artifacts[ArtifactSBOMPath] = sbomPath
	return out, nil
}

// LoadSBOM reads a CycloneDX JSON document and returns a populated SBOM model.
func LoadSBOM(path, assetID string) (*models.SBOM, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc struct {
		BOMFormat   string `json:"bomFormat"`
		SpecVersion string `json:"specVersion"`
		Components  []struct {
			Type    string `json:"type"`
			Name    string `json:"name"`
			Version string `json:"version"`
			PURL    string `json:"purl"`
		} `json:"components"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	sb := &models.SBOM{
		ID:        uuid.NewString(),
		AssetID:   assetID,
		Format:    "cyclonedx-json",
		SpecVer:   doc.SpecVersion,
		RawJSON:   raw,
		CreatedAt: time.Now().UTC(),
	}
	for _, c := range doc.Components {
		sb.Components = append(sb.Components, models.SBOMComponent{
			PURL: c.PURL, Name: c.Name, Version: c.Version, Type: c.Type,
		})
	}
	return sb, nil
}
