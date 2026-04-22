// Package scanner defines the contract every concrete scanner adapter must
// satisfy. Adapters live in subpackages (syft, grype, semgrep, joern, gitleaks)
// and are wired into the orchestrator through registry.go.
package scanner

import (
	"context"

	"github.com/penanamtomat/supplychain-kit/internal/models"
)

// Request is the workspace handed to an adapter.
type Request struct {
	ScanRunID string
	AssetID   string
	// CheckoutDir is a freshly cloned working tree the adapter may read.
	CheckoutDir string
	// SBOMPath is populated for SCA matchers that consume an existing SBOM.
	SBOMPath string
}

// Result is the adapter's normalized output.
type Result struct {
	Source   models.FindingSource
	Findings []*models.Finding
	// Artifacts allows adapters to surface side-products like an SBOM file
	// path or CPG export so downstream stages can pick them up.
	Artifacts map[string]string
}

// Artifact keys written into Result.Artifacts by adapters.
const (
	ArtifactSBOMPath = "sbom_path" // path to CycloneDX JSON written by syft
	ArtifactCPGPath  = "cpg_path"  // path to Joern CPG export directory
)

// Scanner is the universal adapter contract.
type Scanner interface {
	Name() string
	Source() models.FindingSource
	Scan(ctx context.Context, req Request) (Result, error)
}
