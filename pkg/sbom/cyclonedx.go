// Package sbom contains lightweight helpers for working with CycloneDX SBOMs
// outside of the scanner adapter (e.g., for CI plugins that need to consume
// stored SBOMs).
package sbom

import (
	"encoding/json"
	"fmt"
)

// CycloneDX represents the minimal subset of fields the platform consumes.
type CycloneDX struct {
	BOMFormat   string      `json:"bomFormat"`
	SpecVersion string      `json:"specVersion"`
	Components  []Component `json:"components"`
}

// Component is a single SBOM entry.
type Component struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version"`
	PURL    string `json:"purl"`
}

// Parse decodes raw CycloneDX JSON into the in-memory representation.
func Parse(raw []byte) (*CycloneDX, error) {
	var doc CycloneDX
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("decode cyclonedx: %w", err)
	}
	return &doc, nil
}
