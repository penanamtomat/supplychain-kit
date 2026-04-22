// Package types holds public, importable Go types intended for external
// consumers (other services, custom CI plugins, etc.). The internal/models
// package mirrors a superset; this package re-exports the stable subset.
package types

import "github.com/penanamtomat/supplychain-kit/internal/models"

// Public re-exports.
type (
	Asset        = models.Asset
	Finding      = models.Finding
	Severity     = models.Severity
	Reachability = models.Reachability
	SBOM         = models.SBOM
	ScanRequest  = models.ScanRequest
)
