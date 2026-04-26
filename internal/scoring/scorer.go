// Package scoring implements the Integrated Risk Score:
//
//	Risk Score = Severity(CVSS) × Reachability × Exposure × Criticality
//
// The output is scaled to the [0, 100] range so dashboards can render it
// directly without per-customer calibration.
package scoring

import (
	"math"

	"github.com/penanamtomat/supplychain-kit/internal/models"
)

// Scorer is stateless; the zero value is ready to use.
type Scorer struct{}

// Score computes the integrated risk score for a finding given its asset's
// exposure metadata. It mutates the finding's RiskScore field and returns it.
func (Scorer) Score(f *models.Finding, asset *models.Asset) float64 {
	severity := f.CVSS
	if severity == 0 {
		severity = f.Severity.CVSSScore()
	}

	reach := reachabilityFactor(f.Reachability)
	exposure := exposureFactor(asset)
	criticality := criticalityFactor(asset)

	// Raw range: [0, 10] × [0.1, 1] × [0.5, 1.5] × [0.5, 2.0] = [0, 30].
	// Normalize linearly to [0, 100].
	raw := severity * reach * exposure * criticality
	score := math.Min(100, raw*(100.0/30.0))
	f.RiskScore = round2(score)
	return f.RiskScore
}

func reachabilityFactor(r models.Reachability) float64 {
	switch r {
	case models.ReachUnreachable:
		return 0.1
	case models.ReachReachable:
		return 1.0
	default: // ReachUnknown
		return 0.5
	}
}

func exposureFactor(asset *models.Asset) float64 {
	if asset == nil {
		return 1.0
	}
	if asset.InternetFacing {
		return 1.5
	}
	return 0.5
}

func criticalityFactor(asset *models.Asset) float64 {
	if asset == nil {
		return 1.0
	}
	switch asset.Environment {
	case models.EnvProduction:
		// Tier 0 is most critical -> highest factor.
		switch asset.Tier {
		case 0:
			return 2.0
		case 1:
			return 1.6
		default:
			return 1.3
		}
	case models.EnvStaging:
		return 1.0
	case models.EnvDev:
		return 0.7
	case models.EnvSandbox:
		return 0.5
	}
	return 1.0
}

func round2(v float64) float64 {
	return math.Round(v*100) / 100
}
