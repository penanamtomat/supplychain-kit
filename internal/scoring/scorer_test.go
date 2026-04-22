package scoring

import (
	"testing"

	"github.com/penanamtomat/supplychain-kit/internal/models"
)

func TestScore_UnreachableCriticalIsLowerThanReachableMedium(t *testing.T) {
	asset := &models.Asset{Environment: models.EnvProduction, Tier: 0, InternetFacing: true}

	unreach := &models.Finding{
		Severity:     models.SeverityCritical,
		Reachability: models.ReachUnreachable,
	}
	reachableMed := &models.Finding{
		Severity:     models.SeverityMedium,
		Reachability: models.ReachConfirmed,
	}

	s := Scorer{}
	a := s.Score(unreach, asset)
	b := s.Score(reachableMed, asset)

	if a >= b {
		t.Fatalf("expected unreachable critical (%.2f) to score below reachable medium (%.2f)", a, b)
	}
}

func TestScore_BoundedToHundred(t *testing.T) {
	asset := &models.Asset{Environment: models.EnvProduction, Tier: 0, InternetFacing: true}
	f := &models.Finding{Severity: models.SeverityCritical, CVSS: 10.0, Reachability: models.ReachConfirmed}

	got := Scorer{}.Score(f, asset)
	if got > 100 {
		t.Fatalf("score must not exceed 100, got %.2f", got)
	}
}
