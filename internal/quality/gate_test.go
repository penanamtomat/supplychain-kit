package quality

import (
	"testing"

	"github.com/penanamtomat/supplychain-kit/internal/config"
	"github.com/penanamtomat/supplychain-kit/internal/models"
)

func TestGate_FailOnReachableCritical(t *testing.T) {
	tru := true
	policy := config.QualityGateConfig{
		FailOn: []config.GateRule{{Severity: "critical", Reachable: &tru}},
	}
	e := New(policy)

	res := e.Evaluate([]*models.Finding{
		{Severity: models.SeverityCritical, Reachability: models.ReachReachable},
		{Severity: models.SeverityHigh, Reachability: models.ReachReachable},
	})
	if res.Decision != DecisionFail {
		t.Fatalf("expected fail, got %s", res.Decision)
	}
	if len(res.Violations) != 1 {
		t.Fatalf("expected 1 violation, got %d", len(res.Violations))
	}
}

func TestGate_PassWhenNoMatches(t *testing.T) {
	tru := true
	policy := config.QualityGateConfig{
		FailOn: []config.GateRule{{Severity: "critical", Reachable: &tru}},
	}
	res := New(policy).Evaluate([]*models.Finding{
		{Severity: models.SeverityMedium, Reachability: models.ReachReachable},
	})
	if res.Decision != DecisionPass {
		t.Fatalf("expected pass, got %s", res.Decision)
	}
}
