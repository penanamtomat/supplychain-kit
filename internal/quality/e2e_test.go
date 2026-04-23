package quality_test

import (
	"testing"

	"github.com/penanamtomat/supplychain-kit/internal/config"
	"github.com/penanamtomat/supplychain-kit/internal/models"
	"github.com/penanamtomat/supplychain-kit/internal/quality"
	"github.com/penanamtomat/supplychain-kit/internal/scoring"
)

// defaultPolicy mirrors the CLI default: fail on Critical, warn on High.
func defaultPolicy() config.QualityGateConfig {
	return config.QualityGateConfig{
		FailOn: []config.GateRule{{Severity: "critical"}},
		WarnOn: []config.GateRule{{Severity: "high"}},
	}
}

func scored(findings []*models.Finding) []*models.Finding {
	asset := &models.Asset{ID: "test", Environment: models.EnvDev, Tier: 2}
	s := scoring.Scorer{}
	for _, f := range findings {
		if f.Reachability == "" {
			f.Reachability = models.ReachUnknown
		}
		s.Score(f, asset)
	}
	return findings
}

// TestE2E_Gate_Critical verifies exit-2 (fail) when Critical finding is present.
func TestE2E_Gate_Critical(t *testing.T) {
	findings := scored([]*models.Finding{
		{
			ID:           "f1",
			AssetID:      "test",
			RuleID:       "CVE-2021-44228",
			Title:        "Log4Shell RCE",
			Severity:     models.SeverityCritical,
			Package:      "log4j",
			Version:      "2.14.1",
			Sources:      []models.FindingSource{models.SourceGrype},
			Reachability: models.ReachUnknown,
		},
	})

	result := quality.New(defaultPolicy()).Evaluate(findings)

	if result.Decision != quality.DecisionFail {
		t.Errorf("Critical finding: decision = %q, want %q", result.Decision, quality.DecisionFail)
	}
	if len(result.Violations) != 1 {
		t.Errorf("want 1 violation, got %d", len(result.Violations))
	}
}

// TestE2E_Gate_HighOnly verifies exit-1 (warn) when only High findings are present.
func TestE2E_Gate_HighOnly(t *testing.T) {
	findings := scored([]*models.Finding{
		{
			ID:       "f2",
			AssetID:  "test",
			RuleID:   "python.sql-injection",
			Title:    "SQL Injection",
			Severity: models.SeverityHigh,
			FilePath: "app.py",
			Line:     42,
			Sources:  []models.FindingSource{models.SourceSemgrep},
		},
	})

	result := quality.New(defaultPolicy()).Evaluate(findings)

	if result.Decision != quality.DecisionWarn {
		t.Errorf("High-only findings: decision = %q, want %q", result.Decision, quality.DecisionWarn)
	}
	if len(result.Warnings) != 1 {
		t.Errorf("want 1 warning, got %d", len(result.Warnings))
	}
}

// TestE2E_Gate_Clean verifies exit-0 (pass) when no Critical/High findings.
func TestE2E_Gate_Clean(t *testing.T) {
	findings := scored([]*models.Finding{
		{
			ID:       "f3",
			AssetID:  "test",
			RuleID:   "info-leak",
			Title:    "Verbose error message",
			Severity: models.SeverityLow,
			Sources:  []models.FindingSource{models.SourceSemgrep},
		},
	})

	result := quality.New(defaultPolicy()).Evaluate(findings)

	if result.Decision != quality.DecisionPass {
		t.Errorf("Low-only findings: decision = %q, want %q", result.Decision, quality.DecisionPass)
	}
}

// TestE2E_Gate_Empty verifies exit-0 (pass) for empty findings.
func TestE2E_Gate_Empty(t *testing.T) {
	result := quality.New(defaultPolicy()).Evaluate(nil)

	if result.Decision != quality.DecisionPass {
		t.Errorf("empty findings: decision = %q, want %q", result.Decision, quality.DecisionPass)
	}
}

// TestE2E_Gate_MixedCriticalAndHigh verifies fail takes precedence over warn.
func TestE2E_Gate_MixedCriticalAndHigh(t *testing.T) {
	findings := scored([]*models.Finding{
		{ID: "f4", AssetID: "test", RuleID: "CVE-A", Title: "Critical vuln", Severity: models.SeverityCritical, Sources: []models.FindingSource{models.SourceGrype}},
		{ID: "f5", AssetID: "test", RuleID: "CVE-B", Title: "High vuln", Severity: models.SeverityHigh, Sources: []models.FindingSource{models.SourceGrype}},
	})

	result := quality.New(defaultPolicy()).Evaluate(findings)

	if result.Decision != quality.DecisionFail {
		t.Errorf("mixed findings: decision = %q, want %q", result.Decision, quality.DecisionFail)
	}
	// Warnings should also be populated alongside violations.
	if len(result.Warnings) == 0 {
		t.Error("expected warnings to be populated even when fail")
	}
}

// TestE2E_Gate_ReachabilityPolicy verifies a policy that only fails on reachable Criticals.
func TestE2E_Gate_ReachabilityPolicy(t *testing.T) {
	reachableOnly := true
	policy := config.QualityGateConfig{
		FailOn: []config.GateRule{{Severity: "critical", Reachable: &reachableOnly}},
	}

	unreachableCritical := scored([]*models.Finding{
		{ID: "f6", AssetID: "test", RuleID: "CVE-X", Title: "Unreachable critical", Severity: models.SeverityCritical, Reachability: models.ReachUnreachable, Sources: []models.FindingSource{models.SourceGrype}},
	})
	if r := quality.New(policy).Evaluate(unreachableCritical); r.Decision != quality.DecisionPass {
		t.Errorf("unreachable critical with reachable-only policy: want pass, got %q", r.Decision)
	}

	reachableCritical := scored([]*models.Finding{
		{ID: "f7", AssetID: "test", RuleID: "CVE-Y", Title: "Reachable critical", Severity: models.SeverityCritical, Reachability: models.ReachReachable, Sources: []models.FindingSource{models.SourceGrype}},
	})
	if r := quality.New(policy).Evaluate(reachableCritical); r.Decision != quality.DecisionFail {
		t.Errorf("reachable critical with reachable-only policy: want fail, got %q", r.Decision)
	}
}
