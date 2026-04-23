package models

import "testing"

func TestSeverity_CVSSScore(t *testing.T) {
	tests := []struct {
		s    Severity
		want float64
	}{
		{SeverityCritical, 9.5},
		{SeverityHigh, 8.0},
		{SeverityMedium, 5.5},
		{SeverityLow, 3.0},
		{SeverityInfo, 1.0},
		{Severity("unknown"), 0},
	}

	for _, tt := range tests {
		t.Run(string(tt.s), func(t *testing.T) {
			if got := tt.s.CVSSScore(); got != tt.want {
				t.Errorf("CVSSScore() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFinding_Fields(t *testing.T) {
	f := &Finding{
		ID:           "test-1",
		RuleID:       "CVE-2021-44228",
		Package:      "log4j",
		Version:      "2.14.1",
		Severity:     SeverityCritical,
		Reachability: ReachUnknown,
		Confidence:   0.0,
		RiskScore:    0.0,
		Sources:      []FindingSource{SourceGrype},
	}

	if f.ID != "test-1" {
		t.Errorf("ID = %q, want %q", f.ID, "test-1")
	}
	if f.Severity != SeverityCritical {
		t.Errorf("Severity = %q, want %q", f.Severity, SeverityCritical)
	}
	if f.Reachability != ReachUnknown {
		t.Errorf("Reachability = %q, want %q", f.Reachability, ReachUnknown)
	}
	if len(f.Sources) != 1 || f.Sources[0] != SourceGrype {
		t.Errorf("Sources = %v, want [grype]", f.Sources)
	}
}

func TestFindingSource_Constants(t *testing.T) {
	sources := []FindingSource{SourceGrype, SourceSyft, SourceSemgrep, SourceJoern, SourceGitleaks, SourceExternal}
	for _, s := range sources {
		if s == "" {
			t.Errorf("Source constant %v is empty", s)
		}
	}
}

func TestReachability_Constants(t *testing.T) {
	states := []Reachability{ReachUnknown, ReachUnreachable, ReachReachable, ReachConfirmed}
	for _, r := range states {
		if r == "" {
			t.Errorf("Reachability constant %v is empty", r)
		}
	}
}

func TestVEXStatus_Constants(t *testing.T) {
	statuses := []VEXStatus{VEXNotAffected, VEXAffected, VEXFixed, VEXUnderInvestigate}
	for _, v := range statuses {
		if v == "" {
			t.Errorf("VEXStatus constant %v is empty", v)
		}
	}
}
