// Package remediation provides template-based finding analysis without requiring AI APIs.
package remediation

import (
	"testing"
	"time"

	"github.com/penanamtomat/supplychain-kit/internal/models"
)

func TestEngine_Analyze(t *testing.T) {
	engine := New()

	tests := []struct {
		name     string
		finding  *models.Finding
		wantPrio string
	}{
		{
			name: "critical reachable",
			finding: &models.Finding{
				ID:           "f-001",
				RuleID:       "CVE-2021-44228",
				Severity:     models.SeverityCritical,
				Reachability: models.ReachConfirmed,
				Package:      "log4j-core",
				Version:      "2.14.1",
				FixedVersion: "2.15.0",
				CVSS:         10.0,
				Description:  "Remote code execution via JNDI lookup",
			},
			wantPrio: "fix-now",
		},
		{
			name: "high unreachable",
			finding: &models.Finding{
				ID:           "f-002",
				RuleID:       "CVE-2023-0001",
				Severity:     models.SeverityHigh,
				Reachability: models.ReachUnreachable,
				Package:      "lodash",
				Version:      "4.17.20",
				FixedVersion: "4.17.21",
			},
			wantPrio: "next-sprint",
		},
		{
			name: "low severity",
			finding: &models.Finding{
				ID:           "f-003",
				RuleID:       "CVE-2022-1234",
				Severity:     models.SeverityLow,
				Reachability: models.ReachUnknown,
				Package:      "axios",
				Version:      "0.25.0",
			},
			wantPrio: "monitor",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rem := engine.Analyze(tt.finding)
			if rem == nil {
				t.Fatal("Analyze() returned nil")
			}
			if rem.Priority != tt.wantPrio {
				t.Errorf("Priority = %s, want %s", rem.Priority, tt.wantPrio)
			}
			if rem.RuleID != tt.finding.RuleID {
				t.Errorf("RuleID = %s, want %s", rem.RuleID, tt.finding.RuleID)
			}
			if rem.Severity != string(tt.finding.Severity) {
				t.Errorf("Severity = %s, want %s", rem.Severity, tt.finding.Severity)
			}
		})
	}
}

func TestEngine_AnalyzeBatch(t *testing.T) {
	engine := New()

	findings := []*models.Finding{
		{
			ID:           "f-001",
			RuleID:       "CVE-2021-44228",
			Severity:     models.SeverityCritical,
			Reachability: models.ReachConfirmed,
			Package:      "log4j-core",
			Version:      "2.14.1",
			FixedVersion: "2.15.0",
		},
		{
			ID:           "f-002",
			RuleID:       "CVE-2023-0001",
			Severity:     models.SeverityHigh,
			Reachability: models.ReachUnreachable,
			Package:      "lodash",
			Version:      "4.17.20",
			FixedVersion: "4.17.21",
		},
	}

	rems := engine.AnalyzeBatch(findings)
	if len(rems) != len(findings) {
		t.Errorf("AnalyzeBatch() returned %d results, want %d", len(rems), len(findings))
	}

	for i, rem := range rems {
		if rem.RuleID != findings[i].RuleID {
			t.Errorf("rem[%d].RuleID = %s, want %s", i, rem.RuleID, findings[i].RuleID)
		}
	}
}

func TestEngine_generateUpgradeCommand(t *testing.T) {
	engine := New()

	tests := []struct {
		name           string
		pkg            string
		fixedVersion   string
		wantSubstring  string
	}{
		{
			name:          "npm package",
			pkg:           "lodash",
			fixedVersion:  "4.17.21",
			wantSubstring: "npm install",
		},
		{
			name:          "python package",
			pkg:           "requests",
			fixedVersion:  "2.28.0",
			wantSubstring: "pip install",
		},
		{
			name:          "go package",
			pkg:           "github.com/gin-gonic/gin",
			fixedVersion:  "v1.9.0",
			wantSubstring: "go get",
		},
		{
			name:          "rust package",
			pkg:           "serde",
			fixedVersion:  "1.0.150",
			wantSubstring: "cargo update",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &models.Finding{
				Package:      tt.pkg,
				FixedVersion: tt.fixedVersion,
			}
			cmd := engine.generateUpgradeCommand(f)
			if !contains(cmd, tt.wantSubstring) {
				t.Errorf("generateUpgradeCommand() = %s, want to contain %s", cmd, tt.wantSubstring)
			}
		})
	}
}

func TestEngine_assessBreakingChanges(t *testing.T) {
	engine := New()

	tests := []struct {
		name          string
		version       string
		fixedVersion  string
		wantSubstring string
	}{
		{
			name:          "major version bump",
			version:       "1.5.0",
			fixedVersion:  "2.0.0",
			wantSubstring: "breaking changes",
		},
		{
			name:          "minor version bump",
			version:       "1.5.0",
			fixedVersion:  "1.6.0",
			wantSubstring: "unlikely",
		},
		{
			name:          "patch version bump",
			version:       "1.5.0",
			fixedVersion:  "1.5.1",
			wantSubstring: "none",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &models.Finding{
				Version:      tt.version,
				FixedVersion: tt.fixedVersion,
			}
			assessment := engine.assessBreakingChanges(f)
			if !contains(assessment, tt.wantSubstring) {
				t.Errorf("assessBreakingChanges() = %s, want to contain %s", assessment, tt.wantSubstring)
			}
		})
	}
}

func TestEngine_generateVerifyStep(t *testing.T) {
	engine := New()

	f := &models.Finding{
		Package:      "lodash",
		FixedVersion: "4.17.21",
	}

	verify := engine.generateVerifyStep(f)
	if !contains(verify, "npm list") && !contains(verify, "npm show") {
		t.Errorf("generateVerifyStep() = %s, want npm command", verify)
	}
	if !contains(verify, "Re-run") {
		t.Errorf("generateVerifyStep() = %s, want rescan recommendation", verify)
	}
}

func TestEngine_generateReferences(t *testing.T) {
	engine := New()

	tests := []struct {
		name         string
		finding      *models.Finding
		wantContains []string
	}{
		{
			name: "CVE with advisory",
			finding: &models.Finding{
				RuleID:      "CVE-2021-44228",
				AdvisoryURL: "https://logging.apache.org/log4j/2.x/security.html",
			},
			wantContains: []string{"nvd.nist.gov", "logging.apache.org"},
		},
		{
			name: "CVE only",
			finding: &models.Finding{
				RuleID:  "CVE-2023-0001",
				Package: "lodash",
			},
			wantContains: []string{"nvd.nist.gov", "github.com/advisories"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			refs := engine.generateReferences(tt.finding)
			for _, want := range tt.wantContains {
				if !contains(refs, want) {
					t.Errorf("generateReferences() = %s, want to contain %s", refs, want)
				}
			}
		})
	}
}

func TestEngine_AnalyzeNil(t *testing.T) {
	engine := New()
	rem := engine.Analyze(nil)
	if rem != nil {
		t.Error("Analyze(nil) should return nil")
	}
}

func TestEngine_extractMajor(t *testing.T) {
	engine := New()

	tests := []struct {
		version string
		want    int
	}{
		{"1.5.0", 1},
		{"2.0.0", 2},
		{"v1.5.0", 1},
		{"V2.0.0", 2},
		{"0.5.0", 0},
		{"invalid", 0},
	}

	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			got := engine.extractMajor(tt.version)
			if got != tt.want {
				t.Errorf("extractMajor(%s) = %d, want %d", tt.version, got, tt.want)
			}
		})
	}
}

// Helper function
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && containsSubstring(s, substr))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// Helper to create test findings
func makeFinding(id, ruleID string, severity models.Severity, reach models.Reachability) *models.Finding {
	return &models.Finding{
		ID:           id,
		RuleID:       ruleID,
		Severity:     severity,
		Reachability: reach,
		Package:      "test-pkg",
		Version:      "1.0.0",
		FixedVersion: "1.0.1",
		CVSS:         7.5,
		FilePath:     "src/main.go",
		Line:         42,
		RiskScore:    8.0,
		Fingerprint:  "abc123",
		FirstSeen:    time.Now(),
		LastSeen:     time.Now(),
	}
}
