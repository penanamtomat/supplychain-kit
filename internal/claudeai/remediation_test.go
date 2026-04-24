package claudeai

import (
	"testing"

	"github.com/penanamtomat/supplychain-kit/internal/models"
)

func TestNew_NilWhenNoAPIKey(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "")
	a := New()
	if a != nil {
		t.Error("expected nil Analyzer when ANTHROPIC_API_KEY is unset")
	}
}

func TestAvailable_FalseWhenNoKey(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "")
	if Available() {
		t.Error("Available() should be false when ANTHROPIC_API_KEY is unset")
	}
}

func TestAvailable_TrueWhenKeySet(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "sk-test-fake")
	if !Available() {
		t.Error("Available() should be true when ANTHROPIC_API_KEY is set")
	}
}

func TestAnalyze_NilReceiverReturnsError(t *testing.T) {
	var a *Analyzer
	_, err := a.Analyze(nil, "test", &models.Finding{ID: "f1", RuleID: "CVE-2021-0001"}) //nolint:staticcheck
	if err == nil {
		t.Error("expected error from nil Analyzer.Analyze")
	}
}

func TestAnalyzeBatch_NilReceiverReturnsErrors(t *testing.T) {
	var a *Analyzer
	findings := []*models.Finding{
		{ID: "f1", RuleID: "CVE-2021-0001"},
	}
	_, errs := a.AnalyzeBatch(nil, "test", findings, 0) //nolint:staticcheck
	if len(errs) == 0 || errs[0] == nil {
		t.Error("expected error slice from nil Analyzer.AnalyzeBatch")
	}
}

func TestParseRemediationResponse_ValidJSON(t *testing.T) {
	f := &models.Finding{
		ID:           "f1",
		RuleID:       "CVE-2021-44228",
		Severity:     models.SeverityCritical,
		Reachability: models.ReachReachable,
	}
	raw := `{
		"priority": "fix-now",
		"explanation": "Log4Shell RCE via JNDI lookup.",
		"upgrade_command": "mvn versions:use-latest-versions -Dincludes=org.apache.logging.log4j",
		"breaking_changes": "none",
		"verify_step": "mvn dependency:tree | grep log4j",
		"references": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
	}`

	rem, err := parseRemediationResponse(f, raw)
	if err != nil {
		t.Fatalf("parseRemediationResponse error: %v", err)
	}
	if rem.Priority != "fix-now" {
		t.Errorf("priority = %q, want fix-now", rem.Priority)
	}
	if rem.FindingID != "f1" {
		t.Errorf("finding_id = %q, want f1", rem.FindingID)
	}
	if rem.Severity != "CRITICAL" {
		t.Errorf("severity = %q, want CRITICAL", rem.Severity)
	}
}

func TestParseRemediationResponse_StripsMarkdownFences(t *testing.T) {
	f := &models.Finding{ID: "f2", Severity: models.SeverityHigh, Reachability: models.ReachUnknown}
	raw := "```json\n{\"priority\":\"next-sprint\",\"explanation\":\"test\",\"upgrade_command\":\"npm update\",\"breaking_changes\":\"none\",\"verify_step\":\"npm audit\",\"references\":\"\"}\n```"

	rem, err := parseRemediationResponse(f, raw)
	if err != nil {
		t.Fatalf("expected fence stripping to work: %v", err)
	}
	if rem.Priority != "next-sprint" {
		t.Errorf("priority = %q, want next-sprint", rem.Priority)
	}
}

func TestParseRemediationResponse_InvalidJSON(t *testing.T) {
	f := &models.Finding{ID: "f3"}
	_, err := parseRemediationResponse(f, `not json at all`)
	if err == nil {
		t.Error("expected parse error for invalid JSON")
	}
}

func TestBuildPrompt_IncludesKeyFields(t *testing.T) {
	f := &models.Finding{
		ID:           "f1",
		RuleID:       "CVE-2021-44228",
		Severity:     models.SeverityCritical,
		Package:      "log4j-core",
		Version:      "2.14.1",
		FixedVersion: "2.15.0",
		Reachability: models.ReachReachable,
		CVSS:         10.0,
	}
	prompt := buildPrompt("my-engagement", f)

	for _, want := range []string{"my-engagement", "CVE-2021-44228", "log4j-core", "2.14.1", "2.15.0", "CRITICAL", "10.0"} {
		if !contains(prompt, want) {
			t.Errorf("buildPrompt missing %q", want)
		}
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 ||
		func() bool {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
			return false
		}())
}
