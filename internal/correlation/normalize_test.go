package correlation

import (
	"testing"

	"github.com/penanamtomat/supplychain-kit/internal/models"
	"github.com/penanamtomat/supplychain-kit/internal/scanner"
)

func TestMerge_DedupAndEscalateSeverity(t *testing.T) {
	a := &models.Finding{
		Fingerprint: "fp1",
		RuleID:      "CVE-1",
		Severity:    models.SeverityMedium,
		Sources:     []models.FindingSource{models.SourceGrype},
	}
	b := &models.Finding{
		Fingerprint: "fp1",
		RuleID:      "CVE-1",
		Severity:    models.SeverityHigh,
		Sources:     []models.FindingSource{models.SourceSemgrep},
	}

	merged := Merge([]scanner.ScannedResult{
		{Result: scanner.Result{Findings: []*models.Finding{a}}},
		{Result: scanner.Result{Findings: []*models.Finding{b}}},
	})

	if len(merged) != 1 {
		t.Fatalf("expected 1 deduped finding, got %d", len(merged))
	}
	if merged[0].Severity != models.SeverityHigh {
		t.Fatalf("expected severity to escalate to high, got %s", merged[0].Severity)
	}
	if len(merged[0].Sources) != 2 {
		t.Fatalf("expected merged sources to include both scanners, got %v", merged[0].Sources)
	}
}
