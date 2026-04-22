package semgrep_test

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/penanamtomat/supplychain-kit/internal/models"
	"github.com/penanamtomat/supplychain-kit/internal/scanner"
	"github.com/penanamtomat/supplychain-kit/internal/scanner/semgrep"
)

func TestAdapter_BinaryNotFound(t *testing.T) {
	a := semgrep.NewWithBinary("__semgrep_missing__")
	_, err := a.Scan(context.Background(), scanner.Request{})
	if _, ok := err.(scanner.ErrBinaryNotFound); !ok {
		t.Fatalf("expected ErrBinaryNotFound, got %T: %v", err, err)
	}
}

func TestParseReport(t *testing.T) {
	raw, err := os.ReadFile("testdata/report.json")
	if err != nil {
		t.Fatal(err)
	}
	// testdata has 4 results but 1 is inside vendor/ — expect 3 after filtering.
	findings, err := semgrep.ParseReport(raw, "asset-1", "run-1", "/repo")
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 3 {
		t.Fatalf("expected 3 findings (vendor filtered), got %d", len(findings))
	}

	// finding[0]: ERROR → High
	f0 := findings[0]
	if f0.Severity != models.SeverityHigh {
		t.Errorf("expected High for ERROR, got %s", f0.Severity)
	}
	if f0.FilePath != "internal/runner/runner.go" {
		t.Errorf("unexpected file path: %s", f0.FilePath)
	}
	if f0.Line != 42 {
		t.Errorf("expected line 42, got %d", f0.Line)
	}
	if f0.Fingerprint == "" {
		t.Error("fingerprint must not be empty")
	}
	if !strings.HasPrefix(f0.AdvisoryURL, "https://semgrep.dev/r/") {
		t.Errorf("expected semgrep advisory URL, got %q", f0.AdvisoryURL)
	}

	// finding[1]: WARNING → Medium
	f1 := findings[1]
	if f1.Severity != models.SeverityMedium {
		t.Errorf("expected Medium for WARNING, got %s", f1.Severity)
	}

	// finding[2]: CRITICAL → Critical (semgrep 1.75+)
	f2 := findings[2]
	if f2.Severity != models.SeverityCritical {
		t.Errorf("expected Critical for CRITICAL, got %s", f2.Severity)
	}
	if f2.FilePath != "internal/auth/token.go" {
		t.Errorf("unexpected file path for critical finding: %s", f2.FilePath)
	}
}

func TestParseReport_VendorFiltered(t *testing.T) {
	raw, err := os.ReadFile("testdata/report.json")
	if err != nil {
		t.Fatal(err)
	}
	findings, err := semgrep.ParseReport(raw, "asset-1", "run-1", "/repo")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if strings.HasPrefix(f.FilePath, "vendor/") {
			t.Errorf("vendor path must be filtered, got: %s", f.FilePath)
		}
	}
}
