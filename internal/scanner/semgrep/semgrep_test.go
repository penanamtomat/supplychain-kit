package semgrep_test

import (
	"context"
	"os"
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
	findings, err := semgrep.ParseReport(raw, "asset-1", "run-1", "/repo")
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}

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

	f1 := findings[1]
	if f1.Severity != models.SeverityMedium {
		t.Errorf("expected Medium for WARNING, got %s", f1.Severity)
	}
}
