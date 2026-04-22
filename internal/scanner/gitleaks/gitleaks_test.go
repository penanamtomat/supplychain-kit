package gitleaks_test

import (
	"context"
	"os"
	"testing"

	"github.com/penanamtomat/supplychain-kit/internal/models"
	"github.com/penanamtomat/supplychain-kit/internal/scanner"
	"github.com/penanamtomat/supplychain-kit/internal/scanner/gitleaks"
)

func TestAdapter_BinaryNotFound(t *testing.T) {
	a := gitleaks.NewWithBinary("__gitleaks_missing__")
	_, err := a.Scan(context.Background(), scanner.Request{CheckoutDir: t.TempDir()})
	if _, ok := err.(scanner.ErrBinaryNotFound); !ok {
		t.Fatalf("expected ErrBinaryNotFound, got %T: %v", err, err)
	}
}

func TestParseReport(t *testing.T) {
	raw, err := os.ReadFile("testdata/report.json")
	if err != nil {
		t.Fatal(err)
	}
	findings, err := gitleaks.ParseReport(raw, "asset-1", "run-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.RuleID != "gitleaks.aws-access-token" {
		t.Errorf("unexpected rule_id: %s", f.RuleID)
	}
	if f.Severity != models.SeverityHigh {
		t.Errorf("expected High, got %s", f.Severity)
	}
	if f.Reachability != models.ReachReachable {
		t.Errorf("secrets must be reachable, got %s", f.Reachability)
	}
	if f.FilePath != "config/deploy.yaml" {
		t.Errorf("unexpected file: %s", f.FilePath)
	}
	if f.Line != 12 {
		t.Errorf("expected line 12, got %d", f.Line)
	}
	if f.Fingerprint == "" {
		t.Error("fingerprint must not be empty")
	}
}

func TestParseReport_Empty(t *testing.T) {
	findings, err := gitleaks.ParseReport([]byte("[]"), "asset-1", "run-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
}
