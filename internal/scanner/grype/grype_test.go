package grype_test

import (
	"context"
	"os"
	"testing"

	"github.com/penanamtomat/supplychain-kit/internal/models"
	"github.com/penanamtomat/supplychain-kit/internal/scanner"
	"github.com/penanamtomat/supplychain-kit/internal/scanner/grype"
)

func TestAdapter_BinaryNotFound(t *testing.T) {
	a := grype.NewWithBinary("__grype_missing__")
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
	findings, err := grype.ParseReport(raw, "asset-1", "run-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
	f := findings[0]
	if f.RuleID != "CVE-2023-29400" {
		t.Errorf("unexpected rule_id: %s", f.RuleID)
	}
	if f.Severity != models.SeverityCritical {
		t.Errorf("expected Critical, got %s", f.Severity)
	}
	if f.CVSS != 9.8 {
		t.Errorf("expected CVSS 9.8, got %f", f.CVSS)
	}
	if f.FixedVersion != "1.20.5" {
		t.Errorf("expected fixed version 1.20.5, got %s", f.FixedVersion)
	}
	if f.Fingerprint == "" {
		t.Error("fingerprint must not be empty")
	}
}
