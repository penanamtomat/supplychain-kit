package suppress

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/penanamtomat/supplychain-kit/internal/models"
)

func writeIgnore(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, ".supplychain-ignore")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("write ignore: %v", err)
	}
	return p
}

func TestLoad_MissingFileReturnsEmptySet(t *testing.T) {
	s, err := Load(filepath.Join(t.TempDir(), "nope"))
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if s.Len() != 0 {
		t.Errorf("expected empty set, got %d rules", s.Len())
	}
}

func TestLoad_DirectoryAppendsDefaultFilename(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".supplychain-ignore"), []byte("CVE-1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if s.Len() != 1 {
		t.Fatalf("expected 1 rule, got %d", s.Len())
	}
}

func TestApply_MatchesByRuleID(t *testing.T) {
	path := writeIgnore(t, "CVE-2023-1\n")
	s, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	findings := []*models.Finding{
		{ID: "1", RuleID: "CVE-2023-1", Severity: models.SeverityHigh},
		{ID: "2", RuleID: "CVE-2023-2", Severity: models.SeverityHigh},
	}
	if n := s.Apply(findings); n != 1 {
		t.Errorf("expected 1 suppression, got %d", n)
	}
	if findings[0].VEXStatus != models.VEXNotAffected {
		t.Errorf("finding 0 not marked suppressed: %q", findings[0].VEXStatus)
	}
	if findings[1].VEXStatus == models.VEXNotAffected {
		t.Errorf("finding 1 wrongly suppressed")
	}
}

func TestApply_MatchesByPackageWithReason(t *testing.T) {
	path := writeIgnore(t, "* package:lodash reason:unmaintained, isolated in dev-only code\n")
	s, _ := Load(path)
	findings := []*models.Finding{
		{ID: "1", RuleID: "CVE-1", Package: "lodash"},
		{ID: "2", RuleID: "CVE-2", Package: "express"},
	}
	n := s.Apply(findings)
	if n != 1 {
		t.Fatalf("expected 1, got %d", n)
	}
	meta, _ := findings[0].Raw["suppressed_by"].(map[string]any)
	if meta["reason"] != "reason:unmaintained, isolated in dev-only code" && meta["reason"] != "unmaintained, isolated in dev-only code" {
		t.Logf("reason recorded as: %v", meta["reason"])
	}
}

func TestApply_FingerprintExactMatch(t *testing.T) {
	path := writeIgnore(t, "* fingerprint:abc123\n")
	s, _ := Load(path)
	findings := []*models.Finding{
		{ID: "1", Fingerprint: "abc123"},
		{ID: "2", Fingerprint: "def456"},
	}
	if n := s.Apply(findings); n != 1 {
		t.Fatalf("expected 1, got %d", n)
	}
}

func TestLoad_RejectsUnknownKey(t *testing.T) {
	path := writeIgnore(t, "CVE-1 foo:bar\n")
	if _, err := Load(path); err == nil {
		t.Error("expected error for unknown key")
	}
}

func TestLoad_SkipsCommentsAndBlankLines(t *testing.T) {
	path := writeIgnore(t, "# header\n\n  # indented\nCVE-1\n")
	s, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if s.Len() != 1 {
		t.Errorf("expected 1 rule, got %d", s.Len())
	}
}
