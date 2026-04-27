package golang

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/penanamtomat/supplychain-kit/internal/models"
)

// ── go.mod parsing tests ──────────────────────────────────────────────────────

func TestParseGoMod_DirectAndIndirect(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "go.mod"), `module example.com/myapp

go 1.22

require (
	github.com/gin-gonic/gin v1.9.1
	github.com/spf13/cobra v1.8.0
	golang.org/x/net v0.20.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
)
`)

	m, err := parseGoMod(dir)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		mod          string
		wantDirect   bool
		wantIndirect bool
	}{
		{"github.com/gin-gonic/gin", true, false},
		{"github.com/spf13/cobra", true, false},
		{"golang.org/x/net", false, true},
		{"github.com/pkg/errors", false, true},
		{"github.com/unknown/pkg", false, false},
	}

	for _, tc := range cases {
		gotDirect := m.IsDirect(tc.mod)
		gotIndirect := m.IsIndirect(tc.mod)
		if gotDirect != tc.wantDirect {
			t.Errorf("IsDirect(%q) = %v, want %v", tc.mod, gotDirect, tc.wantDirect)
		}
		if gotIndirect != tc.wantIndirect {
			t.Errorf("IsIndirect(%q) = %v, want %v", tc.mod, gotIndirect, tc.wantIndirect)
		}
	}
}

func TestParseGoMod_SingleLineRequire(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "go.mod"), `module example.com/app

go 1.22

require github.com/rs/zerolog v1.32.0
require golang.org/x/crypto v0.21.0 // indirect
`)

	m, err := parseGoMod(dir)
	if err != nil {
		t.Fatal(err)
	}

	if !m.IsDirect("github.com/rs/zerolog") {
		t.Error("zerolog should be direct")
	}
	if !m.IsIndirect("golang.org/x/crypto") {
		t.Error("x/crypto should be indirect")
	}
}

func TestParseGoMod_Missing(t *testing.T) {
	_, err := parseGoMod(t.TempDir())
	if err == nil {
		t.Error("expected error when go.mod missing")
	}
}

// ── govulncheck stream parsing tests ─────────────────────────────────────────

// mockGovulnOutput simulates govulncheck -json output:
// - GO-2023-1234 / CVE-2023-9999: trace len > 1 → vulnCalled
// - GO-2023-5678 / CVE-2023-8888: trace len == 1 → vulnNotCalled
const mockGovulnOutput = `
{"config":{"protocol_version":"v1.0.0","scanner_name":"govulncheck"}}
{"finding":{"osv":"GO-2023-1234","aliases":["CVE-2023-9999"],"trace":[{"module":"golang.org/x/text","function":"vulnerable.Func"},{"module":"example.com/myapp","function":"main.handler"}]}}
{"finding":{"osv":"GO-2023-5678","aliases":["CVE-2023-8888"],"trace":[{"module":"golang.org/x/net","function":"http2.vulnerable"}]}}
`

func TestGovulnStream_CalledVuln(t *testing.T) {
	result := parseGovulnStream(bytes.NewReader([]byte(mockGovulnOutput)))

	// trace len > 1 → called
	status, ok := result.Lookup("golang.org/x/text", "CVE-2023-9999")
	if !ok {
		t.Fatal("expected entry for golang.org/x/text + CVE-2023-9999")
	}
	if status != vulnCalled {
		t.Errorf("expected vulnCalled, got %v", status)
	}

	// Also findable by GO-... ID
	status2, ok2 := result.Lookup("golang.org/x/text", "GO-2023-1234")
	if !ok2 || status2 != vulnCalled {
		t.Errorf("expected vulnCalled via GO alias, got ok=%v status=%v", ok2, status2)
	}
}

func TestGovulnStream_NotCalledVuln(t *testing.T) {
	result := parseGovulnStream(bytes.NewReader([]byte(mockGovulnOutput)))

	// trace len == 1 → not called
	status, ok := result.Lookup("golang.org/x/net", "GO-2023-5678")
	if !ok {
		t.Fatal("expected entry for golang.org/x/net + GO-2023-5678")
	}
	if status != vulnNotCalled {
		t.Errorf("expected vulnNotCalled, got %v", status)
	}
}

func TestGovulnStream_MissingEntry(t *testing.T) {
	result := parseGovulnStream(bytes.NewReader([]byte(mockGovulnOutput)))
	_, ok := result.Lookup("github.com/some/other", "CVE-2023-9999")
	if ok {
		t.Error("expected miss for unknown module")
	}
}

func TestGovulnStream_EmptyInput(t *testing.T) {
	result := parseGovulnStream(bytes.NewReader(nil))
	if result == nil || result.entries == nil {
		t.Error("expected non-nil result for empty input")
	}
}

func TestGovulnStream_CaseInsensitiveID(t *testing.T) {
	// Lookup should be case-insensitive for vuln IDs.
	result := parseGovulnStream(bytes.NewReader([]byte(mockGovulnOutput)))
	status, ok := result.Lookup("golang.org/x/text", "cve-2023-9999")
	if !ok || status != vulnCalled {
		t.Errorf("case-insensitive lookup failed: ok=%v status=%v", ok, status)
	}
}

// ── Analyzer integration tests ────────────────────────────────────────────────

func TestAnalyzer_Ecosystem(t *testing.T) {
	if NewAnalyzer().Ecosystem() != "golang" {
		t.Error("expected ecosystem == golang")
	}
}

func TestAnalyzer_IndirectDep_ReturnsUnknown(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "go.mod"), `module example.com/app

go 1.22

require (
	github.com/direct/dep v1.0.0
	github.com/indirect/dep v1.0.0 // indirect
)
`)

	a := &Analyzer{}
	finding := &models.Finding{
		Package: "github.com/indirect/dep",
		RuleID:  "CVE-2024-0001",
	}

	result, err := a.Analyze(context.Background(), dir, finding)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != models.ReachUnknown {
		t.Errorf("indirect dep: expected unknown, got %v", result.Status)
	}
	if !strings.Contains(result.Evidence, "indirect") {
		t.Errorf("evidence should mention indirect, got %q", result.Evidence)
	}
}

func TestAnalyzer_DirectDep_NoGovulncheck_ReturnsUnknown(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "go.mod"), `module example.com/app

go 1.22

require github.com/direct/dep v1.0.0
`)

	a := &Analyzer{}
	finding := &models.Finding{
		Package: "github.com/direct/dep",
		RuleID:  "CVE-2024-0002",
	}

	result, err := a.Analyze(context.Background(), dir, finding)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != models.ReachUnknown {
		t.Errorf("direct dep without govulncheck: expected unknown, got %v", result.Status)
	}
}

func TestAnalyzer_EmptyPackage_ReturnsUnknown(t *testing.T) {
	a := &Analyzer{}
	result, err := a.Analyze(context.Background(), t.TempDir(), &models.Finding{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != models.ReachUnknown {
		t.Errorf("empty package: expected unknown, got %v", result.Status)
	}
}

func TestAnalyzer_GovulncheckCalled_Reachable(t *testing.T) {
	// Inject a pre-built govulnResult as if govulncheck returned a "called" finding.
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "go.mod"), `module example.com/app

go 1.22

require golang.org/x/text v0.14.0
`)

	vuln := &govulnResult{entries: map[string]vulnStatus{
		"golang.org/x/text|CVE-2023-9999": vulnCalled,
	}}
	gomod, _ := parseGoMod(dir)

	a := &Analyzer{
		gomod:    gomod,
		vulnDB:   vuln,
		lastRepo: dir,
	}

	result, err := a.Analyze(context.Background(), dir, &models.Finding{
		Package: "golang.org/x/text",
		RuleID:  "CVE-2023-9999",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != models.ReachReachable {
		t.Errorf("govulncheck called: expected reachable, got %v", result.Status)
	}
	if result.Confidence < 0.9 {
		t.Errorf("expected high confidence, got %v", result.Confidence)
	}
}

func TestAnalyzer_GovulncheckNotCalled_Unreachable(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "go.mod"), `module example.com/app

go 1.22

require golang.org/x/net v0.20.0
`)

	vuln := &govulnResult{entries: map[string]vulnStatus{
		"golang.org/x/net|CVE-2023-8888": vulnNotCalled,
	}}
	gomod, _ := parseGoMod(dir)

	a := &Analyzer{
		gomod:    gomod,
		vulnDB:   vuln,
		lastRepo: dir,
	}

	result, err := a.Analyze(context.Background(), dir, &models.Finding{
		Package: "golang.org/x/net",
		RuleID:  "CVE-2023-8888",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != models.ReachUnreachable {
		t.Errorf("govulncheck not-called: expected unreachable, got %v", result.Status)
	}
}

// ── helper tests ──────────────────────────────────────────────────────────────

func TestExtractModuleName(t *testing.T) {
	cases := []struct {
		raw  string
		want string
	}{
		{"github.com/foo/bar", "github.com/foo/bar"},
		{"pkg:golang/github.com/foo/bar@v1.2.3", "github.com/foo/bar"},
		{"pkg:golang/golang.org/x/net@v0.20.0", "golang.org/x/net"},
		{"", ""},
	}
	for _, tc := range cases {
		got := extractModuleName(tc.raw)
		if got != tc.want {
			t.Errorf("extractModuleName(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}
}

func TestNormModule(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"github.com/Foo/Bar", "github.com/foo/bar"},
		{"github.com/foo/bar@v1.2.3", "github.com/foo/bar"},
		{" golang.org/x/net ", "golang.org/x/net"},
	}
	for _, tc := range cases {
		got := normModule(tc.in)
		if got != tc.want {
			t.Errorf("normModule(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// ── test helpers ──────────────────────────────────────────────────────────────

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}
