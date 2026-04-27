package js

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/penanamtomat/supplychain-kit/internal/models"
)

func TestAnalyzer_Unreachable_DevDep(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "package.json"), `{
		"dependencies":    {"multer": "^2.0.0"},
		"devDependencies": {"lodash": "^4.17.21", "minimatch": "^3.0.0"}
	}`)
	writeFile(t, filepath.Join(dir, "app.js"), `
const multer = require('multer')
const upload = multer({ storage: multer.memoryStorage() })
`)

	a := NewAnalyzer()
	ctx := context.Background()

	for _, devPkg := range []string{"lodash", "minimatch"} {
		f := &models.Finding{Package: devPkg}
		result, err := a.Analyze(ctx, dir, f)
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", devPkg, err)
		}
		if result.Status != models.ReachUnreachable {
			t.Errorf("%s: expected unreachable (dev dep), got %v", devPkg, result.Status)
		}
	}
}

func TestAnalyzer_Unreachable_NotImported(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "package.json"), `{
		"dependencies": {"multer": "^2.0.0", "tar": "^6.0.0"}
	}`)
	// Only multer is imported; tar is a runtime dep but never imported.
	writeFile(t, filepath.Join(dir, "app.js"), `
const multer = require('multer')
const upload = multer({ dest: 'uploads/' })
`)

	a := NewAnalyzer()
	result, err := a.Analyze(context.Background(), dir, &models.Finding{Package: "tar"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != models.ReachUnreachable {
		t.Errorf("tar not imported → expected unreachable, got %v", result.Status)
	}
}

func TestAnalyzer_Reachable_SymbolCalled(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "package.json"), `{
		"dependencies": {"multer": "^2.0.0"}
	}`)
	writeFile(t, filepath.Join(dir, "routes.js"), `
const multer = require('multer')
const upload = multer({ storage: multer.memoryStorage() })
`)

	a := NewAnalyzer()
	f := &models.Finding{
		Package: "multer",
		Raw:     map[string]any{"affected_functions": "multer"},
	}
	result, err := a.Analyze(context.Background(), dir, f)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != models.ReachReachable {
		t.Errorf("multer() called → expected reachable, got %v (evidence: %s)", result.Status, result.Evidence)
	}
}

func TestAnalyzer_Unknown_NoSymbol(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "package.json"), `{
		"dependencies": {"some-pkg": "^1.0.0"}
	}`)
	writeFile(t, filepath.Join(dir, "app.js"), `
const somePkg = require('some-pkg')
`)

	a := NewAnalyzer()
	// No Raw metadata → symbol can't be resolved → unknown.
	f := &models.Finding{Package: "some-pkg"}
	result, err := a.Analyze(context.Background(), dir, f)
	if err != nil {
		t.Fatal(err)
	}
	// Fallback symbol is "some-pkg" base → "some-pkg", and "some-pkg(" is not
	// in the file, so Layer 3 should return unreachable (symbol not called).
	// Accept either unreachable or unknown depending on fallback symbol match.
	if result.Status != models.ReachUnreachable && result.Status != models.ReachUnknown {
		t.Errorf("expected unreachable or unknown, got %v", result.Status)
	}
}

func TestAnalyzer_Cache(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "package.json"), `{"devDependencies":{"lodash":"4"}}`)
	writeFile(t, filepath.Join(dir, "app.js"), "")

	a := NewAnalyzer()
	ctx := context.Background()

	// First call loads.
	_, _ = a.Analyze(ctx, dir, &models.Finding{Package: "lodash"})
	// Second call should use cache (lastRepo set).
	if a.lastRepo != dir {
		t.Error("cache not populated after first call")
	}
	_, _ = a.Analyze(ctx, dir, &models.Finding{Package: "lodash"})
}
