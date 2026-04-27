package js

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseManifest_DevDependency(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "package.json"), `{
		"dependencies": {
			"multer": "^2.0.0",
			"express": "^4.18.0"
		},
		"devDependencies": {
			"lodash": "^4.17.21",
			"mocha": "^10.0.0",
			"minimatch": "^3.1.2"
		}
	}`)

	m, err := ParseManifest(dir)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		pkg      string
		wantDev  bool
	}{
		{"multer", false},
		{"express", false},
		{"lodash", true},
		{"mocha", true},
		{"minimatch", true},
	}

	for _, tc := range cases {
		scope, _ := m.Classify(tc.pkg)
		gotDev := scope == ScopeDevOnly
		if gotDev != tc.wantDev {
			t.Errorf("Classify(%q): dev=%v, want dev=%v", tc.pkg, gotDev, tc.wantDev)
		}
	}
}

func TestParseManifest_RuntimeWinsOverDev(t *testing.T) {
	// A package in both dependencies AND devDependencies → runtime wins.
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "package.json"), `{
		"dependencies":    {"shared": "1.0"},
		"devDependencies": {"shared": "1.0"}
	}`)

	m, err := ParseManifest(dir)
	if err != nil {
		t.Fatal(err)
	}

	scope, found := m.Classify("shared")
	if !found || scope != ScopeRuntime {
		t.Errorf("shared should be ScopeRuntime, got %v (found=%v)", scope, found)
	}
}

func TestParseManifest_PurlNorm(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "package.json"), `{
		"devDependencies": {"tar": "^6.0.0"}
	}`)

	m, err := ParseManifest(dir)
	if err != nil {
		t.Fatal(err)
	}

	// Finding package field may arrive as purl.
	scope, _ := m.Classify("pkg:npm/tar@6.1.0")
	if scope != ScopeDevOnly {
		t.Errorf("purl lookup: expected ScopeDevOnly, got %v", scope)
	}
}

func TestParseManifest_MissingFile(t *testing.T) {
	_, err := ParseManifest(t.TempDir())
	if err == nil {
		t.Error("expected error when package.json missing")
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}
