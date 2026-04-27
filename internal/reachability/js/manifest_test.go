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

// ── package-lock.json transitive chain tests ────────────────────────────────

func TestParseManifest_LockfileV2_TransitiveDevDep(t *testing.T) {
	// Scenario: "jest-worker" is NOT in package.json but appears in
	// package-lock.json as dev:true (transitive dep of jest). It should be
	// classified as ScopeDevOnly.
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "package.json"), `{
		"dependencies":    {"express": "^4.18.0"},
		"devDependencies": {"jest": "^29.0.0"}
	}`)
	writeFile(t, filepath.Join(dir, "package-lock.json"), `{
		"lockfileVersion": 3,
		"packages": {
			"": {
				"dependencies":    {"express": "^4.18.0"},
				"devDependencies": {"jest": "^29.0.0"}
			},
			"node_modules/express": {"version": "4.18.0"},
			"node_modules/jest":    {"version": "29.0.0", "dev": true},
			"node_modules/jest-worker": {"version": "29.0.0", "dev": true}
		}
	}`)

	m, err := ParseManifest(dir)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		pkg     string
		wantDev bool
	}{
		{"express", false},
		{"jest", true},
		{"jest-worker", true}, // transitive dev dep — must be caught via lockfile
	}
	for _, tc := range cases {
		scope, _ := m.Classify(tc.pkg)
		gotDev := scope == ScopeDevOnly
		if gotDev != tc.wantDev {
			t.Errorf("Classify(%q): dev=%v, want dev=%v", tc.pkg, gotDev, tc.wantDev)
		}
	}
}

func TestParseManifest_LockfileV2_RuntimeTransitiveNotDowngraded(t *testing.T) {
	// "qs" is a transitive of express (runtime). Even though package.json
	// doesn't list it, it should remain ScopeRuntime (not unknown, not dev).
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "package.json"), `{
		"dependencies": {"express": "^4.18.0"}
	}`)
	writeFile(t, filepath.Join(dir, "package-lock.json"), `{
		"lockfileVersion": 2,
		"packages": {
			"": {"dependencies": {"express": "^4.18.0"}},
			"node_modules/express": {"version": "4.18.0"},
			"node_modules/qs":      {"version": "6.11.0"}
		}
	}`)

	m, err := ParseManifest(dir)
	if err != nil {
		t.Fatal(err)
	}

	scope, found := m.Classify("qs")
	if !found {
		t.Error("qs should be found via lockfile")
	}
	if scope != ScopeRuntime {
		t.Errorf("qs should be ScopeRuntime (runtime transitive), got %v", scope)
	}
}

func TestParseManifest_LockfileV2_RuntimeWinsOverLockfileDev(t *testing.T) {
	// If package.json lists pkg as runtime dep, lockfile dev:true must NOT
	// override it (runtime always wins).
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "package.json"), `{
		"dependencies": {"cross-env": "^7.0.0"}
	}`)
	writeFile(t, filepath.Join(dir, "package-lock.json"), `{
		"lockfileVersion": 3,
		"packages": {
			"": {"dependencies": {"cross-env": "^7.0.0"}},
			"node_modules/cross-env": {"version": "7.0.3", "dev": true}
		}
	}`)

	m, err := ParseManifest(dir)
	if err != nil {
		t.Fatal(err)
	}

	scope, _ := m.Classify("cross-env")
	if scope != ScopeRuntime {
		t.Errorf("cross-env runtime dep must not be downgraded by lockfile dev:true, got %v", scope)
	}
}

func TestParseManifest_LockfileV1_TransitiveDevDep(t *testing.T) {
	// npm v1 lockfile uses "dependencies" map with nested "dev": true.
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "package.json"), `{
		"dependencies":    {"axios": "^1.0.0"},
		"devDependencies": {"mocha": "^10.0.0"}
	}`)
	writeFile(t, filepath.Join(dir, "package-lock.json"), `{
		"lockfileVersion": 1,
		"dependencies": {
			"axios":   {"version": "1.0.0"},
			"mocha":   {"version": "10.0.0", "dev": true},
			"mocha-core": {"version": "1.0.0", "dev": true}
		}
	}`)

	m, err := ParseManifest(dir)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		pkg     string
		wantDev bool
	}{
		{"axios", false},
		{"mocha", true},
		{"mocha-core", true},
	}
	for _, tc := range cases {
		scope, _ := m.Classify(tc.pkg)
		gotDev := scope == ScopeDevOnly
		if gotDev != tc.wantDev {
			t.Errorf("Classify(%q): dev=%v, want dev=%v", tc.pkg, gotDev, tc.wantDev)
		}
	}
}

func TestParseManifest_NoLockfile(t *testing.T) {
	// Missing package-lock.json is not fatal — ParseManifest still succeeds.
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "package.json"), `{
		"dependencies": {"express": "^4.0.0"}
	}`)

	m, err := ParseManifest(dir)
	if err != nil {
		t.Fatal(err)
	}
	scope, _ := m.Classify("express")
	if scope != ScopeRuntime {
		t.Errorf("expected ScopeRuntime without lockfile, got %v", scope)
	}
}

func TestLockfileKeyToName(t *testing.T) {
	cases := []struct {
		key  string
		want string
	}{
		{"node_modules/express", "express"},
		{"node_modules/@scope/pkg", "@scope/pkg"},
		{"node_modules/foo/node_modules/bar", "bar"},
		{"", ""},
		{"no-prefix", ""},
	}
	for _, tc := range cases {
		got := lockfileKeyToName(tc.key)
		if got != tc.want {
			t.Errorf("lockfileKeyToName(%q) = %q, want %q", tc.key, got, tc.want)
		}
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}
