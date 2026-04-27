package python

import (
	"path/filepath"
	"testing"
)

func TestParseManifest_Pyproject_Poetry(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "pyproject.toml"), `
[tool.poetry.dependencies]
python = "^3.10"
flask = "^3.0"
requests = "^2.31"

[tool.poetry.dev-dependencies]
pytest = "^7.0"
black = "^23.0"
`)

	m, err := ParseManifest(dir)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		pkg    string
		isDev  bool
	}{
		{"flask", false},
		{"requests", false},
		{"pytest", true},
		{"black", true},
	}
	for _, tc := range cases {
		scope, _ := m.Classify(tc.pkg)
		if (scope == ScopeDevOnly) != tc.isDev {
			t.Errorf("%s: dev=%v want=%v", tc.pkg, scope == ScopeDevOnly, tc.isDev)
		}
	}
}

func TestParseManifest_Pipfile(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "Pipfile"), `
[packages]
flask = "*"
requests = ">=2.0"

[dev-packages]
pytest = "*"
`)

	m, err := ParseManifest(dir)
	if err != nil {
		t.Fatal(err)
	}

	if s, _ := m.Classify("flask"); s != ScopeRuntime {
		t.Errorf("flask should be runtime")
	}
	if s, _ := m.Classify("pytest"); s != ScopeDevOnly {
		t.Errorf("pytest should be dev")
	}
}

func TestParseManifest_Requirements(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "requirements.txt"), "flask==3.0\nrequests>=2.31\n")
	writeFile(t, filepath.Join(dir, "requirements-dev.txt"), "pytest==7.4\nblack==23.0\n")

	m, err := ParseManifest(dir)
	if err != nil {
		t.Fatal(err)
	}

	if s, _ := m.Classify("flask"); s != ScopeRuntime {
		t.Errorf("flask from requirements.txt should be runtime")
	}
	if s, _ := m.Classify("pytest"); s != ScopeDevOnly {
		t.Errorf("pytest from requirements-dev.txt should be dev")
	}
}

func TestParseManifest_PurlNorm(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "requirements-test.txt"), "pytest==7.4\n")
	m, _ := ParseManifest(dir)

	scope, _ := m.Classify("pkg:pypi/pytest@7.4")
	if scope != ScopeDevOnly {
		t.Errorf("purl lookup should return ScopeDevOnly, got %v", scope)
	}
}

func TestParseManifest_NormUnderscoreHyphen(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "requirements.txt"), "python_dateutil==2.8\n")
	m, _ := ParseManifest(dir)

	// PyPI normalisation: "python-dateutil" and "python_dateutil" are the same.
	if s, _ := m.Classify("python-dateutil"); s != ScopeRuntime {
		t.Errorf("python-dateutil should resolve despite underscore in manifest")
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := writeFileRaw(path, content); err != nil {
		t.Fatal(err)
	}
}
