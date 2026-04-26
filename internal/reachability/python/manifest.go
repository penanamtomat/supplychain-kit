// Package python implements the 3-layer Static Import Graph reachability
// analyzer for Python (PyPI ecosystem).
package python

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

// PackageScope classifies a package from the manifest.
type PackageScope string

const (
	ScopeRuntime PackageScope = "runtime"
	ScopeDevOnly PackageScope = "devonly"
)

// ManifestResult holds the scope classification from Python manifest files.
type ManifestResult struct {
	Scope map[string]PackageScope
}

// ParseManifest detects and parses whichever manifest files exist under
// repoPath. Multiple manifest files can coexist; dev signal from any of them
// takes precedence for a package.
//
// Supported:
//   - pyproject.toml  ([tool.poetry.dev-dependencies], [tool.poetry.group.dev.dependencies], [project.optional-dependencies])
//   - Pipfile         ([dev-packages] vs [packages])
//   - requirements*.txt  (heuristic: *dev*, *test*, *lint* in filename → dev)
func ParseManifest(repoPath string) (*ManifestResult, error) {
	result := &ManifestResult{Scope: make(map[string]PackageScope)}

	// Try each manifest in order; errors are non-fatal (file may not exist).
	_ = parsePyproject(repoPath, result)
	_ = parsePipfile(repoPath, result)
	parseRequirements(repoPath, result)

	return result, nil
}

// Classify returns the scope for a package.
// When not found, returns ScopeRuntime and false (conservative).
func (m *ManifestResult) Classify(pkgName string) (PackageScope, bool) {
	scope, ok := m.Scope[normPkg(pkgName)]
	if !ok {
		return ScopeRuntime, false
	}
	return scope, true
}

// ──────────────────────────────────────────────────────────────────────────────
// pyproject.toml
// ──────────────────────────────────────────────────────────────────────────────

type pyproject struct {
	Tool struct {
		Poetry struct {
			Dependencies    map[string]interface{} `toml:"dependencies"`
			DevDependencies map[string]interface{} `toml:"dev-dependencies"`
			Group           map[string]struct {
				Dependencies map[string]interface{} `toml:"dependencies"`
			} `toml:"group"`
		} `toml:"poetry"`
	} `toml:"tool"`
	Project struct {
		Dependencies         []string            `toml:"dependencies"`
		OptionalDependencies map[string][]string `toml:"optional-dependencies"`
	} `toml:"project"`
}

func parsePyproject(repoPath string, result *ManifestResult) error {
	path := filepath.Join(repoPath, "pyproject.toml")
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	var pp pyproject
	if err := toml.Unmarshal(data, &pp); err != nil {
		return err
	}

	// Poetry runtime deps
	for name := range pp.Tool.Poetry.Dependencies {
		if strings.EqualFold(name, "python") {
			continue
		}
		setRuntime(result, name)
	}

	// Poetry dev-dependencies (legacy key)
	for name := range pp.Tool.Poetry.DevDependencies {
		setDevOnly(result, name)
	}

	// Poetry dependency groups (e.g. [tool.poetry.group.dev.dependencies])
	for groupName, group := range pp.Tool.Poetry.Group {
		isDevGroup := strings.Contains(strings.ToLower(groupName), "dev") ||
			strings.Contains(strings.ToLower(groupName), "test") ||
			strings.Contains(strings.ToLower(groupName), "lint")
		for name := range group.Dependencies {
			if isDevGroup {
				setDevOnly(result, name)
			} else {
				setRuntime(result, name)
			}
		}
	}

	// PEP 621 [project.dependencies]
	for _, dep := range pp.Project.Dependencies {
		name := pkgNameFromPEP508(dep)
		if name != "" {
			setRuntime(result, name)
		}
	}

	// PEP 621 [project.optional-dependencies] — groups like "dev", "test" → devonly
	for groupName, deps := range pp.Project.OptionalDependencies {
		isDevGroup := strings.Contains(strings.ToLower(groupName), "dev") ||
			strings.Contains(strings.ToLower(groupName), "test") ||
			strings.Contains(strings.ToLower(groupName), "lint")
		for _, dep := range deps {
			name := pkgNameFromPEP508(dep)
			if name == "" {
				continue
			}
			if isDevGroup {
				setDevOnly(result, name)
			} else {
				setRuntime(result, name)
			}
		}
	}

	return nil
}

// ──────────────────────────────────────────────────────────────────────────────
// Pipfile
// ──────────────────────────────────────────────────────────────────────────────

func parsePipfile(repoPath string, result *ManifestResult) error {
	path := filepath.Join(repoPath, "Pipfile")
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	// Pipfile is TOML.
	var pipfile struct {
		Packages    map[string]interface{} `toml:"packages"`
		DevPackages map[string]interface{} `toml:"dev-packages"`
	}
	if err := toml.Unmarshal(data, &pipfile); err != nil {
		return err
	}

	for name := range pipfile.Packages {
		setRuntime(result, name)
	}
	for name := range pipfile.DevPackages {
		setDevOnly(result, name)
	}

	return nil
}

// ──────────────────────────────────────────────────────────────────────────────
// requirements*.txt
// ──────────────────────────────────────────────────────────────────────────────

// reReqLine matches a requirement name, ignoring version specifiers and options.
var reReqLine = regexp.MustCompile(`^([A-Za-z0-9_.-]+)`)

func parseRequirements(repoPath string, result *ManifestResult) {
	entries, err := os.ReadDir(repoPath)
	if err != nil {
		return
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := strings.ToLower(entry.Name())
		if !strings.HasPrefix(name, "requirements") || !strings.HasSuffix(name, ".txt") {
			continue
		}

		// Heuristic: filenames containing dev/test/lint are dev-only.
		isDevFile := strings.Contains(name, "dev") ||
			strings.Contains(name, "test") ||
			strings.Contains(name, "lint") ||
			strings.Contains(name, "ci") ||
			strings.Contains(name, "local")

		parseReqFile(filepath.Join(repoPath, entry.Name()), isDevFile, result)
	}
}

func parseReqFile(path string, isDevFile bool, result *ManifestResult) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		m := reReqLine.FindStringSubmatch(line)
		if len(m) < 2 {
			continue
		}
		name := m[1]
		if isDevFile {
			setDevOnly(result, name)
		} else {
			setRuntime(result, name)
		}
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────────

func setRuntime(result *ManifestResult, name string) {
	n := normPkg(name)
	if _, alreadyDev := result.Scope[n]; !alreadyDev {
		result.Scope[n] = ScopeRuntime
	}
}

func setDevOnly(result *ManifestResult, name string) {
	n := normPkg(name)
	// Only override if it's not already marked as runtime from another file.
	if existing, ok := result.Scope[n]; !ok || existing == ScopeDevOnly {
		result.Scope[n] = ScopeDevOnly
	}
}

// pkgNameFromPEP508 extracts the package name from a PEP 508 requirement
// string like "requests>=2.0,<3.0" or "black[d]".
var rePEP508Name = regexp.MustCompile(`^([A-Za-z0-9_.-]+)`)

func pkgNameFromPEP508(dep string) string {
	m := rePEP508Name.FindStringSubmatch(strings.TrimSpace(dep))
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

// normPkg normalises a Python package name for map lookups:
// lowercase, replace hyphens/underscores with hyphens (PyPI canonical form).
func normPkg(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	// Strip purl prefix: pkg:pypi/name@ver
	if after, ok := strings.CutPrefix(name, "pkg:pypi/"); ok {
		if idx := strings.Index(after, "@"); idx > 0 {
			name = after[:idx]
		} else {
			name = after
		}
	}
	// PyPI normalisation: underscores and hyphens are equivalent.
	name = strings.ReplaceAll(name, "_", "-")
	return name
}
