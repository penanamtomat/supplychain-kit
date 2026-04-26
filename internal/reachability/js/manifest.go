// Package js implements the 3-layer Static Import Graph reachability analyzer
// for JavaScript/Node.js (npm ecosystem).
package js

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// PackageScope classifies a package from the manifest.
type PackageScope string

const (
	ScopeRuntime PackageScope = "runtime"
	ScopeDevOnly PackageScope = "devonly"
)

// ManifestResult holds the scope classification from package.json.
type ManifestResult struct {
	// Scope maps normalized package name → scope.
	Scope map[string]PackageScope
}

// ParseManifest reads package.json from repoPath and returns scope
// classification for every declared dependency.
//
// Rule: devDependencies → ScopeDevOnly unless the same name also appears in
// dependencies (in which case runtime takes precedence).
func ParseManifest(repoPath string) (*ManifestResult, error) {
	data, err := os.ReadFile(filepath.Join(repoPath, "package.json"))
	if err != nil {
		return nil, err
	}

	var pkg struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil, err
	}

	result := &ManifestResult{Scope: make(map[string]PackageScope)}

	for name := range pkg.Dependencies {
		result.Scope[normPkg(name)] = ScopeRuntime
	}
	for name := range pkg.DevDependencies {
		n := normPkg(name)
		if _, alreadyRuntime := result.Scope[n]; !alreadyRuntime {
			result.Scope[n] = ScopeDevOnly
		}
	}

	return result, nil
}

// Classify returns the scope for a package name.
// Returns ScopeRuntime and false when the package is not found in the manifest
// (transitive deps not in package.json are treated as runtime — conservative).
func (m *ManifestResult) Classify(pkgName string) (PackageScope, bool) {
	scope, ok := m.Scope[normPkg(pkgName)]
	if !ok {
		return ScopeRuntime, false
	}
	return scope, true
}

// normPkg normalises a package name for map lookups:
// lowercase, strip leading @scope/ for bare comparisons, trim whitespace.
func normPkg(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	// Strip purl prefix if present: pkg:npm/<name>@<ver>
	if after, ok := strings.CutPrefix(name, "pkg:npm/"); ok {
		// drop @version suffix
		if idx := strings.Index(after, "@"); idx > 0 {
			name = after[:idx]
		} else {
			name = after
		}
	}
	return name
}
