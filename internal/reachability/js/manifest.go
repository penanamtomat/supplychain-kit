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
// classification for every declared dependency. If package-lock.json is
// present, transitive packages that are only reachable from devDependencies
// are also marked ScopeDevOnly.
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

	// Augment with transitive chain from package-lock.json.
	// In npm v2/v3 lockfile, any entry with "dev": true is exclusively
	// reachable from devDependencies (direct or transitive). This catches
	// packages that don't appear in package.json at all.
	_ = parseLockfileTransitives(repoPath, result)

	return result, nil
}

// parseLockfileTransitives parses package-lock.json and marks packages that
// npm itself tagged as dev-only (dev:true) as ScopeDevOnly, unless they are
// already known to be runtime from package.json.
//
// Supports npm lockfile v1 (dependencies map) and v2/v3 (packages map).
func parseLockfileTransitives(repoPath string, result *ManifestResult) error {
	data, err := os.ReadFile(filepath.Join(repoPath, "package-lock.json"))
	if err != nil {
		return err // not fatal — lock file may not exist (yarn, pnpm, etc.)
	}

	var lock struct {
		LockfileVersion int `json:"lockfileVersion"`
		// v2/v3 format
		Packages map[string]struct {
			Dev      bool   `json:"dev"`
			Name     string `json:"name"` // sometimes present for scoped pkgs
			Optional bool   `json:"optional"`
		} `json:"packages"`
		// v1 format
		Dependencies map[string]struct {
			Dev      bool                       `json:"dev"`
			Requires map[string]string          `json:"requires"`
			Deps     map[string]json.RawMessage `json:"dependencies"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return err
	}

	if lock.LockfileVersion >= 2 {
		// v2/v3: walk packages map. Keys look like "node_modules/foo" or
		// "node_modules/@scope/foo". Strip the "node_modules/" prefix to
		// get the package name.
		for key, entry := range lock.Packages {
			if key == "" {
				continue // root pseudo-package
			}
			name := lockfileKeyToName(key)
			if name == "" {
				continue
			}
			n := normPkg(name)
			if entry.Dev {
				// Only downgrade to dev if not already pinned as runtime.
				if existing, ok := result.Scope[n]; !ok || existing != ScopeRuntime {
					result.Scope[n] = ScopeDevOnly
				}
			} else if _, ok := result.Scope[n]; !ok {
				// Unknown in package.json — present in lockfile as runtime transitive.
				result.Scope[n] = ScopeRuntime
			}
		}
	} else {
		// v1: walk top-level dependencies recursively.
		collectV1DevDeps(lock.Dependencies, false, result)
	}

	return nil
}

// lockfileKeyToName converts a packages map key like "node_modules/@scope/pkg"
// to "@scope/pkg", handling nested paths like "node_modules/foo/node_modules/bar".
func lockfileKeyToName(key string) string {
	// Find the last "node_modules/" segment.
	const prefix = "node_modules/"
	idx := strings.LastIndex(key, prefix)
	if idx < 0 {
		return ""
	}
	return key[idx+len(prefix):]
}

// collectV1DevDeps walks the npm v1 dependency tree recursively.
// parentIsDev propagates dev status to all children of a dev dependency.
func collectV1DevDeps(
	deps map[string]struct {
		Dev      bool                       `json:"dev"`
		Requires map[string]string          `json:"requires"`
		Deps     map[string]json.RawMessage `json:"dependencies"`
	},
	parentIsDev bool,
	result *ManifestResult,
) {
	for name, entry := range deps {
		isDev := parentIsDev || entry.Dev
		n := normPkg(name)
		if isDev {
			if existing, ok := result.Scope[n]; !ok || existing != ScopeRuntime {
				result.Scope[n] = ScopeDevOnly
			}
		} else if _, ok := result.Scope[n]; !ok {
			result.Scope[n] = ScopeRuntime
		}
		// Recurse into nested deps (npm v1 hoisting can produce nesting).
		if len(entry.Deps) > 0 {
			// Re-parse the nested map into the expected type.
			nested := make(map[string]struct {
				Dev      bool                       `json:"dev"`
				Requires map[string]string          `json:"requires"`
				Deps     map[string]json.RawMessage `json:"dependencies"`
			})
			for k, raw := range entry.Deps {
				var sub struct {
					Dev      bool                       `json:"dev"`
					Requires map[string]string          `json:"requires"`
					Deps     map[string]json.RawMessage `json:"dependencies"`
				}
				if err := json.Unmarshal(raw, &sub); err == nil {
					nested[k] = sub
				}
			}
			collectV1DevDeps(nested, isDev, result)
		}
	}
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
