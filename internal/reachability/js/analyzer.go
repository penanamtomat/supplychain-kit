package js

import (
	"context"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
	"github.com/penanamtomat/supplychain-kit/internal/models"
	"github.com/penanamtomat/supplychain-kit/internal/reachability"
)

// Analyzer implements reachability.ReachabilityAnalyzer for the npm ecosystem.
type Analyzer struct {
	mu       sync.Mutex
	manifest *ManifestResult // lazily loaded per repo
	imports  *ImportResult   // lazily loaded per repo
	lastRepo string
}

// NewAnalyzer returns a new JS/npm ReachabilityAnalyzer.
func NewAnalyzer() *Analyzer {
	return &Analyzer{}
}

func (a *Analyzer) Ecosystem() string { return "npm" }

// Analyze runs the 3-layer static import graph analysis for a single SCA finding.
func (a *Analyzer) Analyze(_ context.Context, repoPath string, f *models.Finding) (reachability.Result, error) {
	pkgName := extractPkgName(f.Package)
	if pkgName == "" {
		return reachability.Result{Status: models.ReachUnknown}, nil
	}

	manifest, imports, err := a.loadRepo(repoPath)
	if err != nil {
		log.Warn().Err(err).Str("repo", repoPath).Msg("js: failed to load repo data")
		return reachability.Result{Status: models.ReachUnknown}, nil
	}

	// ── Layer 1: Dependency Scope Classification ───────────────────────────
	if manifest != nil {
		scope, found := manifest.Classify(pkgName)
		if found && scope == ScopeDevOnly {
			log.Debug().Str("pkg", pkgName).Msg("js: dev-only dependency → unreachable")
			return reachability.Result{
				Status:     models.ReachUnreachable,
				Confidence: 0.9,
				Evidence:   "devDependency in package.json",
			}, nil
		}
	}

	// ── Layer 2: Import Tracing ────────────────────────────────────────────
	if imports == nil {
		return reachability.Result{Status: models.ReachUnknown}, nil
	}

	imported, sourceFiles := imports.IsImported(pkgName)
	if !imported {
		log.Debug().Str("pkg", pkgName).Msg("js: package not imported in production files → unreachable")
		return reachability.Result{
			Status:     models.ReachUnreachable,
			Confidence: 0.85,
			Evidence:   "package not imported in any production .js/.ts file",
		}, nil
	}

	// ── Layer 3: Vulnerable Symbol Call Check ─────────────────────────────
	symbol := extractVulnerableSymbol(f)
	if symbol == "" {
		// Imported but no symbol to check → honest unknown
		log.Debug().Str("pkg", pkgName).Msg("js: imported, no CVE symbol resolved → unknown")
		return reachability.Result{
			Status:     models.ReachUnknown,
			Confidence: 0.0,
			Evidence:   "package imported but CVE symbol not resolvable",
		}, nil
	}

	call := CheckSymbolCall(repoPath, pkgName, symbol, sourceFiles)
	if call.Called {
		log.Debug().Str("pkg", pkgName).Str("symbol", symbol).Str("at", call.Evidence).
			Msg("js: vulnerable symbol called → reachable")
		return reachability.Result{
			Status:     models.ReachReachable,
			Confidence: 0.9,
			Evidence:   call.Evidence,
		}, nil
	}

	// Imported but the specific vulnerable symbol is not called.
	log.Debug().Str("pkg", pkgName).Str("symbol", symbol).
		Msg("js: imported but vulnerable symbol not called → unreachable")
	return reachability.Result{
		Status:     models.ReachUnreachable,
		Confidence: 0.8,
		Evidence:   "package imported but vulnerable symbol " + symbol + " not called in production",
	}, nil
}

// loadRepo lazily initialises manifest + imports for the given repo path.
// Results are cached so bulk-scanning many findings for one repo is efficient.
func (a *Analyzer) loadRepo(repoPath string) (*ManifestResult, *ImportResult, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.lastRepo == repoPath && a.imports != nil {
		return a.manifest, a.imports, nil
	}

	manifest, err := ParseManifest(repoPath)
	if err != nil {
		log.Debug().Err(err).Str("repo", repoPath).Msg("js: no package.json, skipping manifest layer")
		manifest = nil // not fatal — repo may not be Node.js
	}

	imports, err := TraceImports(repoPath)
	if err != nil {
		return manifest, nil, err
	}

	a.lastRepo = repoPath
	a.manifest = manifest
	a.imports = imports
	return a.manifest, a.imports, nil
}

// extractPkgName normalises the package name from a finding's Package field,
// which may be a bare name ("multer") or a purl ("pkg:npm/multer@2.0.0").
func extractPkgName(raw string) string {
	if raw == "" {
		return ""
	}
	// purl: pkg:npm/%40scope%2Fname@ver or pkg:npm/name@ver
	if after, ok := strings.CutPrefix(raw, "pkg:npm/"); ok {
		// strip @version
		if idx := strings.Index(after, "@"); idx > 0 {
			return after[:idx]
		}
		return after
	}
	// bare or scoped name without purl
	return raw
}

// extractVulnerableSymbol tries to derive the affected function name from the
// finding.  Order of preference:
//  1. f.Raw["affected_functions"] from Grype/OSV metadata
//  2. Last path segment of the package name as a last resort (weak signal)
func extractVulnerableSymbol(f *models.Finding) string {
	if f.Raw != nil {
		// Grype populates affected function info under various keys.
		for _, key := range []string{"affected_functions", "affectedFunctions", "vulnerability_function"} {
			if v, ok := f.Raw[key]; ok {
				if s, ok := v.(string); ok && s != "" {
					return sanitizeSymbol(s)
				}
				if arr, ok := v.([]interface{}); ok && len(arr) > 0 {
					if s, ok := arr[0].(string); ok && s != "" {
						return sanitizeSymbol(s)
					}
				}
			}
		}
	}
	// Weak fallback: use package base name as the symbol to search for.
	// This catches patterns like `multer(` or `tar.extract(`.
	pkg := extractPkgName(f.Package)
	if pkg == "" {
		return ""
	}
	// For scoped packages, use just the package part: @aws-sdk/client-s3 → client-s3
	return barePackageName(normPkg(pkg))
}

// sanitizeSymbol strips module path prefixes like "lodash.merge" → "merge".
func sanitizeSymbol(s string) string {
	parts := strings.Split(s, ".")
	return parts[len(parts)-1]
}
