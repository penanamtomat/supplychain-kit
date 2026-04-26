package python

import (
	"context"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
	"github.com/penanamtomat/supplychain-kit/internal/models"
	"github.com/penanamtomat/supplychain-kit/internal/reachability"
)

// Analyzer implements reachability.ReachabilityAnalyzer for the PyPI ecosystem.
type Analyzer struct {
	mu       sync.Mutex
	manifest *ManifestResult
	imports  *ImportResult
	lastRepo string
}

// NewAnalyzer returns a new Python/PyPI ReachabilityAnalyzer.
func NewAnalyzer() *Analyzer {
	return &Analyzer{}
}

func (a *Analyzer) Ecosystem() string { return "pypi" }

// Analyze runs the 3-layer static import graph analysis for a single SCA finding.
func (a *Analyzer) Analyze(_ context.Context, repoPath string, f *models.Finding) (reachability.Result, error) {
	pkgName := extractPkgName(f.Package)
	if pkgName == "" {
		return reachability.Result{Status: models.ReachUnknown}, nil
	}

	manifest, imports, err := a.loadRepo(repoPath)
	if err != nil {
		log.Warn().Err(err).Str("repo", repoPath).Msg("python: failed to load repo data")
		return reachability.Result{Status: models.ReachUnknown}, nil
	}

	// ── Layer 1: Dependency Scope Classification ───────────────────────────
	if manifest != nil {
		scope, found := manifest.Classify(pkgName)
		if found && scope == ScopeDevOnly {
			log.Debug().Str("pkg", pkgName).Msg("python: dev-only dependency → unreachable")
			return reachability.Result{
				Status:     models.ReachUnreachable,
				Confidence: 0.9,
				Evidence:   "dev/test dependency in manifest",
			}, nil
		}
	}

	// ── Layer 2: Import Tracing ────────────────────────────────────────────
	if imports == nil {
		return reachability.Result{Status: models.ReachUnknown}, nil
	}

	imported, sourceFiles := imports.IsImported(pkgName)
	if !imported {
		log.Debug().Str("pkg", pkgName).Msg("python: package not imported in production files → unreachable")
		return reachability.Result{
			Status:     models.ReachUnreachable,
			Confidence: 0.85,
			Evidence:   "package not imported in any production .py file",
		}, nil
	}

	// ── Layer 3: Vulnerable Symbol Call Check ─────────────────────────────
	symbol := extractVulnerableSymbol(f)
	if symbol == "" {
		log.Debug().Str("pkg", pkgName).Msg("python: imported, no CVE symbol resolved → unknown")
		return reachability.Result{
			Status:     models.ReachUnknown,
			Confidence: 0.0,
			Evidence:   "package imported but CVE symbol not resolvable",
		}, nil
	}

	call := CheckSymbolCall(repoPath, pkgName, symbol, sourceFiles)
	if call.Called {
		log.Debug().Str("pkg", pkgName).Str("symbol", symbol).Str("at", call.Evidence).
			Msg("python: vulnerable symbol called → reachable")
		return reachability.Result{
			Status:     models.ReachReachable,
			Confidence: 0.9,
			Evidence:   call.Evidence,
		}, nil
	}

	log.Debug().Str("pkg", pkgName).Str("symbol", symbol).
		Msg("python: imported but vulnerable symbol not called → unreachable")
	return reachability.Result{
		Status:     models.ReachUnreachable,
		Confidence: 0.8,
		Evidence:   "package imported but vulnerable symbol " + symbol + " not called in production",
	}, nil
}

// loadRepo lazily loads manifest and imports for the given repo.
func (a *Analyzer) loadRepo(repoPath string) (*ManifestResult, *ImportResult, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.lastRepo == repoPath && a.imports != nil {
		return a.manifest, a.imports, nil
	}

	manifest, err := ParseManifest(repoPath)
	if err != nil {
		log.Debug().Err(err).Str("repo", repoPath).Msg("python: manifest load failed")
		manifest = nil
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

// extractPkgName normalises the package name from a finding's Package field.
func extractPkgName(raw string) string {
	if raw == "" {
		return ""
	}
	if after, ok := strings.CutPrefix(strings.ToLower(raw), "pkg:pypi/"); ok {
		if idx := strings.Index(after, "@"); idx > 0 {
			return after[:idx]
		}
		return after
	}
	return raw
}

// extractVulnerableSymbol derives the affected function name from the finding.
func extractVulnerableSymbol(f *models.Finding) string {
	if f.Raw != nil {
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
	// Fallback: bare package name as symbol (catches pkg() and pkg.method()).
	return bareModule(normPkg(extractPkgName(f.Package)))
}

func sanitizeSymbol(s string) string {
	parts := strings.Split(s, ".")
	return parts[len(parts)-1]
}
