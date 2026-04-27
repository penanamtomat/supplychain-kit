package java

import (
	"context"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
	"github.com/penanamtomat/supplychain-kit/internal/models"
	"github.com/penanamtomat/supplychain-kit/internal/reachability"
)

// Analyzer implements reachability.ReachabilityAnalyzer for Java (Maven/Gradle).
type Analyzer struct {
	mu       sync.Mutex
	manifest *ManifestResult
	imports  *ImportResult
	lastRepo string
}

// NewAnalyzer returns a new Java ReachabilityAnalyzer.
func NewAnalyzer() *Analyzer { return &Analyzer{} }

func (a *Analyzer) Ecosystem() string { return "maven" }

// Analyze runs the 3-layer static import graph analysis for a single Java finding.
func (a *Analyzer) Analyze(_ context.Context, repoPath string, f *models.Finding) (reachability.Result, error) {
	artifactID := extractArtifactID(f.Package)
	if artifactID == "" {
		return reachability.Result{Status: models.ReachUnknown}, nil
	}

	manifest, imports, err := a.loadRepo(repoPath)
	if err != nil {
		log.Warn().Err(err).Str("repo", repoPath).Msg("java: failed to load repo data")
		return reachability.Result{Status: models.ReachUnknown}, nil
	}

	// ── Layer 1: Dependency Scope Classification ───────────────────────────
	if manifest != nil {
		scope, found := manifest.Classify(artifactID)
		if found && scope == ScopeDevOnly {
			log.Debug().Str("pkg", artifactID).Msg("java: test/provided scope → unreachable")
			return reachability.Result{
				Status:     models.ReachUnreachable,
				Confidence: 0.9,
				Evidence:   "test or provided scope in pom.xml/build.gradle",
			}, nil
		}
	}

	// ── Layer 2: Import Tracing ────────────────────────────────────────────
	if imports == nil {
		return reachability.Result{Status: models.ReachUnknown}, nil
	}

	imported, sourceFiles := imports.IsImported(artifactID)
	if !imported {
		log.Debug().Str("pkg", artifactID).Msg("java: artifact not imported in production .java files → unreachable")
		return reachability.Result{
			Status:     models.ReachUnreachable,
			Confidence: 0.8,
			Evidence:   "artifact not imported in any production .java file",
		}, nil
	}

	// ── Layer 3: Vulnerable Class/Method Check ─────────────────────────────
	symbol, isCVESymbol := extractVulnerableSymbol(f)
	if symbol == "" {
		log.Debug().Str("pkg", artifactID).Msg("java: imported, no CVE symbol resolved → unknown")
		return reachability.Result{
			Status:     models.ReachUnknown,
			Confidence: 0.0,
			Evidence:   "artifact imported but CVE symbol not resolvable",
		}, nil
	}

	call := CheckSymbolCall(repoPath, symbol, sourceFiles)
	if call.Found {
		log.Debug().Str("pkg", artifactID).Str("symbol", symbol).Str("at", call.Evidence).
			Msg("java: vulnerable symbol called → reachable")
		return reachability.Result{
			Status:     models.ReachReachable,
			Confidence: 0.85,
			Evidence:   call.Evidence,
		}, nil
	}

	if !isCVESymbol {
		log.Debug().Str("pkg", artifactID).Msg("java: imported, fallback symbol not matched → unknown")
		return reachability.Result{
			Status:     models.ReachUnknown,
			Confidence: 0.4,
			Evidence:   "artifact imported; CVE symbol unknown, cannot confirm call",
		}, nil
	}

	log.Debug().Str("pkg", artifactID).Str("symbol", symbol).
		Msg("java: imported but vulnerable symbol not called → unreachable")
	return reachability.Result{
		Status:     models.ReachUnreachable,
		Confidence: 0.75,
		Evidence:   "artifact imported but vulnerable symbol " + symbol + " not called in production",
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
		log.Debug().Err(err).Str("repo", repoPath).Msg("java: manifest load failed")
		manifest = nil
	}

	imports, err := TraceImports(repoPath)
	if err != nil {
		return manifest, nil, err
	}

	a.lastRepo = repoPath
	a.manifest = manifest
	a.imports = imports
	return manifest, imports, nil
}

// extractArtifactID normalises the package name from a finding.
// Handles purl: pkg:maven/group/artifact@version → artifact
// and bare names like "log4j-core" or "com.example:my-lib"
func extractArtifactID(raw string) string {
	if raw == "" {
		return ""
	}
	if after, ok := strings.CutPrefix(strings.ToLower(raw), "pkg:maven/"); ok {
		parts := strings.SplitN(after, "/", 2)
		if len(parts) == 2 {
			artifact := parts[1]
			if idx := strings.Index(artifact, "@"); idx > 0 {
				artifact = artifact[:idx]
			}
			return normArtifact(artifact)
		}
	}
	return normArtifact(raw)
}

// extractVulnerableSymbol returns the class/method name from CVE metadata,
// or a fallback bare artifact name. isCVESymbol is false for fallback.
func extractVulnerableSymbol(f *models.Finding) (string, bool) {
	if f.Raw != nil {
		for _, key := range []string{"affected_functions", "affectedFunctions", "vulnerability_function", "affected_class"} {
			if v, ok := f.Raw[key]; ok {
				if s, ok := v.(string); ok && s != "" {
					return sanitizeSymbol(s), true
				}
				if arr, ok := v.([]interface{}); ok && len(arr) > 0 {
					if s, ok := arr[0].(string); ok && s != "" {
						return sanitizeSymbol(s), true
					}
				}
			}
		}
	}
	sym := normArtifact(extractArtifactID(f.Package))
	return sym, false
}

// sanitizeSymbol extracts the simple class or method name from a
// fully-qualified Java identifier like "org.apache.log4j.JndiLookup.lookup".
func sanitizeSymbol(s string) string {
	parts := strings.Split(s, ".")
	return parts[len(parts)-1]
}
