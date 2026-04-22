// Package reachability decides whether each Grype/SCA finding is exercised
// by first-party code (static analysis over a Joern CPG export) and, when
// available, confirms reachability via eBPF runtime telemetry.
//
// The CPG analyzer here is intentionally a small, well-defined subset: it
// loads symbols touched by source files and treats a package as "reachable"
// when any of its exported symbols appears in the call graph. A production
// deployment swaps this for a full source-to-sink path search; the interface
// remains stable.
package reachability

import (
	"context"
	"encoding/json"
	"os"
	"strings"

	"github.com/penanamtomat/supplychain-kit/internal/models"
)

// Engine combines a static CPG analyzer with optional runtime confirmation.
type Engine struct {
	runtime RuntimeConfirmer // optional; nil = no eBPF
}

// RuntimeConfirmer reports whether a package is loaded into a running process.
type RuntimeConfirmer interface {
	IsLoaded(ctx context.Context, assetID, pkg string) (bool, error)
}

// New returns an Engine with the supplied (possibly nil) runtime confirmer.
func New(rt RuntimeConfirmer) *Engine { return &Engine{runtime: rt} }

// Analyze annotates each finding with a Reachability verdict. cpgPath may be
// empty; in that case every finding is left as ReachUnknown for SCA hits and
// ReachReachable for SAST/secret findings (those are first-party by nature).
func (e *Engine) Analyze(ctx context.Context, assetID, cpgPath string, findings []*models.Finding) error {
	usedSymbols, err := loadSymbols(cpgPath)
	if err != nil {
		// Missing CPG isn't fatal — degrade to "unknown" for SCA findings.
		usedSymbols = nil
	}

	for _, f := range findings {
		// SAST and secret findings are inherently first-party.
		if isFirstParty(f) {
			if f.Reachability == "" || f.Reachability == models.ReachUnknown {
				f.Reachability = models.ReachReachable
			}
			continue
		}

		// SCA: try CPG, then optionally confirm at runtime.
		switch {
		case usedSymbols != nil && containsPackage(usedSymbols, f.Package):
			f.Reachability = models.ReachReachable
		case usedSymbols != nil:
			f.Reachability = models.ReachUnreachable
		default:
			f.Reachability = models.ReachUnknown
		}

		if e.runtime != nil {
			loaded, err := e.runtime.IsLoaded(ctx, assetID, f.Package)
			if err == nil && loaded {
				f.Reachability = models.ReachConfirmed
			}
		}
	}
	return nil
}

func isFirstParty(f *models.Finding) bool {
	for _, s := range f.Sources {
		if s == models.SourceSemgrep || s == models.SourceJoern || s == models.SourceGitleaks {
			return true
		}
	}
	return false
}

// loadSymbols reads a graphson-exported CPG and returns the set of symbol
// names referenced anywhere in the call graph. Real implementations should
// stream this for large graphs; we read it whole here to keep the reference
// implementation easy to follow.
func loadSymbols(path string) (map[string]struct{}, error) {
	if path == "" {
		return nil, os.ErrNotExist
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Vertices []struct {
			Properties map[string]any `json:"properties"`
		} `json:"vertices"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	syms := map[string]struct{}{}
	for _, v := range doc.Vertices {
		if name, ok := v.Properties["FULL_NAME"].(string); ok && name != "" {
			syms[name] = struct{}{}
		}
		if name, ok := v.Properties["METHOD_FULL_NAME"].(string); ok && name != "" {
			syms[name] = struct{}{}
		}
	}
	return syms, nil
}

func containsPackage(syms map[string]struct{}, pkg string) bool {
	if pkg == "" {
		return false
	}
	for s := range syms {
		if strings.Contains(s, pkg) {
			return true
		}
	}
	return false
}
