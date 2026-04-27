// Package golang implements the reachability analyzer for Go modules using
// govulncheck as a primary source and go.mod parsing as a fallback.
//
// Layer 1 — go.mod parsing: // indirect deps → ScopeTransitive (treated as runtime, lower confidence)
// Layer 2 — govulncheck -json: if the CVE ID is known-called → reachable; known-not-called → unreachable
// Graceful degradation: if govulncheck is not installed, fall back to Layer 1 + unknown.
package golang

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
	"github.com/penanamtomat/supplychain-kit/internal/models"
	"github.com/penanamtomat/supplychain-kit/internal/reachability"
)

// Analyzer implements reachability.ReachabilityAnalyzer for the Go ecosystem.
type Analyzer struct {
	mu       sync.Mutex
	gomod    *modResult   // cached per repo
	vulnDB   *govulnResult // cached per repo
	lastRepo string
}

// NewAnalyzer returns a new Go ReachabilityAnalyzer.
func NewAnalyzer() *Analyzer { return &Analyzer{} }

func (a *Analyzer) Ecosystem() string { return "golang" }

// Analyze runs reachability analysis for a single Go SCA finding.
func (a *Analyzer) Analyze(ctx context.Context, repoPath string, f *models.Finding) (reachability.Result, error) {
	pkgName := extractModuleName(f.Package)
	if pkgName == "" {
		return reachability.Result{Status: models.ReachUnknown}, nil
	}

	gomod, vuln, err := a.loadRepo(ctx, repoPath)
	if err != nil {
		log.Warn().Err(err).Str("repo", repoPath).Msg("golang: failed to load repo data")
		return reachability.Result{Status: models.ReachUnknown}, nil
	}

	// ── govulncheck result (most authoritative) ────────────────────────────
	// govulncheck performs real call-graph analysis: if a vuln ID is in the
	// "called" set, the vulnerable symbol is actually exercised.
	if vuln != nil {
		vulnID := f.RuleID // e.g. "CVE-2024-12345" or "GHSA-..." or "GO-..."
		if status, ok := vuln.Lookup(pkgName, vulnID); ok {
			if status == vulnCalled {
				return reachability.Result{
					Status:     models.ReachReachable,
					Confidence: 0.95,
					Evidence:   "govulncheck: vulnerable symbol is called",
				}, nil
			}
			return reachability.Result{
				Status:     models.ReachUnreachable,
				Confidence: 0.9,
				Evidence:   "govulncheck: package imported but vulnerable symbol not called",
			}, nil
		}
		// Vuln ID not in govulncheck output: either no vuln found by GVC or
		// ID mismatch (CVE vs GO alias). Fall through to Layer 1.
	}

	// ── Layer 1: go.mod indirect flag ─────────────────────────────────────
	// `// indirect` in go.mod means the module is not directly imported by
	// first-party code (only needed because another dep requires it).
	if gomod != nil {
		if gomod.IsIndirect(pkgName) {
			log.Debug().Str("pkg", pkgName).Msg("golang: indirect dep in go.mod → unknown (transitive)")
			return reachability.Result{
				Status:     models.ReachUnknown,
				Confidence: 0.3,
				Evidence:   "go.mod: marked // indirect (transitive dep, govulncheck not conclusive)",
			}, nil
		}
		if gomod.IsDirect(pkgName) {
			// Direct dep but govulncheck didn't flag it → likely not vulnerable
			// or govulncheck couldn't match the CVE ID. Return unknown.
			log.Debug().Str("pkg", pkgName).Msg("golang: direct dep, govulncheck inconclusive → unknown")
			return reachability.Result{
				Status:     models.ReachUnknown,
				Confidence: 0.4,
				Evidence:   "go.mod: direct dep, govulncheck did not flag call",
			}, nil
		}
	}

	return reachability.Result{Status: models.ReachUnknown}, nil
}

// loadRepo lazily initialises go.mod + govulncheck result for the given repo.
func (a *Analyzer) loadRepo(ctx context.Context, repoPath string) (*modResult, *govulnResult, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.lastRepo == repoPath && a.gomod != nil {
		return a.gomod, a.vulnDB, nil
	}

	gomod, err := parseGoMod(repoPath)
	if err != nil {
		log.Debug().Err(err).Str("repo", repoPath).Msg("golang: go.mod parse failed")
		gomod = nil
	}

	vuln, err := runGovulncheck(ctx, repoPath)
	if err != nil {
		// govulncheck not installed or failed — graceful degradation.
		log.Debug().Err(err).Str("repo", repoPath).Msg("golang: govulncheck unavailable, using Layer 1 only")
		vuln = nil
	}

	a.lastRepo = repoPath
	a.gomod = gomod
	a.vulnDB = vuln
	return gomod, vuln, nil
}

// ── go.mod parsing ────────────────────────────────────────────────────────────

type modScope int

const (
	scopeDirect   modScope = iota
	scopeIndirect modScope = iota
)

type modResult struct {
	mods map[string]modScope // module path → scope
}

func (m *modResult) IsDirect(pkg string) bool {
	s, ok := m.mods[normModule(pkg)]
	return ok && s == scopeDirect
}

func (m *modResult) IsIndirect(pkg string) bool {
	s, ok := m.mods[normModule(pkg)]
	return ok && s == scopeIndirect
}

// parseGoMod reads go.mod and classifies each require line.
func parseGoMod(repoPath string) (*modResult, error) {
	data, err := os.ReadFile(filepath.Join(repoPath, "go.mod"))
	if err != nil {
		return nil, err
	}

	result := &modResult{mods: make(map[string]modScope)}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	inRequire := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "require (" {
			inRequire = true
			continue
		}
		if inRequire && line == ")" {
			inRequire = false
			continue
		}

		var modLine string
		if inRequire {
			modLine = line
		} else if strings.HasPrefix(line, "require ") {
			modLine = strings.TrimPrefix(line, "require ")
		} else {
			continue
		}

		// Strip inline comments: "github.com/foo/bar v1.2.3 // indirect"
		modLine = strings.TrimSpace(modLine)
		isIndirect := strings.Contains(modLine, "// indirect")
		modLine = strings.SplitN(modLine, "//", 2)[0]
		parts := strings.Fields(modLine)
		if len(parts) < 1 {
			continue
		}
		modPath := normModule(parts[0])
		if isIndirect {
			result.mods[modPath] = scopeIndirect
		} else {
			result.mods[modPath] = scopeDirect
		}
	}

	return result, scanner.Err()
}

// ── govulncheck integration ───────────────────────────────────────────────────

type vulnStatus int

const (
	vulnCalled    vulnStatus = iota // govulncheck confirmed call chain
	vulnNotCalled vulnStatus = iota // present but not called
)

// govulnResult stores the per-(module, vuln-id) call status from govulncheck.
type govulnResult struct {
	// key: "<normModule>|<vulnID>"
	entries map[string]vulnStatus
}

func (g *govulnResult) Lookup(module, vulnID string) (vulnStatus, bool) {
	key := normModule(module) + "|" + strings.ToUpper(vulnID)
	s, ok := g.entries[key]
	return s, ok
}

// govulncheckOutput mirrors the govulncheck -json stream (each line is one JSON object).
// We only care about "finding" messages.
type govulnMessage struct {
	Finding *govulnFinding `json:"finding"`
}

type govulnFinding struct {
	OSV   string          `json:"osv"`   // GO-YYYY-NNNN
	Trace []govulnFrame   `json:"trace"` // non-empty → symbol called
	// Aliases populated by govulncheck ≥ v1.1
	Aliases []string      `json:"aliases,omitempty"`
}

type govulnFrame struct {
	Module   string `json:"module"`
	Function string `json:"function"`
}

// runGovulncheck shells out to govulncheck -json ./... and parses the stream.
// Returns nil, error if govulncheck is not installed or fails unexpectedly.
func runGovulncheck(ctx context.Context, repoPath string) (*govulnResult, error) {
	binary, err := exec.LookPath("govulncheck")
	if err != nil {
		return nil, errors.New("govulncheck not found in PATH")
	}

	cmd := exec.CommandContext(ctx, binary, "-json", "./...")
	cmd.Dir = repoPath
	out, err := cmd.Output()
	if err != nil {
		// govulncheck exits 1 when vulnerabilities are found — that's normal.
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			return nil, err
		}
	}

	return parseGovulnStream(bytes.NewReader(out)), nil
}


// parseGovulnStream parses the line-delimited JSON stream emitted by
// govulncheck -json and returns a govulnResult. Separated for testability.
func parseGovulnStream(r io.Reader) *govulnResult {
	result := &govulnResult{entries: make(map[string]vulnStatus)}
	decoder := json.NewDecoder(r)

	for decoder.More() {
		var msg govulnMessage
		if err := decoder.Decode(&msg); err != nil {
			break
		}
		f := msg.Finding
		if f == nil {
			continue
		}

		// Collect all ID aliases (GO-..., CVE-..., GHSA-...).
		ids := append([]string{f.OSV}, f.Aliases...)

		// A trace with >1 frame means the vulnerable symbol is reachable
		// from first-party code. A single-frame trace (just the vuln itself,
		// no caller) means it's present but not called.
		status := vulnNotCalled
		if len(f.Trace) > 1 {
			status = vulnCalled
		}

		// Record for every module mentioned in the trace and every alias.
		for _, frame := range f.Trace {
			if frame.Module == "" {
				continue
			}
			modKey := normModule(frame.Module)
			for _, id := range ids {
				if id == "" {
					continue
				}
				key := modKey + "|" + strings.ToUpper(id)
				// "called" wins over "not-called" if multiple findings exist.
				if existing, ok := result.entries[key]; !ok || existing == vulnNotCalled {
					result.entries[key] = status
				}
			}
		}
	}

	return result
}

// ── helpers ───────────────────────────────────────────────────────────────────

// extractModuleName normalises the package name from a finding.
// Handles bare module paths and purl: pkg:golang/github.com/foo/bar@v1.2.3
func extractModuleName(raw string) string {
	if raw == "" {
		return ""
	}
	if after, ok := strings.CutPrefix(raw, "pkg:golang/"); ok {
		if idx := strings.Index(after, "@"); idx > 0 {
			return after[:idx]
		}
		return after
	}
	return raw
}

// normModule lowercases the module path and strips the version suffix.
func normModule(path string) string {
	path = strings.ToLower(strings.TrimSpace(path))
	if idx := strings.Index(path, "@"); idx > 0 {
		path = path[:idx]
	}
	return path
}
