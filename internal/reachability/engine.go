// Package reachability decides whether each SCA finding is exercised by
// first-party code, using a 3-layer Static Import Graph Analysis engine.
//
// Layer 1 — Dependency Scope Classification (manifest parsing)
// Layer 2 — Import/Require Tracing (production files only)
// Layer 3 — Vulnerable Symbol Call Check (CVE advisory metadata)
//
// Joern CPG is intentionally NOT used for SCA reachability (empirical audit
// on gper00/lostpeople showed ~60% false positive rate). CPG types are kept
// in this package because internal/taint still uses them for SAST taint analysis.
package reachability

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
	"github.com/penanamtomat/supplychain-kit/internal/models"
)

// Result is the output of a ReachabilityAnalyzer for a single finding.
type Result struct {
	Status     models.Reachability
	Confidence float64
	Evidence   string // file:line where symbol is called, or reason for unreachable
}

// ReachabilityAnalyzer is a pluggable per-ecosystem static import graph analyzer.
// Implementations live in internal/reachability/<ecosystem>/.
type ReachabilityAnalyzer interface {
	// Ecosystem returns the ecosystem identifier this analyzer handles
	// (e.g. "npm", "pypi", "golang", "maven").
	Ecosystem() string

	// Analyze runs the 3-layer static import graph analysis for a single SCA
	// finding. repoPath is the absolute path to the repository root.
	Analyze(ctx context.Context, repoPath string, finding *models.Finding) (Result, error)
}

// Engine dispatches SCA findings to per-ecosystem ReachabilityAnalyzers and
// handles first-party SAST findings directly.
type Engine struct {
	analyzers map[string]ReachabilityAnalyzer
}

// New returns an Engine with the provided analyzers registered.
// Pass nil or an empty slice to get a no-op engine (all SCA findings → unknown).
func New(analyzers ...ReachabilityAnalyzer) *Engine {
	e := &Engine{analyzers: make(map[string]ReachabilityAnalyzer)}
	for _, a := range analyzers {
		if a != nil {
			e.analyzers[a.Ecosystem()] = a
		}
	}
	return e
}

// RegisterAnalyzer adds or replaces the analyzer for an ecosystem at runtime.
func (e *Engine) RegisterAnalyzer(a ReachabilityAnalyzer) {
	if a != nil {
		e.analyzers[a.Ecosystem()] = a
	}
}

// Analyze runs reachability analysis for every finding concurrently.
// repoPath is passed to ecosystem analyzers; cpgPath is kept for compatibility
// with call sites but is no longer used for SCA reachability (CPG is SAST-only).
func (e *Engine) Analyze(ctx context.Context, assetID, repoPath string, findings []*models.Finding) error {
	var wg sync.WaitGroup
	for _, f := range findings {
		wg.Add(1)
		go func(finding *models.Finding) {
			defer wg.Done()
			e.analyzeFinding(ctx, repoPath, finding)
		}(f)
	}
	wg.Wait()
	return nil
}

func (e *Engine) analyzeFinding(ctx context.Context, repoPath string, f *models.Finding) {
	// SAST / first-party findings are always reachable — the scanner found a
	// real code path, no further import tracing needed.
	if isFirstParty(f) {
		f.Reachability = models.ReachReachable
		f.Confidence = 1.0
		log.Debug().Str("rule_id", f.RuleID).Msg("reachability: first-party finding marked as REACHABLE")
		return
	}

	// SCA findings: delegate to the registered ecosystem analyzer.
	ecosystem := detectEcosystem(f)
	analyzer, ok := e.analyzers[ecosystem]
	if !ok {
		f.Reachability = models.ReachUnknown
		f.Confidence = 0.0
		log.Debug().Str("rule_id", f.RuleID).Str("pkg", f.Package).Str("ecosystem", ecosystem).
			Msg("reachability: no analyzer registered for ecosystem, marked as UNKNOWN")
		return
	}

	result, err := analyzer.Analyze(ctx, repoPath, f)
	if err != nil {
		log.Warn().Err(err).Str("rule_id", f.RuleID).Str("pkg", f.Package).
			Msg("reachability: analyzer error, falling back to UNKNOWN")
		f.Reachability = models.ReachUnknown
		f.Confidence = 0.0
		return
	}

	f.Reachability = result.Status
	f.Confidence = result.Confidence
	if result.Evidence != "" {
		f.Path = []string{result.Evidence}
	}
	log.Debug().Str("rule_id", f.RuleID).Str("pkg", f.Package).
		Str("status", string(result.Status)).Float64("confidence", result.Confidence).
		Msg("reachability: analyzer result")
}

// detectEcosystem infers the ecosystem from the finding's package purl or name.
// Returns a best-effort string; callers must tolerate "unknown".
func detectEcosystem(f *models.Finding) string {
	pkg := f.Package
	if pkg == "" {
		return "unknown"
	}
	// purl format: pkg:<type>/<namespace>/<name>@<version>
	if strings.HasPrefix(pkg, "pkg:npm") {
		return "npm"
	}
	if strings.HasPrefix(pkg, "pkg:pypi") {
		return "pypi"
	}
	if strings.HasPrefix(pkg, "pkg:golang") {
		return "golang"
	}
	if strings.HasPrefix(pkg, "pkg:maven") {
		return "maven"
	}
	if strings.HasPrefix(pkg, "pkg:cargo") {
		return "cargo"
	}
	// Heuristic for bare package names (non-purl findings from grype).
	if strings.Contains(pkg, "github.com") || strings.Contains(pkg, "golang.org") || strings.Contains(pkg, "go.uber.org") {
		return "golang"
	}
	return "unknown"
}

// analyzeWithCPG is kept for internal/taint SAST taint analysis. It is NOT
// called during normal SCA reachability evaluation.
func (e *Engine) analyzeWithCPG(cpg *CPG, f *models.Finding) {
	vulnerableSymbol := extractVulnerableSymbol(f)
	analysis := cpg.FindPathToSink(vulnerableSymbol, f.Package)

	if analysis.PathFound {
		f.Reachability = models.ReachReachable
		f.Confidence = analysis.Confidence
		f.Path = analysis.Path
	} else {
		f.Reachability = models.ReachUnreachable
		f.Confidence = analysis.Confidence
		f.Path = []string{}
	}
}

// ---------------------------------------------------------------------------
// CPG types — used by internal/taint for SAST taint analysis (not SCA).
// ---------------------------------------------------------------------------

type CPG struct {
	Vertices []*Vertex
	Edges    []*Edge

	methodsByFullname map[string]*Vertex
	callsBySource     map[string][]*Edge
	importsByFile     map[string][]string
}

type Vertex struct {
	ID         string
	Type       string
	Properties map[string]any
}

type Edge struct {
	From  string
	To    string
	Label string
}

type PathAnalysis struct {
	PathFound  bool
	Confidence float64
	Path       []string
}

func LoadCPG(path string) (*CPG, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat CPG path: %w", err)
	}

	var raw []byte

	if info.IsDir() {
		exportFile := filepath.Join(path, "export.json")
		if f, ferr := os.Stat(exportFile); ferr == nil && !f.IsDir() {
			raw, err = os.ReadFile(exportFile)
			if err != nil {
				return nil, fmt.Errorf("read export.json: %w", err)
			}
		} else {
			verticesFile := filepath.Join(path, "~1")
			edgesFile := filepath.Join(path, "~2")
			vd, verr := os.ReadFile(verticesFile)
			if verr != nil {
				return nil, fmt.Errorf("read vertices file: %w", verr)
			}
			ed, eerr := os.ReadFile(edgesFile)
			if eerr != nil {
				return nil, fmt.Errorf("read edges file: %w", eerr)
			}
			raw = []byte(fmt.Sprintf(`{"vertices":%s,"edges":%s}`, vd, ed))
		}
	} else {
		raw, err = os.ReadFile(path)
		if err != nil {
			return nil, err
		}
	}

	return parseCPG(raw)
}

func parseCPG(raw []byte) (*CPG, error) {
	var wrapper struct {
		Value json.RawMessage `json:"@value"`
	}
	if err := json.Unmarshal(raw, &wrapper); err == nil && len(wrapper.Value) > 0 {
		raw = wrapper.Value
	}

	var doc struct {
		Vertices []json.RawMessage `json:"vertices"`
		Edges    []json.RawMessage `json:"edges"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parse CPG: %w", err)
	}

	cpg := &CPG{
		Vertices:          make([]*Vertex, 0, len(doc.Vertices)),
		Edges:             make([]*Edge, 0, len(doc.Edges)),
		methodsByFullname: make(map[string]*Vertex),
		callsBySource:     make(map[string][]*Edge),
		importsByFile:     make(map[string][]string),
	}

	for _, rawV := range doc.Vertices {
		id, label, props := parseGraphSONVertex(rawV)
		vertex := &Vertex{ID: id, Type: label, Properties: props}
		cpg.Vertices = append(cpg.Vertices, vertex)

		if fullName, ok := props["FULL_NAME"].(string); ok && fullName != "" {
			cpg.methodsByFullname[fullName] = vertex
		}
		if fullName, ok := props["METHOD_FULL_NAME"].(string); ok && fullName != "" {
			cpg.methodsByFullname[fullName] = vertex
		}
	}

	for _, rawE := range doc.Edges {
		from, to, label := parseGraphSONEdge(rawE)
		edge := &Edge{From: to, To: from, Label: label}
		cpg.Edges = append(cpg.Edges, edge)
		cpg.callsBySource[edge.From] = append(cpg.callsBySource[edge.From], edge)
	}

	cpg.buildImportIndex()
	return cpg, nil
}

func parseGraphSONVertex(raw json.RawMessage) (id, label string, props map[string]any) {
	props = make(map[string]any)

	var v struct {
		ID         any            `json:"id"`
		Label      string         `json:"label"`
		Properties map[string]any `json:"properties"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		return "", "", props
	}

	id = fmt.Sprintf("%v", unwrapGraphSONValue(v.ID))
	label = v.Label

	for k, pv := range v.Properties {
		props[k] = unwrapGraphSONProperty(pv)
	}
	return id, label, props
}

func parseGraphSONEdge(raw json.RawMessage) (from, to, label string) {
	var e struct {
		InV   any    `json:"inV"`
		OutV  any    `json:"outV"`
		Label string `json:"label"`
	}
	if err := json.Unmarshal(raw, &e); err != nil {
		return "", "", ""
	}
	from = fmt.Sprintf("%v", unwrapGraphSONValue(e.InV))
	to = fmt.Sprintf("%v", unwrapGraphSONValue(e.OutV))
	return from, to, e.Label
}

func unwrapGraphSONValue(v any) any {
	m, ok := v.(map[string]any)
	if !ok {
		return v
	}
	if val, exists := m["@value"]; exists {
		return unwrapGraphSONValue(val)
	}
	return v
}

func unwrapGraphSONProperty(v any) any {
	unwrapped := unwrapGraphSONValue(v)
	if slice, ok := unwrapped.([]any); ok && len(slice) > 0 {
		return unwrapGraphSONValue(slice[0])
	}
	return unwrapped
}

func (cpg *CPG) buildImportIndex() {
	cpg.importsByFile = make(map[string][]string)

	for _, v := range cpg.Vertices {
		if v.Type == "FILE" {
			filename, _ := v.Properties["NAME"].(string)
			if imports, ok := v.Properties["IMPORTS"].([]any); ok {
				importList := make([]string, 0, len(imports))
				for _, imp := range imports {
					if s, ok := imp.(string); ok {
						importList = append(importList, s)
					}
				}
				if filename != "" {
					cpg.importsByFile[filename] = importList
				}
			}
		}
	}
}

func (cpg *CPG) FindPathToSink(vulnerableSymbol, pkgName string) PathAnalysis {
	if vulnerableSymbol == "" && pkgName == "" {
		return PathAnalysis{PathFound: false, Confidence: 0.0}
	}

	if vulnerableSymbol != "" {
		if path := cpg.findDirectCallPath(vulnerableSymbol); len(path) > 0 {
			return PathAnalysis{
				PathFound:  true,
				Confidence: 0.95,
				Path:       path,
			}
		}
	}

	if pkgName != "" {
		conf, files := cpg.checkPackageImports(pkgName)
		if files > 0 {
			return PathAnalysis{
				PathFound:  true,
				Confidence: conf,
				Path:       []string{fmt.Sprintf("Package %s imported in %d files", pkgName, files)},
			}
		}
	}

	if vulnerableSymbol != "" {
		for _, v := range cpg.Vertices {
			if name, ok := v.Properties["FULL_NAME"].(string); ok && strings.Contains(name, vulnerableSymbol) {
				return PathAnalysis{
					PathFound:  true,
					Confidence: 0.3,
					Path:       []string{fmt.Sprintf("Symbol %s found in CPG", vulnerableSymbol)},
				}
			}
		}
	}

	return PathAnalysis{PathFound: false, Confidence: 0.0, Path: []string{}}
}

func (cpg *CPG) findDirectCallPath(targetSymbol string) []string {
	sources := cpg.findEntryPoints()
	if len(sources) == 0 {
		return nil
	}

	target, exists := cpg.methodsByFullname[targetSymbol]
	if !exists {
		return nil
	}

	for _, src := range sources {
		if src.ID == target.ID {
			return []string{vertexFullName(src), vertexFullName(target)}
		}
	}

	visited := make(map[string]bool)
	queue := make([]string, 0)

	for _, src := range sources {
		visited[src.ID] = true
		queue = append(queue, src.ID)
	}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		if current == target.ID {
			return []string{vertexFullName(cpg.getVertex(current)), targetSymbol}
		}

		for _, edge := range cpg.callsBySource[current] {
			if !visited[edge.To] {
				visited[edge.To] = true
				queue = append(queue, edge.To)
			}
		}
	}

	return nil
}

func (cpg *CPG) findEntryPoints() []*Vertex {
	var entryPoints []*Vertex

	for _, v := range cpg.Vertices {
		name, hasName := v.Properties["FULL_NAME"].(string)
		if !hasName {
			name, _ = v.Properties["METHOD_FULL_NAME"].(string)
		}
		if name == "" {
			continue
		}

		lower := strings.ToLower(name)
		isEntryPoint :=
			strings.HasSuffix(lower, ".main") ||
				strings.Contains(lower, "handler") ||
				strings.Contains(lower, "controller") ||
				strings.Contains(lower, "serve") ||
				strings.Contains(lower, "listen") ||
				strings.Contains(lower, "start") ||
				strings.Contains(lower, "router") ||
				strings.Contains(lower, "middleware") ||
				strings.Contains(lower, "endpoint") ||
				strings.Contains(lower, ".handle") ||
				strings.Contains(lower, ".process") ||
				strings.Contains(lower, ".worker") ||
				strings.Contains(lower, "http") ||
				strings.Contains(lower, "grpc") ||
				strings.Contains(lower, "server")

		if isEntryPoint {
			entryPoints = append(entryPoints, v)
		}
	}

	return entryPoints
}

func (cpg *CPG) checkPackageImports(pkgName string) (float64, int) {
	var count int
	for _, imports := range cpg.importsByFile {
		for _, imp := range imports {
			if strings.Contains(imp, pkgName) {
				count++
				break
			}
		}
	}

	if count == 0 {
		return 0.0, 0
	}

	return capConfidence(0.7+float64(count)*0.05, 0.95), count
}

func (cpg *CPG) getVertex(id string) *Vertex {
	for _, v := range cpg.Vertices {
		if v.ID == id {
			return v
		}
	}
	return nil
}

func vertexFullName(v *Vertex) string {
	if v == nil {
		return ""
	}
	if name, ok := v.Properties["FULL_NAME"].(string); ok && name != "" {
		return name
	}
	if name, ok := v.Properties["METHOD_FULL_NAME"].(string); ok && name != "" {
		return name
	}
	return ""
}

func capConfidence(val, max float64) float64 {
	if val > max {
		return max
	}
	return val
}

func isFirstParty(f *models.Finding) bool {
	for _, s := range f.Sources {
		if s == models.SourceSemgrep || s == models.SourceJoern || s == models.SourceGitleaks {
			return true
		}
	}
	return false
}

func extractVulnerableSymbol(f *models.Finding) string {
	if f.Package == "" {
		return ""
	}
	parts := strings.Split(f.Package, "/")
	return parts[len(parts)-1]
}
