// Package reachability decides whether each Grype/SCA finding is exercised
// by first-party code (static analysis over a Joern CPG export) and, when
// available, confirms reachability via eBPF runtime telemetry.
package reachability

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/penanamtomat/supplychain-kit/internal/models"
)

type Engine struct {
	runtime RuntimeConfirmer
}

type RuntimeConfirmer interface {
	IsLoaded(ctx context.Context, assetID, pkg string) (bool, error)
}

func New(rt RuntimeConfirmer) *Engine {
	return &Engine{runtime: rt}
}

func (e *Engine) Analyze(ctx context.Context, assetID, cpgPath string, findings []*models.Finding) error {
	var cpg *CPG
	var err error

	if cpgPath != "" {
		cpg, err = loadCPG(cpgPath)
		if err != nil {
			cpg = nil
		}
	}

	var wg sync.WaitGroup
	for _, f := range findings {
		wg.Add(1)
		go func(finding *models.Finding) {
			defer wg.Done()
			e.analyzeFinding(ctx, assetID, cpg, finding)
		}(f)
	}
	wg.Wait()
	return nil
}

func (e *Engine) analyzeFinding(ctx context.Context, assetID string, cpg *CPG, f *models.Finding) {
	if isFirstParty(f) {
		if f.Reachability == "" || f.Reachability == models.ReachUnknown {
			f.Reachability = models.ReachReachable
			f.Confidence = 1.0
		}
		return
	}

	if cpg != nil {
		e.analyzeWithCPG(cpg, f)
	} else {
		f.Reachability = models.ReachUnknown
		f.Confidence = 0.0
	}

	if e.runtime != nil && f.Package != "" {
		loaded, err := e.runtime.IsLoaded(ctx, assetID, f.Package)
		if err == nil && loaded {
			f.Reachability = models.ReachConfirmed
			f.Confidence = 1.0
		}
	}
}

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

func loadCPG(path string) (*CPG, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var doc struct {
		Vertices []struct {
			ID         string         `json:"id"`
			Label      string         `json:"label"`
			Properties map[string]any `json:"properties"`
		} `json:"vertices"`
		Edges []struct {
			From string `json:"inV"`
			To   string `json:"outV"`
			Label string `json:"label"`
		} `json:"edges"`
	}

	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parse CPG: %w", err)
	}

	cpg := &CPG{
		Vertices:          make([]*Vertex, 0, len(doc.Vertices)),
		Edges:            make([]*Edge, 0, len(doc.Edges)),
		methodsByFullname: make(map[string]*Vertex),
		callsBySource:     make(map[string][]*Edge),
		importsByFile:     make(map[string][]string),
	}

	for _, v := range doc.Vertices {
		vertex := &Vertex{
			ID:         v.ID,
			Type:       v.Label,
			Properties: v.Properties,
		}
		cpg.Vertices = append(cpg.Vertices, vertex)

		if fullName, ok := v.Properties["FULL_NAME"].(string); ok && fullName != "" {
			cpg.methodsByFullname[fullName] = vertex
		}
		if fullName, ok := v.Properties["METHOD_FULL_NAME"].(string); ok && fullName != "" {
			cpg.methodsByFullname[fullName] = vertex
		}
	}

	for _, e := range doc.Edges {
		edge := &Edge{
			From:  e.To,
			To:    e.From,
			Label: e.Label,
		}
		cpg.Edges = append(cpg.Edges, edge)
		cpg.callsBySource[edge.From] = append(cpg.callsBySource[edge.From], edge)
	}

	cpg.buildImportIndex()

	return cpg, nil
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

	return PathAnalysis{
		PathFound:  false,
		Confidence: 0.0,
		Path:       []string{},
	}
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
			strings.Contains(lower, ".worker")

		if !isEntryPoint {
			isEntryPoint = strings.Contains(lower, "http") ||
				strings.Contains(lower, "grpc") ||
				strings.Contains(lower, "server")
		}

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

	conf := capConfidence(0.7+float64(count)*0.05, 0.95)

	return conf, count
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

// capConfidence clamps confidence to a maximum value.
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
	symbol := parts[len(parts)-1]

	// If the RuleID looks like a CWE or a function-specific rule (e.g. semgrep rule
	// with a function name), prefer using the package-level symbol.
	// For SCA findings (grype), the package name is the best signal we have.
	if symbol == "" {
		return ""
	}

	return symbol
}
