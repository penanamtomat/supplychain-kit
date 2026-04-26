package taint

import (
	"strings"

	"github.com/penanamtomat/supplychain-kit/internal/reachability"
)

type SanitizerType string

const (
	SanitValidate   SanitizerType = "validate"
	SanitEscape     SanitizerType = "escape"
	SanitFilter     SanitizerType = "filter"
	SanitTypeCheck  SanitizerType = "type_check"
	SanitNormalize  SanitizerType = "normalize"
)

type Sanitizer struct {
	Type      SanitizerType
	Name      string
	File      string
	Line      int
	Efficacy  float64
}

type Propagator struct {
	cpg         *reachability.CPG
	sources     []Source
	sanitizers  []Sanitizer
	// adjacency lists built from CPG edges
	callTargets  map[string][]string // CALL vertex ID -> list of target METHOD vertex IDs
	contains     map[string][]string // parent vertex ID -> child vertex IDs (AST/CONTAINS)
	reachingDef map[string][]string // def vertex ID -> use vertex IDs (REACHING_DEF)
	argument    map[string][]string // argument vertex ID -> parameter vertex IDs
	vertexNames map[string]string   // vertex ID -> METHOD_FULL_NAME or FULL_NAME
	vertexTypes map[string]string   // vertex ID -> label
	registry    *SanitizerRegistry  // ecosystem-specific sanitizer catalog
}

func NewPropagator(cpg *reachability.CPG, sources []Source) *Propagator {
	p := &Propagator{
		cpg:         cpg,
		sources:     sources,
		callTargets: make(map[string][]string),
		contains:    make(map[string][]string),
		reachingDef: make(map[string][]string),
		argument:    make(map[string][]string),
		vertexNames: make(map[string]string),
		vertexTypes: make(map[string]string),
		registry:    NewSanitizerRegistry(),
	}
	if cpg != nil {
		p.buildGraph()
		p.detectSanitizers()
	}
	return p
}

func (p *Propagator) buildGraph() {
	for _, v := range p.cpg.Vertices {
		name := p.extractName(v)
		p.vertexNames[v.ID] = name
		p.vertexTypes[v.ID] = v.Type
	}

	for _, e := range p.cpg.Edges {
		switch e.Label {
		case "CALL":
			p.callTargets[e.From] = append(p.callTargets[e.From], e.To)
		case "AST", "CONTAINS":
			p.contains[e.From] = append(p.contains[e.From], e.To)
		case "REACHING_DEF":
			p.reachingDef[e.From] = append(p.reachingDef[e.From], e.To)
		case "ARGUMENT":
			p.argument[e.From] = append(p.argument[e.From], e.To)
		}
	}
}

func (p *Propagator) extractName(v *reachability.Vertex) string {
	if name, ok := v.Properties["METHOD_FULL_NAME"].(string); ok && name != "" {
		return name
	}
	if name, ok := v.Properties["FULL_NAME"].(string); ok && name != "" {
		return name
	}
	if name, ok := v.Properties["NAME"].(string); ok && name != "" {
		return name
	}
	if code, ok := v.Properties["CODE"].(string); ok && code != "" {
		return code
	}
	return ""
}

func (p *Propagator) detectSanitizers() {
	if p.cpg == nil {
		return
	}

	for _, v := range p.cpg.Vertices {
		if v.Type != "CALL" {
			continue
		}

		name, ok := v.Properties["NAME"].(string)
		if !ok {
			name, _ = v.Properties["METHOD_FULL_NAME"].(string)
		}
		if name == "" {
			continue
		}

		sanitizer := p.isSanitizer(name)
		if sanitizer != nil {
			p.sanitizers = append(p.sanitizers, *sanitizer)
		}
	}
}

func (p *Propagator) isSanitizer(name string) *Sanitizer {
	// Prefer ecosystem-specific registry match (higher-fidelity efficacy scores).
	if p.registry != nil {
		if san := p.registry.Lookup(name); san != nil {
			hit := *san
			hit.Name = name
			return &hit
		}
	}

	lower := strings.ToLower(name)

	if strings.Contains(lower, "validate") || strings.Contains(lower, "verify") || strings.Contains(lower, "check") {
		return &Sanitizer{Type: SanitValidate, Name: name, Efficacy: 0.8}
	}
	if strings.Contains(lower, "escape") || strings.Contains(lower, "encode") || strings.Contains(lower, "sanitize") {
		return &Sanitizer{Type: SanitEscape, Name: name, Efficacy: 0.7}
	}
	if strings.Contains(lower, "filter") || strings.Contains(lower, "allowlist") || strings.Contains(lower, "whitelist") {
		return &Sanitizer{Type: SanitFilter, Name: name, Efficacy: 0.6}
	}
	if strings.Contains(lower, "type") || strings.Contains(lower, "cast") || strings.Contains(lower, "assert") {
		return &Sanitizer{Type: SanitTypeCheck, Name: name, Efficacy: 0.9}
	}

	return nil
}

type TaintNode struct {
	ID         string
	Source     *Source
	Sanitized  bool
	Confidence float64
	Path       []string
}

func (p *Propagator) Trace(targetSymbol string) TaintResult {
	if p.cpg == nil || len(p.sources) == 0 {
		return TaintResult{Exploitable: false, Confidence: 0.0}
	}

	var bestResult TaintResult
	for _, source := range p.sources {
		result := p.traceFromSource(&source, targetSymbol)
		if result.Exploitable && result.Confidence > bestResult.Confidence {
			bestResult = result
		}
	}
	return bestResult
}

type TaintResult struct {
	Exploitable     bool
	Confidence      float64
	Path            []string
	SanitizerFound  bool
}

func (p *Propagator) traceFromSource(source *Source, targetSymbol string) TaintResult {
	if p.cpg == nil {
		return TaintResult{Exploitable: false, Confidence: 0.0}
	}

	lowerTarget := strings.ToLower(targetSymbol)

	// Find all target vertex IDs in CPG
	var targetIDs []string
	for id, name := range p.vertexNames {
		if p.nameMatchesTarget(name, lowerTarget) {
			targetIDs = append(targetIDs, id)
		}
	}

	// BFS from source vertex through graph edges
	startID := source.CPGID
	if startID == "" {
		// Fallback: find vertex by name
		for id, name := range p.vertexNames {
			if name == source.Symbol || strings.Contains(strings.ToLower(name), strings.ToLower(source.Symbol)) {
				startID = id
				break
			}
		}
	}
	if startID == "" {
		return TaintResult{Exploitable: false, Confidence: 0.0}
	}

	targetSet := make(map[string]bool)
	for _, id := range targetIDs {
		targetSet[id] = true
	}

	visited := make(map[string]bool)
	startName := source.Symbol
	if startName == "" {
		startName = p.vertexNames[startID]
	}
	queue := []TaintNode{
		{
			ID:         startID,
			Source:     source,
			Sanitized:  false,
			Confidence: 1.0,
			Path:       []string{startName},
		},
	}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		// Check if current node matches target
		if targetSet[current.ID] {
			return TaintResult{
				Exploitable:     true,
				Confidence:      current.Confidence,
				Path:            sanitizePath(current.Path),
				SanitizerFound:  current.Sanitized,
			}
		}

		if visited[current.ID] {
			continue
		}
		visited[current.ID] = true

		// Expand: find neighbors through CPG edges
		nextNodes := p.expandNode(current.ID)
		for _, nextID := range nextNodes {
			if visited[nextID] {
				continue
			}

			name := p.vertexNames[nextID]
			if name == "" {
				continue
			}

			sanitizer := p.findSanitizerForVertex(nextID)
			confidence := current.Confidence
			if sanitizer != nil {
				confidence *= sanitizer.Efficacy
			}

			newPath := make([]string, len(current.Path)+1)
			copy(newPath, current.Path)
			newPath[len(current.Path)] = name

			queue = append(queue, TaintNode{
				ID:         nextID,
				Source:     current.Source,
				Sanitized:  current.Sanitized || sanitizer != nil,
				Confidence: confidence,
				Path:       newPath,
			})
		}

		// Limit search depth
		if len(current.Path) > 20 {
			break
		}
	}

	return TaintResult{Exploitable: false, Confidence: 0.0}
}

// sanitizePath removes internal CPG markers from taint path before output.
// These are artifacts from Joern CPG that are not meaningful to users.
func sanitizePath(path []string) []string {
	if len(path) == 0 {
		return path
	}

	// Internal CPG markers to filter (case-sensitive)
	internalMarkers := map[string]bool{
		"RET":      true, // return value marker
		"as":       true, // alias/type cast artifact
		"<lambda>": true, // anonymous function marker
		"<init>":   true, // constructor marker
		"<clinit>": true, // class initializer marker
		"<static>": true, // static initializer marker
		"this":     true, // this reference (not a useful path element)
	}

	result := make([]string, 0, len(path))
	for _, p := range path {
		// Skip internal markers
		if internalMarkers[p] {
			continue
		}
		// Skip angle-bracket wrapped patterns (Joern internal nodes)
		if len(p) > 2 && p[0] == '<' && p[len(p)-1] == '>' {
			continue
		}
		result = append(result, p)
	}

	// Ensure at least one element remains
	if len(result) == 0 && len(path) > 0 {
		// Fallback: keep the source (first element)
		result = []string{path[0]}
	}

	return result
}

func (p *Propagator) expandNode(nodeID string) []string {
	var neighbors []string

	// Follow all edge types outward
	for _, targets := range []map[string][]string{p.callTargets, p.contains, p.reachingDef, p.argument} {
		if targets, ok := targets[nodeID]; ok {
			neighbors = append(neighbors, targets...)
		}
	}

	// Also do reverse lookup: if any vertex has an edge TO this node, follow back
	// This helps with data flow (REACHING_DEF goes from def to use, but taint flows use -> def)
	for fromID, targets := range p.reachingDef {
		for _, t := range targets {
			if t == nodeID {
				neighbors = append(neighbors, fromID)
			}
		}
	}

	return neighbors
}

func (p *Propagator) nameMatchesTarget(name, lowerTarget string) bool {
	lower := strings.ToLower(name)
	if lower == lowerTarget {
		return true
	}
	return strings.Contains(lower, lowerTarget) || strings.Contains(lowerTarget, lower)
}

func (p *Propagator) findSanitizerForVertex(vertexID string) *Sanitizer {
	name := p.vertexNames[vertexID]
	if name == "" {
		return nil
	}
	lower := strings.ToLower(name)
	for _, san := range p.sanitizers {
		if strings.Contains(lower, strings.ToLower(san.Name)) {
			return &san
		}
	}
	return nil
}
