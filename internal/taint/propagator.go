// Package taint implements dependency-aware SAST by tracing user-controlled input
// through codebase to determine which CVEs are truly exploitable.
// This bridges SCA (Grype/Trivy) and SAST (Semgrep/Joern) findings.
package taint

import (
	"strings"

	"github.com/penanamtomat/supplychain-kit/internal/reachability"
)

// SanitizerType represents a validation/sanitization function.
type SanitizerType string

const (
	SanitValidate     SanitizerType = "validate"
	SanitEscape       SanitizerType = "escape"
	SanitFilter       SanitizerType = "filter"
	SanitTypeCheck    SanitizerType = "type_check"
	SanitNormalize     SanitizerType = "normalize"
)

// Sanitizer represents a function that cleans/validates tainted data.
type Sanitizer struct {
	Type   SanitizerType
	Name   string
	File   string
	Line   int
	Efficacy float64 // 0.0 = completely ineffective, 1.0 = perfect
}

// Propagator traces taint from sources through call graph.
type Propagator struct {
	cpg          *reachability.CPG
	sources      []Source
	sanitizers  []Sanitizer
}

// NewPropagator creates a new taint propagator.
func NewPropagator(cpg *reachability.CPG, sources []Source) *Propagator {
	p := &Propagator{
		cpg:     cpg,
		sources:  sources,
	}
	p.detectSanitizers()
	return p
}

// detectSanitizers finds validation/escape functions in CPG.
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
	lower := strings.ToLower(name)

	// Common validation patterns
	if strings.Contains(lower, "validate") || strings.Contains(lower, "verify") || strings.Contains(lower, "check") {
		return &Sanitizer{
			Type:     SanitValidate,
			Name:     name,
			File:     "",
			Line:     0,
			Efficacy: 0.8,
		}
	}

	// Common escape patterns
	if strings.Contains(lower, "escape") || strings.Contains(lower, "encode") || strings.Contains(lower, "sanitize") {
		return &Sanitizer{
			Type:     SanitEscape,
			Name:     name,
			File:     "",
			Line:     0,
			Efficacy: 0.7,
		}
	}

	// Common filter patterns
	if strings.Contains(lower, "filter") || strings.Contains(lower, "allowlist") || strings.Contains(lower, "whitelist") {
		return &Sanitizer{
			Type:     SanitFilter,
			Name:     name,
			File:     "",
			Line:     0,
			Efficacy: 0.6,
		}
	}

	// Type checks
	if strings.Contains(lower, "type") || strings.Contains(lower, "cast") || strings.Contains(lower, "assert") {
		return &Sanitizer{
			Type:     SanitTypeCheck,
			Name:     name,
			File:     "",
			Line:     0,
			Efficacy: 0.9,
		}
	}

	return nil
}

// TaintNode represents a node in taint flow graph.
type TaintNode struct {
	ID         string
	Source     *Source
	Sanitized   bool
	Confidence float64
	Path       []string
}

// Trace propagates taint from all sources through call graph.
func (p *Propagator) Trace(targetSymbol string) TaintResult {
	if p.cpg == nil || len(p.sources) == 0 {
		return TaintResult{
			Exploitable: false,
			Confidence:  0.0,
			Path:       []string{},
		}
	}

	var bestResult TaintResult

	// Try to find path from each source to target
	for _, source := range p.sources {
		result := p.traceFromSource(&source, targetSymbol)
		if result.Exploitable && result.Confidence > bestResult.Confidence {
			bestResult = result
		}
	}

	return bestResult
}

// TaintResult represents outcome of taint trace.
type TaintResult struct {
	Exploitable bool
	Confidence float64
	Path       []string
	SanitizerFound bool
}

func (p *Propagator) traceFromSource(source *Source, targetSymbol string) TaintResult {
	if p.cpg == nil {
		return TaintResult{Exploitable: false, Confidence: 0.0}
	}

	// BFS from source through call graph
	visited := make(map[string]bool)
	queue := []TaintNode{
		{
			ID:         source.Symbol,
			Source:     source,
			Sanitized:   false,
			Confidence: 1.0,
			Path:       []string{source.Symbol},
		},
	}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		// Check if we reached the target
		if strings.Contains(current.ID, targetSymbol) || p.cpgMatchesTarget(current.ID, targetSymbol) {
			return TaintResult{
				Exploitable:     true,
				Confidence:      current.Confidence,
				Path:           current.Path,
				SanitizerFound: current.Sanitized,
			}
		}

		if visited[current.ID] {
			continue
		}
		visited[current.ID] = true

		// Find next nodes (function calls)
		nextNodes := p.findNextCalls(current.ID)
		for _, next := range nextNodes {
			// Extract method name from vertex
			methodName := p.extractMethodName(next)
			if methodName == "" {
				continue
			}

			sanitizer := p.findSanitizerForCall(next)
			confidence := current.Confidence

			// Reduce confidence when crossing sanitizer
			if sanitizer != nil {
				confidence *= sanitizer.Efficacy
				visited[methodName] = true // Mark sanitized paths as visited
			}

			newPath := make([]string, len(current.Path)+1)
			copy(newPath, current.Path)
			newPath[len(current.Path)] = methodName

			queue = append(queue, TaintNode{
				ID:         methodName,
				Source:     current.Source,
				Sanitized:   current.Sanitized || sanitizer != nil,
				Confidence: confidence,
				Path:       newPath,
			})
		}

		// Limit search depth to avoid infinite loops
		if len(current.Path) > 20 {
			break
		}
	}

	return TaintResult{Exploitable: false, Confidence: 0.0}
}

func (p *Propagator) extractMethodName(v *reachability.Vertex) string {
	if name, ok := v.Properties["METHOD_FULL_NAME"].(string); ok && name != "" {
		return name
	}
	if name, ok := v.Properties["FULL_NAME"].(string); ok && name != "" {
		return name
	}
	return ""
}

func (p *Propagator) findNextCalls(symbolID string) []*reachability.Vertex {
	var next []*reachability.Vertex

	// Find calls that contain this symbol
	for _, v := range p.cpg.Vertices {
		if v.Type != "CALL" && v.Type != "IDENTIFIER" {
			continue
		}

		name, ok := v.Properties["FULL_NAME"].(string)
		if !ok {
			name, _ = v.Properties["METHOD_FULL_NAME"].(string)
		}
		if name == "" {
			continue
		}

		if strings.Contains(name, symbolID) {
			next = append(next, v)
		}
	}

	return next
}

func (p *Propagator) cpgMatchesTarget(cpgSymbol, targetSymbol string) bool {
	// Fuzzy matching for symbol names
	lowerCPG := strings.ToLower(cpgSymbol)
	lowerTarget := strings.ToLower(targetSymbol)

	// Direct match
	if lowerCPG == lowerTarget {
		return true
	}

	// Contains match (e.g., "torch.load" matches "load")
	return strings.Contains(lowerCPG, lowerTarget) ||
		strings.Contains(lowerTarget, lowerCPG)
}

func (p *Propagator) findSanitizerForCall(vertex *reachability.Vertex) *Sanitizer {
	if vertex.Type != "CALL" {
		return nil
	}

	name, ok := vertex.Properties["NAME"].(string)
	if !ok {
		name, _ = vertex.Properties["METHOD_FULL_NAME"].(string)
	}
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
