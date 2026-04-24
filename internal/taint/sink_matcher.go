// Package taint implements dependency-aware SAST by tracing user-controlled input
// through codebase to determine which CVEs are truly exploitable.
// This bridges SCA (Grype/Trivy) and SAST (Semgrep/Joern) findings.
package taint

import (
	"strings"

	"github.com/penanamtomat/supplychain-kit/internal/models"
	"github.com/penanamtomat/supplychain-kit/internal/reachability"
)

// Sink represents a vulnerable function call (CVE-affected).
type Sink struct {
	Package    string
	Symbol     string // Vulnerable function/method
	CVE        string
	Severity   models.Severity
	File       string
	Line       int
}

// Matcher matches tainted data with vulnerable sink symbols.
type Matcher struct {
	cpg    *reachability.CPG
	prop   *Propagator
	sinks  []Sink
}

// NewMatcher creates a new sink matcher.
func NewMatcher(cpg *reachability.CPG, sources []Source) *Matcher {
	return &Matcher{
		cpg:   cpg,
		prop:  NewPropagator(cpg, sources),
		sinks: []Sink{},
	}
}

// LoadSinksFromFindings extracts sink symbols from SCA findings.
func (m *Matcher) LoadSinksFromFindings(findings []*models.Finding) {
	for _, f := range findings {
		if f.Package == "" {
			continue
		}

		// Extract vulnerable symbol from finding
		symbol := extractSymbolFromFinding(f)

		m.sinks = append(m.sinks, Sink{
			Package:  f.Package,
			Symbol:   symbol,
			CVE:      f.RuleID,
			Severity: f.Severity,
		})
	}
}

// extractSymbolFromFinding extracts vulnerable function symbol from SCA finding.
func extractSymbolFromFinding(f *models.Finding) string {
	// Try to extract from description or rule_id
	if f.Description != "" {
		// Look for function name patterns in description
		// e.g., "torch.load()", "requests.get()"
		parts := strings.Fields(f.Description)
		for _, part := range parts {
			if strings.Contains(part, "(") && strings.Contains(part, ")") {
				// Extract function name
				funcName := strings.TrimSuffix(part, "()")
				funcName = strings.TrimSuffix(funcName, "(")
				return funcName
			}
		}
	}

	// Fallback: use package name
	parts := strings.Split(f.Package, "/")
	return parts[len(parts)-1]
}

// Match checks if any sink is reachable from tainted sources.
func (m *Matcher) Match() []MatchResult {
	var results []MatchResult

	for _, sink := range m.sinks {
		result := m.matchSink(sink)
		if result.Exploitable {
			results = append(results, result)
		}
	}

	return results
}

// MatchResult represents a confirmed exploitable CVE.
type MatchResult struct {
	CVE         string
	Package     string
	Sink        string
	Confidence  float64
	TaintPath   []string
	Source      string
	Sanitized   bool
	Exploitable bool
}

func (m *Matcher) matchSink(sink Sink) MatchResult {
	taintResult := m.prop.Trace(sink.Symbol)

	return MatchResult{
		CVE:         sink.CVE,
		Package:     sink.Package,
		Sink:        sink.Symbol,
		Confidence:  taintResult.Confidence,
		TaintPath:   taintResult.Path,
		Source:      m.getSourceName(taintResult),
		Sanitized:   taintResult.SanitizerFound,
		Exploitable: taintResult.Exploitable,
	}
}

func (m *Matcher) getSourceName(taint TaintResult) string {
	if len(taint.Path) > 0 {
		return taint.Path[0]
	}
	return "unknown"
}

// FindSinksInCPG discovers potential sink functions directly from CPG.
func (m *Matcher) FindSinksInCPG(packageName string) []Sink {
	if m.cpg == nil {
		return []Sink{}
	}

	var sinks []Sink
	lowerPkg := strings.ToLower(packageName)

	// Find calls to functions in the vulnerable package
	for _, v := range m.cpg.Vertices {
		if v.Type != "CALL" {
			continue
		}

		name, ok := v.Properties["METHOD_FULL_NAME"].(string)
		if !ok {
			name, _ = v.Properties["FULL_NAME"].(string)
		}
		if name == "" {
			continue
		}

		// Check if call is to the vulnerable package
		if strings.Contains(strings.ToLower(name), lowerPkg) {
			sinks = append(sinks, Sink{
				Package: packageName,
				Symbol:  name,
				File:    extractFileFromVertex(v),
				Line:    extractLineFromVertex(v),
			})
		}
	}

	return sinks
}

// AnalyzeFinding performs full taint analysis on a single finding.
func (m *Matcher) AnalyzeFinding(finding *models.Finding) MatchResult {
	if finding.Package == "" {
		return MatchResult{Exploitable: false}
	}

	// First, try to find sink in CPG
	sinks := m.FindSinksInCPG(finding.Package)
	if len(sinks) == 0 {
		// Fallback: use finding metadata
		symbol := extractSymbolFromFinding(finding)
		sinks = []Sink{{
			Package: finding.Package,
			Symbol:  symbol,
			CVE:     finding.RuleID,
			Severity: finding.Severity,
		}}
	}

	// Match each potential sink
	var bestResult MatchResult
	for _, sink := range sinks {
		result := m.matchSink(sink)
		if result.Exploitable && result.Confidence > bestResult.Confidence {
			bestResult = result
		}
	}

	return bestResult
}

// UpdateFindingWithTaintResult modifies finding with taint analysis results.
func UpdateFindingWithTaintResult(finding *models.Finding, result MatchResult) {
	if result.Exploitable {
		finding.Reachability = models.ReachConfirmedExploit
		finding.Confidence = result.Confidence

		// Build taint path description
		if len(result.TaintPath) > 0 {
			finding.Path = result.TaintPath
		}

		// Add metadata about exploitability
		if finding.Raw == nil {
			finding.Raw = make(map[string]any)
		}
		finding.Raw["taint_source"] = result.Source
		finding.Raw["taint_sanitized"] = result.Sanitized
		finding.Raw["taint_path"] = result.TaintPath
	}
}

func extractFileFromVertex(v *reachability.Vertex) string {
	if file, ok := v.Properties["FILE_NAME"].(string); ok {
		return file
	}
	return ""
}

func extractLineFromVertex(v *reachability.Vertex) int {
	if line, ok := v.Properties["LINE_NUMBER"].(float64); ok {
		return int(line)
	}
	if line, ok := v.Properties["LINE_NUMBER"].(int); ok {
		return line
	}
	return 0
}

// Engine orchestrates the full taint analysis pipeline.
type Engine struct {
	cpg    *reachability.CPG
	det    *Detector
	prop   *Propagator
	match  *Matcher
}

// NewEngine creates a new taint analysis engine.
func NewEngine(cpg *reachability.CPG) *Engine {
	if cpg == nil {
		return &Engine{cpg: cpg}
	}

	det := NewDetector(cpg)
	sources := det.Detect()

	return &Engine{
		cpg:   cpg,
		det:   det,
		prop:  NewPropagator(cpg, sources),
		match: NewMatcher(cpg, sources),
	}
}

// Analyze runs taint analysis on all findings.
func (e *Engine) Analyze(findings []*models.Finding) {
	if e.cpg == nil {
		return
	}

	e.match.LoadSinksFromFindings(findings)

	for _, f := range findings {
		// Skip first-party findings (already reachable)
		if isFirstParty(f) {
			continue
		}

		result := e.match.AnalyzeFinding(f)
		UpdateFindingWithTaintResult(f, result)
	}
}

func isFirstParty(f *models.Finding) bool {
	for _, s := range f.Sources {
		if s == models.SourceSemgrep || s == models.SourceJoern || s == models.SourceGitleaks {
			return true
		}
	}
	return false
}
