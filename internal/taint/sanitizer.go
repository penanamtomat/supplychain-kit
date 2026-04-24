package taint

// Common sanitizers and validators by ecosystem and category.
import (
	"strings"
)
// This helps reduce false positives by identifying when data is properly sanitized.

// SanitizerRegistry contains known sanitizer functions and their efficacy.
type SanitizerRegistry struct {
	sanitizers map[string]*Sanitizer
}

// NewSanitizerRegistry creates a new sanitizer registry with common functions.
func NewSanitizerRegistry() *SanitizerRegistry {
	registry := &SanitizerRegistry{
		sanitizers: make(map[string]*Sanitizer),
	}
	registry.registerCommonSanitizers()
	return registry
}

// registerCommonSanitizers registers well-known sanitizer functions.
func (r *SanitizerRegistry) registerCommonSanitizers() {
	// JavaScript/TypeScript sanitizers
	jsSanitizers := []struct {
		name     string
		sanType  SanitizerType
		efficacy float64
	}{
		// DOMPurify - XSS protection
		{"DOMPurify.sanitize", SanitEscape, 0.95},
		{"sanitize", SanitEscape, 0.90},
		{"sanitizeHtml", SanitEscape, 0.90},

		// Validation libraries
		{"validator.isEmail", SanitValidate, 0.95},
		{"validator.isURL", SanitValidate, 0.95},
		{"validator.isInt", SanitValidate, 0.95},
		{"validator.isFloat", SanitValidate, 0.95},
		{"validator.matches", SanitValidate, 0.90},
		{"zod.string", SanitValidate, 0.95},
		{"yup.string", SanitValidate, 0.95},
		{"joi.string", SanitValidate, 0.95},

		// Encoding functions
		{"encodeURIComponent", SanitEscape, 0.95},
		{"encodeURI", SanitEscape, 0.95},
		{"escape", SanitEscape, 0.85},
		{"_.escape", SanitEscape, 0.85},
		{"he.encode", SanitEscape, 0.95},

		// Filtering
		{"_.filter", SanitFilter, 0.70},
		{"Array.filter", SanitFilter, 0.70},
		{"allowlist", SanitFilter, 0.80},
		{"whitelist", SanitFilter, 0.80},

		// Type checking
		{"typeof", SanitTypeCheck, 0.60},
		{"instanceof", SanitTypeCheck, 0.70},
		{"Number", SanitTypeCheck, 0.75},
		{"String", SanitTypeCheck, 0.75},
		{"parseInt", SanitTypeCheck, 0.80},
		{"parseFloat", SanitTypeCheck, 0.80},

		// Framework-specific sanitizers
		{"React.createElement", SanitEscape, 0.90},
		{"h", SanitEscape, 0.90}, // Preact, Vue h() function
		{"htm", SanitEscape, 0.85},
	}

	for _, s := range jsSanitizers {
		r.sanitizers[s.name] = &Sanitizer{
			Type:     s.sanType,
			Name:     s.name,
			Efficacy: s.efficacy,
		}
	}

	// Python sanitizers
	pythonSanitizers := []struct {
		name     string
		sanType  SanitizerType
		efficacy float64
	}{
		{"bleach.clean", SanitEscape, 0.95},
		{"bleach.linkify", SanitEscape, 0.90},
		{"html.escape", SanitEscape, 0.90},
		{"cgi.escape", SanitEscape, 0.85},

		{"validators.validate_email", SanitValidate, 0.95},
		{"validators.validate_url", SanitValidate, 0.95},
		{"email_validator.validate_email", SanitValidate, 0.95},

		{"urllib.parse.quote", SanitEscape, 0.95},
		{"urllib.parse.quote_plus", SanitEscape, 0.95},
		{"urllib.parse.unquote", SanitEscape, 0.90},

		{"str.strip", SanitFilter, 0.60},
		{"str.lstrip", SanitFilter, 0.60},
		{"str.rstrip", SanitFilter, 0.60},

		{"isinstance", SanitTypeCheck, 0.70},
		{"type", SanitTypeCheck, 0.60},
		{"int", SanitTypeCheck, 0.75},
		{"float", SanitTypeCheck, 0.75},
	}

	for _, s := range pythonSanitizers {
		r.sanitizers[s.name] = &Sanitizer{
			Type:     s.sanType,
			Name:     s.name,
			Efficacy: s.efficacy,
		}
	}

	// Go sanitizers
	goSanitizers := []struct {
		name     string
		sanType  SanitizerType
		efficacy float64
	}{
		{"html.EscapeString", SanitEscape, 0.95},
		{"template.HTMLEscapeString", SanitEscape, 0.95},
		{"template.JSEscapeString", SanitEscape, 0.95},

		{"url.QueryEscape", SanitEscape, 0.95},
		{"url.PathEscape", SanitEscape, 0.95},
		{"url.QueryUnescape", SanitEscape, 0.90},

		{"strconv.Atoi", SanitTypeCheck, 0.80},
		{"strconv.ParseFloat", SanitTypeCheck, 0.80},
		{"strconv.ParseInt", SanitTypeCheck, 0.80},
		{"strconv.ParseUint", SanitTypeCheck, 0.80},

		{"regexp.QuoteMeta", SanitEscape, 0.90},
		{"strings.ReplaceAll", SanitFilter, 0.70},
		{"strings.Map", SanitFilter, 0.70},

		{"validator.IsEmail", SanitValidate, 0.95},
		{"validator.IsURL", SanitValidate, 0.95},
	}

	for _, s := range goSanitizers {
		r.sanitizers[s.name] = &Sanitizer{
			Type:     s.sanType,
			Name:     s.name,
			Efficacy: s.efficacy,
		}
	}
}

// Lookup finds a sanitizer by name.
func (r *SanitizerRegistry) Lookup(name string) *Sanitizer {
	// Exact match
	if san, ok := r.sanitizers[name]; ok {
		return san
	}

	// Partial match for method calls (e.g., "obj.method" matches "method")
	lowerName := strings.ToLower(name)
	for sanName, san := range r.sanitizers {
		if strings.Contains(lowerName, strings.ToLower(sanName)) {
			// Reduce efficacy for partial matches
			adjusted := *san
			adjusted.Efficacy *= 0.8
			return &adjusted
		}
	}

	return nil
}

// TaintContext provides context-sensitive analysis to reduce over-approximation.
type TaintContext struct {
	// Type tracking - track data types through the flow
	TypeMap map[string]string // vertexID -> type

	// Constant folding - track constant values
	Constants map[string]interface{} // vertexID -> constant value

	// Array bounds tracking
	ArrayBounds map[string]bool // variable -> has bounds check

	// Control flow guards
	Guards map[string]bool // variable -> has validation guard
}

// NewTaintContext creates a new taint context.
func NewTaintContext() *TaintContext {
	return &TaintContext{
		TypeMap:     make(map[string]string),
		Constants:   make(map[string]interface{}),
		ArrayBounds: make(map[string]bool),
		Guards:      make(map[string]bool),
	}
}

// IsSafeByContext checks if a taint flow is safe based on context.
func (tc *TaintContext) IsSafeByContext(vertexID, symbol string) bool {
	// Check if value is a constant (not user input)
	if val, ok := tc.Constants[vertexID]; ok {
		if isUserConstant(val) {
			return false // Still potentially unsafe
		}
		return true // Safe constant
	}

	// Check if variable has bounds check
	if hasGuard, ok := tc.Guards[symbol]; ok && hasGuard {
		return true // Has validation guard
	}

	// Check if array access is bounds-checked
	if isBounded, ok := tc.ArrayBounds[symbol]; ok && isBounded {
		return true // Array access is safe
	}

	// Check if type is safe (e.g., number vs string for SQLi)
	if typ, ok := tc.TypeMap[vertexID]; ok {
		if isSafeType(typ) {
			return true
		}
	}

	return false
}

// isUserConstant checks if a constant value might be from user input.
func isUserConstant(val interface{}) bool {
	// Strings that look like user input
	if str, ok := val.(string); ok {
		// Very short strings are likely constants
		if len(str) <= 3 {
			return false
		}
		// Strings with special patterns might be user input
		if strings.Contains(str, "<script>") ||
		   strings.Contains(str, "../") ||
		   strings.Contains(str, "SELECT") {
			return true
		}
	}
	return false
}

// isSafeType checks if a type is safe for certain operations.
func isSafeType(typ string) bool {
	safeTypes := []string{
		"int", "int8", "int16", "int32", "int64",
		"uint", "uint8", "uint16", "uint32", "uint64",
		"float32", "float64",
		"bool", "boolean",
	}

	lower := strings.ToLower(typ)
	for _, safe := range safeTypes {
		if strings.Contains(lower, safe) {
			return true
		}
	}

	return false
}

// ConfidenceAdjustment calculates confidence reduction based on context.
func (tc *TaintContext) ConfidenceAdjustment(baseConfidence float64, vertexID, symbol string) float64 {
	adjustment := 1.0

	// Reduce confidence if type is safe
	if typ, ok := tc.TypeMap[vertexID]; ok && isSafeType(typ) {
		adjustment *= 0.3
	}

	// Reduce confidence if constant
	if _, ok := tc.Constants[vertexID]; ok {
		adjustment *= 0.1
	}

	// Reduce confidence if validation guard exists
	if hasGuard, ok := tc.Guards[symbol]; ok && hasGuard {
		adjustment *= 0.2
	}

	// Reduce confidence if array bounds checked
	if isBounded, ok := tc.ArrayBounds[symbol]; ok && isBounded {
		adjustment *= 0.5
	}

	return baseConfidence * adjustment
}

// PathPruner removes unlikely taint paths based on heuristics.
type PathPruner struct {
	maxLength int
	maxBranching int
}

// NewPathPruner creates a new path pruner.
func NewPathPruner() *PathPruner {
	return &PathPruner{
		maxLength:   15, // Max path length to consider
		maxBranching: 5, // Max branching factor
	}
}

// ShouldPrunePath checks if a path should be pruned.
func (pp *PathPruner) ShouldPrunePath(path []string, confidence float64) bool {
	// Path too long - likely over-approximation
	if len(path) > pp.maxLength {
		return true
	}

	// Confidence too low
	if confidence < 0.3 {
		return true
	}

	// Check for suspicious patterns indicating over-approximation
	pathStr := strings.Join(path, " → ")

	// Paths that go through generic "return" statements
	if strings.Contains(pathStr, "RET") && len(path) > 8 {
		return true
	}

	// Paths with repeated nodes (cycles)
	seen := make(map[string]bool)
	for _, node := range path {
		if seen[node] {
			return true // Cycle detected
		}
		seen[node] = true
	}

	return false
}

// GetCriticalPath extracts the most critical path from multiple paths.
func (pp *PathPruner) GetCriticalPath(paths [][]string) []string {
	if len(paths) == 0 {
		return []string{}
	}

	// Return shortest path (most direct)
	critical := paths[0]
	for _, path := range paths {
		if len(path) < len(critical) {
			critical = path
		}
	}

	return critical
}
