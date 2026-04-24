package taint

import (
	"testing"

	"github.com/penanamtomat/supplychain-kit/internal/reachability"
)

func TestNewPropagator(t *testing.T) {
	cpg := &reachability.CPG{}
	sources := []Source{{Type: SourceHTTPParam, Name: "test"}}
	prop := NewPropagator(cpg, sources)

	if prop == nil {
		t.Fatal("NewPropagator returned nil")
	}
	if prop.cpg != cpg {
		t.Error("Propagator CPG not set correctly")
	}
	if len(prop.sources) != 1 {
		t.Errorf("Expected 1 source, got %d", len(prop.sources))
	}
}

func TestPropagator_Trace_NilCPG(t *testing.T) {
	prop := NewPropagator(nil, []Source{})
	result := prop.Trace("vulnerable_func")

	if result.Exploitable {
		t.Error("Expected not exploitable with nil CPG")
	}
	if result.Confidence != 0.0 {
		t.Errorf("Expected 0.0 confidence, got %f", result.Confidence)
	}
}

func TestPropagator_Trace_NoSources(t *testing.T) {
	cpg := &reachability.CPG{Vertices: []*reachability.Vertex{}}
	prop := NewPropagator(cpg, []Source{})
	result := prop.Trace("vulnerable_func")

	if result.Exploitable {
		t.Error("Expected not exploitable with no sources")
	}
}

func TestPropagator_Trace_DirectMatch(t *testing.T) {
	cpg := &reachability.CPG{
		Vertices: []*reachability.Vertex{
			{
				ID:         "v1",
				Type:       "CALL",
				Properties: map[string]any{"METHOD_FULL_NAME": "user_input_to_vulnerable_func"},
			},
		},
	}
	sources := []Source{{Type: SourceHTTPParam, Name: "user_input", Symbol: "user_input"}}
	prop := NewPropagator(cpg, sources)
	result := prop.Trace("vulnerable_func")

	if !result.Exploitable {
		t.Error("Expected exploitable with direct match")
	}
	if result.Confidence != 1.0 {
		t.Errorf("Expected 1.0 confidence for direct match, got %f", result.Confidence)
	}
}

func TestPropagator_Trace_ContainsMatch(t *testing.T) {
	cpg := &reachability.CPG{
		Vertices: []*reachability.Vertex{
			{
				ID:         "v1",
				Type:       "CALL",
				Properties: map[string]any{"METHOD_FULL_NAME": "request_param_torch_load"},
			},
		},
	}
	sources := []Source{{Type: SourceHTTPParam, Name: "request.Param", Symbol: "request"}}
	prop := NewPropagator(cpg, sources)
	result := prop.Trace("load")

	if !result.Exploitable {
		t.Error("Expected exploitable with contains match")
	}
}

func TestPropagator_Trace_NoPath(t *testing.T) {
	cpg := &reachability.CPG{
		Vertices: []*reachability.Vertex{
			{
				ID:         "v1",
				Type:       "CALL",
				Properties: map[string]any{"METHOD_FULL_NAME": "safe_function"},
			},
		},
	}
	sources := []Source{{Type: SourceHTTPParam, Name: "user_input", Symbol: "user_input"}}
	prop := NewPropagator(cpg, sources)
	result := prop.Trace("vulnerable_func")

	if result.Exploitable {
		t.Error("Expected not exploitable when no path exists")
	}
	if result.Confidence != 0.0 {
		t.Errorf("Expected 0.0 confidence, got %f", result.Confidence)
	}
}

func TestPropagator_cpgMatchesTarget(t *testing.T) {
	tests := []struct {
		name     string
		cpg      string
		target   string
		expected bool
	}{
		{"exact match", "vulnerable_func", "vulnerable_func", true},
		{"cpg contains target", "torch.load", "load", true},
		{"target contains cpg", "load", "torch.load", true},
		{"case insensitive", "VulnerableFunc", "vulnerablefunc", true},
		{"no match", "safe_func", "vulnerable_func", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cpg := &reachability.CPG{}
			prop := NewPropagator(cpg, []Source{})
			result := prop.cpgMatchesTarget(tt.cpg, tt.target)
			if result != tt.expected {
				t.Errorf("cpgMatchesTarget(%q, %q) = %v, want %v", tt.cpg, tt.target, result, tt.expected)
			}
		})
	}
}

func TestPropagator_isSanitizer(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		expectedType  SanitizerType
		expectedValid bool
	}{
		{"validate", "validateInput", SanitValidate, true},
		{"verify", "verifyToken", SanitValidate, true},
		{"escape", "escapeHTML", SanitEscape, true},
		{"encode", "encodeJSON", SanitEscape, true},
		{"sanitize", "sanitizeSQL", SanitEscape, true},
		{"filter", "filterInput", SanitFilter, true},
		{"allowlist", "allowlistDomains", SanitFilter, true},
		{"type", "typeAssert", SanitTypeCheck, true},
		{"cast", "castInt", SanitTypeCheck, true},
		{"not sanitizer", "processData", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cpg := &reachability.CPG{}
			prop := NewPropagator(cpg, []Source{})
			result := prop.isSanitizer(tt.input)
			if tt.expectedValid {
				if result == nil {
					t.Errorf("isSanitizer(%q) returned nil, expected sanitizer", tt.input)
				} else if result.Type != tt.expectedType {
					t.Errorf("isSanitizer(%q).Type = %v, want %v", tt.input, result.Type, tt.expectedType)
				}
			} else {
				if result != nil {
					t.Errorf("isSanitizer(%q) returned %v, expected nil", tt.input, result)
				}
			}
		})
	}
}

func TestPropagator_SanitizerReducesConfidence(t *testing.T) {
	cpg := &reachability.CPG{
		Vertices: []*reachability.Vertex{
			{
				ID:         "v1",
				Type:       "CALL",
				Properties: map[string]any{"METHOD_FULL_NAME": "user_input_to_validate_to_vulnerable"},
			},
			{
				ID:         "v2",
				Type:       "CALL",
				Properties: map[string]any{"NAME": "validateInput"},
			},
		},
	}
	sources := []Source{{Type: SourceHTTPParam, Name: "user_input", Symbol: "user_input"}}
	prop := NewPropagator(cpg, sources)
	result := prop.Trace("vulnerable")

	if !result.Exploitable {
		t.Error("Expected exploitable even with sanitizer")
	}
	if result.Confidence >= 1.0 {
		t.Errorf("Expected confidence < 1.0 with sanitizer, got %f", result.Confidence)
	}
	if !result.SanitizerFound {
		t.Error("Expected SanitizerFound to be true")
	}
}

func TestPropagator_Trace_DepthLimit(t *testing.T) {
	vertices := make([]*reachability.Vertex, 25)
	for i := 0; i < 25; i++ {
		vertices[i] = &reachability.Vertex{
			ID:         string(rune('a' + i)),
			Type:       "CALL",
			Properties: map[string]any{"METHOD_FULL_NAME": string(rune('a' + i))},
		}
	}
	cpg := &reachability.CPG{Vertices: vertices}
	sources := []Source{{Type: SourceHTTPParam, Name: "a", Symbol: "a"}}
	prop := NewPropagator(cpg, sources)
	result := prop.Trace("z")

	if result.Exploitable {
		t.Error("Expected not exploitable due to depth limit")
	}
}

func TestPropagator_Trace_BestSource(t *testing.T) {
	cpg := &reachability.CPG{
		Vertices: []*reachability.Vertex{
			{
				ID:         "v1",
				Type:       "CALL",
				Properties: map[string]any{"METHOD_FULL_NAME": "high_priority_input_to_vulnerable"},
			},
			{
				ID:         "v2",
				Type:       "CALL",
				Properties: map[string]any{"METHOD_FULL_NAME": "low_priority_input"},
			},
		},
	}
	sources := []Source{
		{Type: SourceCLIArg, Name: "low_priority_input", Symbol: "low_priority_input", Priority: 5},
		{Type: SourceHTTPParam, Name: "high_priority_input", Symbol: "high_priority_input", Priority: 20},
	}
	prop := NewPropagator(cpg, sources)
	result := prop.Trace("vulnerable")

	if !result.Exploitable {
		t.Error("Expected exploitable")
	}
	if result.Confidence != 1.0 {
		t.Errorf("Expected 1.0 confidence, got %f", result.Confidence)
	}
}
