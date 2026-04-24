package taint

import (
	"testing"

	"github.com/penanamtomat/supplychain-kit/internal/models"
	"github.com/penanamtomat/supplychain-kit/internal/reachability"
)

func TestNewMatcher(t *testing.T) {
	cpg := &reachability.CPG{}
	sources := []Source{{Type: SourceHTTPParam, Name: "test"}}
	match := NewMatcher(cpg, sources)

	if match == nil {
		t.Fatal("NewMatcher returned nil")
	}
	if match.cpg != cpg {
		t.Error("Matcher CPG not set correctly")
	}
	if len(match.sinks) != 0 {
		t.Errorf("Expected 0 sinks initially, got %d", len(match.sinks))
	}
}

func TestMatcher_LoadSinksFromFindings(t *testing.T) {
	cpg := &reachability.CPG{}
	sources := []Source{}
	match := NewMatcher(cpg, sources)

	findings := []*models.Finding{
		{
			RuleID:    "CVE-2021-44228",
			Package:   "github.com/log4j/log4j-core",
			Severity:  models.SeverityCritical,
			Title:     "Log4Shell RCE",
		},
		{
			RuleID:    "CVE-2022-22965",
			Package:   "org.springframework:spring-core",
			Severity:  models.SeverityHigh,
			Title:     "Spring4Shell",
		},
	}

	match.LoadSinksFromFindings(findings)

	if len(match.sinks) != 2 {
		t.Fatalf("Expected 2 sinks, got %d", len(match.sinks))
	}

	if match.sinks[0].CVE != "CVE-2021-44228" {
		t.Errorf("Expected CVE CVE-2021-44228, got %s", match.sinks[0].CVE)
	}
	if match.sinks[1].Package != "org.springframework:spring-core" {
		t.Errorf("Expected package org.springframework:spring-core, got %s", match.sinks[1].Package)
	}
}

func TestMatcher_LoadSinksFromFindings_SkipsEmptyPackage(t *testing.T) {
	cpg := &reachability.CPG{}
	sources := []Source{}
	match := NewMatcher(cpg, sources)

	findings := []*models.Finding{
		{RuleID: "CVE-2021-44228", Package: ""},
		{RuleID: "CVE-2022-22965", Package: "valid/package"},
	}

	match.LoadSinksFromFindings(findings)

	if len(match.sinks) != 1 {
		t.Fatalf("Expected 1 sink (empty package skipped), got %d", len(match.sinks))
	}
}

func TestExtractSymbolFromFinding_Description(t *testing.T) {
	findings := []*models.Finding{
		{
			RuleID:      "CVE-2021-44228",
			Package:     "torch",
			Description: "The torch.load() function is vulnerable",
		},
	}

	cpg := &reachability.CPG{}
	match := NewMatcher(cpg, []Source{})
	match.LoadSinksFromFindings(findings)

	if len(match.sinks) != 1 {
		t.Fatalf("Expected 1 sink, got %d", len(match.sinks))
	}

	if match.sinks[0].Symbol != "torch.load" {
		t.Errorf("Expected symbol 'torch.load', got %s", match.sinks[0].Symbol)
	}
}

func TestExtractSymbolFromFinding_Fallback(t *testing.T) {
	findings := []*models.Finding{
		{
			RuleID:  "CVE-2021-44228",
			Package: "github.com/vulnerable/package",
			Title:   "Vulnerable package",
		},
	}

	cpg := &reachability.CPG{}
	match := NewMatcher(cpg, []Source{})
	match.LoadSinksFromFindings(findings)

	if match.sinks[0].Symbol != "package" {
		t.Errorf("Expected symbol 'package' (last segment), got %s", match.sinks[0].Symbol)
	}
}

func TestMatcher_FindSinksInCPG(t *testing.T) {
	cpg := &reachability.CPG{
		Vertices: []*reachability.Vertex{
			{
				ID:         "v1",
				Type:       "CALL",
				Properties: map[string]any{
					"METHOD_FULL_NAME": "torch.load",
					"FILE_NAME":        "model.py",
					"LINE_NUMBER":      42.0,
				},
			},
			{
				ID:         "v2",
				Type:       "CALL",
				Properties: map[string]any{
					"METHOD_FULL_NAME": "torch.nn.Linear",
					"FILE_NAME":        "network.py",
				},
			},
		},
	}
	sources := []Source{}
	match := NewMatcher(cpg, sources)

	sinks := match.FindSinksInCPG("torch")

	if len(sinks) != 2 {
		t.Fatalf("Expected 2 sinks in torch package, got %d", len(sinks))
	}

	if sinks[0].Symbol != "torch.load" {
		t.Errorf("Expected symbol 'torch.load', got %s", sinks[0].Symbol)
	}
	if sinks[0].File != "model.py" {
		t.Errorf("Expected file 'model.py', got %s", sinks[0].File)
	}
	if sinks[0].Line != 42 {
		t.Errorf("Expected line 42, got %d", sinks[0].Line)
	}
}

func TestMatcher_FindSinksInCPG_NilCPG(t *testing.T) {
	match := NewMatcher(nil, []Source{})
	sinks := match.FindSinksInCPG("torch")

	if len(sinks) != 0 {
		t.Errorf("Expected 0 sinks with nil CPG, got %d", len(sinks))
	}
}

func TestMatcher_FindSinksInCPG_NoMatches(t *testing.T) {
	cpg := &reachability.CPG{
		Vertices: []*reachability.Vertex{
			{
				ID:         "v1",
				Type:       "CALL",
				Properties: map[string]any{"METHOD_FULL_NAME": "numpy.array"},
			},
		},
	}
	sources := []Source{}
	match := NewMatcher(cpg, sources)

	sinks := match.FindSinksInCPG("torch")

	if len(sinks) != 0 {
		t.Errorf("Expected 0 sinks for different package, got %d", len(sinks))
	}
}

func TestMatcher_Match(t *testing.T) {
	cpg := &reachability.CPG{
		Vertices: []*reachability.Vertex{
			{
				ID:         "v1",
				Type:       "CALL",
				Properties: map[string]any{"METHOD_FULL_NAME": "user_input_calling_load_func"},
			},
			{
				ID:         "v2",
				Type:       "CALL",
				Properties: map[string]any{"METHOD_FULL_NAME": "another_user_input_func"},
			},
		},
	}
	sources := []Source{{Type: SourceHTTPParam, Name: "user_input", Symbol: "user_input"}}
	match := NewMatcher(cpg, sources)

	// Sink symbol "load" should match vertices containing "user_input" which also contain "load"
	match.sinks = []Sink{
		{Package: "torch", Symbol: "load", CVE: "CVE-2023-1234"},
	}

	results := match.Match()

	if len(results) != 1 {
		t.Fatalf("Expected 1 exploitable result, got %d", len(results))
	}

	if results[0].CVE != "CVE-2023-1234" {
		t.Errorf("Expected CVE CVE-2023-1234, got %s", results[0].CVE)
	}
	if !results[0].Exploitable {
		t.Error("Expected exploitable result")
	}
}

func TestMatcher_AnalyzeFinding_WithCPGSink(t *testing.T) {
	cpg := &reachability.CPG{
		Vertices: []*reachability.Vertex{
			{
				ID:         "v1",
				Type:       "CALL",
				Properties: map[string]any{"METHOD_FULL_NAME": "request_calling_load"},
			},
			{
				ID:         "v2",
				Type:       "CALL",
				Properties: map[string]any{
					"METHOD_FULL_NAME": "load",
					"FILE_NAME":        "model.py",
				},
			},
		},
	}
	sources := []Source{{Type: SourceHTTPParam, Name: "request.Param", Symbol: "request"}}
	match := NewMatcher(cpg, sources)

	// Use a finding with description that will extract "load" as the symbol
	finding := &models.Finding{
		RuleID:      "CVE-2023-1234",
		Package:     "torch",
		Severity:    models.SeverityHigh,
		Description: "The load() function is vulnerable",
	}

	result := match.AnalyzeFinding(finding)

	// ExtractSymbolFromFinding will extract "load" from the description
	if !result.Exploitable {
		t.Error("Expected exploitable result")
	}
	if result.CVE != "CVE-2023-1234" {
		t.Errorf("Expected CVE CVE-2023-1234, got %s", result.CVE)
	}
	if result.Package != "torch" {
		t.Errorf("Expected package torch, got %s", result.Package)
	}
}

func TestMatcher_AnalyzeFinding_EmptyPackage(t *testing.T) {
	cpg := &reachability.CPG{}
	sources := []Source{}
	match := NewMatcher(cpg, sources)

	finding := &models.Finding{
		RuleID:  "CVE-2023-1234",
		Package: "",
	}

	result := match.AnalyzeFinding(finding)

	if result.Exploitable {
		t.Error("Expected not exploitable with empty package")
	}
}

func TestUpdateFindingWithTaintResult_Exploitable(t *testing.T) {
	finding := &models.Finding{
		RuleID:      "CVE-2023-1234",
		Package:     "torch",
		Reachability: models.ReachUnknown,
		Confidence:   0.0,
	}

	result := MatchResult{
		Exploitable: true,
		Confidence:  0.95,
		TaintPath:   []string{"request.Param", "torch.load"},
		Source:      "request.Param",
		Sanitized:   false,
		CVE:         "CVE-2023-1234",
	}

	UpdateFindingWithTaintResult(finding, result)

	if finding.Reachability != models.ReachConfirmedExploit {
		t.Errorf("Expected reachability %s, got %s", models.ReachConfirmedExploit, finding.Reachability)
	}
	if finding.Confidence != 0.95 {
		t.Errorf("Expected confidence 0.95, got %f", finding.Confidence)
	}
	if len(finding.Path) != 2 {
		t.Errorf("Expected 2 path entries, got %d", len(finding.Path))
	}
	if finding.Raw == nil {
		t.Error("Expected Raw map to be initialized")
	} else {
		if finding.Raw["taint_source"] != "request.Param" {
			t.Errorf("Expected taint_source 'request.Param', got %v", finding.Raw["taint_source"])
		}
		if finding.Raw["taint_sanitized"] != false {
			t.Errorf("Expected taint_sanitized false, got %v", finding.Raw["taint_sanitized"])
		}
	}
}

func TestUpdateFindingWithTaintResult_NotExploitable(t *testing.T) {
	finding := &models.Finding{
		RuleID:      "CVE-2023-1234",
		Package:     "torch",
		Reachability: models.ReachUnknown,
		Confidence:   0.0,
	}

	result := MatchResult{
		Exploitable: false,
		Confidence:  0.0,
	}

	UpdateFindingWithTaintResult(finding, result)

	if finding.Reachability != models.ReachUnknown {
		t.Errorf("Expected reachability to remain %s, got %s", models.ReachUnknown, finding.Reachability)
	}
	if finding.Confidence != 0.0 {
		t.Errorf("Expected confidence 0.0, got %f", finding.Confidence)
	}
}

func TestExtractFileFromVertex(t *testing.T) {
	v := &reachability.Vertex{
		Properties: map[string]any{"FILE_NAME": "test/file.go"},
	}

	result := extractFileFromVertex(v)
	if result != "test/file.go" {
		t.Errorf("Expected 'test/file.go', got %s", result)
	}
}

func TestExtractFileFromVertex_Missing(t *testing.T) {
	v := &reachability.Vertex{
		Properties: map[string]any{},
	}

	result := extractFileFromVertex(v)
	if result != "" {
		t.Errorf("Expected empty string, got %s", result)
	}
}

func TestExtractLineFromVertex_Float64(t *testing.T) {
	v := &reachability.Vertex{
		Properties: map[string]any{"LINE_NUMBER": 42.0},
	}

	result := extractLineFromVertex(v)
	if result != 42 {
		t.Errorf("Expected 42, got %d", result)
	}
}

func TestExtractLineFromVertex_Int(t *testing.T) {
	v := &reachability.Vertex{
		Properties: map[string]any{"LINE_NUMBER": 42},
	}

	result := extractLineFromVertex(v)
	if result != 42 {
		t.Errorf("Expected 42, got %d", result)
	}
}

func TestNewEngine(t *testing.T) {
	cpg := &reachability.CPG{
		Vertices: []*reachability.Vertex{
			{
				ID:         "v1",
				Type:       "METHOD",
				Properties: map[string]any{"FULL_NAME": "gin.HandlerFunc"},
			},
		},
	}

	engine := NewEngine(cpg)

	if engine == nil {
		t.Fatal("NewEngine returned nil")
	}
	if engine.cpg != cpg {
		t.Error("Engine CPG not set correctly")
	}
	if engine.det == nil {
		t.Error("Engine detector not initialized")
	}
	if engine.prop == nil {
		t.Error("Engine propagator not initialized")
	}
	if engine.match == nil {
		t.Error("Engine matcher not initialized")
	}
}

func TestNewEngine_NilCPG(t *testing.T) {
	engine := NewEngine(nil)

	if engine == nil {
		t.Fatal("NewEngine returned nil")
	}
	if engine.cpg != nil {
		t.Error("Expected nil CPG in engine")
	}
	if engine.det != nil {
		t.Error("Expected nil detector with nil CPG")
	}
}

func TestEngine_Analyze_NilCPG(t *testing.T) {
	engine := NewEngine(nil)
	findings := []*models.Finding{
		{RuleID: "CVE-2023-1234", Package: "torch"},
	}

	engine.Analyze(findings)

	findings[0].Reachability = models.ReachUnknown
}

func TestEngine_Analyze_FirstPartySkipped(t *testing.T) {
	cpg := &reachability.CPG{
		Vertices: []*reachability.Vertex{
			{ID: "v1", Type: "METHOD", Properties: map[string]any{"FULL_NAME": "gin.HandlerFunc"}},
		},
	}
	engine := NewEngine(cpg)
	findings := []*models.Finding{
		{
			RuleID:      "semgrep-rule",
			Package:     "",
			Sources:     []models.FindingSource{models.SourceSemgrep},
			Reachability: models.ReachUnknown,
		},
	}

	engine.Analyze(findings)

	if findings[0].Reachability != models.ReachUnknown {
		t.Errorf("Expected first-party finding to be skipped and remain %s, got %s",
			models.ReachUnknown, findings[0].Reachability)
	}
}

func TestIsFirstParty(t *testing.T) {
	tests := []struct {
		name     string
		finding  *models.Finding
		expected bool
	}{
		{
			name: "semgrep",
			finding: &models.Finding{
				Sources: []models.FindingSource{models.SourceSemgrep},
			},
			expected: true,
		},
		{
			name: "joern",
			finding: &models.Finding{
				Sources: []models.FindingSource{models.SourceJoern},
			},
			expected: true,
		},
		{
			name: "gitleaks",
			finding: &models.Finding{
				Sources: []models.FindingSource{models.SourceGitleaks},
			},
			expected: true,
		},
		{
			name: "grype",
			finding: &models.Finding{
				Sources: []models.FindingSource{models.SourceGrype},
			},
			expected: false,
		},
		{
			name: "trivy",
			finding: &models.Finding{
				Sources: []models.FindingSource{models.SourceTrivy},
			},
			expected: false,
		},
		{
			name:     "no sources",
			finding:  &models.Finding{Sources: []models.FindingSource{}},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isFirstParty(tt.finding)
			if result != tt.expected {
				t.Errorf("isFirstParty() = %v, want %v", result, tt.expected)
			}
		})
	}
}
