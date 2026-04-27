package reachability

import (
	"testing"

	"github.com/penanamtomat/supplychain-kit/internal/models"
)

func TestEngine_Analyze(t *testing.T) {
	engine := New()

	findings := []*models.Finding{
		{
			ID:           "1",
			AssetID:      "test-asset",
			ScanRunID:    "scan-1",
			Sources:      []models.FindingSource{models.SourceGrype},
			RuleID:       "CVE-2021-44228",
			Title:        "Test vulnerability",
			Severity:     models.SeverityCritical,
			Package:      "log4j",
			Version:       "2.14.1",
			FixedVersion:  "2.17.1",
			Reachability: models.ReachUnknown,
		},
		{
			ID:           "2",
			AssetID:      "test-asset",
			ScanRunID:    "scan-1",
			Sources:      []models.FindingSource{models.SourceSemgrep},
			RuleID:       "python.sql-injection",
			Title:        "SQL injection",
			Severity:     models.SeverityHigh,
			FilePath:      "app.py",
			Line:          42,
			Reachability: models.ReachUnknown,
		},
	}

	err := engine.Analyze(nil, "test-asset", "", findings)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}

	if findings[0].Reachability != models.ReachUnknown {
		t.Errorf("SCA finding without CPG should be ReachUnknown, got %v", findings[0].Reachability)
	}

	if findings[1].Reachability != models.ReachReachable {
		t.Errorf("SAST finding should be Reachable, got %v", findings[1].Reachability)
	}

	if findings[1].Confidence != 1.0 {
		t.Errorf("SAST finding confidence should be 1.0, got %v", findings[1].Confidence)
	}
}

func TestEngine_analyzeWithCPG(t *testing.T) {
	cpg := &CPG{
		Vertices: []*Vertex{
			{ID: "1", Type: "FILE", Properties: map[string]any{"NAME": "main.go", "IMPORTS": []any{"github.com/pkg/vulnerable"}}},
			{ID: "2", Type: "METHOD", Properties: map[string]any{"FULL_NAME": "main.main"}},
			{ID: "3", Type: "METHOD", Properties: map[string]any{"METHOD_FULL_NAME": "pkg.vulnerableFunc"}},
		},
		Edges: []*Edge{
			{From: "2", To: "3", Label: "CALLS"},
		},
		methodsByFullname: map[string]*Vertex{
			"main.main":        {ID: "2", Type: "METHOD", Properties: map[string]any{"FULL_NAME": "main.main"}},
			"pkg.vulnerableFunc": {ID: "3", Type: "METHOD", Properties: map[string]any{"METHOD_FULL_NAME": "pkg.vulnerableFunc"}},
		},
		callsBySource: map[string][]*Edge{
			"2": {{From: "2", To: "3", Label: "CALLS"}},
		},
		importsByFile: map[string][]string{
			"main.go": {"github.com/pkg/vulnerable"},
		},
	}

	engine := New()

	findings := []*models.Finding{
		{
			ID:           "1",
			AssetID:      "test-asset",
			ScanRunID:    "scan-1",
			Sources:      []models.FindingSource{models.SourceGrype},
			RuleID:       "CVE-2021-1234",
			Title:        "Test vulnerability",
			Severity:     models.SeverityHigh,
			Package:      "github.com/pkg/vulnerable",
			Reachability: models.ReachUnknown,
		},
	}

	engine.analyzeWithCPG(cpg, findings[0])

	if findings[0].Reachability == models.ReachUnknown {
		t.Error("Finding with package in imports should have reachability set")
	}

	if findings[0].Confidence <= 0 {
		t.Error("Finding should have confidence > 0")
	}
}

func TestCPG_FindPathToSink(t *testing.T) {
	cpg := &CPG{
		Vertices: []*Vertex{
			{ID: "1", Type: "FILE", Properties: map[string]any{"NAME": "main.go", "IMPORTS": []any{"github.com/pkg/target"}}},
			{ID: "2", Type: "METHOD", Properties: map[string]any{"FULL_NAME": "main.handleRequest"}},
			{ID: "3", Type: "METHOD", Properties: map[string]any{"METHOD_FULL_NAME": "target.vulnerableFunc"}},
		},
		Edges: []*Edge{
			{From: "2", To: "3", Label: "CALLS"},
		},
		methodsByFullname: map[string]*Vertex{
			"main.handleRequest":     {ID: "2", Type: "METHOD", Properties: map[string]any{"FULL_NAME": "main.handleRequest"}},
			"target.vulnerableFunc": {ID: "3", Type: "METHOD", Properties: map[string]any{"METHOD_FULL_NAME": "target.vulnerableFunc"}},
		},
		callsBySource: map[string][]*Edge{
			"2": {{From: "2", To: "3", Label: "CALLS"}},
		},
		importsByFile: map[string][]string{
			"main.go": {"github.com/pkg/target"},
		},
	}

	tests := []struct {
		name             string
		vulnerableSymbol string
		pkgName          string
		wantFound        bool
		wantConfidence   float64
	}{
		{
			name:             "package imported - should find",
			vulnerableSymbol: "",
			pkgName:          "github.com/pkg/target",
			wantFound:        true,
			wantConfidence:   0.75,
		},
		{
			name:             "package not imported - should not find",
			vulnerableSymbol: "",
			pkgName:          "github.com/pkg/notimported",
			wantFound:        false,
			wantConfidence:   0.0,
		},
		{
			name:             "both empty - should not find",
			vulnerableSymbol: "",
			pkgName:          "",
			wantFound:        false,
			wantConfidence:   0.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := cpg.FindPathToSink(tt.vulnerableSymbol, tt.pkgName)

			if result.PathFound != tt.wantFound {
				t.Errorf("PathFound = %v, want %v", result.PathFound, tt.wantFound)
			}

			if result.Confidence != tt.wantConfidence {
				t.Errorf("Confidence = %v, want %v", result.Confidence, tt.wantConfidence)
			}
		})
	}
}

func TestCPG_FindEntryPoints(t *testing.T) {
	cpg := &CPG{
		Vertices: []*Vertex{
			{ID: "1", Type: "METHOD", Properties: map[string]any{"FULL_NAME": "main.main"}},
			{ID: "2", Type: "METHOD", Properties: map[string]any{"FULL_NAME": "api.userHandler"}},
			{ID: "3", Type: "METHOD", Properties: map[string]any{"METHOD_FULL_NAME": "server.startHTTP"}},
			{ID: "4", Type: "METHOD", Properties: map[string]any{"METHOD_FULL_NAME": "internal.calc"}},
		},
	}

	entryPoints := cpg.findEntryPoints()

	expectedCount := 3
	if len(entryPoints) != expectedCount {
		t.Errorf("Expected %d entry points, got %d", expectedCount, len(entryPoints))
	}

	expectedNames := map[string]bool{
		"main.main":        true,
		"api.userHandler":  true,
		"server.startHTTP": true,
	}

	for _, ep := range entryPoints {
		name := getFullNameFromVertex(ep)
		if !expectedNames[name] {
			t.Errorf("Unexpected entry point: %s", name)
		}
	}
}

func getFullNameFromVertex(v *Vertex) string {
	if name, ok := v.Properties["FULL_NAME"].(string); ok && name != "" {
		return name
	}
	if name, ok := v.Properties["METHOD_FULL_NAME"].(string); ok && name != "" {
		return name
	}
	return ""
}

func TestIsFirstParty(t *testing.T) {
	tests := []struct {
		name     string
		sources  []models.FindingSource
		expected bool
	}{
		{
			name:     "Semgrep finding",
			sources:  []models.FindingSource{models.SourceSemgrep},
			expected: true,
		},
		{
			name:     "Joern finding",
			sources:  []models.FindingSource{models.SourceJoern},
			expected: true,
		},
		{
			name:     "Gitleaks finding",
			sources:  []models.FindingSource{models.SourceGitleaks},
			expected: true,
		},
		{
			name:     "Grype finding",
			sources:  []models.FindingSource{models.SourceGrype},
			expected: false,
		},
		{
			name:     "Syft finding",
			sources:  []models.FindingSource{models.SourceSyft},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isFirstParty(&models.Finding{Sources: tt.sources})

			if result != tt.expected {
				t.Errorf("isFirstParty() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestCapConfidence(t *testing.T) {
	tests := []struct {
		val, max, want float64
	}{
		{0.5, 0.95, 0.5},
		{1.0, 0.95, 0.95},
		{0.9, 0.95, 0.9},
		{0.0, 0.95, 0.0},
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			result := capConfidence(tt.val, tt.max)
			if result != tt.want {
				t.Errorf("capConfidence(%v, %v) = %v, want %v", tt.val, tt.max, result, tt.want)
			}
		})
	}
}

func TestCapConfidence_IncreasesWithMoreImports(t *testing.T) {
	// Regression test: previously minConfidence was used, which always returned
	// the lower bound (0.7), making confidence constant regardless of import count.
	conf1 := capConfidence(0.7+float64(1)*0.05, 0.95) // 1 import
	conf3 := capConfidence(0.7+float64(3)*0.05, 0.95) // 3 imports
	conf20 := capConfidence(0.7+float64(20)*0.05, 0.95) // many imports — should cap

	if conf1 <= 0.7 {
		t.Errorf("1 import: confidence should be > 0.7, got %v", conf1)
	}
	if conf3 <= conf1 {
		t.Errorf("3 imports should have higher confidence than 1, got %v <= %v", conf3, conf1)
	}
	if conf20 != 0.95 {
		t.Errorf("many imports should cap at 0.95, got %v", conf20)
	}
}

func TestExtractVulnerableSymbol(t *testing.T) {
	tests := []struct {
		name string
		pkg  string
		want string
	}{
		{name: "simple package", pkg: "log4j", want: "log4j"},
		{name: "golang module path", pkg: "github.com/pkg/vulnerable", want: "vulnerable"},
		{name: "deep module path", pkg: "go.uber.org/zap/zapcore", want: "zapcore"},
		{name: "empty package", pkg: "", want: ""},
		{name: "single segment", pkg: "lodash", want: "lodash"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &models.Finding{Package: tt.pkg}
			got := extractVulnerableSymbol(f)
			if got != tt.want {
				t.Errorf("extractVulnerableSymbol() = %q, want %q", got, tt.want)
			}
		})
	}
}
