package taint

import (
	"testing"

	"github.com/penanamtomat/supplychain-kit/internal/reachability"
)

func TestNewDetector(t *testing.T) {
	cpg := &reachability.CPG{}
	det := NewDetector(cpg)

	if det == nil {
		t.Fatal("NewDetector returned nil")
	}
	if det.cpg != cpg {
		t.Error("Detector CPG not set correctly")
	}
}

func TestDetector_Detect_NilCPG(t *testing.T) {
	det := NewDetector(nil)
	sources := det.Detect()

	if len(sources) != 0 {
		t.Errorf("Expected 0 sources with nil CPG, got %d", len(sources))
	}
}

func TestDetector_Detect_EmptyCPG(t *testing.T) {
	cpg := &reachability.CPG{
		Vertices: []*reachability.Vertex{},
		Edges:    []*reachability.Edge{},
	}
	det := NewDetector(cpg)
	sources := det.Detect()

	if len(sources) != 0 {
		t.Errorf("Expected 0 sources with empty CPG, got %d", len(sources))
	}
}

func TestDetector_Detect_HTTPHandlers_Gin(t *testing.T) {
	cpg := &reachability.CPG{
		Vertices: []*reachability.Vertex{
			{
				ID:         "v1",
				Type:       "METHOD",
				Properties: map[string]any{"FULL_NAME": "myapp.handler.UserHandler", "FILE_NAME": "handler.go", "LINE_NUMBER": 42.0},
			},
		},
	}
	det := NewDetector(cpg)
	sources := det.Detect()

	if len(sources) != 1 {
		t.Fatalf("Expected 1 source, got %d", len(sources))
	}

	src := sources[0]
	if src.Type != SourceHTTPParam {
		t.Errorf("Expected type %s, got %s", SourceHTTPParam, src.Type)
	}
	if src.Priority != 10 {
		t.Errorf("Expected priority 10 for generic handler, got %d", src.Priority)
	}
	if src.File != "handler.go" {
		t.Errorf("Expected file handler.go, got %s", src.File)
	}
	if src.Line != 42 {
		t.Errorf("Expected line 42, got %d", src.Line)
	}
}

func TestDetector_Detect_HTTPHandlers_Echo(t *testing.T) {
	cpg := &reachability.CPG{
		Vertices: []*reachability.Vertex{
			{
				ID:         "v1",
				Type:       "METHOD",
				Properties: map[string]any{"METHOD_FULL_NAME": "echo.ContextHandler", "FILE_NAME": "controller.go"},
			},
		},
	}
	det := NewDetector(cpg)
	sources := det.Detect()

	if len(sources) != 1 {
		t.Fatalf("Expected 1 source, got %d", len(sources))
	}

	if sources[0].Priority != 20 {
		t.Errorf("Expected priority 20 for echo handler, got %d", sources[0].Priority)
	}
}

func TestDetector_Detect_HTTPHandlers_NetHTTP(t *testing.T) {
	cpg := &reachability.CPG{
		Vertices: []*reachability.Vertex{
			{
				ID:         "v1",
				Type:       "METHOD",
				Properties: map[string]any{"FULL_NAME": "net/http.HandlerFunc.ServeHTTP", "FILE_NAME": "server.go"},
			},
		},
	}
	det := NewDetector(cpg)
	sources := det.Detect()

	if len(sources) != 1 {
		t.Fatalf("Expected 1 source, got %d", len(sources))
	}

	if sources[0].Priority != 15 {
		t.Errorf("Expected priority 15 for net/http handler, got %d", sources[0].Priority)
	}
}

func TestDetector_Detect_HTTPHandlers_Controller(t *testing.T) {
	cpg := &reachability.CPG{
		Vertices: []*reachability.Vertex{
			{
				ID:         "v1",
				Type:       "METHOD",
				Properties: map[string]any{"FULL_NAME": "myapp.controller.UserController.GetUser", "FILE_NAME": "user.go"},
			},
		},
	}
	det := NewDetector(cpg)
	sources := det.Detect()

	if len(sources) != 1 {
		t.Fatalf("Expected 1 source, got %d", len(sources))
	}

	if sources[0].Type != SourceHTTPParam {
		t.Errorf("Expected HTTP param source for controller, got %s", sources[0].Type)
	}
}

func TestDetector_Detect_EnvReads(t *testing.T) {
	cpg := &reachability.CPG{
		Vertices: []*reachability.Vertex{
			{
				ID:         "v1",
				Type:       "CALL",
				Properties: map[string]any{"NAME": "os.Getenv", "FILE_NAME": "config.go", "LINE_NUMBER": 15.0},
			},
		},
	}
	det := NewDetector(cpg)
	sources := det.Detect()

	if len(sources) != 1 {
		t.Fatalf("Expected 1 source, got %d", len(sources))
	}

	src := sources[0]
	if src.Type != SourceEnvVar {
		t.Errorf("Expected type %s, got %s", SourceEnvVar, src.Type)
	}
	if src.Priority != 8 {
		t.Errorf("Expected priority 8 for env read, got %d", src.Priority)
	}
}

func TestDetector_Detect_EnvReads_Python(t *testing.T) {
	cpg := &reachability.CPG{
		Vertices: []*reachability.Vertex{
			{
				ID:         "v1",
				Type:       "CALL",
				Properties: map[string]any{"NAME": "os.environ.get", "FILE_NAME": "settings.py"},
			},
		},
	}
	det := NewDetector(cpg)
	sources := det.Detect()

	if len(sources) != 1 {
		t.Fatalf("Expected 1 source, got %d", len(sources))
	}

	if sources[0].Type != SourceEnvVar {
		t.Errorf("Expected env var source for Python, got %s", sources[0].Type)
	}
}

func TestDetector_Detect_FileReads(t *testing.T) {
	cpg := &reachability.CPG{
		Vertices: []*reachability.Vertex{
			{
				ID:         "v1",
				Type:       "CALL",
				Properties: map[string]any{"NAME": "os.ReadFile", "FILE_NAME": "io.go", "LINE_NUMBER": 23.0},
			},
		},
	}
	det := NewDetector(cpg)
	sources := det.Detect()

	if len(sources) != 1 {
		t.Fatalf("Expected 1 source, got %d", len(sources))
	}

	src := sources[0]
	if src.Type != SourceFileRead {
		t.Errorf("Expected type %s, got %s", SourceFileRead, src.Type)
	}
	if src.Priority != 6 {
		t.Errorf("Expected priority 6 for file read, got %d", src.Priority)
	}
}

func TestDetector_Detect_CLIArgs(t *testing.T) {
	cpg := &reachability.CPG{
		Vertices: []*reachability.Vertex{
			{
				ID:         "v1",
				Type:       "CALL",
				Properties: map[string]any{"NAME": "flag.Parse", "FILE_NAME": "main.go", "LINE_NUMBER": 10.0},
			},
		},
	}
	det := NewDetector(cpg)
	sources := det.Detect()

	if len(sources) != 1 {
		t.Fatalf("Expected 1 source, got %d", len(sources))
	}

	src := sources[0]
	if src.Type != SourceCLIArg {
		t.Errorf("Expected type %s, got %s", SourceCLIArg, src.Type)
	}
	if src.Priority != 5 {
		t.Errorf("Expected priority 5 for CLI arg, got %d", src.Priority)
	}
}

func TestDetector_Detect_MultipleSources(t *testing.T) {
	cpg := &reachability.CPG{
		Vertices: []*reachability.Vertex{
			{
				ID:         "v1",
				Type:       "METHOD",
				Properties: map[string]any{"FULL_NAME": "gin.HandlerFunc", "FILE_NAME": "handler.go"},
			},
			{
				ID:         "v2",
				Type:       "CALL",
				Properties: map[string]any{"NAME": "os.Getenv", "FILE_NAME": "config.go"},
			},
			{
				ID:         "v3",
				Type:       "CALL",
				Properties: map[string]any{"NAME": "os.ReadFile", "FILE_NAME": "io.go"},
			},
		},
	}
	det := NewDetector(cpg)
	sources := det.Detect()

	if len(sources) != 3 {
		t.Fatalf("Expected 3 sources, got %d", len(sources))
	}

	types := make(map[SourceType]bool)
	for _, src := range sources {
		types[src.Type] = true
	}

	if !types[SourceHTTPParam] {
		t.Error("Missing HTTP param source")
	}
	if !types[SourceEnvVar] {
		t.Error("Missing env var source")
	}
	if !types[SourceFileRead] {
		t.Error("Missing file read source")
	}
}

func TestDetector_extractParams(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"simple function", "func(a, b)", "a, b"},
		{"nested", "myapp.handler(_request, *response)", "_request, *response"},
		{"no params", "func()", "request"},
		{"malformed", "invalid", "request"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			det := NewDetector(nil)
			result := det.extractParams(tt.input)
			if result != tt.expected {
				t.Errorf("extractParams(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestDetector_extractTarget(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"assignment", "x = os.Getenv()", "os.Getenv()"},
		{"no assignment", "os.Getenv()", "os.Getenv()"},
		{"complex", "cfg.DatabaseURL = os.Getenv()", "os.Getenv()"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			det := NewDetector(nil)
			result := det.extractTarget(tt.input)
			if result != tt.expected {
				t.Errorf("extractTarget(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}
