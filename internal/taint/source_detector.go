// Package taint implements dependency-aware SAST by tracing user-controlled input
// through the codebase to determine which CVEs are truly exploitable.
// This bridges SCA (Grype/Trivy) and SAST (Semgrep/Joern) findings.
package taint

import (
	"strings"

	"github.com/penanamtomat/supplychain-kit/internal/reachability"
)

// SourceType represents the origin of taint.
type SourceType string

const (
	SourceHTTPParam    SourceType = "http_param"
	SourceEnvVar       SourceType = "env_var"
	SourceFileRead     SourceType = "file_read"
	SourceCLIArg       SourceType = "cli_arg"
	SourceUserInput    SourceType = "user_input"
)

// Source represents a taint source — user-controlled input entry point.
type Source struct {
	Type     SourceType
	Name     string
	File     string
	Line     int
	Symbol   string // Variable name or function parameter
	Priority int    // Higher = more likely to be exploitable
}

// Detector identifies user-controlled input entry points from CPG.
type Detector struct {
	cpg *reachability.CPG
}

// NewDetector creates a new source detector with the provided CPG.
func NewDetector(cpg *reachability.CPG) *Detector {
	return &Detector{cpg: cpg}
}

// Detect finds all taint sources in the CPG.
func (d *Detector) Detect() []Source {
	var sources []Source

	if d.cpg == nil {
		return sources
	}

	// Detect HTTP handler entry points
	sources = append(sources, d.detectHTTPHandlers()...)

	// Detect environment variable reads
	sources = append(sources, d.detectEnvReads()...)

	// Detect file reads with user-controlled paths
	sources = append(sources, d.detectFileReads()...)

	// Detect CLI argument parsing
	sources = append(sources, d.detectCLIArgs()...)

	return sources
}

func (d *Detector) detectHTTPHandlers() []Source {
	var sources []Source

	for _, v := range d.cpg.Vertices {
		name, hasName := v.Properties["FULL_NAME"].(string)
		if !hasName {
			name, _ = v.Properties["METHOD_FULL_NAME"].(string)
		}
		if name == "" {
			continue
		}

		lower := strings.ToLower(name)
		// Common HTTP handler patterns across frameworks
		isHandler :=
			strings.Contains(lower, "handle") ||
			strings.Contains(lower, "servehttp") ||
			strings.Contains(lower, ".handler") ||
			strings.Contains(lower, "controller.") ||
			strings.Contains(lower, "endpoint.") ||
			strings.HasSuffix(lower, ".get") ||
			strings.HasSuffix(lower, ".post") ||
			strings.HasSuffix(lower, ".put") ||
			strings.HasSuffix(lower, ".delete") ||
			strings.HasSuffix(lower, ".patch")

		if isHandler {
			priority := 10
			// Framework-specific patterns
			if strings.Contains(lower, "gin") || strings.Contains(lower, "echo") {
				priority = 20
			}
			if strings.Contains(lower, "net/http") {
				priority = 15
			}

			sources = append(sources, Source{
				Type:     SourceHTTPParam,
				Name:     name,
				File:     d.vertexFile(v),
				Line:     d.vertexLine(v),
				Symbol:   d.extractParams(name),
				Priority: priority,
			})
		}
	}

	return sources
}

func (d *Detector) detectEnvReads() []Source {
	var sources []Source

	for _, v := range d.cpg.Vertices {
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

		lower := strings.ToLower(name)
		isEnvRead :=
			strings.Contains(lower, "os.getenv") ||
			strings.Contains(lower, "os.environ") ||
			strings.Contains(lower, "os.lookupenv") ||
			strings.Contains(lower, "environ.get") ||
			strings.Contains(lower, "getenv") ||
			strings.Contains(lower, "dotenv")

		if isEnvRead {
			sources = append(sources, Source{
				Type:     SourceEnvVar,
				Name:     name,
				File:     d.vertexFile(v),
				Line:     d.vertexLine(v),
				Symbol:   d.extractTarget(name),
				Priority: 8,
			})
		}
	}

	return sources
}

func (d *Detector) detectFileReads() []Source {
	var sources []Source

	for _, v := range d.cpg.Vertices {
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

		lower := strings.ToLower(name)
		isFileRead :=
			strings.Contains(lower, "os.readfile") ||
			strings.Contains(lower, "ioutil.readfile") ||
			strings.Contains(lower, "io.readall") ||
			strings.Contains(lower, "open(") ||
			strings.Contains(lower, "fopen") ||
			strings.Contains(lower, "read(") ||
			strings.Contains(lower, "file.")

		if isFileRead {
			sources = append(sources, Source{
				Type:     SourceFileRead,
				Name:     name,
				File:     d.vertexFile(v),
				Line:     d.vertexLine(v),
				Symbol:   d.extractTarget(name),
				Priority: 6,
			})
		}
	}

	return sources
}

func (d *Detector) detectCLIArgs() []Source {
	var sources []Source

	for _, v := range d.cpg.Vertices {
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

		lower := strings.ToLower(name)
		isCLIParse :=
			strings.Contains(lower, "os.args") ||
			strings.Contains(lower, "flag.parse") ||
			strings.Contains(lower, "argparse") ||
			strings.Contains(lower, "parseargs") ||
			strings.Contains(lower, "getopt") ||
			strings.Contains(lower, ".arg(")

		if isCLIParse {
			sources = append(sources, Source{
				Type:     SourceCLIArg,
				Name:     name,
				File:     d.vertexFile(v),
				Line:     d.vertexLine(v),
				Symbol:   d.extractTarget(name),
				Priority: 5,
			})
		}
	}

	return sources
}

func (d *Detector) vertexFile(v *reachability.Vertex) string {
	if file, ok := v.Properties["FILE_NAME"].(string); ok {
		return file
	}
	return ""
}

func (d *Detector) vertexLine(v *reachability.Vertex) int {
	if line, ok := v.Properties["LINE_NUMBER"].(float64); ok {
		return int(line)
	}
	if line, ok := v.Properties["LINE_NUMBER"].(int); ok {
		return line
	}
	return 0
}

func (d *Detector) extractParams(name string) string {
	// Extract parameter names from function signature
	// For now, return simplified indicator
	if idx := strings.LastIndex(name, "("); idx > 0 {
		params := name[idx+1:]
		if idx2 := strings.Index(params, ")"); idx2 > 0 {
			return params[:idx2]
		}
	}
	return "request"
}

func (d *Detector) extractTarget(name string) string {
	// Extract the variable being assigned to
	if idx := strings.Index(name, "="); idx > 0 {
		return strings.TrimSpace(name[idx+1:])
	}
	return name
}
