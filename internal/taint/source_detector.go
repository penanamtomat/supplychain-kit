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
	Symbol   string // Method full name used as BFS start identifier
	CPGID    string // CPG vertex ID for edge-based traversal
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

	// Build a map of METHOD -> CALL vertices via AST containment
	methodCalls := d.findCallsInMethods()

	for _, v := range d.cpg.Vertices {
		if v.Type != "METHOD" {
			continue
		}

		name, _ := v.Properties["FULL_NAME"].(string)
		if name == "" {
			name, _ = v.Properties["METHOD_FULL_NAME"].(string)
		}
		if name == "" {
			continue
		}

		lower := strings.ToLower(name)
		isHandler :=
			// Go: net/http, gin, echo, fiber, chi
			strings.Contains(lower, "handle") ||
			strings.Contains(lower, "servehttp") ||
			strings.Contains(lower, ".handler") ||
			strings.Contains(lower, "handler.") ||
			strings.Contains(lower, "controller.") ||
			strings.Contains(lower, "endpoint.") ||
			// Python: Flask route functions, FastAPI path operations
			strings.Contains(lower, "flask.route") ||
			strings.Contains(lower, "@app.route") ||
			strings.Contains(lower, "@router.") ||
			strings.Contains(lower, "view_func") ||
			strings.Contains(lower, "dispatch_request") ||
			strings.Contains(lower, "apiview.") ||
			strings.Contains(lower, "viewset.") ||
			strings.Contains(lower, "fastapi.get") ||
			strings.Contains(lower, "fastapi.post") ||
			strings.Contains(lower, "fastapi.put") ||
			strings.Contains(lower, "fastapi.delete") ||
			// JavaScript/TypeScript: Express, Fastify, Koa, NestJS
			strings.Contains(lower, "router.get") ||
			strings.Contains(lower, "router.post") ||
			strings.Contains(lower, "router.put") ||
			strings.Contains(lower, "router.delete") ||
			strings.Contains(lower, "app.get(") ||
			strings.Contains(lower, "app.post(") ||
			strings.Contains(lower, "app.put(") ||
			strings.Contains(lower, "app.delete(") ||
			strings.Contains(lower, "@get(") ||
			strings.Contains(lower, "@post(") ||
			strings.Contains(lower, "@put(") ||
			strings.Contains(lower, "@delete(") ||
			strings.Contains(lower, "middleware")

		if !isHandler {
			continue
		}

		priority := 10
		if strings.Contains(lower, "gin") || strings.Contains(lower, "echo") {
			priority = 20
		}
		if strings.Contains(lower, "net/http") {
			priority = 15
		}
		// Python frameworks
		if strings.Contains(lower, "flask") || strings.Contains(lower, "fastapi") || strings.Contains(lower, "django") {
			priority = 20
		}
		// JS frameworks
		if strings.Contains(lower, "express") || strings.Contains(lower, "fastify") || strings.Contains(lower, "nestjs") {
			priority = 18
		}

		sources = append(sources, Source{
			Type:     SourceHTTPParam,
			Name:     name,
			File:     d.vertexFile(v),
			Line:     d.vertexLine(v),
			Symbol:   name,
			CPGID:    v.ID,
			Priority: priority,
		})

		// Also add framework-specific input CALL vertices as sources
		// e.g., gin.Context.Query, gin.Context.BindJSON, gin.Context.Param
		if calls, ok := methodCalls[v.ID]; ok {
			for _, call := range calls {
				callName := d.vertexName(call)
				if d.isInputSource(callName) {
					sources = append(sources, Source{
						Type:     SourceHTTPParam,
						Name:     callName,
						File:     d.vertexFile(call),
						Line:     d.vertexLine(call),
						Symbol:   callName,
						CPGID:    call.ID,
						Priority: priority + 5,
					})
				}
			}
		}
	}

	return sources
}

func (d *Detector) isInputSource(name string) bool {
	if name == "" {
		return false
	}
	lower := strings.ToLower(name)

	// Go: gin, echo, net/http
	goSources := strings.Contains(lower, "context.query") ||
		strings.Contains(lower, "context.param") ||
		strings.Contains(lower, "context.bindjson") ||
		strings.Contains(lower, "context.bind") ||
		strings.Contains(lower, "context.formvalue") ||
		strings.Contains(lower, "context.postform") ||
		strings.Contains(lower, "context.getheader") ||
		strings.Contains(lower, "context.getrawdata") ||
		strings.Contains(lower, "request.formvalue") ||
		strings.Contains(lower, "request.header") ||
		strings.Contains(lower, "request.body") ||
		strings.Contains(lower, "request.url") ||
		strings.Contains(lower, "request.parseform")

	// Python: Flask, FastAPI, Django
	pythonSources := strings.Contains(lower, "request.args") ||
		strings.Contains(lower, "request.form") ||
		strings.Contains(lower, "request.json") ||
		strings.Contains(lower, "request.get_json") ||
		strings.Contains(lower, "request.data") ||
		strings.Contains(lower, "request.files") ||
		strings.Contains(lower, "request.cookies") ||
		strings.Contains(lower, "request.values") ||
		strings.Contains(lower, "request.get") ||
		strings.Contains(lower, "request.post") ||
		strings.Contains(lower, "fastapi.query") ||
		strings.Contains(lower, "fastapi.body") ||
		strings.Contains(lower, "fastapi.path") ||
		strings.Contains(lower, "fastapi.form") ||
		strings.Contains(lower, "depends(") ||
		strings.Contains(lower, "annotated[") ||
		strings.Contains(lower, "query(") ||
		strings.Contains(lower, "body(") ||
		strings.Contains(lower, "path(") ||
		strings.Contains(lower, "django.http") ||
		strings.Contains(lower, "request.meta") ||
		strings.Contains(lower, "request.resolver_match")

	// JavaScript/TypeScript: Express, Fastify, Koa, NestJS
	jsSources := strings.Contains(lower, "req.body") ||
		strings.Contains(lower, "req.query") ||
		strings.Contains(lower, "req.params") ||
		strings.Contains(lower, "req.headers") ||
		strings.Contains(lower, "req.cookies") ||
		strings.Contains(lower, "req.files") ||
		strings.Contains(lower, "request.body") ||
		strings.Contains(lower, "request.query") ||
		strings.Contains(lower, "request.params") ||
		strings.Contains(lower, "ctx.request") ||
		strings.Contains(lower, "ctx.query") ||
		strings.Contains(lower, "ctx.params") ||
		strings.Contains(lower, "ctx.body") ||
		strings.Contains(lower, "nestjs.body") ||
		strings.Contains(lower, "@body()") ||
		strings.Contains(lower, "@query()") ||
		strings.Contains(lower, "@param(")

	return goSources || pythonSources || jsSources
}

func (d *Detector) findCallsInMethods() map[string][]*reachability.Vertex {
	// Build parent->child mapping from CPG edges
	children := make(map[string][]*reachability.Vertex)
	for _, e := range d.cpg.Edges {
		if e.Label == "AST" || e.Label == "CONTAINS" {
			for _, v := range d.cpg.Vertices {
				if v.ID == e.To {
					children[e.From] = append(children[e.From], v)
					break
				}
			}
		}
	}

	// For each METHOD, find CALL children
	result := make(map[string][]*reachability.Vertex)
	for _, v := range d.cpg.Vertices {
		if v.Type != "METHOD" {
			continue
		}
		var calls []*reachability.Vertex
		d.collectCalls(v.ID, children, make(map[string]bool), &calls)
		if len(calls) > 0 {
			result[v.ID] = calls
		}
	}
	return result
}

func (d *Detector) collectCalls(nodeID string, children map[string][]*reachability.Vertex, visited map[string]bool, calls *[]*reachability.Vertex) {
	if visited[nodeID] {
		return
	}
	visited[nodeID] = true

	for _, child := range children[nodeID] {
		if child.Type == "CALL" {
			*calls = append(*calls, child)
		}
		d.collectCalls(child.ID, children, visited, calls)
	}
}

func (d *Detector) vertexName(v *reachability.Vertex) string {
	if name, ok := v.Properties["METHOD_FULL_NAME"].(string); ok && name != "" {
		return name
	}
	if name, ok := v.Properties["FULL_NAME"].(string); ok && name != "" {
		return name
	}
	if name, ok := v.Properties["NAME"].(string); ok && name != "" {
		return name
	}
	return ""
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
	if file, ok := v.Properties["FILENAME"].(string); ok {
		return file
	}
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
