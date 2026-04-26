// Package mcp implements the supplychain-kit MCP server (stdio transport).
// It exposes five tools that Claude Code uses to automate the full scan pipeline:
// init_engagement, scan_repository, generate_sbom, run_gate, generate_report.
package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/rs/zerolog/log"

	"github.com/penanamtomat/supplychain-kit/internal/config"
	"github.com/penanamtomat/supplychain-kit/internal/correlation"
	"github.com/penanamtomat/supplychain-kit/internal/models"
	"github.com/penanamtomat/supplychain-kit/internal/quality"
	"github.com/penanamtomat/supplychain-kit/internal/reachability"
	"github.com/penanamtomat/supplychain-kit/internal/scanner"
	"github.com/penanamtomat/supplychain-kit/internal/scanner/gitleaks"
	"github.com/penanamtomat/supplychain-kit/internal/scanner/grype"
	"github.com/penanamtomat/supplychain-kit/internal/scanner/joern"
	"github.com/penanamtomat/supplychain-kit/internal/scanner/osvscanner"
	"github.com/penanamtomat/supplychain-kit/internal/scanner/semgrep"
	syftadapter "github.com/penanamtomat/supplychain-kit/internal/scanner/syft"
	trivyadapter "github.com/penanamtomat/supplychain-kit/internal/scanner/trivy"
	"github.com/penanamtomat/supplychain-kit/internal/scoring"
)

const (
	serverName    = "supplychain-kit"
	serverVersion = "0.8.0"
)

// EngagementState tracks which pipeline phases have completed.
type EngagementState struct {
	Engagement string            `json:"engagement"`
	Repo       string            `json:"repo"`
	Policy     string            `json:"policy"`
	Mode       string            `json:"mode"`
	OutputDir  string            `json:"output_dir"`
	CreatedAt  string            `json:"created_at"`
	Phases     map[string]string `json:"phases"` // phase → "done" | "skipped" | "failed"
}

// toolResult is the standard JSON envelope returned by every tool.
type toolResult struct {
	Status  string      `json:"status"`           // "ok" | "error"
	Data    interface{} `json:"data,omitempty"`
	Summary string      `json:"summary,omitempty"`
	Errors  []string    `json:"errors,omitempty"`
}

func respond(v toolResult) (*mcp.CallToolResult, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			mcp.TextContent{Type: "text", Text: string(raw)},
		},
	}, nil
}

func errRespond(msg string) (*mcp.CallToolResult, error) {
	return respond(toolResult{Status: "error", Errors: []string{msg}})
}

// New constructs and returns a configured MCP server with all five tools registered.
func New() *server.MCPServer {
	s := server.NewMCPServer(
		serverName,
		serverVersion,
		server.WithToolCapabilities(true),
	)

	s.AddTool(toolInitEngagement(), handleInitEngagement)
	s.AddTool(toolScanRepository(), handleScanRepository)
	s.AddTool(toolGenerateSBOM(), handleGenerateSBOM)
	s.AddTool(toolRunGate(), handleRunGate)
	s.AddTool(toolGenerateReport(), handleGenerateReport)

	return s
}

// Serve starts the MCP server on stdio (blocks until stdin closes).
func Serve(ctx context.Context) error {
	return server.ServeStdio(New())
}

// PrintConfig writes the ~/.claude/mcp.json snippet to stdout.
func PrintConfig() {
	exe, _ := os.Executable()
	cfg := map[string]interface{}{
		"mcpServers": map[string]interface{}{
			"supplychain-kit": map[string]interface{}{
				"command": exe,
				"args":    []string{"mcp"},
			},
		},
	}
	raw, _ := json.MarshalIndent(cfg, "", "  ")
	fmt.Println(string(raw))
}

// ── tool definitions ──────────────────────────────────────────────────────────

func toolInitEngagement() mcp.Tool {
	return mcp.NewTool("init_engagement",
		mcp.WithDescription("Bootstrap a new scan engagement: create directory structure (results/<engagement>/findings/, sbom/, reports/) and state.json that tracks pipeline progress."),
		mcp.WithString("engagement", mcp.Required(), mcp.Description("Engagement name (used as directory name under results/)")),
		mcp.WithString("repo", mcp.Required(), mcp.Description("Absolute path or remote git URL of the repository to scan")),
		mcp.WithString("policy", mcp.Description("Policy preset: strict | moderate | permissive (default: moderate)")),
		mcp.WithString("mode", mcp.Description("Scan mode: sca | sast | all (default: all)")),
		mcp.WithString("output_dir", mcp.Description("Base output directory (default: results)")),
	)
}

func toolScanRepository() mcp.Tool {
	return mcp.NewTool("scan_repository",
		mcp.WithDescription("Run the full scan pipeline (SCA + SAST + reachability analysis) against a repository. Returns structured findings with severity, reachability, and risk score."),
		mcp.WithString("engagement", mcp.Required(), mcp.Description("Engagement name — must have been initialised with init_engagement first")),
		mcp.WithString("repo", mcp.Required(), mcp.Description("Absolute local path to the repository")),
		mcp.WithString("mode", mcp.Description("Scanner mode: sca | sast | all (default: all)")),
		mcp.WithString("semgrep_config", mcp.Description("Semgrep ruleset override (default: p/owasp-top-ten)")),
	)
}

func toolGenerateSBOM() mcp.Tool {
	return mcp.NewTool("generate_sbom",
		mcp.WithDescription("Generate a CycloneDX 1.5 SBOM for a repository using syft. Returns the path to the saved sbom.json and a component count summary."),
		mcp.WithString("engagement", mcp.Required(), mcp.Description("Engagement name")),
		mcp.WithString("repo", mcp.Required(), mcp.Description("Absolute local path to the repository")),
	)
}

func toolRunGate() mcp.Tool {
	return mcp.NewTool("run_gate",
		mcp.WithDescription("Evaluate a findings set against the quality gate policy. Returns pass/warn/fail decision plus all violations."),
		mcp.WithString("engagement", mcp.Required(), mcp.Description("Engagement name — findings.json must exist in the engagement dir")),
		mcp.WithString("policy", mcp.Description("Policy preset or path to a custom YAML file (default: moderate)")),
	)
}

func toolGenerateReport() mcp.Tool {
	return mcp.NewTool("generate_report",
		mcp.WithDescription("Render all findings for an engagement into a per-finding Markdown report saved to results/<engagement>/reports/report.md."),
		mcp.WithString("engagement", mcp.Required(), mcp.Description("Engagement name — findings.json must exist in the engagement dir")),
		mcp.WithString("format", mcp.Description("Output format: markdown | docx | all (default: markdown). DOCX requires pandoc.")),
	)
}

// ── handlers ──────────────────────────────────────────────────────────────────

func handleInitEngagement(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := req.GetArguments()
	engagement, _ := args["engagement"].(string)
	repo, _ := args["repo"].(string)
	policy, _ := args["policy"].(string)
	mode, _ := args["mode"].(string)
	outputDir, _ := args["output_dir"].(string)

	if engagement == "" || repo == "" {
		return errRespond("engagement and repo are required")
	}
	if policy == "" {
		policy = "moderate"
	}
	if mode == "" {
		mode = "all"
	}
	if outputDir == "" {
		outputDir = "results"
	}

	engDir := filepath.Join(outputDir, engagement)
	for _, sub := range []string{"findings", "sbom", "reports"} {
		if err := os.MkdirAll(filepath.Join(engDir, sub), 0o755); err != nil {
			return errRespond(fmt.Sprintf("create dir %s: %v", sub, err))
		}
	}

	state := EngagementState{
		Engagement: engagement,
		Repo:       repo,
		Policy:     policy,
		Mode:       mode,
		OutputDir:  outputDir,
		CreatedAt:  time.Now().UTC().Format(time.RFC3339),
		Phases: map[string]string{
			"init":   "done",
			"sbom":   "pending",
			"scan":   "pending",
			"gate":   "pending",
			"report": "pending",
		},
	}
	raw, _ := json.MarshalIndent(state, "", "  ")
	statePath := filepath.Join(engDir, "state.json")
	if err := os.WriteFile(statePath, raw, 0o644); err != nil {
		return errRespond(fmt.Sprintf("write state.json: %v", err))
	}

	return respond(toolResult{
		Status:  "ok",
		Summary: fmt.Sprintf("Engagement %q initialised at %s", engagement, engDir),
		Data: map[string]interface{}{
			"engagement_dir": engDir,
			"state_path":     statePath,
			"state":          state,
		},
	})
}

func handleScanRepository(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := req.GetArguments()
	engagement, _ := args["engagement"].(string)
	repo, _ := args["repo"].(string)
	mode, _ := args["mode"].(string)
	semgrepConfig, _ := args["semgrep_config"].(string)

	if engagement == "" || repo == "" {
		return errRespond("engagement and repo are required")
	}
	if mode == "" {
		mode = "all"
	}

	abs, err := filepath.Abs(repo)
	if err != nil {
		return errRespond(fmt.Sprintf("resolve repo path: %v", err))
	}

	reg := buildRegistry(mode, semgrepConfig)
	asset := &models.Asset{
		ID:          engagement,
		Name:        abs,
		Environment: models.EnvDev,
		Tier:        2,
	}

	results, artifacts := reg.RunLocal(ctx, asset, abs)
	merged := correlation.Merge(results)

	cpgPath := ""
	if artifacts != nil {
		cpgPath = artifacts[joern.ArtifactCPGPath]
		if cpgPath != "" {
			log.Info().Str("cpg_path", cpgPath).Msg("scan: CPG artifact found from Joern")
		} else {
			log.Warn().Msg("scan: no CPG artifact found — Joern may have failed or not been included in scan mode")
		}
	}
	reach := reachability.New(nil)
	var reachErr string
	if err := reach.Analyze(ctx, asset.ID, cpgPath, merged); err != nil {
		reachErr = err.Error()
		log.Warn().Err(err).Msg("scan: reachability analysis failed")
	}

	scorer := scoring.Scorer{}
	for _, f := range merged {
		if f.Reachability == "" {
			f.Reachability = models.ReachUnknown
		}
		scorer.Score(f, asset)
	}

	// Persist findings to engagement dir.
	engDir := filepath.Join("results", engagement)
	findingsPath := filepath.Join(engDir, "findings", "findings.json")
	_ = os.MkdirAll(filepath.Dir(findingsPath), 0o755)
	raw, _ := json.MarshalIndent(merged, "", "  ")
	_ = os.WriteFile(findingsPath, raw, 0o644)

	// Update state.
	updatePhase(engDir, "scan", "done")

	counts := severityCounts(merged)
	var errs []string
	if reachErr != "" {
		errs = append(errs, "reachability: "+reachErr)
	}

	return respond(toolResult{
		Status: "ok",
		Summary: fmt.Sprintf("%d findings: CRITICAL:%d HIGH:%d MEDIUM:%d LOW:%d — saved to %s",
			len(merged), counts["CRITICAL"], counts["HIGH"], counts["MEDIUM"], counts["LOW"], findingsPath),
		Data: map[string]interface{}{
			"findings_path":  findingsPath,
			"total":          len(merged),
			"severity_counts": counts,
			"findings":       merged,
		},
		Errors: errs,
	})
}

func handleGenerateSBOM(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := req.GetArguments()
	engagement, _ := args["engagement"].(string)
	repo, _ := args["repo"].(string)

	if engagement == "" || repo == "" {
		return errRespond("engagement and repo are required")
	}

	abs, err := filepath.Abs(repo)
	if err != nil {
		return errRespond(fmt.Sprintf("resolve repo path: %v", err))
	}

	reg := scanner.NewRegistry(syftadapter.New())
	asset := &models.Asset{ID: engagement, Name: abs, Environment: models.EnvDev, Tier: 2}
	results, _ := reg.RunLocal(ctx, asset, abs)

	var sbomRaw []byte
	for _, r := range results {
		if p, ok := r.Result.Artifacts[scanner.ArtifactSBOMPath]; ok {
			sbomRaw, err = os.ReadFile(p)
			if err != nil {
				return errRespond(fmt.Sprintf("read sbom: %v", err))
			}
			break
		}
	}
	if sbomRaw == nil {
		return errRespond("syft did not produce an SBOM — is syft installed?")
	}

	engDir := filepath.Join("results", engagement)
	sbomPath := filepath.Join(engDir, "sbom", "sbom.json")
	_ = os.MkdirAll(filepath.Dir(sbomPath), 0o755)
	if err := os.WriteFile(sbomPath, sbomRaw, 0o644); err != nil {
		return errRespond(fmt.Sprintf("write sbom: %v", err))
	}

	// Count components from the SBOM JSON.
	var sbomDoc struct {
		Components []json.RawMessage `json:"components"`
	}
	_ = json.Unmarshal(sbomRaw, &sbomDoc)

	updatePhase(engDir, "sbom", "done")

	return respond(toolResult{
		Status:  "ok",
		Summary: fmt.Sprintf("SBOM generated: %d components → %s", len(sbomDoc.Components), sbomPath),
		Data: map[string]interface{}{
			"sbom_path":       sbomPath,
			"component_count": len(sbomDoc.Components),
		},
	})
}

func handleRunGate(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := req.GetArguments()
	engagement, _ := args["engagement"].(string)
	policy, _ := args["policy"].(string)

	if engagement == "" {
		return errRespond("engagement is required")
	}

	findingsPath := filepath.Join("results", engagement, "findings", "findings.json")
	raw, err := os.ReadFile(findingsPath)
	if err != nil {
		return errRespond(fmt.Sprintf("read findings: %v — run scan_repository first", err))
	}
	var findings []*models.Finding
	if err := json.Unmarshal(raw, &findings); err != nil {
		return errRespond(fmt.Sprintf("parse findings: %v", err))
	}

	policyFile := policyPresetPath(policy)
	cfg, err := config.Load(policyFile)
	if err != nil {
		return errRespond(fmt.Sprintf("load policy: %v", err))
	}
	result := quality.New(cfg.QualityGate).Evaluate(findings)

	engDir := filepath.Join("results", engagement)
	updatePhase(engDir, "gate", string(result.Decision))

	type violationSummary struct {
		Severity string `json:"severity"`
		RuleID   string `json:"rule_id"`
		Package  string `json:"package"`
	}
	var violations []violationSummary
	for _, v := range result.Violations {
		violations = append(violations, violationSummary{
			Severity: strings.ToUpper(string(v.Finding.Severity)),
			RuleID:   v.Finding.RuleID,
			Package:  v.Finding.Package,
		})
	}

	return respond(toolResult{
		Status:  "ok",
		Summary: fmt.Sprintf("Gate: %s — %s", strings.ToUpper(string(result.Decision)), result.Summary),
		Data: map[string]interface{}{
			"decision":   string(result.Decision),
			"summary":    result.Summary,
			"violations": violations,
		},
	})
}

func handleGenerateReport(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := req.GetArguments()
	engagement, _ := args["engagement"].(string)
	format, _ := args["format"].(string)

	if engagement == "" {
		return errRespond("engagement is required")
	}
	if format == "" {
		format = "markdown"
	}

	findingsPath := filepath.Join("results", engagement, "findings", "findings.json")
	raw, err := os.ReadFile(findingsPath)
	if err != nil {
		return errRespond(fmt.Sprintf("read findings: %v — run scan_repository first", err))
	}
	var findings []*models.Finding
	if err := json.Unmarshal(raw, &findings); err != nil {
		return errRespond(fmt.Sprintf("parse findings: %v", err))
	}

	engDir := filepath.Join("results", engagement)
	reportDir := filepath.Join(engDir, "reports")
	_ = os.MkdirAll(reportDir, 0o755)

	var generatedPaths []string
	var errs []string

	if format == "markdown" || format == "all" {
		mdPath := filepath.Join(reportDir, "report.md")
		if err := writeMarkdownReport(mdPath, engagement, findings); err != nil {
			errs = append(errs, fmt.Sprintf("markdown: %v", err))
		} else {
			generatedPaths = append(generatedPaths, mdPath)
		}
	}

	if format == "docx" || format == "all" {
		mdPath := filepath.Join(reportDir, "report.md")
		// Ensure markdown exists for pandoc conversion.
		if _, err := os.Stat(mdPath); os.IsNotExist(err) {
			_ = writeMarkdownReport(mdPath, engagement, findings)
		}
		docxPath := filepath.Join(reportDir, "report.docx")
		if err := convertToDOCX(mdPath, docxPath); err != nil {
			errs = append(errs, fmt.Sprintf("docx: %v", err))
		} else {
			generatedPaths = append(generatedPaths, docxPath)
		}
	}

	updatePhase(engDir, "report", "done")

	status := "ok"
	if len(errs) > 0 && len(generatedPaths) == 0 {
		status = "error"
	}
	return respond(toolResult{
		Status:  status,
		Summary: fmt.Sprintf("Report generated: %s", strings.Join(generatedPaths, ", ")),
		Data: map[string]interface{}{
			"paths":   generatedPaths,
			"format":  format,
			"total":   len(findings),
		},
		Errors: errs,
	})
}

// ── helpers ───────────────────────────────────────────────────────────────────

func buildRegistry(mode, semgrepConfig string) *scanner.Registry {
	sg := semgrep.New()
	if semgrepConfig != "" {
		sg.WithConfig(semgrepConfig)
	}
	switch mode {
	case "sca":
		// Include Joern for reachability analysis of SCA findings
		return scanner.NewRegistry(syftadapter.New(), grype.New(), trivyadapter.New(), osvscanner.New(), joern.New())
	case "sast":
		// Include Joern for reachability analysis of SAST findings
		return scanner.NewRegistry(sg, gitleaks.New(), joern.New())
	default:
		return scanner.NewRegistry(
			syftadapter.New(), grype.New(), trivyadapter.New(), osvscanner.New(),
			sg, gitleaks.New(),
			joern.New(),
		)
	}
}

func severityCounts(findings []*models.Finding) map[string]int {
	counts := map[string]int{"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
	for _, f := range findings {
		counts[strings.ToUpper(string(f.Severity))]++
	}
	return counts
}

func reachabilityNote(r models.Reachability) string {
	switch r {
	case models.ReachReachable:
		return "Fix segera. Prioritas 1 — vulnerable code path terekspos."
	case models.ReachUnreachable:
		return "Fix di sprint berikutnya — code path tidak terekspos di runtime."
	default:
		return "Treat as reachable sampai terbukti sebaliknya."
	}
}

func policyPresetPath(policy string) string {
	switch policy {
	case "strict":
		return "configs/policy-strict.yaml"
	case "permissive":
		return "configs/policy-permissive.yaml"
	default:
		return "configs/policy-moderate.yaml"
	}
}

func updatePhase(engDir, phase, status string) {
	statePath := filepath.Join(engDir, "state.json")
	raw, err := os.ReadFile(statePath)
	if err != nil {
		return
	}
	var state EngagementState
	if err := json.Unmarshal(raw, &state); err != nil {
		return
	}
	if state.Phases == nil {
		state.Phases = map[string]string{}
	}
	state.Phases[phase] = status
	updated, _ := json.MarshalIndent(state, "", "  ")
	_ = os.WriteFile(statePath, updated, 0o644)
}

func writeMarkdownReport(path, engagement string, findings []*models.Finding) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	counts := map[models.Severity]int{}
	for _, fn := range findings {
		counts[fn.Severity]++
	}

	fmt.Fprintf(f, "# Supply Chain Security Report — %s\n\n", engagement)
	fmt.Fprintf(f, "Generated: %s\n\n", time.Now().UTC().Format("2006-01-02 15:04 UTC"))
	fmt.Fprintf(f, "## Executive Summary\n\nTotal findings: **%d**\n\n", len(findings))

	if len(findings) > 0 {
		fmt.Fprintf(f, "| Severity | Count |\n|---|---|\n")
		for _, sev := range []models.Severity{
			models.SeverityCritical, models.SeverityHigh,
			models.SeverityMedium, models.SeverityLow, models.SeverityInfo,
		} {
			if n := counts[sev]; n > 0 {
				fmt.Fprintf(f, "| %s | %d |\n", strings.ToUpper(string(sev)), n)
			}
		}
		fmt.Fprintf(f, "\n")
	}

	fmt.Fprintf(f, "## Findings\n\n")
	for i, fn := range findings {
		pkg := fn.Package
		if pkg == "" {
			pkg = "—"
		}
		ver := fn.Version
		if ver == "" {
			ver = "—"
		}
		fix := fn.FixedVersion
		if fix == "" {
			fix = "—"
		}
		loc := fn.FilePath
		if loc == "" {
			loc = "—"
		} else if fn.Line > 0 {
			loc = fmt.Sprintf("%s:%d", loc, fn.Line)
		}

		fmt.Fprintf(f, "### [%d] [%s] %s\n\n", i+1, strings.ToUpper(string(fn.Severity)), fn.RuleID)
		fmt.Fprintf(f, "| Field | Value |\n|---|---|\n")
		fmt.Fprintf(f, "| **Affected** | `%s %s` |\n", pkg, ver)
		fmt.Fprintf(f, "| **CVSS** | %.1f |\n", fn.CVSS)
		fmt.Fprintf(f, "| **Reachable** | %s |\n", strings.ToUpper(string(fn.Reachability)))
		fmt.Fprintf(f, "| **Risk Score** | %.2f |\n", fn.RiskScore)
		fmt.Fprintf(f, "| **File** | %s |\n\n", loc)

		fmt.Fprintf(f, "**REMEDIATION**\n\n")
		fmt.Fprintf(f, "- Fix: Upgrade `%s` to ≥`%s`\n", pkg, fix)
		fmt.Fprintf(f, "- Reachability note: %s\n\n", reachabilityNote(fn.Reachability))

		if fn.AdvisoryURL != "" {
			fmt.Fprintf(f, "**References:** %s\n\n", fn.AdvisoryURL)
		}
		fmt.Fprintf(f, "---\n\n")
	}
	return nil
}

func convertToDOCX(mdPath, docxPath string) error {
	if _, err := exec.LookPath("pandoc"); err != nil {
		return fmt.Errorf("pandoc not found in PATH — install pandoc to generate DOCX output")
	}
	// Use markdown-yaml_metadata_block to avoid parsing '---' separators as YAML delimiters
	cmd := exec.Command("pandoc", "-f", "markdown-yaml_metadata_block", mdPath, "-o", docxPath, "--toc", "--highlight-style=tango")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("pandoc: %w\n%s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
