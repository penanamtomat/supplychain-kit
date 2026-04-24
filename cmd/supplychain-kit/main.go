// Command supplychain-kit is the operator CLI for local scans, quality gate
// checks, and one-shot scan submission. It is intended to be the integration
// point for CI pipelines.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"text/template"
	"time"

	"github.com/spf13/cobra"

	"github.com/penanamtomat/supplychain-kit/internal/claudeai"
	"github.com/penanamtomat/supplychain-kit/internal/config"
	"github.com/penanamtomat/supplychain-kit/internal/correlation"
	"github.com/penanamtomat/supplychain-kit/internal/defectdojo"
	"github.com/penanamtomat/supplychain-kit/internal/deptrack"
	kitmc "github.com/penanamtomat/supplychain-kit/internal/mcp"
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

// version is set at build time: go build -ldflags "-X main.version=$(git describe --tags --always)"
var version = "dev"

func main() {
	root := &cobra.Command{
		Use:     "supplychain-kit",
		Short:   "Supply chain security scanner — SCA, SAST, secrets, quality gate, and report in one tool",
		Version: version,
	}
	root.AddCommand(runCmd(), scanCmd(), gateCmd(), sbomCmd(), engageCmd(), submitCmd(), deptrackCmd(), defectdojoCmd(), mcpCmd(), initEngagementCmd(), analyzeCmd(), reportCmd(), installHooksCmd())
	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func scanCmd() *cobra.Command {
	var (
		repo          string
		ref           string
		out           string
		mode          string
		format        string
		target        string
		semgrepConfig string
		gitHistory    bool
	)
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Run a security scan and emit normalized findings",
		Long: `Run a security scan against a local directory or remote git repository.

Modes:
  sca   Supply chain analysis only (syft + grype)
  sast  Code analysis only (semgrep + gitleaks)
  all   All scanners (default)

Formats:
  json  Full findings as JSON (default when --out is set)
  table Human-readable table to stdout

Target:
  --target <name>  Save all outputs to results/<name>/ directory.
                   If omitted and --repo is a local path, the directory
                   name of the repo is used as target.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if repo == "" {
				return fmt.Errorf("--repo required")
			}

			reg := buildRegistry(mode, semgrepConfig, gitHistory)
			asset := &models.Asset{
				ID:          "local",
				Name:        repo,
				Environment: models.EnvDev,
				Tier:        2,
			}

			var results []scanner.ScannedResult
			var artifacts map[string]string
			var cleanup func()

			if isLocalPath(repo) {
				abs, err := filepath.Abs(repo)
				if err != nil {
					return fmt.Errorf("resolve path: %w", err)
				}
				asset.Name = abs
				results, artifacts = reg.RunLocal(cmd.Context(), asset, abs)
				cleanup = func() {}
			} else {
				asset.RepoURL = repo
				var err error
				results, artifacts, cleanup, err = reg.RunPipeline(cmd.Context(), asset, ref)
				if err != nil {
					return err
				}
			}
			defer cleanup()

			merged := correlation.Merge(results)

			cpgPath := ""
			if artifacts != nil {
				cpgPath = artifacts[joern.ArtifactCPGPath]
			}
			reach := reachability.New(nil)
			if err := reach.Analyze(cmd.Context(), asset.ID, cpgPath, merged); err != nil {
				fmt.Fprintf(os.Stderr, "warn: reachability analysis failed: %v\n", err)
			}

			scorer := scoring.Scorer{}
			for _, f := range merged {
				if f.Reachability == "" {
					f.Reachability = models.ReachUnknown
				}
				scorer.Score(f, asset)
			}

			printSummary(merged)

			// Target mode: write all reports to results/<target>/
			if target != "" {
				targetDir, err := resolveTargetDir(target)
				if err != nil {
					return err
				}
				if err := os.MkdirAll(targetDir, 0o755); err != nil {
					return fmt.Errorf("create target dir: %w", err)
				}
				writeTargetReports(targetDir, merged, repo, mode)
				fmt.Fprintf(os.Stderr, "  Reports saved to %s/\n\n", targetDir)
				return nil
			}

			if format == "table" {
				return printTable(merged)
			}
			// Default: JSON output when --out is set or --format json.
			if out != "" || format == "json" {
				return writeFindings(out, merged)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&repo, "repo", "", "local path or git repository URL")
	cmd.Flags().StringVar(&ref, "ref", "HEAD", "git ref (branch, tag, commit)")
	cmd.Flags().StringVar(&out, "out", "", "write JSON findings to file (- for stdout)")
	cmd.Flags().StringVar(&mode, "mode", "all", "scanner mode: sca, sast, all")
	cmd.Flags().StringVar(&format, "format", "", "output format: json, table")
	cmd.Flags().StringVar(&target, "target", "", "target name — saves reports to results/<target>/")
	cmd.Flags().StringVar(&semgrepConfig, "semgrep-config", "", "semgrep ruleset override (default: p/owasp-top-ten)")
	cmd.Flags().BoolVar(&gitHistory, "git-history", false, "scan git commit history for secrets (gitleaks)")
	return cmd
}

// resolveTargetDir returns the absolute path to results/<target>.
// It rejects targets that would escape the results/ base directory.
func resolveTargetDir(target string) (string, error) {
	if target == "" {
		return "results", nil
	}
	base, err := filepath.Abs("results")
	if err != nil {
		return "", err
	}
	resolved := filepath.Clean(filepath.Join(base, target))
	if !strings.HasPrefix(resolved, base+string(filepath.Separator)) && resolved != base {
		return "", fmt.Errorf("invalid target %q: must not escape results/ directory", target)
	}
	return resolved, nil
}

// inferTargetName extracts a target name from a repo path or URL.
func inferTargetName(repo string) string {
	if isLocalPath(repo) {
		return filepath.Base(repo)
	}
	// From URL like https://github.com/org/repo.git → repo
	parts := strings.Split(strings.TrimSuffix(repo, ".git"), "/")
	return parts[len(parts)-1]
}

// writeTargetReports writes findings.json, findings.txt, and summary.json
// into the target directory.
func writeTargetReports(dir string, findings []*models.Finding, repo, mode string) {
	_ = writeFindings(filepath.Join(dir, "findings.json"), findings)

	f, err := os.Create(filepath.Join(dir, "findings.txt"))
	if err == nil {
		writeTableTo(f, findings)
		f.Close()
	}

	counts := map[string]int{}
	for _, f := range findings {
		counts[strings.ToUpper(string(f.Severity))]++
	}
	summary := map[string]interface{}{
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"target":    filepath.Base(dir),
		"repo":      repo,
		"mode":      mode,
		"total":     len(findings),
		"severity":  counts,
	}
	raw, _ := json.MarshalIndent(summary, "", "  ")
	_ = os.WriteFile(filepath.Join(dir, "summary.json"), raw, 0o644)
}

// writeTableTo writes a human-readable table to any io.Writer.
func writeTableTo(w *os.File, findings []*models.Finding) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "SEVERITY\tRULE / CVE\tPACKAGE\tFIX\tFILE\tREACHABLE\tRISK_SCORE")
	fmt.Fprintln(tw, "--------\t----------\t-------\t---\t----\t---------\t----------")
	for _, f := range findings {
		pkg := f.Package
		if pkg == "" {
			pkg = "-"
		}
		fix := f.FixedVersion
		if fix == "" {
			fix = "-"
		}
		loc := f.FilePath
		if loc == "" {
			loc = "-"
		} else if f.Line > 0 {
			loc = fmt.Sprintf("%s:%d", loc, f.Line)
		}
		reach := string(f.Reachability)
		if reach == "" {
			reach = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%.2f\n",
			strings.ToUpper(string(f.Severity)),
			f.RuleID, pkg, fix, loc, reach, f.RiskScore,
		)
	}
	tw.Flush()
}

// buildRegistry returns a Registry populated according to the requested mode.
func buildRegistry(mode, semgrepConfig string, gitHistory bool) *scanner.Registry {
	sg := semgrep.New()
	if semgrepConfig != "" {
		sg.WithConfig(semgrepConfig)
	}
	gl := gitleaks.New()
	if gitHistory {
		gl.WithGitHistory()
	}
	switch mode {
	case "sca":
		return scanner.NewRegistry(syftadapter.New(), grype.New(), trivyadapter.New(), osvscanner.New())
	case "sast":
		return scanner.NewRegistry(sg, gl)
	default:
		return scanner.NewRegistry(
			syftadapter.New(), grype.New(), trivyadapter.New(), osvscanner.New(),
			sg, gl,
			joern.New(),
		)
	}
}

// printSummary writes a sectioned count (SCA / SAST / Secrets) to stderr.
func printSummary(findings []*models.Finding) {
	var sca, sast, secrets []*models.Finding
	for _, f := range findings {
		switch categorizeFinding(f) {
		case "sca":
			sca = append(sca, f)
		case "sast":
			sast = append(sast, f)
		case "secrets":
			secrets = append(secrets, f)
		}
	}

	fmt.Fprintf(os.Stderr, "\n── Scan Summary ─────────────────────────\n")
	fmt.Fprintf(os.Stderr, "  Total findings : %d\n\n", len(findings))
	printSummarySection("SCA  (dependencies)", sca)
	printSummarySection("SAST (code)", sast)
	printSummarySection("Secrets", secrets)
	fmt.Fprintf(os.Stderr, "─────────────────────────────────────────\n")
}

func categorizeFinding(f *models.Finding) string {
	for _, s := range f.Sources {
		switch s {
		case models.SourceGrype, models.SourceSyft:
			return "sca"
		case models.SourceGitleaks:
			return "secrets"
		case models.SourceSemgrep, models.SourceJoern:
			return "sast"
		}
	}
	return "other"
}

func printSummarySection(label string, findings []*models.Finding) {
	if len(findings) == 0 {
		fmt.Fprintf(os.Stderr, "  %-22s: none\n", label)
		return
	}
	counts := map[models.Severity]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}
	var parts []string
	for _, sev := range []models.Severity{
		models.SeverityCritical, models.SeverityHigh,
		models.SeverityMedium, models.SeverityLow, models.SeverityInfo,
	} {
		if n := counts[sev]; n > 0 {
			parts = append(parts, fmt.Sprintf("%s:%d", strings.ToUpper(string(sev)), n))
		}
	}
	fmt.Fprintf(os.Stderr, "  %-22s: %s\n", label, strings.Join(parts, "  "))
}

// printTable writes a human-readable table of findings to stdout.
func printTable(findings []*models.Finding) error {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "SEVERITY\tRULE / CVE\tPACKAGE\tFIX\tFILE\tREACHABLE\tRISK_SCORE")
	fmt.Fprintln(w, "--------\t----------\t-------\t---\t----\t---------\t----------")
	for _, f := range findings {
		pkg := f.Package
		if pkg == "" {
			pkg = "-"
		}
		fix := f.FixedVersion
		if fix == "" {
			fix = "-"
		}
		loc := f.FilePath
		if loc == "" {
			loc = "-"
		} else if f.Line > 0 {
			loc = fmt.Sprintf("%s:%d", loc, f.Line)
		}
		reach := string(f.Reachability)
		if reach == "" {
			reach = "-"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%.2f\n",
			strings.ToUpper(string(f.Severity)),
			f.RuleID, pkg, fix, loc, reach, f.RiskScore,
		)
	}
	return w.Flush()
}

func gateCmd() *cobra.Command {
	var (
		findingsFile string
		policyFile   string
	)
	cmd := &cobra.Command{
		Use:   "gate",
		Short: "Evaluate a finding set against the configured Quality Gate",
		Long: `Evaluate a findings JSON against the quality gate policy.

Exit codes:
  0  pass — no policy violations
  1  warn — High findings present (no Critical)
  2  fail — Critical findings present

Examples:
  supplychain-kit gate --findings results/myapp/findings.json
  supplychain-kit gate --findings results/myapp/findings.json --policy configs/policy-strict.yaml
  supplychain-kit scan --repo . --format json | supplychain-kit gate`,
		RunE: func(cmd *cobra.Command, args []string) error {
			findings, err := readFindings(findingsFile)
			if err != nil {
				return err
			}
			cfg, err := config.Load(policyFile)
			if err != nil {
				return err
			}
			result := quality.New(cfg.QualityGate).Evaluate(findings)

			printGateResult(result)

			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			_ = enc.Encode(result)

			switch result.Decision {
			case quality.DecisionFail:
				os.Exit(2)
			case quality.DecisionWarn:
				os.Exit(1)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&findingsFile, "findings", "-", "findings JSON file (- for stdin)")
	cmd.Flags().StringVar(&policyFile, "policy", "", "policy YAML file (defaults to configs/aspm.yaml)")
	return cmd
}

// printGateResult writes a human-readable gate summary to stderr.
func printGateResult(result quality.Result) {
	decisionColor := map[quality.Decision]string{
		quality.DecisionPass: "PASS",
		quality.DecisionWarn: "WARN",
		quality.DecisionFail: "FAIL",
	}
	label := decisionColor[result.Decision]

	fmt.Fprintf(os.Stderr, "\n── Quality Gate ──────────────────────────\n")
	fmt.Fprintf(os.Stderr, "  Decision : %s\n", label)
	fmt.Fprintf(os.Stderr, "  Summary  : %s\n", result.Summary)

	if len(result.Violations) > 0 {
		fmt.Fprintf(os.Stderr, "\n  Violations:\n")
		for _, v := range result.Violations {
			f := v.Finding
			loc := f.Package
			if loc == "" {
				loc = f.FilePath
			}
			if loc == "" {
				loc = "-"
			}
			adv := ""
			if f.AdvisoryURL != "" {
				adv = "  " + f.AdvisoryURL
			}
			fmt.Fprintf(os.Stderr, "    [%s] %s  %s%s\n",
				strings.ToUpper(string(f.Severity)), f.RuleID, loc, adv)
		}
	}
	if len(result.Warnings) > 0 {
		fmt.Fprintf(os.Stderr, "\n  Warnings:\n")
		for _, w := range result.Warnings {
			f := w.Finding
			loc := f.Package
			if loc == "" {
				loc = f.FilePath
			}
			if loc == "" {
				loc = "-"
			}
			fmt.Fprintf(os.Stderr, "    [%s] %s  %s\n",
				strings.ToUpper(string(f.Severity)), f.RuleID, loc)
		}
	}
	fmt.Fprintf(os.Stderr, "─────────────────────────────────────────\n\n")
}

func submitCmd() *cobra.Command {
	var (
		repo string
		api  string
	)
	cmd := &cobra.Command{
		Use:   "submit",
		Short: "POST a scan request to a running aspm-api",
		RunE: func(cmd *cobra.Command, args []string) error {
			body, _ := json.Marshal(map[string]string{"repo_url": repo, "trigger": "manual"})
			resp, err := http.Post(api+"/api/v1/scans", "application/json", bytes.NewReader(body))
			if err != nil {
				return err
			}
			defer func() { _ = resp.Body.Close() }()
			fmt.Println(resp.Status)
			return nil
		},
	}
	cmd.Flags().StringVar(&repo, "repo", "", "git repository URL")
	cmd.Flags().StringVar(&api, "api", "http://localhost:8080", "aspm-api base URL")
	return cmd
}

func sbomCmd() *cobra.Command {
	var (
		repo   string
		out    string
		format string
		target string
	)
	cmd := &cobra.Command{
		Use:   "sbom",
		Short: "Generate a CycloneDX 1.5 SBOM for a repository",
		Long: `Generate an SBOM for a local or remote repository using syft.

Formats:
  cyclonedx  CycloneDX 1.5 JSON (default)
  spdx       SPDX 2.3 JSON`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if repo == "" {
				return fmt.Errorf("--repo required")
			}
			syftScanner := syftadapter.NewWithFormat(format)
			reg := scanner.NewRegistry(syftScanner)
			asset := &models.Asset{ID: "local", Name: repo, Environment: models.EnvDev, Tier: 2}

			var results []scanner.ScannedResult
			if isLocalPath(repo) {
				abs, err := filepath.Abs(repo)
				if err != nil {
					return fmt.Errorf("resolve path: %w", err)
				}
				results, _ = reg.RunLocal(cmd.Context(), asset, abs)
			} else {
				asset.RepoURL = repo
				var err error
				var cleanup func()
				results, _, cleanup, err = reg.RunPipeline(cmd.Context(), asset, "HEAD")
				if err != nil {
					return err
				}
				defer cleanup()
			}

			for _, r := range results {
				if sbomPath, ok := r.Result.Artifacts[scanner.ArtifactSBOMPath]; ok {
					raw, err := os.ReadFile(sbomPath)
					if err != nil {
						return err
					}

					// Target mode: save to results/<target>/sbom.json
					if target != "" {
						targetDir, err := resolveTargetDir(target)
						if err != nil {
							return err
						}
						if err := os.MkdirAll(targetDir, 0o755); err != nil {
							return fmt.Errorf("create target dir: %w", err)
						}
						dest := filepath.Join(targetDir, "sbom.json")
						if err := os.WriteFile(dest, raw, 0o644); err != nil {
							return err
						}
						fmt.Fprintf(os.Stderr, "SBOM saved to %s\n", dest)
						return nil
					}

					// Default: write to --out or stdout
					w := os.Stdout
					if out != "" && out != "-" {
						if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
							return err
						}
						f, err := os.Create(out)
						if err != nil {
							return err
						}
						defer func() { _ = f.Close() }()
						w = f
					}
					_, err = w.Write(raw)
					return err
				}
			}
			return fmt.Errorf("syft did not produce an SBOM — is syft installed?")
		},
	}
	cmd.Flags().StringVar(&repo, "repo", "", "local path or git repository URL")
	cmd.Flags().StringVar(&out, "out", "-", "output file (- for stdout)")
	cmd.Flags().StringVar(&format, "format", "cyclonedx", "output format: cyclonedx, spdx")
	cmd.Flags().StringVar(&target, "target", "", "target name — saves SBOM to results/<target>/sbom.json")
	return cmd
}

// isLocalPath returns true when repo looks like a filesystem path rather than
// a remote URL (http/https/git/ssh scheme or SCP-style git@host:path).
func isLocalPath(repo string) bool {
	for _, prefix := range []string{"http://", "https://", "git://", "ssh://", "git@"} {
		if strings.HasPrefix(repo, prefix) {
			return false
		}
	}
	return true
}

func writeFindings(path string, fs []*models.Finding) error {
	w := os.Stdout
	if path != "" && path != "-" {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		f, err := os.Create(path)
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()
		w = f
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(fs)
}

func readFindings(path string) ([]*models.Finding, error) {
	r := os.Stdin
	if path != "" && path != "-" {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer func() { _ = f.Close() }()
		r = f
	}
	var out []*models.Finding
	if err := json.NewDecoder(r).Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

// ── run command ───────────────────────────────────────────────────────────────

func runCmd() *cobra.Command {
	var (
		repo          string
		ref           string
		mode          string
		policy        string
		semgrepConfig string
		gitHistory    bool
	)
	cmd := &cobra.Command{
		Use:   "run <engagement>",
		Short: "Scan a repository end-to-end and generate a full report (one command)",
		Long: `Run a complete security scan and generate a report in one command.

Steps performed automatically:
  1. Clone repository (if a remote URL is given)
  2. Run scanner pipeline based on --mode
  3. Evaluate quality gate against policy
  4. Generate report files in results/<engagement>/

Output files:
  results/<engagement>/findings.json   — full findings (machine-readable)
  results/<engagement>/findings.txt    — findings table (human-readable)
  results/<engagement>/summary.json    — counts + metadata
  results/<engagement>/report.md       — full markdown report

Exit codes:
  0  pass   — no policy violations
  1  warn   — High findings present
  2  fail   — Critical findings present

To push results to external systems after the scan:
  supplychain-kit deptrack upload --sbom results/<engagement>/sbom.json ...
  supplychain-kit defectdojo push --findings results/<engagement>/findings.json ...

Examples:
  supplychain-kit run myapp-2026q1 --repo https://github.com/org/repo
  supplychain-kit run myapp-2026q1 --repo . --mode sca
  supplychain-kit run myapp-2026q1 --repo https://github.com/org/repo --mode sast --ref main
  supplychain-kit run myapp-2026q1 --repo . --policy configs/policy-strict.yaml`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			engagement := args[0]

			targetDir, err := resolveTargetDir(engagement)
			if err != nil {
				return err
			}
			if err := os.MkdirAll(targetDir, 0o755); err != nil {
				return fmt.Errorf("create engagement dir: %w", err)
			}

			fmt.Fprintf(os.Stderr, "\n── supplychain-kit ───────────────────────\n")
			fmt.Fprintf(os.Stderr, "  Engagement : %s\n", engagement)
			fmt.Fprintf(os.Stderr, "  Repository : %s\n", repo)
			fmt.Fprintf(os.Stderr, "  Mode       : %s\n", mode)
			fmt.Fprintf(os.Stderr, "─────────────────────────────────────────\n\n")

			// Step 1 & 2: scan
			reg := buildRegistry(mode, semgrepConfig, gitHistory)
			asset := &models.Asset{
				ID:          engagement,
				Name:        repo,
				Environment: models.EnvDev,
				Tier:        2,
			}

			var results []scanner.ScannedResult
			var artifacts map[string]string
			var cleanup func()

			if isLocalPath(repo) {
				abs, err := filepath.Abs(repo)
				if err != nil {
					return fmt.Errorf("resolve path: %w", err)
				}
				asset.Name = abs
				results, artifacts = reg.RunLocal(cmd.Context(), asset, abs)
				cleanup = func() {}
			} else {
				asset.RepoURL = repo
				var err error
				results, artifacts, cleanup, err = reg.RunPipeline(cmd.Context(), asset, ref)
				if err != nil {
					return err
				}
			}
			defer cleanup()

			merged := correlation.Merge(results)

			cpgPath := ""
			if artifacts != nil {
				cpgPath = artifacts[joern.ArtifactCPGPath]
			}
			reach := reachability.New(nil)
			if err := reach.Analyze(cmd.Context(), asset.ID, cpgPath, merged); err != nil {
				fmt.Fprintf(os.Stderr, "warn: reachability analysis failed: %v\n", err)
			}

			scorer := scoring.Scorer{}
			for _, f := range merged {
				if f.Reachability == "" {
					f.Reachability = models.ReachUnknown
				}
				scorer.Score(f, asset)
			}

			printSummary(merged)

			// Step 3: save findings + summary
			writeTargetReports(targetDir, merged, repo, mode)

			// Step 4: quality gate
			cfg, err := config.Load(policy)
			if err != nil {
				return err
			}
			gateResult := quality.New(cfg.QualityGate).Evaluate(merged)

			// Step 5: generate markdown report
			reportPath := filepath.Join(targetDir, "report.md")
			if err := writeMarkdownReport(reportPath, engagement, repo, mode, merged, gateResult); err != nil {
				return fmt.Errorf("generate report: %w", err)
			}

			// Step 5: print results
			fmt.Fprintf(os.Stderr, "\n── Results saved to %s/ ─────────────────\n", targetDir)
			fmt.Fprintf(os.Stderr, "  findings.json  — full findings (machine-readable)\n")
			fmt.Fprintf(os.Stderr, "  findings.txt   — findings table\n")
			fmt.Fprintf(os.Stderr, "  summary.json   — counts + metadata\n")
			fmt.Fprintf(os.Stderr, "  report.md      — full markdown report\n")
			fmt.Fprintf(os.Stderr, "\n  Gate decision  : %s\n", strings.ToUpper(string(gateResult.Decision)))
			fmt.Fprintf(os.Stderr, "  Gate summary   : %s\n", gateResult.Summary)
			fmt.Fprintf(os.Stderr, "─────────────────────────────────────────\n\n")

			switch gateResult.Decision {
			case quality.DecisionFail:
				os.Exit(2)
			case quality.DecisionWarn:
				os.Exit(1)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&repo, "repo", "", "local path or remote git URL")
	cmd.Flags().StringVar(&ref, "ref", "HEAD", "git ref (branch, tag, commit)")
	cmd.Flags().StringVar(&mode, "mode", "all", "scanner mode: sca, sast, all")
	cmd.Flags().StringVar(&policy, "policy", "", "policy YAML (default: configs/aspm.yaml)")
	cmd.Flags().StringVar(&semgrepConfig, "semgrep-config", "", "semgrep ruleset override (default: p/owasp-top-ten)")
	cmd.Flags().BoolVar(&gitHistory, "git-history", false, "scan git commit history for secrets (gitleaks)")
	_ = cmd.MarkFlagRequired("repo")
	return cmd
}

// writeMarkdownReport generates a human-readable markdown report.
func writeMarkdownReport(path, engagement, repo, mode string, findings []*models.Finding, gate quality.Result) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	counts := map[models.Severity]int{}
	for _, fn := range findings {
		counts[fn.Severity]++
	}

	now := time.Now().UTC()

	fmt.Fprintf(f, "# Security Report — %s\n\n", engagement)
	fmt.Fprintf(f, "| | |\n|---|---|\n")
	fmt.Fprintf(f, "| **Repository** | `%s` |\n", repo)
	fmt.Fprintf(f, "| **Scan mode** | `%s` |\n", mode)
	fmt.Fprintf(f, "| **Date** | %s |\n", now.Format("2006-01-02 15:04 UTC"))
	fmt.Fprintf(f, "| **Quality gate** | **%s** |\n\n", strings.ToUpper(string(gate.Decision)))

	fmt.Fprintf(f, "## Executive Summary\n\n")
	fmt.Fprintf(f, "Total findings: **%d**\n\n", len(findings))

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

	fmt.Fprintf(f, "## Quality Gate\n\n")
	fmt.Fprintf(f, "**Decision: %s** — %s\n\n", strings.ToUpper(string(gate.Decision)), gate.Summary)

	if len(findings) == 0 {
		fmt.Fprintf(f, "## Findings\n\nNo vulnerabilities found.\n")
		return nil
	}

	fmt.Fprintf(f, "## Findings\n\n")
	fmt.Fprintf(f, "| Severity | CVE / Rule | Package | Version | Fix | File |\n")
	fmt.Fprintf(f, "|---|---|---|---|---|---|\n")
	for _, fn := range findings {
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
		fmt.Fprintf(f, "| %s | `%s` | %s | %s | %s | %s |\n",
			strings.ToUpper(string(fn.Severity)),
			fn.RuleID, pkg, ver, fix, loc,
		)
	}
	fmt.Fprintf(f, "\n")

	return nil
}

// ── engage command ────────────────────────────────────────────────────────────

func engageCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "engage",
		Short: "Manage scan engagements",
	}
	cmd.AddCommand(engageListCmd(), engageStatusCmd())
	return cmd
}

func engageListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all past engagements",
		RunE: func(cmd *cobra.Command, args []string) error {
			entries, err := os.ReadDir("results")
			if err != nil || len(entries) == 0 {
				fmt.Println("No engagements found.")
				fmt.Println("Run: supplychain-kit run <engagement> --repo <url-or-path>")
				return nil
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "ENGAGEMENT\tDATE\tTOTAL\tCRITICAL\tHIGH\tMEDIUM\tLOW")
			fmt.Fprintln(w, "----------\t----\t-----\t--------\t----\t------\t---")
			found := false
			for _, e := range entries {
				if !e.IsDir() {
					continue
				}
				s := readEngagementSummary(filepath.Join("results", e.Name(), "summary.json"))
				if s.Timestamp == "" {
					continue
				}
				found = true
				date := s.Timestamp
				if len(date) >= 10 {
					date = date[:10]
				}
				fmt.Fprintf(w, "%s\t%s\t%d\t%d\t%d\t%d\t%d\n",
					e.Name(), date, s.Total,
					s.Severity["CRITICAL"], s.Severity["HIGH"],
					s.Severity["MEDIUM"], s.Severity["LOW"],
				)
			}
			if !found {
				fmt.Println("No engagements found.")
				fmt.Println("Run: supplychain-kit run <engagement> --repo <url-or-path>")
				return nil
			}
			return w.Flush()
		},
	}
}

func engageStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status <engagement>",
		Short: "Show details of a specific engagement",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			dir := filepath.Join("results", name)
			s := readEngagementSummary(filepath.Join(dir, "summary.json"))
			if s.Timestamp == "" {
				return fmt.Errorf("engagement %q not found\nRun: supplychain-kit run %s --repo <url-or-path>", name, name)
			}

			fmt.Printf("Engagement : %s\n", name)
			fmt.Printf("Repository : %s\n", s.Repo)
			fmt.Printf("Mode       : %s\n", s.Mode)
			fmt.Printf("Date       : %s\n", s.Timestamp)
			fmt.Printf("Total      : %d findings\n", s.Total)
			for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"} {
				if n := s.Severity[sev]; n > 0 {
					fmt.Printf("  %-10s: %d\n", sev, n)
				}
			}
			fmt.Printf("\nFiles:\n")
			for _, fname := range []string{"report.md", "findings.json", "findings.txt", "summary.json"} {
				p := filepath.Join(dir, fname)
				if _, err := os.Stat(p); err == nil {
					fmt.Printf("  ✓ %s\n", p)
				}
			}
			return nil
		},
	}
}

type engagementSummary struct {
	Timestamp string         `json:"timestamp"`
	Repo      string         `json:"repo"`
	Mode      string         `json:"mode"`
	Total     int            `json:"total"`
	Severity  map[string]int `json:"severity"`
}

func readEngagementSummary(path string) engagementSummary {
	var s engagementSummary
	raw, err := os.ReadFile(path)
	if err != nil {
		return s
	}
	_ = json.Unmarshal(raw, &s)
	return s
}

// deptrackCmd returns the top-level `deptrack` command with upload/status/sync subcommands.
func deptrackCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "deptrack",
		Short: "Interact with a Dependency-Track instance from the CLI",
	}
	cmd.AddCommand(deptrackUploadCmd(), deptrackStatusCmd(), deptrackSyncCmd())
	return cmd
}

func deptrackUploadCmd() *cobra.Command {
	var (
		dtURL      string
		dtAPIKey   string
		sbomFile   string
		projectID  string
		projectVer string
	)
	cmd := &cobra.Command{
		Use:   "upload",
		Short: "Upload an SBOM to Dependency-Track",
		Example: `  supplychain-kit deptrack upload --url https://dt.example.com --api-key $DT_KEY --sbom sbom.json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			raw, err := os.ReadFile(sbomFile)
			if err != nil {
				return fmt.Errorf("read sbom: %w", err)
			}
			client := deptrack.New(dtURL, dtAPIKey)
			uuid, err := client.EnsureProject(cmd.Context(), projectID, projectVer)
			if err != nil {
				return fmt.Errorf("deptrack ensure project: %w", err)
			}
			if err := client.UploadBOM(cmd.Context(), uuid, raw); err != nil {
				return fmt.Errorf("deptrack upload: %w", err)
			}
			fmt.Fprintf(os.Stderr, "  SBOM uploaded to project %s (uuid: %s)\n", projectID, uuid)
			return nil
		},
	}
	cmd.Flags().StringVar(&dtURL, "url", "", "Dependency-Track base URL (e.g. https://dt.example.com)")
	cmd.Flags().StringVar(&dtAPIKey, "api-key", "", "Dependency-Track API key")
	cmd.Flags().StringVar(&sbomFile, "sbom", "", "path to CycloneDX SBOM JSON file")
	cmd.Flags().StringVar(&projectID, "project", "", "project name in Dependency-Track")
	cmd.Flags().StringVar(&projectVer, "version", "latest", "project version")
	_ = cmd.MarkFlagRequired("url")
	_ = cmd.MarkFlagRequired("api-key")
	_ = cmd.MarkFlagRequired("sbom")
	_ = cmd.MarkFlagRequired("project")
	return cmd
}

func deptrackStatusCmd() *cobra.Command {
	var (
		dtURL     string
		dtAPIKey  string
		projectID string
	)
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Poll vulnerability findings for a project in Dependency-Track",
		Example: `  supplychain-kit deptrack status --url https://dt.example.com --api-key $DT_KEY --project myapp`,
		RunE: func(cmd *cobra.Command, args []string) error {
			client := deptrack.New(dtURL, dtAPIKey)
			uuid, err := client.EnsureProject(cmd.Context(), projectID, "")
			if err != nil {
				return fmt.Errorf("deptrack lookup: %w", err)
			}
			findings, err := client.GetFindings(cmd.Context(), uuid)
			if err != nil {
				return fmt.Errorf("deptrack findings: %w", err)
			}
			if len(findings) == 0 {
				fmt.Fprintln(os.Stderr, "  No findings from Dependency-Track.")
				return nil
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "COMPONENT\tVERSION\tCVE\tSEVERITY\tCVSSv3")
			for _, f := range findings {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%.1f\n",
					f.Component.Name, f.Component.Version,
					f.Vulnerability.VulnID, f.Vulnerability.Severity,
					f.Vulnerability.CVSSv3)
			}
			_ = tw.Flush()
			return nil
		},
	}
	cmd.Flags().StringVar(&dtURL, "url", "", "Dependency-Track base URL")
	cmd.Flags().StringVar(&dtAPIKey, "api-key", "", "Dependency-Track API key")
	cmd.Flags().StringVar(&projectID, "project", "", "project name in Dependency-Track")
	_ = cmd.MarkFlagRequired("url")
	_ = cmd.MarkFlagRequired("api-key")
	_ = cmd.MarkFlagRequired("project")
	return cmd
}

func deptrackSyncCmd() *cobra.Command {
	var (
		dtURL      string
		dtAPIKey   string
		projectID  string
		projectVer string
		repo       string
	)
	cmd := &cobra.Command{
		Use:   "sync",
		Short: "Generate SBOM for a repo and upload it to Dependency-Track in one step",
		Example: `  supplychain-kit deptrack sync --repo . --url https://dt.example.com --api-key $DT_KEY --project myapp`,
		RunE: func(cmd *cobra.Command, args []string) error {
			abs, err := filepath.Abs(repo)
			if err != nil {
				return fmt.Errorf("resolve path: %w", err)
			}
			// Step 1: generate SBOM via syft.
			syftScanner := syftadapter.New()
			reg := scanner.NewRegistry(syftScanner)
			asset := &models.Asset{ID: "local", Name: abs, Environment: models.EnvDev, Tier: 2}
			results, _ := reg.RunLocal(cmd.Context(), asset, abs)

			var sbomRaw []byte
			for _, r := range results {
				if p, ok := r.Result.Artifacts[scanner.ArtifactSBOMPath]; ok {
					sbomRaw, err = os.ReadFile(p)
					if err != nil {
						return fmt.Errorf("read sbom: %w", err)
					}
					break
				}
			}
			if sbomRaw == nil {
				return fmt.Errorf("syft did not produce an SBOM — is syft installed?")
			}

			// Step 2: upload to Dependency-Track.
			client := deptrack.New(dtURL, dtAPIKey)
			uuid, err := client.EnsureProject(cmd.Context(), projectID, projectVer)
			if err != nil {
				return fmt.Errorf("deptrack ensure project: %w", err)
			}
			if err := client.UploadBOM(cmd.Context(), uuid, sbomRaw); err != nil {
				return fmt.Errorf("deptrack upload: %w", err)
			}
			fmt.Fprintf(os.Stderr, "  Synced SBOM for %s to Dependency-Track project %s\n", abs, projectID)
			return nil
		},
	}
	cmd.Flags().StringVar(&repo, "repo", ".", "local repository path")
	cmd.Flags().StringVar(&dtURL, "url", "", "Dependency-Track base URL")
	cmd.Flags().StringVar(&dtAPIKey, "api-key", "", "Dependency-Track API key")
	cmd.Flags().StringVar(&projectID, "project", "", "project name in Dependency-Track")
	cmd.Flags().StringVar(&projectVer, "version", "latest", "project version")
	_ = cmd.MarkFlagRequired("url")
	_ = cmd.MarkFlagRequired("api-key")
	_ = cmd.MarkFlagRequired("project")
	return cmd
}

// defectdojoCmd returns the `defectdojo` command with push subcommand.
func defectdojoCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "defectdojo",
		Short: "Push findings to a DefectDojo instance from the CLI",
	}
	cmd.AddCommand(defectdojoPushCmd())
	return cmd
}

func defectdojoPushCmd() *cobra.Command {
	var (
		djURL        string
		djAPIKey     string
		findingsFile string
		productID    int
		engagementID int
	)
	cmd := &cobra.Command{
		Use:   "push",
		Short: "Push findings JSON to DefectDojo",
		Example: `  supplychain-kit defectdojo push --url https://dojo.example.com --api-key $DJ_KEY --findings findings.json --product 1`,
		RunE: func(cmd *cobra.Command, args []string) error {
			findings, err := readFindings(findingsFile)
			if err != nil {
				return err
			}

			client := defectdojo.New(djURL, djAPIKey)

			// Use provided engagement ID or create a new one under the product.
			eid := engagementID
			if eid == 0 {
				if productID == 0 {
					return fmt.Errorf("provide --engagement-id or --product to create a new engagement")
				}
				eid, err = client.EnsureEngagement(cmd.Context(), productID, fmt.Sprintf("cli-%d", time.Now().Unix()))
				if err != nil {
					return fmt.Errorf("defectdojo engagement: %w", err)
				}
			}

			if err := client.PushFindings(cmd.Context(), eid, findings); err != nil {
				return fmt.Errorf("defectdojo push: %w", err)
			}
			fmt.Fprintf(os.Stderr, "  Pushed %d findings to DefectDojo engagement %d\n", len(findings), eid)
			return nil
		},
	}
	cmd.Flags().StringVar(&djURL, "url", "", "DefectDojo base URL (e.g. https://dojo.example.com)")
	cmd.Flags().StringVar(&djAPIKey, "api-key", "", "DefectDojo API token")
	cmd.Flags().StringVar(&findingsFile, "findings", "", "path to findings JSON file (- for stdin)")
	cmd.Flags().IntVar(&productID, "product", 0, "DefectDojo product ID (used when creating a new engagement)")
	cmd.Flags().IntVar(&engagementID, "engagement-id", 0, "existing DefectDojo engagement ID")
	_ = cmd.MarkFlagRequired("url")
	_ = cmd.MarkFlagRequired("api-key")
	_ = cmd.MarkFlagRequired("findings")
	return cmd
}

// ── mcp command ───────────────────────────────────────────────────────────────

func mcpCmd() *cobra.Command {
	var printConfig bool
	cmd := &cobra.Command{
		Use:   "mcp",
		Short: "Start the supplychain-kit MCP server (stdio transport)",
		Long: `Start supplychain-kit as an MCP server that Claude Code can call as tools.

The server communicates via stdin/stdout using JSON-RPC (MCP protocol).
Register it in Claude Code by adding the snippet from --print-config to
~/.claude/mcp.json (or the project-level .claude/mcp.json).

Tools exposed:
  init_engagement    Bootstrap a new scan engagement
  scan_repository    Run full SCA + SAST + reachability pipeline
  generate_sbom      Generate CycloneDX SBOM via syft
  run_gate           Evaluate findings against quality gate policy
  analyze_finding    AI-powered remediation via Claude API
  generate_report    Render Markdown (and optionally DOCX) report

Examples:
  supplychain-kit mcp                  # start server (Claude Code connects automatically)
  supplychain-kit mcp --print-config   # print mcp.json snippet`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if printConfig {
				kitmc.PrintConfig()
				return nil
			}
			return kitmc.Serve(cmd.Context())
		},
	}
	cmd.Flags().BoolVar(&printConfig, "print-config", false, "print ~/.claude/mcp.json registration snippet and exit")
	return cmd
}

// ── init command ──────────────────────────────────────────────────────────────

func initEngagementCmd() *cobra.Command {
	var (
		repo      string
		policy    string
		mode      string
		outputDir string
	)
	cmd := &cobra.Command{
		Use:   "init <engagement>",
		Short: "Bootstrap a new scan engagement (creates results/<engagement>/ structure)",
		Long: `Bootstrap a new scan engagement directory.

Creates:
  results/<engagement>/findings/
  results/<engagement>/sbom/
  results/<engagement>/reports/
  results/<engagement>/state.json   (tracks pipeline progress)

After init, run:
  supplychain-kit run <engagement> --repo <path>    # full pipeline
  /security-scan                                    # via Claude Code skill (agentic)

Examples:
  supplychain-kit init myapp-2026q1 --repo .
  supplychain-kit init myapp-2026q1 --repo https://github.com/org/repo --policy strict`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			engagement := args[0]
			if repo == "" {
				return fmt.Errorf("--repo required")
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

			engDir, err := resolveTargetDir(engagement)
			if err != nil {
				return err
			}
			for _, sub := range []string{"findings", "sbom", "reports"} {
				if err := os.MkdirAll(filepath.Join(engDir, sub), 0o755); err != nil {
					return fmt.Errorf("create %s: %w", sub, err)
				}
			}

			state := map[string]interface{}{
				"engagement": engagement,
				"repo":       repo,
				"policy":     policy,
				"mode":       mode,
				"output_dir": outputDir,
				"created_at": time.Now().UTC().Format(time.RFC3339),
				"phases": map[string]string{
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
				return fmt.Errorf("write state.json: %w", err)
			}

			fmt.Fprintf(os.Stderr, "\n── supplychain-kit init ──────────────────\n")
			fmt.Fprintf(os.Stderr, "  Engagement : %s\n", engagement)
			fmt.Fprintf(os.Stderr, "  Repository : %s\n", repo)
			fmt.Fprintf(os.Stderr, "  Policy     : %s\n", policy)
			fmt.Fprintf(os.Stderr, "  Mode       : %s\n", mode)
			fmt.Fprintf(os.Stderr, "  Output     : %s/\n", engDir)
			fmt.Fprintf(os.Stderr, "─────────────────────────────────────────\n\n")
			fmt.Fprintf(os.Stderr, "  Next: supplychain-kit run %s --repo %s\n\n", engagement, repo)
			return nil
		},
	}
	cmd.Flags().StringVar(&repo, "repo", "", "local path or remote git URL of the repository")
	cmd.Flags().StringVar(&policy, "policy", "moderate", "policy preset: strict | moderate | permissive")
	cmd.Flags().StringVar(&mode, "mode", "all", "scan mode: sca | sast | all")
	cmd.Flags().StringVar(&outputDir, "out", "results", "base output directory")
	_ = cmd.MarkFlagRequired("repo")
	return cmd
}

// ── analyze command ───────────────────────────────────────────────────────────

func analyzeCmd() *cobra.Command {
	var (
		findingsFile string
		engagement   string
		topN         int
		outFile      string
	)
	cmd := &cobra.Command{
		Use:   "analyze",
		Short: "AI-powered remediation analysis via Claude API (requires ANTHROPIC_API_KEY)",
		Long: `Send findings to the Claude API for structured remediation guidance.

For each finding, Claude produces:
  - Technical explanation of root cause and attack vector
  - Reachability-aware priority (fix-now | next-sprint | monitor)
  - Exact upgrade command for the affected package
  - Breaking change warning
  - Verification step after the fix
  - Advisory reference URL

Priority is driven by reachability:
  reachable / unknown   → fix-now
  unreachable + critical → next-sprint
  unreachable + ≤ high  → next-sprint
  low / info            → monitor

Requires ANTHROPIC_API_KEY environment variable.

Examples:
  supplychain-kit analyze --findings results/myapp/findings/findings.json --engagement myapp
  supplychain-kit analyze --findings results/myapp/findings/findings.json --engagement myapp --top 5 --out remediation.json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if !claudeai.Available() {
				return fmt.Errorf("ANTHROPIC_API_KEY not set — export ANTHROPIC_API_KEY=<your-key>")
			}

			findings, err := readFindings(findingsFile)
			if err != nil {
				return err
			}
			if len(findings) == 0 {
				fmt.Fprintln(os.Stderr, "  No findings to analyze.")
				return nil
			}

			// Prioritise: reachable CRITICAL first, then reachable HIGH, then UNKNOWN order.
			sortFindingsByPriority(findings)

			analyzer := claudeai.New()
			rems, errs := analyzer.AnalyzeBatch(cmd.Context(), engagement, findings, topN)

			fmt.Fprintf(os.Stderr, "\n── AI Remediation Analysis ──────────────\n")
			fmt.Fprintf(os.Stderr, "  Findings analyzed: %d\n\n", len(rems))

			var successRems []*claudeai.Remediation
			for i, rem := range rems {
				if errs[i] != nil {
					fmt.Fprintf(os.Stderr, "  [warn] %s: %v\n", findings[i].RuleID, errs[i])
					continue
				}
				successRems = append(successRems, rem)
				printRemediation(rem)
			}
			fmt.Fprintf(os.Stderr, "─────────────────────────────────────────\n\n")

			if outFile != "" {
				raw, _ := json.MarshalIndent(successRems, "", "  ")
				if err := os.WriteFile(outFile, raw, 0o644); err != nil {
					return fmt.Errorf("write output: %w", err)
				}
				fmt.Fprintf(os.Stderr, "  Remediation saved to %s\n", outFile)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&findingsFile, "findings", "", "path to findings JSON file")
	cmd.Flags().StringVar(&engagement, "engagement", "", "engagement name (used for context in prompts)")
	cmd.Flags().IntVar(&topN, "top", 10, "analyse top N findings by priority (0 = all)")
	cmd.Flags().StringVar(&outFile, "out", "", "write remediation JSON to file")
	_ = cmd.MarkFlagRequired("findings")
	return cmd
}

func printRemediation(r *claudeai.Remediation) {
	fmt.Fprintf(os.Stderr, "  [%s] %s\n", r.Severity, r.RuleID)
	fmt.Fprintf(os.Stderr, "    Priority     : %s\n", r.Priority)
	fmt.Fprintf(os.Stderr, "    Reachability : %s\n", r.Reachability)
	fmt.Fprintf(os.Stderr, "    Explanation  : %s\n", r.Explanation)
	if r.UpgradeCommand != "" {
		fmt.Fprintf(os.Stderr, "    Fix          : %s\n", r.UpgradeCommand)
	}
	if r.BreakingChanges != "" && r.BreakingChanges != "none" {
		fmt.Fprintf(os.Stderr, "    Breaking     : %s\n", r.BreakingChanges)
	}
	if r.VerifyStep != "" {
		fmt.Fprintf(os.Stderr, "    Verify       : %s\n", r.VerifyStep)
	}
	fmt.Fprintln(os.Stderr)
}

// ── report command ────────────────────────────────────────────────────────────

func reportCmd() *cobra.Command {
	var (
		engagement   string
		format       string
		remFile      string
		tmplPath     string
	)
	cmd := &cobra.Command{
		Use:   "report",
		Short: "Generate Markdown (and optionally DOCX) security report for an engagement",
		Long: `Render all findings for an engagement into a structured security report.

Reads:
  results/<engagement>/findings/findings.json   — required
  results/<engagement>/remediation.json         — optional AI remediation overlay

Writes:
  results/<engagement>/reports/report.md        — always
  results/<engagement>/reports/report.docx      — when --format docx|all (requires pandoc)

Uses configs/report-templates/finding.md.tmpl for per-finding sections.
Optionally provide --template to override the built-in template.

Examples:
  supplychain-kit report --engagement myapp-2026q1
  supplychain-kit report --engagement myapp-2026q1 --format docx
  supplychain-kit report --engagement myapp-2026q1 --format all --remediation remediation.json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if engagement == "" {
				return fmt.Errorf("--engagement required")
			}
			if format == "" {
				format = "markdown"
			}

			findingsPath := filepath.Join("results", engagement, "findings", "findings.json")
			findings, err := readFindings(findingsPath)
			if err != nil {
				return fmt.Errorf("read findings: %w — run scan first", err)
			}

			// Optional AI remediation overlay.
			remByID := map[string]*claudeai.Remediation{}
			if remFile != "" {
				raw, err := os.ReadFile(remFile)
				if err != nil {
					return fmt.Errorf("read remediation: %w", err)
				}
				var rems []*claudeai.Remediation
				if err := json.Unmarshal(raw, &rems); err != nil {
					return fmt.Errorf("parse remediation: %w", err)
				}
				for _, r := range rems {
					if r != nil {
						remByID[r.FindingID] = r
					}
				}
			} else {
				// Auto-load from default path if it exists.
				defaultRem := filepath.Join("results", engagement, "remediation.json")
				if raw, err := os.ReadFile(defaultRem); err == nil {
					var rems []*claudeai.Remediation
					if json.Unmarshal(raw, &rems) == nil {
						for _, r := range rems {
							if r != nil {
								remByID[r.FindingID] = r
							}
						}
					}
				}
			}

			// Load finding template.
			if tmplPath == "" {
				tmplPath = filepath.Join("configs", "report-templates", "finding.md.tmpl")
			}

			reportDir := filepath.Join("results", engagement, "reports")
			_ = os.MkdirAll(reportDir, 0o755)

			mdPath := filepath.Join(reportDir, "report.md")
			if err := renderMarkdownReport(mdPath, engagement, findings, remByID, tmplPath); err != nil {
				return fmt.Errorf("render markdown: %w", err)
			}
			fmt.Fprintf(os.Stderr, "  report.md → %s\n", mdPath)

			if format == "docx" || format == "all" {
				docxPath := filepath.Join(reportDir, "report.docx")
				if err := runPandoc(mdPath, docxPath); err != nil {
					fmt.Fprintf(os.Stderr, "  [warn] DOCX skipped: %v\n", err)
				} else {
					fmt.Fprintf(os.Stderr, "  report.docx → %s\n", docxPath)
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&engagement, "engagement", "", "engagement name (results/<engagement>/)")
	cmd.Flags().StringVar(&format, "format", "markdown", "output format: markdown | docx | all")
	cmd.Flags().StringVar(&remFile, "remediation", "", "path to AI remediation JSON (default: results/<engagement>/remediation.json)")
	cmd.Flags().StringVar(&tmplPath, "template", "", "override finding template (default: configs/report-templates/finding.md.tmpl)")
	_ = cmd.MarkFlagRequired("engagement")
	return cmd
}

// findingTemplateData is the data passed to the finding.md.tmpl template.
type findingTemplateData struct {
	Index           int
	ID              string
	RuleID          string
	Severity        string
	Package         string
	Version         string
	FixedVersion    string
	CVSS            float64
	Reachability    string
	RiskScore       float64
	Location        string
	Description     string
	AdvisoryURL     string
	ReachabilityNote string
	AIRemediation   *claudeai.Remediation
}

func renderMarkdownReport(path, engagement string, findings []*models.Finding, remByID map[string]*claudeai.Remediation, tmplPath string) error {
	// Load and parse the per-finding template.
	tmplSrc, err := os.ReadFile(tmplPath)
	if err != nil {
		return fmt.Errorf("read template %s: %w", tmplPath, err)
	}
	tmpl, err := template.New("finding").Parse(string(tmplSrc))
	if err != nil {
		return fmt.Errorf("parse template: %w", err)
	}

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

	fmt.Fprintf(f, "## Executive Summary\n\n")
	fmt.Fprintf(f, "Total findings: **%d**\n\n", len(findings))
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

	if len(remByID) > 0 {
		fmt.Fprintf(f, "> AI remediation guidance (Claude) is included for %d findings.\n\n", len(remByID))
	}

	fmt.Fprintf(f, "## Findings\n\n")
	if len(findings) == 0 {
		fmt.Fprintf(f, "No vulnerabilities found.\n")
		return nil
	}

	for i, fn := range findings {
		loc := fn.FilePath
		if loc == "" {
			loc = "—"
		} else if fn.Line > 0 {
			loc = fmt.Sprintf("%s:%d", loc, fn.Line)
		}
		data := findingTemplateData{
			Index:            i + 1,
			ID:               fn.ID,
			RuleID:           fn.RuleID,
			Severity:         strings.ToUpper(string(fn.Severity)),
			Package:          fn.Package,
			Version:          fn.Version,
			FixedVersion:     fn.FixedVersion,
			CVSS:             fn.CVSS,
			Reachability:     string(fn.Reachability),
			RiskScore:        fn.RiskScore,
			Location:         loc,
			Description:      fn.Description,
			AdvisoryURL:      fn.AdvisoryURL,
			ReachabilityNote: reachabilityNote(fn.Reachability),
			AIRemediation:    remByID[fn.ID],
		}
		if err := tmpl.Execute(f, data); err != nil {
			fmt.Fprintf(f, "\n<!-- template error for finding %s: %v -->\n\n", fn.ID, err)
		}
	}
	return nil
}

func reachabilityNote(r models.Reachability) string {
	switch r {
	case models.ReachReachable, models.ReachConfirmed:
		return "Confirmed reachable — highest priority"
	case models.ReachUnknown:
		return "Reachability unknown — treat as reachable"
	case models.ReachUnreachable:
		return "No reachable path detected — still patch at next sprint"
	default:
		return string(r)
	}
}

func runPandoc(mdPath, docxPath string) error {
	if _, err := exec.LookPath("pandoc"); err != nil {
		return fmt.Errorf("pandoc not found in PATH — install from https://pandoc.org")
	}
	out, err := exec.Command("pandoc", mdPath, "-o", docxPath, "--toc", "--highlight-style=tango").CombinedOutput()
	if err != nil {
		return fmt.Errorf("pandoc: %w\n%s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// sortFindingsByPriority sorts findings: reachable CRITICAL first, reachable HIGH,
// unknown CRITICAL, then remaining by severity desc.
func sortFindingsByPriority(findings []*models.Finding) {
	reachPriority := func(r models.Reachability) int {
		switch r {
		case models.ReachReachable, models.ReachConfirmed:
			return 0
		case models.ReachUnknown:
			return 1
		default:
			return 2
		}
	}
	sevPriority := func(s models.Severity) int {
		switch s {
		case models.SeverityCritical:
			return 0
		case models.SeverityHigh:
			return 1
		case models.SeverityMedium:
			return 2
		case models.SeverityLow:
			return 3
		default:
			return 4
		}
	}
	// Simple insertion sort — finding sets are typically small (<200).
	for i := 1; i < len(findings); i++ {
		for j := i; j > 0; j-- {
			a, b := findings[j-1], findings[j]
			ra, rb := reachPriority(a.Reachability), reachPriority(b.Reachability)
			sa, sb := sevPriority(a.Severity), sevPriority(b.Severity)
			if ra > rb || (ra == rb && sa > sb) {
				findings[j-1], findings[j] = findings[j], findings[j-1]
			} else {
				break
			}
		}
	}
}

// ── install-hooks command ─────────────────────────────────────────────────────

func installHooksCmd() *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "install-hooks",
		Short: "Install the supplychain-kit git pre-commit hook into .git/hooks/",
		Long: `Copy configs/hooks/pre-commit.sh into .git/hooks/pre-commit.

The hook runs a fast SCA-only scan before every commit and blocks the commit
if the quality gate fails.

To bypass in an emergency: git commit --no-verify

The Claude Code PostToolUse and Stop hooks are registered via .claude/settings.json
and take effect automatically when Claude Code loads the project.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			src := filepath.Join("configs", "hooks", "pre-commit.sh")
			if _, err := os.Stat(src); err != nil {
				return fmt.Errorf("hook script not found at %s — are you in the supplychain-kit root?", src)
			}

			gitHooksDir := filepath.Join(".git", "hooks")
			if _, err := os.Stat(gitHooksDir); err != nil {
				return fmt.Errorf(".git/hooks not found — run from the root of a git repository")
			}

			dst := filepath.Join(gitHooksDir, "pre-commit")
			if _, err := os.Stat(dst); err == nil && !force {
				return fmt.Errorf("pre-commit hook already exists at %s — use --force to overwrite", dst)
			}

			raw, err := os.ReadFile(src)
			if err != nil {
				return fmt.Errorf("read hook script: %w", err)
			}
			if err := os.WriteFile(dst, raw, 0o755); err != nil {
				return fmt.Errorf("write hook: %w", err)
			}

			fmt.Fprintf(os.Stderr, "  Installed: %s\n", dst)
			fmt.Fprintf(os.Stderr, "  The hook runs 'supplychain-kit gate' before every commit.\n")
			fmt.Fprintf(os.Stderr, "  Bypass: git commit --no-verify\n")
			return nil
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "overwrite existing pre-commit hook")
	return cmd
}
