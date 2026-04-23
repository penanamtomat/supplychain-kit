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
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/penanamtomat/supplychain-kit/internal/config"
	"github.com/penanamtomat/supplychain-kit/internal/correlation"
	"github.com/penanamtomat/supplychain-kit/internal/models"
	"github.com/penanamtomat/supplychain-kit/internal/quality"
	"github.com/penanamtomat/supplychain-kit/internal/scanner"
	"github.com/penanamtomat/supplychain-kit/internal/scanner/gitleaks"
	"github.com/penanamtomat/supplychain-kit/internal/scanner/grype"
	"github.com/penanamtomat/supplychain-kit/internal/scanner/joern"
	"github.com/penanamtomat/supplychain-kit/internal/scanner/semgrep"
	syftadapter "github.com/penanamtomat/supplychain-kit/internal/scanner/syft"
	"github.com/penanamtomat/supplychain-kit/internal/scoring"
)

func main() {
	root := &cobra.Command{
		Use:   "supplychain-kit",
		Short: "Supply chain security scanner — SCA, SAST, secrets, quality gate, and report in one tool",
	}
	root.AddCommand(runCmd(), scanCmd(), gateCmd(), sbomCmd(), engageCmd(), submitCmd())
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
			var cleanup func()

			if isLocalPath(repo) {
				abs, err := filepath.Abs(repo)
				if err != nil {
					return fmt.Errorf("resolve path: %w", err)
				}
				asset.Name = abs
				var artifacts map[string]string
				results, artifacts = reg.RunLocal(cmd.Context(), asset, abs)
				_ = artifacts
				cleanup = func() {}
			} else {
				asset.RepoURL = repo
				var artifacts map[string]string
				var err error
				results, artifacts, cleanup, err = reg.RunPipeline(cmd.Context(), asset, ref)
				_ = artifacts
				if err != nil {
					return err
				}
			}
			defer cleanup()

			merged := correlation.Merge(results)
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
		return scanner.NewRegistry(syftadapter.New(), grype.New())
	case "sast":
		return scanner.NewRegistry(sg, gl)
	default:
		return scanner.NewRegistry(
			syftadapter.New(), grype.New(),
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

Examples:
  supplychain-kit run myapp-2026q1 --repo https://github.com/org/repo
  supplychain-kit run myapp-2026q1 --repo /path/to/project --mode sca
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
			var cleanup func()

			if isLocalPath(repo) {
				abs, err := filepath.Abs(repo)
				if err != nil {
					return fmt.Errorf("resolve path: %w", err)
				}
				asset.Name = abs
				results, _ = reg.RunLocal(cmd.Context(), asset, abs)
				cleanup = func() {}
			} else {
				asset.RepoURL = repo
				var artifacts map[string]string
				var err error
				results, artifacts, cleanup, err = reg.RunPipeline(cmd.Context(), asset, ref)
				_ = artifacts
				if err != nil {
					return err
				}
			}
			defer cleanup()

			merged := correlation.Merge(results)
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

			// Step 6: print results
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
