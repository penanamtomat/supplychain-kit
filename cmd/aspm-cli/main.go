// Command aspm-cli is the operator CLI for local scans, quality gate checks,
// and one-shot scan submission. It is intended to be the integration point
// for CI pipelines.
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
	root := &cobra.Command{Use: "aspm-cli", Short: "ASPM operator CLI"}
	root.AddCommand(scanCmd(), gateCmd(), submitCmd(), sbomCmd())
	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func scanCmd() *cobra.Command {
	var (
		repo   string
		ref    string
		out    string
		mode   string
		format string
		target string
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

			reg := buildRegistry(mode)
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
				targetDir := resolveTargetDir(target)
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
	return cmd
}

// resolveTargetDir returns the absolute path to results/<target>.
func resolveTargetDir(target string) string {
	if target == "" {
		return "results"
	}
	return filepath.Join("results", target)
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
	fmt.Fprintln(tw, "SEVERITY\tRULE / CVE\tPACKAGE\tFIX\tFILE")
	fmt.Fprintln(tw, "--------\t----------\t-------\t---\t----")
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
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			strings.ToUpper(string(f.Severity)),
			f.RuleID, pkg, fix, loc,
		)
	}
	tw.Flush()
}

// buildRegistry returns a Registry populated according to the requested mode.
func buildRegistry(mode string) *scanner.Registry {
	switch mode {
	case "sca":
		return scanner.NewRegistry(syftadapter.New(), grype.New())
	case "sast":
		return scanner.NewRegistry(semgrep.New(), gitleaks.New())
	default:
		return scanner.NewRegistry(
			syftadapter.New(), grype.New(),
			semgrep.New(), gitleaks.New(),
			joern.New(),
		)
	}
}

// printSummary writes a one-line count per severity to stderr.
func printSummary(findings []*models.Finding) {
	counts := map[models.Severity]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}
	total := len(findings)
	fmt.Fprintf(os.Stderr, "\n── Scan Summary ─────────────────────────\n")
	fmt.Fprintf(os.Stderr, "  Total findings : %d\n", total)
	for _, sev := range []models.Severity{
		models.SeverityCritical, models.SeverityHigh,
		models.SeverityMedium, models.SeverityLow, models.SeverityInfo,
	} {
		if n := counts[sev]; n > 0 {
			fmt.Fprintf(os.Stderr, "  %-10s : %d\n", strings.ToUpper(string(sev)), n)
		}
	}
	fmt.Fprintf(os.Stderr, "─────────────────────────────────────────\n")
}

// printTable writes a human-readable table of findings to stdout.
func printTable(findings []*models.Finding) error {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "SEVERITY\tRULE / CVE\tPACKAGE\tFIX\tFILE")
	fmt.Fprintln(w, "--------\t----------\t-------\t---\t----")
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
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			strings.ToUpper(string(f.Severity)),
			f.RuleID, pkg, fix, loc,
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
			_ = json.NewEncoder(os.Stdout).Encode(result)
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
		target string
	)
	cmd := &cobra.Command{
		Use:   "sbom",
		Short: "Generate a CycloneDX 1.5 SBOM for a repository",
		RunE: func(cmd *cobra.Command, args []string) error {
			if repo == "" {
				return fmt.Errorf("--repo required")
			}
			reg := scanner.NewRegistry(syftadapter.New())
			asset := &models.Asset{ID: "local", Name: repo, Environment: models.EnvDev, Tier: 2}

			var results []scanner.ScannedResult
			if isLocalPath(repo) {
				abs, err := filepath.Abs(repo)
				if err != nil {
					return fmt.Errorf("resolve path: %w", err)
				}
				results, _ = reg.RunLocal(cmd.Context(), asset, abs)
			} else {
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
						targetDir := resolveTargetDir(target)
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
