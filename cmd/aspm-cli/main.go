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

	"github.com/spf13/cobra"

	"github.com/penanamtomat/supplychain-kit/internal/config"
	"github.com/penanamtomat/supplychain-kit/internal/correlation"
	"github.com/penanamtomat/supplychain-kit/internal/models"
	"github.com/penanamtomat/supplychain-kit/internal/quality"
	"github.com/penanamtomat/supplychain-kit/internal/scanner"
	"github.com/penanamtomat/supplychain-kit/internal/scanner/gitleaks"
	"github.com/penanamtomat/supplychain-kit/internal/scanner/grype"
	"github.com/penanamtomat/supplychain-kit/internal/scanner/semgrep"
	syftadapter "github.com/penanamtomat/supplychain-kit/internal/scanner/syft"
	"github.com/penanamtomat/supplychain-kit/internal/scoring"
)

func main() {
	root := &cobra.Command{Use: "aspm-cli", Short: "ASPM operator CLI"}
	root.AddCommand(scanCmd(), gateCmd(), submitCmd())
	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func scanCmd() *cobra.Command {
	var (
		repo string
		ref  string
		out  string
	)
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Run a local end-to-end scan and emit normalized findings",
		RunE: func(cmd *cobra.Command, args []string) error {
			if repo == "" {
				return fmt.Errorf("--repo required")
			}
			asset := &models.Asset{
				ID: "local", Name: "local", RepoURL: repo,
				Environment: models.EnvDev, Tier: 2,
			}

			reg := scanner.NewRegistry(syftadapter.New(), grype.New(), semgrep.New(), gitleaks.New())
			results, _, cleanup, err := reg.RunPipeline(cmd.Context(), asset, ref)
			if err != nil {
				return err
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
			return writeFindings(out, merged)
		},
	}
	cmd.Flags().StringVar(&repo, "repo", "", "git repository URL")
	cmd.Flags().StringVar(&ref, "ref", "HEAD", "git ref")
	cmd.Flags().StringVar(&out, "out", "-", "output file (- for stdout)")
	return cmd
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
	cmd.Flags().StringVar(&policyFile, "policy", "", "policy file (defaults to configs/aspm.yaml)")
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
			defer resp.Body.Close()
			fmt.Println(resp.Status)
			return nil
		},
	}
	cmd.Flags().StringVar(&repo, "repo", "", "git repository URL")
	cmd.Flags().StringVar(&api, "api", "http://localhost:8080", "aspm-api base URL")
	return cmd
}

func writeFindings(path string, fs []*models.Finding) error {
	w := os.Stdout
	if path != "" && path != "-" {
		f, err := os.Create(path)
		if err != nil {
			return err
		}
		defer f.Close()
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
		defer f.Close()
		r = f
	}
	var out []*models.Finding
	if err := json.NewDecoder(r).Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}
