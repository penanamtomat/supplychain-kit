// Package report contains integration-level tests for the report rendering
// pipeline (template loading, markdown generation, AI overlay).
package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"text/template"

	"github.com/penanamtomat/supplychain-kit/internal/claudeai"
	"github.com/penanamtomat/supplychain-kit/internal/models"
)

const findingTemplate = `### [{{.Index}}] [{{.Severity}}] {{.RuleID}}
Package: {{.Package}} {{.Version}}
Risk: {{printf "%.2f" .RiskScore}}
{{- if .AIRemediation}}
Priority: {{.AIRemediation.Priority}}
{{- end}}
---
`

func TestFindingTemplate_BasicRendering(t *testing.T) {
	tmpl, err := template.New("finding").Parse(findingTemplate)
	if err != nil {
		t.Fatalf("parse template: %v", err)
	}

	data := struct {
		Index         int
		Severity      string
		RuleID        string
		Package       string
		Version       string
		RiskScore     float64
		AIRemediation *claudeai.Remediation
	}{
		Index:     1,
		Severity:  "CRITICAL",
		RuleID:    "CVE-2021-44228",
		Package:   "log4j-core",
		Version:   "2.14.1",
		RiskScore: 10.0,
	}

	var buf strings.Builder
	if err := tmpl.Execute(&buf, data); err != nil {
		t.Fatalf("execute template: %v", err)
	}

	out := buf.String()
	for _, want := range []string{"CVE-2021-44228", "log4j-core", "2.14.1", "10.00", "CRITICAL"} {
		if !strings.Contains(out, want) {
			t.Errorf("template output missing %q\nout: %s", want, out)
		}
	}
}

func TestFindingTemplate_AIRemediationBlock(t *testing.T) {
	tmpl, err := template.New("finding").Parse(findingTemplate)
	if err != nil {
		t.Fatalf("parse template: %v", err)
	}

	data := struct {
		Index         int
		Severity      string
		RuleID        string
		Package       string
		Version       string
		RiskScore     float64
		AIRemediation *claudeai.Remediation
	}{
		Index:    1,
		Severity: "HIGH",
		RuleID:   "CVE-2023-0001",
		Package:  "lodash",
		Version:  "4.17.20",
		AIRemediation: &claudeai.Remediation{
			Priority:    "fix-now",
			Explanation: "Prototype pollution allows arbitrary code execution.",
		},
	}

	var buf strings.Builder
	if err := tmpl.Execute(&buf, data); err != nil {
		t.Fatalf("execute template: %v", err)
	}

	if !strings.Contains(buf.String(), "fix-now") {
		t.Errorf("AI remediation priority not rendered; got: %s", buf.String())
	}
}

func TestFindingTemplateFile_LoadsAndRenders(t *testing.T) {
	// Locate configs/report-templates/finding.md.tmpl relative to project root.
	tmplPath := findProjectFile(t, filepath.Join("configs", "report-templates", "finding.md.tmpl"))

	raw, err := os.ReadFile(tmplPath)
	if err != nil {
		t.Skipf("template file not found at %s: %v", tmplPath, err)
	}

	tmpl, err := template.New("finding").Parse(string(raw))
	if err != nil {
		t.Fatalf("parse project template: %v", err)
	}

	type templateData struct {
		Index            int
		ID               string
		RuleID           string
		Severity         string
		Package          string
		Version          string
		FixedVersion     string
		CVSS             float64
		Reachability     string
		RiskScore        float64
		Location         string
		Description      string
		AdvisoryURL      string
		ReachabilityNote string
		AIRemediation    *claudeai.Remediation
	}

	data := templateData{
		Index:            1,
		ID:               "f-001",
		RuleID:           "CVE-2021-44228",
		Severity:         "CRITICAL",
		Package:          "log4j-core",
		Version:          "2.14.1",
		FixedVersion:     "2.15.0",
		CVSS:             10.0,
		Reachability:     string(models.ReachReachable),
		RiskScore:        10.0,
		Location:         "src/main/App.java:42",
		ReachabilityNote: "Confirmed reachable — highest priority",
	}

	var buf strings.Builder
	if err := tmpl.Execute(&buf, data); err != nil {
		t.Fatalf("execute project template: %v", err)
	}

	for _, want := range []string{"CVE-2021-44228", "log4j-core", "2.15.0", "10.0", "CRITICAL"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("rendered output missing %q", want)
		}
	}
}

// findProjectFile walks up from the test binary location to find the project root.
func findProjectFile(t *testing.T, rel string) string {
	t.Helper()
	dir, _ := os.Getwd()
	for {
		candidate := filepath.Join(dir, rel)
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return rel
}
