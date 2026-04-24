// Package claudeai integrates the Anthropic Claude API for AI-powered finding analysis.
//
// DEPRECATED: This package is superseded by internal/remediation (template-based analysis).
// Kept for backward compatibility. Use internal/remediation for new development.
//
// Requires ANTHROPIC_API_KEY environment variable. Gracefully skipped if absent.
package claudeai

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"

	"github.com/penanamtomat/supplychain-kit/internal/models"
)

const (
	analysisModel = anthropic.ModelClaudeHaiku4_5
	maxTokens     = int64(1024)
)

// Remediation is the structured AI analysis output for a single finding.
type Remediation struct {
	FindingID       string `json:"finding_id"`
	RuleID          string `json:"rule_id"`
	Severity        string `json:"severity"`
	Reachability    string `json:"reachability"`
	Priority        string `json:"priority"`         // "fix-now" | "next-sprint" | "monitor"
	Explanation     string `json:"explanation"`      // technical root-cause explanation
	UpgradeCommand  string `json:"upgrade_command"`  // exact package manager command
	BreakingChanges string `json:"breaking_changes"` // "none" or description
	VerifyStep      string `json:"verify_step"`      // command to verify after fix
	References      string `json:"references"`       // advisory URLs
}

// Analyzer sends findings to the Claude API for structured remediation.
type Analyzer struct {
	client *anthropic.Client
}

// New returns an Analyzer. Returns nil if ANTHROPIC_API_KEY is not set.
func New() *Analyzer {
	key := os.Getenv("ANTHROPIC_API_KEY")
	if key == "" {
		return nil
	}
	c := anthropic.NewClient(option.WithAPIKey(key))
	return &Analyzer{client: &c}
}

// Available reports whether the Claude API key is configured.
func Available() bool {
	return os.Getenv("ANTHROPIC_API_KEY") != ""
}

// Analyze sends a single finding to Claude and returns structured remediation.
func (a *Analyzer) Analyze(ctx context.Context, engagement string, f *models.Finding) (*Remediation, error) {
	if a == nil {
		return nil, fmt.Errorf("ANTHROPIC_API_KEY not set")
	}

	msg, err := a.client.Messages.New(ctx, anthropic.MessageNewParams{
		Model:     analysisModel,
		MaxTokens: maxTokens,
		System: []anthropic.TextBlockParam{
			{Text: systemPrompt()},
		},
		Messages: []anthropic.MessageParam{
			anthropic.NewUserMessage(anthropic.NewTextBlock(buildPrompt(engagement, f))),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("claude api: %w", err)
	}

	raw := extractText(msg)
	return parseRemediationResponse(f, raw)
}

// AnalyzeBatch sends multiple findings to Claude concurrently (up to topN).
func (a *Analyzer) AnalyzeBatch(ctx context.Context, engagement string, findings []*models.Finding, topN int) ([]*Remediation, []error) {
	if a == nil {
		return nil, []error{fmt.Errorf("ANTHROPIC_API_KEY not set")}
	}
	if topN > 0 && len(findings) > topN {
		findings = findings[:topN]
	}

	type result struct {
		rem *Remediation
		err error
		idx int
	}
	ch := make(chan result, len(findings))
	for i, f := range findings {
		go func(i int, f *models.Finding) {
			rem, err := a.Analyze(ctx, engagement, f)
			ch <- result{rem: rem, err: err, idx: i}
		}(i, f)
	}

	rems := make([]*Remediation, len(findings))
	errs := make([]error, len(findings))
	for range findings {
		r := <-ch
		rems[r.idx] = r.rem
		errs[r.idx] = r.err
	}
	return rems, errs
}

// ── prompt construction ───────────────────────────────────────────────────────

func systemPrompt() string {
	return `You are a supply chain security expert. You analyse CVEs and SAST findings and produce actionable, technically precise remediation guidance for engineers.

Respond ONLY with a valid JSON object matching this schema — no markdown, no explanation outside the JSON:
{
  "priority": "fix-now" | "next-sprint" | "monitor",
  "explanation": "<2-3 sentences: root cause, attack vector, why dangerous>",
  "upgrade_command": "<exact package manager command, e.g. npm install pkg@1.2.3>",
  "breaking_changes": "none" | "<concise description of breaking changes>",
  "verify_step": "<command to run after upgrade to confirm fix>",
  "references": "<advisory URL or NVD link>"
}

Priority rules:
- reachable=reachable or reachable=runtime_confirmed → always "fix-now"
- reachable=unknown → treat as reachable → "fix-now"
- reachable=unreachable AND severity=critical → "next-sprint"
- reachable=unreachable AND severity<=high → "next-sprint"
- severity=low or info → "monitor"

Be precise. No filler text. Engineers reading this already know what a CVE is.`
}

func buildPrompt(engagement string, f *models.Finding) string {
	b := &strings.Builder{}
	fmt.Fprintf(b, "Engagement: %s\n", engagement)
	fmt.Fprintf(b, "Finding ID: %s\n", f.ID)
	fmt.Fprintf(b, "CVE/Rule: %s\n", f.RuleID)
	fmt.Fprintf(b, "Severity: %s\n", strings.ToUpper(string(f.Severity)))
	fmt.Fprintf(b, "Package: %s %s\n", f.Package, f.Version)
	if f.FixedVersion != "" {
		fmt.Fprintf(b, "Fixed in: %s\n", f.FixedVersion)
	}
	fmt.Fprintf(b, "Reachability: %s\n", f.Reachability)
	if f.FilePath != "" {
		fmt.Fprintf(b, "Location: %s", f.FilePath)
		if f.Line > 0 {
			fmt.Fprintf(b, ":%d", f.Line)
		}
		fmt.Fprint(b, "\n")
	}
	if f.CVSS > 0 {
		fmt.Fprintf(b, "CVSS: %.1f\n", f.CVSS)
	}
	if f.AdvisoryURL != "" {
		fmt.Fprintf(b, "Advisory: %s\n", f.AdvisoryURL)
	}
	if f.Description != "" {
		fmt.Fprintf(b, "Description: %s\n", f.Description)
	}
	fmt.Fprintf(b, "\nProvide remediation JSON.")
	return b.String()
}

// ── response parsing ──────────────────────────────────────────────────────────

func extractText(msg *anthropic.Message) string {
	for _, block := range msg.Content {
		if block.Type == "text" {
			return block.Text
		}
	}
	return ""
}

func parseRemediationResponse(f *models.Finding, raw string) (*Remediation, error) {
	raw = strings.TrimSpace(raw)
	// Strip markdown code fences if present despite instructions.
	if strings.HasPrefix(raw, "```") {
		raw = strings.TrimPrefix(raw, "```json")
		raw = strings.TrimPrefix(raw, "```")
		if idx := strings.LastIndex(raw, "```"); idx >= 0 {
			raw = raw[:idx]
		}
		raw = strings.TrimSpace(raw)
	}

	var parsed struct {
		Priority        string `json:"priority"`
		Explanation     string `json:"explanation"`
		UpgradeCommand  string `json:"upgrade_command"`
		BreakingChanges string `json:"breaking_changes"`
		VerifyStep      string `json:"verify_step"`
		References      string `json:"references"`
	}
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		return nil, fmt.Errorf("parse claude response: %w (raw: %.200s)", err, raw)
	}

	return &Remediation{
		FindingID:       f.ID,
		RuleID:          f.RuleID,
		Severity:        strings.ToUpper(string(f.Severity)),
		Reachability:    string(f.Reachability),
		Priority:        parsed.Priority,
		Explanation:     parsed.Explanation,
		UpgradeCommand:  parsed.UpgradeCommand,
		BreakingChanges: parsed.BreakingChanges,
		VerifyStep:      parsed.VerifyStep,
		References:      parsed.References,
	}, nil
}
