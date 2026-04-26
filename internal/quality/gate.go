// Package quality implements the deterministic Quality Gate evaluator
// invoked by CI to decide whether a pipeline should pass, warn, or fail.
package quality

import (
	"fmt"
	"strings"

	"github.com/penanamtomat/supplychain-kit/internal/config"
	"github.com/penanamtomat/supplychain-kit/internal/models"
)

// Decision is the outcome of a gate evaluation.
type Decision string

const (
	DecisionPass Decision = "pass"
	DecisionWarn Decision = "warn"
	DecisionFail Decision = "fail"
)

// Result includes the categorical decision plus the violating findings so the
// CI integration can render a useful failure log.
type Result struct {
	Decision   Decision           `json:"decision"`
	Violations []ViolatingFinding `json:"violations,omitempty"`
	Warnings   []ViolatingFinding `json:"warnings,omitempty"`
	Summary    string             `json:"summary"`
}

// ViolatingFinding is a finding paired with the rule it tripped.
type ViolatingFinding struct {
	Finding *models.Finding `json:"finding"`
	Rule    string          `json:"rule"`
}

// Evaluator applies a configured policy.
type Evaluator struct {
	policy config.QualityGateConfig
}

// New returns a Evaluator bound to the supplied policy.
func New(policy config.QualityGateConfig) *Evaluator {
	return &Evaluator{policy: policy}
}

// Evaluate runs the policy against findings and returns a deterministic Result.
func (e *Evaluator) Evaluate(findings []*models.Finding) Result {
	var fail, warn []ViolatingFinding

	for _, f := range findings {
		for _, rule := range e.policy.FailOn {
			if matches(f, rule) {
				fail = append(fail, ViolatingFinding{Finding: f, Rule: ruleString(rule)})
			}
		}
		for _, rule := range e.policy.WarnOn {
			if matches(f, rule) {
				warn = append(warn, ViolatingFinding{Finding: f, Rule: ruleString(rule)})
			}
		}
	}

	// MaxCount semantics: a fail rule with MaxCount > 0 only trips when the
	// count of *matching findings* exceeds MaxCount.
	fail = filterByMaxCount(fail, e.policy.FailOn)

	switch {
	case len(fail) > 0:
		return Result{
			Decision:   DecisionFail,
			Violations: fail,
			Warnings:   warn,
			Summary:    fmt.Sprintf("%d finding(s) violate fail policy", len(fail)),
		}
	case len(warn) > 0:
		return Result{
			Decision: DecisionWarn,
			Warnings: warn,
			Summary:  fmt.Sprintf("%d finding(s) trigger warn policy", len(warn)),
		}
	default:
		return Result{Decision: DecisionPass, Summary: "no policy violations"}
	}
}

func matches(f *models.Finding, rule config.GateRule) bool {
	if rule.Severity != "" && !strings.EqualFold(string(f.Severity), rule.Severity) {
		return false
	}
	if rule.Reachable != nil {
		isReachable := f.Reachability == models.ReachReachable
		if isReachable != *rule.Reachable {
			return false
		}
	}
	return true
}

func ruleString(r config.GateRule) string {
	parts := []string{"severity=" + r.Severity}
	if r.Reachable != nil {
		parts = append(parts, fmt.Sprintf("reachable=%v", *r.Reachable))
	}
	if r.MaxCount > 0 {
		parts = append(parts, fmt.Sprintf("max_count=%d", r.MaxCount))
	}
	return strings.Join(parts, ",")
}

func filterByMaxCount(violations []ViolatingFinding, rules []config.GateRule) []ViolatingFinding {
	if len(violations) == 0 {
		return violations
	}
	counts := map[string]int{}
	for _, v := range violations {
		counts[v.Rule]++
	}
	limits := map[string]int{}
	for _, r := range rules {
		if r.MaxCount > 0 {
			limits[ruleString(r)] = r.MaxCount
		}
	}
	if len(limits) == 0 {
		return violations
	}
	out := violations[:0]
	for _, v := range violations {
		if limit, ok := limits[v.Rule]; ok && counts[v.Rule] <= limit {
			continue
		}
		out = append(out, v)
	}
	return out
}
