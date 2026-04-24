// Package remediation provides template-based finding analysis without requiring AI APIs.
// This reduces token usage and eliminates external dependencies for remediation guidance.
package remediation

import (
	"fmt"
	"strings"

	"github.com/penanamtomat/supplychain-kit/internal/models"
)

// Remediation is the structured analysis output for a single finding.
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

// Engine generates remediation guidance using rule-based templates.
type Engine struct{}

// New creates a new remediation engine.
func New() *Engine {
	return &Engine{}
}

// Analyze generates remediation guidance for a single finding.
func (e *Engine) Analyze(f *models.Finding) *Remediation {
	if f == nil {
		return nil
	}

	priority := e.determinePriority(f)
	explanation := e.generateExplanation(f)
	upgradeCmd := e.generateUpgradeCommand(f)
	breaking := e.assessBreakingChanges(f)
	verify := e.generateVerifyStep(f)
	references := e.generateReferences(f)

	return &Remediation{
		FindingID:       f.ID,
		RuleID:          f.RuleID,
		Severity:        string(f.Severity),
		Reachability:    string(f.Reachability),
		Priority:        priority,
		Explanation:     explanation,
		UpgradeCommand:  upgradeCmd,
		BreakingChanges: breaking,
		VerifyStep:      verify,
		References:      references,
	}
}

// AnalyzeBatch generates remediation for multiple findings.
func (e *Engine) AnalyzeBatch(findings []*models.Finding) []*Remediation {
	rems := make([]*Remediation, 0, len(findings))
	for _, f := range findings {
		if r := e.Analyze(f); r != nil {
			rems = append(rems, r)
		}
	}
	return rems
}

// determinePriority assigns priority based on severity and reachability.
func (e *Engine) determinePriority(f *models.Finding) string {
	// Priority rules (matching the original Claude prompt):
	// - severity=low or info → "monitor" (checked first)
	// - reachable=reachable or reachable=runtime_confirmed → always "fix-now"
	// - reachable=unknown → treat as reachable → "fix-now"
	// - reachable=unreachable AND severity=critical → "fix-now"
	// - reachable=unreachable AND severity<=high → "next-sprint"

	// Check low severity first
	if f.Severity == models.SeverityLow || f.Severity == models.SeverityInfo {
		return "monitor"
	}

	switch f.Reachability {
	case models.ReachReachable, models.ReachConfirmed, models.ReachUnknown:
		return "fix-now"
	case models.ReachUnreachable:
		if f.Severity == models.SeverityCritical {
			return "fix-now"
		}
		return "next-sprint"
	}

	// Default to next-sprint for medium+ severity
	return "next-sprint"
}

// generateExplanation creates a technical explanation based on finding metadata.
func (e *Engine) generateExplanation(f *models.Finding) string {
	var parts []string

	// Add severity context
	if f.Severity == models.SeverityCritical {
		parts = append(parts, "Critical vulnerability with high exploit potential.")
	} else if f.Severity == models.SeverityHigh {
		parts = append(parts, "High-severity security issue.")
	}

	// Add reachability context
	switch f.Reachability {
	case models.ReachConfirmed:
		parts = append(parts, "Runtime confirmed reachable — attacker-exploitable path exists.")
	case models.ReachReachable:
		parts = append(parts, "Static analysis confirms reachable code path.")
	case models.ReachUnreachable:
		parts = append(parts, "Code appears unreachable in current usage.")
	default:
		parts = append(parts, "Reachability not fully analyzed.")
	}

	// Add description if available
	if f.Description != "" {
		parts = append(parts, f.Description)
	}

	// Add CVE context if applicable
	if strings.HasPrefix(f.RuleID, "CVE-") {
		parts = append(parts, fmt.Sprintf("Publicly disclosed vulnerability %s.", f.RuleID))
	}

	if len(parts) == 0 {
		return "Security vulnerability detected in dependency."
	}
	return strings.Join(parts, " ")
}

// generateUpgradeCommand creates package manager upgrade commands.
func (e *Engine) generateUpgradeCommand(f *models.Finding) string {
	if f.Package == "" {
		return "No upgrade command available — manual review required"
	}

	if f.FixedVersion != "" {
		// Detect package manager based on package name patterns
		pkg := strings.ToLower(f.Package)

		switch {
		case strings.HasPrefix(pkg, "npm:") || strings.Contains(pkg, "@") && strings.Contains(pkg, "/") || e.isNpmPackage(pkg):
			return fmt.Sprintf("npm install %s@%s", f.Package, f.FixedVersion)
		case strings.HasPrefix(pkg, "pypi:") || e.hasPythonSuffix(pkg):
			return fmt.Sprintf("pip install %s==%s", f.Package, f.FixedVersion)
		case strings.HasPrefix(pkg, "cargo:") || e.hasRustPattern(pkg):
			return fmt.Sprintf("cargo update %s --precise %s", f.Package, f.FixedVersion)
		case strings.HasPrefix(pkg, "go:") || strings.HasPrefix(pkg, "github.com/") || strings.HasPrefix(pkg, "golang.org/"):
			return fmt.Sprintf("go get %s@%s", f.Package, f.FixedVersion)
		case strings.HasPrefix(pkg, "maven:") || strings.Contains(pkg, "org.") || strings.Contains(pkg, "com."):
			return fmt.Sprintf("Update %s to version %s in pom.xml", f.Package, f.FixedVersion)
		case strings.HasPrefix(pkg, "gradle:") || strings.Contains(pkg, "implementation ") || strings.Contains(pkg, "compile "):
			return fmt.Sprintf("Update %s to version %s in build.gradle", f.Package, f.FixedVersion)
		case strings.HasPrefix(pkg, "composer:") || strings.HasSuffix(pkg, "-bundle"):
			return fmt.Sprintf("composer require %s:%s", f.Package, f.FixedVersion)
		case strings.HasPrefix(pkg, "rubygems:") || e.hasRubyPattern(pkg):
			return fmt.Sprintf("gem update %s -v %s", f.Package, f.FixedVersion)
		case strings.HasPrefix(pkg, "nuget:") || strings.HasSuffix(pkg, ".dll") || strings.Contains(pkg, "Microsoft."):
			return fmt.Sprintf("dotnet add package %s --version %s", f.Package, f.FixedVersion)
		default:
			// Generic command
			return fmt.Sprintf("Upgrade %s to version %s", f.Package, f.FixedVersion)
		}
	}

	return fmt.Sprintf("Monitor %s for security updates", f.Package)
}

// isNpmPackage checks if package name looks like an npm package
func (e *Engine) isNpmPackage(pkg string) bool {
	npmPatterns := []string{"lodash", "axios", "react", "vue", "angular", "express", "moment", "underscore", "jquery"}
	for _, pattern := range npmPatterns {
		if strings.Contains(pkg, pattern) {
			return true
		}
	}
	return false
}

// hasPythonSuffix checks if package name looks like a Python package
func (e *Engine) hasPythonSuffix(pkg string) bool {
	pythonSuffixes := []string{"py", "python", "django", "flask", "requests", "numpy", "pandas"}
	for _, suffix := range pythonSuffixes {
		if strings.Contains(pkg, suffix) {
			return true
		}
	}
	return false
}

// hasRustPattern checks if package name looks like a Rust crate
func (e *Engine) hasRustPattern(pkg string) bool {
	rustPatterns := []string{"serde", "tokio", "rand", "clap", "actix", "hyper"}
	for _, pattern := range rustPatterns {
		if strings.Contains(pkg, pattern) {
			return true
		}
	}
	return false
}

// hasRubyPattern checks if package name looks like a Ruby gem
func (e *Engine) hasRubyPattern(pkg string) bool {
	rubyPatterns := []string{"rails", "rake", "rspec", "pry", "devise", "sidekiq"}
	for _, pattern := range rubyPatterns {
		if strings.Contains(pkg, pattern) {
			return true
		}
	}
	return false
}

// assessBreakingChanges estimates potential breaking changes.
func (e *Engine) assessBreakingChanges(f *models.Finding) string {
	// Semantic versioning heuristics
	if f.FixedVersion != "" && f.Version != "" {
		currentMajor := e.extractMajor(f.Version)
		fixedMajor := e.extractMajor(f.FixedVersion)

		// Extract minor versions too
		currentMinor := e.extractMinor(f.Version)
		fixedMinor := e.extractMinor(f.FixedVersion)

		if fixedMajor > currentMajor {
			return fmt.Sprintf("Major version update (%s → %s) may contain breaking changes. Review changelog.", f.Version, f.FixedVersion)
		}

		if fixedMajor == currentMajor && fixedMinor > currentMinor {
			return "Minor update — breaking changes unlikely but review changelog."
		}

		return "none"
	}

	return "Unable to assess — version information incomplete"
}

// extractMajor extracts the major version number from a version string.
func (e *Engine) extractMajor(version string) int {
	version = strings.TrimPrefix(version, "v")
	version = strings.TrimPrefix(version, "V")

	parts := strings.Split(version, ".")
	if len(parts) == 0 {
		return 0
	}

	var major int
	fmt.Sscanf(parts[0], "%d", &major)
	return major
}

// extractMinor extracts the minor version number from a version string.
func (e *Engine) extractMinor(version string) int {
	version = strings.TrimPrefix(version, "v")
	version = strings.TrimPrefix(version, "V")

	parts := strings.Split(version, ".")
	if len(parts) < 2 {
		return 0
	}

	var minor int
	fmt.Sscanf(parts[1], "%d", &minor)
	return minor
}

// generateVerifyStep creates verification commands for the fix.
func (e *Engine) generateVerifyStep(f *models.Finding) string {
	var steps []string

	// Version verification
	if f.Package != "" && f.FixedVersion != "" {
		pkg := strings.ToLower(f.Package)

		switch {
		case strings.HasPrefix(pkg, "npm:") || strings.Contains(pkg, "@") && strings.Contains(pkg, "/") || e.isNpmPackage(pkg):
			steps = append(steps, fmt.Sprintf("npm list %s", f.Package))
		case strings.HasPrefix(pkg, "pypi:") || e.hasPythonSuffix(pkg):
			steps = append(steps, fmt.Sprintf("pip show %s", f.Package))
		case strings.HasPrefix(pkg, "cargo:") || e.hasRustPattern(pkg):
			steps = append(steps, fmt.Sprintf("cargo tree | grep %s", f.Package))
		case strings.HasPrefix(pkg, "go:") || strings.HasPrefix(pkg, "github.com/") || strings.HasPrefix(pkg, "golang.org/"):
			steps = append(steps, fmt.Sprintf("go list -m %s", f.Package))
		case strings.HasPrefix(pkg, "maven:") || strings.Contains(pkg, "org.") || strings.Contains(pkg, "com."):
			steps = append(steps, fmt.Sprintf("mvn dependency:tree | grep %s", f.Package))
		case strings.HasPrefix(pkg, "gradle:") || strings.Contains(pkg, "implementation ") || strings.Contains(pkg, "compile "):
			steps = append(steps, fmt.Sprintf("./gradlew dependencies | grep %s", f.Package))
		case strings.HasPrefix(pkg, "composer:") || strings.HasSuffix(pkg, "-bundle"):
			steps = append(steps, fmt.Sprintf("composer show %s", f.Package))
		case strings.HasPrefix(pkg, "rubygems:") || e.hasRubyPattern(pkg):
			steps = append(steps, fmt.Sprintf("gem list %s", f.Package))
		case strings.HasPrefix(pkg, "nuget:") || strings.HasSuffix(pkg, ".dll") || strings.Contains(pkg, "Microsoft."):
			steps = append(steps, fmt.Sprintf("dotnet list package | grep %s", f.Package))
		default:
			steps = append(steps, fmt.Sprintf("Verify %s version is %s or later", f.Package, f.FixedVersion))
		}
	}

	// Re-scan recommendation
	steps = append(steps, "Re-run supply-chain-kit to confirm vulnerability is resolved")

	if len(steps) == 0 {
		return "Re-run security scan to verify fix"
	}

	return strings.Join(steps, " && ")
}

// generateReferences creates reference links.
func (e *Engine) generateReferences(f *models.Finding) string {
	var refs []string

	// Advisory URL from finding
	if f.AdvisoryURL != "" {
		refs = append(refs, f.AdvisoryURL)
	}

	// CVE reference
	if strings.HasPrefix(f.RuleID, "CVE-") {
		refs = append(refs, fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", f.RuleID))
	}

	// GitHub Security Advisory
	if f.Package != "" {
		refs = append(refs, fmt.Sprintf("https://github.com/advisories?query=%s", f.Package))
	}

	if len(refs) == 0 {
		return "Check vendor security advisories for details"
	}

	return strings.Join(refs, ", ")
}
