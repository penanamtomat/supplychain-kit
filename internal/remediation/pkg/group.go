// Package pkg provides package-level remediation grouping and guidance.
package pkg

import (
	"fmt"
	"sort"
	"strings"

	"github.com/penanamtomat/supplychain-kit/internal/models"
)

// Ecosystem represents a package ecosystem.
type Ecosystem string

const (
	EcosystemNPM     Ecosystem = "npm"
	EcosystemPyPI    Ecosystem = "pypi"
	EcosystemMaven   Ecosystem = "maven"
	EcosystemGo      Ecosystem = "go"
	EcosystemCargo   Ecosystem = "cargo"
	EcosystemNuGet   Ecosystem = "nuget"
	EcosystemUnknown Ecosystem = "unknown"
)

// PackageRemediation contains remediation guidance for a package.
type PackageRemediation struct {
	Package       string              `json:"package"`
	Ecosystem     Ecosystem           `json:"ecosystem"`
	CurrentVersion string             `json:"current_version"`
	FixedVersion  string             `json:"fixed_version"`
	Vulnerabilities []*VulnSummary   `json:"vulnerabilities"`
	UpgradeCommand string            `json:"upgrade_command"`
	RiskScore     float64            `json:"risk_score"`
	Priority      string             `json:"priority"`
	BreakingNotes string             `json:"breaking_notes,omitempty"`
	Reachability  string             `json:"reachability"`
}

// VulnSummary summarizes a vulnerability.
type VulnSummary struct {
	RuleID      string  `json:"rule_id"`
	Severity    string  `json:"severity"`
	CVSS        float64 `json:"cvss"`
	Title       string  `json:"title"`
	AdvisoryURL string  `json:"advisory_url"`
	Reachable   bool    `json:"reachable"`
}

// Grouper groups findings by package for remediation.
type Grouper struct {
	findings []*models.Finding
}

// NewGrouper creates a new findings grouper.
func NewGrouper(findings []*models.Finding) *Grouper {
	return &Grouper{findings: findings}
}

// GroupByPackage groups findings by package name.
func (g *Grouper) GroupByPackage() []*PackageRemediation {
	packages := make(map[string]*PackageRemediation)

	for _, f := range g.findings {
		pkgName := f.Package
		if pkgName == "" {
			pkgName = f.FilePath // For SAST findings
		}

		if _, exists := packages[pkgName]; !exists {
			packages[pkgName] = &PackageRemediation{
				Package:        pkgName,
				Ecosystem:      detectEcosystem(f),
				CurrentVersion: f.Version,
			}
		}

		pr := packages[pkgName]

		// Add vulnerability summary
		vuln := &VulnSummary{
			RuleID:      f.RuleID,
			Severity:    strings.ToUpper(string(f.Severity)),
			CVSS:        f.CVSS,
			Title:       f.Title,
			AdvisoryURL: f.AdvisoryURL,
			Reachable:   f.Reachability == models.ReachReachable,
		}
		pr.Vulnerabilities = append(pr.Vulnerabilities, vuln)

		// Update fixed version to latest
		if f.FixedVersion != "" && isNewerVersion(f.FixedVersion, pr.FixedVersion) {
			pr.FixedVersion = f.FixedVersion
		}

		// Update risk score
		if f.RiskScore > pr.RiskScore {
			pr.RiskScore = f.RiskScore
		}

		// Update reachability to worst
		if isMoreReachable(f.Reachability, pr.Reachability) {
			pr.Reachability = string(f.Reachability)
		}
	}

	// Generate upgrade commands and determine priority
	for _, pr := range packages {
		pr.UpgradeCommand = generateUpgradeCommand(pr)
		pr.Priority = determinePriority(pr)
	}

	// Sort by risk score
	var result []*PackageRemediation
	for _, pr := range packages {
		result = append(result, pr)
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].RiskScore > result[j].RiskScore
	})

	return result
}

// detectEcosystem detects the package ecosystem from a finding.
func detectEcosystem(f *models.Finding) Ecosystem {
	// Check file path hints
	if strings.Contains(f.FilePath, "node_modules") || strings.Contains(f.FilePath, "package.json") {
		return EcosystemNPM
	}
	if strings.Contains(f.FilePath, "site-packages") || strings.Contains(f.FilePath, "requirements.txt") {
		return EcosystemPyPI
	}
	if strings.Contains(f.FilePath, "pom.xml") || strings.Contains(f.FilePath, ".m2") {
		return EcosystemMaven
	}
	if strings.Contains(f.FilePath, "go.mod") || strings.Contains(f.FilePath, "go.sum") {
		return EcosystemGo
	}
	if strings.Contains(f.FilePath, "Cargo.toml") || strings.Contains(f.FilePath, "Cargo.lock") {
		return EcosystemCargo
	}
	if strings.Contains(f.FilePath, "packages.config") || strings.Contains(f.FilePath, ".csproj") {
		return EcosystemNuGet
	}

	// Check package name patterns
	if strings.HasPrefix(f.Package, "@") || strings.Contains(f.Package, "/") {
		return EcosystemNPM
	}

	// Check rule ID patterns
	if strings.HasPrefix(f.RuleID, "CVE-") || strings.HasPrefix(f.RuleID, "GHSA-") {
		// Could be any ecosystem, try to infer from common packages
		commonNPMPackages := map[string]bool{
			"lodash": true, "react": true, "express": true, "axios": true,
			"tar": true, "minimist": true, "ws": true,
		}
		if commonNPMPackages[f.Package] {
			return EcosystemNPM
		}
	}

	return EcosystemUnknown
}

// isNewerVersion checks if version1 is newer than version2.
func isNewerVersion(version1, version2 string) bool {
	if version2 == "" {
		return true
	}
	// Simple comparison - can be enhanced with semver library
	return version1 > version2
}

// isMoreReachable checks if reachability1 is more critical than reachability2.
func isMoreReachable(reachability1 models.Reachability, reachability2 string) bool {
	// Order: reachable > unknown > unreachable
	order := map[string]int{
		string(models.ReachReachable):   3,
		string(models.ReachUnknown):     2,
		string(models.ReachUnreachable): 1,
		"":                              0,
	}

	return order[string(reachability1)] > order[reachability2]
}

// generateUpgradeCommand generates the appropriate upgrade command for a package.
func generateUpgradeCommand(pr *PackageRemediation) string {
	if pr.FixedVersion == "" {
		return fmt.Sprintf("# No fixed version available for %s", pr.Package)
	}

	switch pr.Ecosystem {
	case EcosystemNPM:
		return fmt.Sprintf("npm install %s@%s", pr.Package, pr.FixedVersion)
	case EcosystemPyPI:
		return fmt.Sprintf("pip install %s==%s", pr.Package, pr.FixedVersion)
	case EcosystemMaven:
		return fmt.Sprintf("# Update %s to version %s in pom.xml", pr.Package, pr.FixedVersion)
	case EcosystemGo:
		return fmt.Sprintf("go get %s@%s", pr.Package, pr.FixedVersion)
	case EcosystemCargo:
		return fmt.Sprintf("cargo update %s --precise %s", pr.Package, pr.FixedVersion)
	case EcosystemNuGet:
		return fmt.Sprintf("Update-Package %s -Version %s", pr.Package, pr.FixedVersion)
	default:
		return fmt.Sprintf("# Update %s to version %s", pr.Package, pr.FixedVersion)
	}
}

// determinePriority determines the remediation priority based on multiple factors.
func determinePriority(pr *PackageRemediation) string {
	// Check for confirmed exploitable
	hasConfirmedExploitable := false
	hasHigh := false
	hasReachable := false

	for _, vuln := range pr.Vulnerabilities {
		if vuln.Reachable {
			hasReachable = true
		}
		if vuln.Severity == "HIGH" || vuln.Severity == "CRITICAL" {
			if vuln.Reachable {
				hasConfirmedExploitable = true
			} else {
				hasHigh = true
			}
		}
	}

	// Determine priority
	if hasConfirmedExploitable {
		return "P0 - Fix Immediately"
	}
	if hasReachable && hasHigh {
		return "P1 - This Sprint"
	}
	if pr.RiskScore > 5.0 {
		return "P1 - This Sprint"
	}
	if hasHigh {
		return "P2 - Next Sprint"
	}
	if hasReachable {
		return "P2 - Next Sprint"
	}
	return "P3 - Monitor"
}

// GenerateRemediationReport generates a comprehensive remediation report.
func (g *Grouper) GenerateRemediationReport() string {
	var b strings.Builder

	packages := g.GroupByPackage()

	b.WriteString("# 📦 Package-Level Remediation Report\n\n")

	// Summary
	b.WriteString("## 📊 Executive Summary\n\n")

	p0Count := 0
	p1Count := 0
	p2Count := 0
	totalVulns := 0

	for _, pr := range packages {
		totalVulns += len(pr.Vulnerabilities)
		switch {
		case strings.HasPrefix(pr.Priority, "P0"):
			p0Count++
		case strings.HasPrefix(pr.Priority, "P1"):
			p1Count++
		case strings.HasPrefix(pr.Priority, "P2"):
			p2Count++
		}
	}

	b.WriteString(fmt.Sprintf("| Metric | Count |\n|---|---|\n"))
	b.WriteString(fmt.Sprintf("| Total Packages with Vulnerabilities | %d |\n", len(packages)))
	b.WriteString(fmt.Sprintf("| Total Vulnerabilities | %d |\n", totalVulns))
	b.WriteString(fmt.Sprintf("| P0 - Fix Immediately | %d |\n", p0Count))
	b.WriteString(fmt.Sprintf("| P1 - This Sprint | %d |\n", p1Count))
	b.WriteString(fmt.Sprintf("| P2 - Next Sprint | %d |\n", p2Count))
	b.WriteString("\n")

	// P0 - Fix Immediately
	if p0Count > 0 {
		b.WriteString("## 🚨 P0 - Fix Immediately (Confirmed Exploitable)\n\n")
		for _, pr := range packages {
			if strings.HasPrefix(pr.Priority, "P0") {
				g.writePackageSection(&b, pr)
			}
		}
	}

	// P1 - This Sprint
	if p1Count > 0 {
		b.WriteString("## ⚠️ P1 - This Sprint\n\n")
		for _, pr := range packages {
			if strings.HasPrefix(pr.Priority, "P1") {
				g.writePackageSection(&b, pr)
			}
		}
	}

	// P2 - Next Sprint
	if p2Count > 0 {
		b.WriteString("## 📋 P2 - Next Sprint\n\n")
		for _, pr := range packages {
			if strings.HasPrefix(pr.Priority, "P2") {
				g.writePackageSection(&b, pr)
			}
		}
	}

	// P3 - Monitor
	remaining := false
	for _, pr := range packages {
		if strings.HasPrefix(pr.Priority, "P3") {
			if !remaining {
				b.WriteString("## 👁️ P3 - Monitor\n\n")
				remaining = true
			}
			g.writePackageSection(&b, pr)
		}
	}

	return b.String()
}

// writePackageSection writes a section for a single package.
func (g *Grouper) writePackageSection(b *strings.Builder, pr *PackageRemediation) {
	b.WriteString(fmt.Sprintf("### %s @ %s\n\n", pr.Package, pr.CurrentVersion))
	b.WriteString(fmt.Sprintf("**Priority:** %s  \n", pr.Priority))
	b.WriteString(fmt.Sprintf("**Risk Score:** %.2f  \n", pr.RiskScore))
	b.WriteString(fmt.Sprintf("**Ecosystem:** %s  \n", pr.Ecosystem))

	if pr.FixedVersion != "" {
		b.WriteString(fmt.Sprintf("**Fixed Version:** %s  \n", pr.FixedVersion))
	}

	b.WriteString(fmt.Sprintf("**Reachability:** %s  \n\n", pr.Reachability))

	// Upgrade command
	b.WriteString("#### 🔧 Remediation\n\n")
	b.WriteString(fmt.Sprintf("```bash\n%s\n```\n\n", pr.UpgradeCommand))

	// Breaking changes notes
	if pr.BreakingNotes != "" {
		b.WriteString(fmt.Sprintf("**⚠️ Breaking Changes:** %s\n\n", pr.BreakingNotes))
	}

	// Vulnerabilities list
	b.WriteString("#### 🐛 Vulnerabilities\n\n")
	for _, vuln := range pr.Vulnerabilities {
		reachableIcon := "✅"
		if vuln.Reachable {
			reachableIcon = "🔴"
		}

		b.WriteString(fmt.Sprintf("- **%s** `%s` - %s %s\n",
			vuln.Severity, vuln.RuleID, reachableIcon, vuln.Title))

		if vuln.CVSS > 0 {
			b.WriteString(fmt.Sprintf("  - CVSS: %.1f\n", vuln.CVSS))
		}

		if vuln.AdvisoryURL != "" {
			b.WriteString(fmt.Sprintf("  - [%s](%s)\n", "View Advisory", vuln.AdvisoryURL))
		}

		b.WriteString("\n")
	}

	b.WriteString("---\n\n")
}

// GetQuickFixCommands returns a list of quick fix commands for P0/P1 packages.
func (g *Grouper) GetQuickFixCommands() []string {
	packages := g.GroupByPackage()
	var commands []string

	commands = append(commands, "# Quick Fix Commands (P0/P1)")
	commands = append(commands, "# Copy and paste these commands to fix critical vulnerabilities\n")

	for _, pr := range packages {
		if strings.HasPrefix(pr.Priority, "P0") || strings.HasPrefix(pr.Priority, "P1") {
			if pr.FixedVersion != "" {
				commands = append(commands, fmt.Sprintf("# %s - %s", pr.Package, pr.Priority))
				commands = append(commands, pr.UpgradeCommand)
			}
		}
	}

	return commands
}

// GetUpgradeImpact analyzes what would happen if all packages are upgraded.
func (g *Grouper) GetUpgradeImpact() map[string]interface{} {
	packages := g.GroupByPackage()

	totalVulnsFixed := 0
	criticalVulnsFixed := 0
	highVulnsFixed := 0
	packagesFixed := len(packages)

	for _, pr := range packages {
		for _, vuln := range pr.Vulnerabilities {
			totalVulnsFixed++
			if vuln.Severity == "CRITICAL" {
				criticalVulnsFixed++
			} else if vuln.Severity == "HIGH" {
				highVulnsFixed++
			}
		}
	}

	return map[string]interface{}{
		"packages_to_upgrade":      packagesFixed,
		"vulnerabilities_fixed":    totalVulnsFixed,
		"critical_vulnerabilities_fixed": criticalVulnsFixed,
		"high_vulnerabilities_fixed": highVulnsFixed,
		"reduction_percentage":     float64(totalVulnsFixed) / float64(totalVulnsFixed+1) * 100,
	}
}
