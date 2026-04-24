// Package license provides license compliance scanning for dependencies.
// It detects licenses from package metadata and evaluates them against policies.
package license

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// LicenseType represents the risk category of a license.
type LicenseType string

const (
	LicenseTypeApproved    LicenseType = "approved"
	LicenseTypeNeutral     LicenseType = "neutral"
	LicenseTypeRestricted  LicenseType = "restricted"
	LicenseTypeUnknown     LicenseType = "unknown"
)

// License represents a detected license with metadata.
type License struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Type        LicenseType `json:"type"`
	SPDXID      string      `json:"spdx_id,omitempty"`
	URL         string      `json:"url,omitempty"`
	RiskScore   float64     `json:"risk_score"`
	Description string      `json:"description,omitempty"`
}

// PackageLicense represents license information for a specific package.
type PackageLicense struct {
	Package     string   `json:"package"`
	Version     string   `json:"version"`
	Licenses    []License `json:"licenses"`
	LicenseFile string   `json:"license_file,omitempty"`
	Compliant   bool     `json:"compliant"`
	RiskScore   float64  `json:"risk_score"`
}

// Scanner detects and evaluates licenses.
type Scanner struct {
	policy *Policy
}

// Policy defines which licenses are approved, neutral, or restricted.
type Policy struct {
	Approved   []string `json:"approved"`
	Neutral    []string `json:"neutral"`
	Restricted []string `json:"restricted"`
}

// NewScanner creates a new license scanner with the given policy.
func NewScanner(policy *Policy) *Scanner {
	if policy == nil {
		policy = DefaultPolicy()
	}
	return &Scanner{policy: policy}
}

// DefaultPolicy returns a default license policy.
func DefaultPolicy() *Policy {
	return &Policy{
		Approved: []string{
			"MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause",
			"ISC", "0BSD", "CC0-1.0", "Unlicense",
		},
		Neutral: []string{
			"MPL-2.0", "LGPL-2.1", "LGPL-3.0", "CDDL-1.0",
		},
		Restricted: []string{
			"GPL-3.0", "GPL-2.0", "AGPL-3.0", "SSPL",
			"CPAL-1.0", "EPL-1.0",
		},
	}
}

// ScanPackageDir scans a package directory for license information.
func (s *Scanner) ScanPackageDir(pkgDir string) (*PackageLicense, error) {
	// Try to find license file
	licenseFiles := []string{
		"LICENSE", "LICENSE.txt", "LICENSE.md",
		"LICENCE", "LICENCE.txt", "LICENCE.md",
		" COPYING", "COPYING.txt",
	}

	var licenseFile string
	var licenseContent string

	for _, fname := range licenseFiles {
		fpath := filepath.Join(pkgDir, fname)
		if content, err := os.ReadFile(fpath); err == nil {
			licenseFile = fpath
			licenseContent = string(content)
			break
		}
	}

	// Parse package name from directory
	pkgName := filepath.Base(pkgDir)

	licenses := s.detectLicenses(licenseContent)

	pl := &PackageLicense{
		Package:     pkgName,
		Licenses:    licenses,
		LicenseFile: licenseFile,
	}

	s.evaluateCompliance(pl)

	return pl, nil
}

// ScanFromSBOM extracts license information from an SBOM.
func (s *Scanner) ScanFromSBOM(sbomPath string) ([]*PackageLicense, error) {
	// This would parse CycloneDX SBOM for license data
	// For now, return empty
	return []*PackageLicense{}, nil
}

// detectLicenses attempts to detect licenses from text content.
func (s *Scanner) detectLicenses(content string) []License {
	if content == "" {
		return []License{{
			ID:        "UNKNOWN",
			Name:      "Unknown License",
			Type:      LicenseTypeUnknown,
			RiskScore: 0.5,
		}}
	}

	contentLower := strings.ToLower(content)

	// Common license detections
	detectors := []struct {
		id          string
		name        string
		keywords    []string
		spdxID      string
		licenseType LicenseType
	}{
		{
			id:   "MIT",
			name: "MIT License",
			keywords: []string{
				"permission is hereby granted", "without restriction",
				"the above copyright notice", "shall be included",
			},
			spdxID:      "MIT",
			licenseType: LicenseTypeApproved,
		},
		{
			id:   "Apache-2.0",
			name: "Apache License 2.0",
			keywords: []string{
				"apache license", "version 2.0",
				"licensed under the apache license",
			},
			spdxID:      "Apache-2.0",
			licenseType: LicenseTypeApproved,
		},
		{
			id:   "GPL-3.0",
			name: "GNU General Public License v3.0",
			keywords: []string{
				"gnu general public license", "version 3",
				"gnu gpl", "gplv3",
			},
			spdxID:      "GPL-3.0-only",
			licenseType: LicenseTypeRestricted,
		},
		{
			id:   "BSD-2-Clause",
			name: "BSD 2-Clause License",
			keywords: []string{
				"redistribution and use in source and binary forms",
				"without modification", "are permitted",
				"binary must reproduce the above copyright",
			},
			spdxID:      "BSD-2-Clause",
			licenseType: LicenseTypeApproved,
		},
		{
			id:   "BSD-3-Clause",
			name: "BSD 3-Clause License",
			keywords: []string{
				"redistribution and use in source and binary forms",
				"neither the name of", "three-clause bsd",
			},
			spdxID:      "BSD-3-Clause",
			licenseType: LicenseTypeApproved,
		},
		{
			id:   "ISC",
			name: "ISC License",
			keywords: []string{
				"permission to use, copy, modify, and/or distribute",
				"for any purpose", "with or without fee",
				"isc license",
			},
			spdxID:      "ISC",
			licenseType: LicenseTypeApproved,
		},
	}

	var detected []License

	for _, detector := range detectors {
		matchCount := 0
		for _, keyword := range detector.keywords {
			if strings.Contains(contentLower, keyword) {
				matchCount++
			}
		}

		if matchCount >= 2 {
			licenseType := detector.licenseType
			riskScore := s.calculateRiskScore(licenseType)

			detected = append(detected, License{
				ID:        detector.id,
				Name:      detector.name,
				Type:      licenseType,
				SPDXID:    detector.spdxID,
				RiskScore: riskScore,
			})
		}
	}

	if len(detected) == 0 {
		return []License{{
			ID:        "UNKNOWN",
			Name:      "Unknown License",
			Type:      LicenseTypeUnknown,
			RiskScore: 0.5,
		}}
	}

	return detected
}

// calculateRiskScore calculates a risk score for a license type.
func (s *Scanner) calculateRiskScore(licenseType LicenseType) float64 {
	switch licenseType {
	case LicenseTypeApproved:
		return 0.0
	case LicenseTypeNeutral:
		return 0.3
	case LicenseTypeRestricted:
		return 0.8
	case LicenseTypeUnknown:
		return 0.5
	default:
		return 0.5
	}
}

// evaluateCompliance evaluates if a package's licenses are compliant.
func (s *Scanner) evaluateCompliance(pl *PackageLicense) {
	maxRisk := 0.0
	hasRestricted := false

	for _, lic := range pl.Licenses {
		if lic.RiskScore > maxRisk {
			maxRisk = lic.RiskScore
		}
		if lic.Type == LicenseTypeRestricted {
			hasRestricted = true
		}
	}

	pl.RiskScore = maxRisk
	pl.Compliant = !hasRestricted
}

// GenerateReport generates a license compliance report.
func (s *Scanner) GenerateReport(packages []*PackageLicense) string {
	var b strings.Builder

	b.WriteString("# License Compliance Report\n\n")

	compliant := 0
	nonCompliant := 0
	unknown := 0

	for _, pkg := range packages {
		if pkg.Compliant {
			compliant++
		} else {
			nonCompliant++
		}
	}

	b.WriteString(fmt.Sprintf("## Summary\n\n"))
	b.WriteString(fmt.Sprintf("| | |\n|---|---|\n"))
	b.WriteString(fmt.Sprintf("| Total Packages | %d |\n", len(packages)))
	b.WriteString(fmt.Sprintf("| Compliant | %d |\n", compliant))
	b.WriteString(fmt.Sprintf("| Non-Compliant | %d |\n", nonCompliant))
	b.WriteString(fmt.Sprintf("| Unknown | %d |\n\n", unknown))

	b.WriteString("## Packages by License Status\n\n")

	// Non-compliant packages
	if nonCompliant > 0 {
		b.WriteString("### 🔴 Non-Compliant (Restricted Licenses)\n\n")
		for _, pkg := range packages {
			if !pkg.Compliant {
				b.WriteString(fmt.Sprintf("- **%s**", pkg.Package))
				if pkg.Version != "" {
					b.WriteString(fmt.Sprintf(" @ %s", pkg.Version))
				}
				b.WriteString("\n  ")
				for _, lic := range pkg.Licenses {
					b.WriteString(fmt.Sprintf("[%s] ", lic.Name))
				}
				b.WriteString("\n\n")
			}
		}
	}

	// Compliant packages
	b.WriteString("### ✅ Compliant (Approved Licenses)\n\n")
	for _, pkg := range packages {
		if pkg.Compliant {
			b.WriteString(fmt.Sprintf("- **%s**", pkg.Package))
			if pkg.Version != "" {
				b.WriteString(fmt.Sprintf(" @ %s", pkg.Version))
			}
			b.WriteString("\n  ")
			for _, lic := range pkg.Licenses {
				b.WriteString(fmt.Sprintf("[%s] ", lic.Name))
			}
			b.WriteString("\n\n")
		}
	}

	return b.String()
}

// FindLicenseFiles finds license files in a directory tree.
func FindLicenseFiles(rootDir string) ([]string, error) {
	var licenseFiles []string

	err := filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		if info.IsDir() {
			// Skip node_modules and vendor directories
			base := filepath.Base(path)
			if base == "node_modules" || base == "vendor" || base == ".git" {
				return filepath.SkipDir
			}
			return nil
		}

		base := strings.ToLower(filepath.Base(path))
		for _, licenseName := range []string{"license", "licence", "copying"} {
			if strings.HasPrefix(base, licenseName) {
				licenseFiles = append(licenseFiles, path)
				break
			}
		}

		return nil
	})

	return licenseFiles, err
}

// ReadPackageJSON reads package.json for license field.
func ReadPackageJSON(pkgDir string) (string, error) {
	pkgJSONPath := filepath.Join(pkgDir, "package.json")
	if _, err := os.Stat(pkgJSONPath); err != nil {
		return "", nil
	}

	file, err := os.Open(pkgJSONPath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	inLicense := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "\"license\"") {
			inLicense = true
			// Extract license value from same line
			if idx := strings.Index(line, ":"); idx > 0 {
				value := strings.TrimSpace(line[idx+1:])
				value = strings.Trim(value, ",\"'")
				return value, nil
			}
			continue
		}
		if inLicense {
			value := strings.Trim(line, ",\"'")
			if value != "" {
				return value, nil
			}
			inLicense = false
		}
	}

	return "", nil
}
