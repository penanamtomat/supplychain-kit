// Package report renders findings in downstream-consumable formats.
//
// SARIF 2.1.0 output targets GitHub Code Scanning, GitLab, Azure DevOps,
// and other security dashboards that standardize on the OASIS SARIF schema.
package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/penanamtomat/supplychain-kit/internal/models"
)

const (
	sarifSchema  = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
	sarifVersion = "2.1.0"
	toolName     = "supplychain-kit"
	toolInfoURI  = "https://github.com/penanamtomat/supplychain-kit"
)

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool      `json:"tool"`
	Results []sarifResult  `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string            `json:"id"`
	Name             string            `json:"name,omitempty"`
	ShortDescription sarifText         `json:"shortDescription"`
	FullDescription  *sarifText        `json:"fullDescription,omitempty"`
	HelpURI          string            `json:"helpUri,omitempty"`
	Properties       map[string]any    `json:"properties,omitempty"`
	DefaultConfig    *sarifRuleConfig  `json:"defaultConfiguration,omitempty"`
}

type sarifRuleConfig struct {
	Level string `json:"level"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex"`
	Level               string            `json:"level"`
	Message             sarifText         `json:"message"`
	Locations           []sarifLocation   `json:"locations,omitempty"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
	Properties          map[string]any    `json:"properties,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           *sarifRegion          `json:"region,omitempty"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

// severityToLevel maps our Severity to SARIF level enum.
func severityToLevel(s models.Severity) string {
	switch s {
	case models.SeverityCritical, models.SeverityHigh:
		return "error"
	case models.SeverityMedium:
		return "warning"
	case models.SeverityLow, models.SeverityInfo:
		return "note"
	default:
		return "warning"
	}
}

// WriteSARIF renders findings as SARIF 2.1.0 and writes to path.
// toolVersion is typically the git-describe version passed via -ldflags.
func WriteSARIF(path, toolVersion string, findings []*models.Finding) error {
	if toolVersion == "" {
		toolVersion = "dev"
	}

	ruleIndex := map[string]int{}
	var rules []sarifRule
	var results []sarifResult

	for _, f := range findings {
		if f == nil || f.RuleID == "" {
			continue
		}
		idx, ok := ruleIndex[f.RuleID]
		if !ok {
			idx = len(rules)
			ruleIndex[f.RuleID] = idx
			rules = append(rules, sarifRule{
				ID:               f.RuleID,
				Name:             f.RuleID,
				ShortDescription: sarifText{Text: truncate(f.Title, 200)},
				FullDescription:  optionalText(f.Description),
				HelpURI:          f.AdvisoryURL,
				DefaultConfig:    &sarifRuleConfig{Level: severityToLevel(f.Severity)},
				Properties: map[string]any{
					"security-severity": securityScore(f),
					"tags":              []string{"security", string(f.Severity)},
				},
			})
		}

		var locs []sarifLocation
		if f.FilePath != "" {
			loc := sarifLocation{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: toURI(f.FilePath)},
				},
			}
			if f.Line > 0 {
				loc.PhysicalLocation.Region = &sarifRegion{StartLine: f.Line}
			}
			locs = append(locs, loc)
		}

		results = append(results, sarifResult{
			RuleID:    f.RuleID,
			RuleIndex: idx,
			Level:     severityToLevel(f.Severity),
			Message:   sarifText{Text: buildMessage(f)},
			Locations: locs,
			PartialFingerprints: map[string]string{
				"supplychainKitFingerprint/v1": f.Fingerprint,
			},
			Properties: map[string]any{
				"package":      f.Package,
				"version":      f.Version,
				"fixedVersion": f.FixedVersion,
				"reachability": string(f.Reachability),
				"confidence":   f.Confidence,
				"cvss":         f.CVSS,
				"riskScore":    f.RiskScore,
			},
		})
	}

	log := sarifLog{
		Schema:  sarifSchema,
		Version: sarifVersion,
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           toolName,
				Version:        toolVersion,
				InformationURI: toolInfoURI,
				Rules:          rules,
			}},
			Results: results,
		}},
	}

	raw, err := json.MarshalIndent(log, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal sarif: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o644)
}

func optionalText(s string) *sarifText {
	if s == "" {
		return nil
	}
	return &sarifText{Text: s}
}

func truncate(s string, n int) string {
	if s == "" {
		return "(no title)"
	}
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

// toURI normalizes a file path to a forward-slash relative URI (SARIF requirement).
func toURI(p string) string {
	return strings.ReplaceAll(filepath.ToSlash(p), "\\", "/")
}

// buildMessage produces a human-readable one-line description.
func buildMessage(f *models.Finding) string {
	parts := []string{}
	if f.Title != "" {
		parts = append(parts, f.Title)
	}
	if f.Package != "" {
		pkg := f.Package
		if f.Version != "" {
			pkg += "@" + f.Version
		}
		parts = append(parts, "in "+pkg)
	}
	if f.FixedVersion != "" {
		parts = append(parts, "(fixed in "+f.FixedVersion+")")
	}
	if f.Reachability == models.ReachReachable || f.Reachability == models.ReachConfirmed {
		parts = append(parts, "["+string(f.Reachability)+"]")
	}
	if len(parts) == 0 {
		return f.RuleID
	}
	return strings.Join(parts, " ")
}

// securityScore exposes CVSS (or a severity-derived fallback) for GitHub
// Code Scanning's "security-severity" property. Range 0.0–10.0.
func securityScore(f *models.Finding) string {
	score := f.CVSS
	if score == 0 {
		score = f.Severity.CVSSScore()
	}
	return fmt.Sprintf("%.1f", score)
}
