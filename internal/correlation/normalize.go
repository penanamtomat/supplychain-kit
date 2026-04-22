// Package correlation merges scanner outputs into a deduplicated set of
// findings. Two findings collapse into one when they share the same
// fingerprint (rule_id|package|version|file_path|line). The merged record
// keeps every contributing source so downstream consumers know the finding
// was confirmed by multiple tools.
package correlation

import (
	"sort"

	"github.com/penanamtomat/supplychain-kit/internal/models"
	"github.com/penanamtomat/supplychain-kit/internal/scanner"
)

// Merge takes the per-scanner results and returns a deduplicated finding set.
func Merge(results []scanner.ScannedResult) []*models.Finding {
	byFP := map[string]*models.Finding{}
	for _, r := range results {
		for _, f := range r.Result.Findings {
			if existing, ok := byFP[f.Fingerprint]; ok {
				existing.Sources = mergeSources(existing.Sources, f.Sources)
				if f.LastSeen.After(existing.LastSeen) {
					existing.LastSeen = f.LastSeen
				}
				// Severity escalates: keep the strictest rating.
				if rank(f.Severity) > rank(existing.Severity) {
					existing.Severity = f.Severity
					existing.CVSS = f.CVSS
				}
				continue
			}
			byFP[f.Fingerprint] = f
		}
	}

	out := make([]*models.Finding, 0, len(byFP))
	for _, v := range byFP {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Fingerprint < out[j].Fingerprint })
	return out
}

func mergeSources(a, b []models.FindingSource) []models.FindingSource {
	seen := map[models.FindingSource]struct{}{}
	for _, s := range a {
		seen[s] = struct{}{}
	}
	for _, s := range b {
		seen[s] = struct{}{}
	}
	out := make([]models.FindingSource, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func rank(s models.Severity) int {
	switch s {
	case models.SeverityCritical:
		return 5
	case models.SeverityHigh:
		return 4
	case models.SeverityMedium:
		return 3
	case models.SeverityLow:
		return 2
	case models.SeverityInfo:
		return 1
	}
	return 0
}
