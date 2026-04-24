// Package models defines the canonical domain types shared across the
// ingestion, scanning, correlation, scoring, and storage layers.
package models

import (
	"time"
)

// Severity is an enum aligned with CVSS qualitative ratings.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// CVSSScore returns the numeric upper bound of each qualitative rating
// (used by the scoring engine when an explicit CVSS base score is missing).
func (s Severity) CVSSScore() float64 {
	switch s {
	case SeverityCritical:
		return 9.5
	case SeverityHigh:
		return 8.0
	case SeverityMedium:
		return 5.5
	case SeverityLow:
		return 3.0
	case SeverityInfo:
		return 1.0
	}
	return 0
}

// Environment classifies the asset's deployment tier.
type Environment string

const (
	EnvProduction Environment = "production"
	EnvStaging    Environment = "staging"
	EnvDev        Environment = "development"
	EnvSandbox    Environment = "sandbox"
)

// Asset is a tracked unit (typically a repository or service).
type Asset struct {
	ID             string      `json:"id"`
	Name           string      `json:"name"`
	RepoURL        string      `json:"repo_url"`
	Environment    Environment `json:"environment"`
	Tier           int         `json:"tier"` // 0 = most critical
	InternetFacing bool        `json:"internet_facing"`
	Tags           []string    `json:"tags,omitempty"`
	CreatedAt      time.Time   `json:"created_at"`
	UpdatedAt      time.Time   `json:"updated_at"`
}

// SBOM is a CycloneDX 1.5 document plus extracted metadata for fast lookups.
type SBOM struct {
	ID         string         `json:"id"`
	AssetID    string         `json:"asset_id"`
	Format     string         `json:"format"` // "cyclonedx-json"
	SpecVer    string         `json:"spec_version"`
	Components []SBOMComponent `json:"components"`
	RawJSON    []byte         `json:"-"`
	CreatedAt  time.Time      `json:"created_at"`
}

// SBOMComponent is a single dependency entry, identified by Package URL (purl).
type SBOMComponent struct {
	PURL    string `json:"purl"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Type    string `json:"type"` // library, framework, application, ...
}

// FindingSource captures which scanner produced the finding.
type FindingSource string

const (
	SourceGrype    FindingSource = "grype"
	SourceSyft     FindingSource = "syft"
	SourceSemgrep  FindingSource = "semgrep"
	SourceJoern    FindingSource = "joern"
	SourceGitleaks    FindingSource = "gitleaks"
	SourceExternal    FindingSource = "external"
	SourceTrivy       FindingSource = "trivy"
	SourceOSVScanner  FindingSource = "osv-scanner"
)

// Reachability indicates whether the vulnerable code is exercised.
type Reachability string

const (
	ReachUnknown         Reachability = "unknown"
	ReachUnreachable     Reachability = "unreachable"
	ReachReachable       Reachability = "reachable"
	ReachConfirmed       Reachability = "runtime_confirmed"
	ReachConfirmedExploit Reachability = "confirmed_exploitable"
)

// VEXStatus aligns with CSAF 2.0 (Profile 5) status values.
type VEXStatus string

const (
	VEXNotAffected      VEXStatus = "not_affected"
	VEXAffected         VEXStatus = "affected"
	VEXFixed            VEXStatus = "fixed"
	VEXUnderInvestigate VEXStatus = "under_investigation"
)

// VEXJustification captures a CISA status justification when status is not_affected.
type VEXJustification string

const (
	VEXJustCodeNotPresent       VEXJustification = "vulnerable_code_not_present"
	VEXJustInlineMitigation     VEXJustification = "inline_mitigation_already_exist"
	VEXJustNotControlled        VEXJustification = "vulnerable_code_cannot_be_controlled_by_adversary"
	VEXJustNotInExecutionPath   VEXJustification = "vulnerable_code_not_in_execute_path"
)

// Finding is the normalized, scanner-agnostic vulnerability record.
type Finding struct {
	ID            string           `json:"id"`
	AssetID       string           `json:"asset_id"`
	ScanRunID     string           `json:"scan_run_id"`
	Sources       []FindingSource  `json:"sources"`
	RuleID        string           `json:"rule_id"`        // e.g. CVE-2021-44228 or semgrep.tainted-sql
	Title         string           `json:"title"`
	Description   string           `json:"description,omitempty"`
	Severity      Severity         `json:"severity"`
	CVSS          float64          `json:"cvss,omitempty"`
	FilePath      string           `json:"file_path,omitempty"`
	Line          int              `json:"line,omitempty"`
	Package       string           `json:"package,omitempty"`
	Version       string           `json:"version,omitempty"`
	FixedVersion  string           `json:"fixed_version,omitempty"`
	AdvisoryURL   string           `json:"advisory_url,omitempty"`
	Reachability  Reachability     `json:"reachability"`
	Confidence    float64          `json:"confidence"`       // 0.0-1.0 confidence in reachability assessment
	Path          []string         `json:"path,omitempty"`    // call graph path from source to sink
	RiskScore     float64          `json:"risk_score"`
	VEXStatus     VEXStatus        `json:"vex_status,omitempty"`
	VEXJustify    VEXJustification `json:"vex_justification,omitempty"`
	Fingerprint   string           `json:"fingerprint"`
	FirstSeen     time.Time        `json:"first_seen"`
	LastSeen      time.Time        `json:"last_seen"`
	Raw           map[string]any   `json:"raw,omitempty"`
}

// ScanRequest is the unit of work consumed by the scanner worker.
type ScanRequest struct {
	ID        string    `json:"id"`
	AssetID   string    `json:"asset_id"`
	RepoURL   string    `json:"repo_url"`
	Ref       string    `json:"ref"`
	Trigger   string    `json:"trigger"` // push, pr, manual, scheduled
	CreatedAt time.Time `json:"created_at"`
}

// ScanRun is the persisted outcome of a single scan invocation.
type ScanRun struct {
	ID         string    `json:"id"`
	AssetID    string    `json:"asset_id"`
	Ref        string    `json:"ref"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at,omitempty"`
	Status     string    `json:"status"` // queued, running, succeeded, failed
	Error      string    `json:"error,omitempty"`
}
