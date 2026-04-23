// Package storage holds PostgreSQL repositories for assets, findings, scan
// runs, and SBOMs. Repositories return models.* types so consumers never see
// pgx-specific errors at API boundaries.
package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/penanamtomat/supplychain-kit/internal/models"
)

// ErrNotFound is returned when a row is missing.
var ErrNotFound = errors.New("not found")

// Store wraps a pgxpool.Pool and exposes the repositories.
type Store struct {
	pool *pgxpool.Pool
}

// New returns a Store backed by the supplied DSN.
func New(ctx context.Context, dsn string, maxConns int) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse dsn: %w", err)
	}
	if maxConns > 0 {
		cfg.MaxConns = int32(maxConns)
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		return nil, fmt.Errorf("ping: %w", err)
	}
	return &Store{pool: pool}, nil
}

// Close releases all connections.
func (s *Store) Close() { s.pool.Close() }

// --- Assets ---

func (s *Store) UpsertAsset(ctx context.Context, a *models.Asset) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO assets (id, name, repo_url, environment, tier, internet_facing, tags, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7, NOW(), NOW())
		ON CONFLICT (id) DO UPDATE SET
		  name = EXCLUDED.name,
		  repo_url = EXCLUDED.repo_url,
		  environment = EXCLUDED.environment,
		  tier = EXCLUDED.tier,
		  internet_facing = EXCLUDED.internet_facing,
		  tags = EXCLUDED.tags,
		  updated_at = NOW()
	`, a.ID, a.Name, a.RepoURL, a.Environment, a.Tier, a.InternetFacing, a.Tags)
	return err
}

func (s *Store) GetAsset(ctx context.Context, id string) (*models.Asset, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, name, repo_url, environment, tier, internet_facing, tags, created_at, updated_at
		FROM assets WHERE id = $1
	`, id)
	var a models.Asset
	if err := row.Scan(&a.ID, &a.Name, &a.RepoURL, &a.Environment, &a.Tier, &a.InternetFacing, &a.Tags, &a.CreatedAt, &a.UpdatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &a, nil
}

// --- Findings ---

func (s *Store) UpsertFinding(ctx context.Context, f *models.Finding) error {
	raw, _ := json.Marshal(f.Raw)
	sources, _ := json.Marshal(f.Sources)
	_, err := s.pool.Exec(ctx, `
		INSERT INTO findings (
		  id, asset_id, scan_run_id, sources, rule_id, title, description,
		  severity, cvss, file_path, line, package, version, fixed_version,
		  reachability, risk_score, vex_status, vex_justification,
		  fingerprint, first_seen, last_seen, raw
		) VALUES (
		  $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22
		)
		ON CONFLICT (fingerprint) DO UPDATE SET
		  last_seen = EXCLUDED.last_seen,
		  reachability = EXCLUDED.reachability,
		  risk_score = EXCLUDED.risk_score,
		  vex_status = EXCLUDED.vex_status,
		  vex_justification = EXCLUDED.vex_justification,
		  raw = EXCLUDED.raw
	`,
		f.ID, f.AssetID, f.ScanRunID, sources, f.RuleID, f.Title, f.Description,
		f.Severity, f.CVSS, f.FilePath, f.Line, f.Package, f.Version, f.FixedVersion,
		f.Reachability, f.RiskScore, f.VEXStatus, f.VEXJustify,
		f.Fingerprint, f.FirstSeen, f.LastSeen, raw,
	)
	return err
}

// FindingFilter narrows ListFindings results.
type FindingFilter struct {
	AssetID      string
	Severity     models.Severity
	Reachability models.Reachability
	Limit        int
	Offset       int
}

func (s *Store) ListFindings(ctx context.Context, f FindingFilter) ([]*models.Finding, error) {
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 100
	}
	if f.Offset < 0 {
		f.Offset = 0
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, asset_id, scan_run_id, rule_id, title, severity, cvss,
		       file_path, line, package, version, fixed_version,
		       reachability, risk_score, vex_status, fingerprint,
		       first_seen, last_seen
		FROM findings
		WHERE ($1 = '' OR asset_id = $1)
		  AND ($2 = '' OR severity = $2)
		  AND ($3 = '' OR reachability = $3)
		ORDER BY risk_score DESC, last_seen DESC
		LIMIT $4 OFFSET $5
	`, f.AssetID, string(f.Severity), string(f.Reachability), f.Limit, f.Offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*models.Finding
	for rows.Next() {
		x := &models.Finding{}
		if err := rows.Scan(
			&x.ID, &x.AssetID, &x.ScanRunID, &x.RuleID, &x.Title, &x.Severity, &x.CVSS,
			&x.FilePath, &x.Line, &x.Package, &x.Version, &x.FixedVersion,
			&x.Reachability, &x.RiskScore, &x.VEXStatus, &x.Fingerprint,
			&x.FirstSeen, &x.LastSeen,
		); err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

// --- Scan runs ---

func (s *Store) CreateScanRun(ctx context.Context, r *models.ScanRun) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO scan_runs (id, asset_id, ref, started_at, status)
		VALUES ($1,$2,$3,$4,$5)
	`, r.ID, r.AssetID, r.Ref, r.StartedAt, r.Status)
	return err
}

func (s *Store) FinishScanRun(ctx context.Context, id, status, errMsg string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE scan_runs SET finished_at = $1, status = $2, error = $3 WHERE id = $4
	`, time.Now(), status, errMsg, id)
	return err
}

// AssetRiskSummary computes risk aggregates for an asset entirely in the DB,
// avoiding the 500-row cap that in-memory approaches impose.
type AssetRiskSummary struct {
	AssetID        string  `json:"asset_id"`
	FindingCount   int     `json:"finding_count"`
	MaxRiskScore   float64 `json:"max_risk_score"`
	AvgRiskScore   float64 `json:"avg_risk_score"`
	ReachableCount int     `json:"reachable_count"`
	CriticalCount  int     `json:"critical_count"`
}

func (s *Store) AssetRiskSummary(ctx context.Context, assetID string) (*AssetRiskSummary, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT
		  COUNT(*)                                                        AS finding_count,
		  COALESCE(MAX(risk_score), 0)                                   AS max_risk_score,
		  COALESCE(AVG(risk_score), 0)                                   AS avg_risk_score,
		  COUNT(*) FILTER (WHERE reachability IN ('reachable','confirmed')) AS reachable_count,
		  COUNT(*) FILTER (WHERE severity = 'critical')                  AS critical_count
		FROM findings
		WHERE asset_id = $1
	`, assetID)
	out := &AssetRiskSummary{AssetID: assetID}
	if err := row.Scan(&out.FindingCount, &out.MaxRiskScore, &out.AvgRiskScore, &out.ReachableCount, &out.CriticalCount); err != nil {
		return nil, err
	}
	return out, nil
}

// --- SBOMs ---

func (s *Store) StoreSBOM(ctx context.Context, sb *models.SBOM) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO sboms (id, asset_id, format, spec_version, raw, created_at)
		VALUES ($1,$2,$3,$4,$5,$6)
		ON CONFLICT (id) DO NOTHING
	`, sb.ID, sb.AssetID, sb.Format, sb.SpecVer, sb.RawJSON, sb.CreatedAt)
	if err != nil {
		return err
	}
	for _, c := range sb.Components {
		if _, err := s.pool.Exec(ctx, `
			INSERT INTO sbom_components (sbom_id, purl, name, version, type)
			VALUES ($1,$2,$3,$4,$5)
			ON CONFLICT DO NOTHING
		`, sb.ID, c.PURL, c.Name, c.Version, c.Type); err != nil {
			return err
		}
	}
	return nil
}
