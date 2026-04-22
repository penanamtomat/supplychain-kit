-- Initial schema for the ASPM platform.

CREATE TABLE IF NOT EXISTS assets (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    repo_url        TEXT,
    environment     TEXT NOT NULL DEFAULT 'development',
    tier            INT  NOT NULL DEFAULT 2,
    internet_facing BOOLEAN NOT NULL DEFAULT FALSE,
    tags            TEXT[],
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS scan_runs (
    id          TEXT PRIMARY KEY,
    asset_id    TEXT REFERENCES assets(id) ON DELETE CASCADE,
    ref         TEXT,
    started_at  TIMESTAMPTZ NOT NULL,
    finished_at TIMESTAMPTZ,
    status      TEXT NOT NULL,
    error       TEXT
);

CREATE INDEX IF NOT EXISTS scan_runs_asset_idx ON scan_runs(asset_id);

CREATE TABLE IF NOT EXISTS sboms (
    id           TEXT PRIMARY KEY,
    asset_id     TEXT REFERENCES assets(id) ON DELETE CASCADE,
    format       TEXT NOT NULL,
    spec_version TEXT,
    raw          BYTEA,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS sbom_components (
    sbom_id  TEXT REFERENCES sboms(id) ON DELETE CASCADE,
    purl     TEXT,
    name     TEXT,
    version  TEXT,
    type     TEXT,
    PRIMARY KEY (sbom_id, purl)
);

CREATE INDEX IF NOT EXISTS sbom_components_purl_idx ON sbom_components(purl);

CREATE TABLE IF NOT EXISTS findings (
    id                TEXT PRIMARY KEY,
    asset_id          TEXT REFERENCES assets(id) ON DELETE CASCADE,
    scan_run_id       TEXT REFERENCES scan_runs(id) ON DELETE SET NULL,
    sources           JSONB NOT NULL DEFAULT '[]'::jsonb,
    rule_id           TEXT NOT NULL,
    title             TEXT NOT NULL,
    description       TEXT,
    severity          TEXT NOT NULL,
    cvss              NUMERIC,
    file_path         TEXT,
    line              INT,
    package           TEXT,
    version           TEXT,
    fixed_version     TEXT,
    reachability      TEXT NOT NULL DEFAULT 'unknown',
    risk_score        NUMERIC NOT NULL DEFAULT 0,
    vex_status        TEXT,
    vex_justification TEXT,
    fingerprint       TEXT NOT NULL UNIQUE,
    first_seen        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    raw               JSONB
);

CREATE INDEX IF NOT EXISTS findings_asset_idx     ON findings(asset_id);
CREATE INDEX IF NOT EXISTS findings_severity_idx  ON findings(severity);
CREATE INDEX IF NOT EXISTS findings_reach_idx     ON findings(reachability);
CREATE INDEX IF NOT EXISTS findings_risk_idx      ON findings(risk_score DESC);
