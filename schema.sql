-- Schema SQLite / Postgres para Humo vs Miedo

CREATE TABLE IF NOT EXISTS cves (
    cve_id TEXT PRIMARY KEY,
    published TIMESTAMP,
    last_modified TIMESTAMP,
    description TEXT,
    cvss_score REAL,
    cvss_vector TEXT,
    cvss_severity TEXT,
    raw_json TEXT,
    synced_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS enrichments (
    cve_id TEXT PRIMARY KEY,
    in_kev BOOLEAN DEFAULT 0,
    kev_date TEXT,
    ransomware_use BOOLEAN DEFAULT 0,
    epss REAL,
    epss_percentile REAL,
    poc_count INTEGER DEFAULT 0,
    media_count INTEGER DEFAULT 0,
    tone_score REAL,
    branding BOOLEAN DEFAULT 0,
    brand_name TEXT,
    wild_confirmation BOOLEAN DEFAULT 0,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (cve_id) REFERENCES cves(cve_id)
);

-- UNIQUE(cve_id): un solo score vigente por CVE. El scoring hace UPSERT
-- (ON CONFLICT(cve_id) DO UPDATE) en lugar de acumular filas históricas.
-- Ese UNIQUE ya indexa las búsquedas por CVE: no hace falta un idx aparte.
CREATE TABLE IF NOT EXISTS scores (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT NOT NULL UNIQUE,
    hype REAL,
    reality REAL,
    category TEXT,
    calculated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (cve_id) REFERENCES cves(cve_id)
);

CREATE TABLE IF NOT EXISTS assets (
    asset_id TEXT PRIMARY KEY,
    name TEXT,
    criticality REAL,          -- 1.0 a 10.0
    product TEXT,
    environment TEXT,          -- prod, staging, lab
    owner TEXT
);

CREATE TABLE IF NOT EXISTS cve_assets (
    cve_id TEXT,
    asset_id TEXT,
    adjusted_reality REAL,
    PRIMARY KEY (cve_id, asset_id)
);

CREATE INDEX IF NOT EXISTS idx_cves_published ON cves(published);
CREATE INDEX IF NOT EXISTS idx_scores_date ON scores(calculated_at);
