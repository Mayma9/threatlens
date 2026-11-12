-- warehouse/sql/01_constellation_ddl.sql
-- Constellation schema of section 11.2 of the specification (FR-19): 3 fact tables, 1 bridge table
-- and 11 dimensions in the dw schema. Safe to run many times (CREATE ... IF NOT EXISTS).
--
-- Conventions
--   * The surrogate key of a loaded dimension is the id of the operational row (cti_vulnerability.id,
--     cti_product.id, pipeline_source.id), so keys stay the same from one refresh to the next.
--   * Key 0 is the "unknown" member of a dimension (a CVE with no affected product, no known CWE).
--   * Static members (severity, alert status) and all data are loaded by 02_refresh.sql.
--   * The grain of each fact table is written in its table comment (COMMENT ON TABLE).

CREATE SCHEMA IF NOT EXISTS dw;

-- ============================================================ dimensions

CREATE TABLE IF NOT EXISTS dw.dim_date (
    date_key  integer  PRIMARY KEY,           -- yyyymmdd, for example 20261112
    full_date date     NOT NULL UNIQUE,
    day       smallint NOT NULL,
    week      smallint NOT NULL,
    month     smallint NOT NULL,
    quarter   smallint NOT NULL,
    year      smallint NOT NULL
);

CREATE TABLE IF NOT EXISTS dw.dim_source (
    source_key  integer      PRIMARY KEY,     -- id of pipeline_source
    name        varchar(100) NOT NULL UNIQUE,
    source_type varchar(50)  NOT NULL,
    url         text         NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS dw.dim_vulnerability (
    vuln_key     bigint      PRIMARY KEY,     -- id of cti_vulnerability
    cve_id       varchar(32) NOT NULL UNIQUE,
    description  text        NOT NULL DEFAULT '',
    nvd_status   varchar(32) NOT NULL DEFAULT '',
    published_at date
);

CREATE TABLE IF NOT EXISTS dw.dim_product (
    product_key bigint       PRIMARY KEY,     -- id of cti_product; 0 = unknown product
    vendor      varchar(200) NOT NULL,
    product     varchar(200) NOT NULL,
    cpe_prefix  varchar(200) NOT NULL DEFAULT '',
    is_watched  boolean      NOT NULL DEFAULT false,
    criticality smallint     CHECK (criticality BETWEEN 1 AND 4)
);

CREATE TABLE IF NOT EXISTS dw.dim_weakness (
    weakness_key bigint       PRIMARY KEY,    -- id of cti_weakness; 0 = the CVE record names no CWE
    cwe_id       varchar(32)  NOT NULL UNIQUE,
    name         varchar(300) NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS dw.dim_severity (
    severity_key smallint         PRIMARY KEY,
    label        varchar(16)      NOT NULL UNIQUE,
    score_min    double precision,
    score_max    double precision
);

CREATE TABLE IF NOT EXISTS dw.dim_technique (
    technique_key bigint       PRIMARY KEY,
    technique_id  varchar(32)  NOT NULL UNIQUE,
    name          varchar(300) NOT NULL,
    tactic        varchar(100) NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS dw.dim_alert_status (
    status_key smallint    PRIMARY KEY,
    label      varchar(32) NOT NULL UNIQUE,
    is_open    boolean     NOT NULL
);

CREATE TABLE IF NOT EXISTS dw.dim_indicator (
    indicator_key bigint       PRIMARY KEY,
    value         varchar(500) NOT NULL,
    ioc_type      varchar(50)  NOT NULL
);

CREATE TABLE IF NOT EXISTS dw.dim_malware (
    malware_key bigint       PRIMARY KEY,
    family      varchar(200) NOT NULL,
    category    varchar(100) NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS dw.dim_threat_type (
    threat_type_key smallint     PRIMARY KEY,
    label           varchar(100) NOT NULL UNIQUE,
    description     text         NOT NULL DEFAULT ''
);

-- ============================================================ bridge

CREATE TABLE IF NOT EXISTS dw.bridge_cve_technique (
    vuln_key       bigint      NOT NULL REFERENCES dw.dim_vulnerability,
    technique_key  bigint      NOT NULL REFERENCES dw.dim_technique,
    mapping_source varchar(50) NOT NULL DEFAULT '',
    PRIMARY KEY (vuln_key, technique_key)
);

-- ============================================================ fact tables

CREATE TABLE IF NOT EXISTS dw.fact_vulnerability (
    vuln_key             bigint   NOT NULL REFERENCES dw.dim_vulnerability,
    product_key          bigint   NOT NULL REFERENCES dw.dim_product,
    published_date_key   integer  REFERENCES dw.dim_date,       -- empty when the CVE has no publication date
    kev_date_key         integer  REFERENCES dw.dim_date,       -- empty when the CVE is not in KEV
    weakness_key         bigint   NOT NULL REFERENCES dw.dim_weakness,
    severity_key         smallint NOT NULL REFERENCES dw.dim_severity,
    source_key           integer  NOT NULL REFERENCES dw.dim_source,
    cvss_score           double precision CHECK (cvss_score BETWEEN 0 AND 10),  -- empty when no score
    epss_score           double precision CHECK (epss_score BETWEEN 0 AND 1),   -- empty when not in the EPSS file
    epss_percentile      double precision CHECK (epss_percentile BETWEEN 0 AND 1),
    is_kev               boolean  NOT NULL,
    days_to_kev          integer,                                -- KEV date minus publication date
    exploit_probability  double precision CHECK (exploit_probability BETWEEN 0 AND 1),  -- M2, Sprint 3
    is_severity_predicted boolean NOT NULL DEFAULT false,        -- M1, Sprint 3
    PRIMARY KEY (vuln_key, product_key)
);

CREATE TABLE IF NOT EXISTS dw.fact_alert (
    alert_id          bigint   PRIMARY KEY,                      -- id of alerts_alert (gives the grain a key)
    vuln_key          bigint   NOT NULL REFERENCES dw.dim_vulnerability,
    product_key       bigint   NOT NULL REFERENCES dw.dim_product,
    severity_key      smallint NOT NULL REFERENCES dw.dim_severity,
    status_key        smallint NOT NULL REFERENCES dw.dim_alert_status,
    created_date_key  integer  NOT NULL REFERENCES dw.dim_date,
    closed_date_key   integer  REFERENCES dw.dim_date,           -- empty while the alert is open
    priority_score    double precision NOT NULL DEFAULT 0,
    criticality       smallint NOT NULL CHECK (criticality BETWEEN 1 AND 4),
    days_open         integer  NOT NULL,
    is_kev            boolean  NOT NULL,
    is_overdue        boolean  NOT NULL
);

CREATE TABLE IF NOT EXISTS dw.fact_ioc (
    indicator_key        bigint   NOT NULL REFERENCES dw.dim_indicator,
    first_seen_date_key  integer  NOT NULL REFERENCES dw.dim_date,
    malware_key          bigint   REFERENCES dw.dim_malware,
    threat_type_key      smallint NOT NULL REFERENCES dw.dim_threat_type,
    source_key           integer  NOT NULL REFERENCES dw.dim_source,
    ioc_count            integer  NOT NULL DEFAULT 1,
    confidence           integer  CHECK (confidence BETWEEN 0 AND 100),
    PRIMARY KEY (indicator_key, first_seen_date_key, source_key)
);

-- ============================================================ grain of each fact table

COMMENT ON TABLE dw.fact_vulnerability IS 'Grain: one row per CVE x affected product (count CVEs with DISTINCTCOUNT of vuln_key). Keeps the primary CWE only.';
COMMENT ON TABLE dw.fact_alert IS 'Grain: one row per alert, rebuilt at each run.';
COMMENT ON TABLE dw.fact_ioc IS 'Grain: one row per indicator x first-seen day x source.';

-- ============================================================ read access for Power BI

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'powerbi_reader') THEN
        GRANT USAGE ON SCHEMA dw TO powerbi_reader;
        GRANT SELECT ON ALL TABLES IN SCHEMA dw TO powerbi_reader;
    END IF;
END
$$;
