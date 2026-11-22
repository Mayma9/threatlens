# ThreatLens

**Cybersecurity Threat Intelligence Data Warehouse with AI-Based Analytics**

ThreatLens collects public cyber threat intelligence (CVE, KEV, EPSS, NVD, CWE, ATT&CK, CTID, ThreatFox) through an ETL pipeline, stores it in a PostgreSQL constellation data warehouse and turns it into decisions:

- a **Django triage console** for security analysts (search, enriched CVE record, watchlist, prioritized alerts, remediation plan);
- **Power BI Desktop reports** for the CISO (exposure, exploitation, remediation KPIs);
- **machine learning models**: CVE severity prediction (M1), exploitation prediction compared with EPSS (M2), APT group clustering (M3).

The full scope is defined in the [requirements specification](docs/specification/CTI_Data_Warehouse_Requirements_Specification_v2.docx), which is the single source of truth.

## Academic context

| | |
|---|---|
| Module | Projet de développement — ING-4 SDIA, TEK-UP |
| Supervisor | Abdelaziz Menchari |
| Academic year | 2026 / 2027 |

## Team

| Member | Scrum role | Lead areas |
|---|---|---|
| Imen Hichri ([@imenHi](https://github.com/imenHi)) | Product Owner | Connectors (KEV, EPSS, NVD, CWE, ThreatFox, ATT&CK, CTID), data quality, data warehouse |
| Oumaima Hafiane ([@Mayma9](https://github.com/Mayma9)) | Scrum Master | CVE List V5 connector, Django console |

Shared: machine learning (M1–M3), Power BI reports, environment setup, code reviews, tests, documentation, demonstration.

## Sprint calendar

| Sprint | Dates | Goal | Validation |
|---|---|---|---|
| Sprint 1 | 08 Oct – 22 Oct 2026 | Foundations and first data slice | Validation 1 — 22 Oct 2026 (design review) |
| Sprint 2 | 23 Oct – 12 Nov 2026 | Complete integration and first alerts | Validation 2 — 12 Nov 2026 |
| Sprint 3 | 13 Nov – 26 Nov 2026 | Machine learning and prioritization | Validation 3 — 26 Nov 2026 |
| Sprint 4 | 27 Nov – 10 Dec 2026 | Finalization | Validation 4 — 10 Dec 2026 (final) |

The product and sprint backlogs live in the GitHub Project **ThreatLens**.

## Tech stack

Python 3.13 · Django 6.1 + Django REST Framework · PostgreSQL (operational schema + `dw` schema) · Pandas · scikit-learn · Jupyter · Power BI Desktop · Docker Compose · GitHub Projects

## Repository structure

```
docker-compose.yml     services: db (PostgreSQL), web (Django), etl (pipeline, same image)
Dockerfile             Python 3.13 image used by web and etl
requirements.txt       pinned runtime dependencies (requirements-dev.txt: tests + Jupyter)
.env.example           environment variables to copy into .env (never committed)
backend/               Django project
  config/              settings, URLs
  accounts/            custom User, roles (US01)
    templates/         layout (accounts/base.html), home, login (registration/), 403 page,
                       admin look (admin/base_site.html overrides Django's)
    static/accounts/   ThreatLens theme: lens.css (shared), threatlens.css (console), admin.css;
                       js/alerts.js shows messages and errors with SweetAlert2
  cti/                 vulnerabilities, CVSS, KEV, CWE, ATT&CK, threat groups, IOCs
  watchlist/           products, aliases, watchlist items
  alerts/              alerts, status history, remediation plans
  pipeline/            pipeline runs, ingestion tasks, run_pipeline command
    connectors/        base connector interface + one connector per source
  ml/                  model versions and predictions
warehouse/
  init/                database initialization (dw schema, Power BI read-only user)
  sql/                 constellation DDL + SQL refresh scripts (ELT) + OLAP queries
ml/notebooks/          exploration and model training (Jupyter)
ml/models/             trained model files (git-ignored)
powerbi/               .pbix reports + connection and KPI documentation
docs/                  specification, UML diagrams, data dictionary
data/staging/          raw source snapshots (git-ignored)
scripts/github/        one-off scripts that created the GitHub settings and backlog
```

Each Django app keeps its own templates in `<app>/templates/<app>/` and its static files in `<app>/static/<app>/` (`APP_DIRS = True`, no project-level template folder). Other apps extend the shared layout with `{% extends "accounts/base.html" %}`.

## Run with Docker

Prerequisites: Git, Docker Desktop (WSL2 backend on Windows) running.

```bash
git clone https://github.com/Mayma9/threatlens.git
cd threatlens
cp .env.example .env          # then replace every "change-me" in .env
docker compose up -d --build  # starts db and web
docker compose ps             # db must be "healthy", web "running"
docker compose exec web python manage.py createsuperuser
```

Open http://localhost:8000/ and log in.

### Demo accounts

Set `DEMO_USER_PASSWORD` in `.env`, restart (`docker compose up -d`), then:

```bash
docker compose exec web python manage.py create_demo_users
```

| Account | Role | Access |
|---|---|---|
| `analyst1` | Security analyst | triage console |
| `ciso1` | CISO | everything the analyst can do + remediation plan approval |
| `admin1` | Administrator | Django admin (users, roles, sources, models), pipeline monitoring |

All three belong to the organization *Demo Bank*. The command can be run again safely.

| Task | Command |
|---|---|
| Logs of the web service | `docker compose logs -f web` |
| Run the tests | `docker compose exec web python manage.py test` |
| Django shell | `docker compose exec web python manage.py shell` |
| PostgreSQL shell | `docker compose exec db psql -U threatlens -d threatlens` |
| Run the ETL pipeline (from US02) | `docker compose run --rm etl` |
| Stop | `docker compose down` |
| Reset the database (deletes all data) | `docker compose down -v` |

### Triage console pages

Open http://localhost:8000 and log in as `analyst1` or `ciso1`.

| Page | URL | User story |
|---|---|---|
| Vulnerability search | `/vulnerabilities/` | US03 |
| Enriched CVE record: CVSS scores by provider, effective severity, EPSS, KEV, CWE, affected products | `/vulnerabilities/CVE-2024-3400/` (or a click on a search result) | US04 |
| Watchlist and product aliases | `/watchlist/` | US07 |
| Prioritized alerts: open alerts sorted by priority score, filters, status / assignee / comment, history, score explained | `/alerts/` | US11 |
| Weekly remediation plan: the analyst selects open alerts and submits the plan, a CISO approves it or requests changes (log in as `ciso1`) | `/plans/` | US13 |

## ETL pipeline

```bash
docker compose run --rm etl python manage.py run_pipeline --source cwe   # MITRE CWE catalog (~1 min)
docker compose run --rm etl python manage.py run_pipeline --source cve   # CVE List V5 + CVE-to-CWE links (first load: 20-40 min)
docker compose run --rm etl python manage.py run_pipeline --source nvd   # NVD scores, CWEs and status (needs the CVEs; first load: about 1 hour, then only the changes)
docker compose run --rm etl python manage.py run_pipeline --source kev   # CISA KEV (needs the CVEs first)
docker compose run --rm etl python manage.py run_pipeline --source epss  # FIRST EPSS scores (needs the CVEs first)
docker compose run --rm etl python manage.py run_pipeline --source threatfox  # abuse.ch ThreatFox IOCs of the last 7 days
docker compose run --rm etl                                              # every active source, in order
```

| Option | Effect |
|---|---|
| `--source NAME` | run one source (repeatable): `cwe`, `cve`, `nvd`, `kev`, `epss`, `threatfox` |
| `--file PATH` | load a local snapshot instead of downloading (one source only) |
| `--full` | reload every record, not only those updated since the last load (`cve`, `nvd`) |
| `--triggered-by USERNAME` | record the administrator who started the run |
| `--scheduled` | scheduler mode (used by `scripts\run_pipeline.bat`): skip the sources whose last successful run is younger than their frequency (`hourly`, `daily`, `weekly`); without this option every selected source runs |

**Frequency (FR-15).** The administrator sets the frequency of each source in the admin (*Sources*: `hourly`, `daily` or `weekly`, `daily` by default) or disables it. The daily Windows task (`scripts\run_pipeline.bat`) runs `run_pipeline --scheduled`: a source runs again only when 90 % of its delay has passed since its last successful run (a failed run does not count, an unknown value counts as `daily`). Keep `threatfox` on `daily`, because its API only returns the last 7 days.

**NVD (US05).** The API key `NVD_API_KEY` of `.env` raises the limit from 5 to 50 requests per 30 seconds. Only the NVD's own data is kept (CVSS scores and CWEs of type *Primary*, status `vulnStatus`, and the CPE prefix of the products whose names match the NVD CPE exactly); since April 2026 NIST no longer scores every CVE, the quality report counts them (`without_nvd_score`). After the first load, each run reads only the CVEs modified since the previous successful run.

**ThreatFox (US05, FR-14).** The Auth-Key `ABUSECH_AUTH_KEY` of `.env` is required. Each run reads the IOCs first seen in the last 7 days (the maximum of the API) and updates those already loaded, so the history grows from the first run on: run the pipeline at least once a week. IOCs are metadata only, never visited or opened (risk R9); they are analyzed in Power BI (`fact_ioc`), not in the console.

Each run is logged in the admin (*Pipeline runs*, *Ingestion tasks*): status, extracted / loaded / rejected counts, quality report and error message.

**Alerts (US08).** At the end of each run, the new or updated CVEs are matched with every watchlist (product names and aliases): one alert per CVE and watched product, status NEW, with a due date (`ALERT_DUE_DAYS` in `settings.py`). The admin page *Alert generations* shows, for each run, the CVEs checked, the alerts created and the unmatched names to review. For CVEs loaded before a product was added to the watchlist:

```bash
docker compose run --rm etl python manage.py generate_alerts --since 2026-10-01
```

**Priority score (US11, FR-10).** Each open alert gets a score from 0 to 100, recomputed at the end of each run (EPSS, KEV and severity change) and when the criticality of a product changes:

| Factor | Value between 0 and 1 | Weight |
|---|---|---|
| Effective severity | effective CVSS score / 10; for a severity predicted by M1, the middle of its class (LOW 0.2, MEDIUM 0.55, HIGH 0.8, CRITICAL 0.95); **0.5** with no score and no prediction | 35 % |
| Exploitation probability | EPSS score | 25 % |
| CISA KEV | 1 when the CVE is in the KEV catalog | 25 % |
| Product criticality | (criticality − 1) / 3, criticality 1 to 4 | 15 % |

The weights are `PRIORITY_WEIGHTS`, `PRIORITY_PREDICTED_SEVERITY` and `PRIORITY_UNSCORED_SEVERITY` in `settings.py` (team decisions, Sprint 3). After changing them: `docker compose exec -T web python manage.py refresh_priorities`. A closed alert keeps the score it had when it was closed. The alert page shows the points of each factor.

**Predicted severity (US10, model M1).** Some CVEs get no CVSS score from the NVD, their CNA or CISA ADP. Model M1 predicts their severity class (LOW, MEDIUM, HIGH, CRITICAL) from what the CNA publishes: description, title, affected products, CWE and the CNA's name (TF-IDF + logistic regression, FR-23). It predicts the 8 CVSS base metrics and applies the official CVSS formula, combined with a direct prediction of the class. After the loading, each run predicts the CVEs without any CVSS score (scoring step, UC19), then computes the effective severity: NVD > CNA > CISA ADP > M1 prediction (FR-06). A predicted severity is always labeled *predicted* in the console, with the model version and the confidence on the CVE record.

```bash
docker compose run --rm etl python manage.py run_pipeline --source cve --full   # once: loads the CNA and the title of every CVE
docker compose run --rm etl python manage.py train_m1 --activate   # trains, evaluates and activates a new version (30-45 min)
docker compose run --rm etl python manage.py score_m1              # predicts now instead of waiting for the next run
```

`train_m1` learns from the CVSS 3.x scores of the CNAs and of the independent analysts (CISA ADP, else the NVD): the two do not score alike, so M1 learns both and predicts the analyst's score for a CVE without score. The settings are chosen on the validation period (Jul 2024 – Jun 2025). The test period (from Jul 2025, the same as the Sprint 1 baseline) is measured twice: with a strict split (a model trained before it, never retrained) and with a model retrained each quarter; `--quick` skips the second measure (about 3 times faster). The model is then refit on every labelled CVE. The file goes to `ml/models/m1_severity_v<N>.joblib` (git-ignored) and the version with its metrics (macro-F1, F1 by class, confusion matrix, scores by scorer, by quarter and by confidence) to the table `ml_mlmodel` and `ml/models/m1_severity_v<N>_metrics.json`. Without `--activate`, the new version is kept but not used. **Retrain every quarter:** new CNAs appear and scoring habits change. The notebook `ml/notebooks/m1_final.ipynb` explains the choices and the results.

**Warehouse (UC21).** The last step of each run rebuilds the `dw` schema by SQL (constellation schema, read by Power BI). By hand, and the FR-20 queries:

```bash
docker compose exec -T web python manage.py refresh_warehouse
docker compose exec -T db psql -U threatlens -d threatlens < warehouse/sql/olap/02_distribution.sql
```

Raw snapshots are kept in `data/staging/<source>/` (last 3 per source, git-ignored). Tables and quality rules: [data dictionary](docs/data_dictionary.md) and [warehouse dictionary](docs/data_warehouse_dictionary.md).

### Daily run (Windows Task Scheduler)

1. Open *Task Scheduler* → *Create Basic Task* → name `ThreatLens pipeline`.
2. Trigger: *Daily*, e.g. 07:00.
3. Action: *Start a program* → `scripts\run_pipeline.bat` in your clone (full path).
4. Docker Desktop must be running at that time. The output goes to `data\staging\pipeline.log`.

After a change to `requirements.txt` or the `Dockerfile`, rebuild with `docker compose up -d --build`. Python code changes are reloaded automatically.

## Run the notebooks (ml/notebooks)

Prerequisites: the Docker database is running with the CVE data loaded (`docker compose up -d`) and your `.env` exists. The notebooks read the PostgreSQL settings from `.env` (`POSTGRES_HOST=localhost`).

```powershell
py -3.13 -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.venv\Scripts\python.exe -m jupyterlab
```

Open `ml/notebooks/m1_baseline.ipynb` (Sprint 1), `m1_improvement.ipynb` or `m1_final.ipynb` (Sprint 3, after `train_m1`) and choose **Kernel → Restart Kernel and Run All Cells**. Running a notebook rewrites its outputs: do not commit the modified `.ipynb` or metrics files unless that is intended.

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a branch: branch naming, commit convention, pull requests and Definition of Done.

## Secrets

API keys (NVD, abuse.ch) and database passwords are stored only in a local `.env` file, which is never committed. A `.env.example` file documents the expected variables.
