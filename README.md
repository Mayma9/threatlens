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
| Imen Hichri ([@imenHi](https://github.com/imenHi)) | Product Owner | Connectors (KEV, EPSS, NVD, CWE, ThreatFox, ATT&CK, CTID), data quality, data warehouse, Power BI |
| Oumaima Hafiane ([@Mayma9](https://github.com/Mayma9)) | Scrum Master | CVE List V5 connector, machine learning (M1–M3), Django console |

Shared: environment setup, code reviews, tests, documentation, demonstration.

## Sprint calendar

| Sprint | Dates | Goal | Validation |
|---|---|---|---|
| Sprint 1 | 08 Oct – 22 Oct 2026 | Foundations and first data slice | Validation 1 — 22 Oct 2026 (design review) |
| Sprint 2 | 23 Oct – 05 Nov 2026 | Complete integration and first alerts | Validation 2 — 05 Nov 2026 |
| Sprint 3 | 06 Nov – 19 Nov 2026 | Machine learning and prioritization | Validation 3 — 19 Nov 2026 |
| Sprint 4 | 20 Nov – 03 Dec 2026 | Finalization | Validation 4 — 03 Dec 2026 (final) |

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
  cti/                 vulnerabilities, CVSS, KEV, CWE, ATT&CK, threat groups, IOCs
  watchlist/           products, aliases, watchlist items
  alerts/              alerts, status history, remediation plans
  pipeline/            pipeline runs, ingestion tasks, run_pipeline command
    connectors/        base connector interface + one connector per source
  ml/                  model versions and predictions
  templates/           shared templates (Bootstrap 5)
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

Open http://localhost:8000/admin/ and log in with the superuser.

| Task | Command |
|---|---|
| Logs of the web service | `docker compose logs -f web` |
| Run the tests | `docker compose exec web python manage.py test` |
| Django shell | `docker compose exec web python manage.py shell` |
| PostgreSQL shell | `docker compose exec db psql -U threatlens -d threatlens` |
| Run the ETL pipeline (from US02) | `docker compose run --rm etl` |
| Stop | `docker compose down` |
| Reset the database (deletes all data) | `docker compose down -v` |

After a change to `requirements.txt` or the `Dockerfile`, rebuild with `docker compose up -d --build`. Python code changes are reloaded automatically.

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a branch: branch naming, commit convention, pull requests and Definition of Done.

## Secrets

API keys (NVD, abuse.ch) and database passwords are stored only in a local `.env` file, which is never committed. A `.env.example` file documents the expected variables.
