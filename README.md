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
docs/                  specification, UML diagrams, data dictionary
scripts/github/        one-off scripts that create the GitHub repository settings and backlog
```

The application structure (`backend/`, `warehouse/`, `ml/`, `powerbi/`, `data/`) is added in Sprint 1 (see the Sprint 1 setup issues).

## Getting started

Prerequisites: Git, Docker Desktop (WSL2 backend on Windows), Python 3.13, GitHub CLI.

```bash
git clone https://github.com/Mayma9/threatlens.git
cd threatlens
```

Docker instructions will be added with the Docker Compose setup issue.

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a branch: branch naming, commit convention, pull requests and Definition of Done.

## Secrets

API keys (NVD, abuse.ch) and database passwords are stored only in a local `.env` file, which is never committed. A `.env.example` file documents the expected variables.
