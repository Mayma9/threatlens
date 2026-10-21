# Decisions

Team decisions that change or confirm the specification. Newest first.

| Date | Topic | Decision | Reason | Impact |
|---|---|---|---|---|
| 2026-10-21 | Sprint length (§12.4) | Sprints stay aligned with the official validations, every 2 weeks (22 Oct, 5 Nov, 19 Nov, 3 Dec). | Validation dates are fixed by the school. | Scope is managed with MoSCoW priorities: Could items (US16, US17) are started only once the Must items are done (risk R5). |
| 2026-10-21 | Power BI licence (risk R12) | No Power BI licence: reports are built in Power BI Desktop and opened outside the Django console. | Embedding needs a Pro, Premium or Embedded licence; "Publish to web" would make security data public. | Unchanged from the specification (FR-21). Read-only access through the `powerbi_reader` account on the `dw` schema. |
| 2026-10-21 | ETL tool (risk R8) | The ETL pipeline is written in Python (Django management command `run_pipeline`), not SSIS. | Sources are REST APIs and JSON/CSV feeds; the same code base serves the console and ML; runs in Docker with PostgreSQL. | No SSIS flow is planned. The supervisor is informed at Validation 1. |
