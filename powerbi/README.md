# Power BI

Power BI Desktop reports (`.pbix`) connected to the `dw` schema of the PostgreSQL warehouse. Reports are opened in Power BI Desktop, outside the Django console (specification FR-21).

## Connection

| Parameter | Value |
|---|---|
| Connector | PostgreSQL database (*Get data → Database → PostgreSQL database*) |
| Server | `localhost:5432` |
| Database | `threatlens` (value of `POSTGRES_DB` in `.env`) |
| Data connectivity mode | Import |
| User | `powerbi_reader` |
| Password | value of `POWERBI_READER_PASSWORD` in your `.env` |

The `powerbi_reader` account is read-only and can only see the `dw` schema (created by `warehouse/init/01_dw_schema_and_powerbi_user.sh`). The containers must be running (`docker compose up -d`).

If Power BI asks about encryption, accept connecting without encryption: the database only listens on your own computer.

## Files

| File | Content |
|---|---|
| *(Sprint 2)* `threatlens_exposure.pbix` | first report (US09) |

## KPIs

Documented here as the reports are built (definition, DAX measure, source table).
