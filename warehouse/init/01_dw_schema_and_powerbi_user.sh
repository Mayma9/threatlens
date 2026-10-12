#!/usr/bin/env bash
# Runs once, when the PostgreSQL volume is created (docker-entrypoint-initdb.d).
# - "public" schema: operational tables managed by Django migrations
# - "dw" schema: constellation data warehouse (ELT refresh)
# - powerbi_reader: read-only login for Power BI Desktop, limited to the dw schema
# Note: the postgres image sources this file when it is not executable (Windows checkout),
# so it must not change shell options or call exit. ON_ERROR_STOP stops psql on any error.

psql -v ON_ERROR_STOP=1 \
     --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
     -v app_user="$POSTGRES_USER" \
     -v db_name="$POSTGRES_DB" \
     -v reader_password="$POWERBI_READER_PASSWORD" <<'SQL'
CREATE SCHEMA IF NOT EXISTS dw AUTHORIZATION :"app_user";

CREATE ROLE powerbi_reader LOGIN PASSWORD :'reader_password'
  NOSUPERUSER NOCREATEDB NOCREATEROLE;

GRANT CONNECT ON DATABASE :"db_name" TO powerbi_reader;
GRANT USAGE ON SCHEMA dw TO powerbi_reader;
GRANT SELECT ON ALL TABLES IN SCHEMA dw TO powerbi_reader;

-- Tables created later in dw by the application user are readable too
ALTER DEFAULT PRIVILEGES FOR ROLE :"app_user" IN SCHEMA dw
  GRANT SELECT ON TABLES TO powerbi_reader;

-- Power BI only sees the dw schema
ALTER ROLE powerbi_reader SET search_path = dw;
SQL

echo "dw schema and powerbi_reader role created."
