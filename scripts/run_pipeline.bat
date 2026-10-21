@echo off
REM Daily ETL run for the Windows Task Scheduler (US02).
REM Runs every active source in order and appends the output to data\staging\pipeline.log.
cd /d "%~dp0\.."
echo ===== %date% %time% ===== >> data\staging\pipeline.log
docker compose run --rm -T etl >> data\staging\pipeline.log 2>&1
