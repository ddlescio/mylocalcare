#!/bin/zsh
set -e

PROJECT_DIR="/Users/davidelescio/Library/CloudStorage/GoogleDrive-ddlescio@gmail.com/Altri computer/Il mio laptop (1)/PROGRAMMAZIONE/LOCALCARE"
PY="/usr/local/bin/python3"
LOG_DIR="$PROJECT_DIR/logs"
LOG_FILE="$LOG_DIR/daily_matches.log"

mkdir -p "$LOG_DIR"
cd "$PROJECT_DIR"

/bin/date "+[%Y-%m-%d %H:%M:%S] START run_daily_matches" >> "$LOG_FILE"
"$PY" run_daily_matches.py >> "$LOG_FILE" 2>&1
/bin/date "+[%Y-%m-%d %H:%M:%S] END run_daily_matches" >> "$LOG_FILE"
echo "--------------------------------------------------" >> "$LOG_FILE"
