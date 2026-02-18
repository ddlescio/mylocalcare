#!/bin/bash

# ==========================================================
# CONFRONTO SCHEMA DATABASE
# DB reale  vs  DB generato da init_dp.py
# ==========================================================

DB_REALE="database.db"
DB_INIT="__initdb_test.db"
INIT_SCRIPT="init_db.py"

echo "========================================="
echo "🔍 CONFRONTO SCHEMA: DB REALE vs INITDB"
echo "========================================="

# ----------------------------------------------------------
# 1️⃣ CONTROLLI PRELIMINARI
# ----------------------------------------------------------

if [ ! -f "$DB_REALE" ]; then
  echo "❌ database.db non trovato"
  exit 1
fi

if [ ! -f "$INIT_SCRIPT" ]; then
  echo "❌ init_dp.py non trovato"
  exit 1
fi

# ----------------------------------------------------------
# 2️⃣ PULIZIA EVENTUALE DB TEMPORANEO
# ----------------------------------------------------------

rm -f "$DB_INIT"

# ----------------------------------------------------------
# 3️⃣ CREAZIONE DB PULITO DA INIT
# ----------------------------------------------------------

echo "▶️ Creazione database temporaneo da $INIT_SCRIPT"

python3 "$INIT_SCRIPT" >/dev/null 2>&1

if [ ! -f "database.db" ]; then
  echo "❌ Errore: init_dp.py non ha creato database.db"
  exit 1
fi

# Rinomina il DB appena creato
mv database.db "$DB_INIT"

# ----------------------------------------------------------
# 4️⃣ FUNZIONE DUMP SCHEMA
# ----------------------------------------------------------

dump_schema () {
  sqlite3 "$1" <<'EOF'
.headers off
.mode list

SELECT 'TABLE|' || name || '|' || sql
FROM sqlite_master
WHERE type='table'
AND name NOT LIKE 'sqlite_%'
ORDER BY name;

SELECT 'INDEX|' || name || '|' || tbl_name || '|' || sql
FROM sqlite_master
WHERE type='index'
AND sql IS NOT NULL
ORDER BY name;
EOF
}

# ----------------------------------------------------------
# 5️⃣ ESTRAZIONE SCHEMI
# ----------------------------------------------------------

echo "▶️ Estrazione schema DB reale"
dump_schema "$DB_REALE" > /tmp/schema_reale.txt

echo "▶️ Estrazione schema INITDB"
dump_schema "$DB_INIT" > /tmp/schema_init.txt

# ----------------------------------------------------------
# 6️⃣ DIFF
# ----------------------------------------------------------

echo "========================================="
echo "📊 DIFFERENZE TROVATE (se presenti)"
echo "========================================="

diff -u /tmp/schema_init.txt /tmp/schema_reale.txt || true

# ----------------------------------------------------------
# 7️⃣ CLEANUP
# ----------------------------------------------------------

rm -f "$DB_INIT"

echo
echo "========================================="
echo "✅ CONFRONTO COMPLETATO"
echo "========================================="
