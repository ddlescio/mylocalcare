#!/usr/bin/env bash
set -euo pipefail

DB="database.db"

echo "========================================="
echo "RIPRISTINO SCHEMA MONETIZZAZIONE"
echo "========================================="

if [ ! -f "$DB" ]; then
  echo "ERRORE: $DB non trovato."
  exit 1
fi

TS="$(date +%Y%m%d_%H%M%S)"
BK="backup_${DB%.db}_${TS}.db"
cp -p "$DB" "$BK"
echo "Backup creato: $BK"

echo "Applico aggiornamenti schema..."

sqlite3 "$DB" <<'SQL'
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS pacchetti (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  codice TEXT UNIQUE NOT NULL,
  nome TEXT NOT NULL,
  descrizione TEXT,
  attivo INTEGER DEFAULT 1,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS pacchetti_servizi (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  pacchetto_id INTEGER NOT NULL,
  servizio_id INTEGER NOT NULL,
  created_at TEXT DEFAULT (datetime('now')),
  UNIQUE(pacchetto_id, servizio_id),
  FOREIGN KEY (pacchetto_id) REFERENCES pacchetti(id),
  FOREIGN KEY (servizio_id) REFERENCES servizi(id)
);

CREATE TABLE IF NOT EXISTS prezzi (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tipo TEXT NOT NULL CHECK(tipo IN ('servizio','pacchetto')),
  ref_id INTEGER NOT NULL,
  durata_giorni INTEGER,
  prezzo_cent INTEGER NOT NULL,
  valuta TEXT DEFAULT 'EUR',
  attivo INTEGER DEFAULT 1,
  ordine INTEGER DEFAULT 0,
  stripe_price_id TEXT,
  paypal_plan_id TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  UNIQUE(tipo, ref_id, durata_giorni)
);

CREATE TABLE IF NOT EXISTS acquisti (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  utente_id INTEGER NOT NULL,
  tipo TEXT NOT NULL CHECK(tipo IN ('servizio','pacchetto')),
  ref_id INTEGER NOT NULL,
  prezzo_id INTEGER,
  metodo TEXT NOT NULL,
  importo_cent INTEGER DEFAULT 0,
  valuta TEXT DEFAULT 'EUR',
  stato TEXT DEFAULT 'creato',
  riferimento_esterno TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (utente_id) REFERENCES utenti(id),
  FOREIGN KEY (prezzo_id) REFERENCES prezzi(id)
);

ALTER TABLE attivazioni_servizi
ADD COLUMN acquisto2_id INTEGER;

CREATE INDEX IF NOT EXISTS idx_acquisti_utente
ON acquisti(utente_id);

CREATE INDEX IF NOT EXISTS idx_acquisti_tipo_ref
ON acquisti(tipo, ref_id);

CREATE INDEX IF NOT EXISTS idx_attivazioni_acquisto2
ON attivazioni_servizi(acquisto2_id);

SQL

echo "Schema monetizzazione applicato correttamente."
