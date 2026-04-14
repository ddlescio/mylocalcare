#!/bin/bash

DB="database.db"

echo "========================================="
echo "🔍 VERIFICA DATABASE LOCALCARE - MONETIZZAZIONE"
echo "========================================="

sqlite3 "$DB" <<'EOF'

.headers on
.mode column

.print ''
.print '=== SERVIZI (catalogo) ==='
.schema servizi
SELECT id, codice, nome, ambito, target, durata_default_giorni, ripetibile, attivo
FROM servizi
ORDER BY id;

.print ''
.print '=== PACCHETTI ==='
.schema pacchetti
SELECT id, codice, nome, attivo
FROM pacchetti
ORDER BY id;

.print ''
.print '=== PACCHETTI_SERVIZI ==='
.schema pacchetti_servizi
SELECT ps.id, p.codice AS pacchetto, s.codice AS servizio
FROM pacchetti_servizi ps
JOIN pacchetti p ON p.id = ps.pacchetto_id
JOIN servizi s ON s.id = ps.servizio_id
ORDER BY p.id;

.print ''
.print '=== PREZZI ==='
.schema prezzi
SELECT tipo, ref_id, durata_giorni, prezzo_cent, valuta, attivo, ordine
FROM prezzi
ORDER BY tipo, ref_id, durata_giorni;

.print ''
.print '=== ACQUISTI ==='
.schema acquisti
SELECT id, utente_id, tipo, ref_id, prezzo_id, metodo, importo_cent, stato, created_at
FROM acquisti
ORDER BY created_at DESC
LIMIT 20;

.print ''
.print '=== ATTIVAZIONI_SERVIZI ==='
.schema attivazioni_servizi
SELECT id, servizio_id, utente_id, annuncio_id,
       data_inizio, data_fine, stato, attivato_da
FROM attivazioni_servizi
ORDER BY data_inizio DESC
LIMIT 20;

.print ''
.print '=== CHECK AMBITO ATTIVAZIONI ==='
SELECT a.id,
       s.codice AS servizio,
       s.ambito,
       a.utente_id,
       a.annuncio_id,
       a.stato
FROM attivazioni_servizi a
JOIN servizi s ON s.id = a.servizio_id
ORDER BY a.id DESC
LIMIT 20;

.print ''
.print '=== OVERRIDE_ADMIN ==='
.schema override_admin
SELECT id, admin_id, servizio_id, utente_id, annuncio_id, data_inizio, data_fine, motivo
FROM override_admin
ORDER BY created_at DESC
LIMIT 20;

.print ''
.print '=== STORICO_SERVIZI ==='
.schema storico_servizi
SELECT id, attivazione_id, azione, eseguito_da, data
FROM storico_servizi
ORDER BY data DESC
LIMIT 20;

.print ''
.print '=== INTEGRITY CHECK ==='
PRAGMA integrity_check;

.print ''
.print '=== FOREIGN KEY CHECK ==='
PRAGMA foreign_key_check;

EOF

echo "========================================="
echo "✅ VERIFICA COMPLETATA"
echo "========================================="
