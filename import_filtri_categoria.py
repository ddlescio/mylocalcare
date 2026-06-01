import os
import json
import psycopg2

JSON_PATH = "static/data/filtri_categoria.json"
DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL non trovato")

with open(JSON_PATH, "r", encoding="utf-8") as f:
    dati = json.load(f)

conn = psycopg2.connect(DATABASE_URL)
cur = conn.cursor()

for categoria, filtri in dati.items():
    for ordine, filtro in enumerate(filtri, start=1):
        cur.execute("""
            INSERT INTO filtri_categoria (categoria, filtro, ordine, attivo)
            VALUES (%s, %s, %s, 1)
            ON CONFLICT (categoria, filtro)
            DO UPDATE SET
                ordine = EXCLUDED.ordine,
                attivo = 1
        """, (categoria, filtro, ordine))

conn.commit()
cur.close()
conn.close()

print("✅ Filtri categoria importati/aggiornati nel DB.")
