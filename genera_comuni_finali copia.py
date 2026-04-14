import json

# Percorsi file
COMUNI_FILE = "static/data/comuni.json"
PROVINCE_FILE = "static/data/province.json"
OUTPUT_FILE = "static/data/comuni_finali.json"

# Carica province
with open(PROVINCE_FILE, encoding="utf-8") as f:
    province = json.load(f)

# Mappa nome provincia → regione
provincia_to_regione = {
    p["nome"].lower(): p["regione"]
    for p in province
}

# Carica comuni
with open(COMUNI_FILE, encoding="utf-8") as f:
    comuni = json.load(f)

comuni_finali = []

for c in comuni:
    comune = c["comune"].strip()
    provincia = c.get("provincia", "").strip()

    regione = provincia_to_regione.get(provincia.lower())

    comuni_finali.append({
        "comune": comune,
        "provincia": provincia,
        "regione": regione
    })

# Salva file finale
with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
    json.dump(comuni_finali, f, ensure_ascii=False, indent=2)

print(f"✅ Creato {OUTPUT_FILE} con {len(comuni_finali)} comuni completi")
