import csv
import json

input_file = "comuni_istat.csv"
output_file = "static/data/comuni.json"

comuni = []

with open(input_file, encoding="latin-1") as f:
    reader = csv.reader(f, delimiter=";")
    header = next(reader)  # salta intestazione

    for row in reader:
        comune = row[5].strip()      # Denominazione in italiano
        provincia = row[11].strip()  # Denominazione provincia

        comuni.append({
            "comune": comune,
            "provincia": provincia
        })

with open(output_file, "w", encoding="utf-8") as f:
    json.dump(comuni, f, ensure_ascii=False, indent=2)

print(f"✅ Creato {output_file} con {len(comuni)} comuni")
