import os


# Il cron riusa servizi applicativi senza avviare i loop permanenti dei web
# worker. Oltre al consumer immediato, offre un recupero periodico dell'outbox
# dopo eventuali restart simultanei dei processi web.
if not os.getenv("RUNTIME_SERVICE", "").strip():
    os.environ["RUNTIME_SERVICE"] = "job"

from app import app, processa_referenze_notifiche_outbox_once
from services import aggiorna_servizi_scaduti

if __name__ == "__main__":
    with app.app_context():
        updated = aggiorna_servizi_scaduti()
        print(f"Servizi scaduti aggiornati: {updated}", flush=True)
        outbox = processa_referenze_notifiche_outbox_once()
        print(f"Outbox notifiche referenze: {outbox}", flush=True)
