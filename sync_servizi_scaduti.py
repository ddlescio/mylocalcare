from app import app
from services import aggiorna_servizi_scaduti

if __name__ == "__main__":
    with app.app_context():
        updated = aggiorna_servizi_scaduti()
        print(f"Servizi scaduti aggiornati: {updated}", flush=True)
