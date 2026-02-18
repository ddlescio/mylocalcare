# run_daily_matches.py
import os
import sys
from datetime import datetime

# Assicura che il working dir sia la cartella del progetto
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
os.chdir(BASE_DIR)

def main():
    # Importa app e la funzione
    from app import app, processa_match_nuovi_annunci

    # Serve app context perché dentro processa_match usi roba Flask (es. url_for)
    with app.app_context():
        n = processa_match_nuovi_annunci()

    print(f"[{datetime.now().isoformat(timespec='seconds')}] match inseriti: {n}")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print("ERRORE run_daily_matches:", repr(e))
        raise
