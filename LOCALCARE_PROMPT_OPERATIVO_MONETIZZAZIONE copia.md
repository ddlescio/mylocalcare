# 🧠 PROMPT OPERATIVO – LOCALCARE (MONETIZZAZIONE)
**Servizi · Pacchetti · Prezzi · Acquisti · Attivazioni · UI · Logica**

> **Scopo del file:** riprendere il lavoro *senza perdere focus*, *senza riscrivere nulla di già fatto*, seguendo una roadmap **a step obbligatori e verificati**.  
> **Regola chiave:** si procede **UNO step alla volta**. Nessun salto di step.  
> **Stato del progetto:** monetizzazione **già funzionante lato admin**, da completare **lato utente (pagamento + attivazione)**.

---

## 0) CONTESTO (SEMPRE VERO)

LocalCare è un marketplace locale con:
- utenti registrati
- profili pubblici
- annunci (offro / cerco)
- chat interna
- recensioni

La **monetizzazione** si basa su:
- **servizi singoli** (annuncio o utente)
- **pacchetti combo** (solo combinazioni di servizi esistenti)
- **prezzi** configurabili da admin (durata / importo)
- **acquisti** (pagamento, promo, override)
- **attivazioni** con durata, scadenza, revoca e audit log

⚠️ Tutta la logica **admin → attivazione servizio** è **GIÀ IMPLEMENTATA E FUNZIONANTE**.

---

## 1) PRINCIPI VINCOLANTI (NON VIOLABILI)

1. **Uno step alla volta**
2. **Mai scrivere codice** senza:
   - conferma stato DB reale
   - conferma di cosa è già funzionante
3. **Mai hardcodare prezzi o durate**
4. Ogni servizio deve essere:
   - attivabile
   - disattivabile
   - tracciabile
   - reversibile
5. Separazione netta:
   - modello concettuale
   - database
   - backend
   - UI
6. **Admin override totale**
7. **Nessuna promessa ingannevole**
8. UX sempre trasparente:
   - prima dell’acquisto
   - durante l’attivazione
   - dopo la scadenza

---

## 2) MODELLO CONCETTUALE (DEFINITIVO)

### 2.1 Distinzione chiave
- **Servizi ANNUNCIO** → `annuncio_id`
- **Servizi UTENTE** → `utente_id`, `annuncio_id = NULL`

⚠️ Non vanno mai confusi.

---

### 2.2 Catalogo servizi (GIÀ DEFINITO)

| Servizio | Livello | Nota UX |
|---|---|---|
| Boost lista | Annuncio | migliora ranking (senza garanzie) |
| Evidenza | Annuncio | badge + visibilità |
| Vetrina | Annuncio | sezione / slot |
| Urgente | Annuncio | servizio singolo multi-effetto |
| Contatti | Utente | sblocca contatti profilo + annunci |

✔️ Tutti questi servizi:
- esistono in DB
- funzionano già se attivati da admin
- applicano correttamente gli effetti

---

### 2.3 CONTATTI (regola definitiva)

**Contatti = servizio UTENTE**

Sblocca:
- contatti nel profilo
- contatti in **tutti** gli annunci (presenti e futuri)

#### Tipologie
1. **Contatti temporanei**
   - 3 / 7 / 14 giorni
2. **Contatti permanenti**
   - senza scadenza (`durata_giorni = NULL`)

#### Contatti nei pacchetti
- solo **temporanei**
- validi **solo per la durata del pacchetto**

✅ Regola di priorità:
I contatti sono visibili se **almeno una** condizione è vera:
- contatti permanenti attivi
- contatti temporanei attivi
- contatti attivi via pacchetto non scaduto

⚠️ La scadenza di un pacchetto **non deve mai disattivare** contatti permanenti.

---

### 2.4 URGENTE (definitivo)

- **NON è un pacchetto**
- è un **servizio singolo**
- quando attivo applica:
  - boost
  - vetrina
  - contatti temporanei
  - + effetti già previsti dalla logica esistente

Durate:
- 48h
- 3 giorni
- 7 giorni

⚠️ Urgente:
- manda notifiche a utenti compatibili
- la logica notifiche **esiste già**
- va solo collegata all’attivazione utente

---

### 2.5 Pacchetti combo (definitivi)

I pacchetti **non creano nuovi servizi**.

- **Visibilità**
  - boost
  - evidenza
  - contatti temporanei
- **Visibilità Premium**
  - boost
  - evidenza
  - vetrina
  - contatti temporanei

---

## 3) COSA È GIÀ COMPLETATO (NON TOCCARE)

✔️ STEP 1 — Verifica DB  
✔️ STEP 2 — Catalogo servizi  
✔️ STEP 3 — Pacchetti combo  
✔️ STEP 4 — Prezzi (struttura)  
✔️ STEP 5 — Modello acquisti  
✔️ STEP 6 — Attivazioni  
✔️ STEP 7 — Audit log  
✔️ STEP 8 — Override admin  
✔️ STEP 9 — Logica effetti (ranking, badge, contatti, urgente)

👉 Tutto questo **funziona già** quando l’attivazione è fatta da admin.

---

## 4) COSA MANCA DAVVERO (UNICO OBIETTIVO ATTUALE)

❌ **Flusso UTENTE → acquisto → pagamento → attivazione**

In particolare:
- creazione acquisto da parte utente
- scelta durata/prezzo (da DB)
- pagamento (inizialmente simulato)
- cambio stato acquisto (`pagato`)
- attivazione servizio usando **la logica già esistente**
- scrittura audit log

⚠️ **NON va riscritta la logica di attivazione**  
⚠️ **NON vanno duplicati effetti**  
⚠️ **NON va toccata la parte admin**

---

## 5) ROADMAP AGGIORNATA (RIDOTTA E REALISTICA)

### 🔥 STEP 10A — Flusso UTENTE (LOGICO)
**Obiettivo:** definire il flusso completo **senza UI e senza codice**

- punto di ingresso dell’utente
- selezione servizio / pacchetto
- selezione durata / prezzo
- creazione record `acquisti`
- pagamento
- attivazione automatica
- gestione scadenza

**Done quando:** il flusso è definitivo e non ambiguo.

---

### 🟡 STEP 10B — Modale “Aumenta visibilità”
**Obiettivo:** UI per annuncio che mostra:
- servizi applicabili
- stato attuale / scadenza
- CTA: Scopri / Attivo / Prolunga
- pacchetti disponibili

⚠️ Niente prezzi hardcoded.

---

### 🟢 STEP 11 — Testi definitivi
- servizi singoli
- pacchetti
- urgente
- contatti temporanei vs permanenti

Copy:
- chiaro
- trasparente
- senza promesse ingannevoli

---

## 6) STATO ATTUALE

- **Step corrente:** 🔥 **STEP 10A — Flusso UTENTE**
- **Nota:** tutto ciò che precede è già fatto e non va rifatto

---

## 7) REGOLA OPERATIVA PER LE PROSSIME RISPOSTE

- un solo micro-step per volta
- nessun codice finché il flusso non è chiuso
- ogni decisione nuova viene scritta qui

---

**Fine file.**
