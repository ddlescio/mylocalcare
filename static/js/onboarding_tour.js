(function () {

  "use strict";

  const TOUR_STEPS = [
    {
      title: "Completa prima il tuo profilo",
      action: "Per iniziare, carica una foto profilo.",
      text: "Tocca l’icona profilo nella barra in alto, poi carica una foto per rendere il tuo account più riconoscibile.",
      image: "/static/img/onboarding/step-1-home.png",
      cursorText: "Vado al profilo",
      caption: { top: "14%", left: "38%" },
      cursorStart: { top: "72%", left: "50%" },
      cursorEnd: { top: "7%", left: "63%" }
    },
    {
      title: "Carica la tua foto",
      action: "Tocca il cerchio della foto profilo.",
      text: "Una foto chiara aumenta fiducia e credibilità.",
      image: "/static/img/onboarding/step-3-carica-foto.png",
      cursorText: "Carico la foto",
      caption: { top: "12%", left: "50%" },
      cursorStart: { top: "75%", left: "50%" },
      cursorEnd: { top: "38%", left: "50%" }
    },
    {
      title: "Compila le informazioni di base",
      action: "Prima tocca Info, poi apri Informazioni di base.",
      text: "Questi dati servono per mostrarti annunci più coerenti con la tua zona e i tuoi interessi.",
      image: "/static/img/onboarding/step-4-info-base.png",
      cursorText: "Apri Info",
      caption: { top: "9%", left: "72%" },
      cursorStart: { top: "18%", left: "43%" },
      cursorEnd: { top: "30%", left: "34%" }
    },
    {
      title: "Aggiungi città e lingue",
      action: "Inserisci la città e seleziona le lingue che conosci.",
      text: "Ad esempio puoi selezionare Italiano e Inglese.",
      image: "/static/img/onboarding/step-5-lingue.png",
      cursorText: "Le lingue che parli",
      caption: { top: "12%", left: "50%" },
      cursorStart: { top: "75%", left: "50%" },
      cursorEnd: { top: "57%", left: "58%" }
    },
    {
      title: "Indica cosa offri o cerchi",
      action: "Seleziona le categorie che ti interessano.",
      text: "Puoi scegliere se offri un servizio o se cerchi aiuto in quella categoria.",
      image: "/static/img/onboarding/step-6-offro-cerco.png",
      cursorText: "Scelgo Offro / Cerco",
      caption: { top: "10%", left: "50%" },
      cursorStart: { top: "30%", left: "50%" },
      cursorEnd: { top: "48%", left: "78%" }
    },
    {
      title: "Torna alla Home",
      action: "Dalla barra in alto puoi tornare alla Home.",
      text: "Ora sei pronto per cercare persone e servizi vicino a te.",
      image: "/static/img/onboarding/step-7-torna-home.png",
      cursorText: "Torno alla Home",
      caption: { top: "14%", left: "58%" },
      cursorStart: { top: "76%", left: "50%" },
      cursorEnd: { top: "7%", left: "28%" }
    },
    {
      title: "Cerca una categoria",
      action: "Esempio: vuoi cercare una babysitter.",
      text: "Tocca direttamente la card della categoria che ti interessa.",
      image: "/static/img/onboarding/step-8-home-cerca.png",
      cursorText: "Cerco una babysitter",
      caption: { top: "10%", left: "50%" },
      cursorStart: { top: "78%", left: "50%" },
      cursorEnd: { top: "34%", left: "31%" }
    },
    {
      title: "Usa i filtri e apri un annuncio",
      action: "Puoi usare i filtri per una ricerca più mirata.",
      text: "Filtra per zona, servizio o categoria, poi tocca una card per aprire il dettaglio dell’annuncio.",
      image: "/static/img/onboarding/step-9-lista-babysitter.png",
      moves: [
        {
          caption: "Usa i filtri",
          captionPosition: { top: "13%", left: "50%" },
          start: { top: "78%", left: "50%" },
          end: { top: "14%", left: "31%" }
        },
        {
          caption: "Apro l’annuncio",
          captionPosition: { top: "13%", left: "50%" },
          start: { top: "14%", left: "31%" },
          end: { top: "45%", left: "50%" }
        }
      ]
    },
    {
      title: "Controlla profilo, recensioni e contatta",
      action: "Prima di scrivere puoi controllare profilo e recensioni.",
      text: "Quando hai trovato una persona interessante, puoi aprire il profilo, guardare le recensioni e poi contattarla in chat.",
      image: "/static/img/onboarding/step-10-annuncio-maria93.png",
      moves: [
        {
          caption: "Controllo il profilo",
          captionPosition: { top: "13%", left: "50%" },
          start: { top: "78%", left: "50%" },
          end: { top: "37%", left: "38%" }
        },
        {
          caption: "Guardo le recensioni",
          captionPosition: { top: "13%", left: "50%" },
          start: { top: "37%", left: "38%" },
          end: { top: "37%", left: "65%" }
        },
        {
          caption: "Scrivo in chat",
          captionPosition: { top: "13%", left: "50%" },
          start: { top: "37%", left: "65%" },
          end: { top: "43%", left: "50%" }
        }
      ]
    },
    {
      title: "Crea un tuo annuncio",
      action: "Dalla Home puoi tornare al tuo profilo.",
      text: "Per pubblicare un annuncio, entra nel profilo e usa il pulsante Crea annuncio.",
      image: "/static/img/onboarding/step-1-home.png",
      cursorText: "Vado al profilo",
      caption: { top: "14%", left: "38%" },
      cursorStart: { top: "72%", left: "50%" },
      cursorEnd: { top: "7%", left: "63%" }
    },
    {
      title: "Apri la creazione annuncio",
      action: "Tocca il pulsante Crea annuncio.",
      text: "Da qui puoi pubblicare un annuncio per offrire un servizio o cercare aiuto.",
      image: "/static/img/onboarding/step-3-carica-foto.png",
      moves: [
        {
          caption: "Creo un annuncio",
          captionPosition: { top: "12%", left: "50%" },
          start: { top: "75%", left: "50%" },
          end: { top: "58%", left: "50%" }
        }
      ]
    },
    {
      title: "Compila i campi principali",
      action: "Inserisci tipo annuncio, categoria, zona, titolo e descrizione.",
      text: "Più l’annuncio è chiaro, più sarà facile ricevere contatti adatti.",
      image: "/static/img/onboarding/step-11-nuovo-annuncio-campi.png",
      moves: [
        {
          caption: "Compila i campi",
          captionPosition: { top: "12%", left: "50%" },
          start: { top: "20%", left: "50%" },
          end: { top: "64%", left: "50%" }
        },
        {
          caption: "Scrivi la descrizione",
          captionPosition: { top: "12%", left: "50%" },
          start: { top: "64%", left: "50%" },
          end: { top: "79%", left: "50%" }
        },
        {
          caption: "Fatti aiutare dall’AI",
          captionPosition: { top: "12%", left: "50%" },
          start: { top: "79%", left: "50%" },
          end: { top: "66%", left: "66%" }
        }
      ]
    },
    {
      title: "Pubblica l’annuncio",
      action: "Quando hai finito, invia l’annuncio per la revisione.",
      text: "Dopo l’approvazione sarà visibile nella categoria scelta.",
      image: "/static/img/onboarding/step-12-nuovo-annuncio-pubblica.png",
      moves: [
        {
          caption: "Pubblica annuncio",
          captionPosition: { top: "12%", left: "50%" },
          start: { top: "25%", left: "50%" },
          end: { top: "78%", left: "50%" }
        }
      ]
    }
  ];

  let currentStep = 0;

  let animationTimers = [];

  let autoAdvanceTimer = null;

  function clearAutoAdvanceTimer() {
    if (autoAdvanceTimer) {
      clearTimeout(autoAdvanceTimer);
      autoAdvanceTimer = null;
    }
  }

  function getAutoAdvanceDelay(step) {
    const movesCount = step.moves ? step.moves.length : 1;

    // Ogni movimento dura circa 3300 ms.
    // Aggiungiamo una pausa finale per far leggere il testo.
    return (movesCount * 2800) + 1800;

  }

  function scheduleAutoAdvance(step) {
    clearAutoAdvanceTimer();

    autoAdvanceTimer = setTimeout(() => {
      if (currentStep >= TOUR_STEPS.length - 1) {
        closeTour();
        return;
      }

      currentStep += 1;
      renderStep();
    }, getAutoAdvanceDelay(step));
  }

  function clearAnimationTimers() {

    animationTimers.forEach(timer => clearTimeout(timer));

    animationTimers = [];

  }

  function setTimer(fn, delay) {

    const timer = setTimeout(fn, delay);

    animationTimers.push(timer);

  }

  function createTourModal() {

    if (document.getElementById("onboarding-tour-modal")) return;

    const modal = document.createElement("div");

    modal.id = "onboarding-tour-modal";

    modal.className = "fixed inset-0 z-[99999] hidden items-start justify-center bg-slate-950/70 backdrop-blur-sm px-3 pt-[calc(env(safe-area-inset-top)+5rem)] pb-4 overflow-y-auto";

    modal.innerHTML = `

      <div class="w-full max-w-[540px] max-h-[calc(100dvh-6rem)] rounded-[2rem] bg-white shadow-2xl overflow-hidden border border-white/70 flex flex-col">

        <div class="relative bg-slate-100">

          <div class="relative h-[330px] min-[390px]:h-[390px] sm:h-[520px] overflow-hidden bg-slate-100">

            <img id="onboarding-tour-image"

                 src=""

                 alt=""

                 class="w-full h-full object-contain bg-slate-100">

            <div id="onboarding-tour-caption"

                 class="absolute top-4 left-1/2 -translate-x-1/2 z-20 rounded-full bg-white/95 px-4 py-2 text-sm font-black text-blue-700 shadow-lg border border-blue-100 whitespace-nowrap">

            </div>

            <div id="onboarding-tour-cursor"

                 class="absolute z-30 -translate-x-1/2 -translate-y-1/2 transition-all duration-1000 ease-in-out">

              <div class="relative">

                <span class="absolute -inset-3 rounded-full bg-blue-500/20 animate-ping"></span>

                <div class="relative w-10 h-10 rounded-full bg-white shadow-xl border border-blue-100 flex items-center justify-center text-xl">

                  👆

                </div>

              </div>

            </div>

            <div id="onboarding-tour-click"

                 class="absolute z-20 hidden -translate-x-1/2 -translate-y-1/2">

              <span class="block w-12 h-12 rounded-full border-4 border-blue-500 animate-ping"></span>

            </div>

          </div>

          <button type="button"

                  id="onboarding-tour-close"

                  class="absolute top-4 right-4 w-10 h-10 rounded-full bg-white text-slate-600 hover:text-slate-900 font-black shadow-lg border border-slate-100">

            ×

          </button>

        </div>

        <div class="p-5 sm:p-6 space-y-4">

          <div>

            <p id="onboarding-tour-counter" class="text-xs font-black text-blue-600 mb-1"></p>

            <h2 id="onboarding-tour-title" class="text-2xl font-black text-slate-950 leading-tight"></h2>

            <p id="onboarding-tour-action"

               class="mt-3 rounded-2xl bg-blue-50 border border-blue-100 px-4 py-3 text-sm font-extrabold text-blue-800 leading-relaxed">

            </p>

            <p id="onboarding-tour-text" class="mt-3 text-sm text-slate-600 leading-relaxed"></p>

          </div>

          <div class="flex items-center justify-between gap-3 pt-1">

            <button type="button"

                    id="onboarding-tour-prev"

                    class="px-5 py-3 rounded-2xl border border-slate-200 text-slate-700 font-extrabold bg-white disabled:opacity-40">

              Indietro

            </button>

            <button type="button"

                    id="onboarding-tour-next"

                    class="px-6 py-3 rounded-2xl bg-blue-600 hover:bg-blue-700 text-white font-extrabold shadow-lg shadow-blue-200">

              Avanti

            </button>

          </div>

        </div>

      </div>

    `;

    document.body.appendChild(modal);

    document.getElementById("onboarding-tour-close").addEventListener("click", closeTour);

    document.getElementById("onboarding-tour-prev").addEventListener("click", prevStep);

    document.getElementById("onboarding-tour-next").addEventListener("click", nextStep);

  }

  function animateCursor(step) {
    clearAnimationTimers();

    const cursor = document.getElementById("onboarding-tour-cursor");
    const click = document.getElementById("onboarding-tour-click");
    const caption = document.getElementById("onboarding-tour-caption");

    const moves = step.moves || [
      {
        caption: step.cursorText,
        captionPosition: step.caption,
        start: step.cursorStart,
        end: step.cursorEnd
      }
    ];

    if (!moves.length) return;

    let delay = 0;

    moves.forEach((move, index) => {
      setTimer(() => {
        caption.textContent = move.caption || step.cursorText || "";

        if (move.captionPosition) {
          caption.style.top = move.captionPosition.top;
          caption.style.left = move.captionPosition.left;
        }

        cursor.style.top = move.start.top;
        cursor.style.left = move.start.left;
        click.classList.add("hidden");
      }, delay);

      setTimer(() => {
        click.style.top = move.start.top;
        click.style.left = move.start.left;
        click.classList.remove("hidden");
      }, delay + 250);

      setTimer(() => {
        click.classList.add("hidden");
      }, delay + 850);

      setTimer(() => {
        cursor.style.top = move.end.top;
        cursor.style.left = move.end.left;
      }, delay + 1050);

      setTimer(() => {
        click.style.top = move.end.top;
        click.style.left = move.end.left;
        click.classList.remove("hidden");
      }, delay + 2150);

      setTimer(() => {
        click.classList.add("hidden");
      }, delay + 2950);

      delay += 3300;
    });
  }

  function renderStep() {

    const step = TOUR_STEPS[currentStep];

    document.getElementById("onboarding-tour-image").src = step.image;

    document.getElementById("onboarding-tour-title").textContent = step.title;

    document.getElementById("onboarding-tour-action").textContent = step.action;

    document.getElementById("onboarding-tour-text").textContent = step.text;

    const caption = document.getElementById("onboarding-tour-caption");

    if (step.caption) {
      caption.style.top = step.caption.top;
      caption.style.left = step.caption.left;
    }

    document.getElementById("onboarding-tour-counter").textContent =

      `Passo ${currentStep + 1} di ${TOUR_STEPS.length}`;

    document.getElementById("onboarding-tour-prev").disabled = currentStep === 0;

    document.getElementById("onboarding-tour-next").textContent =

      currentStep === TOUR_STEPS.length - 1 ? "Fine" : "Avanti";

      animateCursor(step);
      scheduleAutoAdvance(step);
  }

  function openTour() {

    createTourModal();

    currentStep = 0;

    renderStep();

    const modal = document.getElementById("onboarding-tour-modal");

    modal.classList.remove("hidden");

    modal.classList.add("flex");

    document.body.classList.add("overflow-hidden");

  }

  function closeTour() {

    clearAnimationTimers();
    clearAutoAdvanceTimer();

    const modal = document.getElementById("onboarding-tour-modal");

    if (!modal) return;

    modal.classList.add("hidden");

    modal.classList.remove("flex");

    document.body.classList.remove("overflow-hidden");

  }

  function nextStep() {

    if (currentStep >= TOUR_STEPS.length - 1) {

      closeTour();

      return;

    }

    currentStep += 1;

    renderStep();

  }

  function prevStep() {

    if (currentStep <= 0) return;

    currentStep -= 1;

    renderStep();

  }

  window.MyLocalCareOnboardingTour = {

    open: openTour,

    close: closeTour

  };

})();
