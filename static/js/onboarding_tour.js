(function () {
  "use strict";

  const TOUR_STEPS = [
    {
      title: "Benvenuto su MyLocalCare",
      action: "Esempio: vuoi cercare una babysitter.",
      text: "Guarda le categorie principali: puoi toccare direttamente la card della categoria che ti interessa.",
      image: "/static/img/onboarding/step-1-home.png",
      cursorText: "Cerco una babysitter",
      cursorStart: { top: "82%", left: "50%" },
      cursorEnd: { top: "34%", left: "30%" }
    },
    {
      title: "Carica la foto profilo",
      action: "Tocca la tua foto profilo per rendere l’account più riconoscibile.",
      text: "Una foto chiara aumenta fiducia e credibilità.",
      image: "/static/img/onboarding/step-2-foto-profilo.png",
      cursorText: "Aggiungo la foto",
      cursorStart: { top: "76%", left: "50%" },
      cursorEnd: { top: "8%", left: "73%" }
    },
    {
      title: "Cerca servizi o annunci",
      action: "Usa categoria, zona e filtri per trovare ciò che ti serve.",
      text: "Puoi cercare chi offre servizi oppure annunci di chi cerca aiuto.",
      image: "/static/img/onboarding/step-3-cerca.png",
      cursorText: "Uso i filtri",
      cursorStart: { top: "82%", left: "50%" },
      cursorEnd: { top: "30%", left: "50%" }
    },
    {
      title: "Pubblica un annuncio",
      action: "Scegli se Offri o Cerchi, poi compila categoria, zona e descrizione.",
      text: "L’annuncio sarà controllato prima della pubblicazione.",
      image: "/static/img/onboarding/step-4-annuncio.png",
      cursorText: "Creo l’annuncio",
      cursorStart: { top: "80%", left: "50%" },
      cursorEnd: { top: "24%", left: "50%" }
    },
    {
      title: "Gestisci il tuo profilo",
      action: "Aggiorna informazioni, foto, annunci e preferenze.",
      text: "Un profilo completo aiuta gli altri utenti a capire meglio chi sei.",
      image: "/static/img/onboarding/step-5-profilo.png",
      cursorText: "Apro il profilo",
      cursorStart: { top: "76%", left: "50%" },
      cursorEnd: { top: "10%", left: "73%" }
    }
  ];

  let currentStep = 0;
  let animationTimer = null;

  function createTourModal() {
    if (document.getElementById("onboarding-tour-modal")) return;

    const modal = document.createElement("div");
    modal.id = "onboarding-tour-modal";
    modal.className = "fixed inset-0 z-[9999] hidden items-center justify-center bg-slate-950/70 backdrop-blur-sm px-3 py-5";

    modal.innerHTML = `
      <div class="w-full max-w-[520px] max-h-[92dvh] rounded-[2rem] bg-white shadow-2xl overflow-hidden border border-white/70 flex flex-col">

        <div class="relative bg-slate-100">
          <div class="relative h-[430px] sm:h-[470px] overflow-hidden bg-slate-100">
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
                <div class="relative w-12 h-12 rounded-full bg-white shadow-xl border border-blue-100 flex items-center justify-center text-2xl">
                  👆
                </div>
              </div>
            </div>

            <div id="onboarding-tour-click"
                 class="absolute z-20 hidden -translate-x-1/2 -translate-y-1/2">
              <span class="block w-16 h-16 rounded-full border-4 border-blue-500 animate-ping"></span>
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
    clearTimeout(animationTimer);

    const cursor = document.getElementById("onboarding-tour-cursor");
    const click = document.getElementById("onboarding-tour-click");

    cursor.style.top = step.cursorStart.top;
    cursor.style.left = step.cursorStart.left;
    click.classList.add("hidden");

    animationTimer = setTimeout(() => {
      cursor.style.top = step.cursorEnd.top;
      cursor.style.left = step.cursorEnd.left;
    }, 250);

    animationTimer = setTimeout(() => {
      click.style.top = step.cursorEnd.top;
      click.style.left = step.cursorEnd.left;
      click.classList.remove("hidden");
    }, 1350);

    animationTimer = setTimeout(() => {
      click.classList.add("hidden");
    }, 2300);
  }

  function renderStep() {
    const step = TOUR_STEPS[currentStep];

    document.getElementById("onboarding-tour-image").src = step.image;
    document.getElementById("onboarding-tour-title").textContent = step.title;
    document.getElementById("onboarding-tour-action").textContent = step.action;
    document.getElementById("onboarding-tour-text").textContent = step.text;
    document.getElementById("onboarding-tour-caption").textContent = step.cursorText;

    document.getElementById("onboarding-tour-counter").textContent =
      `Passo ${currentStep + 1} di ${TOUR_STEPS.length}`;

    document.getElementById("onboarding-tour-prev").disabled = currentStep === 0;
    document.getElementById("onboarding-tour-next").textContent =
      currentStep === TOUR_STEPS.length - 1 ? "Fine" : "Avanti";

    animateCursor(step);
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
    clearTimeout(animationTimer);

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
