(function () {
  "use strict";

  const TOUR_STEPS = [
    {
      title: "Benvenuto su MyLocalCare",
      action: "Guarda le categorie principali e usa il pulsante Cerca per iniziare.",
      text: "Da qui puoi cercare servizi locali, pubblicare annunci e gestire il tuo profilo.",
      image: "/static/img/onboarding/step-1-home.png",
      hotspot: { top: "78%", left: "78%", label: "Cerca" }
    },
    {
      title: "Carica la foto profilo",
      action: "Tocca la tua foto profilo o entra nel profilo per aggiungerla.",
      text: "Una foto riconoscibile aumenta fiducia e credibilità.",
      image: "/static/img/onboarding/step-2-foto-profilo.png",
      hotspot: { top: "8%", left: "73%", label: "Profilo" }
    },
    {
      title: "Cerca servizi o annunci",
      action: "Usa filtri, categoria e zona per trovare ciò che ti serve.",
      text: "Puoi cercare persone che offrono servizi oppure annunci di chi cerca aiuto.",
      image: "/static/img/onboarding/step-3-cerca.png",
      hotspot: { top: "78%", left: "70%", label: "Filtri" }
    },
    {
      title: "Pubblica un annuncio",
      action: "Scegli se Offri o Cerchi, poi compila categoria, zona e descrizione.",
      text: "L’annuncio sarà controllato prima della pubblicazione.",
      image: "/static/img/onboarding/step-4-annuncio.png",
      hotspot: { top: "22%", left: "50%", label: "Annuncio" }
    },
    {
      title: "Gestisci il tuo profilo",
      action: "Aggiorna informazioni, foto, annunci e preferenze.",
      text: "Un profilo completo rende più chiaro chi sei e cosa offri o cerchi.",
      image: "/static/img/onboarding/step-5-profilo.png",
      hotspot: { top: "12%", left: "72%", label: "Profilo" }
    }
  ];

  let currentStep = 0;

  function createTourModal() {
    if (document.getElementById("onboarding-tour-modal")) return;

    const modal = document.createElement("div");
    modal.id = "onboarding-tour-modal";
    modal.className = "fixed inset-0 z-[9999] hidden items-center justify-center bg-slate-950/70 backdrop-blur-sm px-3 py-5";

    modal.innerHTML = `
      <div class="w-full max-w-[520px] max-h-[92dvh] rounded-[2rem] bg-white shadow-2xl overflow-hidden border border-white/70 flex flex-col">

        <div class="relative bg-slate-100">
          <div class="relative h-[390px] sm:h-[440px] overflow-hidden bg-slate-100">
            <img id="onboarding-tour-image"
                 src=""
                 alt=""
                 class="w-full h-full object-contain bg-slate-100 transition-all duration-300">

            <div id="onboarding-tour-hotspot"
                 class="absolute hidden -translate-x-1/2 -translate-y-1/2 z-20">
              <div class="relative flex flex-col items-center">
                <span class="absolute inline-flex h-14 w-14 rounded-full bg-blue-500 opacity-30 animate-ping"></span>
                <span class="relative inline-flex h-12 w-12 items-center justify-center rounded-full bg-blue-600 text-white shadow-xl ring-4 ring-white font-black">
                  ↓
                </span>
                <span id="onboarding-tour-hotspot-label"
                      class="mt-2 rounded-full bg-white px-3 py-1 text-xs font-extrabold text-blue-700 shadow-md border border-blue-100 whitespace-nowrap">
                </span>
              </div>
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

  function renderStep() {
    const step = TOUR_STEPS[currentStep];

    const image = document.getElementById("onboarding-tour-image");
    const title = document.getElementById("onboarding-tour-title");
    const text = document.getElementById("onboarding-tour-text");
    const action = document.getElementById("onboarding-tour-action");
    const hotspot = document.getElementById("onboarding-tour-hotspot");
    const hotspotLabel = document.getElementById("onboarding-tour-hotspot-label");

    image.src = step.image;
    title.textContent = step.title;
    action.textContent = step.action;
    text.textContent = step.text;

    document.getElementById("onboarding-tour-counter").textContent =
      `Passo ${currentStep + 1} di ${TOUR_STEPS.length}`;

    if (step.hotspot) {
      hotspot.style.top = step.hotspot.top;
      hotspot.style.left = step.hotspot.left;
      hotspotLabel.textContent = step.hotspot.label;
      hotspot.classList.remove("hidden");
    } else {
      hotspot.classList.add("hidden");
    }

    document.getElementById("onboarding-tour-prev").disabled = currentStep === 0;
    document.getElementById("onboarding-tour-next").textContent =
      currentStep === TOUR_STEPS.length - 1 ? "Fine" : "Avanti";
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
