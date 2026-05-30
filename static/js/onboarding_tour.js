(function () {
  "use strict";

  const TOUR_STEPS = [
    {
      title: "Benvenuto su MyLocalCare",
      text: "Qui puoi cercare servizi locali, pubblicare annunci e gestire il tuo profilo in modo semplice.",
      image: "/static/img/onboarding/step-1-home.png"
    },
    {
      title: "Carica la foto profilo",
      text: "La foto profilo rende il tuo account più riconoscibile e aumenta la fiducia di chi visita i tuoi annunci o il tuo profilo.",
      image: "/static/img/onboarding/step-2-foto-profilo.png"
    },
    {
      title: "Cerca servizi o annunci",
      text: "Dalla pagina Cerca puoi filtrare per categoria, zona e tipo di servizio.",
      image: "/static/img/onboarding/step-3-cerca.png"
    },
    {
      title: "Pubblica un annuncio",
      text: "Puoi creare un annuncio per offrire un servizio o cercare qualcuno nella tua zona.",
      image: "/static/img/onboarding/step-4-annuncio.png"
    },
    {
      title: "Gestisci il tuo profilo",
      text: "Dal profilo puoi aggiornare informazioni, foto, annunci e preferenze.",
      image: "/static/img/onboarding/step-5-profilo.png"
    }
  ];

  let currentStep = 0;

  function createTourModal() {
    if (document.getElementById("onboarding-tour-modal")) return;

    const modal = document.createElement("div");
    modal.id = "onboarding-tour-modal";
    modal.className = "fixed inset-0 z-[9999] hidden items-center justify-center bg-slate-900/60 px-4";

    modal.innerHTML = `
      <div class="w-full max-w-md rounded-3xl bg-white shadow-2xl overflow-hidden border border-slate-100">
        <div class="relative">
          <img id="onboarding-tour-image"
               src=""
               alt=""
               class="w-full h-56 object-cover bg-slate-100">

          <button type="button"
                  id="onboarding-tour-close"
                  class="absolute top-3 right-3 w-9 h-9 rounded-full bg-white/90 text-slate-700 font-bold shadow">
            ×
          </button>
        </div>

        <div class="p-5 space-y-4">
          <div>
            <p id="onboarding-tour-counter" class="text-xs font-bold text-blue-600 mb-1"></p>
            <h2 id="onboarding-tour-title" class="text-xl font-extrabold text-slate-900"></h2>
            <p id="onboarding-tour-text" class="mt-2 text-sm text-slate-600 leading-relaxed"></p>
          </div>

          <div class="flex items-center justify-between gap-3">
            <button type="button"
                    id="onboarding-tour-prev"
                    class="px-4 py-2 rounded-2xl border border-slate-200 text-slate-700 font-bold">
              Indietro
            </button>

            <button type="button"
                    id="onboarding-tour-next"
                    class="px-5 py-2.5 rounded-2xl bg-blue-600 text-white font-bold shadow">
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

    [image, title, text].forEach(el => {
      el.classList.add("opacity-0", "translate-y-2");
    });

    setTimeout(() => {
      image.src = step.image;
      title.textContent = step.title;
      text.textContent = step.text;

      [image, title, text].forEach(el => {
        el.classList.remove("opacity-0", "translate-y-2");
        el.classList.add("transition-all", "duration-300");
      });
    }, 120);    
    document.getElementById("onboarding-tour-counter").textContent =
      `Passo ${currentStep + 1} di ${TOUR_STEPS.length}`;

    document.getElementById("onboarding-tour-prev").disabled = currentStep === 0;
    document.getElementById("onboarding-tour-prev").classList.toggle("opacity-40", currentStep === 0);

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
  }

  function closeTour() {
    const modal = document.getElementById("onboarding-tour-modal");
    if (!modal) return;

    modal.classList.add("hidden");
    modal.classList.remove("flex");
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
