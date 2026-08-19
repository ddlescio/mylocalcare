document.addEventListener("DOMContentLoaded", () => {
  const zonaInput = document.getElementById("zona-autocomplete");
  const provinciaInput = document.getElementById("zona_provincia");

  const section = document.getElementById("quartieri-section");
  const toggle = document.getElementById("quartieri-toggle");
  const panel = document.getElementById("quartieri-panel");
  const freccia = document.getElementById("quartieri-freccia");
  const riepilogo = document.getElementById("quartieri-riepilogo");

  const ricercaBox = document.getElementById("quartieri-ricerca-box");
  const ricercaInput = document.getElementById("quartieri-ricerca");
  const checkboxContainer = document.getElementById("quartieri-checkboxes");
  const stato = document.getElementById("quartieri-stato");

  const coperturaInput = document.getElementById("copertura-quartieri");

  if (
    !zonaInput ||
    !provinciaInput ||
    !section ||
    !toggle ||
    !panel ||
    !freccia ||
    !riepilogo ||
    !ricercaBox ||
    !ricercaInput ||
    !checkboxContainer ||
    !stato ||
    !coperturaInput
  ) {
    return;
  }

  let comuneAttuale = "";
  let quartieriDisponibili = [];
  let numeroRichiesta = 0;

  const copertureValide = new Set([
    "non_specificato",
    "tutta_citta",
    "quartieri"
  ]);

  const coperturaIniziale =
    copertureValide.has(coperturaInput.value)
      ? coperturaInput.value
      : "non_specificato";

  let quartieriIdsIniziali = [];

  const datiInizialiElement = document.getElementById(
    "quartieri-selezionati-iniziali"
  );

  if (datiInizialiElement) {
    try {
      const datiIniziali = JSON.parse(
        datiInizialiElement.textContent || "[]"
      );

      if (Array.isArray(datiIniziali)) {
        quartieriIdsIniziali = [
          ...new Set(
            datiIniziali
              .map((valore) => Number.parseInt(valore, 10))
              .filter(
                (valore) =>
                  Number.isInteger(valore) &&
                  valore > 0
              )
          )
        ];
      }
    } catch (errore) {
      quartieriIdsIniziali = [];
    }
  }

  function normalizzaTesto(valore) {
    return String(valore || "")
      .trim()
      .toLowerCase()
      .normalize("NFD")
      .replace(/[\u0300-\u036f]/g, "");
  }

  function impostaPannello(aperto) {
    panel.classList.toggle("hidden", !aperto);
    toggle.setAttribute("aria-expanded", aperto ? "true" : "false");
    freccia.classList.toggle("rotate-180", aperto);
  }

  function aggiornaRiepilogo() {
    const tuttaCitta = checkboxContainer.querySelector(
      'input[data-tipo="tutta-citta"]'
    );

    const quartieriSelezionati = Array.from(
      checkboxContainer.querySelectorAll(
        'input[name="quartieri_ids"]:checked'
      )
    );

    if (tuttaCitta && tuttaCitta.checked) {
      coperturaInput.value = "tutta_citta";
      riepilogo.textContent = `Tutta ${comuneAttuale}`;
      return;
    }

    if (quartieriSelezionati.length > 0) {
      coperturaInput.value = "quartieri";

      riepilogo.textContent =
        quartieriSelezionati.length === 1
          ? "1 quartiere selezionato"
          : `${quartieriSelezionati.length} quartieri selezionati`;

      return;
    }

    coperturaInput.value = "non_specificato";
    riepilogo.textContent =
      "Puoi indicare tutta la città oppure uno o più quartieri.";
  }

  function azzeraQuartieri(nascondiSezione = true) {
    numeroRichiesta += 1;
    comuneAttuale = "";
    quartieriDisponibili = [];

    checkboxContainer.innerHTML = "";
    ricercaInput.value = "";
    ricercaBox.classList.add("hidden");

    stato.textContent = "";
    stato.classList.add("hidden");

    coperturaInput.value = "non_specificato";

    riepilogo.textContent =
      "Puoi indicare tutta la città oppure uno o più quartieri.";

    impostaPannello(false);

    if (nascondiSezione) {
      section.classList.add("hidden");
    }
  }

  function creaBolla({
    testo,
    valore,
    nomeCampo = "",
    tipo = "quartiere"
  }) {
    const label = document.createElement("label");

    label.className =
      "cursor-pointer select-none inline-block";

    label.dataset.nome = normalizzaTesto(testo);
    label.dataset.tipo = tipo;

    const input = document.createElement("input");

    input.type = "checkbox";
    input.value = String(valore);
    input.className = "hidden peer";
    input.dataset.tipo = tipo;

    if (nomeCampo) {
      input.name = nomeCampo;
    }

    const span = document.createElement("span");

    span.className =
      "peer-checked:bg-blue-600 peer-checked:text-white " +
      "peer-checked:border-blue-600 bg-gray-100 hover:bg-blue-50 " +
      "text-gray-700 text-sm px-3 py-1.5 rounded-full " +
      "border border-gray-200 shadow-sm transition-all duration-150 " +
      "hover:shadow-md hover:-translate-y-0.5 select-none inline-block";

    span.textContent = testo;

    input.addEventListener("change", () => {
      if (tipo === "tutta-citta" && input.checked) {
        checkboxContainer
          .querySelectorAll('input[name="quartieri_ids"]')
          .forEach((checkbox) => {
            checkbox.checked = false;
          });
      }

      if (tipo === "quartiere" && input.checked) {
        const tuttaCitta = checkboxContainer.querySelector(
          'input[data-tipo="tutta-citta"]'
        );

        if (tuttaCitta) {
          tuttaCitta.checked = false;
        }
      }

      aggiornaRiepilogo();
    });

    label.appendChild(input);
    label.appendChild(span);

    return label;
  }

  function mostraQuartieri(
    data,
    applicaSelezioneIniziale = false
  ) {
    checkboxContainer.innerHTML = "";
    comuneAttuale = String(data.comune || "").trim();
    quartieriDisponibili = Array.isArray(data.quartieri)
      ? data.quartieri
      : [];

    const bollaTuttaCitta = creaBolla({
      testo:
        data.tutta_citta_label ||
        `Tutta ${comuneAttuale}`,
      valore: "tutta_citta",
      tipo: "tutta-citta"
    });

    checkboxContainer.appendChild(bollaTuttaCitta);

    quartieriDisponibili.forEach((quartiere) => {
      const id = Number.parseInt(quartiere.id, 10);
      const nome = String(quartiere.nome || "").trim();

      if (!Number.isInteger(id) || id <= 0 || !nome) {
        return;
      }

      checkboxContainer.appendChild(
        creaBolla({
          testo: nome,
          valore: id,
          nomeCampo: "quartieri_ids",
          tipo: "quartiere"
        })
      );
    });

    ricercaBox.classList.toggle(
      "hidden",
      quartieriDisponibili.length <= 20
    );

    ricercaInput.value = "";

    stato.textContent = "";
    stato.classList.add("hidden");

    section.classList.remove("hidden");

    let selezioneInizialePresente = false;

    if (applicaSelezioneIniziale) {
      if (coperturaIniziale === "tutta_citta") {
        const tuttaCitta = checkboxContainer.querySelector(
          'input[data-tipo="tutta-citta"]'
        );

        if (tuttaCitta) {
          tuttaCitta.checked = true;
          selezioneInizialePresente = true;
        }
      }

      if (
        coperturaIniziale === "quartieri" &&
        quartieriIdsIniziali.length > 0
      ) {
        const idsDaSelezionare = new Set(
          quartieriIdsIniziali
        );

        checkboxContainer
          .querySelectorAll(
            'input[name="quartieri_ids"]'
          )
          .forEach((checkbox) => {
            const quartiereId = Number.parseInt(
              checkbox.value,
              10
            );

            if (idsDaSelezionare.has(quartiereId)) {
              checkbox.checked = true;
              selezioneInizialePresente = true;
            }
          });
      }
    }

    aggiornaRiepilogo();

    // In modifica si apre soltanto se esiste già
    // una selezione salvata. Negli altri casi resta chiuso.
    impostaPannello(selezioneInizialePresente);
  }

  async function caricaQuartieri(
    comune,
    provincia,
    applicaSelezioneIniziale = false
  ) {
    comune = String(comune || "").trim();
    provincia = String(provincia || "").trim();

    azzeraQuartieri(true);

    if (!comune || !provincia) {
      return;
    }

    const richiestaCorrente = ++numeroRichiesta;

    try {
      const parametri = new URLSearchParams({
        comune,
        provincia
      });

      const response = await fetch(
        `/api/quartieri-citta?${parametri.toString()}`,
        {
          method: "GET",
          credentials: "same-origin",
          cache: "no-store"
        }
      );

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }

      const data = await response.json();

      if (richiestaCorrente !== numeroRichiesta) {
        return;
      }

      if (
        !data ||
        data.ok !== true ||
        data.disponibile !== true ||
        !Array.isArray(data.quartieri) ||
        data.quartieri.length === 0
      ) {
        azzeraQuartieri(true);
        return;
      }

      mostraQuartieri(
        data,
        applicaSelezioneIniziale
      );
    } catch (errore) {
      if (richiestaCorrente !== numeroRichiesta) {
        return;
      }

      console.error(
        "Errore caricamento quartieri:",
        errore
      );

      azzeraQuartieri(true);
    }
  }

  toggle.addEventListener("click", () => {
    if (section.classList.contains("hidden")) {
      return;
    }

    const aperto =
      toggle.getAttribute("aria-expanded") === "true";

    impostaPannello(!aperto);
  });

  ricercaInput.addEventListener("input", () => {
    const ricerca = normalizzaTesto(ricercaInput.value);

    checkboxContainer
      .querySelectorAll('label[data-tipo="quartiere"]')
      .forEach((label) => {
        const visibile =
          !ricerca ||
          String(label.dataset.nome || "").includes(ricerca);

        label.classList.toggle("hidden", !visibile);
      });
  });

  zonaInput.addEventListener(
    "localcare:comune-invalidato",
    () => {
      azzeraQuartieri(true);
    }
  );

  zonaInput.addEventListener(
    "localcare:comune-selezionato",
    (evento) => {
      const dettaglio = evento.detail || {};

      caricaQuartieri(
        dettaglio.comune,
        dettaglio.provincia
      );
    }
  );

  document
    .querySelectorAll('input[name="modalita_servizio"]')
    .forEach((radio) => {
      radio.addEventListener("change", () => {
        setTimeout(() => {
          const modalitaSelezionata =
            document.querySelector(
              'input[name="modalita_servizio"]:checked'
            );

          if (
            modalitaSelezionata &&
            modalitaSelezionata.value === "online"
          ) {
            azzeraQuartieri(true);
            return;
          }

          const comune = zonaInput.value.trim();
          const provincia = provinciaInput.value.trim();

          if (comune && provincia) {
            caricaQuartieri(comune, provincia);
          } else {
            azzeraQuartieri(true);
          }
        }, 0);
      });
    });

  // Serve soprattutto nella modifica di un annuncio già esistente.
  const comuneIniziale = zonaInput.value.trim();
  const provinciaIniziale = provinciaInput.value.trim();

  if (comuneIniziale && provinciaIniziale) {
    caricaQuartieri(
      comuneIniziale,
      provinciaIniziale,
      true
    );
  }  
});
