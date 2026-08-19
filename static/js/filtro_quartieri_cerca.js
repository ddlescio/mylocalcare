document.addEventListener("DOMContentLoaded", () => {
  const zonaInput = document.getElementById("zona-autocomplete");
  const provinciaInput = document.getElementById("provincia");
  const comuneInput = document.getElementById("comune-quartieri");

  const section = document.getElementById(
    "filtro-quartieri-section"
  );

  const ricercaBox = document.getElementById(
    "filtro-quartieri-ricerca-box"
  );

  const ricercaInput = document.getElementById(
    "filtro-quartieri-ricerca"
  );

  const bolleContainer = document.getElementById(
    "filtro-quartieri-bolle"
  );

  if (
    !zonaInput ||
    !provinciaInput ||
    !comuneInput ||
    !section ||
    !ricercaBox ||
    !ricercaInput ||
    !bolleContainer
  ) {
    return;
  }

  let numeroRichiesta = 0;

  const parametriPagina = new URL(
    window.location.href
  ).searchParams;

  const quartieriIniziali = new Set(
    parametriPagina
      .getAll("quartieri")
      .map((valore) => Number.parseInt(valore, 10))
      .filter(
        (valore) =>
          Number.isInteger(valore) &&
          valore > 0
      )
  );

  function normalizzaTesto(valore) {
    return String(valore || "")
      .trim()
      .toLowerCase()
      .normalize("NFD")
      .replace(/[\u0300-\u036f]/g, "");
  }

  function azzeraInterfaccia(
    nascondiSezione = true,
    azzeraComune = false
  ) {
    numeroRichiesta += 1;

    bolleContainer.innerHTML = "";
    ricercaInput.value = "";
    ricercaBox.classList.add("hidden");

    if (azzeraComune) {
      comuneInput.value = "";
    }

    if (nascondiSezione) {
      section.classList.add("hidden");
    }
  }

  function creaBolla({
    testo,
    valore,
    tipo
  }) {
    const label = document.createElement("label");

    label.className =
      "cursor-pointer select-none inline-block";

    label.dataset.tipo = tipo;
    label.dataset.nome = normalizzaTesto(testo);

    const input = document.createElement("input");

    input.type = "checkbox";
    input.value = String(valore);
    input.className = "hidden peer";
    input.dataset.tipo = tipo;

    if (tipo === "quartiere") {
      input.name = "quartieri";
    }

    const span = document.createElement("span");

    span.className =
      "peer-checked:bg-gradient-to-r " +
      "peer-checked:from-blue-600 " +
      "peer-checked:to-indigo-600 " +
      "peer-checked:text-white " +
      "peer-checked:border-blue-600 " +
      "bg-gray-100 hover:bg-blue-50 text-gray-700 " +
      "text-sm px-3 py-1.5 rounded-full " +
      "border border-gray-200 shadow-sm " +
      "transition-all duration-150 " +
      "hover:shadow-md hover:-translate-y-0.5 " +
      "select-none inline-block";

    span.textContent = testo;

    input.addEventListener("change", () => {
      const tuttaCitta = bolleContainer.querySelector(
        'input[data-tipo="tutta-citta"]'
      );

      const quartieriSelezionati = Array.from(
        bolleContainer.querySelectorAll(
          'input[name="quartieri"]:checked'
        )
      );

      if (tipo === "tutta-citta") {
        if (input.checked) {
          quartieriSelezionati.forEach((checkbox) => {
            checkbox.checked = false;
          });
        } else if (quartieriSelezionati.length === 0) {
          input.checked = true;
        }

        return;
      }

      if (input.checked && tuttaCitta) {
        tuttaCitta.checked = false;
      }

      const almenoUnQuartiere = bolleContainer.querySelector(
        'input[name="quartieri"]:checked'
      );

      if (!almenoUnQuartiere && tuttaCitta) {
        tuttaCitta.checked = true;
      }
    });

    label.appendChild(input);
    label.appendChild(span);

    return label;
  }

  function mostraBolle(
    data,
    applicaSelezioneIniziale = false
  ) {
    bolleContainer.innerHTML = "";

    const comune = String(data.comune || "").trim();

    const quartieri = Array.isArray(data.quartieri)
      ? data.quartieri
      : [];

    if (!comune || quartieri.length === 0) {
      azzeraInterfaccia(true, true);
      return;
    }

    comuneInput.value = comune;

    const bollaTuttaCitta = creaBolla({
      testo:
        data.tutta_citta_label ||
        `Tutta ${comune}`,
      valore: "tutta_citta",
      tipo: "tutta-citta"
    });

    const tuttaCittaInput =
      bollaTuttaCitta.querySelector("input");

    bolleContainer.appendChild(bollaTuttaCitta);

    let selezioniApplicate = 0;

    quartieri.forEach((quartiere) => {
      const id = Number.parseInt(
        quartiere.id,
        10
      );

      const nome = String(
        quartiere.nome || ""
      ).trim();

      if (
        !Number.isInteger(id) ||
        id <= 0 ||
        !nome
      ) {
        return;
      }

      const bolla = creaBolla({
        testo: nome,
        valore: id,
        tipo: "quartiere"
      });

      const checkbox = bolla.querySelector("input");

      if (
        applicaSelezioneIniziale &&
        quartieriIniziali.has(id)
      ) {
        checkbox.checked = true;
        selezioniApplicate += 1;
      }

      bolleContainer.appendChild(bolla);
    });

    if (tuttaCittaInput) {
      tuttaCittaInput.checked =
        selezioniApplicate === 0;
    }

    ricercaBox.classList.toggle(
      "hidden",
      quartieri.length <= 20
    );

    ricercaInput.value = "";
    section.classList.remove("hidden");
  }

  async function caricaQuartieri(
    comune,
    provincia,
    applicaSelezioneIniziale = false
  ) {
    comune = String(comune || "").trim();
    provincia = String(provincia || "").trim();

    azzeraInterfaccia(true, false);

    if (!comune || !provincia) {
      comuneInput.value = "";
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
        throw new Error(
          `HTTP ${response.status}`
        );
      }

      const data = await response.json();

      if (
        richiestaCorrente !== numeroRichiesta
      ) {
        return;
      }

      if (
        !data ||
        data.ok !== true ||
        data.disponibile !== true ||
        !Array.isArray(data.quartieri) ||
        data.quartieri.length === 0
      ) {
        azzeraInterfaccia(true, true);
        return;
      }

      mostraBolle(
        data,
        applicaSelezioneIniziale
      );
    } catch (errore) {
      if (
        richiestaCorrente !== numeroRichiesta
      ) {
        return;
      }

      console.error(
        "Errore caricamento filtro quartieri:",
        errore
      );

      azzeraInterfaccia(true, true);
    }
  }

  ricercaInput.addEventListener("input", () => {
    const ricerca = normalizzaTesto(
      ricercaInput.value
    );

    bolleContainer
      .querySelectorAll(
        'label[data-tipo="quartiere"]'
      )
      .forEach((label) => {
        const visibile =
          !ricerca ||
          String(
            label.dataset.nome || ""
          ).includes(ricerca);

        label.classList.toggle(
          "hidden",
          !visibile
        );
      });
  });

  zonaInput.addEventListener(
    "localcare:filtro-comune-invalidato",
    () => {
      azzeraInterfaccia(true, true);
    }
  );

  zonaInput.addEventListener(
    "localcare:filtro-comune-selezionato",
    (evento) => {
      const dettaglio = evento.detail || {};

      caricaQuartieri(
        dettaglio.comune,
        dettaglio.provincia,
        false
      );
    }
  );

  const comuneIniziale = comuneInput.value.trim();

  const provinciaIniziale =
    provinciaInput.value.trim() ||
    parametriPagina.get("provincia") ||
    "";

  if (comuneIniziale && provinciaIniziale) {
    caricaQuartieri(
      comuneIniziale,
      provinciaIniziale,
      true
    );
  }
});
