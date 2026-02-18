document.addEventListener("DOMContentLoaded", () => {
  const input = document.getElementById("macro-autocomplete");
  const list = document.getElementById("macro-suggerimenti");
  const hiddenProvincia = document.getElementById("macro_area");
  const hiddenRegione = document.getElementById("macro_regione");
  const form = input ? input.closest("form") : null;

  if (!input || !list || !form) return;

  let comuni = [];
  let hasSelected = false; // ✅ diventa true SOLO quando clicchi un suggerimento

  const norm = (s) =>
    (s || "")
      .toString()
      .trim()
      .toLowerCase()
      .normalize("NFD")
      .replace(/[\u0300-\u036f]/g, "")
      .replace(/['’]/g, "");

  fetch("/static/data/comuni.json")
    .then((r) => r.json())
    .then((data) => (comuni = Array.isArray(data) ? data : []))
    .catch(() => (comuni = []));

  function scoreComune(c, q) {
    const nome = norm(c.comune);
    if (nome === q) return 0;
    if (nome.startsWith(q)) return 1;
    if (nome.includes(q)) return 2;
    return 99;
  }

  function resetSelection() {
    hasSelected = false;
    if (hiddenProvincia) hiddenProvincia.value = "";
    if (hiddenRegione) hiddenRegione.value = "";
  }

  input.addEventListener("input", () => {
    const q = norm(input.value);
    list.innerHTML = "";
    resetSelection();

    if (q.length < 2) {
      list.classList.add("hidden");
      return;
    }

    const risultati = comuni
      .filter((c) => norm(c.comune).includes(q))
      .sort((a, b) => {
        const sa = scoreComune(a, q);
        const sb = scoreComune(b, q);
        if (sa !== sb) return sa - sb;
        return norm(a.comune).localeCompare(norm(b.comune));
      })
      .slice(0, 12);

    if (!risultati.length) {
      list.classList.add("hidden");
      return;
    }

    risultati.forEach((c) => {
      const li = document.createElement("li");
      li.textContent = `${c.comune} (${c.provincia})`;
      li.className = "px-4 py-2 cursor-pointer hover:bg-blue-50 text-sm";

      li.addEventListener("mousedown", (e) => {
        e.preventDefault(); // 🔒 blocca il blur prima della selezione

        input.value = c.comune;

        // ✅ selezione valida
        hasSelected = true;

        // ✅ provincia/regione certificate
        if (hiddenProvincia) hiddenProvincia.value = c.provincia || "";
        if (hiddenRegione) hiddenRegione.value = c.regione || "";

        list.classList.add("hidden");
      });
      
      list.appendChild(li);
    });

    list.classList.remove("hidden");
  });

  // ✅ Blocca ENTER se non è stata fatta una selezione
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !hasSelected) {
      e.preventDefault();
      list.classList.remove("hidden"); // opzionale: mostra lista
    }
  });

  // ✅ Se esci dal campo senza selezione valida, svuota input (così non resta “testo libero”)
  input.addEventListener("blur", () => {
    setTimeout(() => {
      if (!hasSelected) {
        input.value = "";
        resetSelection();
      }
      list.classList.add("hidden");
    }, 120);
  });

  // ✅ Blocca submit se provincia non valorizzata (quindi non hai cliccato suggerimento)
  form.addEventListener("submit", (e) => {
    if (!hiddenProvincia || !hiddenProvincia.value.trim()) {
      e.preventDefault();
      alert("Seleziona un comune dall’elenco (autocomplete) per continuare.");
      input.focus();
    }
  });

  document.addEventListener("click", (e) => {
    if (!list.contains(e.target) && e.target !== input) {
      list.classList.add("hidden");
    }
  });
});
