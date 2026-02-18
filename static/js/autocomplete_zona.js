document.addEventListener("DOMContentLoaded", () => {
  const input = document.getElementById("zona-autocomplete");
  const list = document.getElementById("zona-suggerimenti");
  const hiddenProvincia = document.getElementById("zona_provincia");
  const form = input ? input.closest("form") : null;

  if (!input || !list || !hiddenProvincia || !form) return;

  // ✅ anti-doppia inizializzazione (fondamentale nel tuo caso)
  if (input.dataset.autocompleteInit === "1") return;
  input.dataset.autocompleteInit = "1";

  input.setAttribute("autocomplete", "off");

  let comuni = [];

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
    .then((data) => {
      comuni = Array.isArray(data) ? data : [];
    })
    .catch(() => (comuni = []));

  function scoreComune(c, q) {
    const nome = norm(c.comune);
    if (nome === q) return 0;
    if (nome.startsWith(q)) return 1;
    if (nome.includes(q)) return 2;
    return 99;
  }

  function hideList() {
    list.classList.add("hidden");
  }

  function showList() {
    list.classList.remove("hidden");
  }

  function invalidate() {
    // 🔒 appena l’utente digita, la selezione NON è più certificata
    hiddenProvincia.value = "";
  }

  function selectComune(c) {
    input.value = c.comune;
    hiddenProvincia.value = c.provincia || "";
    hideList();
  }

  input.addEventListener("input", () => {
    const q = norm(input.value);
    list.innerHTML = "";
    invalidate();

    if (q.length < 2) {
      hideList();
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
      .slice(0, 10);

    if (!risultati.length) {
      hideList();
      return;
    }

    risultati.forEach((c) => {
      const li = document.createElement("li");
      li.textContent = `${c.comune} (${c.provincia})`;
      li.className = "px-4 py-2 cursor-pointer hover:bg-blue-50 text-sm";

      // ✅ pointerdown copre mouse + touch e previene il blur prima della selezione
      li.addEventListener("pointerdown", (e) => {
        e.preventDefault();
        selectComune(c);
      });

      list.appendChild(li);
    });

    showList();
  });

  // 🚫 ENTER bloccato se non certificato
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !hiddenProvincia.value.trim()) {
      e.preventDefault();
      showList();
    }
  });

  // ✅ BLUR: se non certificato -> svuota, altrimenti lascia com’è
  input.addEventListener("blur", () => {
    setTimeout(() => {
      if (!hiddenProvincia.value.trim()) {
        input.value = "";
      }
      hideList();
    }, 120);
  });

  // ✅ SUBMIT: controllo finale
  form.addEventListener("submit", (e) => {
    if (!hiddenProvincia.value.trim()) {
      e.preventDefault();
      alert("Seleziona un comune dall’elenco.");
      input.focus();
    }
  });

  document.addEventListener("click", (e) => {
    if (!list.contains(e.target) && e.target !== input) {
      hideList();
    }
  });
});
