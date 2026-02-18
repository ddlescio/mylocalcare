document.addEventListener("DOMContentLoaded", () => {
  const input = document.getElementById("citta-autocomplete");
  const list = document.getElementById("citta-suggerimenti");
  const hidden = document.getElementById("citta_hidden");
  const form = input ? input.closest("form") : null;

  if (!input || !list || !hidden || !form) return;

  let comuni = [];
  let hasSelected = false; // ✅ true SOLO se clicchi un suggerimento

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
    if (nome === q) return 0;          // match perfetto
    if (nome.startsWith(q)) return 1;  // inizia per
    if (nome.includes(q)) return 2;    // contiene
    return 99;
  }

  function resetSelection() {
    hasSelected = false;
    hidden.value = "";
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
      .slice(0, 10);

    if (!risultati.length) {
      list.classList.add("hidden");
      return;
    }

    risultati.forEach((c) => {
      const li = document.createElement("li");
      li.textContent = `${c.comune} (${c.provincia})`;
      li.className = "px-4 py-2 cursor-pointer hover:bg-blue-50 text-sm";

      li.addEventListener("mousedown", (e) => {
        e.preventDefault(); // 🔒 evita blur prima della selezione

        input.value = c.comune;

        // ✅ selezione certificata
        hasSelected = true;
        hidden.value = c.comune;

        list.classList.add("hidden");
      });
      
      list.appendChild(li);
    });

    list.classList.remove("hidden");
  });

  // 🚫 ENTER bloccato se non hai selezionato
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !hasSelected) {
      e.preventDefault();
      list.classList.remove("hidden");
    }
  });

  // 🚫 se esci dal campo senza selezione → pulizia
  input.addEventListener("blur", () => {
    setTimeout(() => {
      if (!hasSelected) {
        input.value = "";
        resetSelection();
      }
      list.classList.add("hidden");
    }, 120);
  });

  // 🚫 submit bloccato se non valido
  form.addEventListener("submit", (e) => {
    if (!hidden.value.trim()) {
      e.preventDefault();
      alert("Seleziona una città dall’elenco (autocomplete).");
      input.focus();
    }
  });

  document.addEventListener("click", (e) => {
    if (!list.contains(e.target) && e.target !== input) {
      list.classList.add("hidden");
    }
  });
});
