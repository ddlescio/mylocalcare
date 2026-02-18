let FILTRI_PER_CATEGORIA = {};

// 🔹 Carica i filtri dal JSON
fetch("/static/data/filtri_categoria.json")
  .then(response => response.json())
  .then(data => {
    FILTRI_PER_CATEGORIA = data;
    aggiornaFiltriCategoria();
  })
  .catch(err => console.error("Errore caricamento filtri:", err));

  function aggiornaFiltriCategoria() {
    const selectCategoria = document.querySelector('select[name="categoria"]');
    const container = document.getElementById("filtri-container");
    const checkboxBox = document.getElementById("filtri-checkboxes");

    if (!selectCategoria || !container || !checkboxBox) return;

    checkboxBox.innerHTML = "";
    const categoria = selectCategoria.value.trim();
    const filtri = FILTRI_PER_CATEGORIA[categoria];

    if (!filtri || filtri.length === 0) {
      container.classList.add("hidden");
      return;
    }

    container.classList.remove("hidden");

    filtri.forEach(filtro => {
      const label = document.createElement("label");
      label.className = "cursor-pointer select-none inline-block"; // ✅ niente flex o block a tutta larghezza
      label.innerHTML = `
        <input type="checkbox" name="filtri_categoria" value="${filtro}" class="hidden peer">
        <span class="peer-checked:bg-blue-600 peer-checked:text-white
                     bg-gray-100 hover:bg-blue-50 text-gray-700
                     text-sm px-3 py-1 rounded-full border border-gray-200
                     shadow-sm transition-all duration-150
                     hover:shadow-md hover:-translate-y-0.5 select-none inline-block">
          ${filtro}
        </span>
      `;
      checkboxBox.appendChild(label);
    });
  }
  
document.addEventListener("DOMContentLoaded", () => {
  const selectCategoria = document.querySelector('select[name="categoria"]');
  if (selectCategoria) {
    selectCategoria.addEventListener("change", aggiornaFiltriCategoria);
  }
});
