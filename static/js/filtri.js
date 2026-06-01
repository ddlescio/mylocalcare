let FILTRI_PER_CATEGORIA = {};

fetch("/api/filtri-categoria")
  .then(response => response.json())
  .then(data => {
    FILTRI_PER_CATEGORIA = data || {};
    aggiornaFiltriCategoria();
  })
  .catch(err => console.error("Errore caricamento filtri categoria:", err));

function getFiltriSelezionati() {
  const el = document.getElementById("filtri-selezionati");
  if (!el) return [];

  try {
    return JSON.parse(el.textContent || "[]");
  } catch {
    return [];
  }
}

function aggiornaFiltriCategoria() {
  const selectCategoria = document.querySelector('select[name="categoria"]');
  const container = document.getElementById("filtri-container");
  const checkboxBox = document.getElementById("filtri-checkboxes");

  if (!selectCategoria || !container || !checkboxBox) return;

  checkboxBox.innerHTML = "";

  const categoria = selectCategoria.value.trim();
  const filtri = FILTRI_PER_CATEGORIA[categoria] || [];
  const filtriSelezionati = getFiltriSelezionati();

  if (!filtri.length) {
    container.classList.add("hidden");
    return;
  }

  container.classList.remove("hidden");

  filtri.forEach(filtro => {
    const checked = filtriSelezionati.includes(filtro) ? "checked" : "";

    const label = document.createElement("label");
    label.className = "cursor-pointer select-none inline-block";
    label.innerHTML = `
      <input type="checkbox" name="filtri_categoria" value="${filtro}" class="hidden peer" ${checked}>
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
