document.addEventListener("DOMContentLoaded", () => {
  // ✅ Cerca solo elementi che hanno un ruolo di messaggio Flask
  //    oppure che sono nel container specifico del messaggio
  const flashMessages = document.querySelectorAll(
    '.flash-message, [data-flash="true"], [role="alert"], .alert-success, .alert-error, .alert-info, .alert-warning'
  );

  flashMessages.forEach((msg) => {
    // Evita qualsiasi interferenza con il resto della pagina
    if (!msg.textContent.trim()) return;

    // Aggiunge sicurezza: non tocca elementi interattivi
    if (msg.closest("form") || msg.closest(".recensione-form")) return;

    // Mostra subito (fade-in)
    msg.style.transition = "opacity 0.5s ease";
    msg.style.opacity = "1";

    // Dopo 3.5 secondi → fade-out
    setTimeout(() => {
      msg.style.transition = "opacity 0.8s ease, transform 0.8s ease";
      msg.style.opacity = "0";
      msg.style.transform = "translateY(-6px)";

      // Rimuovi dopo l'animazione
      setTimeout(() => {
        if (msg && msg.parentNode) msg.remove();
      }, 800);
    }, 3500);
  });
});
