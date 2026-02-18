document.addEventListener("DOMContentLoaded", () => {
  const HIDE_AFTER = 3500;
  const FADE_TIME = 300;

  function hideMessage(msg) {
    msg.style.transition = `opacity ${FADE_TIME}ms ease, transform ${FADE_TIME}ms ease`;
    msg.style.opacity = "0";
    msg.style.transform = "translateY(-6px)";
    setTimeout(() => msg.remove(), FADE_TIME);
  }

  document.querySelectorAll('[data-flash="true"][role="alert"]').forEach((msg) => {
    // Chiudi manualmente
    const btn = msg.querySelector(".flash-close");
    if (btn) btn.addEventListener("click", () => hideMessage(msg));

    // Dissolvenza automatica dopo qualche secondo
    let timer = setTimeout(() => hideMessage(msg), HIDE_AFTER);

    // Pausa su hover
    msg.addEventListener("mouseenter", () => clearTimeout(timer));
    msg.addEventListener("mouseleave", () => {
      timer = setTimeout(() => hideMessage(msg), 1200);
    });
  });
});
