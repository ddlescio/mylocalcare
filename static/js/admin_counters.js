(function () {
  const ENDPOINT = "/admin/counters";
  let timer = null;

  function setText(id, val) {
    const el = document.getElementById(id);
    if (el) el.textContent = String(val);
  }

  async function fetchCounters() {
    try {
      const res = await fetch(ENDPOINT, { cache: "no-store" });
      if (!res.ok) return;
      const data = await res.json();
      setText("badge-annunci", data.annunci ?? 0);
      setText("badge-recensioni", data.recensioni ?? 0);
      setText("badge-risposte", data.risposte ?? 0);
      setText("badge-totale", data.totale ?? 0);
    } catch (e) {
      console.error("Errore fetch /admin/counters:", e);
    }
  }

  // Avvio: chiamata immediata + ogni 10 secondi
  document.addEventListener("DOMContentLoaded", () => {
    fetchCounters();
    timer = setInterval(fetchCounters, 10000);

    // Socket.IO: aggiorna subito quando il server emette un evento
    if (window.io) {
      const socket = io({ transports: ["websocket"] });
      socket.on("connect", () => {
        // unisciti alla tua stanza utente se serve, altrimenti basta globale
        socket.emit("join", {});
      });

      // quando il backend emette questo, aggiorni subito i contatori
      socket.on("update_admin_counters", () => {
        fetchCounters();
      });

      // opzionale: se usi questo evento per le notifiche, puoi rinfrescare i badge
      socket.on("update_notifications", (data) => {
        // compatibile sia con vecchio evento vuoto che con nuovo payload {count}
        fetchCounters();
      });      
    }
  });
})();
