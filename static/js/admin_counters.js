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

  function bindAdminCountersSocket(socket) {
    if (!socket) return;

    window.__adminCountersHandlers = window.__adminCountersHandlers || {};
    const prevSocket = window.__adminCountersHandlers.socket || null;

    // stacca eventuali listener dal vecchio socket
    if (prevSocket && prevSocket !== socket) {
      if (window.__adminCountersHandlers.updateAdminCounters) {
        prevSocket.off("update_admin_counters", window.__adminCountersHandlers.updateAdminCounters);
      }
      if (window.__adminCountersHandlers.updateNotifications) {
        prevSocket.off("update_notifications", window.__adminCountersHandlers.updateNotifications);
      }
    }

    // stacca eventuali listener duplicati dal socket corrente
    if (window.__adminCountersHandlers.updateAdminCounters) {
      socket.off("update_admin_counters", window.__adminCountersHandlers.updateAdminCounters);
    }
    if (window.__adminCountersHandlers.updateNotifications) {
      socket.off("update_notifications", window.__adminCountersHandlers.updateNotifications);
    }

    window.__adminCountersHandlers.socket = socket;

    window.__adminCountersHandlers.updateAdminCounters = function () {
      fetchCounters();
    };

    window.__adminCountersHandlers.updateNotifications = function () {
      fetchCounters();
    };

    socket.on("update_admin_counters", window.__adminCountersHandlers.updateAdminCounters);
    socket.on("update_notifications", window.__adminCountersHandlers.updateNotifications);

    console.log("🧷 admin_counters agganciato alla socket globale", socket.id || null);
  }

  document.addEventListener("DOMContentLoaded", () => {
    fetchCounters();

    if (!timer) {
      timer = setInterval(fetchCounters, 10000);
    }

    // RIUSA SOLO la socket globale, non crearne una nuova
    if (window.whenSocketReady) {
      window.whenSocketReady((socket) => {
        bindAdminCountersSocket(socket);
      });
    } else if (window.socket) {
      if (window.socket.connected) {
        bindAdminCountersSocket(window.socket);
      } else {
        window.socket.once("connect", () => {
          bindAdminCountersSocket(window.socket);
        });
      }
    }
  });
})();
