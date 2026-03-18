// static/js/socket_global.js

// evita esecuzione multipla dello script nello stesso contesto pagina
if (window.__socket_bootstrap_done__) {
  console.log("♻️ socket bootstrap già eseguito");
} else {
  window.__socket_bootstrap_done__ = true;

  // ===============================
  // SOCKET GLOBALE
  // ===============================

  // Se esiste già una socket nello stesso contesto JS:
  // - se è viva la riusiamo
  // - se è morta / zombie la eliminiamo e la ricreiamo
  if (window.socket) {
    if (window.socket.connected) {
      console.log("♻️ Socket già attiva → riutilizzo");
    } else {
      console.log("🧹 Socket esistente ma NON connessa → reset");

      try {
        window.socket.removeAllListeners();
      } catch (e) {}

      try {
        window.socket.disconnect();
      } catch (e) {}

      window.socket = null;
    }
  }

  if (!window.socket) {
    window.socket = io({
      transports: ["websocket"],
      upgrade: false,
      withCredentials: true,
      reconnection: true,
      reconnectionAttempts: 5,
      reconnectionDelay: 1000
    });

    console.log("🟢 Nuova socket creata");
  }

  const socket = window.socket;

  // ===============================
  // BASE LISTENERS (una sola volta)
  // ===============================

  if (!socket._baseListenersBound) {
    socket._baseListenersBound = true;

    socket.on("connect", () => {
      console.log("🔌 socket connected:", socket.id);
      window.dispatchEvent(new Event("socket_ready"));
    });

    socket.on("disconnect", (reason) => {
      console.log("🔌 socket disconnected:", reason);
    });

    socket.on("connect_error", (err) => {
      console.warn("⚠️ socket connect_error:", err?.message || err);
    });
  }

  // ===============================
  // UTILITY
  // ===============================

  window.whenSocketReady = function(callback) {
    const s = window.socket;

    if (!s) return;

    if (s.connected) {
      callback(s);
      return;
    }

    s.once("connect", () => {
      callback(s);
    });
  };

  // ===============================
  // FIX iOS / PWA RESUME
  // ===============================
  // Quando la PWA torna visibile, iOS a volte lascia
  // una websocket "apparentemente viva" ma in realtà morta.
  // Qui forziamo sempre un refresh della connessione.

  if (!window.__socket_visibility_fix_bound__) {
    window.__socket_visibility_fix_bound__ = true;

    document.addEventListener("visibilitychange", () => {
      const s = window.socket;
      if (!s) return;

      if (document.visibilityState === "visible") {
        console.log("👀 App tornata visibile → refresh socket");

        try {
          s.disconnect();
        } catch (e) {}

        setTimeout(() => {
          try {
            s.connect();
          } catch (e) {}
        }, 120);
      }
    });
  }

  // ===============================
  // FIX BFCache / ritorno pagina
  // ===============================
  // Safari/iOS può ripristinare la pagina da cache interna.
  // In quel caso la socket spesso non è più affidabile.

  if (!window.__socket_pageshow_fix_bound__) {
    window.__socket_pageshow_fix_bound__ = true;

    window.addEventListener("pageshow", (event) => {
      const s = window.socket;
      if (!s) return;

      if (event.persisted) {
        console.log("📄 pageshow da bfcache → reconnect socket");

        try {
          s.disconnect();
        } catch (e) {}

        setTimeout(() => {
          try {
            s.connect();
          } catch (e) {}
        }, 120);
      }
    });
  }

  // ===============================
  // FAILSAFE PERIODICO
  // ===============================
  // Se per qualche motivo la socket resta giù, proviamo
  // a rialzarla quando la pagina è visibile.

  if (!window.__socket_failsafe_interval__) {
    window.__socket_failsafe_interval__ = setInterval(() => {
      const s = window.socket;
      if (!s) return;

      if (document.visibilityState !== "visible") return;

      if (!s.connected) {
        console.log("🛠️ failsafe reconnect socket");
        try {
          s.connect();
        } catch (e) {}
      }
    }, 15000);
  }
}
