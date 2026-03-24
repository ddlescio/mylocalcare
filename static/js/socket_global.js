// static/js/socket_global.js

// evita esecuzione multipla dello script nello stesso contesto pagina
if (window.__socket_bootstrap_done__) {
  console.log("♻️ socket bootstrap già eseguito");
} else {
  window.__socket_bootstrap_done__ = true;

  // ===============================
  // SOCKET GLOBALE
  // ===============================

  if (window.socket) {
    console.log("♻️ Riutilizzo socket esistente");
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

  // ===============================
// 🔥 AUTO-CLOSE SOCKET FUORI CHAT
// ===============================

window.addEventListener("beforeunload", () => {
  console.log("📄 beforeunload → NON chiudo socket (persistente)");
});  
}

  const socket = window.socket;

  // ===============================
  // BASE LISTENERS (una sola volta)
  // ===============================

  if (!socket._baseListenersBound) {
    socket._baseListenersBound = true;

    socket.on("connect", () => {

      console.log("🔌 socket connected:", socket.id);

      // 🔥 SEMPRE aggiorna socket attiva
      window.__active_socket = socket;
      window.socket = socket;

      window.__current_socket_id = socket.id;

      window.dispatchEvent(new Event("socket_ready"));
    });

    // 🔥 RILEVA SOCKET MORTE O SOSTITUITE
    socket.on("disconnect", (reason) => {

      console.log("🔴 socket disconnect:", reason);

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
  // FIX iOS / PWA RESUME (CORRETTO)
  // ===============================

  if (!window.__socket_visibility_fix_bound__) {
    window.__socket_visibility_fix_bound__ = true;

    document.addEventListener("visibilitychange", () => {
      const s = window.socket;
      if (!s) return;

      if (document.visibilityState === "visible") {
        console.log("👀 App tornata visibile");

        // 🔥 FIX: NON forzare disconnect
        if (!s.connected) {
          console.log("🛠️ socket non connessa → reconnect");

          try {
            s.connect();
          } catch (e) {}
        } else {
          console.log("♻️ socket ancora viva → nessuna azione");
        }
      }
    });
  }

  // ===============================
  // FIX BFCache / ritorno pagina
  // ===============================

  if (!window.__socket_pageshow_fix_bound__) {
    window.__socket_pageshow_fix_bound__ = true;

    window.addEventListener("pageshow", (event) => {
      const s = window.socket;
      if (!s) return;

      if (event.persisted) {
        console.log("📄 pageshow da bfcache → reconnect socket");

        // 🔥 QUI lasciamo reconnect leggero
        if (!s.connected) {
          try {
            s.connect();
          } catch (e) {}
        }
      }
    });
  }

  // ===============================
  // FAILSAFE PERIODICO
  // ===============================

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
