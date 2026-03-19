// static/js/socket_global.js

// evita esecuzione multipla nello stesso contesto
if (window.__socket_bootstrap_done__) {
  console.log("♻️ socket bootstrap già eseguito");
} else {
  window.__socket_bootstrap_done__ = true;

  // ===============================
  // SOCKET GLOBALE (STABILE)
  // ===============================

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
  } else {
    console.log("♻️ Riutilizzo socket esistente");
  }

  const socket = window.socket;

  // ===============================
  // BASE LISTENERS (UNA SOLA VOLTA)
  // ===============================

  if (!socket._baseListenersBound) {
    socket._baseListenersBound = true;

    socket.on("connect", () => {
      console.log("🔌 socket connected:", socket.id);

      window.__current_socket_id = socket.id;

      window.dispatchEvent(new Event("socket_ready"));
    });

    socket.on("disconnect", (reason) => {
      console.log("🔴 socket disconnect:", reason);
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
    } else {
      s.once("connect", () => {
        callback(s);
      });
    }
  };

  // ===============================
  // FIX VISIBILITY (iOS / Safari)
  // ===============================

  if (!window.__socket_visibility_fix_bound__) {
    window.__socket_visibility_fix_bound__ = true;

    document.addEventListener("visibilitychange", () => {
      const s = window.socket;
      if (!s) return;

      if (document.visibilityState === "visible") {
        console.log("👀 App visibile");

        if (!s.connected) {
          console.log("🛠️ reconnect socket");
          try {
            s.connect();
          } catch (e) {}
        }
      }
    });
  }

  // ===============================
  // FIX BFCache
  // ===============================

  if (!window.__socket_pageshow_fix_bound__) {
    window.__socket_pageshow_fix_bound__ = true;

    window.addEventListener("pageshow", (event) => {
      const s = window.socket;
      if (!s) return;

      if (event.persisted && !s.connected) {
        console.log("📄 pageshow → reconnect socket");
        try {
          s.connect();
        } catch (e) {}
      }
    });
  }

  // ===============================
  // FAILSAFE
  // ===============================

  if (!window.__socket_failsafe_interval__) {
    window.__socket_failsafe_interval__ = setInterval(() => {
      const s = window.socket;
      if (!s) return;

      if (document.visibilityState !== "visible") return;

      if (!s.connected) {
        console.log("🛠️ failsafe reconnect");
        try {
          s.connect();
        } catch (e) {}
      }
    }, 15000);
  }
}
