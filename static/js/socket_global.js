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

  function detectDeviceType() {
    try {
      // PWA installata
      if (window.matchMedia('(display-mode: standalone)').matches) {
        return "pwa";
      }

      // Mobile browser
      if (/Mobi|Android|iPhone|iPad/i.test(navigator.userAgent)) {
        return "mobile";
      }

      // Default desktop
      return "desktop";

    } catch (e) {
      return "unknown";
    }
  }

  if (!window.socket) {
    window.socket = io({
      transports: ["websocket"],
      upgrade: false,
      withCredentials: true,
      reconnection: true,
      reconnectionAttempts: 5,
      reconnectionDelay: 1000,

      auth: {
        device_type: detectDeviceType()
      }
    });

    console.log("🟢 Nuova socket creata");
  }

  // ===============================
  // SOCKET PERSISTENTE
  // ===============================

  window.addEventListener("beforeunload", () => {
    console.log("📄 beforeunload → NON chiudo socket (persistente)");
  });

  const socket = window.socket;

  // ===============================
  // BASE LISTENERS (una sola volta)
  // ===============================

  if (!socket._baseListenersBound) {
    socket._baseListenersBound = true;

    socket.on("connect", () => {
      console.log("🔌 socket connected:", socket.id);

      window.__active_socket = socket;
      window.socket = socket;
      window.__current_socket_id = socket.id;

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

  window.whenSocketReady = function (callback) {
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

  if (!window.__socket_visibility_fix_bound__) {
    window.__socket_visibility_fix_bound__ = true;

    document.addEventListener("visibilitychange", () => {
      const s = window.socket;
      if (!s) return;

      if (document.visibilityState === "visible") {
        console.log("👀 App tornata visibile");

        if (!s.connected) {
          console.log("🛠️ socket non connessa → reconnect");
          try {
            s.connect();
          } catch (e) {
            console.warn("Errore reconnect visibilitychange:", e);
          }
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

        if (!s.connected) {
          try {
            s.connect();
          } catch (e) {
            console.warn("Errore reconnect pageshow:", e);
          }
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
        } catch (e) {
          console.warn("Errore failsafe reconnect:", e);
        }
      }
    }, 15000);
  }
}
