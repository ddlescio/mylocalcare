// static/js/socket_global.js

if (window.__socket_bootstrap_done__) {
  console.log("♻️ socket bootstrap già eseguito");
} else {
  window.__socket_bootstrap_done__ = true;

  // ===============================
  // CLIENT ID STABILE (FIX iOS PWA)
  // ===============================
  if (!localStorage.getItem("client_id")) {
    localStorage.setItem("client_id", crypto.randomUUID());
  }

  // ===============================
  // DEVICE TYPE
  // ===============================
  function detectDeviceType() {
    try {
      if (window.matchMedia('(display-mode: standalone)').matches) return "pwa";
      if (/Mobi|Android|iPhone|iPad/i.test(navigator.userAgent)) return "mobile";
      return "desktop";
    } catch (e) {
      return "unknown";
    }
  }

  // ===============================
  // SOCKET CREAZIONE (UNA SOLA)
  // ===============================
  if (!window.socket || window.socket.disconnected) {

    if (window.socket && window.socket.connected) {
      console.log("⚠️ Socket già attiva → NON ne creo un'altra");
    } else {

      window.socket = io({
        transports: ["websocket", "polling"],
        upgrade: true,
        withCredentials: true,

        reconnection: true,
        reconnectionAttempts: Infinity,
        reconnectionDelayMax: 5000,
        timeout: 20000,
        reconnectionDelay: 1000,

        auth: {
          device_type: detectDeviceType(),
          client_id: localStorage.getItem("client_id")
        }
      });

      console.log("🟢 Nuova socket creata");

    }

  } else {
    console.log("♻️ Riutilizzo socket esistente");
  }

  const socket = window.socket;

  // ===============================
  // BASE LISTENERS (UNA SOLA VOLTA)
  // ===============================
  if (!socket._baseListenersBound) {
    socket._baseListenersBound = true;

    const emitHeartbeat = () => {
      const s = window.socket;
      if (!s || !s.connected) return;

      try {
        s.emit("socket_heartbeat");
      } catch (e) {
        console.warn("Errore emit socket_heartbeat:", e);
      }
    };

    window.__emitSocketHeartbeat = emitHeartbeat;

    socket.on("connect", () => {
      console.log("🔌 socket connected:", socket.id);

      window.__active_socket = socket;
      window.__current_socket_id = socket.id;

      // 🔥 heartbeat immediato all'aggancio
      emitHeartbeat();

      window.dispatchEvent(new Event("socket_ready"));
    });

    socket.on("disconnect", (reason) => {
      console.log("🔌 socket disconnected:", reason);

      if (
        reason === "transport close" ||
        reason === "ping timeout" ||
        reason === "transport error"
      ) {
        console.log("🛠️ reconnect forzato post-disconnect");

        setTimeout(() => {
          if (!socket.connected && socket.active !== false) {
            try {
              socket.connect();
            } catch (e) {
              console.warn("Errore reconnect:", e);
            }
          }
        }, 1000);
      }
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

    s.once("connect", () => callback(s));
  };

  // ===============================
// HEARTBEAT REDIS MULTI-WORKER
// ===============================
if (!window.__socket_heartbeat_interval__) {
  window.__socket_heartbeat_interval__ = setInterval(() => {
    if (typeof window.__emitSocketHeartbeat === "function") {
      window.__emitSocketHeartbeat();
    }
  }, 20000);
}

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
          console.log("🛠️ reconnect visibility");

          try {
            s.connect();
          } catch (e) {
            console.warn("Errore reconnect visibilitychange:", e);
          }
        }
      }
    });
  }

  // ===============================
  // FIX BFCache (Safari iOS)
  // ===============================
  if (!window.__socket_pageshow_fix_bound__) {
    window.__socket_pageshow_fix_bound__ = true;

    window.addEventListener("pageshow", (event) => {
      const s = window.socket;
      if (!s) return;

      if (event.persisted && !s.connected) {
        console.log("📄 pageshow → reconnect");

        try {
          s.connect();
        } catch (e) {
          console.warn("Errore reconnect pageshow:", e);
        }
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
        } catch (e) {
          console.warn("Errore failsafe:", e);
        }
      }
    }, 15000);
  }

  // ===============================
  // NON chiudere socket
  // ===============================
  window.addEventListener("beforeunload", () => {
    console.log("📄 beforeunload → socket lasciata viva");
  });
}
