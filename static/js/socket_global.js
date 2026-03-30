// static/js/socket_global.js

(function () {
  if (window.__socket_page_bootstrap_done__) {
    console.log("⏭️ socket_global già inizializzato in questa pagina → skip");
    return;
  }
  window.__socket_page_bootstrap_done__ = true;

  // ===============================
  // CLIENT ID STABILE
  // ===============================
  if (!localStorage.getItem("client_id")) {
    localStorage.setItem("client_id", crypto.randomUUID());
  }

  function detectDeviceType() {
    try {
      if (window.matchMedia("(display-mode: standalone)").matches || window.navigator.standalone) {
        return "pwa";
      }
      if (/Mobi|Android|iPhone|iPad/i.test(navigator.userAgent)) return "mobile";
      return "desktop";
    } catch (e) {
      return "unknown";
    }
  }

  // ===============================
  // CREA SOCKET DELLA PAGINA CORRENTE
  // ===============================
  const socket = io({
    transports: ["websocket", "polling"],
    upgrade: true,
    withCredentials: true,

    reconnection: true,
    reconnectionAttempts: Infinity,
    reconnectionDelay: 1000,
    reconnectionDelayMax: 5000,
    timeout: 20000,

    auth: {
      device_type: detectDeviceType(),
      client_id: localStorage.getItem("client_id")
    }
  });

  // riferimenti globali compatibili col resto del progetto
  window.socket = socket;
  window.__active_socket = socket;
  window.__current_socket_id = null;

  // ===============================
  // HEARTBEAT
  // ===============================
  function emitHeartbeat() {
    if (!socket || !socket.connected) return;

    try {
      socket.emit("socket_heartbeat");
    } catch (e) {
      console.warn("Errore emit socket_heartbeat:", e);
    }
  }

  window.__emitSocketHeartbeat = emitHeartbeat;

  // ===============================
  // LISTENER BASE SOCKET
  // ===============================
  socket.on("connect", () => {
    console.log("🔌 socket connected:", socket.id);

    window.__active_socket = socket;
    window.__current_socket_id = socket.id;

    emitHeartbeat();
    window.dispatchEvent(new Event("socket_ready"));
  });

  socket.on("disconnect", (reason) => {
    console.log("🔌 socket disconnected:", reason);
  });

  socket.on("connect_error", (err) => {
    console.warn("⚠️ socket connect_error:", err?.message || err);
  });

  // ===============================
  // API USATA DAL RESTO DEL SITO
  // ===============================
  window.whenSocketReady = function (callback) {
    if (!socket) return;

    if (socket.connected) {
      callback(socket);
      return;
    }

    socket.once("connect", () => {
      callback(socket);
    });
  };

  // ===============================
  // HEARTBEAT INTERVAL
  // ===============================
  if (!window.__socket_heartbeat_interval__) {
    window.__socket_heartbeat_interval__ = setInterval(() => {
      emitHeartbeat();
    }, 20000);
  }

  // ===============================
  // RECONNECT SU RITORNO PAGINA
  // ===============================
  if (!window.__socket_visibility_fix_bound__) {
    window.__socket_visibility_fix_bound__ = true;

    document.addEventListener("visibilitychange", () => {
      if (document.visibilityState === "visible") {
        if (socket && !socket.connected) {
          console.log("👀 Pagina visibile → reconnect socket");
          try {
            socket.connect();
          } catch (e) {
            console.warn("Errore reconnect visibilitychange:", e);
          }
        }
      }
    });
  }

  if (!window.__socket_pageshow_fix_bound__) {
    window.__socket_pageshow_fix_bound__ = true;

    window.addEventListener("pageshow", () => {
      if (socket && !socket.connected) {
        console.log("📄 pageshow → reconnect socket");
        try {
          socket.connect();
        } catch (e) {
          console.warn("Errore reconnect pageshow:", e);
        }
      }
    });
  }

  // ===============================
  // DISCONNECT SEMPRE SU USCITA PAGINA
  // ===============================
  function cleanupSocketOnExit() {
    if (!window.socket) return;

    try {
      if (window.socket.connected) {
        console.log("🧨 uscita pagina → disconnect socket");
        window.socket.disconnect();
      }
    } catch (e) {
      console.warn("Errore disconnect in uscita:", e);
    }
  }

  if (!window.__socket_cleanup_bound__) {
    window.__socket_cleanup_bound__ = true;

    window.addEventListener("pagehide", cleanupSocketOnExit);
    window.addEventListener("beforeunload", cleanupSocketOnExit);
  }
  
})();
