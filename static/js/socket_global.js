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
  // PAGE LIFECYCLE FIX
  // Safari / PWA / BFCache:
  // chiude la socket quando la pagina esce,
  // la riapre se la pagina torna viva
  // ===============================
  if (!window.__socket_pagehide_handler_attached__) {
    window.__socket_pagehide_handler_attached__ = true;

    window.addEventListener("pagehide", () => {
      try {
        if (socket && socket.connected) {
          console.log("📴 pagehide -> socket.disconnect()");
          socket.disconnect();
        }
      } catch (e) {
        console.warn("Errore disconnect su pagehide:", e);
      }
    });
  }

  if (!window.__socket_pageshow_handler_attached__) {
    window.__socket_pageshow_handler_attached__ = true;

    window.addEventListener("pageshow", (event) => {
      try {
        if (socket && !socket.connected) {
          console.log("📳 pageshow -> socket.connect()", { persisted: !!event.persisted });
          socket.connect();
        }
      } catch (e) {
        console.warn("Errore reconnect su pageshow:", e);
      }
    });
  }
})();
