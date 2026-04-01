window.addEventListener("pageshow", function (event) {
  const navEntry = performance.getEntriesByType("navigation")[0];
  const fromBFCache =
    event.persisted === true ||
    (navEntry && navEntry.type === "back_forward");

  if (!fromBFCache) return;

  console.log("♻️ pageshow da BFCache rilevato -> reload forzato pagina");

  try {
    window.__socket_page_bootstrap_done__ = false;
  } catch (_) {}

  window.location.reload();
});

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

  // ======================================================
  // DEBUG HARD: traccia chi aggancia/stacca listener chat
  // ======================================================
  const __origOn = socket.on.bind(socket);
  const __origOff = socket.off.bind(socket);

  const __traceEvents = new Set([
    "new_message",
    "messages_read",
    "message_delivered",
    "user_typing",
    "chat_threads_update",
    "update_unread_count",
    "connect",
    "disconnect"
  ]);

  socket.on = function (eventName, handler, ...rest) {
    if (__traceEvents.has(eventName)) {
      console.log("🧷 [SOCKET TRACE] on", eventName, {
        socketId: socket.id || null,
        handlerName: handler?.name || "(anonimo)",
        stack: new Error().stack
      });
    }
    return __origOn(eventName, handler, ...rest);
  };

  socket.off = function (eventName, handler, ...rest) {
    if (__traceEvents.has(eventName)) {
      console.warn("✂️ [SOCKET TRACE] off", eventName, {
        socketId: socket.id || null,
        withHandler: !!handler,
        handlerName: handler?.name || null,
        stack: new Error().stack
      });
    }
    return __origOff(eventName, handler, ...rest);
  };

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


  })();
