// static/js/socket_global.js

if (!window.__socket_bootstrap_done__) {
  window.__socket_bootstrap_done__ = true;
}

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
  // SOCKET CREAZIONE / RIUSO (FIX PERSISTENZA TRA PAGINE)
  // ===============================
  const globalScope = window.top || window;

  if (!globalScope.socket || globalScope.socket.disconnected) {

    console.log("🆕 Creo socket UNA VOLTA (globale)");

    globalScope.socket = io({
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

  } else {

    console.log("♻️ Riutilizzo socket globale");

    if (!globalScope.socket.connected && !globalScope.socket.connecting) {
      try {
        globalScope.socket.connect();
        console.log("🔁 reconnect socket");
      } catch (e) {
        console.warn("Errore reconnect:", e);
      }
    }
  }

  // 🔥 ALLINEA SEMPRE window.socket
  window.socket = globalScope.socket;


  // ===============================
  // DA QUI IN POI: INIT COMUNE
  // ===============================
  const socket = window.socket;

  // 🔥 SEMPRE DEFINITO
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


  if (!socket) {
    console.warn("❌ Socket assente dopo bootstrap");
  } else {

    if (!window.__base_socket_listeners__) {
      window.__base_socket_listeners__ = true;

      console.log("🧠 init listener UNA SOLA VOLTA");

    // 🔥 evita duplicazione init su pagine diverse
    // SEMPRE inizializza listener sulla socket attuale

      // ===============================
      // BASE LISTENERS (UNA SOLA VOLTA)
      // ===============================

      // ===============================
      // BASE LISTENERS (SEMPRE)
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

        if (reason === "io client disconnect") return;

        // ❌ NON forzare reconnect manuale
        // Socket.IO gestisce già tutto automaticamente
      });

      socket.on("connect_error", (err) => {
        console.warn("⚠️ socket connect_error:", err?.message || err);
      });
    }
      // ===============================
      // UTILITY
      // ===============================
      window.whenSocketReady = function (callback) {
        const getSocket = () => window.socket;

        const s = getSocket();
        if (!s) return;

        if (s.connected) {
          callback(s);
          return;
        }

        const handler = () => {
          const latest = getSocket();
          if (latest && latest.connected) {
            callback(latest);
          }
        };

        s.once("connect", handler);
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
            // ❌ NON forzare reconnect: gestito da Socket.IO
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

          if (event.persisted) {
            console.log("📄 pageshow (BFCache restore)");
            // ❌ NON forzare reconnect
          }
        });
      }


    }

    // ===============================
    // CLEAN DISCONNECT ON PAGE EXIT
    // ===============================
    if (!window.__socket_cleanup_bound__) {
      window.__socket_cleanup_bound__ = true;


      window.addEventListener("pagehide", (event) => {
        const s = window.socket;

        // 🔥 SOLO se NON è PWA
        if (!window.matchMedia('(display-mode: standalone)').matches) {
          if (s && s.connected) {
            console.log("🧨 pagehide → disconnect (browser)");
            s.disconnect();
          }
        } else {
          console.log("📱 pagehide → mantengo socket (PWA)");
        }
      });      
    }
