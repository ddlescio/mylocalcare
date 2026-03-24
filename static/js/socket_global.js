// static/js/socket_global.js

if (window.__socket_bootstrap_done__) {
  console.log("♻️ socket bootstrap già eseguito");
} else {
  window.__socket_bootstrap_done__ = true;

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
  if (!window.socket) {

    window.socket = io({
      transports: ["websocket"],   // 🔥 SOLO websocket
      upgrade: false,              // 🔥 NO upgrade polling
      withCredentials: true,

      reconnection: true,
      reconnectionAttempts: 5,
      reconnectionDelay: 1000,

      auth: {
        device_type: detectDeviceType()
      }
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

      window.__active_socket = socket;
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

    s.once("connect", () => callback(s));
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

// ===============================
// 🔥 TRACK VISIBILITÀ (FONDAMENTALE PER PUSH)
// ===============================
if (!window.__page_visibility_tracking__) {
  window.__page_visibility_tracking__ = true;

  document.addEventListener("visibilitychange", () => {
    const s = window.socket;
    if (!s || !s.connected) return;

    const visible = !document.hidden;

    console.log("👁️ page_visible:", visible);

    s.emit("page_visible", {
      visible: visible
    });
  });

  // 🔥 iOS PWA (CRITICO)
  window.addEventListener("pagehide", () => {
    const s = window.socket;
    if (!s || !s.connected) return;

    console.log("📴 pagehide → visible false");

    s.emit("page_visible", {
      visible: false
    });
  });

  // 🔥 fallback ulteriore
  window.addEventListener("blur", () => {
    const s = window.socket;
    if (!s || !s.connected) return;

    console.log("💤 blur → visible false");

    s.emit("page_visible", {
      visible: false
    });
  });
}
