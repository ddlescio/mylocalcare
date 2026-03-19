// ===============================
// RESET SOCKET (SE ESISTE)
// ===============================

if (window.socket) {
  console.log("🧹 Reset socket forzato");

  try {
    window.socket.removeAllListeners();
  } catch (e) {}

  try {
    window.socket.disconnect();
  } catch (e) {}

  window.socket = null;
}

// ===============================
// CREA SOCKET SEMPRE NUOVA
// ===============================

window.socket = io({
  transports: ["websocket"],
  upgrade: false,
  withCredentials: true,
  reconnection: true,
  reconnectionAttempts: 5,
  reconnectionDelay: 1000
});

console.log("🟢 Nuova socket creata");

const socket = window.socket;


// ===============================
// BASE LISTENERS (UNA SOLA VOLTA)
// ===============================

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
// FIX VISIBILITY (Safari / iOS)
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
// FIX BFCache (Safari)
// ===============================

if (!window.__socket_pageshow_fix_bound__) {
  window.__socket_pageshow_fix_bound__ = true;

  window.addEventListener("pageshow", (event) => {
    const s = window.socket;
    if (!s) return;

    if (event.persisted) {
      console.log("📄 pageshow da cache");

      if (!s.connected) {
        console.log("🛠️ reconnect socket (bfcache)");

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
      console.log("🛠️ failsafe reconnect");

      try {
        s.connect();
      } catch (e) {}
    }
  }, 15000);
}
