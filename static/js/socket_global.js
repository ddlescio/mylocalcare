// evita esecuzione multipla dello script
if (window.__socket_bootstrap_done__) {
  console.log("♻️ socket bootstrap già eseguito");
} else {

window.__socket_bootstrap_done__ = true;

// ===============================
// SOCKET GLOBALE
// ===============================

if (!window.socket) {

  window.socket = io({
    transports: ["websocket"],
    upgrade: false,
    withCredentials: true,
    reconnection: true
  });

  console.log("🟢 Socket creato");

} else {

  console.log("♻️ Socket riutilizzato");

}

const socket = window.socket;


// evita doppio listener connect
if (!socket._baseConnectListener) {

  socket._baseConnectListener = true;

  socket.on("connect", () => {

    console.log("🔌 socket connected:", socket.id);

    window.dispatchEvent(new Event("socket_ready"));

  });

}


// ===============================
// UTILITY
// ===============================

window.whenSocketReady = function(callback) {

  const socket = window.socket;

  if (socket && socket.connected) {
    callback(socket);
    return;
  }

  socket.once("connect", () => {
    callback(socket);
  });

};

}

// ===============================
// AUTO ATTIVAZIONE PUSH (iOS fix)
// ===============================

document.addEventListener("pointerdown", async () => {

  try {

    if (!("Notification" in window)) return;
    if (!("serviceWorker" in navigator)) return;

    const reg = await navigator.serviceWorker.ready;

    if (Notification.permission === "default") {

      const perm = await Notification.requestPermission();

      console.log("Push permission:", perm);

      if (perm === "granted") {

        if (typeof registerPush === "function") {
          registerPush(reg);
        }

      }

    }

  } catch (e) {
    console.log("Push activation error:", e);
  }

}, { once: true });
