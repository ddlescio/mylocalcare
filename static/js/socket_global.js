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

  if (!window.socket.connected) {
    console.log("🔄 Reconnect socket esistente");
    try {
      window.socket.connect();
    } catch(e) {
      console.error("Errore reconnect:", e);
    }
  }

}

const socket = window.socket;


// Safari lifecycle fix
window.addEventListener("pageshow", function (e) {

  const s = window.socket;
  if (!s) return;

  if (!s.connected) {

    console.log("🔄 pageshow -> reconnect socket");

    try {
      s.connect();
    } catch (err) {
      console.error("Errore reconnect pageshow:", err);
    }

  } else {

    console.log("♻️ pageshow -> socket già attiva");

    window.dispatchEvent(new Event("socket_ready"));

  }

});


// evita doppio listener connect
if (!socket._baseConnectListener) {

  socket._baseConnectListener = true;

  socket.on("connect", () => {

    console.log("🔌 socket connected:", socket.id);

    window.dispatchEvent(new Event("socket_ready"));

  });

  socket.on("disconnect", (reason) => {
    console.log("🔌 socket disconnected:", reason);
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
