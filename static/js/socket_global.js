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


  // ===============================
  // FIX rete ballerina (treno)
  // ===============================

  socket.on("disconnect", (reason) => {

    console.log("⚠️ socket disconnected:", reason);

    // se cade la rete proviamo a riconnettere
    if (reason === "ping timeout" || reason === "transport close") {

      setTimeout(() => {
        console.log("🔄 retry reconnect");
        socket.connect();
      }, 1500);

    }

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
