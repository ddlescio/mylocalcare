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

    // reconnessione robusta (rete ballerina tipo treno)
    reconnection: true,
    reconnectionAttempts: Infinity,
    reconnectionDelay: 500,
    reconnectionDelayMax: 3000,
    timeout: 20000
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

  // solo log di debug, non cambia comportamento
  socket.on("disconnect", (reason) => {
    console.log("⚠️ socket disconnected:", reason);
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
