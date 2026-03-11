// evita esecuzione multipla dello script
if (window.__socket_bootstrap_done__) {
  console.log("♻️ socket bootstrap già eseguito");
} else {

window.__socket_bootstrap_done__ = true;

// ===============================
// SOCKET GLOBALE
// ===============================

if (!window.socket || window.socket.disconnected) {

  if (window.socket) {
    try {
      window.socket.close();
    } catch(e) {}
  }

  window.socket = io({
    transports: ["websocket"],
    upgrade: false,
    withCredentials: true,
    reconnection: true,
    reconnectionAttempts: 5,
    reconnectionDelay: 2000
  });

  console.log("🟢 Socket creata");

} else {

  console.log("♻️ Socket riutilizzata");

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
