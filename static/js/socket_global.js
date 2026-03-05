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
