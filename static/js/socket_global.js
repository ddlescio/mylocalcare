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

    // resilienza connessione
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


// ===============================
// LISTENER BASE SOCKET
// ===============================

if (!socket._baseConnectListener) {

  socket._baseConnectListener = true;

  socket.on("connect", () => {

    console.log("🔌 socket connected:", socket.id);

    // notifica alle pagine che la socket è pronta
    window.dispatchEvent(new Event("socket_ready"));

  });

  // 🔁 FIX CONNESSIONI BALLERINE
  socket.on("reconnect", (attempt) => {

    console.log("🔄 socket reconnect:", attempt);

    // forza ri-bind listener delle pagine
    window.dispatchEvent(new Event("socket_ready"));

  });

  // utile per debug reti instabili
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
