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


// ===============================
// BASE CONNECT LISTENER
// ===============================

if (!socket._baseConnectListener) {

  socket._baseConnectListener = true;

  socket.on("connect", () => {

    console.log("🔌 socket connected:", socket.id);

    window.dispatchEvent(new Event("socket_ready"));

  });

}


// ===============================
// FIX iOS / PWA FREEZE (CRITICO)
// ===============================

if (!socket._visibilityFix) {

  socket._visibilityFix = true;

  document.addEventListener("visibilitychange", () => {

    if (!window.socket) return;

    const s = window.socket;

    if (document.visibilityState === "visible") {

      console.log("👁️ tab visibile");

      // 🔥 se socket morta → reconnect
      if (!s.connected) {
        console.log("🔄 reconnect socket dopo sleep");
        s.connect();
      }

    } else {
      console.log("🌙 tab nascosta");
    }

  });

}


// ===============================
// HEARTBEAT CLIENT (ANTI-ZOMBIE)
// ===============================

if (!socket._heartbeatInterval) {

  socket._heartbeatInterval = setInterval(() => {

    if (!window.socket) return;

    const s = window.socket;

    if (s.connected) {
      s.emit("ping_client_alive");
      // console.log("💓 heartbeat");
    }

  }, 15000); // ogni 15s

}


// ===============================
// FAILSAFE RECONNECT
// ===============================

if (!socket._failsafeReconnect) {

  socket._failsafeReconnect = true;

  setInterval(() => {

    if (!window.socket) return;

    const s = window.socket;

    // se risulta connessa ma non risponde più → forza reconnect
    if (!s.connected) {
      console.log("⚠️ failsafe reconnect");
      s.connect();
    }

  }, 20000);

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
