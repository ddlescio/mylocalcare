window.addEventListener("pageshow", function (event) {
  const navEntry = performance.getEntriesByType("navigation")[0];
  const fromBFCache =
    event.persisted === true ||
    (navEntry && navEntry.type === "back_forward");

  if (!fromBFCache) return;

  console.log("♻️ pageshow da BFCache rilevato -> reload forzato pagina");

  try {
    window.__socket_page_bootstrap_done__ = false;
  } catch (_) {}

  window.location.reload();
});

(function () {
  if (window.__socket_page_bootstrap_done__) {
    console.log("⏭️ socket_global già inizializzato in questa pagina → skip");
    return;
  }
  window.__socket_page_bootstrap_done__ = true;

  // ===============================
  // CLIENT ID STABILE
  // ===============================
  if (!localStorage.getItem("client_id")) {
    localStorage.setItem("client_id", crypto.randomUUID());
  }

  function detectDeviceType() {
    try {
      if (window.matchMedia("(display-mode: standalone)").matches || window.navigator.standalone) {
        return "pwa";
      }
      if (/Mobi|Android|iPhone|iPad/i.test(navigator.userAgent)) return "mobile";
      return "desktop";
    } catch (e) {
      return "unknown";
    }
  }
  function shouldInitSocketOnThisPage() {
    try {
      // Socket globale leggera su tutte le pagine.
      // La logica chat vera resta confinata a chat_conversazione.html.
      return true;
    } catch (e) {
      return true;
    }
  }

if (!shouldInitSocketOnThisPage()) {
  console.log("⏭️ socket_global: init socket saltata su questa pagina", {
    pathname: window.location.pathname
  });

  window.socket = null;
  window.__active_socket = null;
  window.__current_socket_id = null;

  window.whenSocketReady = function () {
    console.log("⏭️ whenSocketReady ignorato: socket non prevista su questa pagina");
  };

  return;
}

// ===============================
// CREA SOCKET DELLA PAGINA CORRENTE
// ===============================
const SOCKET_BASE_URL =
  window.__SOCKET_BASE_URL__ ||
  document.documentElement.dataset.socketBaseUrl ||
  "https://chat.mylocalcare.it";

// ======================================================
// HARD GUARD SOCKET.IO
// ======================================================
// Qualunque chiamata a io(...) fatta da altri script dopo socket_global
// viene forzata a usare SOLO websocket.
// Serve a evitare il ritorno del polling su pagine globali/admin/navbar.
if (window.io && !window.__io_websocket_only_guard_installed__) {
  window.__io_websocket_only_guard_installed__ = true;

  const __originalIo = window.io;

  window.io = function (...args) {
    let url = args[0];
    let opts = args[1];

    // Caso io(options)
    if (typeof url === "object" && url !== null) {
      opts = url;
      url = undefined;
    }

    opts = {
      ...(opts || {}),
      transports: ["websocket"],
      upgrade: false,
      path: (opts && opts.path) || "/socket.io"
    };

    console.log("🛡️ io() forzato websocket-only", {
      url: url || "(default)",
      transports: opts.transports,
      upgrade: opts.upgrade,
      pathname: window.location.pathname
    });

    if (url === undefined) {
      return __originalIo(opts);
    }

    return __originalIo(url, opts);
  };

  // Copia proprietà statiche eventuali di io, per compatibilità.
  try {
    Object.keys(__originalIo).forEach((key) => {
      if (!(key in window.io)) {
        window.io[key] = __originalIo[key];
      }
    });
  } catch (_) {}
}

    // ===============================
    // CLEANUP LEGGERO PRECEDENTE
    // ===============================
    // Qui NON disconnettiamo la socket precedente:
    // in Safari/PWA durante esci->rientra rischiamo di abbattere
    // proprio la connessione valida mentre la nuova pagina si sta legando.
    // Facciamo solo cleanup del debug globale e del vecchio heartbeat.
    try {
      if (window.__socket_heartbeat_interval__) {
        clearInterval(window.__socket_heartbeat_interval__);
        window.__socket_heartbeat_interval__ = null;
        console.log("🧹 heartbeat interval precedente ripulito");
      }

      if (window.__active_socket && window.__socket_debug_any_handler__) {
        try {
          window.__active_socket.offAny(window.__socket_debug_any_handler__);
          console.log("🧹 offAny debug precedente ripulito");
        } catch (_) {}
      }
    } catch (e) {
      console.warn("⚠️ Errore cleanup leggero socket precedente:", e);
    }

    const socket = io(SOCKET_BASE_URL, {
      path: "/socket.io",

      // ✅ Usiamo SOLO websocket.
      // Evita il ciclo polling GET/POST che su Render/gunicorn multi-worker
      // può produrre 400 "Session ID unknown" quando GET e POST finiscono
      // su worker diversi.
      transports: ["websocket"],
      upgrade: false,

      withCredentials: true,

      reconnection: true,
      reconnectionAttempts: Infinity,
      reconnectionDelay: 500,
      reconnectionDelayMax: 2000,
      randomizationFactor: 0.2,
      timeout: 8000,

      auth: {
        device_type: detectDeviceType(),
        client_id: localStorage.getItem("client_id"),
        token: window.__SOCKET_AUTH_TOKEN__ || null
      }
    });

  // ======================================================
  // DEBUG HARD: traccia chi aggancia/stacca listener chat
  // ======================================================
  const __origOn = socket.on.bind(socket);
  const __origOff = socket.off.bind(socket);

  const __traceEvents = new Set([
    "new_message",
    "messages_read",
    "message_delivered",
    "user_typing",
    "chat_threads_update",
    "update_unread_count",
    "connect",
    "disconnect"
  ]);

  socket.on = function (eventName, handler, ...rest) {
    if (__traceEvents.has(eventName)) {
      console.log("🧷 [SOCKET TRACE] on", eventName, {
        socketId: socket.id || null,
        handlerName: handler?.name || "(anonimo)",
        stack: new Error().stack
      });
    }
    return __origOn(eventName, handler, ...rest);
  };

  socket.off = function (eventName, handler, ...rest) {
    if (__traceEvents.has(eventName)) {
      console.warn("✂️ [SOCKET TRACE] off", eventName, {
        socketId: socket.id || null,
        withHandler: !!handler,
        handlerName: handler?.name || null,
        stack: new Error().stack
      });
    }
    return __origOff(eventName, handler, ...rest);
  };

  // riferimenti globali compatibili col resto del progetto
  window.socket = socket;
  window.__active_socket = socket;
  window.__current_socket_id = null;

  // ===============================
  // BADGE ICONA PWA
  // ===============================
  async function lcSetPWABadge(count) {
    try {
      const numero = parseInt(count || 0, 10);

      if (!("setAppBadge" in navigator) || !("clearAppBadge" in navigator)) {
        return;
      }

      if (numero > 0) {
        await navigator.setAppBadge(numero);
      } else {
        await navigator.clearAppBadge();
      }

      console.log("🔢 Badge PWA aggiornato:", numero);

    } catch (e) {
      console.warn("⚠️ Badge PWA non aggiornabile:", e);
    }
  }

  async function lcRefreshPWABadgeFromServer() {
    try {
      const res = await fetch("/pwa/badge_count", {
        method: "GET",
        credentials: "same-origin",
        headers: {
          "Accept": "application/json"
        }
      });

      if (!res.ok) return;

      const data = await res.json();
      await lcSetPWABadge(data.count || 0);

    } catch (e) {
      console.warn("⚠️ Errore refresh badge PWA:", e);
    }
  }

  // ===============================
  // BADGE CAMPANELLA NAVBAR
  // ===============================
  function lcSetNavbarNotificationBadge(count) {
    try {
      const badge = document.getElementById("notifBadge");
      if (!badge) return;

      const numero = parseInt(count || 0, 10);

      badge.dataset.unread = String(numero);

      if (numero > 0) {
        badge.textContent = String(numero);
        badge.style.display = "";
      } else {
        badge.textContent = "";
        badge.style.display = "none";
      }

      console.log("🔔 Badge campanella aggiornato:", numero);

    } catch (e) {
      console.warn("⚠️ Badge campanella non aggiornabile:", e);
    }
  }

  async function lcRefreshNavbarNotificationBadgeFromServer() {
    try {
      const res = await fetch("/notifiche/unread_count", {
        method: "GET",
        credentials: "same-origin",
        headers: {
          "Accept": "application/json"
        }
      });

      if (!res.ok) return;

      const data = await res.json();
      lcSetNavbarNotificationBadge(data.count || 0);

    } catch (e) {
      console.warn("⚠️ Errore refresh badge campanella:", e);
    }
  }


  window.lcSetPWABadge = lcSetPWABadge;
  window.lcRefreshPWABadgeFromServer = lcRefreshPWABadgeFromServer;
  window.lcSetNavbarNotificationBadge = lcSetNavbarNotificationBadge;
  window.lcRefreshNavbarNotificationBadgeFromServer = lcRefreshNavbarNotificationBadgeFromServer;

  // Aggiorna badge quando la pagina/PWA viene caricata
  lcRefreshPWABadgeFromServer();
  lcRefreshNavbarNotificationBadgeFromServer();

  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible") {
      lcRefreshPWABadgeFromServer();
      lcRefreshNavbarNotificationBadgeFromServer();
    }
  });

  window.addEventListener("focus", () => {
    lcRefreshPWABadgeFromServer();
    lcRefreshNavbarNotificationBadgeFromServer();
  });

  window.addEventListener("pageshow", () => {
    lcRefreshPWABadgeFromServer();
    lcRefreshNavbarNotificationBadgeFromServer();
  });

  // ===============================
  // HEARTBEAT
  // ===============================
  function emitHeartbeat() {
    if (!socket || !socket.connected) return;

    try {
      socket.emit("socket_heartbeat");
    } catch (e) {
      console.warn("Errore emit socket_heartbeat:", e);
    }
  }

  window.__emitSocketHeartbeat = emitHeartbeat;

  let pageSocketDisposed = false;

  function disposePageSocket(reason = "pagehide") {
    if (pageSocketDisposed) return;
    pageSocketDisposed = true;
    socket.__page_disposed__ = true;

    try {
      console.log("🛑 disposePageSocket", {
        reason,
        socketId: socket.id || null,
        connected: socket.connected
      });
    } catch (_) {}

    try {
      if (window.__socket_heartbeat_interval__) {
        clearInterval(window.__socket_heartbeat_interval__);
        window.__socket_heartbeat_interval__ = null;
      }
    } catch (_) {}

    try {
      if (window.__socket_debug_any_handler__) {
        socket.offAny(window.__socket_debug_any_handler__);
      }
    } catch (_) {}

    try {
      if (fastReconnectTimer) {
        clearTimeout(fastReconnectTimer);
        fastReconnectTimer = null;
      }
      fastReconnectInFlight = false;
    } catch (_) {}

    // IMPORTANTE:
    // su iPhone PWA pagehide/beforeunload possono scattare in situazioni
    // in cui non vogliamo abbattere aggressivamente la socket.
    // Lasciamo che sia il browser / socket.io a gestire la chiusura naturale.
    try {
      console.log("ℹ️ disposePageSocket: nessun socket.disconnect() esplicito");
    } catch (_) {}
  }

  window.addEventListener("pagehide", (event) => {
    disposePageSocket(event && event.persisted ? "pagehide_bfcache" : "pagehide");
  });

  window.addEventListener("beforeunload", () => {
    disposePageSocket("beforeunload");
  });

  // ===============================
  // LISTENER BASE SOCKET
  // ===============================
  socket.on("connect", () => {
    console.log("🔌 socket connected:", socket.id);

    window.__active_socket = socket;
    window.__current_socket_id = socket.id;

    emitHeartbeat();
    lcRefreshPWABadgeFromServer();
    lcRefreshNavbarNotificationBadgeFromServer();

    window.dispatchEvent(new Event("socket_ready"));

    socket.on("notifiche_unread_count", () => {
      lcRefreshPWABadgeFromServer();
      lcRefreshNavbarNotificationBadgeFromServer();
    });

    socket.on("nuova_notifica", () => {
      lcRefreshPWABadgeFromServer();
      lcRefreshNavbarNotificationBadgeFromServer();
    });

    socket.on("notifica_letta", () => {
      lcRefreshPWABadgeFromServer();
      lcRefreshNavbarNotificationBadgeFromServer();
    });
    
  /*
    Eventi chat:
    il badge interno messaggi resta gestito dai suoi script.
    Qui aggiorniamo solo il badge icona PWA con totale notifiche + messaggi.
  */
  socket.on("update_unread_count", () => {
    lcRefreshPWABadgeFromServer();
  });

  socket.on("new_message", () => {
    lcRefreshPWABadgeFromServer();
  });

  socket.on("messages_read", () => {
    lcRefreshPWABadgeFromServer();
  });

  socket.on("disconnect", (reason) => {
    console.log("🔌 socket disconnected:", reason);
  });

  socket.on("connect_error", (err) => {
    console.warn("⚠️ socket connect_error:", err?.message || err);
  });

  let fastReconnectTimer = null;
  let fastReconnectInFlight = false;
  let lastFastReconnectAt = 0;

  function forceFastReconnect(reason, delay = 120) {
    try {
      const now = Date.now();
      if (pageSocketDisposed || socket.__page_disposed__ === true) {
        console.log("⏸️ force reconnect skip: pagina/socket dismessa", reason);
        return;
      }

      console.log("⚡ forceFastReconnect:", reason, {
        connected: socket.connected,
        active: socket.active,
        visibility: document.visibilityState,
        online: navigator.onLine,
        inFlight: fastReconnectInFlight,
        hasTimer: !!fastReconnectTimer,
        sinceLast: now - lastFastReconnectAt
      });

      if (socket.connected) {
        emitHeartbeat();
        return;
      }

      if (!navigator.onLine) {
        console.log("⏸️ force reconnect skip: offline", reason);
        return;
      }

      if (fastReconnectInFlight) {
        console.log("⏸️ force reconnect skip: already in flight", reason);
        return;
      }

      if (fastReconnectTimer) {
        console.log("⏸️ force reconnect skip: timer già presente", reason);
        return;
      }

      if (now - lastFastReconnectAt < 1200) {
        console.log("⏸️ force reconnect skip: cooldown attivo", reason);
        return;
      }

      fastReconnectTimer = setTimeout(() => {
        if (pageSocketDisposed || socket.__page_disposed__ === true) {
          fastReconnectTimer = null;
          fastReconnectInFlight = false;
          console.log("⏸️ force reconnect timer abort: pagina/socket dismessa", reason);
          return;
        }

        fastReconnectTimer = null;
        fastReconnectInFlight = true;
        lastFastReconnectAt = Date.now();

        try {
          console.log("🚀 force reconnect start:", reason, {
            connected: socket.connected,
            active: socket.active,
            visibility: document.visibilityState,
            online: navigator.onLine
          });

          if (socket.connected) {
            emitHeartbeat();
            return;
          }

          try {
            // ✅ Mantieni websocket-only anche nei reconnect forzati.
            // Non reintrodurre polling, altrimenti tornano i POST /socket.io 400.
            socket.io.opts.transports = ["websocket"];
            socket.io.opts.upgrade = false;
          } catch (_) {}

          try {
            socket.disconnect();
          } catch (e) {
            console.warn("⚠️ force reconnect disconnect error:", e);
          }

          setTimeout(() => {
            try {
              if (pageSocketDisposed || socket.__page_disposed__ === true) {
                console.log("⏸️ force reconnect connect abort: pagina/socket dismessa", reason);
                return;
              }

              socket.connect();
            } catch (e) {
              console.warn("⚠️ force reconnect connect error:", e);
            } finally {
              setTimeout(() => {
                fastReconnectInFlight = false;
              }, 700);
            }
          }, 150);

        } catch (e) {
          fastReconnectInFlight = false;
          console.warn("⚠️ forceFastReconnect error:", e);
        }
      }, delay);

    } catch (e) {
      console.warn("⚠️ forceFastReconnect outer error:", e);
    }
  }

  window.__forceFastReconnect = forceFastReconnect;

  function isRealChatPage() {
    try {
      return !!document.querySelector('meta[name="chat-aperta"][content="true"]');
    } catch (_) {
      return false;
    }
  }

  function forceFastReconnectOnlyOnChat(reason, delay) {
    if (!isRealChatPage()) {
      console.log("⏭️ forceFastReconnect skip: pagina non chat", {
        reason,
        pathname: window.location.pathname
      });
      return;
    }

    forceFastReconnect(reason, delay);
  }

  window.addEventListener("online", () => {
    forceFastReconnectOnlyOnChat("window_online", 50);
  });

  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible") {
      forceFastReconnectOnlyOnChat("visibility_visible", 80);
    }
  });

  window.addEventListener("focus", () => {
    forceFastReconnectOnlyOnChat("window_focus", 100);
  });

  window.addEventListener("pageshow", () => {
    forceFastReconnectOnlyOnChat("pageshow", 120);
  });
  // ===============================
  // DEBUG INGRESSO EVENTI SOCKET
  // ===============================
  const __debugIncomingEvents = new Set([
    "new_message",
    "messages_read",
    "message_delivered",
    "user_typing",
    "chat_threads_update",
    "update_unread_count"
  ]);

  if (window.__socket_debug_any_handler__) {
    socket.offAny(window.__socket_debug_any_handler__);
  }

  window.__socket_debug_any_handler__ = function (eventName, ...args) {
    if (!__debugIncomingEvents.has(eventName)) return;

    const payload = args && args.length ? args[0] : null;
    const isChatPage = !!document.querySelector('meta[name="chat-aperta"][content="true"]');
    const pageId = window.__chatPageId || null;

    console.log("📥 [SOCKET IN]", {
      event: eventName,
      socketId: socket.id || null,
      pathname: window.location.pathname,
      pageId,
      payload
    });

    // DEBUG HTTP disattivato di default per evitare tempeste di POST
    // durante reconnect / on-off rete / resume PWA iPhone.
    const enableHttpSocketDebug = window.__ENABLE_HTTP_SOCKET_DEBUG__ === true;
    if (!enableHttpSocketDebug) {
      return;
    }

    // POST debug solo nella pagina chat reale
    // e solo quando la pagina ha già creato il suo page_id
    if (!isChatPage || !pageId) {
      return;
    }

    fetch("/chat-debug-socket-event", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      credentials: "same-origin",
      keepalive: true,
      body: JSON.stringify({
        event: eventName,
        socket_id: socket.id || null,
        pathname: window.location.pathname,
        page_id: pageId,
        payload,
        ts: new Date().toISOString()
      })
    }).catch((err) => {
      console.warn("❌ Errore chat-debug-socket-event", err);
    });
  };
  socket.onAny(window.__socket_debug_any_handler__);

  // ===============================
  // API USATA DAL RESTO DEL SITO
  // ===============================
  window.whenSocketReady = function (callback) {
    if (!socket) return;

    if (socket.connected) {
      callback(socket);
      return;
    }

    socket.once("connect", () => {
      callback(socket);
    });
  };

  // ===============================
  // DISCONNECT SOLO SU NAVIGAZIONE INTERNA REALE
  // ===============================
  if (window.__socketInternalNavHandlerRef) {
    document.removeEventListener("click", window.__socketInternalNavHandlerRef, true);
  }

  window.__socketInternalNavHandlerRef = function (e) {
    const a = e.target.closest("a");
    if (!a) return;

    const href = a.getAttribute("href");
    if (!href) return;

    // ignora anchor, javascript, nuova scheda, link esterni
    if (
      href.startsWith("#") ||
      href.startsWith("javascript:") ||
      a.target === "_blank" ||
      (a.origin && a.origin !== window.location.origin)
    ) {
      return;
    }

    // evita doppie chiusure
    if (socket.__internal_nav_disconnect_done__) {
      return;
    }
    socket.__internal_nav_disconnect_done__ = true;

    try {
      console.log("🧭 Navigazione interna rilevata -> disconnect socket corrente", {
        href,
        socketId: socket.id || null,
        connected: socket.connected
      });
    } catch (_) {}

    socket.__page_disposed__ = true;

    try {
      if (window.__socket_heartbeat_interval__) {
        clearInterval(window.__socket_heartbeat_interval__);
        window.__socket_heartbeat_interval__ = null;
      }
    } catch (_) {}

    try {
      if (window.__socket_debug_any_handler__) {
        socket.offAny(window.__socket_debug_any_handler__);
      }
    } catch (_) {}

    try {
      if (fastReconnectTimer) {
        clearTimeout(fastReconnectTimer);
        fastReconnectTimer = null;
      }
      fastReconnectInFlight = false;
    } catch (_) {}

    try {
      socket.disconnect();
    } catch (err) {
      console.warn("⚠️ Errore disconnect su navigazione interna:", err);
    }
  };

  document.addEventListener("click", window.__socketInternalNavHandlerRef, true);

  // ===============================
  // HEARTBEAT INTERVAL
  // ===============================
  window.__socket_heartbeat_interval__ = setInterval(() => {
    emitHeartbeat();
  }, 20000);

  })();
