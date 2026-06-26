self.addEventListener('install', event => {
  self.skipWaiting();
});

self.addEventListener('activate', event => {
  event.waitUntil(self.clients.claim());
});

self.addEventListener('fetch', event => {
  const request = event.request;

  // Gestiamo solo le navigazioni pagina della PWA
  if (request.mode !== "navigate") {
    return;
  }

  event.respondWith(
    fetch(request)
      .then(response => {
        // Se Render risponde 502/503/504 mostriamo pagina di attesa
        if ([502, 503, 504].includes(response.status)) {
          return paginaAttesaRender();
        }

        return response;
      })
      .catch(() => {
        // Se rete/server non raggiungibile
        return paginaAttesaRender();
      })
  );
});

function paginaAttesaRender() {
  return new Response(`
    <!doctype html>
    <html lang="it">
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>MyLocalCare si sta aggiornando</title>
        <style>
          body {
            margin: 0;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
            background: #f8fafc;
            color: #0f172a;
            padding: 24px;
          }

          .card {
            max-width: 420px;
            width: 100%;
            text-align: center;
            background: white;
            border: 1px solid #e2e8f0;
            border-radius: 26px;
            padding: 28px 22px;
            box-shadow: 0 18px 50px rgba(15, 23, 42, 0.12);
          }

          img {
            width: 86px;
            height: 86px;
            object-fit: contain;
            margin-bottom: 16px;
          }

          h1 {
            font-size: 1.35rem;
            margin: 0 0 10px;
          }

          p {
            margin: 0 0 20px;
            color: #64748b;
            line-height: 1.45;
          }

          button {
            border: 0;
            border-radius: 999px;
            background: #2563eb;
            color: white;
            font-weight: 800;
            padding: 13px 22px;
            font-size: 0.95rem;
          }
        </style>
      </head>
      <body>
        <div class="card">
          <img src="/static/img/logo.png" alt="MyLocalCare">
          <h1>MyLocalCare si sta aggiornando</h1>
          <p>Il server potrebbe essere in fase di riavvio o deploy. Riprova tra qualche secondo.</p>
          <button onclick="window.location.reload()">Riprova</button>
        </div>
      </body>
    </html>
  `, {
    status: 200,
    headers: {
      "Content-Type": "text/html; charset=utf-8"
    }
  });
}

/* ===========================
   GESTIONE PUSH
=========================== */

self.addEventListener('push', function(event) {

  console.log("🔥 PUSH RICEVUTO");

  let data = {
    title: "MyLocalCare",
    body: "Nuova notifica",
    url: "/utente/dashboard",
    unread_count: 1
  };

  if (event.data) {
    try {
      data = event.data.json();
    } catch (e) {
      data.body = event.data.text();
    }
  }

  const unreadCountRaw = parseInt(data.unread_count, 10);
  const unreadCount = Number.isFinite(unreadCountRaw) ? unreadCountRaw : 1;
  
  const showNotificationPromise = self.registration.showNotification(data.title || "MyLocalCare", {
    body: data.body || "Nuova notifica",
    icon: "/static/icons/icon-192.png",
    badge: "/static/icons/icon-192.png",
    data: {
      url: data.url || "/notifiche"
    }
  });

  let badgePromise = Promise.resolve();

  try {
    if ("setAppBadge" in self.registration) {
      if (unreadCount > 0) {
        badgePromise = self.registration.setAppBadge(unreadCount);
      } else if ("clearAppBadge" in self.registration) {
        badgePromise = self.registration.clearAppBadge();
      }
    }
  } catch (e) {
    badgePromise = Promise.resolve();
  }

  event.waitUntil(
    Promise.all([
      showNotificationPromise,
      badgePromise
    ])
  );
});

/* ===========================
   CLICK SULLA NOTIFICA
=========================== */

self.addEventListener('notificationclick', function(event) {

  event.notification.close();

  const url = event.notification.data.url || "/";

  event.waitUntil(
    clients.matchAll({ type: "window", includeUncontrolled: true, visibilityState: "visible" })
      .then(function(clientList) {

        for (const client of clientList) {
          if (client.url === url && 'focus' in client) {
            return client.focus();
          }
        }

        if (clients.openWindow) {
          return clients.openWindow(url);
        }
      })
  );
});
