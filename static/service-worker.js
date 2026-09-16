self.addEventListener('install', event => {
  self.skipWaiting();
});

self.addEventListener('activate', event => {
  event.waitUntil(self.clients.claim());
});

function localcareLanguageCode() {
  const rawLanguage = String(
    (self.navigator && self.navigator.language) || "it"
  ).toLowerCase();
  const language = rawLanguage.slice(0, 2);

  return ["it", "en", "fr", "es", "de"].includes(language)
    ? language
    : "it";
}

function localcareOfflineCopy() {
  const language = localcareLanguageCode();
  const translations = {
    it: {
      title: "MyLocalCare si sta aggiornando",
      description: "Il server potrebbe essere in fase di riavvio o deploy. Riprova tra qualche secondo.",
      retry: "Riprova",
      notification: "Nuova notifica"
    },
    en: {
      title: "MyLocalCare is updating",
      description: "The server may be restarting or deploying an update. Please try again in a few seconds.",
      retry: "Try again",
      notification: "New notification"
    },
    fr: {
      title: "MyLocalCare est en cours de mise à jour",
      description: "Le serveur redémarre peut-être ou déploie une mise à jour. Réessayez dans quelques secondes.",
      retry: "Réessayer",
      notification: "Nouvelle notification"
    },
    es: {
      title: "MyLocalCare se está actualizando",
      description: "Es posible que el servidor se esté reiniciando o instalando una actualización. Inténtalo de nuevo en unos segundos.",
      retry: "Volver a intentar",
      notification: "Nueva notificación"
    },
    de: {
      title: "MyLocalCare wird aktualisiert",
      description: "Der Server wird möglicherweise neu gestartet oder aktualisiert. Versuche es in wenigen Sekunden erneut.",
      retry: "Erneut versuchen",
      notification: "Neue Benachrichtigung"
    }
  };

  return { language, ...translations[language] };
}

function localcareNotificationFallback() {
  return localcareOfflineCopy().notification;
}

self.addEventListener('fetch', event => {
  const request = event.request;

  // Gestiamo solo le normali navigazioni GET.
  // I POST, soprattutto quelli con file, devono raggiungere direttamente il server.
  if (request.mode !== "navigate" || request.method !== "GET") {
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
  const copy = localcareOfflineCopy();

  return new Response(`
    <!doctype html>
    <html lang="${copy.language}">
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>${copy.title}</title>
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
          <h1>${copy.title}</h1>
          <p>${copy.description}</p>
          <button onclick="window.location.reload()">${copy.retry}</button>
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
    body: localcareNotificationFallback(),
    url: "/utente/dashboard",
    pwa_badge_count: 1
  };

  if (event.data) {
    try {
      data = event.data.json();
    } catch (e) {
      data.body = event.data.text();
    }
  }

  const badgeCountRaw = parseInt(
    data.pwa_badge_count !== undefined ? data.pwa_badge_count : data.unread_count,
    10
  );

  const badgeCount = Number.isFinite(badgeCountRaw) ? badgeCountRaw : 1;

  const showNotificationPromise = self.registration.showNotification(data.title || "MyLocalCare", {
    body: data.body || localcareNotificationFallback(),
    icon: "/static/icons/icon-192.png",
    badge: "/static/icons/icon-192.png",
    data: {
      url: data.url || "/notifiche"
    }
  });

  let badgePromise = Promise.resolve();

  try {
    if ("setAppBadge" in self.registration) {
      if (badgeCount > 0) {
        badgePromise = self.registration.setAppBadge(badgeCount);
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
