self.addEventListener('install', event => {
  self.skipWaiting();
});

self.addEventListener('activate', event => {
  event.waitUntil(self.clients.claim());
});

self.addEventListener('fetch', event => {
  // Nessuna cache per ora
});

/* ===========================
   GESTIONE PUSH
=========================== */

self.addEventListener('push', function(event) {

  console.log("🔥 PUSH RICEVUTO");

  let data = {
    title: "LocalCare",
    body: "Nuova notifica",
    url: "/utente/dashboard"
  };

  if (event.data) {
    try {
      // Prova JSON
      data = event.data.json();
    } catch (e) {
      // Se non è JSON, usa testo semplice
      data.body = event.data.text();
    }
  }

  event.waitUntil(
    self.registration.showNotification(data.title, {
      body: data.body,
      icon: "/static/icons/icon-192.png",
      badge: "/static/icons/icon-192.png",
      data: {
        url: data.url
      }
    })
  );
});

/* ===========================
   CLICK SULLA NOTIFICA
=========================== */

self.addEventListener('notificationclick', function(event) {

  event.notification.close();

  const url = event.notification.data.url || "/";

  event.waitUntil(
    clients.matchAll({ type: "window", includeUncontrolled: true })
      .then(function(clientList) {

        for (let i = 0; i < clientList.length; i++) {
          const client = clientList[i];
          if (client.url.includes(self.location.origin) && 'focus' in client) {
            return client.focus();
          }
        }

        if (clients.openWindow) {
          return clients.openWindow(url);
        }
      })
  );
});
