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

  console.log("Push ricevuta", event);

  let data = {};

  try {
    if (event.data) {
      data = event.data.json();
    }
  } catch (e) {
    console.error("Errore parsing push data", e);
  }

  const title = data.title || "LocalCare";

  const options = {
    body: data.body || "Hai una nuova notifica",
    icon: "/static/icons/icon-192.png",
    badge: "/static/icons/icon-192.png",
    data: {
      url: data.url || "/"
    }
  };

  event.waitUntil(
    self.registration.showNotification(title, options)
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
