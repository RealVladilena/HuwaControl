// HuwaControl — Service Worker (PWA)
// Cache les ressources statiques pour un chargement hors-ligne basique.
const CACHE_NAME = 'huwacontrol-v1';
const STATIC_ASSETS = [
  '/static/css/style.css',
  '/static/js/dashboard.js',
  'https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js',
  'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css',
];

self.addEventListener('install', event => {
  self.skipWaiting();
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => cache.addAll(STATIC_ASSETS).catch(() => {}))
  );
});

self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k)))
    )
  );
  self.clients.claim();
});

self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);
  // Ne pas intercepter les appels API ni les routes dynamiques
  if (url.pathname.startsWith('/api/') || event.request.method !== 'GET') return;

  // Stratégie network-first pour les pages, cache-first pour les assets statiques
  if (url.pathname.startsWith('/static/')) {
    event.respondWith(
      caches.match(event.request).then(cached =>
        cached || fetch(event.request).then(resp => {
          if (resp.ok) {
            const clone = resp.clone();
            caches.open(CACHE_NAME).then(c => c.put(event.request, clone));
          }
          return resp;
        })
      )
    );
  }
});
