/* Minimal Service Worker - 404 방지 및 PWA 등록용 */
self.addEventListener('install', function() { self.skipWaiting(); });
self.addEventListener('activate', function(e) { e.waitUntil(self.clients.claim()); });
