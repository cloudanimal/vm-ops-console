/* VM Ops Console service worker — offline support.
   - App shell + same-origin files: network-first (so deploys show immediately), fall back to cache offline.
   - Big immutable assets (vendor libs, gzipped sample data, fonts, the jsDelivr Transformers.js ESM,
     and the Hugging Face Ask AI model files): cache-first, so the on-device LLM works offline after
     one full (uninterrupted) Ask AI run while online has populated the cache. (Transformers.js also
     keeps its own Cache Storage copy of the model, so it won't re-download regardless.)
   - Live public-CVE APIs (NVD, EPSS, CISA, …): passthrough, network only (they need fresh data and a
     connection; offline simply fails for those, the rest of the app keeps working).
   Bump CACHE to invalidate old caches on the next visit. */
var CACHE = 'vmops-v1';
var PRECACHE = [
  './', './index.html',
  './vmops.js', './vmops.css', './acd.js', './acd.css', './tvd.js', './tvd.css',
  './pscan.js', './pscan.css', './vmstore.js',
  './vendor/papaparse.min.js', './vendor/xlsx.full.min.js', './vendor/chart.umd.js',
  './vendor/html2canvas.min.js', './vendor/gifenc.global.js'
];

self.addEventListener('install', function (e) {
  e.waitUntil(caches.open(CACHE).then(function (c) {
    // best-effort precache — don't fail the install if one file is missing
    return Promise.all(PRECACHE.map(function (u) { return c.add(u).catch(function () {}); }));
  }).then(function () { return self.skipWaiting(); }));
});

self.addEventListener('activate', function (e) {
  e.waitUntil(caches.keys().then(function (keys) {
    return Promise.all(keys.map(function (k) { return k === CACHE ? null : caches.delete(k); }));
  }).then(function () { return self.clients.claim(); }));
});

function cacheFirst(req) {
  return caches.open(CACHE).then(function (c) {
    return c.match(req).then(function (hit) {
      if (hit) return hit;
      return fetch(req).then(function (res) { if (res && res.ok) c.put(req, res.clone()); return res; });
    });
  });
}
function networkFirst(req) {
  return caches.open(CACHE).then(function (c) {
    return fetch(req).then(function (res) {
      if (res && res.ok) c.put(req, res.clone());
      return res;
    }).catch(function () {
      return c.match(req).then(function (hit) {
        return hit || (req.mode === 'navigate' ? c.match('./index.html') : Response.error());
      });
    });
  });
}

self.addEventListener('fetch', function (e) {
  var req = e.request;
  if (req.method !== 'GET') return;
  // Honor the app's explicit freshness opt-out: the "Datasets & freshness" page fetches the live
  // feed with cache:'no-store' to read a true Last-Modified. Never cache or serve those from the SW,
  // so that check stays truthful (it fails honestly when offline rather than reporting stale-as-live).
  if (req.cache === 'no-store' || req.cache === 'no-cache') return;
  var url;
  try { url = new URL(req.url); } catch (err) { return; }
  var sameOrigin = url.origin === self.location.origin;
  var cdn = /(\.jsdelivr\.net|fonts\.googleapis\.com|fonts\.gstatic\.com|huggingface\.co|\.hf\.co|cdn-lfs)/.test(url.hostname);
  // Cache-first for big immutable assets: CDN/model/fonts + local vendor libs + gzipped sample data.
  if (cdn || (sameOrigin && /\/(vendor|sample-data)\//.test(url.pathname))) { e.respondWith(cacheFirst(req)); return; }
  // Same-origin app files (HTML/JS/CSS/JSON): network-first, fall back to cache when offline.
  if (sameOrigin) { e.respondWith(networkFirst(req)); return; }
  // Everything else (live CVE APIs, etc.): default network handling.
});
