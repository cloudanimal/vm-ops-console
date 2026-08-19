/* Campaigns v2 — ClickUp-style workspace merged into vm-ops-console.
   Phase P0 placeholder: exposes the CV2 mount/unmount contract the console
   host router drives. The wrapped clone app + shared-data adapter arrive in
   later phases. All clone code will live inside this one IIFE under window.CV2. */
(function () {
  'use strict';
  window.CV2 = {
    _booted: false,
    _root: null,
    boot: function () { this._booted = true; },
    mount: function (root /*, store */) {
      this._root = root;
      root.innerHTML =
        '<div style="padding:28px 24px;color:var(--ink);font-family:var(--sans)">' +
        '<div style="font-size:12px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:var(--accent)">Campaigns v2</div>' +
        '<h2 style="font-family:var(--serif);font-size:24px;margin:6px 0 8px">ClickUp-style workspace</h2>' +
        '<p style="color:var(--soft);max-width:640px">Scaffolding is in place. The task/board manager and the shared-data adapter (reading your real campaigns and findings) mount here in the next build phases.</p>' +
        '</div>';
      window._cv2Cleanup = function () { if (window.CV2 && window.CV2.unmount) window.CV2.unmount(); };
    },
    rerender: function () {},
    unmount: function () { this._root = null; }
  };
})();
