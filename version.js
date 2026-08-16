// Single source of truth for the app version.
// Loaded by index.html as a classic <script> (sets window.APP_VERSION) and imported by
// sw.js via importScripts() (sets the service-worker global). Bump this one line to release;
// the footer badge and the service-worker cache name both derive from it.
var APP_VERSION = '1.9.7';
if (typeof self !== 'undefined') self.APP_VERSION = APP_VERSION;
