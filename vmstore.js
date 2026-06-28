/* VMStore — a tiny shared IndexedDB cache for uploaded source files, so the unified
   Data Import page can feed every dashboard. Stores RAW file text per source id
   ({id, name, text, kind:'json'|'csv', size, importedAt}); each consumer parses on
   read with its own logic, which guarantees format compatibility.

   Source ids: acd:ad, acd:me, acd:tsc, acd:tio, acd:cs (Agent Coverage),
               findings (Findings workbench).
   Everything stays in the browser — IndexedDB is local-only, never uploaded. */
(function () {
  var DB = 'vmops-data', STORE = 'files', VER = 1;
  var _db = null;
  function open() {
    if (_db) return Promise.resolve(_db);
    return new Promise(function (res, rej) {
      var rq = indexedDB.open(DB, VER);
      rq.onupgradeneeded = function () { var db = rq.result; if (!db.objectStoreNames.contains(STORE)) db.createObjectStore(STORE, { keyPath: 'id' }); };
      rq.onsuccess = function () { _db = rq.result; res(_db); };
      rq.onerror = function () { rej(rq.error); };
    });
  }
  function tx(mode, fn) {
    return open().then(function (db) {
      return new Promise(function (res, rej) {
        var t = db.transaction(STORE, mode), req = fn(t.objectStore(STORE));
        t.oncomplete = function () { res(req ? req.result : undefined); };
        t.onerror = function () { rej(t.error); };
        t.onabort = function () { rej(t.error); };
      });
    });
  }
  window.VMStore = {
    // put({id, name, text, kind, size}); stamps importedAt
    put: function (rec) {
      rec = Object.assign({ importedAt: new Date().toISOString() }, rec);
      return tx('readwrite', function (st) { return st.put(rec); }).then(function () { return rec; });
    },
    get: function (id) { return tx('readonly', function (st) { return st.get(id); }); },
    all: function () {
      return open().then(function (db) {
        return new Promise(function (res, rej) {
          var out = [], t = db.transaction(STORE, 'readonly'), c = t.objectStore(STORE).openCursor();
          c.onsuccess = function () { var cur = c.result; if (cur) { out.push(cur.value); cur.continue(); } else res(out); };
          c.onerror = function () { rej(c.error); };
        });
      });
    },
    remove: function (id) { return tx('readwrite', function (st) { return st.delete(id); }); }
  };
})();
