// inject-hook.js — runs in the PAGE's MAIN world at document_start.
// It wraps fetch() and XMLHttpRequest so VYASA learns the application's REAL
// request parameters (the ones the SPA actually talks to), not just the static
// links and forms in the initial HTML. It only records metadata (URL, method,
// body field NAMES) and posts it to the isolated content script via postMessage.
// It never blocks, modifies, or logs request bodies/values — purely observational.
(function () {
  'use strict';
  if (window.__VYASA_HOOKED__) return;
  window.__VYASA_HOOKED__ = true;

  var SEEN = new Set();
  var MAX = 300;

  function keysFromBody(body) {
    try {
      if (!body) return [];
      if (typeof body === 'string') {
        // JSON?
        if (/^\s*[\{\[]/.test(body)) {
          try { var o = JSON.parse(body); return o && typeof o === 'object' ? Object.keys(o).slice(0, 40) : []; } catch (e) { /* not json */ }
        }
        // urlencoded?
        if (body.indexOf('=') !== -1) {
          return body.split('&').map(function (kv) { return kv.split('=')[0]; }).filter(Boolean).slice(0, 40);
        }
        return [];
      }
      if (typeof URLSearchParams !== 'undefined' && body instanceof URLSearchParams) {
        return [].concat.apply([], [[].concat.apply([], [Array.from(body.keys())])]).slice(0, 40);
      }
      if (typeof FormData !== 'undefined' && body instanceof FormData) {
        var ks = []; body.forEach(function (_v, k) { ks.push(k); }); return ks.slice(0, 40);
      }
    } catch (e) { /* noop */ }
    return [];
  }

  function record(url, method, bodyKeys) {
    try {
      if (!url) return;
      var abs = new URL(url, location.href).href;
      var key = (method || 'GET') + ' ' + abs + ' ' + (bodyKeys || []).join(',');
      if (SEEN.has(key) || SEEN.size > MAX) return;
      SEEN.add(key);
      window.postMessage({ source: 'vyasa-hook', req: { url: abs, method: (method || 'GET').toUpperCase(), bodyKeys: bodyKeys || [] } }, '*');
    } catch (e) { /* noop */ }
  }

  // --- fetch ---
  var origFetch = window.fetch;
  if (typeof origFetch === 'function') {
    window.fetch = function (input, init) {
      try {
        var url = typeof input === 'string' ? input : (input && input.url);
        var method = (init && init.method) || (input && input.method) || 'GET';
        var body = init && init.body;
        record(url, method, keysFromBody(body));
      } catch (e) { /* noop */ }
      return origFetch.apply(this, arguments);
    };
  }

  // --- XMLHttpRequest ---
  var origOpen = XMLHttpRequest.prototype.open;
  var origSend = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.open = function (method, url) {
    this.__vyasa_m = method; this.__vyasa_u = url;
    return origOpen.apply(this, arguments);
  };
  XMLHttpRequest.prototype.send = function (body) {
    try { record(this.__vyasa_u, this.__vyasa_m, keysFromBody(body)); } catch (e) { /* noop */ }
    return origSend.apply(this, arguments);
  };
})();
