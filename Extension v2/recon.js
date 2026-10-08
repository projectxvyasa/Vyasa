// recon.js — VYASA Attack-Surface Discovery Engine
// -----------------------------------------------------------------------------
// Answers "what endpoints and subdomains exist, and where is what?" BEFORE any
// active testing. It crawls the same origin (links + forms, including the search
// form), reads robots.txt and sitemap.xml, extracts endpoint-looking URLs from
// inline HTML/JS, guesses search parameters, and enumerates subdomains passively
// via Certificate Transparency (crt.sh) and a small DNS-over-HTTPS wordlist.
//
// Discovery is READ-ONLY reconnaissance: GET requests and public CT/DNS lookups.
// It does not send attack payloads — that is the active engine's job, and only
// on the authorized target origin. Subdomains are listed for situational
// awareness; VYASA never actively tests a subdomain it merely discovered.
// -----------------------------------------------------------------------------

const VYASA_RECON = (() => {
  'use strict';

  const LIMITS = {
    MAX_CRAWL_PAGES: 8,       // same-origin pages fetched during crawl
    MAX_LINKS_PER_PAGE: 60,
    MAX_ENDPOINTS: 40,
    MAX_SUBDOMAINS: 60,
    FETCH_TIMEOUT_MS: 9000,
    DELAY_MS: 140,
    MAX_HTML: 500000
  };

  const SEARCH_PARAM_HINTS = ['q', 's', 'query', 'search', 'keyword', 'keywords', 'term', 'k', 'wd'];
  const SUBDOMAIN_WORDLIST = [
    'www', 'api', 'dev', 'staging', 'stage', 'test', 'admin', 'portal', 'app', 'mail',
    'webmail', 'cpanel', 'blog', 'shop', 'store', 'm', 'mobile', 'beta', 'demo', 'vpn',
    'ftp', 'ns1', 'ns2', 'dashboard', 'secure', 'login', 'auth', 'cdn', 'assets', 'static'
  ];

  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

  function withTimeout(p, ms) {
    return Promise.race([p, new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), ms))]);
  }

  async function getText(url, init) {
    try {
      const res = await withTimeout(fetch(url, Object.assign({ credentials: 'omit', redirect: 'follow', cache: 'no-store' }, init || {})), LIMITS.FETCH_TIMEOUT_MS);
      let t = '';
      try { t = await res.text(); } catch (e) { t = ''; }
      if (t.length > LIMITS.MAX_HTML) t = t.slice(0, LIMITS.MAX_HTML);
      return { ok: res.ok, status: res.status, body: t };
    } catch (e) {
      return { ok: false, status: 0, body: '', error: e.message };
    }
  }

  function registrableDomain(hostname) {
    const labels = hostname.replace(/^www\./i, '').split('.');
    if (labels.length <= 2) return labels.join('.');
    // naive 2-label base; good enough for .com/.net/.org/.in etc. common cases
    return labels.slice(-2).join('.');
  }

  // --- HTML parsing via regex (no DOM in service worker) ---------------------
  function extractLinks(html, baseUrl) {
    const out = [];
    const rx = /(?:href|src)\s*=\s*["']([^"'#]+)["']/gi;
    let m;
    while ((m = rx.exec(html)) && out.length < LIMITS.MAX_LINKS_PER_PAGE) {
      const raw = m[1].trim();
      if (!raw || raw.startsWith('data:') || raw.startsWith('javascript:') || raw.startsWith('mailto:') || raw.startsWith('tel:')) continue;
      try { out.push(new URL(raw, baseUrl).href); } catch (e) { /* noop */ }
    }
    return out;
  }

  function extractForms(html, baseUrl) {
    const forms = [];
    const formRx = /<form\b([^>]*)>([\s\S]*?)<\/form>/gi;
    let fm;
    while ((fm = formRx.exec(html)) && forms.length < 20) {
      const attrs = fm[1] || '';
      const inner = fm[2] || '';
      const action = (attrs.match(/action\s*=\s*["']([^"']*)["']/i) || [])[1] || baseUrl;
      const method = ((attrs.match(/method\s*=\s*["']([^"']*)["']/i) || [])[1] || 'GET').toUpperCase();
      const inputs = [];
      const inRx = /<(?:input|select|textarea)\b([^>]*)>/gi;
      let im;
      while ((im = inRx.exec(inner))) {
        const ia = im[1] || '';
        const name = (ia.match(/name\s*=\s*["']([^"']*)["']/i) || [])[1] || (ia.match(/\bid\s*=\s*["']([^"']*)["']/i) || [])[1] || '';
        const type = (ia.match(/type\s*=\s*["']([^"']*)["']/i) || [])[1] || 'text';
        if (name) inputs.push({ name, type });
      }
      let absAction = baseUrl;
      try { absAction = new URL(action, baseUrl).href; } catch (e) { /* noop */ }
      forms.push({ action: absAction, method, inputs });
    }
    return forms;
  }

  // Endpoint-looking paths referenced in scripts (e.g., "/api/search?q=").
  function extractJsEndpoints(html, baseUrl) {
    const out = [];
    const rx = /["'`](\/[A-Za-z0-9_\-./]+\?[A-Za-z0-9_\-=&%]+)["'`]/g;
    let m;
    while ((m = rx.exec(html)) && out.length < 40) {
      try { out.push(new URL(m[1], baseUrl).href); } catch (e) { /* noop */ }
    }
    return out;
  }

  // --- Endpoint normalization -------------------------------------------------
  function makeKey(method, u) { return `${method} ${u.origin}${u.pathname}`; }

  function addUrlAsEndpoint(map, rawUrl, method, origin, source) {
    let u;
    try { u = new URL(rawUrl); } catch (e) { return; }
    if (u.origin !== origin) return;
    const params = [];
    u.searchParams.forEach((value, name) => params.push({ name, value, location: 'query' }));
    const key = makeKey(method, u);
    let ep = map.get(key);
    if (!ep) { ep = { url: `${u.origin}${u.pathname}`, method, params: [], sources: new Set() }; map.set(key, ep); }
    ep.sources.add(source);
    for (const p of params) {
      if (!ep.params.some((x) => x.name === p.name && x.location === p.location)) ep.params.push(p);
    }
  }

  // Fields whose presence marks a form as STATE-CHANGING (submitting it has
  // real side effects: sends mail, creates accounts, places orders). VYASA must
  // never auto-submit these without a separate, explicit opt-in.
  const STATE_FIELD_RX = /(contact|message|comment|signup|sign_up|register|subscribe|newsletter|review|feedback|order|checkout|payment|pay|booking|book|enquiry|inquiry|password)/i;

  function classifyForm(inputs, method) {
    const names = (inputs || []).map((i) => (i.name || '').toLowerCase());
    const types = (inputs || []).map((i) => (i.type || '').toLowerCase());
    const hasPassword = types.includes('password');
    const isStateChanging = method === 'POST' && (hasPassword || names.some((n) => STATE_FIELD_RX.test(n)));
    const isSearch = !isStateChanging && (
      types.includes('search') ||
      names.some((n) => SEARCH_PARAM_HINTS.includes(n) || /search/.test(n))
    );
    const formType = isSearch ? 'search' : (isStateChanging ? 'state-changing' : 'generic');
    return { formType, isStateChanging };
  }

  function addFormAsEndpoint(map, form, origin, source) {
    let u;
    try { u = new URL(form.action); } catch (e) { return; }
    if (u.origin !== origin) return;
    const method = form.method || 'GET';
    const loc = method === 'GET' ? 'query' : 'body';
    const params = (form.inputs || []).map((i) => ({ name: i.name, value: i.type === 'number' ? '1' : 'test', location: loc }));
    const { formType, isStateChanging } = classifyForm(form.inputs, method);

    // Search-form heuristic (GET only): seed common search parameter names so a
    // reflected search XSS (e.g. WordPress ?s=) is reachable even when the real
    // input name is JS-driven. POST search forms already expose their real field.
    if (formType === 'search' && method === 'GET') {
      for (const hint of SEARCH_PARAM_HINTS) {
        if (!params.some((p) => p.name === hint)) params.push({ name: hint, value: 'test', location: 'query', inferred: true });
      }
    }

    // Distinct forms that post to the same path must stay distinct endpoints
    // (a search form and a contact form both hitting "/" are NOT one endpoint).
    const sig = params.map((p) => p.name).sort().join(',').slice(0, 120);
    const key = makeKey(method, u) + ' [' + sig + ']';
    let ep = map.get(key);
    if (!ep) { ep = { url: `${u.origin}${u.pathname}`, method, params: [], sources: new Set(), formType, isStateChanging }; map.set(key, ep); }
    ep.sources.add(source);
    if (formType === 'search') ep.sources.add('search-form');
    if (isStateChanging) ep.sources.add('state-changing');
    for (const p of params) {
      if (!ep.params.some((x) => x.name === p.name && x.location === p.location)) ep.params.push(p);
    }
  }

  // --- robots.txt / sitemap.xml ----------------------------------------------
  async function fetchRobotsAndSitemap(origin) {
    const found = [];
    const robots = await getText(`${origin}/robots.txt`);
    const sitemaps = [];
    if (robots.ok && robots.body) {
      const pathRx = /^(?:allow|disallow)\s*:\s*(\/\S*)/gim;
      let m;
      while ((m = pathRx.exec(robots.body))) {
        const p = m[1].replace(/\*$/, '');
        if (p && p !== '/') { try { found.push(new URL(p, origin).href); } catch (e) { /* noop */ } }
      }
      const smRx = /sitemap\s*:\s*(\S+)/gi;
      while ((m = smRx.exec(robots.body))) sitemaps.push(m[1].trim());
    }
    // default sitemap location
    sitemaps.push(`${origin}/sitemap.xml`);
    for (const sm of sitemaps.slice(0, 2)) {
      const res = await getText(sm);
      if (res.ok && res.body) {
        const locRx = /<loc>\s*([^<\s]+)\s*<\/loc>/gi;
        let lm, c = 0;
        while ((lm = locRx.exec(res.body)) && c < 40) { found.push(lm[1].trim()); c++; }
      }
      await sleep(LIMITS.DELAY_MS);
    }
    return found;
  }

  // --- Subdomain discovery ----------------------------------------------------
  async function discoverSubdomains(hostname) {
    const base = registrableDomain(hostname);
    const set = new Set();

    // (a) Certificate Transparency (crt.sh) — passive, public.
    try {
      const res = await getText(`https://crt.sh/?q=%25.${encodeURIComponent(base)}&output=json`, { headers: { 'Accept': 'application/json' } });
      if (res.ok && res.body) {
        let data = [];
        try { data = JSON.parse(res.body); } catch (e) { data = []; }
        for (const row of data) {
          const nv = (row && row.name_value) ? String(row.name_value) : '';
          nv.split(/\s+/).forEach((h) => {
            h = h.replace(/^\*\./, '').toLowerCase().trim();
            if (h.endsWith(base) && h !== base) set.add(h);
          });
          if (set.size > LIMITS.MAX_SUBDOMAINS) break;
        }
      }
    } catch (e) { /* tolerate */ }

    // (b) DNS-over-HTTPS wordlist probe (resolves common names).
    for (const w of SUBDOMAIN_WORDLIST) {
      if (set.size > LIMITS.MAX_SUBDOMAINS) break;
      const cand = `${w}.${base}`;
      if (set.has(cand)) continue;
      try {
        const r = await getText(`https://cloudflare-dns.com/dns-query?name=${cand}&type=A`, { headers: { 'Accept': 'application/dns-json' } });
        if (r.ok && r.body) {
          const j = JSON.parse(r.body);
          if (j.Answer && j.Answer.some((a) => a.type === 1 || a.type === 5)) set.add(cand);
        }
      } catch (e) { /* noop */ }
      await sleep(80);
    }

    return [...set].slice(0, LIMITS.MAX_SUBDOMAINS).sort();
  }

  // --- Orchestrator -----------------------------------------------------------
  async function discoverSurface(targetUrl, seed, opts) {
    opts = opts || {};
    const started = Date.now();
    let origin, hostname;
    try { const u = new URL(targetUrl); origin = u.origin; hostname = u.hostname; } catch (e) { return { error: 'INVALID_URL' }; }

    const map = new Map();
    const crawledPages = [];

    // 1. Seed from the live page (content script): links, forms, captured XHR.
    seed = seed || {};
    (seed.links || []).forEach((href) => addUrlAsEndpoint(map, href, 'GET', origin, 'dom-link'));
    (seed.forms || []).forEach((f) => addFormAsEndpoint(map, f, origin, 'dom-form'));
    (seed.requests || []).forEach((r) => addUrlAsEndpoint(map, r.url, (r.method || 'GET').toUpperCase(), origin, 'xhr-capture'));
    // target URL's own query
    addUrlAsEndpoint(map, targetUrl, 'GET', origin, 'address-bar');

    // 2. robots.txt + sitemap.xml
    let robotPaths = [];
    try { robotPaths = await fetchRobotsAndSitemap(origin); } catch (e) { robotPaths = []; }
    robotPaths.forEach((p) => addUrlAsEndpoint(map, p, 'GET', origin, 'robots/sitemap'));

    // 3. Shallow crawl: fetch the target + a few same-origin links, parse each.
    const toCrawl = [targetUrl, ...(seed.links || [])]
      .filter((h) => { try { return new URL(h).origin === origin; } catch (e) { return false; } })
      .filter((h, i, a) => a.indexOf(h) === i)
      .slice(0, LIMITS.MAX_CRAWL_PAGES);

    for (const pageUrl of toCrawl) {
      const res = await getText(pageUrl);
      if (res.ok && res.body) {
        crawledPages.push(pageUrl);
        extractLinks(res.body, pageUrl).forEach((l) => addUrlAsEndpoint(map, l, 'GET', origin, 'crawl-link'));
        extractForms(res.body, pageUrl).forEach((f) => addFormAsEndpoint(map, f, origin, 'crawl-form'));
        extractJsEndpoints(res.body, pageUrl).forEach((e) => addUrlAsEndpoint(map, e, 'GET', origin, 'js-endpoint'));
      }
      await sleep(LIMITS.DELAY_MS);
    }

    // 4. Subdomains (passive) — unless disabled.
    let subdomains = [];
    if (opts.subdomains !== false) {
      try { subdomains = await discoverSubdomains(hostname); } catch (e) { subdomains = []; }
    }

    // Finalize endpoints.
    const endpoints = [...map.values()]
      .map((ep) => ({ url: ep.url, method: ep.method, params: ep.params, sources: [...ep.sources] }))
      // endpoints that actually have testable params float to the top
      .sort((a, b) => (b.params.length > 0) - (a.params.length > 0))
      .slice(0, LIMITS.MAX_ENDPOINTS);

    return {
      ran: true,
      origin,
      hostname,
      durationMs: Date.now() - started,
      crawledPages,
      endpoints,
      subdomains,
      stats: {
        endpoints: endpoints.length,
        withParams: endpoints.filter((e) => e.params.length > 0).length,
        subdomains: subdomains.length,
        pagesCrawled: crawledPages.length
      }
    };
  }

  return { discoverSurface, discoverSubdomains, extractForms, extractLinks, registrableDomain, LIMITS };
})();

if (typeof self !== 'undefined') { self.VYASA_RECON = VYASA_RECON; }
if (typeof module !== 'undefined' && module.exports) { module.exports = VYASA_RECON; }
