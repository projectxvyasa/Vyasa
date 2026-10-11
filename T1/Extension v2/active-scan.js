// active-scan.js — VYASA Active Vulnerability Confirmation Engine
// -----------------------------------------------------------------------------
// This module turns VYASA from a PASSIVE auditor ("XSS is possible") into an
// ACTIVE confirmer ("parameter `q` on /search reflects unencoded in HTML context
// -> XSS CONFIRMED"). It discovers the real attack surface, tests each parameter
// individually with a unique canary, classifies the reflection context, and
// fingerprints exactly which characters a filter lets through.
//
// SAFETY MODEL (important — read before editing):
//   * Nothing here runs until the target origin is explicitly authorized by the
//     operator (handled in background.js via the authorization gate).
//   * GET parameters are tested by default. POST/mutating endpoints are only
//     touched when the operator opts in (opts.includePost), and even then only
//     with non-destructive canaries — never payloads that write/delete data.
//   * Confirmation is canary/marker based. We verify that *breaking characters
//     survive*; we do NOT fire a working exploit. The human operator fires the
//     final payload manually. This keeps VYASA on the "confirm + guide" side.
//   * SQLi probing is error-based + boolean-differential only (read-only). No
//     time-based blind (self-inflicted DoS), no stacked queries, no writes.
//   * All requests are throttled and capped (MAX_ENDPOINTS / MAX_PARAMS).
// -----------------------------------------------------------------------------

const VYASA_ACTIVE = (() => {
  'use strict';

  // ---- Tunables -------------------------------------------------------------
  const LIMITS = {
    MAX_ENDPOINTS: 25,       // endpoints tested per active scan
    MAX_PARAMS_PER_EP: 12,   // parameters probed per endpoint
    REQUEST_DELAY_MS: 120,   // throttle between active requests
    FETCH_TIMEOUT_MS: 9000,
    MAX_BODY_SCAN: 400000    // cap response body size we scan (chars)
  };

  // Delimiter wraps the probe so we can isolate what the app did to our chars.
  const MARK_L = 'qzx';
  const MARK_R = 'xzq';
  // Special chars whose survival determines exploitability per context.
  const PROBE_CHARS = ['<', '>', '"', "'", '`', '(', ')', ';', '/', '=', '{', '}'];

  // SQL error signatures (error-based SQLi — a single quote is enough to trigger).
  const SQL_ERRORS = [
    { db: 'MySQL', rx: /(SQL syntax.*MySQL|valid MySQL result|MySqlClient\.|com\.mysql\.jdbc|check the manual that corresponds to your (MySQL|MariaDB))/i },
    { db: 'PostgreSQL', rx: /(PostgreSQL.*ERROR|pg_query\(\)|pg_exec\(\)|PSQLException|unterminated quoted string)/i },
    { db: 'Microsoft SQL Server', rx: /(Microsoft SQL (Server|Native)|Unclosed quotation mark after the character string|SqlClient\.SqlException|System\.Data\.SqlClient)/i },
    { db: 'Oracle', rx: /(ORA-\d{4,5}|Oracle error|quoted string not properly terminated|OracleException)/i },
    { db: 'SQLite', rx: /(SQLite3::|SQLite\/JDBCDriver|sqlite3\.OperationalError|unrecognized token:)/i },
    { db: 'Generic SQL', rx: /(SQLSTATE\[|JDBC|ODBC SQL|syntax error at or near|quoted string not properly terminated)/i }
  ];

  // Common open-redirect parameter names (heuristic prioritization).
  const REDIRECT_PARAM_HINTS = /^(url|uri|redirect|redir|return|returnurl|return_to|next|dest|destination|continue|goto|target|r|u|link|out|view|page)$/i;

  // Path-based search routes to probe (many sites route search as /search/<term>/).
  const SEARCH_ROUTES = ['search', 's', 'find', 'results', 'search-results', 'query'];

  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const rand = () => Math.random().toString(36).slice(2, 8);

  function withTimeout(promise, ms) {
    return Promise.race([
      promise,
      new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), ms))
    ]);
  }

  async function safeFetchText(url, init) {
    try {
      const res = await withTimeout(fetch(url, init), LIMITS.FETCH_TIMEOUT_MS);
      let text = '';
      try { text = await res.text(); } catch (e) { text = ''; }
      if (text.length > LIMITS.MAX_BODY_SCAN) text = text.slice(0, LIMITS.MAX_BODY_SCAN);
      return { ok: true, status: res.status, body: text, headers: res.headers, finalUrl: res.url };
    } catch (err) {
      return { ok: false, status: 0, body: '', error: err.message };
    }
  }

  // ---------------------------------------------------------------------------
  // 1. ENDPOINT MAP NORMALIZATION
  //    Merge discovery sources (URL query, forms, links, captured XHR/fetch)
  //    into a deduped list of { url, method, params:[{name, location, value}] }.
  // ---------------------------------------------------------------------------
  function buildEndpointMap(targetUrl, discovery) {
    const map = new Map(); // key -> endpoint
    const origin = safeOrigin(targetUrl);

    const addEndpoint = (rawUrl, method, params, source) => {
      let u;
      try { u = new URL(rawUrl, targetUrl); } catch (e) { return; }
      if (u.protocol !== 'http:' && u.protocol !== 'https:') return;
      // Stay in-scope: only same-origin endpoints are actively tested.
      if (u.origin !== origin) return;

      const key = `${method} ${u.origin}${u.pathname}`;
      let ep = map.get(key);
      if (!ep) {
        ep = { url: `${u.origin}${u.pathname}`, method, params: [], sources: new Set() };
        map.set(key, ep);
      }
      ep.sources.add(source);
      for (const p of params) {
        if (!p || !p.name) continue;
        if (!ep.params.some((x) => x.name === p.name && x.location === p.location)) {
          ep.params.push({ name: p.name, location: p.location || 'query', value: p.value || '' });
        }
      }
    };

    // (a) Target URL's own query string
    try {
      const tu = new URL(targetUrl);
      const qp = [...tu.searchParams.entries()].map(([name, value]) => ({ name, value, location: 'query' }));
      if (qp.length) addEndpoint(tu.href, 'GET', qp, 'address-bar');
    } catch (e) { /* noop */ }

    // (b) Links carrying query parameters
    (discovery.links || []).forEach((href) => {
      try {
        const lu = new URL(href, targetUrl);
        const qp = [...lu.searchParams.entries()].map(([name, value]) => ({ name, value, location: 'query' }));
        if (qp.length) addEndpoint(lu.href, 'GET', qp, 'dom-link');
      } catch (e) { /* noop */ }
    });

    // (c) Forms
    (discovery.forms || []).forEach((f) => {
      const method = (f.method || 'GET').toUpperCase();
      const params = (f.inputs || []).map((i) => ({
        name: i.name,
        value: i.value || (i.type === 'number' ? '1' : 'test'),
        location: method === 'GET' ? 'query' : 'body'
      })).filter((p) => p.name && p.name !== 'unnamed');
      if (params.length) addEndpoint(f.action || targetUrl, method, params, 'dom-form');
    });

    // (d2) Pre-normalized endpoints from the recon engine (crawl, robots,
    //      sitemap, JS extraction, search-param inference).
    (discovery.endpoints || []).forEach((ep) => {
      const params = (ep.params || []).map((p) => ({ name: p.name, value: p.value || '', location: p.location || 'query' }));
      addEndpoint(ep.url, (ep.method || 'GET').toUpperCase(), params, 'recon');
    });

    // (d) Captured live requests (fetch / XHR) — the app's REAL parameters
    (discovery.requests || []).forEach((r) => {
      const method = (r.method || 'GET').toUpperCase();
      const params = [];
      try {
        const ru = new URL(r.url, targetUrl);
        ru.searchParams.forEach((value, name) => params.push({ name, value, location: 'query' }));
      } catch (e) { /* noop */ }
      (r.bodyKeys || []).forEach((name) => params.push({ name, value: 'test', location: 'body' }));
      if (params.length) addEndpoint(r.url, method, params, 'xhr-capture');
    });

    // Finalize: arrays, caps, sources as array
    const endpoints = [...map.values()]
      .map((ep) => ({ ...ep, sources: [...ep.sources], params: ep.params.slice(0, LIMITS.MAX_PARAMS_PER_EP) }))
      .slice(0, LIMITS.MAX_ENDPOINTS);
    return endpoints;
  }

  function safeOrigin(u) { try { return new URL(u).origin; } catch (e) { return null; } }

  function setQueryParam(url, name, value) {
    const u = new URL(url);
    u.searchParams.set(name, value);
    return u.href;
  }

  // Use recon's already-separated endpoints verbatim (do NOT re-merge forms).
  function normalizeReconEndpoints(reconEndpoints, targetUrl) {
    const origin = safeOrigin(targetUrl);
    const out = [];
    for (const ep of reconEndpoints) {
      let u;
      try { u = new URL(ep.url, targetUrl); } catch (e) { continue; }
      if (u.origin !== origin) continue;
      const params = (ep.params || []).slice(0, LIMITS.MAX_PARAMS_PER_EP).map((p) => ({
        name: p.name, value: p.value || '', location: p.location || 'query', inferred: !!p.inferred
      })).filter((p) => p.name);
      out.push({
        url: `${u.origin}${u.pathname}`,
        method: (ep.method || 'GET').toUpperCase(),
        params,
        sources: ep.sources || [],
        formType: ep.formType,
        isStateChanging: !!ep.isStateChanging
      });
    }
    out.sort((a, b) => (b.params.length > 0) - (a.params.length > 0));
    return out.slice(0, LIMITS.MAX_ENDPOINTS);
  }

  // ---------------------------------------------------------------------------
  // 2. REFLECTION CONTEXT CLASSIFIER
  //    Where did our canary land? This decides which characters actually matter.
  // ---------------------------------------------------------------------------
  function classifyContext(body, canary) {
    const idx = body.indexOf(canary);
    if (idx === -1) return { reflected: false, context: 'none', count: 0 };

    const count = body.split(canary).length - 1;
    const pre = body.slice(Math.max(0, idx - 220), idx);
    const post = body.slice(idx + canary.length, idx + canary.length + 120);

    // Inside a <script> block?
    const lastScriptOpen = pre.lastIndexOf('<script');
    const lastScriptClose = pre.lastIndexOf('</script');
    if (lastScriptOpen > lastScriptClose) {
      // crude JS string vs raw-JS distinction
      const inStr = /["'`][^"'`]*$/.test(pre);
      return { reflected: true, context: inStr ? 'js-string' : 'js-code', count, idx };
    }

    // Inside an HTML tag (attribute area)?
    const lastLt = pre.lastIndexOf('<');
    const lastGt = pre.lastIndexOf('>');
    if (lastLt > lastGt) {
      // We're between < and > -> attribute region.
      const attrQuote = /=(["'])[^"']*$/.exec(pre);
      // URL-bearing attribute (href/src/action/formaction) -> url context
      const urlAttr = /\b(href|src|action|formaction|data|poster|cite|background)\s*=\s*["']?[^"'>]*$/i.test(pre);
      if (urlAttr) return { reflected: true, context: 'url-attr', quoted: attrQuote ? attrQuote[1] : null, count, idx };
      if (attrQuote) return { reflected: true, context: 'attr-quoted', quoted: attrQuote[1], count, idx };
      return { reflected: true, context: 'attr-unquoted', count, idx };
    }

    // Otherwise: plain HTML text node
    return { reflected: true, context: 'html-text', count, idx };
  }

  // ---------------------------------------------------------------------------
  // 3. FILTER FINGERPRINT (single probe)
  //    Inject MARK_L + each special char + MARK_R, then read back the region
  //    between the two markers to see which chars survived raw vs were encoded
  //    or stripped. One request characterizes the whole filter.
  // ---------------------------------------------------------------------------
  function buildProbeValue() {
    // e.g. qzx|<|>|"|'|`|(|)|;|/|=|{|}|xzq  (pipe-separated so we can split back)
    return MARK_L + '|' + PROBE_CHARS.join('|') + '|' + MARK_R;
  }

  function parseFilterProfile(body) {
    const start = body.indexOf(MARK_L);
    if (start === -1) return null;
    const end = body.indexOf(MARK_R, start);
    const region = end === -1 ? body.slice(start, start + 200) : body.slice(start, end + MARK_R.length);

    const profile = {};
    for (const c of PROBE_CHARS) {
      // char survives raw if it appears literally in the reflected region
      const raw = region.includes(c);
      // detect common encodings of that char
      const enc = isEncoded(region, c);
      profile[c] = raw ? 'raw' : (enc ? 'encoded' : 'stripped');
    }
    return { region: region.slice(0, 260), chars: profile };
  }

  function isEncoded(region, c) {
    const encMap = {
      '<': ['&lt;', '%3c', '\\u003c', '&#60;', '&#x3c;'],
      '>': ['&gt;', '%3e', '\\u003e', '&#62;', '&#x3e;'],
      '"': ['&quot;', '%22', '\\u0022', '&#34;', '\\"'],
      "'": ['&#39;', '&apos;', '%27', '\\u0027', "\\'"],
      '`': ['%60', '\\u0060'],
      '(': ['%28', '&#40;'],
      ')': ['%29', '&#41;'],
      ';': ['%3b'],
      '/': ['%2f', '&#47;'],
      '=': ['%3d'],
      '{': ['%7b'],
      '}': ['%7d']
    };
    const low = region.toLowerCase();
    return (encMap[c] || []).some((e) => low.includes(e.toLowerCase()));
  }

  // Decide XSS verdict from context + which chars survived.
  function xssVerdict(context, profile) {
    if (!profile) return { state: 'suspected', note: 'Reflected but filter profile unavailable.' };
    const ch = profile.chars;
    const survived = (c) => ch[c] === 'raw';

    switch (context) {
      case 'html-text':
        if (survived('<') && survived('>')) {
          return { state: 'confirmed', note: 'Angle brackets reflect unencoded in HTML body — tag injection works.' };
        }
        return { state: 'suspected', note: 'Reflects in HTML body but < or > is encoded/stripped.' };
      case 'attr-unquoted':
        if (survived('=') || survived('/') || survived('>')) {
          return { state: 'confirmed', note: 'Unquoted attribute with break chars intact — event-handler injection works.' };
        }
        return { state: 'suspected', note: 'Unquoted attribute but break chars filtered.' };
      case 'attr-quoted':
        if (survived('"') || survived("'")) {
          return { state: 'confirmed', note: 'Quote survives inside quoted attribute — can break out and add handler.' };
        }
        return { state: 'suspected', note: 'Quoted attribute but the quote char is encoded.' };
      case 'js-string':
        if ((survived("'") || survived('"') || survived('`')) && survived(';')) {
          return { state: 'confirmed', note: 'Quote + semicolon survive inside JS string — statement break works.' };
        }
        if (survived("'") || survived('"') || survived('`')) {
          return { state: 'suspected', note: 'String quote survives in JS context; verify breakout manually.' };
        }
        return { state: 'suspected', note: 'Reflects in JS but quotes are escaped.' };
      case 'js-code':
        return { state: 'confirmed', note: 'Input reflects directly into executable JS — high impact, verify manually.' };
      case 'url-attr':
        return { state: 'suspected', note: 'Reflects into a URL attribute — check javascript: scheme / open redirect.' };
      default:
        return { state: 'suspected', note: 'Reflected; context indeterminate.' };
    }
  }

  // Context-specific proof payload the operator can paste to verify execution.
  function payloadForContext(context, profile) {
    switch (context) {
      case 'html-text': return '<svg onload=alert(document.domain)>';
      case 'attr-quoted': {
        const singleSurvives = profile && profile["'"] === 'raw' && !(profile['"'] === 'raw');
        return singleSurvives ? "'><svg onload=alert(document.domain)>" : '"><svg onload=alert(document.domain)>';
      }
      case 'attr-unquoted': return ' onmouseover=alert(document.domain) vyx=';
      case 'url-attr': return 'javascript:alert(document.domain)';
      case 'js-string': return "';alert(document.domain)//";
      case 'js-code': return 'alert(document.domain)';
      default: return '<svg onload=alert(document.domain)>';
    }
  }

  // Build a urlencoded body with all body params defaulted, one overridden.
  function buildBody(bodyParams, overrideName, overrideValue) {
    const usp = new URLSearchParams();
    for (const p of bodyParams) {
      usp.set(p.name, p.name === overrideName ? overrideValue : (p.value || 'test'));
    }
    return usp.toString();
  }

  // Shared: turn a canary response (+ optional probe response) into an XSS finding.
  function buildXssFinding(endpoint, param, location, canary, body1, body2) {
    const ctx = classifyContext(body1, canary);
    if (!ctx.reflected) return null;
    const profile = body2 ? parseFilterProfile(body2) : null;
    const verdict = xssVerdict(ctx.context, profile);
    const chars = profile ? profile.chars : null;
    return {
      kind: 'xss',
      endpoint: endpoint.url,
      method: endpoint.method,
      param: param.name,
      location,
      context: ctx.context,
      reflectionCount: ctx.count,
      filterProfile: chars,
      state: verdict.state,
      severity: verdict.state === 'confirmed' ? 'high' : 'medium',
      note: verdict.note,
      samplePayload: payloadForContext(ctx.context, chars),
      evidence: `param "${param.name}" reflected in ${ctx.context} context at ${endpoint.method} ${endpoint.url}`
    };
  }

  // Tag-injection confirmation: inject a real <tag>; if its angle brackets come
  // back RAW, HTML injection is proven (definitive, context-independent).
  function makeTagProbe() { const tag = 'vt' + rand(); return { tag, value: '<' + tag + '>' }; }
  function tagReflectedRaw(body, tag) { return !!body && body.indexOf('<' + tag + '>') !== -1; }
  function confirmedTagFinding(endpoint, paramName, location, evidence) {
    return {
      kind: 'xss',
      endpoint: endpoint.url, method: endpoint.method, param: paramName, location,
      context: 'html-text', reflectionCount: 1,
      filterProfile: { '<': 'raw', '>': 'raw', '"': 'raw' },
      state: 'confirmed', severity: 'high',
      note: 'Injected HTML tag reflected unencoded in the response — tag injection confirmed (XSS).',
      samplePayload: payloadForContext('html-text'),
      evidence
    };
  }

  // ---------------------------------------------------------------------------
  // 4a. PER-PARAMETER XSS TEST — GET / query
  // ---------------------------------------------------------------------------
  async function testParamXss(endpoint, param, fetchInit) {
    const findings = [];
    if (param.location !== 'query') return findings;

    const canary = 'vy' + rand() + 'xss';
    let testUrl;
    try { testUrl = setQueryParam(endpoint.url, param.name, canary); } catch (e) { return findings; }

    const r1 = await safeFetchText(testUrl, fetchInit);
    if (!r1.ok || !r1.body) return findings;
    if (classifyContext(r1.body, canary).reflected === false) return findings;

    // Tag-injection confirmation first (definitive).
    await sleep(LIMITS.REQUEST_DELAY_MS);
    const tp = makeTagProbe();
    const rt = await safeFetchText(setQueryParam(endpoint.url, param.name, tp.value), fetchInit);
    if (tagReflectedRaw(rt.body, tp.tag)) {
      findings.push(confirmedTagFinding(endpoint, param.name, 'query', `raw <${tp.tag}> reflected for param "${param.name}" at ${endpoint.url}`));
      return findings;
    }

    // Else characterize the filter to decide confirmed/suspected per context.
    await sleep(LIMITS.REQUEST_DELAY_MS);
    const r2 = await safeFetchText(setQueryParam(endpoint.url, param.name, buildProbeValue()), fetchInit);
    const f = buildXssFinding(endpoint, param, 'query', canary, r1.body, r2.ok ? r2.body : null);
    if (f) findings.push(f);
    return findings;
  }

  // ---------------------------------------------------------------------------
  // 4b. PER-PARAMETER XSS TEST — POST / body
  //     Submits the form urlencoded with the target field carrying the canary.
  //     Only reached for forms the caller cleared for POST testing (search forms
  //     by default; state-changing forms only on an explicit separate opt-in).
  // ---------------------------------------------------------------------------
  async function testParamXssPost(endpoint, param, bodyParams, baseInit) {
    const findings = [];
    const canary = 'vy' + rand() + 'xss';
    const postInit = {
      method: 'POST',
      credentials: baseInit.credentials,
      redirect: 'follow',
      cache: 'no-store',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: buildBody(bodyParams, param.name, canary)
    };

    const r1 = await safeFetchText(endpoint.url, postInit);
    if (!r1.ok || !r1.body) return findings;
    if (classifyContext(r1.body, canary).reflected === false) return findings;

    // Tag-injection confirmation first.
    await sleep(LIMITS.REQUEST_DELAY_MS);
    const tp = makeTagProbe();
    const tagInit = Object.assign({}, postInit, { body: buildBody(bodyParams, param.name, tp.value) });
    const rt = await safeFetchText(endpoint.url, tagInit);
    if (tagReflectedRaw(rt.body, tp.tag)) {
      findings.push(confirmedTagFinding(endpoint, param.name, 'body', `raw <${tp.tag}> reflected for body field "${param.name}" at ${endpoint.url}`));
      return findings;
    }

    await sleep(LIMITS.REQUEST_DELAY_MS);
    const probeInit = Object.assign({}, postInit, { body: buildBody(bodyParams, param.name, buildProbeValue()) });
    const r2 = await safeFetchText(endpoint.url, probeInit);

    const f = buildXssFinding(endpoint, param, 'body', canary, r1.body, r2.ok ? r2.body : null);
    if (f) findings.push(f);
    return findings;
  }

  // ---------------------------------------------------------------------------
  // 5. PER-PARAMETER SQLi TEST (error-based + boolean-diff, read-only)
  // ---------------------------------------------------------------------------
  function detectSqlError(body) {
    for (const sig of SQL_ERRORS) {
      const m = body.match(sig.rx);
      if (m) return { db: sig.db, snippet: m[0].slice(0, 140) };
    }
    return null;
  }

  function similarity(a, b) {
    if (!a && !b) return 1;
    if (!a || !b) return 0;
    const la = a.length, lb = b.length;
    return 1 - Math.abs(la - lb) / Math.max(la, lb); // cheap length-based ratio
  }

  async function testParamSqli(endpoint, param, fetchInit) {
    const findings = [];
    if (param.location !== 'query') return findings;
    const base = param.value || '1';

    // (a) Error-based: a single quote is enough and is non-destructive.
    const errUrl = setQueryParam(endpoint.url, param.name, base + "'");
    const er = await safeFetchText(errUrl, fetchInit);
    if (er.ok) {
      const sqlErr = detectSqlError(er.body);
      if (sqlErr) {
        findings.push({
          kind: 'sqli',
          endpoint: endpoint.url, method: endpoint.method, param: param.name, location: 'query',
          state: 'confirmed', severity: 'critical', technique: 'error-based',
          note: `${sqlErr.db} error surfaced when a single quote was injected.`,
          evidence: sqlErr.snippet
        });
        return findings; // confirmed; no need to probe further
      }
    }
    await sleep(LIMITS.REQUEST_DELAY_MS);

    // (b) Boolean-differential (read-only): TRUE vs FALSE condition response size.
    const trueUrl = setQueryParam(endpoint.url, param.name, base + "'||'a'='a");
    const falseUrl = setQueryParam(endpoint.url, param.name, base + "'||'a'='b");
    const [tr, fr] = [await safeFetchText(trueUrl, fetchInit), await (async () => { await sleep(LIMITS.REQUEST_DELAY_MS); return safeFetchText(falseUrl, fetchInit); })()];
    if (tr.ok && fr.ok) {
      const sim = similarity(tr.body, fr.body);
      if (sim < 0.92 && Math.abs(tr.body.length - fr.body.length) > 40) {
        findings.push({
          kind: 'sqli',
          endpoint: endpoint.url, method: endpoint.method, param: param.name, location: 'query',
          state: 'suspected', severity: 'high', technique: 'boolean-differential',
          note: 'TRUE and FALSE boolean conditions produced measurably different responses — possible blind SQLi. Verify manually.',
          evidence: `response delta: ${tr.body.length} vs ${fr.body.length} bytes (similarity ${sim.toFixed(2)})`
        });
      }
    }
    return findings;
  }

  // Error-based SQLi for a POST/body field (single quote, non-destructive).
  async function testParamSqliPost(endpoint, param, bodyParams, baseInit) {
    const findings = [];
    const base = param.value || '1';
    const postInit = {
      method: 'POST', credentials: baseInit.credentials, redirect: 'follow', cache: 'no-store',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: buildBody(bodyParams, param.name, base + "'")
    };
    const er = await safeFetchText(endpoint.url, postInit);
    if (er.ok) {
      const sqlErr = detectSqlError(er.body);
      if (sqlErr) {
        findings.push({
          kind: 'sqli',
          endpoint: endpoint.url, method: endpoint.method, param: param.name, location: 'body',
          state: 'confirmed', severity: 'critical', technique: 'error-based',
          note: `${sqlErr.db} error surfaced when a single quote was injected into the body field.`,
          evidence: sqlErr.snippet
        });
      }
    }
    return findings;
  }

  // ---------------------------------------------------------------------------
  // 5b. PATH-SEGMENT INJECTION
  //     Many apps route input through the URL PATH (e.g. /search/<term>/), not a
  //     query param. The canary is placed in a path segment (percent-encoded, as
  //     a browser would send it — the server decodes and reflects). This is the
  //     vector behind path-based reflected search XSS.
  // ---------------------------------------------------------------------------
  function buildPathCandidates(origin, endpoints) {
    const out = [];
    const seen = new Set();
    const base = origin.replace(/\/+$/, '');
    const push = (label, build) => { if (seen.has(label)) return; seen.add(label); out.push({ label, build }); };

    // (a) Common search routes — the high-signal pattern.
    SEARCH_ROUTES.forEach((r) => push(`/${r}/<term>/`, (v) => `${base}/${r}/${encodeURIComponent(v)}/`));

    // (b) Search form action paths (if the form posts/gets to a real route).
    endpoints.filter((e) => e.formType === 'search').forEach((e) => {
      try {
        const p = new URL(e.url).pathname.replace(/^\/+|\/+$/g, '');
        if (p) push(`/${p}/<term>/`, (v) => `${base}/${p}/${encodeURIComponent(v)}/`);
      } catch (e2) { /* noop */ }
    });

    // (c) Replace the last path segment of discovered endpoints (e.g. /tours/<id>).
    endpoints.forEach((e) => {
      let u; try { u = new URL(e.url); } catch (e2) { return; }
      const segs = u.pathname.split('/').filter(Boolean);
      if (segs.length >= 1) {
        const parent = segs.slice(0, -1);
        const label = '/' + [...parent, '<v>'].join('/');
        push(label, (v) => `${base}/${[...parent, encodeURIComponent(v)].join('/')}`);
      }
    });

    return out.slice(0, 14);
  }

  async function testPathCandidate(cand, fetchInit) {
    const canary = 'vy' + rand() + 'xss';
    const r1 = await safeFetchText(cand.build(canary), fetchInit);
    if (!r1.ok || !r1.body) return { finding: null, requests: 1 };
    if (!classifyContext(r1.body, canary).reflected) return { finding: null, requests: 1 };

    // Tag-injection confirmation first (definitive for path reflection).
    await sleep(LIMITS.REQUEST_DELAY_MS);
    const tp = makeTagProbe();
    const rt = await safeFetchText(cand.build(tp.value), fetchInit);
    if (tagReflectedRaw(rt.body, tp.tag)) {
      const f = confirmedTagFinding({ url: cand.label, method: 'GET' }, '<path>', 'path', `raw <${tp.tag}> reflected via URL path: ${cand.build(tp.value)}`);
      f.note = 'Injected HTML tag reflected unencoded — confirmed XSS via URL path segment (not a query/body parameter).';
      return { finding: f, requests: 2 };
    }

    await sleep(LIMITS.REQUEST_DELAY_MS);
    const r2 = await safeFetchText(cand.build(buildProbeValue()), fetchInit);
    const f = buildXssFinding({ url: cand.label, method: 'GET' }, { name: '<path>' }, 'path', canary, r1.body, r2.ok ? r2.body : null);
    if (f) {
      f.evidence = `canary reflected via URL path: ${cand.build(canary)}`;
      f.note = f.note + ' (injection point is a URL path segment, not a query/body parameter).';
    }
    return { finding: f, requests: 3 };
  }

  // ---------------------------------------------------------------------------
  // 6. OPEN REDIRECT (reuses reflection, cheap)
  // ---------------------------------------------------------------------------
  async function testOpenRedirect(endpoint, param, fetchInit) {
    const findings = [];
    if (param.location !== 'query') return findings;
    if (!REDIRECT_PARAM_HINTS.test(param.name)) return findings;

    const marker = 'https://vyasa-redirect-check.example';
    const url = setQueryParam(endpoint.url, param.name, marker);
    const r = await safeFetchText(url, { ...fetchInit, redirect: 'manual' });
    // manual redirect: look at Location header; or reflected as a meta/js redirect
    let loc = null;
    try { loc = r.headers && r.headers.get ? r.headers.get('location') : null; } catch (e) { loc = null; }
    const reflectedInBody = r.ok && (r.body.includes(marker + '"') || r.body.includes("location.href") && r.body.includes(marker));
    if ((loc && loc.includes('vyasa-redirect-check.example')) || reflectedInBody) {
      findings.push({
        kind: 'open-redirect',
        endpoint: endpoint.url, method: endpoint.method, param: param.name, location: 'query',
        state: loc ? 'confirmed' : 'suspected',
        severity: 'medium',
        note: loc ? 'External URL was placed into the redirect Location header unchanged.' : 'External URL reflected into a client-side redirect sink.',
        evidence: loc ? `Location: ${loc.slice(0, 160)}` : 'reflected in body redirect sink'
      });
    }
    return findings;
  }

  // ---------------------------------------------------------------------------
  // 7. EXPANDED CORS TRUST MAP
  //    Probe several origin shapes to understand the real trust boundary.
  // ---------------------------------------------------------------------------
  async function mapCorsTrust(targetUrl) {
    const origin = safeOrigin(targetUrl);
    if (!origin) return { tested: false };
    let host = '';
    try { host = new URL(targetUrl).hostname; } catch (e) { host = ''; }

    const candidates = [
      { label: 'arbitrary', origin: 'https://vyasa-evil.example' },
      { label: 'null', origin: 'null' },
      { label: 'subdomain-takeover', origin: `https://vyasa-sub.${host}` },
      { label: 'http-downgrade', origin: `http://${host}` }
    ];

    const results = [];
    for (const c of candidates) {
      const r = await safeFetchText(origin, {
        method: 'GET',
        headers: { 'Origin': c.origin },
        credentials: 'omit'
      });
      let acao = null, acac = null;
      try { acao = r.headers.get('access-control-allow-origin'); acac = r.headers.get('access-control-allow-credentials'); } catch (e) { /* noop */ }
      const reflected = acao === c.origin || (c.label === 'arbitrary' && acao === 'https://vyasa-evil.example');
      results.push({
        probe: c.label,
        sentOrigin: c.origin,
        acao,
        acac,
        reflected,
        dangerous: (reflected || acao === '*') && acac === 'true'
      });
      await sleep(LIMITS.REQUEST_DELAY_MS);
    }

    const dangerous = results.filter((x) => x.dangerous);
    return {
      tested: true,
      results,
      trustedOrigins: results.filter((x) => x.reflected).map((x) => x.sentOrigin),
      verdict: dangerous.length
        ? { state: 'confirmed', severity: 'high', note: `Origin reflected WITH credentials for: ${dangerous.map((d) => d.probe).join(', ')}. Cross-origin credential theft is possible.` }
        : results.some((x) => x.acao === '*')
          ? { state: 'suspected', severity: 'low', note: 'Wildcard ACAO present but without credentials — low risk.' }
          : { state: 'info', severity: 'info', note: 'No permissive cross-origin reflection observed.' }
    };
  }

  // ---------------------------------------------------------------------------
  // 8. ORCHESTRATOR
  // ---------------------------------------------------------------------------
  async function runActiveScan(targetUrl, discovery, opts) {
    opts = opts || {};
    const started = Date.now();
    const fetchInit = {
      method: 'GET',
      // Authenticated testing advantage: reuse the operator's session so we can
      // reach endpoints that require login. The authorization gate guarantees
      // the operator is allowed to test this origin.
      credentials: opts.useCredentials === false ? 'omit' : 'include',
      redirect: 'follow',
      cache: 'no-store'
    };

    // Prefer the recon engine's pre-separated endpoints (forms kept distinct,
    // formType/isStateChanging preserved). Fall back to the merge-based map only
    // when no recon list was supplied.
    const endpoints = (discovery && Array.isArray(discovery.endpoints) && discovery.endpoints.length)
      ? normalizeReconEndpoints(discovery.endpoints, targetUrl)
      : buildEndpointMap(targetUrl, discovery || {});
    const origin = safeOrigin(targetUrl);
    const findings = [];
    const skipped = [];
    let requests = 0;
    let bodyParamsTested = 0;
    let pathTested = 0;

    for (const ep of endpoints) {
      const queryParams = ep.params.filter((p) => p.location === 'query');

      // --- Query parameters (GET): always tested ---
      for (const p of queryParams) {
        try {
          const xss = await testParamXss(ep, p, fetchInit); requests += xss.length ? 2 : 1;
          findings.push(...xss);
          await sleep(LIMITS.REQUEST_DELAY_MS);

          if (opts.sqli !== false) {
            const sqli = await testParamSqli(ep, p, fetchInit); requests += 2;
            findings.push(...sqli);
            await sleep(LIMITS.REQUEST_DELAY_MS);
          }
          const redir = await testOpenRedirect(ep, p, fetchInit); requests += 1;
          findings.push(...redir);
          await sleep(LIMITS.REQUEST_DELAY_MS);
        } catch (err) {
          console.warn('[VYASA active] query param error', ep.url, p.name, err.message);
        }
      }

      // --- Body parameters (POST): gated ---
      const bodyParams = ep.params.filter((p) => p.location === 'body' && p.name);
      if (bodyParams.length) {
        const stateChanging = !!ep.isStateChanging;
        const allowPost = opts.includePost && (!stateChanging || opts.includeStateChanging);
        if (!allowPost) {
          skipped.push({ url: ep.url, method: ep.method, reason: stateChanging ? 'state-changing form (needs explicit opt-in)' : 'POST testing disabled', params: bodyParams.map((p) => p.name) });
        } else {
          for (const p of bodyParams) {
            try {
              const xss = await testParamXssPost(ep, p, bodyParams, fetchInit); requests += 2; bodyParamsTested++;
              findings.push(...xss);
              await sleep(LIMITS.REQUEST_DELAY_MS);
              if (opts.sqli !== false) {
                const sqli = await testParamSqliPost(ep, p, bodyParams, fetchInit); requests += 1;
                findings.push(...sqli);
                await sleep(LIMITS.REQUEST_DELAY_MS);
              }
            } catch (err) {
              console.warn('[VYASA active] body param error', ep.url, p.name, err.message);
            }
          }
        }
      }
    }

    // --- Path-segment injection (learned routes + search routes + last-segment) ---
    if (origin) {
      // Behavior-learned templates come FIRST — these are observed, not guessed.
      const learnedCands = (discovery.learnedTemplates || []).map((t) => ({
        label: (t.label || t.template) + (t.kind === 'query' ? ` (?${t.paramName})` : ' [path]') + ' [learned]',
        build: (v) => String(t.template).split('{INJECT}').join(encodeURIComponent(v))
      }));
      const guessCands = buildPathCandidates(origin, endpoints);
      const seenLabels = new Set();
      const pathCands = [...learnedCands, ...guessCands].filter((c) => {
        if (seenLabels.has(c.label)) return false; seenLabels.add(c.label); return true;
      }).slice(0, 20);
      for (const c of pathCands) {
        try {
          const res = await testPathCandidate(c, fetchInit);
          requests += res.requests;
          if (res.finding) { pathTested++; findings.push(res.finding); }
          await sleep(LIMITS.REQUEST_DELAY_MS);
        } catch (err) {
          console.warn('[VYASA active] path probe error', c.label, err.message);
        }
      }
    }

    // CORS trust map (origin-level, once).
    let cors = { tested: false };
    try { cors = await mapCorsTrust(targetUrl); } catch (e) { cors = { tested: false, error: e.message }; }

    const confirmed = findings.filter((f) => f.state === 'confirmed');
    const suspected = findings.filter((f) => f.state === 'suspected');
    const queryParamCount = endpoints.reduce((n, e) => n + e.params.filter((p) => p.location === 'query').length, 0);

    return {
      ran: true,
      durationMs: Date.now() - started,
      endpointsTested: endpoints.length,
      paramsTested: queryParamCount + bodyParamsTested + pathTested,
      pathProbes: pathTested,
      learnedRoutes: (discovery.learnedTemplates || []).map((t) => t.label || t.template),
      requestsSent: requests,
      skipped,
      endpointMap: endpoints.map((e) => ({ url: e.url, method: e.method, params: e.params.map((p) => p.name), sources: e.sources, formType: e.formType })),
      findings,
      cors,
      summary: {
        confirmed: confirmed.length,
        suspected: suspected.length,
        byKind: findings.reduce((acc, f) => { acc[f.kind] = (acc[f.kind] || 0) + 1; return acc; }, {})
      }
    };
  }

  return { runActiveScan, buildEndpointMap, classifyContext, parseFilterProfile, xssVerdict, mapCorsTrust, LIMITS };
})();

// Expose for the service worker (classic worker scope) and allow node --check.
if (typeof self !== 'undefined') { self.VYASA_ACTIVE = VYASA_ACTIVE; }
if (typeof module !== 'undefined' && module.exports) { module.exports = VYASA_ACTIVE; }
