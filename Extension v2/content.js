// content.js — VYASA DOM, Client Recon & Technology Scanner

// 0. Live request capture — collect metadata posted by inject-hook.js (MAIN world).
//    This gives the active engine the application's REAL endpoints/parameters.
const VYASA_CAPTURED_REQUESTS = [];
const VYASA_REQ_SEEN = new Set();
window.addEventListener('message', (event) => {
  if (event.source !== window) return;
  const data = event.data;
  if (!data || data.source !== 'vyasa-hook' || !data.req) return;
  const r = data.req;
  const key = `${r.method} ${r.url} ${(r.bodyKeys || []).join(',')}`;
  if (VYASA_REQ_SEEN.has(key) || VYASA_CAPTURED_REQUESTS.length > 300) return;
  VYASA_REQ_SEEN.add(key);
  VYASA_CAPTURED_REQUESTS.push(r);
});

// 0b. Attack-surface collector: links carrying query params, forms with values,
//     and the captured live requests. Consumed by the active-scan engine.
function collectAttackSurface() {
  const links = [];
  const seenLinks = new Set();
  document.querySelectorAll('a[href]').forEach((a) => {
    try {
      const u = new URL(a.href, window.location.href);
      if ((u.protocol === 'http:' || u.protocol === 'https:') && u.search && u.origin === window.location.origin) {
        const k = u.origin + u.pathname + u.search;
        if (!seenLinks.has(k)) { seenLinks.add(k); links.push(u.href); }
      }
    } catch (e) { /* noop */ }
  });

  const forms = [];
  document.querySelectorAll('form').forEach((form, idx) => {
    const action = form.getAttribute('action') || window.location.href;
    const method = (form.getAttribute('method') || 'GET').toUpperCase();
    const inputs = Array.from(form.querySelectorAll('input, select, textarea'))
      .map((inp) => ({
        name: inp.getAttribute('name') || inp.getAttribute('id') || '',
        type: inp.getAttribute('type') || 'text',
        value: (inp.value && inp.type !== 'password') ? String(inp.value).slice(0, 40) : ''
      }))
      .filter((i) => i.name);
    forms.push({ index: idx + 1, action, method, inputs });
  });

  return { links, forms, requests: VYASA_CAPTURED_REQUESTS.slice(0, 300) };
}

// 1. Client-side Technology Fingerprinting via DOM & Window Objects
function detectDomTechnologies() {
  const techs = [];

  // Window object / Global variable inspection
  try {
    if (window.React || document.querySelector('[data-reactroot], [data-reactid], #react-root')) {
      techs.push({ name: 'React', type: 'frontend' });
    }
    if (window.Vue || document.querySelector('[v-cloak], [v-is], [v-model]')) {
      techs.push({ name: 'Vue.js', type: 'frontend' });
    }
    if (window.angular || window.ng || document.querySelector('[ng-app], [ng-version]')) {
      const ngVer = document.querySelector('[ng-version]')?.getAttribute('ng-version');
      techs.push({ name: 'Angular', type: 'frontend', version: ngVer || null });
    }
    if (window.jQuery || window.$?.fn?.jquery) {
      const jqVer = window.jQuery?.fn?.jquery || window.$?.fn?.jquery;
      techs.push({ name: 'jQuery', type: 'frontend', version: jqVer || null });
    }
    if (window.__NEXT_DATA__ || document.querySelector('#__next')) {
      techs.push({ name: 'Next.js', type: 'framework' });
    }
    if (window.__NUXT__ || document.querySelector('#__nuxt')) {
      techs.push({ name: 'Nuxt.js', type: 'framework' });
    }
    if (window.Shopify) {
      techs.push({ name: 'Shopify', type: 'cms' });
    }
    if (window.wp || document.querySelector('link[href*="wp-content"]')) {
      techs.push({ name: 'WordPress', type: 'cms' });
    }
  } catch (e) {}

  // Meta Generator Tag Inspection
  const metaGen = document.querySelector('meta[name="generator"], meta[name="Generator"]');
  if (metaGen && metaGen.content) {
    const val = metaGen.content;
    techs.push({ name: val, type: 'generator' });
  }

  return techs;
}

// 2. Secrets & Leaks Scanner
const SECRET_PATTERNS = [
  { name: 'AWS Access Key ID', regex: /AKIA[0-9A-Z]{16}/g, severity: 'critical' },
  { name: 'Stripe Secret Key', regex: /sk_live_[0-9a-zA-Z]{24,}/g, severity: 'critical' },
  { name: 'Google API Key', regex: /AIza[0-9A-Za-z\-_]{35}/g, severity: 'high' },
  { name: 'JWT Auth Token', regex: /eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]+/g, severity: 'medium' },
  { name: 'Private Key Block', regex: /-----BEGIN (RSA|EC|PGP|PRIVATE) KEY-----/g, severity: 'critical' },
  { name: 'OpenAI API Key', regex: /sk-[a-zA-Z0-9]{32,}/g, severity: 'high' },
  { name: 'GitHub Access Token', regex: /(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59})/g, severity: 'critical' },
  { name: 'Slack Webhook URL', regex: /https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]+\/B[a-zA-Z0-9_]+\/[a-zA-Z0-9_]+/g, severity: 'high' },
  { name: 'Hardcoded Secret Assignment', regex: /(api[_-]?key|secret[_-]?key|sk[_-]?live|auth[_-]?token|access[_-]?token|client[_-]?secret|private[_-]?key)\s*[:=]\s*["']([a-zA-Z0-9_\-]{16,})["']/gi, severity: 'high' }
];

function scanForSecrets() {
  const leaks = [];
  const checkedTexts = new Set();

  const testText = (text, source) => {
    if (!text || checkedTexts.has(text)) return;
    checkedTexts.add(text);

    for (const rule of SECRET_PATTERNS) {
      rule.regex.lastIndex = 0;
      let match;
      while ((match = rule.regex.exec(text)) !== null) {
        const secretVal = match[0];
        const redacted = secretVal.length > 12 
          ? `${secretVal.substring(0, 6)}...${secretVal.substring(secretVal.length - 4)}` 
          : '***REDACTED***';

        leaks.push({
          type: rule.name,
          severity: rule.severity,
          snippet: redacted,
          source: source
        });
      }
    }
  };

  document.querySelectorAll('script').forEach((script, idx) => {
    if (!script.src && script.textContent) {
      testText(script.textContent, `Inline Script #${idx + 1}`);
    }
  });

  const iterator = document.createNodeIterator(
    document.documentElement,
    NodeFilter.SHOW_COMMENT,
    null
  );
  let commentNode;
  while ((commentNode = iterator.nextNode())) {
    const val = commentNode.nodeValue;
    if (val && /TODO|FIXME|HACK|SECRET|PASS|KEY|TOKEN/i.test(val)) {
      leaks.push({
        type: 'Developer Comment Leak',
        severity: 'info',
        snippet: val.trim().substring(0, 100),
        source: 'DOM Comment'
      });
    }
  }

  return leaks;
}

// 3. Scan LocalStorage & SessionStorage
function scanWebStorage() {
  const storageFindings = [];
  const inspectStorage = (storageObj, storageName) => {
    try {
      for (let i = 0; i < storageObj.length; i++) {
        const key = storageObj.key(i);
        const value = storageObj.getItem(key);
        const isSensitiveKey = /token|auth|session|jwt|password|secret|key|user|cred|bearer/i.test(key);
        let isJwt = false;
        try { isJwt = /^eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+/.test(value); } catch (e) {}

        if (isSensitiveKey || isJwt) {
          storageFindings.push({
            storage: storageName,
            key: key,
            isJwt: isJwt,
            sample: value ? (value.length > 40 ? value.substring(0, 30) + '...' : value) : '',
            risk: isJwt ? 'JWT Token stored in unencrypted Web Storage' : 'Sensitive auth key stored client-side'
          });
        }
      }
    } catch (e) {}
  };

  inspectStorage(window.localStorage, 'localStorage');
  inspectStorage(window.sessionStorage, 'sessionStorage');

  return storageFindings;
}

// 4. DOM XSS Sink Scanner
function scanDomXssSinks() {
  const sinksFound = [];
  const SINK_PATTERNS = [
    { name: 'innerHTML Assignment', regex: /\.innerHTML\s*=/gi },
    { name: 'outerHTML Assignment', regex: /\.outerHTML\s*=/gi },
    { name: 'document.write Call', regex: /document\.write\s*\(/gi },
    { name: 'eval() Execution', regex: /\beval\s*\(/gi },
    { name: 'setTimeout String Execution', regex: /setTimeout\s*\(\s*["'`]/gi },
    { name: 'setInterval String Execution', regex: /setInterval\s*\(\s*["'`]/gi },
    { name: 'location.href Assignment', regex: /(location|window\.location)(\.href)?\s*=\s*/gi }
  ];

  document.querySelectorAll('script').forEach((script, idx) => {
    const text = script.textContent;
    if (!script.src && text) {
      for (const sink of SINK_PATTERNS) {
        sink.regex.lastIndex = 0;
        let match;
        while ((match = sink.regex.exec(text)) !== null) {
          const start = Math.max(0, match.index - 20);
          const end = Math.min(text.length, match.index + 50);
          const snippet = text.substring(start, end).replace(/\s+/g, ' ');

          sinksFound.push({
            sink: sink.name,
            source: `Inline Script #${idx + 1}`,
            snippet: snippet
          });
        }
      }
    }
  });

  return sinksFound;
}

// 5. Mixed Content Detector
function detectMixedContent() {
  const mixedResources = [];
  const isHttps = window.location.protocol === 'https:';
  if (!isHttps) return mixedResources;

  const checkUrl = (url, tag, attr) => {
    if (url && url.startsWith('http:')) {
      mixedResources.push({
        url: url,
        type: tag,
        attribute: attr
      });
    }
  };

  document.querySelectorAll('script[src]').forEach(s => checkUrl(s.src, 'script', 'src'));
  document.querySelectorAll('link[rel="stylesheet"][href]').forEach(l => checkUrl(l.href, 'stylesheet', 'href'));
  document.querySelectorAll('img[src]').forEach(i => checkUrl(i.src, 'image', 'src'));
  document.querySelectorAll('iframe[src]').forEach(f => checkUrl(f.src, 'iframe', 'src'));
  document.querySelectorAll('audio[src], video[src]').forEach(m => checkUrl(m.src, 'media', 'src'));

  return mixedResources;
}

// 6. Collect Resources & Forms for OWASP Audit
function collectDomResources() {
  const resources = [];
  const forms = [];

  const addResource = (url, type) => {
    if (!url || url.startsWith('data:') || url.startsWith('javascript:')) return;
    try {
      const absoluteUrl = new URL(url, window.location.href).href;
      if (!resources.some(r => r.url === absoluteUrl)) {
        resources.push({ url: absoluteUrl, type: type, source: 'dom' });
      }
    } catch (e) {}
  };

  document.querySelectorAll('script[src]').forEach(s => addResource(s.src, 'script'));
  document.querySelectorAll('link[rel*="stylesheet"], link[rel*="icon"]').forEach(l => addResource(l.href, 'link'));
  document.querySelectorAll('img[src]').forEach(i => addResource(i.src, 'image'));
  document.querySelectorAll('iframe[src]').forEach(f => addResource(f.src, 'iframe'));
  document.querySelectorAll('a[href]').forEach(a => {
    if (a.href && (a.href.startsWith(window.location.origin) || a.href.includes('/api/'))) {
      addResource(a.href, 'endpoint');
    }
  });

  document.querySelectorAll('form').forEach((form, idx) => {
    const action = form.getAttribute('action') || window.location.href;
    const method = (form.getAttribute('method') || 'GET').toUpperCase();
    const inputs = Array.from(form.querySelectorAll('input, select, textarea')).map(inp => ({
      name: inp.getAttribute('name') || inp.getAttribute('id') || 'unnamed',
      type: inp.getAttribute('type') || 'text'
    }));

    const hasPassword = inputs.some(i => i.type === 'password');
    const isSearch = inputs.some(i => /search|q|find|query/i.test(i.name));
    const isHttpSubmit = action.startsWith('http:');
    const hasCsrfToken = inputs.some(i => /csrf|token|_token|xsrf/i.test(i.name));

    forms.push({
      index: idx + 1,
      action: action,
      method: method,
      inputs: inputs,
      hasPassword: hasPassword,
      isSearch: isSearch,
      isHttpSubmit: isHttpSubmit,
      hasCsrfToken: hasCsrfToken
    });
  });

  return { resources, forms };
}

// 6b. Behavior-driven route learning helpers.
// Classify a form so we only ever auto-submit SEARCH forms (never contact/
// signup/booking forms, which would send real submissions / emails).
const VYASA_STATE_FIELD_RX = /(contact|message|comment|signup|sign_up|register|subscribe|newsletter|review|feedback|order|checkout|payment|pay|booking|book|enquiry|inquiry|password)/i;
const VYASA_SEARCH_HINTS = /^(q|s|query|search|keyword|keywords|term|k|wd|search_text)$/i;

function vyasaIsSearchForm(form) {
  const inputs = Array.from(form.querySelectorAll('input, textarea'));
  const names = inputs.map((i) => (i.getAttribute('name') || i.getAttribute('id') || '').toLowerCase());
  const types = inputs.map((i) => (i.getAttribute('type') || 'text').toLowerCase());
  if (types.includes('password')) return false;
  if (names.some((n) => VYASA_STATE_FIELD_RX.test(n))) return false;
  const hasTextLike = inputs.some((i) => ['text', 'search', ''].includes((i.getAttribute('type') || 'text').toLowerCase()));
  const looksSearch = types.includes('search') || names.some((n) => VYASA_SEARCH_HINTS.test(n) || /search/.test(n));
  // A short form with a single text input is very likely a search box.
  const textCount = inputs.filter((i) => ['text', 'search', ''].includes((i.getAttribute('type') || 'text').toLowerCase())).length;
  return looksSearch || (hasTextLike && textCount <= 2 && inputs.length <= 3);
}

function vyasaListSearchForms() {
  const forms = Array.from(document.querySelectorAll('form')).filter(vyasaIsSearchForm);
  return forms.map((f, i) => ({
    index: i,
    action: f.getAttribute('action') || location.href,
    inputs: Array.from(f.querySelectorAll('input, textarea')).map((inp) => inp.getAttribute('name') || inp.getAttribute('id') || '').filter(Boolean)
  }));
}

function vyasaSubmitSearchProbe(formIndex, canary) {
  const forms = Array.from(document.querySelectorAll('form')).filter(vyasaIsSearchForm);
  const form = forms[formIndex];
  if (!form) return { ok: false, reason: 'no-form' };
  // Fill every text-like input with the canary.
  form.querySelectorAll('input, textarea').forEach((inp) => {
    const t = (inp.getAttribute('type') || 'text').toLowerCase();
    if (['text', 'search', ''].includes(t) || inp.tagName === 'TEXTAREA') {
      try { inp.focus(); inp.value = canary; inp.dispatchEvent(new Event('input', { bubbles: true })); } catch (e) {}
    }
  });
  // Trigger submission the way the site does — prefer clicking the submit control
  // (fires JS handlers that may build pretty URLs), then Enter, then native submit.
  const btn = form.querySelector('button[type="submit"], input[type="submit"], button:not([type])');
  const firstText = form.querySelector('input[type="text"], input[type="search"], input:not([type])');
  try {
    if (firstText) firstText.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', keyCode: 13, which: 13, bubbles: true }));
  } catch (e) {}
  try {
    if (btn) btn.click();
    else if (form.requestSubmit) form.requestSubmit();
    else form.submit();
  } catch (e) {
    try { form.submit(); } catch (e2) {}
  }
  return { ok: true };
}

// 7. Message Listener
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'COLLECT_ATTACK_SURFACE') {
    sendResponse(collectAttackSurface());
    return true;
  }
  if (message.type === 'LIST_SEARCH_FORMS') {
    sendResponse({ forms: vyasaListSearchForms() });
    return true;
  }
  if (message.type === 'SUBMIT_FORM_PROBE') {
    sendResponse(vyasaSubmitSearchProbe(message.formIndex || 0, message.canary));
    return true;
  }
  if (message.type === 'COLLECT_DOM_RESOURCES' || message.type === 'DEEP_CLIENT_RECON') {
    const secrets = scanForSecrets();
    const storage = scanWebStorage();
    const technologies = detectDomTechnologies();
    const domSinks = scanDomXssSinks();
    const mixedContent = detectMixedContent();
    const { resources, forms } = collectDomResources();

    sendResponse({
      secrets: secrets,
      storage: storage,
      technologies: technologies,
      domSinks: domSinks,
      mixedContent: mixedContent,
      resources: resources,
      forms: forms,
      title: document.title,
      metaTagsCount: document.querySelectorAll('meta').length
    });
    return true; // Asynchronous channel
  }
});