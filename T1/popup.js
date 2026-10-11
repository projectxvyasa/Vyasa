// popup.js — Cyber Terminal HUD Controller

document.addEventListener('DOMContentLoaded', () => {
  const scanBtn = document.getElementById('scanBtn');
  const exportJsonBtn = document.getElementById('exportJsonBtn');
  const exportMdBtn = document.getElementById('exportMdBtn');
  const targetUrlDisplay = document.getElementById('targetUrlDisplay');
  const scoreNum = document.getElementById('scoreNum');
  const scoreGrade = document.getElementById('scoreGrade');
  const scoreCircle = document.getElementById('scoreCircle');
  const terminalConsole = document.getElementById('terminalConsole');

  let activeTab = null;
  let lastAuditResults = null;
  let lastActiveResults = null;

  // Theme (light / dark) with persistence.
  const themeToggle = document.getElementById('themeToggle');
  function applyTheme(theme) {
    if (theme === 'light') document.documentElement.setAttribute('data-theme', 'light');
    else document.documentElement.removeAttribute('data-theme');
    if (themeToggle) themeToggle.textContent = theme === 'light' ? '☀️' : '🌙';
  }
  (function initTheme() {
    let saved = 'dark';
    try { saved = localStorage.getItem('vyasa_theme') || 'dark'; } catch (e) {}
    applyTheme(saved);
  })();
  if (themeToggle) {
    themeToggle.addEventListener('click', () => {
      const isLight = document.documentElement.getAttribute('data-theme') === 'light';
      const next = isLight ? 'dark' : 'light';
      applyTheme(next);
      try { localStorage.setItem('vyasa_theme', next); } catch (e) {}
    });
  }

  // 1. Initialize Active Tab Info
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs && tabs[0]) {
      activeTab = tabs[0];
      if (activeTab.url) {
        targetUrlDisplay.innerHTML = `TARGET: <span>${activeTab.url}</span>`;
        logTerminal(`Target acquired: ${activeTab.url}`, 'info');
      } else {
        targetUrlDisplay.innerHTML = `TARGET: <span style="color:var(--alert-red);">Unrestricted / Restricted Page</span>`;
        scanBtn.disabled = true;
        logTerminal('Restricted chrome:// or local origin. Navigation required.', 'warn');
      }
    }
  });

  // 2. Tab Navigation Switcher
  const tabButtons = document.querySelectorAll('.tab-btn');
  const tabPanels = document.querySelectorAll('.tab-panel');

  tabButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      tabButtons.forEach(b => b.classList.remove('active'));
      tabPanels.forEach(p => p.classList.remove('active'));

      btn.classList.add('active');
      const targetPanelId = btn.getAttribute('data-tab');
      const targetPanel = document.getElementById(targetPanelId);
      if (targetPanel) {
        targetPanel.classList.add('active');
      }
    });
  });

  // 3. Initiate Scan Handler
  scanBtn.addEventListener('click', async () => {
    if (!activeTab || !activeTab.url || !activeTab.url.startsWith('http')) {
      logTerminal('ERROR: Invalid HTTP/HTTPS target.', 'err');
      return;
    }

    scanBtn.disabled = true;
    scanBtn.innerHTML = '◉ SCANNING...';
    clearTerminal();
    logTerminal(`[INIT] Starting Security & Tech Recon on ${activeTab.url}`, 'info');

    try {
      logTerminal('[RECON] Fetching response headers & DOM assets...', 'info');
      
      const response = await chrome.runtime.sendMessage({
        type: 'ANALYZE_SITE',
        url: activeTab.url,
        tabId: activeTab.id
      });

      if (chrome.runtime.lastError) {
        throw new Error(chrome.runtime.lastError.message);
      }

      if (response.error) {
        throw new Error(response.error);
      }

      lastAuditResults = response;
      logTerminal('[RECON] Security headers & server exposure parsed.', 'success');
      logTerminal(`[RECON] Detected ${response.technologies.length} technologies in target stack.`, 'success');
      logTerminal(`[RECON] Found ${response.secrets.length} client-side secret/leak warnings.`, response.secrets.length > 0 ? 'warn' : 'success');
      logTerminal(`[RECON] Cloudflare DoH DNS lookup completed.`, 'success');
      logTerminal(`[COMPLETE] Passive threat score: ${response.score}/100`, response.score >= 80 ? 'success' : 'warn');

      renderAllResults(response);

      // Phase 2: discover the attack surface, then optionally confirm actively.
      await runDiscoveryAndMaybeActive();

    } catch (err) {
      console.error('Scan Error:', err);
      logTerminal(`[FAIL] ${err.message}`, 'err');
    } finally {
      scanBtn.disabled = false;
      scanBtn.innerHTML = '▶ INITIATE SCAN';
    }
  });

  // 3b. Discovery + Active confirmation — driven by INITIATE SCAN + ACTIVE toggle
  const activeToggle = document.getElementById('activeToggle');
  const authModal = document.getElementById('authModal');
  const authModalOrigin = document.getElementById('authModalOrigin');
  const optSqli = document.getElementById('optSqli');
  const optPost = document.getElementById('optPost');
  const optState = document.getElementById('optState');
  const optAck = document.getElementById('optAck');
  const authCancel = document.getElementById('authCancel');
  const authConfirm = document.getElementById('authConfirm');

  let lastRecon = null; // discovered surface (endpoints + subdomains)

  function escapeHtml(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  function currentOrigin() {
    try { return new URL(activeTab.url).origin; } catch (e) { return null; }
  }

  // Delegated copy handler for any generated proof/payload button.
  document.addEventListener('click', (e) => {
    const btn = e.target && e.target.closest ? e.target.closest('.vy-copy-btn') : null;
    if (!btn) return;
    const payload = btn.getAttribute('data-payload') || '';
    navigator.clipboard.writeText(payload).then(() => {
      const orig = btn.textContent;
      btn.textContent = 'COPIED!';
      setTimeout(() => { btn.textContent = orig; }, 1200);
    }).catch(() => {});
  });

  if (optAck) optAck.addEventListener('change', () => { authConfirm.disabled = !optAck.checked; });
  if (authCancel) authCancel.addEventListener('click', () => {
    authModal.style.display = 'none';
    // User declined active mode — leave recon map as-is, untick the toggle.
    if (activeToggle) activeToggle.checked = false;
    logTerminal('[ACTIVE] Authorization declined — discovery results only.', 'warn');
  });

  if (authConfirm) {
    authConfirm.addEventListener('click', async () => {
      const origin = currentOrigin();
      const opts = { sqli: optSqli.checked, includePost: optPost.checked, includeStateChanging: optState.checked };
      await chrome.runtime.sendMessage({ type: 'SET_AUTH', origin, authorized: true, opts });
      authModal.style.display = 'none';
      await doActiveScan(opts);
    });
  }

  // Runs after passive scan: discover the surface, then (if ACTIVE toggled)
  // confirm vulnerabilities, gating on per-origin authorization.
  async function runDiscoveryAndMaybeActive() {
    const asTabBtn = document.querySelector('.tab-btn[data-tab="panelActive"]');
    if (asTabBtn) asTabBtn.click();

    logTerminal('[DISCOVER] Mapping attack surface — crawl, robots/sitemap, subdomains...', 'info');
    try {
      const recon = await chrome.runtime.sendMessage({ type: 'DISCOVER', url: activeTab.url, tabId: activeTab.id, opts: {} });
      if (recon && !recon.error) {
        lastRecon = recon;
        logTerminal(`[DISCOVER] ${recon.stats.endpoints} endpoint(s) (${recon.stats.withParams} with params) · ${recon.stats.subdomains} subdomain(s) · ${recon.stats.pagesCrawled} pages.`, 'success');
        renderSurfacePanel({ recon });
      } else {
        logTerminal(`[DISCOVER] notice: ${recon ? recon.error : 'no response'}`, 'warn');
      }
    } catch (err) {
      logTerminal(`[DISCOVER][FAIL] ${err.message}`, 'err');
    }

    if (!activeToggle || !activeToggle.checked) {
      logTerminal('[ACTIVE] Toggle off — passive + discovery only (no test traffic sent).', 'info');
      return;
    }

    // Active mode requested — check authorization.
    const origin = currentOrigin();
    const { authorized } = await chrome.runtime.sendMessage({ type: 'GET_AUTH', origin });
    if (authorized) {
      await doActiveScan({ sqli: true, includePost: true, includeStateChanging: false });
    } else {
      authModalOrigin.textContent = origin;
      optAck.checked = false;
      authConfirm.disabled = true;
      authModal.style.display = 'flex';
      logTerminal('[ACTIVE] Awaiting authorization confirmation for this origin...', 'warn');
    }
  }

  async function doActiveScan(opts) {
    logTerminal(`[ACTIVE] Confirming vulnerabilities on ${currentOrigin()} — testing each parameter...`, 'warn');
    try {
      const baseScore = lastAuditResults ? lastAuditResults.score : 100;
      const endpoints = lastRecon && lastRecon.endpoints ? lastRecon.endpoints : [];
      const results = await chrome.runtime.sendMessage({
        type: 'ACTIVE_SCAN', url: activeTab.url, tabId: activeTab.id,
        opts: Object.assign({}, opts, { endpoints }), baseScore
      });

      if (!results || results.error) {
        const msg = results ? results.error : 'no response';
        logTerminal(`[ACTIVE][FAIL] ${msg}`, 'err');
        renderActiveError(msg);
        return;
      }

      if (results.learnedRoutes && results.learnedRoutes.length) {
        logTerminal(`[ACTIVE] Learned ${results.learnedRoutes.length} route(s) by submitting forms: ${results.learnedRoutes.slice(0, 4).join(' · ')}`, 'success');
      }
      logTerminal(`[ACTIVE] Tested ${results.paramsTested} injection point(s) across ${results.endpointsTested} endpoint(s) incl. path segments — ${results.requestsSent} requests.`, 'info');
      logTerminal(`[ACTIVE] CONFIRMED: ${results.summary.confirmed} · SUSPECTED: ${results.summary.suspected}`, results.summary.confirmed > 0 ? 'warn' : 'success');
      if (typeof results.adjustedScore === 'number') {
        logTerminal(`[ACTIVE] Score after active confirmation: ${results.adjustedScore}/100`, 'info');
        updateScoreGauge(results.adjustedScore);
      }
      lastActiveResults = results;
      renderSurfacePanel({ recon: lastRecon, active: results });
      // Refresh PAYLOADS so confirmed injection points (endpoint+param+payload) show there.
      renderPayloadsTab(lastAuditResults || {});
    } catch (err) {
      logTerminal(`[ACTIVE][FAIL] ${err.message}`, 'err');
      renderActiveError(err.message);
    }
  }

  function renderActiveError(msg) {
    const container = document.getElementById('activeResults');
    const empty = document.getElementById('activeEmptyState');
    if (empty) empty.style.display = 'none';
    const friendly = msg === 'NOT_AUTHORIZED'
      ? 'This origin is not authorized for active scanning. Re-run and confirm authorization.'
      : msg === 'ACTIVE_ENGINE_UNAVAILABLE'
        ? 'Active engine failed to load (check active-scan.js).'
        : msg;
    container.innerHTML = `<div class="cyber-card" style="border-color:var(--alert-red);"><div class="cyber-card-header" style="color:var(--alert-red);">⚠ ACTIVE SCAN ERROR</div><p style="font-size:11px;color:var(--text-sub);margin:0;">${escapeHtml(friendly)}</p></div>`;
  }

  const CTX_LABEL = {
    'html-text': 'HTML body', 'attr-quoted': 'quoted attribute', 'attr-unquoted': 'unquoted attribute',
    'url-attr': 'URL attribute', 'js-string': 'JS string', 'js-code': 'JS code', 'none': 'not reflected'
  };

  function filterProfileHtml(profile) {
    if (!profile) return '';
    const order = ['<', '>', '"', "'", '`', '(', ')', ';', '/', '=', '{', '}'];
    const cell = (c) => {
      const st = profile[c] || 'n/a';
      const color = st === 'raw' ? 'var(--alert-red)' : st === 'encoded' ? 'var(--matrix-green)' : 'var(--text-muted)';
      const glyph = st === 'raw' ? '●' : st === 'encoded' ? '🛡' : '∅';
      return `<td style="text-align:center;color:${color};" title="${st}"><code>${escapeHtml(c)}</code><br>${glyph}</td>`;
    };
    return `
      <div style="margin-top:8px;">
        <div style="font-size:9px;color:var(--text-muted);margin-bottom:4px;">FILTER PROFILE — <span style="color:var(--alert-red);">● raw (passes)</span> · <span style="color:var(--matrix-green);">🛡 encoded</span> · ∅ stripped</div>
        <table class="cyber-table" style="font-size:10px;"><tbody><tr>${order.map(cell).join('')}</tr></tbody></table>
      </div>`;
  }

  function findingCard(f) {
    const stateColor = f.state === 'confirmed' ? 'var(--alert-red)' : 'var(--warn-orange)';
    const kindLabel = { xss: 'REFLECTED XSS', sqli: 'SQL INJECTION', 'open-redirect': 'OPEN REDIRECT' }[f.kind] || f.kind.toUpperCase();
    return `
      <div class="threat-item ${f.state === 'confirmed' ? 'high' : 'medium'}" style="border-left-color:${stateColor};">
        <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;">
          <span class="threat-title" style="margin:0;">${kindLabel}</span>
          <span class="state-badge ${f.state}">${f.state.toUpperCase()}</span>
        </div>
        <div style="font-family:var(--font-mono);font-size:10px;margin:6px 0;">
          <div><span style="color:var(--text-muted);">param</span> <code style="color:var(--neon-cyan);">${escapeHtml(f.param)}</code> <span style="color:var(--text-muted);">(${escapeHtml(f.location)})</span></div>
          <div><span style="color:var(--text-muted);">endpoint</span> <code style="color:var(--matrix-green);word-break:break-all;">${escapeHtml(f.method)} ${escapeHtml(f.endpoint)}</code></div>
          ${f.context ? `<div><span style="color:var(--text-muted);">context</span> ${escapeHtml(CTX_LABEL[f.context] || f.context)}${f.reflectionCount ? ` · ${f.reflectionCount}× reflected` : ''}</div>` : ''}
          ${f.technique ? `<div><span style="color:var(--text-muted);">technique</span> ${escapeHtml(f.technique)}</div>` : ''}
        </div>
        <p class="threat-detail" style="margin:4px 0;">${escapeHtml(f.note)}</p>
        ${f.evidence ? `<div class="secret-code" style="margin-top:4px;">${escapeHtml(f.evidence)}</div>` : ''}
        ${f.samplePayload ? `
          <div style="margin-top:6px;">
            <div style="font-size:9px;color:var(--text-muted);margin-bottom:3px;">PROOF PAYLOAD (${escapeHtml(CTX_LABEL[f.context] || f.context || 'context')}):</div>
            <div style="display:flex;align-items:center;gap:6px;">
              <code style="flex:1;color:var(--matrix-green);font-size:10px;word-break:break-all;background:var(--bg-tertiary);padding:5px 7px;border-radius:3px;">${escapeHtml(f.samplePayload)}</code>
              <button class="vy-copy-btn" data-payload="${escapeHtml(f.samplePayload)}">COPY</button>
            </div>
          </div>` : ''}
        ${f.filterProfile ? filterProfileHtml(f.filterProfile) : ''}
      </div>`;
  }

  // Combined ATTACK SURFACE renderer: recon map (endpoints + subdomains) plus
  // active findings when an active scan has run.
  function renderSurfacePanel(state) {
    const container = document.getElementById('activeResults');
    const empty = document.getElementById('activeEmptyState');
    if (empty) empty.style.display = 'none';
    const recon = state.recon;
    const data = state.active;
    let html = '';

    // --- Active findings (top, when present) ---
    if (data) {
      const findings = data.findings || [];
      const confirmed = findings.filter((f) => f.state === 'confirmed');
      const suspected = findings.filter((f) => f.state === 'suspected');

      html += `
        <div class="cyber-card">
          <div class="cyber-card-header">
            <span>⚡ ACTIVE SCAN SUMMARY</span>
            <span class="count-badge" style="border-color:var(--alert-red);color:var(--alert-red);">${confirmed.length} CONFIRMED</span>
          </div>
          <div style="font-size:10px;color:var(--text-sub);font-family:var(--font-mono);">
            <div>Endpoints tested: <strong>${data.endpointsTested}</strong> · Parameters: <strong>${data.paramsTested}</strong> · Requests: <strong>${data.requestsSent}</strong></div>
            <div>Confirmed: <strong style="color:var(--alert-red);">${confirmed.length}</strong> · Suspected: <strong style="color:var(--warn-orange);">${suspected.length}</strong> · Duration: ${Math.round((data.durationMs || 0) / 100) / 10}s</div>
            ${data.scanOpts ? `<div style="color:var(--text-muted);">options: SQLi ${data.scanOpts.sqli ? 'on' : 'off'} · POST ${data.scanOpts.includePost ? 'on' : 'off'}</div>` : ''}
          </div>
        </div>`;

      if (findings.length === 0) {
        html += `<div class="cyber-card"><div class="cyber-card-header">✓ NO REFLECTED/INJECTABLE PARAMS CONFIRMED</div><p style="font-size:11px;color:var(--matrix-green);margin:0;">No parameter reflected a canary unencoded and no SQL errors surfaced. If a known bug was missed: it may be a <strong>POST</strong> field (enable POST testing) or <strong>DOM-based</strong> (executes client-side — phase 2). Interact with the app and re-run to widen the surface.</p></div>`;
      } else {
        if (confirmed.length) html += `<div class="cyber-card" style="border-color:var(--alert-red);"><div class="cyber-card-header" style="color:var(--alert-red);"><span>🎯 CONFIRMED FINDINGS</span><span class="count-badge" style="border-color:var(--alert-red);color:var(--alert-red);">${confirmed.length}</span></div>${confirmed.map(findingCard).join('')}</div>`;
        if (suspected.length) html += `<div class="cyber-card" style="border-color:var(--warn-orange);"><div class="cyber-card-header" style="color:var(--warn-orange);"><span>⚠ SUSPECTED (verify manually)</span><span class="count-badge" style="border-color:var(--warn-orange);color:var(--warn-orange);">${suspected.length}</span></div>${suspected.map(findingCard).join('')}</div>`;
      }

      if (data.cors && data.cors.tested) {
        const v = data.cors.verdict || {};
        const vc = v.state === 'confirmed' ? 'var(--alert-red)' : v.state === 'suspected' ? 'var(--warn-orange)' : 'var(--matrix-green)';
        html += `
          <div class="cyber-card">
            <div class="cyber-card-header"><span>🔗 CORS TRUST MAP</span><span class="count-badge" style="border-color:${vc};color:${vc};">${(v.state || 'info').toUpperCase()}</span></div>
            <p style="font-size:10px;color:var(--text-sub);margin:0 0 8px;">${escapeHtml(v.note || '')}</p>
            <table class="cyber-table" style="font-size:9px;"><thead><tr><th>Probe Origin</th><th>ACAO</th><th>Creds</th><th>Reflected</th></tr></thead><tbody>
            ${(data.cors.results || []).map((r) => `<tr class="${r.dangerous ? 'row-fail' : ''}"><td><code>${escapeHtml(r.probe)}</code></td><td><code>${escapeHtml(r.acao || '—')}</code></td><td>${r.acac === 'true' ? '✓' : '✖'}</td><td>${r.reflected ? '⚠' : '—'}</td></tr>`).join('')}
            </tbody></table>
          </div>`;
      }

      // Forms deliberately not submitted (state-changing, or POST testing off).
      if (data.skipped && data.skipped.length) {
        html += `
          <div class="cyber-card" style="border-color:var(--text-muted);">
            <div class="cyber-card-header"><span>⏭ NOT TESTED (by safety policy)</span><span class="count-badge">${data.skipped.length}</span></div>
            <p style="font-size:9px;color:var(--text-muted);margin:0 0 6px;">To test contact/signup/booking forms (sends real submissions), re-run with the <strong>state-changing</strong> option ticked in the authorization dialog.</p>
            ${data.skipped.map((s) => `<div style="font-family:var(--font-mono);font-size:9px;margin-bottom:3px;"><code style="color:var(--warn-orange);word-break:break-all;">${escapeHtml(s.method)} ${escapeHtml(s.url)}</code><div style="color:var(--text-muted);">${escapeHtml(s.reason)} · fields: ${(s.params || []).map(escapeHtml).join(', ')}</div></div>`).join('')}
          </div>`;
      }
    }

    // --- Recon map: discovered endpoints ---
    if (recon && recon.endpoints) {
      const withParams = recon.endpoints.filter((e) => e.params && e.params.length);
      const noParams = recon.endpoints.filter((e) => !e.params || !e.params.length);
      html += `
        <div class="cyber-card">
          <div class="cyber-card-header"><span>🗺 DISCOVERED ENDPOINTS</span><span class="count-badge">${recon.endpoints.length} (${withParams.length} testable)</span></div>
          ${recon.crawledPages ? `<div style="font-size:9px;color:var(--text-muted);margin-bottom:6px;">crawled ${recon.crawledPages.length} page(s) · robots/sitemap · JS extraction</div>` : ''}
          <div style="max-height:220px;overflow-y:auto;font-family:var(--font-mono);font-size:9px;">
          ${withParams.map((e) => `
            <div style="padding:5px 0;border-bottom:1px solid var(--border-cyber);">
              <code style="color:var(--neon-cyan);word-break:break-all;">${escapeHtml(e.method)} ${escapeHtml(e.url)}</code>
              <div style="color:var(--matrix-green);">params: ${e.params.map((p) => escapeHtml(p.name) + (p.inferred ? '<span style="color:var(--warn-orange);" title="inferred search param">*</span>' : '')).join(', ')}</div>
              <div style="color:var(--text-muted);opacity:.7;">via ${(e.sources || []).map(escapeHtml).join(', ')}</div>
            </div>`).join('')}
          ${noParams.length ? `<details style="margin-top:6px;"><summary style="color:var(--text-muted);cursor:pointer;">+ ${noParams.length} endpoint(s) without parameters</summary>${noParams.map((e) => `<div style="padding:3px 0;color:var(--text-muted);"><code style="word-break:break-all;">${escapeHtml(e.url)}</code></div>`).join('')}</details>` : ''}
          </div>
          <div style="font-size:9px;color:var(--text-muted);margin-top:6px;">* = inferred search parameter. ${data ? '' : 'Enable the <strong>⚡ ACTIVE</strong> toggle and re-scan to confirm which of these are injectable.'}</div>
        </div>`;
    }

    // --- Recon map: subdomains ("what is where") ---
    if (recon && recon.subdomains && recon.subdomains.length) {
      html += `
        <div class="cyber-card">
          <div class="cyber-card-header"><span>🌐 DISCOVERED SUBDOMAINS</span><span class="count-badge">${recon.subdomains.length}</span></div>
          <p style="font-size:9px;color:var(--text-muted);margin:0 0 6px;">Passive recon via Certificate Transparency (crt.sh) + DNS. Listed for scope awareness — VYASA does not actively test a subdomain you haven't targeted.</p>
          <div style="max-height:160px;overflow-y:auto;font-family:var(--font-mono);font-size:9px;">
          ${recon.subdomains.map((s) => `<div style="padding:2px 0;"><code style="color:var(--neon-cyan);">${escapeHtml(s)}</code></div>`).join('')}
          </div>
        </div>`;
    }

    if (!html) {
      html = `<div class="cyber-card"><div class="cyber-card-header">ℹ NO ATTACK SURFACE DISCOVERED</div><p style="font-size:11px;color:var(--text-sub);margin:0;">No endpoints or subdomains found. Interact with the page and re-scan.</p></div>`;
    }

    container.innerHTML = html;
  }

  // 4. Render Results into Tab Panels
  function renderAllResults(data) {
    updateScoreGauge(data.score);

    renderOverviewTab(data);
    renderHeadersTab(data);
    renderPayloadsTab(data);
    renderSecretsTab(data);
    renderCookiesTab(data);
    renderTechTab(data);
    renderDnsTab(data);
  }

  // 4a. Overview Panel
  function renderOverviewTab(data) {
    const emptyState = document.getElementById('overviewEmptyState');
    const container = document.getElementById('overviewResults');
    emptyState.style.display = 'none';

    let html = '';

    // Security Drift Card
    if (data.drift && data.drift.hasHistory) {
      const deltaStr = data.drift.scoreDelta >= 0 ? `+${data.drift.scoreDelta}` : `${data.drift.scoreDelta}`;
      const deltaColor = data.drift.scoreDelta >= 0 ? 'var(--matrix-green)' : 'var(--alert-red)';
      html += `
        <div class="cyber-card" style="border-color:var(--neon-cyan);">
          <div class="cyber-card-header">
            <span>📈 SECURITY DRIFT TRACKING</span>
            <span class="count-badge" style="border-color:${deltaColor}; color:${deltaColor};">SCORE DELTA: ${deltaStr}</span>
          </div>
          <div style="font-size:10px; color:var(--text-sub);">
            <div>Previous Score: <strong>${data.drift.previousScore}/100</strong> → Current: <strong>${data.score}/100</strong></div>
            ${data.drift.addedHeaders.length > 0 ? `<div style="color:var(--matrix-green);">+ Added Protection Headers: ${data.drift.addedHeaders.join(', ')}</div>` : ''}
            ${data.drift.removedHeaders.length > 0 ? `<div style="color:var(--alert-red);">- Removed Protection Headers: ${data.drift.removedHeaders.join(', ')}</div>` : ''}
          </div>
        </div>
      `;
    }

    // Vulnerabilities Summary
    if (data.vulnerabilities && data.vulnerabilities.length > 0) {
      html += `
        <div class="cyber-card">
          <div class="cyber-card-header">
            <span>⚠ PREDICTED THREATS & RISKS</span>
            <span class="count-badge" style="border-color:var(--alert-red); color:var(--alert-red);">${data.vulnerabilities.length} DETECTED</span>
          </div>
          ${data.vulnerabilities.map(v => `
            <div class="threat-item ${v.severity}">
              <div class="threat-title">[${v.severity.toUpperCase()}] ${v.title}</div>
              <p class="threat-detail">${v.detail}</p>
              <div class="threat-fix"><span>RECOMMENDED FIX:</span> ${v.mitigation}</div>
            </div>
          `).join('')}
        </div>
      `;
    } else {
      html += `
        <div class="cyber-card">
          <div class="cyber-card-header">✓ THREAT MATRIX CLEAN</div>
          <p style="font-size:11px; color:var(--matrix-green); margin:0;">No immediate high-severity header or secret vulnerabilities detected.</p>
        </div>
      `;
    }

    // Client-side findings previously collected but never surfaced:
    // web storage, DOM XSS sinks, and mixed content.
    html += clientFindingsHtml(data);

    container.innerHTML = html;
  }

  // Render web-storage, DOM-sink and mixed-content findings (collected by content.js).
  function clientFindingsHtml(data) {
    let html = '';

    if (data.storage && data.storage.length > 0) {
      html += `
        <div class="cyber-card" style="border-color:var(--warn-orange);">
          <div class="cyber-card-header" style="color:var(--warn-orange);"><span>💾 SENSITIVE WEB STORAGE</span><span class="count-badge">${data.storage.length}</span></div>
          ${data.storage.map((s) => `
            <div style="font-family:var(--font-mono);font-size:10px;margin-bottom:6px;">
              <div><code style="color:var(--neon-cyan);">${escapeHtml(s.storage)}.${escapeHtml(s.key)}</code> ${s.isJwt ? '<span style="color:var(--cyber-purple);">[JWT]</span>' : ''}</div>
              <div style="color:var(--text-sub);">${escapeHtml(s.risk)}</div>
            </div>`).join('')}
        </div>`;
    }

    if (data.domSinks && data.domSinks.length > 0) {
      html += `
        <div class="cyber-card" style="border-color:var(--alert-red);">
          <div class="cyber-card-header" style="color:var(--alert-red);"><span>🧨 DOM XSS SINKS</span><span class="count-badge" style="border-color:var(--alert-red);color:var(--alert-red);">${data.domSinks.length}</span></div>
          <p style="font-size:9px;color:var(--text-muted);margin:0 0 6px;">Dangerous sinks in inline scripts. Confirm whether user input reaches these via an Active Scan.</p>
          ${data.domSinks.slice(0, 20).map((s) => `
            <div style="font-family:var(--font-mono);font-size:9px;margin-bottom:5px;">
              <div style="color:var(--warn-orange);">${escapeHtml(s.sink)} <span style="color:var(--text-muted);">— ${escapeHtml(s.source)}</span></div>
              <div class="secret-code">${escapeHtml(s.snippet)}</div>
            </div>`).join('')}
        </div>`;
    }

    if (data.mixedContent && data.mixedContent.length > 0) {
      html += `
        <div class="cyber-card" style="border-color:var(--warn-orange);">
          <div class="cyber-card-header" style="color:var(--warn-orange);"><span>🔓 MIXED CONTENT</span><span class="count-badge">${data.mixedContent.length}</span></div>
          ${data.mixedContent.slice(0, 20).map((m) => `
            <div style="font-family:var(--font-mono);font-size:9px;margin-bottom:4px;">
              <span style="color:var(--text-muted);">${escapeHtml(m.type)}:</span> <code style="color:var(--warn-orange);word-break:break-all;">${escapeHtml(m.url)}</code>
            </div>`).join('')}
        </div>`;
    }

    return html;
  }

  // 4b. Security Headers Panel
  function renderHeadersTab(data) {
    const emptyState = document.getElementById('headersEmptyState');
    const container = document.getElementById('headersResults');
    emptyState.style.display = 'none';

    const headers = data.securityHeaders || {};
    const passCount = Object.values(headers).filter(h => h.status === 'pass').length;
    const totalCount = Object.keys(headers).length;

    let html = `
      <div class="cyber-card">
        <div class="cyber-card-header">
          <span>🛡 SECURITY HEADERS</span>
          <span class="count-badge">${passCount}/${totalCount} PASS</span>
        </div>
        <table class="cyber-table">
          <thead>
            <tr><th>Header</th><th>Status</th></tr>
          </thead>
          <tbody>
            ${Object.entries(headers).map(([name, details]) => `
              <tr class="${details.status === 'pass' ? 'row-pass' : 'row-fail'}">
                <td>
                  <strong>${name}</strong><br>
                  <span style="font-size:9px; color:var(--text-muted);">${details.description}</span>
                </td>
                <td>${details.status === 'pass' ? '● PASS' : '○ FAIL'}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    `;

    if (data.headerExposures && data.headerExposures.length > 0) {
      html += `
        <div class="cyber-card" style="border-color:var(--warn-orange);">
          <div class="cyber-card-header" style="color:var(--warn-orange);">
            <span>⚠ SERVER BANNER DISCLOSURE</span>
          </div>
          ${data.headerExposures.map(e => `
            <div style="font-family:var(--font-mono); font-size:10px; margin-bottom:4px;">
              <span style="color:var(--text-sub);">${e.header}:</span> <code style="color:var(--warn-orange);">${e.value}</code>
            </div>
          `).join('')}
        </div>
      `;
    }

    container.innerHTML = html;
  }

  // 4c. Secrets & Leaks Panel
  function renderSecretsTab(data) {
    const emptyState = document.getElementById('secretsEmptyState');
    const container = document.getElementById('secretsResults');
    emptyState.style.display = 'none';

    if (!data.secrets || data.secrets.length === 0) {
      container.innerHTML = `
        <div class="cyber-card">
          <div class="cyber-card-header">✓ NO SECRETS EXPOSED</div>
          <p style="font-size:11px; color:var(--matrix-green); margin:0;">No hardcoded API keys, JWTs, or private keys found in the client DOM.</p>
        </div>
      `;
      return;
    }

    let html = `
      <div class="cyber-card">
        <div class="cyber-card-header">
          <span>🔑 LEAKED SECRETS & TOKENS</span>
          <span class="count-badge" style="border-color:var(--cyber-purple); color:var(--cyber-purple);">${data.secrets.length} FOUND</span>
        </div>
        ${data.secrets.map(s => `
          <div class="secret-item">
            <span class="secret-type">[${s.severity.toUpperCase()}] ${s.type}</span>
            <div style="color:var(--text-sub);">Source: ${s.source}</div>
            <div class="secret-code">${s.snippet}</div>
          </div>
        `).join('')}
      </div>
    `;

    container.innerHTML = html;
  }

  // 4d. Cookies Audit Panel
  function renderCookiesTab(data) {
    const emptyState = document.getElementById('cookiesEmptyState');
    const container = document.getElementById('cookiesResults');
    emptyState.style.display = 'none';

    if (!data.cookies || data.cookies.length === 0) {
      container.innerHTML = `
        <div class="cyber-card">
          <div class="cyber-card-header">ℹ COOKIES AUDIT</div>
          <p style="font-size:11px; color:var(--text-sub); margin:0;">No cookies set for this origin.</p>
        </div>
      `;
      return;
    }

    const failedCount = data.cookies.filter(c => c.status === 'fail').length;

    let html = `
      <div class="cyber-card">
        <div class="cyber-card-header">
          <span>🍪 COOKIE SECURITY</span>
          <span class="count-badge">${data.cookies.length} TOTAL (${failedCount} RISKS)</span>
        </div>
        <table class="cyber-table">
          <thead>
            <tr><th>Cookie</th><th>HttpOnly</th><th>Secure</th><th>SameSite</th></tr>
          </thead>
          <tbody>
            ${data.cookies.map(c => `
              <tr class="${c.status === 'pass' ? 'row-pass' : 'row-fail'}">
                <td><strong>${c.name}</strong></td>
                <td>${c.httpOnly ? '✓' : '✖'}</td>
                <td>${c.secure ? '✓' : '✖'}</td>
                <td>${c.sameSite || 'None'}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    `;

    container.innerHTML = html;
  }

  // 4e. Tech Stack Panel
  function renderTechTab(data) {
    const emptyState = document.getElementById('techEmptyState');
    const container = document.getElementById('techResults');
    emptyState.style.display = 'none';

    let html = '';

    if (data.technologies && data.technologies.length > 0) {
      html += `
        <div class="cyber-card">
          <div class="cyber-card-header">
            <span>⚙ DETECTED TECHNOLOGIES</span>
            <span class="count-badge">${data.technologies.length} IDENTIFIED</span>
          </div>
          <div class="tech-grid">
            ${data.technologies.map(t => `
              <div class="cyber-tag ${t.type}">${t.name} ${t.version ? `v${t.version}` : ''}</div>
            `).join('')}
          </div>
        </div>
      `;
    } else {
      html += `
        <div class="cyber-card">
          <p style="font-size:11px; color:var(--text-sub); margin:0;">No known tech signatures identified.</p>
        </div>
      `;
    }

    if (data.endpoints && data.endpoints.length > 0) {
      html += `
        <div class="cyber-card">
          <div class="cyber-card-header">
            <span>⊞ DISCOVERED ENDPOINTS</span>
            <span class="count-badge">${data.endpoints.length} ASSETS</span>
          </div>
          <div style="max-height:160px; overflow-y:auto;">
            ${data.endpoints.slice(0, 35).map(e => `
              <div style="font-family:var(--font-mono); font-size:9px; padding:3px 0; border-bottom:1px solid var(--border-cyber); display:flex; justify-content:space-between;">
                <code style="color:var(--neon-cyan); word-break:break-all;">${e.path}</code>
                <span style="color:var(--text-muted); text-transform:uppercase;">${e.type}</span>
              </div>
            `).join('')}
          </div>
        </div>
      `;
    }

    container.innerHTML = html;
  }

  // 4f. DNS & Net Panel
  function renderDnsTab(data) {
    const emptyState = document.getElementById('dnsEmptyState');
    const container = document.getElementById('dnsResults');
    emptyState.style.display = 'none';

    const dns = data.dns || {};

    let html = `
      <div class="cyber-card">
        <div class="cyber-card-header">
          <span>🌐 DNS & EMAIL RECON</span>
        </div>
        <div style="font-family:var(--font-mono); font-size:10px;">
          <div style="margin-bottom:8px;">
            <strong style="color:var(--neon-cyan);">SERVER IP(s):</strong><br>
            ${dns.ips && dns.ips.length > 0 ? dns.ips.map(ip => `<code style="color:var(--matrix-green);">${ip}</code>`).join(', ') : 'None resolved'}
          </div>
          <div style="margin-bottom:8px;">
            <strong style="color:var(--neon-cyan);">SPF RECORD:</strong> ${dns.hasSpf ? '✓ PRESENT' : '✖ MISSING'}<br>
            <code style="font-size:9px; color:var(--text-sub);">${dns.spf || 'No SPF TXT record found.'}</code>
          </div>
          <div style="margin-bottom:8px;">
            <strong style="color:var(--neon-cyan);">DMARC POLICY:</strong> ${dns.hasDmarc ? '✓ PRESENT' : '✖ MISSING'}<br>
            <code style="font-size:9px; color:var(--text-sub);">${dns.dmarc || 'No _dmarc TXT record found.'}</code>
          </div>
        </div>
      </div>
    `;

    html += hostIntelHtml(data.hostIntel);
    container.innerHTML = html;
  }

  // Server location + open ports/protocols (passive host intel).
  function hostIntelHtml(intel) {
    if (!intel) return '';
    let html = '';

    // Server location
    if (intel.geo) {
      const g = intel.geo;
      const place = [g.city, g.region, g.country].filter(Boolean).join(', ') || 'Unknown';
      const mapLink = (g.lat != null && g.lon != null) ? `https://www.openstreetmap.org/?mlat=${g.lat}&mlon=${g.lon}#map=10/${g.lat}/${g.lon}` : null;
      html += `
        <div class="cyber-card">
          <div class="cyber-card-header"><span>📍 SERVER LOCATION</span>${g.countryCode ? `<span class="count-badge">${escapeHtml(g.flag || '')} ${escapeHtml(g.countryCode)}</span>` : ''}</div>
          <div style="font-family:var(--font-mono);font-size:10px;line-height:1.7;">
            <div><span style="color:var(--text-muted);">location</span> <strong style="color:var(--matrix-green);">${escapeHtml(place)}</strong></div>
            ${g.org || g.isp ? `<div><span style="color:var(--text-muted);">hosted by</span> ${escapeHtml(g.org || g.isp)}</div>` : ''}
            ${g.asn ? `<div><span style="color:var(--text-muted);">network</span> ${escapeHtml(g.asn)}</div>` : ''}
            ${g.timezone ? `<div><span style="color:var(--text-muted);">timezone</span> ${escapeHtml(g.timezone)}</div>` : ''}
            ${g.lat != null ? `<div><span style="color:var(--text-muted);">coords</span> <code>${escapeHtml(g.lat)}, ${escapeHtml(g.lon)}</code>${mapLink ? ` · <a href="${mapLink}" target="_blank" style="color:var(--neon-cyan);">map ↗</a>` : ''}</div>` : ''}
          </div>
        </div>`;
    }

    // Open ports & protocols
    if (intel.services && intel.services.length) {
      html += `
        <div class="cyber-card">
          <div class="cyber-card-header"><span>🔌 OPEN PORTS & PROTOCOLS</span><span class="count-badge">${intel.services.length}</span></div>
          <table class="cyber-table" style="font-size:10px;">
            <thead><tr><th>Port</th><th>Protocol / Service</th></tr></thead>
            <tbody>
            ${intel.services.map((s) => {
              const risky = [21, 23, 3306, 3389, 5432, 6379, 27017, 9200, 11211, 5900, 445, 1433].includes(s.port);
              return `<tr class="${risky ? 'row-fail' : ''}"><td><code style="color:var(--neon-cyan);">${s.port}</code></td><td style="color:${risky ? 'var(--warn-orange)' : 'var(--text-sub)'};">${escapeHtml(s.service)}${risky ? ' ⚠' : ''}</td></tr>`;
            }).join('')}
            </tbody>
          </table>
          ${intel.tags && intel.tags.length ? `<div style="font-size:9px;color:var(--text-muted);margin-top:6px;">tags: ${intel.tags.map(escapeHtml).join(', ')}</div>` : ''}
        </div>`;
    } else if (intel.ip) {
      html += `<div class="cyber-card"><div class="cyber-card-header">🔌 OPEN PORTS</div><p style="font-size:10px;color:var(--text-sub);margin:0;">No ports reported by Shodan InternetDB for ${escapeHtml(intel.ip)} (host may be behind a CDN/WAF, or not indexed).</p></div>`;
    }

    // Known CVEs for the host (from InternetDB)
    if (intel.vulns && intel.vulns.length) {
      html += `
        <div class="cyber-card" style="border-color:var(--alert-red);">
          <div class="cyber-card-header" style="color:var(--alert-red);"><span>🧬 HOST CVEs (Shodan)</span><span class="count-badge" style="border-color:var(--alert-red);color:var(--alert-red);">${intel.vulns.length}</span></div>
          <div style="max-height:150px;overflow-y:auto;font-family:var(--font-mono);font-size:9px;">
          ${intel.vulns.map((v) => `<a href="https://nvd.nist.gov/vuln/detail/${encodeURIComponent(v)}" target="_blank" style="color:var(--alert-red);display:inline-block;margin:2px 6px 2px 0;">${escapeHtml(v)}</a>`).join('')}
          </div>
        </div>`;
    }

    if (html && intel.sources && intel.sources.length) {
      html += `<div style="font-size:9px;color:var(--text-muted);padding:0 4px 4px;">Passive host intel via ${intel.sources.map(escapeHtml).join(' + ')} — public data, no traffic sent to the target.</div>`;
    }
    return html;
  }

  // 4g. Payloads Panel
  // Build the "where exactly" section from confirmed/suspected active findings.
  function confirmedInjectionHtml() {
    if (!lastActiveResults || !lastActiveResults.findings) return '';
    const inj = lastActiveResults.findings.filter((f) => f.kind === 'xss' || f.kind === 'sqli' || f.kind === 'open-redirect');
    if (!inj.length) return '';
    inj.sort((a, b) => (b.state === 'confirmed') - (a.state === 'confirmed'));
    const kindLabel = { xss: 'XSS', sqli: 'SQLi', 'open-redirect': 'OPEN REDIRECT' };
    return `
      <div class="cyber-card" style="border-color:var(--alert-red);">
        <div class="cyber-card-header" style="color:var(--alert-red);">
          <span>🎯 CONFIRMED INJECTION POINTS</span>
          <span class="count-badge" style="border-color:var(--alert-red);color:var(--alert-red);">${inj.filter((f) => f.state === 'confirmed').length} CONFIRMED</span>
        </div>
        <p style="font-size:10px;color:var(--text-sub);margin:0 0 10px;">These are tied to the exact endpoint &amp; parameter the active scan verified — paste the payload into that input/parameter to prove execution.</p>
        ${inj.map((f) => `
          <div class="payload-category" style="margin-bottom:12px;border:1px solid ${f.state === 'confirmed' ? 'var(--alert-red)' : 'var(--warn-orange)'};border-radius:4px;padding:10px;">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;">
              <span style="font-weight:700;color:var(--neon-cyan);">${kindLabel[f.kind] || f.kind}</span>
              <span class="state-badge ${f.state}">${f.state.toUpperCase()}</span>
            </div>
            <div style="font-family:var(--font-mono);font-size:10px;margin-bottom:6px;">
              <div><span style="color:var(--text-muted);">parameter</span> <code style="color:var(--neon-cyan);">${escapeHtml(f.param)}</code> <span style="color:var(--text-muted);">(${escapeHtml(f.location || 'query')})</span></div>
              <div><span style="color:var(--text-muted);">endpoint</span> <code style="color:var(--matrix-green);word-break:break-all;">${escapeHtml(f.method || 'GET')} ${escapeHtml(f.endpoint)}</code></div>
              ${f.context ? `<div><span style="color:var(--text-muted);">context</span> ${escapeHtml(CTX_LABEL[f.context] || f.context)}</div>` : ''}
            </div>
            ${f.samplePayload ? `
              <div style="display:flex;align-items:center;gap:6px;">
                <code class="payload-text" style="flex:1;color:var(--matrix-green);font-size:10px;word-break:break-all;background:var(--bg-tertiary);padding:6px 8px;border-radius:3px;">${escapeHtml(f.samplePayload)}</code>
                <button class="vy-copy-btn" data-payload="${escapeHtml(f.samplePayload)}">COPY</button>
              </div>` : `<div style="font-size:10px;color:var(--text-sub);">${escapeHtml(f.note || '')}</div>`}
          </div>`).join('')}
      </div>`;
  }

  function renderPayloadsTab(data) {
    const emptyState = document.getElementById('payloadsEmptyState');
    const container = document.getElementById('payloadsResults');
    emptyState.style.display = 'none';

    const injHtml = confirmedInjectionHtml();

    if (!data.payloads || data.payloads.length === 0) {
      container.innerHTML = injHtml + `
        <div class="cyber-card">
          <div class="cyber-card-header">${injHtml ? 'ℹ GENERIC PAYLOAD LIBRARY' : '✓ NO TEST PAYLOADS NEEDED'}</div>
          <p style="font-size:11px; color:var(--matrix-green); margin:0;">${injHtml ? 'No header-based generic payloads generated — see confirmed injection points above.' : 'All security headers present. No vulnerability payloads generated.'}</p>
        </div>
      `;
      return;
    }

    let html = injHtml + `
      <div class="cyber-card">
        <div class="cyber-card-header">
          <span>🎯 VULNERABILITY TEST PAYLOADS</span>
          <span class="count-badge" style="border-color:var(--cyber-purple); color:var(--cyber-purple);">${data.payloads.length} CATEGORIES</span>
        </div>
        <p style="font-size:10px; color:var(--text-muted); margin-bottom:12px;">
          <strong>⚠ AUTHORIZED TESTING ONLY:</strong> These payloads are for verification in controlled environments. Do not use against unauthorized targets.
        </p>
        ${data.payloads.map((p, idx) => `
          <div class="payload-category" style="margin-bottom:16px; border:1px solid var(--border-cyber); border-radius:4px; padding:12px;">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
              <span class="payload-type" style="font-weight:600; color:var(--neon-cyan);">${p.category}</span>
              <span class="severity-badge ${p.severity}" style="text-transform:uppercase; font-size:9px; padding:2px 8px; border-radius:3px; background:var(--bg-tertiary);">${p.severity}</span>
            </div>
            <p style="font-size:10px; color:var(--text-sub); margin-bottom:8px;">${p.description}</p>
            <div style="max-height:200px; overflow-y:auto; font-family:var(--font-mono); font-size:9px;">
              ${p.payloads.map((payload, pi) => `
                <div class="payload-item" style="margin-bottom:6px; padding:6px 8px; background:var(--bg-tertiary); border-radius:3px; position:relative;">
                  <div style="display:flex; justify-content:space-between; margin-bottom:4px;">
                    <span style="color:var(--text-muted);">Payload #${pi + 1}</span>
                    <button class="copy-payload-btn">COPY</button>
                  </div>
                  <code class="payload-text" style="color:var(--matrix-green); word-break:break-all; white-space:pre-wrap;">${payload.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')}</code>
                </div>
              `).join('')}
            </div>
            <div style="margin-top:8px; padding:6px 8px; background:rgba(255,165,0,0.1); border:1px solid var(--warn-orange); border-radius:3px; font-size:9px; color:var(--warn-orange);">
              <strong>TEST NOTES:</strong> ${p.testNotes}
            </div>
          </div>
        `).join('')}
      </div>
    `;

    container.innerHTML = html;

    // Add copy button handlers
    container.querySelectorAll('.payload-item').forEach(item => {
      const btn = item.querySelector('.copy-payload-btn');
      const code = item.querySelector('.payload-text');
      if (btn && code) {
        btn.addEventListener('click', () => {
          const payload = code.textContent;
          navigator.clipboard.writeText(payload).then(() => {
            const original = btn.textContent;
            btn.textContent = 'COPIED!';
            btn.style.background = 'var(--matrix-green)';
            setTimeout(() => {
              btn.textContent = original;
              btn.style.background = 'var(--neon-cyan)';
            }, 1500);
          });
        });
      }
    });
  }

  // 4h. Guide & OWASP reference (static — rendered once on load)
  // 5. Score Gauge Animation
  function updateScoreGauge(score) {
    scoreNum.textContent = score;
    scoreCircle.className = 'gauge-circle';
    scoreGrade.className = 'score-status';

    if (score >= 80) {
      scoreCircle.classList.add('high');
      scoreGrade.classList.add('high');
      scoreGrade.textContent = 'SECURE';
    } else if (score >= 50) {
      scoreCircle.classList.add('medium');
      scoreGrade.classList.add('medium');
      scoreGrade.textContent = 'MODERATE';
    } else {
      scoreCircle.classList.add('low');
      scoreGrade.classList.add('low');
      scoreGrade.textContent = 'CRITICAL';
    }
  }

  // 6. Terminal Console Helper
  function logTerminal(msg, type = 'info') {
    const time = new Date().toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
    const typeClass = type === 'success' ? 'log-success' : type === 'warn' ? 'log-warn' : type === 'err' ? 'log-err' : 'log-info';

    const line = document.createElement('div');
    line.className = 'log-line';
    line.innerHTML = `<span class="log-time">[${time}]</span> <span class="${typeClass}">${msg}</span>`;
    terminalConsole.appendChild(line);
    terminalConsole.scrollTop = terminalConsole.scrollHeight;
  }

  function clearTerminal() {
    terminalConsole.innerHTML = '';
  }

  // 7. Export Handlers (JSON, PDF, HTML & Markdown)
  exportJsonBtn.addEventListener('click', () => {
    if (!lastAuditResults) {
      logTerminal('No audit results available to export. Run a scan first.', 'warn');
      return;
    }
    const exportBundle = Object.assign({}, lastAuditResults, lastActiveResults ? { activeScan: lastActiveResults } : {});
    const blob = new Blob([JSON.stringify(exportBundle, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `vyasa-audit-${lastAuditResults.hostname || 'report'}.json`;
    a.click();
    URL.revokeObjectURL(url);
    logTerminal('JSON Audit Report exported successfully.', 'success');
  });

  exportMdBtn.addEventListener('click', () => {
    if (!lastAuditResults) {
      logTerminal('No audit results available to copy. Run a scan first.', 'warn');
      return;
    }

    const md = generateMarkdownReport(lastAuditResults);
    navigator.clipboard.writeText(md).then(() => {
      logTerminal('Markdown Bug Bounty Report copied to clipboard!', 'success');
    }).catch(err => {
      logTerminal(`Failed to copy report: ${err.message}`, 'err');
    });
  });

  const exportPdfBtn = document.getElementById('exportPdfBtn');
  if (exportPdfBtn) {
    exportPdfBtn.addEventListener('click', () => {
      if (!lastAuditResults) {
        logTerminal('No audit results available to export. Run a scan first.', 'warn');
        return;
      }
      exportPdfReport(lastAuditResults);
    });
  }

  function exportPdfReport(data) {
    const printWindow = window.open('', '_blank');
    if (!printWindow) {
      logTerminal('Print popup blocked. Please allow popups to export PDF.', 'err');
      return;
    }

    const html = generatePdfReportHtml(data);
    printWindow.document.write(html);
    printWindow.document.close();
    printWindow.focus();
    setTimeout(() => {
      printWindow.print();
    }, 600);
    logTerminal('PDF print dialog triggered. Choose "Save as PDF".', 'success');
  }

  function generatePdfReportHtml(data) {
    const scoreColor = data.score >= 80 ? '#10b981' : data.score >= 50 ? '#f59e0b' : '#ef4444';
    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>VYASA Executive Audit Report - ${data.hostname}</title>
  <style>
    @page { size: A4; margin: 15mm; }
    body { font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; background: #fff; color: #1e293b; margin: 0; padding: 20px; font-size: 13px; line-height: 1.5; }
    .header { display: flex; justify-content: space-between; align-items: center; border-bottom: 3px solid #0f172a; padding-bottom: 12px; margin-bottom: 20px; }
    .brand { font-size: 24px; font-weight: 800; color: #0f172a; letter-spacing: -0.5px; }
    .badge { background: #0f172a; color: #38bdf8; font-size: 11px; padding: 3px 8px; border-radius: 4px; font-weight: bold; margin-left: 8px; }
    .meta-box { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 15px; margin-bottom: 20px; display: flex; justify-content: space-between; align-items: center; }
    .score-badge { font-size: 36px; font-weight: 900; color: ${scoreColor}; }
    .section-title { font-size: 16px; font-weight: 700; color: #0f172a; border-bottom: 1px solid #cbd5e1; padding-bottom: 6px; margin-top: 25px; margin-bottom: 12px; }
    .vuln-card { border-left: 4px solid #ef4444; background: #fef2f2; padding: 10px 14px; margin-bottom: 10px; border-radius: 0 4px 4px 0; }
    .vuln-card.high { border-color: #ef4444; background: #fef2f2; }
    .vuln-card.medium { border-color: #f59e0b; background: #fffbe6; }
    .vuln-card.low { border-color: #3b82f6; background: #eff6ff; }
    .vuln-title { font-weight: bold; color: #0f172a; margin-bottom: 4px; }
    table { width: 100%; border-collapse: collapse; margin-top: 8px; font-size: 12px; }
    th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid #e2e8f0; }
    th { background: #f1f5f9; color: #475569; font-weight: 600; }
    code { font-family: monospace; background: #f1f5f9; padding: 2px 5px; border-radius: 3px; font-size: 11px; word-break: break-all; }
    .footer { margin-top: 40px; text-align: center; font-size: 11px; color: #94a3b8; border-top: 1px solid #e2e8f0; padding-top: 12px; }
    @media print {
      .no-print { display: none; }
      body { padding: 0; }
    }
  </style>
</head>
<body>
  <div class="no-print" style="margin-bottom: 15px; text-align: right;">
    <button onclick="window.print()" style="background:#0284c7; color:#fff; border:none; padding:8px 16px; font-weight:bold; border-radius:4px; cursor:pointer;">⎙ SAVE AS PDF</button>
  </div>
  <div class="header">
    <div class="brand">VYASA <span class="badge">SECURITY AUDIT REPORT</span></div>
    <div style="text-align:right; font-size:11px; color:#64748b;">
      Generated: ${new Date().toLocaleString()}<br>
      Engine: VYASA HUD v2.0
    </div>
  </div>

  <div class="meta-box">
    <div>
      <div style="font-size:12px; color:#64748b;">TARGET HOST ORIGIN</div>
      <div style="font-size:16px; font-weight:bold; color:#0f172a;">${data.url}</div>
      <div style="font-size:11px; color:#64748b; margin-top:4px;">IP Address: ${data.dns && data.dns.ips ? data.dns.ips.join(', ') : 'N/A'}</div>
    </div>
    <div style="text-align:center;">
      <div style="font-size:11px; color:#64748b;">SECURITY EVALUATION SCORE</div>
      <div class="score-badge">${data.score}<span style="font-size:18px;">/100</span></div>
    </div>
  </div>

  <div class="section-title">1. Identified Vulnerabilities & Risk Findings (${data.vulnerabilities ? data.vulnerabilities.length : 0})</div>
  ${data.vulnerabilities && data.vulnerabilities.length > 0 ? data.vulnerabilities.map(v => `
    <div class="vuln-card ${v.severity}">
      <div class="vuln-title">[${v.severity.toUpperCase()}] ${v.title}</div>
      <div>${v.detail}</div>
      <div style="margin-top:4px; font-size:11px; color:#475569;"><strong>Fix:</strong> ${v.mitigation}</div>
    </div>
  `).join('') : '<p>No critical security vulnerabilities detected during audit.</p>'}

  <div class="section-title">2. Exposed Client-Side Secrets & Credentials (${data.secrets ? data.secrets.length : 0})</div>
  ${data.secrets && data.secrets.length > 0 ? `
    <table>
      <thead><tr><th>Severity</th><th>Key Type</th><th>Snippet / Sample</th><th>Source</th></tr></thead>
      <tbody>
        ${data.secrets.map(s => `
          <tr>
            <td><strong style="color:${s.severity === 'critical' ? '#ef4444' : '#f59e0b'};">[${s.severity.toUpperCase()}]</strong></td>
            <td>${s.type}</td>
            <td><code>${s.snippet}</code></td>
            <td>${s.source}</td>
          </tr>
        `).join('')}
      </tbody>
    </table>
  ` : '<p>No hardcoded secrets or exposed tokens detected.</p>'}

  <div class="section-title">3. HTTP Security Response Headers</div>
  <table>
    <thead><tr><th>Header Requirement</th><th>Audit Status</th><th>Observed Header Value</th></tr></thead>
    <tbody>
      ${Object.entries(data.securityHeaders || {}).map(([k, v]) => `
        <tr>
          <td><strong>${k}</strong></td>
          <td style="color:${v.status === 'pass' ? '#10b981' : '#ef4444'}; font-weight:bold;">${v.status === 'pass' ? 'PASS' : 'FAIL'}</td>
          <td><code>${v.value || 'Missing / Not Set'}</code></td>
        </tr>
      `).join('')}
    </tbody>
  </table>

  <div class="section-title">4. Technology Stack & Component Fingerprinting</div>
  ${data.technologies && data.technologies.length > 0 ? `
    <div style="display:flex; flex-wrap:wrap; gap:8px;">
      ${data.technologies.map(t => `<span style="background:#f1f5f9; border:1px solid #cbd5e1; padding:4px 8px; border-radius:4px; font-size:11px;"><strong>${t.name}</strong> ${t.version ? `v${t.version}` : ''} (${t.type})</span>`).join('')}
    </div>
  ` : '<p>No known framework signatures identified.</p>'}

  <div class="footer">
    Confidential Security Audit Document • Prepared by VYASA (Vulnerability Yield & Attack Simulation Automation)
  </div>
</body>
</html>`;
  }

  const exportHtmlBtn = document.getElementById('exportHtmlBtn');
  if (exportHtmlBtn) {
    exportHtmlBtn.addEventListener('click', () => {
      if (!lastAuditResults) {
        logTerminal('No audit results available to export. Run a scan first.', 'warn');
        return;
      }
      const htmlContent = generateHtmlReport(lastAuditResults);
      const blob = new Blob([htmlContent], { type: 'text/html' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `vyasa-audit-${lastAuditResults.hostname || 'report'}.html`;
      a.click();
      URL.revokeObjectURL(url);
      logTerminal('Professional HTML Audit Report exported successfully.', 'success');
    });
  }

  function generateMarkdownReport(data) {
    const payloadsSection = data.payloads && data.payloads.length > 0
      ? `\n## 6. Vulnerability Test Payloads\n${data.payloads.map(p =>
        `### ${p.category} (${p.severity.toUpperCase()})\n${p.description}\n\n**Test Payloads:**\n${p.payloads.map((pl, i) => `${i + 1}. \`${pl}\``).join('\n')}\n\n**Test Notes:** ${p.testNotes}`
      ).join('\n\n')}`
      : '';

    return `# VYASA (Vulnerability Yield & Attack Simulation Automation) Audit Report
Target: \`${data.url}\`
Timestamp: \`${data.timestamp}\`
Final Security Score: **${data.score}/100**

## 1. Vulnerability Findings
${data.vulnerabilities.map(v => `- **[${v.severity.toUpperCase()}] ${v.title}**: ${v.detail}\n  *Mitigation*: ${v.mitigation}`).join('\n\n') || 'No critical threat findings.'}

## 2. Exposed Secrets & Leaks
${data.secrets.map(s => `- **${s.type}** (${s.severity}): \`${s.snippet}\` (Source: ${s.source})`).join('\n') || 'None.'}

## 3. Security Headers Overview
${Object.entries(data.securityHeaders).map(([k, v]) => `- **${k}**: ${v.status === 'pass' ? 'PASS' : 'FAIL'} (${v.value || 'Missing'})`).join('\n')}

## 4. Tech Stack Identification
${data.technologies.map(t => `- **${t.name}** (${t.type}) ${t.version ? `v${t.version}` : ''}`).join('\n') || 'None.'}

## 5. DNS & Email Security
- Server IP(s): ${data.dns.ips.join(', ') || 'N/A'}
- SPF Protection: ${data.dns.hasSpf ? 'PASS' : 'FAIL'}
- DMARC Protection: ${data.dns.hasDmarc ? 'PASS' : 'FAIL'}${payloadsSection}

---
*Report generated by VYASA Cyber Terminal HUD v2.0*`;
  }

  function generateHtmlReport(data) {
    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>VYASA Audit Report - ${data.hostname}</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 40px; background: #0f172a; color: #e2e8f0; }
    h1 { color: #38bdf8; border-bottom: 2px solid #334155; padding-bottom: 10px; }
    .score { font-size: 32px; font-weight: bold; color: ${data.score >= 80 ? '#22c55e' : data.score >= 50 ? '#eab308' : '#ef4444'}; }
    .card { background: #1e293b; padding: 20px; border-radius: 8px; margin-bottom: 20px; border: 1px solid #334155; }
    table { width: 100%; border-collapse: collapse; margin-top: 10px; }
    th, td { text-align: left; padding: 10px; border-bottom: 1px solid #334155; }
    th { background: #0f172a; color: #94a3b8; }
    .pass { color: #22c55e; } .fail { color: #ef4444; }
    code { background: #0f172a; padding: 2px 6px; border-radius: 4px; font-family: monospace; }
  </style>
</head>
<body>
  <h1>VYASA Vulnerability & Security Audit Report</h1>
  <div class="card">
    <p><strong>Target URL:</strong> ${data.url}</p>
    <p><strong>Timestamp:</strong> ${data.timestamp}</p>
    <p><strong>Security Score:</strong> <span class="score">${data.score}/100</span></p>
  </div>
  <div class="card">
    <h2>Vulnerabilities Identified (${data.vulnerabilities ? data.vulnerabilities.length : 0})</h2>
    ${data.vulnerabilities ? data.vulnerabilities.map(v => `
      <div style="margin-bottom:15px; border-left:4px solid #ef4444; padding-left:10px;">
        <h3 style="margin:0; color:#f87171;">[${v.severity.toUpperCase()}] ${v.title}</h3>
        <p>${v.detail}</p>
        <p><strong>Mitigation:</strong> ${v.mitigation}</p>
      </div>
    `).join('') : '<p>No vulnerabilities found.</p>'}
  </div>
  <div class="card">
    <h2>Security Headers</h2>
    <table>
      <tr><th>Header</th><th>Status</th><th>Value</th></tr>
      ${Object.entries(data.securityHeaders || {}).map(([k, v]) => `
        <tr>
          <td>${k}</td>
          <td class="${v.status}">${v.status.toUpperCase()}</td>
          <td><code>${v.value || 'Missing'}</code></td>
        </tr>
      `).join('')}
    </table>
  </div>
</body>
</html>`;
  }
});