// Hunt Kit — offensive security utilities

const securityHeaderChecks = [
  { name: 'Strict-Transport-Security', severity: 'high', hint: 'Enforces HTTPS', remediation: 'Add Strict-Transport-Security: max-age=31536000; includeSubDomains' },
  { name: 'Content-Security-Policy', severity: 'high', hint: 'Mitigates XSS', remediation: 'Add a robust Content-Security-Policy header restricting script-src to trusted domains.' },
  { name: 'X-Frame-Options', severity: 'medium', hint: 'Clickjacking protection', remediation: 'Add X-Frame-Options: DENY or SAMEORIGIN (or use CSP frame-ancestors).' },
  { name: 'X-Content-Type-Options', severity: 'medium', hint: 'Should be nosniff', remediation: 'Add X-Content-Type-Options: nosniff to prevent MIME-sniffing.' },
  { name: 'Referrer-Policy', severity: 'low', hint: 'Controls referrer leakage', remediation: 'Add Referrer-Policy: strict-origin-when-cross-origin' },
  { name: 'Permissions-Policy', severity: 'low', hint: 'Feature policy', remediation: 'Add Permissions-Policy to restrict browser features like camera, microphone, geolocation.' },
];

const googleDorkTemplates = [
  // ── Exposed Files & Credentials ──────────────────────────────
  { label: 'Exposed .env files',      cat: 'Credentials', q: 'site:{{domain}} ext:env | ext:env.example | ext:env.backup' },
  { label: 'Exposed SSH Keys',        cat: 'Credentials', q: 'site:{{domain}} ext:pem | ext:ppk | ext:key | intitle:"index of" id_rsa' },
  { label: 'Backup / Archive files',  cat: 'Credentials', q: 'site:{{domain}} ext:bak | ext:sql | ext:zip | ext:tar.gz | ext:swp | ext:old' },
  { label: 'Log files',              cat: 'Credentials', q: 'site:{{domain}} ext:log | inurl:log | intitle:"index of" "access.log"' },
  { label: 'Config files',           cat: 'Credentials', q: 'site:{{domain}} ext:json | ext:yaml | ext:yml | ext:xml | ext:conf | ext:ini' },
  { label: 'Exposed Git / SVN',      cat: 'Credentials', q: 'site:{{domain}} inurl:.git | inurl:.svn | inurl:.hg' },
  { label: 'Database dumps',         cat: 'Credentials', q: 'site:{{domain}} ext:sql | ext:db | ext:sqlite | ext:dbf | ext:mdb' },
  { label: 'WordPress config',       cat: 'Credentials', q: 'site:{{domain}} inurl:wp-config | intitle:"Index of" wp-content' },
  { label: 'PHP source files',       cat: 'Credentials', q: 'site:{{domain}} ext:php inurl:config | ext:php inurl:db | ext:php inurl:pass' },

  // ── Endpoints & APIs ──────────────────────────────────────────
  { label: 'Swagger / OpenAPI docs', cat: 'APIs',        q: 'site:{{domain}} inurl:swagger | inurl:api-docs | inurl:graphql | inurl:graphiql' },
  { label: 'API v1 / v2 / v3',       cat: 'APIs',        q: 'site:{{domain}} inurl:api/v1 | inurl:api/v2 | inurl:api/v3' },
  { label: 'WSDL / WADL',           cat: 'APIs',        q: 'site:{{domain}} ext:wsdl | ext:wadl | inurl:?wsdl' },
  { label: 'REST endpoints',         cat: 'APIs',        q: 'site:{{domain}} inurl:/rest/ | inurl:/api/ | inurl:/service/' },
  { label: 'GraphQL',               cat: 'APIs',        q: 'site:{{domain}} inurl:graphql | inurl:graphiql | inurl:/graph' },
  { label: 'Webhook endpoints',      cat: 'APIs',        q: 'site:{{domain}} inurl:webhook | inurl:webhooks | inurl:callback' },

  // ── Admin & Login ─────────────────────────────────────────────
  { label: 'Admin panels',           cat: 'Admin',       q: 'site:{{domain}} inurl:admin | inurl:cpanel | inurl:dashboard | intitle:"admin login"' },
  { label: 'Login / Auth pages',     cat: 'Admin',       q: 'site:{{domain}} inurl:login | inurl:signin | inurl:register | inurl:signup | inurl:auth' },
  { label: 'Internal portals',       cat: 'Admin',       q: 'site:{{domain}} inurl:intranet | inurl:portal | inurl:corp | inurl:internal' },
  { label: 'phpMyAdmin',            cat: 'Admin',       q: 'site:{{domain}} inurl:phpmyadmin | intitle:"phpMyAdmin"' },

  // ── Errors & Debug ────────────────────────────────────────────
  { label: 'SQL error messages',     cat: 'Errors',      q: 'site:{{domain}} intext:"sql syntax near" | intext:"Warning: mysql_connect()" | intext:"Warning: pg_connect()"' },
  { label: 'PHP errors / info',      cat: 'Errors',      q: 'site:{{domain}} ext:php intitle:phpinfo | intext:"Fatal error:" | intext:"Warning: session_start()"' },
  { label: 'Stack traces',           cat: 'Errors',      q: 'site:{{domain}} intext:"stack trace" | intext:"exception" | intext:"Traceback (most recent call"' },
  { label: 'Debug / trace files',    cat: 'Errors',      q: 'site:{{domain}} ext:txt | ext:log intext:"debug" | intext:"traceback"' },

  // ── Sensitive Documents ───────────────────────────────────────
  { label: 'Confidential PDFs',      cat: 'Documents',   q: 'site:{{domain}} ext:pdf intext:"confidential" | intext:"do not distribute" | intext:"internal use only"' },
  { label: 'Excel / CSV files',      cat: 'Documents',   q: 'site:{{domain}} ext:xls | ext:xlsx | ext:csv | ext:ods' },
  { label: 'Word documents',         cat: 'Documents',   q: 'site:{{domain}} ext:doc | ext:docx | ext:odt' },
  { label: 'Presentation files',     cat: 'Documents',   q: 'site:{{domain}} ext:ppt | ext:pptx' },

  // ── Cloud & Infrastructure ────────────────────────────────────
  { label: 'S3 Buckets',            cat: 'Cloud',       q: 'site:s3.amazonaws.com {{domain}}' },
  { label: 'Azure Blob storage',     cat: 'Cloud',       q: 'site:blob.core.windows.net "{{domain}}"' },
  { label: 'GCS buckets',           cat: 'Cloud',       q: 'site:storage.googleapis.com "{{domain}}"' },
  { label: 'Jenkins / CI/CD',        cat: 'Cloud',       q: 'site:{{domain}} intitle:"Dashboard [Jenkins]" | inurl:jenkins | inurl:gitlab' },
  { label: 'Kibana / Elasticsearch', cat: 'Cloud',       q: 'site:{{domain}} inurl:_plugin/kibana | inurl:_dashboards | intitle:"Kibana"' },
  { label: 'Jira / Confluence',      cat: 'Cloud',       q: 'site:{{domain}} inurl:jira | inurl:confluence | intitle:"Jira -"' },

  // ── Vulnerability-Specific ────────────────────────────────────
  { label: 'Open redirects',        cat: 'Vulns',       q: 'site:{{domain}} inurl:redir | inurl:redirect | inurl:return | inurl:next= | inurl:url=' },
  { label: 'LFI / Path traversal',  cat: 'Vulns',       q: 'site:{{domain}} inurl:include= | inurl:page= | inurl:file= | inurl:load=' },
  { label: 'SSRF params',           cat: 'Vulns',       q: 'site:{{domain}} inurl:url= | inurl:dest= | inurl:path= | inurl:uri= | inurl:window=' },
  { label: 'IDOR patterns',         cat: 'Vulns',       q: 'site:{{domain}} inurl:/user/ | inurl:/account/ | inurl:/profile/ | inurl:/id=' },
  { label: 'File upload endpoints', cat: 'Vulns',       q: 'site:{{domain}} inurl:upload | inurl:file_upload | intitle:"Upload"' },

  // ── GitHub Code Dorks ─────────────────────────────────────────
  { label: 'GH: Hardcoded passwords', cat: 'GitHub',  q: 'org:{{domain}} password OR secret OR api_key language:JavaScript' },
  { label: 'GH: .env files',          cat: 'GitHub',  q: 'org:{{domain}} filename:.env' },
  { label: 'GH: AWS credentials',     cat: 'GitHub',  q: 'org:{{domain}} AKIA OR aws_access_key_id' },
  { label: 'GH: Private keys',        cat: 'GitHub',  q: 'org:{{domain}} "BEGIN RSA PRIVATE KEY" OR "BEGIN EC PRIVATE KEY"' },
  { label: 'GH: DB connection strings',cat: 'GitHub', q: 'org:{{domain}} "mongodb://" OR "mysql://" OR "postgres://"' },
  { label: 'GH: JWT secrets',         cat: 'GitHub',  q: 'org:{{domain}} jwt_secret OR JWT_SECRET' },
  { label: 'GH: Slack tokens',        cat: 'GitHub',  q: 'org:{{domain}} xoxb- OR xoxa- OR xoxp-' },
];

const shodanTemplates = [
  // ── General ───────────────────────────────────────────────────
  { label: 'SSL cert match',         cat: 'General',    q: 'ssl:"{{domain}}" 200' },
  { label: 'HTTP title contains',    cat: 'General',    q: 'http.title:"{{domain}}"' },
  { label: 'HTML body contains',     cat: 'General',    q: 'http.html:"{{domain}}"' },
  { label: 'Favicon hash',          cat: 'General',    q: 'http.favicon.hash:"-REPLACE-"' },
  { label: 'Organization (ASN)',     cat: 'General',    q: 'org:"{{domain}}"' },
  { label: 'Hostname',              cat: 'General',    q: 'hostname:"{{domain}}"' },

  // ── Cloud & Hosting ───────────────────────────────────────────
  { label: 'AWS-hosted assets',      cat: 'Cloud',      q: 'ssl:"{{domain}}" org:"Amazon.com"' },
  { label: 'Azure-hosted assets',    cat: 'Cloud',      q: 'ssl:"{{domain}}" org:"Microsoft"' },
  { label: 'GCP-hosted assets',      cat: 'Cloud',      q: 'ssl:"{{domain}}" org:"Google"' },
  { label: 'Cloudflare bypass',      cat: 'Cloud',      q: 'ssl:"{{domain}}" -org:"Cloudflare"' },
  { label: 'Fastly bypass',          cat: 'Cloud',      q: 'ssl:"{{domain}}" -org:"Fastly"' },

  // ── Open Ports ────────────────────────────────────────────────
  { label: 'Open RDP (3389)',        cat: 'Ports',      q: 'ssl:"{{domain}}" port:3389' },
  { label: 'Open SSH (22)',          cat: 'Ports',      q: 'ssl:"{{domain}}" port:22' },
  { label: 'Open Telnet (23)',       cat: 'Ports',      q: 'ssl:"{{domain}}" port:23' },
  { label: 'Open FTP (21)',          cat: 'Ports',      q: 'ssl:"{{domain}}" port:21 "230 Login successful"' },
  { label: 'Open SMTP (25)',         cat: 'Ports',      q: 'ssl:"{{domain}}" port:25' },
  { label: 'Open MQTT (1883)',       cat: 'Ports',      q: 'ssl:"{{domain}}" port:1883' },

  // ── Databases ─────────────────────────────────────────────────
  { label: 'MongoDB',               cat: 'Databases',  q: 'ssl:"{{domain}}" product:MongoDB' },
  { label: 'Elasticsearch (9200)',   cat: 'Databases',  q: 'ssl:"{{domain}}" port:9200 product:elastic' },
  { label: 'MySQL',                  cat: 'Databases',  q: 'ssl:"{{domain}}" product:MySQL' },
  { label: 'PostgreSQL',             cat: 'Databases',  q: 'ssl:"{{domain}}" product:PostgreSQL' },
  { label: 'Redis (6379)',           cat: 'Databases',  q: 'ssl:"{{domain}}" product:Redis port:6379' },
  { label: 'CouchDB (5984)',         cat: 'Databases',  q: 'ssl:"{{domain}}" port:5984' },
  { label: 'Cassandra (9042)',       cat: 'Databases',  q: 'ssl:"{{domain}}" port:9042' },

  // ── DevOps & Tooling ──────────────────────────────────────────
  { label: 'Jenkins',               cat: 'DevOps',     q: 'ssl:"{{domain}}" "Dashboard [Jenkins]"' },
  { label: 'GitLab',                cat: 'DevOps',     q: 'ssl:"{{domain}}" http.title:"GitLab"' },
  { label: 'Jira',                  cat: 'DevOps',     q: 'ssl:"{{domain}}" http.title:"Jira"' },
  { label: 'Grafana',               cat: 'DevOps',     q: 'ssl:"{{domain}}" http.title:"Grafana"' },
  { label: 'Kubernetes API',         cat: 'DevOps',     q: 'ssl:"{{domain}}" "Kubernetes-master"' },
  { label: 'Docker API',            cat: 'DevOps',     q: 'ssl:"{{domain}}" "Docker Containers"' },
  { label: 'Consul (8500)',          cat: 'DevOps',     q: 'ssl:"{{domain}}" port:8500' },
  { label: 'Prometheus (9090)',      cat: 'DevOps',     q: 'ssl:"{{domain}}" port:9090 http.title:"Prometheus"' },

  // ── Web Frameworks ────────────────────────────────────────────
  { label: 'Tomcat / JBoss',        cat: 'Frameworks',  q: 'ssl:"{{domain}}" product:"Apache Tomcat"' },
  { label: 'Spring Boot',           cat: 'Frameworks',  q: 'ssl:"{{domain}}" http.favicon.hash:116323821' },
  { label: 'Nginx',                 cat: 'Frameworks',  q: 'ssl:"{{domain}}" product:nginx' },
  { label: 'IIS',                   cat: 'Frameworks',  q: 'ssl:"{{domain}}" product:"Microsoft IIS"' },

  // ── Vulnerability Intel ───────────────────────────────────────
  { label: 'Log4Shell targets',      cat: 'Vulns',      q: 'ssl:"{{domain}}" (product:"Apache Solr" OR product:"VMware vCenter")' },
  { label: 'Exchange / OWA',        cat: 'Vulns',      q: 'ssl:"{{domain}}" http.title:"Outlook Web App"' },
  { label: 'Confluence',            cat: 'Vulns',      q: 'ssl:"{{domain}}" http.component:"Atlassian Confluence"' },
  { label: 'Citrix Netscaler',       cat: 'Vulns',      q: 'ssl:"{{domain}}" "Citrix Systems" | product:NetScaler' },
];

/* ═══════════════════════════════════════════════
   DORK BUILDER — state
═══════════════════════════════════════════════ */
let _dorkCatFilter = 'All';
let _shodanCatFilter = 'All';

function renderDorkTemplates() {
  const el = document.getElementById('dork-templates');
  if (!el) return;
  const q = (document.getElementById('dork-search')?.value || '').toLowerCase();
  const catFilter = _dorkCatFilter;
  const domain = document.getElementById('dork-domain')?.value.trim() || '{{domain}}';

  // Build category pill list once
  const pillEl = document.getElementById('dork-cat-pills');
  if (pillEl && !pillEl.dataset.ready) {
    const cats = ['All', ...new Set(googleDorkTemplates.map(t => t.cat))];
    pillEl.innerHTML = cats.map(c =>
      `<button class="gh-cat-btn ${c === 'All' ? 'active' : ''}" onclick="setDorkCat('${c}')" data-cat="${c}">${c}</button>`
    ).join('');
    pillEl.dataset.ready = '1';
  }

  let list = googleDorkTemplates;
  if (catFilter && catFilter !== 'All') list = list.filter(t => t.cat === catFilter);
  if (q) list = list.filter(t => t.label.toLowerCase().includes(q) || t.q.toLowerCase().includes(q) || t.cat.toLowerCase().includes(q));

  if (!list.length) {
    el.innerHTML = '<div style="color:var(--text3);font-size:12px;padding:10px 0">No templates match your search.</div>';
    return;
  }

  // Group by category
  const grouped = {};
  list.forEach(t => { if (!grouped[t.cat]) grouped[t.cat] = []; grouped[t.cat].push(t); });

  el.innerHTML = Object.entries(grouped).map(([cat, items]) => `
    <div style="margin-bottom:8px;">
      <div style="font-size:10px;font-weight:700;color:var(--text3);text-transform:uppercase;letter-spacing:1px;margin-bottom:4px;padding-left:2px;">${cat}</div>
      <div style="display:flex;flex-wrap:wrap;gap:5px;">
        ${items.map(t => {
          const full = t.q.replace(/\{\{domain\}\}/g, domain || 'target.com');
          return `<button class="btn btn-sm dork-pill" title="${full}" onclick="applyDork('${t.q.replace(/'/g,"\\'")}');dorkLivePreview();">${t.label}</button>`;
        }).join('')}
      </div>
    </div>`).join('');
}

function setDorkCat(cat) {
  _dorkCatFilter = cat;
  document.querySelectorAll('#dork-cat-pills .gh-cat-btn').forEach(b => b.classList.toggle('active', b.dataset.cat === cat));
  renderDorkTemplates();
}

function applyDork(rawQ) {
  const domain = document.getElementById('dork-domain')?.value.trim() || 'target.com';
  document.getElementById('dork-output').value = rawQ.replace(/\{\{domain\}\}/g, domain);
  dorkLiveLabel();
}

function dorkLivePreview() {
  // Re-render template buttons with new domain substituted in tooltips
  renderDorkTemplates();
  // If there's already a value in dork-output that contains {{domain}}, update it
  const out = document.getElementById('dork-output');
  const domain = document.getElementById('dork-domain')?.value.trim() || 'target.com';
  if (out && out.value.includes('{{domain}}')) {
    out.value = out.value.replace(/\{\{domain\}\}/g, domain);
  }
  dorkLiveLabel();
  // Sync open-button label with selected engine
  const eng = document.getElementById('dork-engine')?.value || 'google';
  const labels = { google: '🔍 Search Google', bing: '🔎 Search Bing', duckduckgo: '🦆 Search DDG', github: '🐙 Search GitHub Code' };
  const btn = document.getElementById('dork-open-btn');
  if (btn) btn.textContent = labels[eng] || '🔍 Search';
}

function dorkLiveLabel() {
  const out = document.getElementById('dork-output')?.value || '';
  const label = document.getElementById('dork-live-label');
  if (label) label.textContent = out ? `${out.length} chars` : '';
}

function copyDork() {
  const v = document.getElementById('dork-output').value;
  if (!v) { toast('Generate a dork first', 'error'); return; }
  window.copyTextToClipboard(v).then(() => toast('Dork copied!', 'success'));
}

function copyAllDorks() {
  const domain = document.getElementById('dork-domain')?.value.trim() || 'target.com';
  const all = googleDorkTemplates.map(t =>
    `# ${t.cat}: ${t.label}\n` + t.q.replace(/\{\{domain\}\}/g, domain)
  ).join('\n\n');
  window.copyTextToClipboard(all).then(() => toast(`All ${googleDorkTemplates.length} dorks copied!`, 'success'));
}

function openDorkEngine() {
  const q = document.getElementById('dork-output').value.trim();
  if (!q) { toast('Generate or write a dork first', 'error'); return; }
  const engine = document.getElementById('dork-engine')?.value || 'google';
  const urls = {
    google:    'https://www.google.com/search?q=' + encodeURIComponent(q),
    bing:      'https://www.bing.com/search?q=' + encodeURIComponent(q),
    duckduckgo:'https://duckduckgo.com/?q=' + encodeURIComponent(q),
    github:    'https://github.com/search?q=' + encodeURIComponent(q) + '&type=code'
  };
  window.open(urls[engine] || urls.google, '_blank', 'noopener');
}

// Keep legacy function name working
function openDorkGoogle() { openDorkEngine(); }

/* ═══════════════════════════════════════════════
   SHODAN BUILDER — state & render
═══════════════════════════════════════════════ */
function renderShodanTemplates() {
  const el = document.getElementById('shodan-templates');
  if (!el) return;
  const q = (document.getElementById('shodan-search')?.value || '').toLowerCase();
  const catFilter = _shodanCatFilter;
  const domain = document.getElementById('shodan-domain')?.value.trim() || '{{domain}}';

  // Category pills
  const pillEl = document.getElementById('shodan-cat-pills');
  if (pillEl && !pillEl.dataset.ready) {
    const cats = ['All', ...new Set(shodanTemplates.map(t => t.cat))];
    pillEl.innerHTML = cats.map(c =>
      `<button class="gh-cat-btn ${c === 'All' ? 'active' : ''}" onclick="setShodanCat('${c}')" data-cat="${c}">${c}</button>`
    ).join('');
    pillEl.dataset.ready = '1';
  }

  let list = shodanTemplates;
  if (catFilter && catFilter !== 'All') list = list.filter(t => t.cat === catFilter);
  if (q) list = list.filter(t => t.label.toLowerCase().includes(q) || t.q.toLowerCase().includes(q));

  if (!list.length) {
    el.innerHTML = '<div style="color:var(--text3);font-size:12px;padding:10px 0">No templates match.</div>';
    return;
  }

  const grouped = {};
  list.forEach(t => { if (!grouped[t.cat]) grouped[t.cat] = []; grouped[t.cat].push(t); });

  el.innerHTML = Object.entries(grouped).map(([cat, items]) => `
    <div style="margin-bottom:8px;">
      <div style="font-size:10px;font-weight:700;color:var(--text3);text-transform:uppercase;letter-spacing:1px;margin-bottom:4px;padding-left:2px;">${cat}</div>
      <div style="display:flex;flex-wrap:wrap;gap:5px;">
        ${items.map(t => {
          const full = t.q.replace(/\{\{domain\}\}/g, domain || 'target.com');
          return `<button class="btn btn-sm dork-pill" title="${full}" onclick="applyShodan('${t.q.replace(/'/g,"\\'")}');shodanLivePreview();">${t.label}</button>`;
        }).join('')}
      </div>
    </div>`).join('');
}

function setShodanCat(cat) {
  _shodanCatFilter = cat;
  document.querySelectorAll('#shodan-cat-pills .gh-cat-btn').forEach(b => b.classList.toggle('active', b.dataset.cat === cat));
  renderShodanTemplates();
}

function applyShodan(rawQ) {
  const domain = document.getElementById('shodan-domain')?.value.trim() || 'target.com';
  document.getElementById('shodan-output').value = rawQ
    .replace(/\{\{domain\}\}/g, domain)
    .replace(/\{\{target\}\}/g, domain);
}

function shodanLivePreview() {
  renderShodanTemplates();
  const out = document.getElementById('shodan-output');
  const domain = document.getElementById('shodan-domain')?.value.trim() || 'target.com';
  if (out && out.value.includes('{{domain}}')) {
    out.value = out.value.replace(/\{\{domain\}\}/g, domain).replace(/\{\{target\}\}/g, domain);
  }
}

function openShodan() {
  const q = document.getElementById('shodan-output').value.trim();
  if (!q) { toast('Build a Shodan query first', 'error'); return; }
  window.open('https://www.shodan.io/search?query=' + encodeURIComponent(q), '_blank', 'noopener');
}

function openCensys() {
  const q = document.getElementById('shodan-output').value.trim();
  if (!q) { toast('Build a query first', 'error'); return; }
  window.open('https://search.censys.io/search?resource=hosts&q=' + encodeURIComponent(q), '_blank', 'noopener');
}

// Keep legacy compatibility
function applyDorkTemplate(i) { applyDork(googleDorkTemplates[i].q); dorkLivePreview(); }
function applyShodanTemplate(i) { applyShodan(shodanTemplates[i].q); }



const cveQuickRef = [
  { id: 'CVE-2021-44228', name: 'Log4Shell', sev: 'critical' },
  { id: 'CVE-2021-34527', name: 'PrintNightmare', sev: 'critical' },
  { id: 'CVE-2022-22965', name: 'Spring4Shell', sev: 'critical' },
  { id: 'CVE-2023-44487', name: 'HTTP/2 Rapid Reset', sev: 'high' },
  { id: 'CVE-2023-4966', name: 'Citrix Bleed', sev: 'critical' },
  { id: 'CVE-2024-3400', name: 'PAN-OS Command Injection', sev: 'critical' }
];

function showHuntPanel(id) {
  document.querySelectorAll('.hunt-panel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.tool-tile').forEach(t => t.classList.remove('active'));
  const panel = document.getElementById('hunt-' + id);
  if (panel) panel.classList.add('active');
  const tile = document.querySelector('.tool-tile[data-hunt="' + id + '"]');
  if (tile) tile.classList.add('active');
  if (id === 'oob' && typeof renderOobPage === 'function') renderOobPage();
}

function renderHuntKitPage() {
  renderDorkTemplates();
  renderShodanTemplates();
  // Wire engine select → update button label
  const engSel = document.getElementById('dork-engine');
  if (engSel && !engSel.dataset.wired) {
    engSel.addEventListener('change', dorkLivePreview);
    engSel.dataset.wired = '1';
  }
  const cveEl = document.getElementById('cve-list');
  if (cveEl && !cveEl.dataset.ready) {
    cveEl.innerHTML = cveQuickRef.map(c =>
      `<div class="bookmark-item" onclick="window.copyTextToClipboard('${c.id}').then(()=>toast('Copied ${c.id}'))">
        <span class="chip chip-${c.sev === 'critical' ? 'red' : 'orange'}">${c.sev}</span>
        <strong>${c.id}</strong> — ${c.name}
      </div>`
    ).join('');
    cveEl.dataset.ready = '1';
  }
}

function applyDorkTemplate(i) {
  const domain = document.getElementById('dork-domain').value.trim() || 'target.com';
  document.getElementById('dork-output').value = googleDorkTemplates[i].q.replace(/\{\{domain\}\}/g, domain);
}

function applyShodanTemplate(i) {
  const domain = document.getElementById('shodan-domain').value.trim() || 'target.com';
  document.getElementById('shodan-output').value = shodanTemplates[i].q
    .replace(/\{\{domain\}\}/g, domain).replace(/\{\{target\}\}/g, domain);
}

function copyDork() {
  const v = document.getElementById('dork-output').value;
  window.copyTextToClipboard(v).then(() => toast('Dork copied', 'success'));
}

function openDorkGoogle() {
  const q = encodeURIComponent(document.getElementById('dork-output').value);
  window.open('https://www.google.com/search?q=' + q, '_blank');
}

function analyzeSecurityHeaders() {
  const raw = document.getElementById('sec-headers-input').value.trim();
  const out = document.getElementById('sec-headers-result');
  if (!raw) {
    out.innerHTML = '<div style="color:var(--text3);font-size:12px;">Paste HTTP response headers above to analyze them.</div>';
    return;
  }

  const lines = raw.split(/\r?\n/).filter(Boolean);
  const found = {};
  const cookies = [];
  
  lines.forEach(line => {
    // Skip HTTP/1.1 200 OK lines
    if (line.toUpperCase().startsWith('HTTP/')) return;
    const idx = line.indexOf(':');
    if (idx > 0) {
      const key = line.slice(0, idx).trim().toLowerCase();
      const val = line.slice(idx + 1).trim();
      if (key === 'set-cookie') {
        cookies.push(val);
      } else {
        found[key] = val; // Store last value for dupes
      }
    }
  });

  let html = '<div style="display:flex;flex-direction:column;gap:12px;">';
  let findingsCount = 0;
  
  // 1. Standard Header Checks
  let headersHtml = '<div style="border:1px solid var(--border);border-radius:var(--r);background:var(--bg);overflow:hidden;">';
  securityHeaderChecks.forEach((check, i) => {
    const key = check.name.toLowerCase();
    const present = Object.keys(found).some(k => k === key || k.replace(/-/g, '') === key.replace(/-/g, ''));
    
    if (present) {
      const val = found[Object.keys(found).find(k => k.includes(check.name.split('-')[0].toLowerCase()))];
      headersHtml += `<div style="padding:10px 12px;border-bottom:${i<securityHeaderChecks.length-1?'1px solid var(--border)':'none'};display:flex;justify-content:space-between;align-items:center;">
        <div><div style="font-weight:600;font-size:13px;color:var(--text);">${check.name}</div><div style="font-size:11px;color:var(--text3);font-family:var(--mono);">${esc(val.substring(0,60))}${val.length>60?'...':''}</div></div>
        <div class="result-ok" style="font-size:12px;display:flex;align-items:center;gap:4px;"><span style="font-size:14px;">✓</span> Present</div>
      </div>`;
    } else {
      findingsCount++;
      const badgeColor = check.severity === 'high' ? 'var(--red)' : (check.severity === 'medium' ? 'var(--orange)' : 'var(--accent)');
      headersHtml += `<div style="padding:10px 12px;border-bottom:${i<securityHeaderChecks.length-1?'1px solid var(--border)':'none'};display:flex;flex-direction:column;gap:6px;background:rgba(255,255,255,0.02);">
        <div style="display:flex;justify-content:space-between;align-items:center;">
          <div><div style="font-weight:600;font-size:13px;color:var(--text);">${check.name}</div><div style="font-size:11px;color:var(--text3);">${check.hint}</div></div>
          <div style="font-size:11px;padding:2px 6px;border-radius:4px;background:${badgeColor}22;color:${badgeColor};font-weight:600;border:1px solid ${badgeColor}44;">Missing</div>
        </div>
        <div style="font-size:11.5px;font-family:var(--mono);color:var(--text2);background:var(--bg2);padding:6px;border-radius:4px;border:1px dashed var(--border);display:flex;justify-content:space-between;align-items:center;">
          <span>${esc(check.remediation)}</span>
          <button class="btn btn-sm" style="padding:2px 6px;font-size:10px;" onclick="window.copyTextToClipboard('${check.remediation.replace(/'/g,"\\'")}').then(()=>toast('Copied remediation'))">Copy</button>
        </div>
      </div>`;
    }
  });
  headersHtml += '</div>';
  html += headersHtml;

  // 2. Info Leaks
  const leaks = [];
  if (found['server']) leaks.push(`Server header discloses version: <strong>${esc(found['server'])}</strong>`);
  if (found['x-powered-by']) leaks.push(`X-Powered-By discloses technology: <strong>${esc(found['x-powered-by'])}</strong>`);
  if (found['x-aspnet-version']) leaks.push(`ASP.NET version disclosed: <strong>${esc(found['x-aspnet-version'])}</strong>`);
  
  if (leaks.length > 0) {
    findingsCount += leaks.length;
    html += `<div style="border:1px solid var(--border);border-left:3px solid var(--orange);border-radius:var(--r);background:var(--bg);padding:10px 12px;">
      <div style="font-size:11px;font-weight:700;color:var(--text3);text-transform:uppercase;margin-bottom:6px;">Information Disclosure</div>
      <ul style="margin:0;padding-left:16px;font-size:12.5px;color:var(--text2);line-height:1.6;">
        ${leaks.map(l => `<li>${l}</li>`).join('')}
      </ul>
    </div>`;
  }

  // 3. Cookie Flags
  if (cookies.length > 0) {
    let cookieHtml = `<div style="border:1px solid var(--border);border-radius:var(--r);background:var(--bg);padding:10px 12px;">
      <div style="font-size:11px;font-weight:700;color:var(--text3);text-transform:uppercase;margin-bottom:8px;">Cookie Security</div>
      <div style="display:flex;flex-direction:column;gap:8px;">`;
      
    cookies.forEach(c => {
      const parts = c.split(';').map(p => p.trim());
      const nameVal = parts[0];
      const isHttpOnly = c.toLowerCase().includes('httponly');
      const isSecure = c.toLowerCase().includes('secure');
      const hasSameSite = c.toLowerCase().includes('samesite=');
      
      let issues = [];
      if (!isHttpOnly) issues.push('Missing HttpOnly');
      if (!isSecure) issues.push('Missing Secure');
      if (!hasSameSite) issues.push('Missing SameSite');
      
      if (issues.length > 0) findingsCount++;

      cookieHtml += `<div style="font-size:12px;padding:6px;background:var(--bg2);border-radius:4px;border:1px solid var(--border);">
        <div style="font-family:var(--mono);color:var(--text);margin-bottom:4px;word-break:break-all;">${esc(nameVal)}</div>
        <div style="display:flex;gap:6px;flex-wrap:wrap;">
          <span class="${isHttpOnly ? 'result-ok' : 'result-bad'}" style="font-size:11px;">HttpOnly: ${isHttpOnly?'Yes':'No'}</span>
          <span class="${isSecure ? 'result-ok' : 'result-bad'}" style="font-size:11px;">Secure: ${isSecure?'Yes':'No'}</span>
          <span class="${hasSameSite ? 'result-ok' : 'result-warn'}" style="font-size:11px;">SameSite: ${hasSameSite?'Yes':'No'}</span>
        </div>
      </div>`;
    });
    cookieHtml += `</div></div>`;
    html += cookieHtml;
  }

  html += `</div>`;
  
  if (findingsCount === 0) {
    out.innerHTML = `<div style="padding:16px;text-align:center;color:var(--green);background:rgba(34,211,166,0.1);border:1px solid var(--green);border-radius:var(--r);">✅ No security header issues found!</div>` + html;
  } else {
    out.innerHTML = html;
  }
}

async function sendHttpRequest() {
  const url = document.getElementById('http-url').value.trim();
  const method = document.getElementById('http-method').value;
  const headersRaw = document.getElementById('http-headers').value.trim();
  const body = document.getElementById('http-body').value;
  const out = document.getElementById('http-response');
  if (!url) { toast('Enter a URL'); return; }
  out.textContent = 'Sending...';
  const headers = {};
  if (headersRaw) {
    headersRaw.split('\n').forEach(line => {
      const i = line.indexOf(':');
      if (i > 0) headers[line.slice(0, i).trim()] = line.slice(i + 1).trim();
    });
  }
  try {
    const opts = { method, headers, mode: 'cors' };
    if (body && !['GET', 'HEAD'].includes(method)) opts.body = body;
    const t0 = performance.now();
    const res = await fetch(url, opts);
    const ms = Math.round(performance.now() - t0);
    const text = await res.text();
    let hdr = `HTTP ${res.status} ${res.statusText} (${ms}ms)\n`;
    res.headers.forEach((v, k) => { hdr += k + ': ' + v + '\n'; });
    out.textContent = hdr + '\n--- body (first 8000 chars) ---\n' + text.slice(0, 8000);
    document.getElementById('sec-headers-input').value = hdr.split('\n---')[0];
  } catch (e) {
    out.textContent = 'Request failed (often CORS on external sites):\n' + e.message +
      '\n\nTip: Use Burp/curl for cross-origin targets. Copy as curl below.';
    generateCurl();
  }
}

function generateCurl() {
  const url = document.getElementById('http-url').value.trim();
  const method = document.getElementById('http-method').value;
  const headersRaw = document.getElementById('http-headers').value.trim();
  const body = document.getElementById('http-body').value;
  let cmd = `curl -X ${method} '${url}'`;
  if (headersRaw) {
    headersRaw.split('\n').forEach(line => {
      const i = line.indexOf(':');
      if (i > 0) cmd += ` \\\n  -H '${line.slice(0, i).trim()}: ${line.slice(i + 1).trim()}'`;
    });
  }
  if (body && !['GET', 'HEAD'].includes(method)) cmd += ` \\\n  -d '${body.replace(/'/g, "'\\''")}'`;
  document.getElementById('curl-output').textContent = cmd;
}

function testOpenRedirect() {
  const base = document.getElementById('redirect-base').value.trim();
  const payloads = [
    'https://evil.com', '//evil.com', '/\\evil.com', '////evil.com',
    'https:evil.com', 'javascript:alert(1)', '%2f%2fevil.com', '?next=//evil.com'
  ];
  const param = document.getElementById('redirect-param').value.trim() || 'url';
  const out = document.getElementById('redirect-results');
  if (!base) { out.innerHTML = '<div class="es-sub">Enter base URL with param placeholder</div>'; return; }
  const sep = base.includes('?') ? '&' : '?';
  out.innerHTML = payloads.map(p => {
    const testUrl = base.includes('FUZZ') ? base.replace('FUZZ', encodeURIComponent(p)) : base + sep + param + '=' + encodeURIComponent(p);
    return `<div class="bookmark-item"><a href="${esc(testUrl)}" target="_blank">${esc(testUrl)}</a>
      <button class="btn btn-sm" onclick="window.copyTextToClipboard('${esc(testUrl)}').then(()=>toast('Copied'))">Copy</button></div>`;
  }).join('');
}

function parseCookies() {
  const raw = document.getElementById('cookie-input').value.trim();
  const out = document.getElementById('cookie-parsed');
  if (!raw) { out.textContent = ''; return; }
  try {
    if (raw.startsWith('{')) {
      out.textContent = JSON.stringify(JSON.parse(raw), null, 2);
      return;
    }
  } catch (e) { /* cookie string */ }
  const parts = raw.split(';').map(s => s.trim()).filter(Boolean);
  const obj = {};
  parts.forEach(p => {
    const eq = p.indexOf('=');
    if (eq > 0) obj[p.slice(0, eq)] = p.slice(eq + 1);
  });
  out.textContent = JSON.stringify(obj, null, 2);
}

function cleanUrlList() {
  const lines = document.getElementById('url-list-input').value.split(/\r?\n/);
  const seen = new Set();
  const clean = [];
  lines.forEach(line => {
    let u = line.trim();
    if (!u) return;
    if (!u.startsWith('http')) u = 'https://' + u;
    try {
      const parsed = new URL(u);
      const norm = parsed.origin + parsed.pathname + parsed.search;
      if (!seen.has(norm)) { seen.add(norm); clean.push(norm); }
    } catch (e) { /* skip invalid */ }
  });
  document.getElementById('url-list-output').value = clean.join('\n');
  toast(clean.length + ' unique URLs', 'success');
}

function generateSubdomainPermutations() {
  const word = document.getElementById('sub-word').value.trim() || 'api';
  const domain = document.getElementById('sub-domain').value.trim() || 'target.com';
  const prefixes = ['dev', 'staging', 'test', 'uat', 'beta', 'admin', 'internal', 'vpn', 'mail', 'cdn', 'static', 'm', 'mobile', 'api', 'app', 'portal'];
  const suffixes = ['-dev', '-stg', '-test', '-uat', '-old', '-new', '1', '2'];
  const out = new Set();
  prefixes.forEach(p => { out.add(p + '.' + domain); out.add(p + '-' + word + '.' + domain); });
  suffixes.forEach(s => { out.add(word + s + '.' + domain); });
  out.add(word + '.' + domain);
  document.getElementById('sub-output').value = [...out].sort().join('\n');
}

function diffTextBlocks() {
  const a = document.getElementById('diff-a').value.split(/\r?\n/);
  const b = document.getElementById('diff-b').value.split(/\r?\n/);
  const onlyA = a.filter(x => x && !b.includes(x));
  const onlyB = b.filter(x => x && !a.includes(x));
  document.getElementById('diff-out').textContent =
    'Only in A (' + onlyA.length + '):\n' + onlyA.slice(0, 100).join('\n') +
    '\n\nOnly in B (' + onlyB.length + '):\n' + onlyB.slice(0, 100).join('\n');
}

// ==========================================
// ENCODER / DECODER HELPERS
// ==========================================
const b32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
function base32Encode(str) {
  let bin = "";
  for (let i = 0; i < str.length; i++) {
    bin += str.charCodeAt(i).toString(2).padStart(8, '0');
  }
  let b32 = "";
  for (let i = 0; i < bin.length; i += 5) {
    let chunk = bin.substr(i, 5);
    if (chunk.length < 5) {
      chunk = chunk.padEnd(5, '0');
    }
    b32 += b32Alphabet[parseInt(chunk, 2)];
  }
  let pad = (8 - (b32.length % 8)) % 8;
  return b32 + "=".repeat(pad);
}

function base32Decode(str) {
  str = str.replace(/=+$/, '').toUpperCase().replace(/\s/g, '');
  if (!str) return "";
  let bin = "";
  for (let i = 0; i < str.length; i++) {
    let val = b32Alphabet.indexOf(str[i]);
    if (val === -1) throw new Error("Invalid Base32 character: " + str[i]);
    bin += val.toString(2).padStart(5, '0');
  }
  let out = "";
  for (let i = 0; i < bin.length - (bin.length % 8); i += 8) {
    out += String.fromCharCode(parseInt(bin.substr(i, 8), 2));
  }
  return out;
}

function rot13(str) {
  return str.replace(/[a-zA-Z]/g, c => {
    const code = c.charCodeAt(0);
    const start = code >= 65 && code <= 90 ? 65 : 97;
    return String.fromCharCode(((code - start + 13) % 26) + start);
  });
}

// ==========================================
// ENCODER / DECODER
// ==========================================
function doEncode(action) {
  const input = document.getElementById('encode-in').value;
  const out = document.getElementById('encode-out');
  try {
    if (action === 'b64e') out.value = btoa(input);
    if (action === 'b64d') out.value = atob(input);
    if (action === 'urle') out.value = encodeURIComponent(input);
    if (action === 'urld') out.value = decodeURIComponent(input);
    if (action === 'durle') out.value = encodeURIComponent(encodeURIComponent(input));
    if (action === 'durld') out.value = decodeURIComponent(decodeURIComponent(input));
    if (action === 'hexe') out.value = input.split('').map(c => c.charCodeAt(0).toString(16).padStart(2, '0')).join('');
    if (action === 'hexd') out.value = input.replace(/\s/g, '').match(/.{1,2}/g)?.map(byte => String.fromCharCode(parseInt(byte, 16))).join('') || '';
    if (action === 'htmle') out.value = esc(input);
    if (action === 'htmld') {
      const txt = document.createElement('textarea');
      txt.innerHTML = input;
      out.value = txt.value;
    }
    if (action === 'bine') out.value = input.split('').map(c => c.charCodeAt(0).toString(2).padStart(8, '0')).join(' ');
    if (action === 'bind') out.value = input.replace(/[\s\r\n]+/g, '').match(/.{1,8}/g)?.map(bin => String.fromCharCode(parseInt(bin, 2))).join('') || '';
    if (action === 'b32e') out.value = base32Encode(input);
    if (action === 'b32d') out.value = base32Decode(input);
    if (action === 'rot13') out.value = rot13(input);
    if (action === 'rev') out.value = input.split('').reverse().join('');
  } catch (e) {
    out.value = 'Error: ' + e.message;
  }
}

// ==========================================
// JWT ANALYZER
// ==========================================
function decodeJwt() {
  const token = document.getElementById('jwt-in').value.trim();
  const hOut = document.getElementById('jwt-header');
  const pOut = document.getElementById('jwt-payload');
  const sOut = document.getElementById('jwt-sig');
  hOut.textContent = ''; pOut.textContent = ''; sOut.textContent = '';
  
  if (!token) return;
  const parts = token.split('.');
  if (parts.length !== 3) {
    pOut.textContent = 'Invalid JWT format (must have 3 parts separated by dots)';
    return;
  }
  
  try {
    const header = JSON.parse(atob(parts[0].replace(/-/g, '+').replace(/_/g, '/')));
    hOut.textContent = JSON.stringify(header, null, 2);
  } catch (e) { hOut.textContent = 'Invalid Base64 Header: ' + parts[0]; }
  
  try {
    const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
    pOut.textContent = JSON.stringify(payload, null, 2);
  } catch (e) { pOut.textContent = 'Invalid Base64 Payload: ' + parts[1]; }
  
  sOut.textContent = parts[2];
}

// ==========================================
// HASH GENERATOR
// ==========================================
async function generateHashes() {
  const input = document.getElementById('hash-in').value;
  if (!input) return;
  try {
    if (window.crypto && window.crypto.subtle) {
      const buffer = new TextEncoder().encode(input);
      const sha1Buffer = await crypto.subtle.digest('SHA-1', buffer);
      const sha256Buffer = await crypto.subtle.digest('SHA-256', buffer);
      const sha512Buffer = await crypto.subtle.digest('SHA-512', buffer);
      
      document.getElementById('hash-sha1').value = Array.from(new Uint8Array(sha1Buffer)).map(b => b.toString(16).padStart(2, '0')).join('');
      document.getElementById('hash-sha256').value = Array.from(new Uint8Array(sha256Buffer)).map(b => b.toString(16).padStart(2, '0')).join('');
      document.getElementById('hash-sha512').value = Array.from(new Uint8Array(sha512Buffer)).map(b => b.toString(16).padStart(2, '0')).join('');
    } else if (typeof CryptoJS !== 'undefined') {
      document.getElementById('hash-sha1').value = CryptoJS.SHA1(input).toString(CryptoJS.enc.Hex);
      document.getElementById('hash-sha256').value = CryptoJS.SHA256(input).toString(CryptoJS.enc.Hex);
      document.getElementById('hash-sha512').value = CryptoJS.SHA512(input).toString(CryptoJS.enc.Hex);
    } else {
      toast('Crypto API unavailable', 'error');
    }
  } catch(e) {
    toast('Error generating hashes: ' + e.message, 'error');
  }
}

// ==========================================
// JSON FORMATTER
// ==========================================
function formatJson(pretty) {
  const input = document.getElementById('json-in').value;
  const out = document.getElementById('json-out');
  if (!input.trim()) return;
  try {
    const obj = JSON.parse(input);
    out.value = pretty ? JSON.stringify(obj, null, 2) : JSON.stringify(obj);
  } catch(e) {
    out.value = 'Invalid JSON: ' + e.message;
  }
}

// ==========================================
// EPOCH CALCULATOR
// ==========================================
function calcEpoch() {
  const raw = document.getElementById('epoch-in').value.trim();
  if (!raw) return;
  const v = parseInt(raw, 10);
  if (isNaN(v)) return;
  
  // Auto-detect seconds vs milliseconds (seconds usually <= 10 digits)
  const isSeconds = raw.length <= 10;
  const d = new Date(isSeconds ? v * 1000 : v);
  
  if (isNaN(d.getTime())) {
    document.getElementById('epoch-local').value = 'Invalid timestamp';
    document.getElementById('epoch-utc').value = 'Invalid timestamp';
    return;
  }
  
  document.getElementById('epoch-local').value = d.toString();
  document.getElementById('epoch-utc').value = d.toISOString();
}


// ==========================================
// JS EXTRACTOR
// ==========================================
function extractJsEndpoints() {
  const input = document.getElementById('js-extract-input').value;
  const out = document.getElementById('js-extract-result');
  if (!input.trim()) {
    out.innerHTML = '<div style="color:var(--text3);font-size:12px;">Paste JavaScript code above to extract data.</div>';
    return;
  }

  // Regex Patterns
  const pathRegex = /(?:"|')(\/[a-zA-Z0-9_?&=.\/-]+)(?:"|')/g;
  const urlRegex = /(?:https?|wss?):\/\/[a-zA-Z0-9.-]+(?:\.[a-zA-Z]{2,})+(?:\/[a-zA-Z0-9_?&=.\/-]*)?/g;
  
  // Basic secrets matching (JWT, AWS, Google API, generic tokens)
  const secretRegexes = [
    { name: 'JWT Token', regex: /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g },
    { name: 'AWS Access Key', regex: /AKIA[0-9A-Z]{16}/g },
    { name: 'Google API Key', regex: /AIza[0-9A-Za-z-_]{35}/g },
    { name: 'Bearer Token', regex: /Bearer\s+[A-Za-z0-9\-._~+/]+/g },
    { name: 'Generic Secret/Key', regex: /(?:secret|key|token|password|passwd)["']?\s*[:=]\s*["']?([A-Za-z0-9\-_]{8,})["']?/gi }
  ];

  // Extract
  const paths = [...new Set(Array.from(input.matchAll(pathRegex), m => m[1]))].sort();
  const urls = [...new Set(input.match(urlRegex) || [])].sort();
  
  const secrets = [];
  secretRegexes.forEach(s => {
    const matches = input.match(s.regex);
    if (matches) {
      matches.forEach(m => secrets.push({ type: s.name, value: m }));
    }
  });
  
  // Additional key/value extraction from regex group 1 for generic secret
  const genericMatches = Array.from(input.matchAll(/(?:secret|key|token|password)["']?\s*[:=]\s*["']?([A-Za-z0-9\-_]{8,})["']?/gi));
  genericMatches.forEach(m => {
    if (m[1]) secrets.push({ type: 'Generic Token', value: m[1] });
  });
  
  // Dedupe secrets
  const uniqueSecrets = [];
  const seenSecrets = new Set();
  secrets.forEach(s => {
    if (!seenSecrets.has(s.value)) {
      seenSecrets.add(s.value);
      uniqueSecrets.push(s);
    }
  });

  // Render HTML
  let html = '<div style="display:flex;flex-direction:column;gap:16px;">';
  
  // Paths
  if (paths.length > 0) {
    html += `<div style="border:1px solid var(--border);border-radius:var(--r);background:var(--bg);padding:10px 12px;">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
        <div style="font-size:11px;font-weight:700;color:var(--accent);text-transform:uppercase;">Extracted Paths (${paths.length})</div>
        <button class="btn btn-sm" onclick="window.copyTextToClipboard('${paths.join('\n').replace(/'/g,"\\'")}').then(()=>toast('Copied paths'))">Copy All</button>
      </div>
      <div style="max-height:200px;overflow-y:auto;background:var(--bg2);padding:8px;border-radius:4px;border:1px solid var(--border);font-family:var(--mono);font-size:11.5px;color:var(--text);white-space:pre-wrap;line-height:1.5;">${paths.map(p => esc(p)).join('\n')}</div>
    </div>`;
  }

  // URLs
  if (urls.length > 0) {
    html += `<div style="border:1px solid var(--border);border-radius:var(--r);background:var(--bg);padding:10px 12px;">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
        <div style="font-size:11px;font-weight:700;color:var(--orange);text-transform:uppercase;">Extracted Absolute URLs (${urls.length})</div>
        <button class="btn btn-sm" onclick="window.copyTextToClipboard('${urls.join('\n').replace(/'/g,"\\'")}').then(()=>toast('Copied URLs'))">Copy All</button>
      </div>
      <div style="max-height:200px;overflow-y:auto;background:var(--bg2);padding:8px;border-radius:4px;border:1px solid var(--border);font-family:var(--mono);font-size:11.5px;color:var(--text);white-space:pre-wrap;line-height:1.5;">${urls.map(u => esc(u)).join('\n')}</div>
    </div>`;
  }

  // Secrets
  if (uniqueSecrets.length > 0) {
    html += `<div style="border:1px solid var(--border);border-left:3px solid var(--red);border-radius:var(--r);background:var(--bg);padding:10px 12px;">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
        <div style="font-size:11px;font-weight:700;color:var(--red);text-transform:uppercase;">Potential Secrets (${uniqueSecrets.length})</div>
      </div>
      <div style="display:flex;flex-direction:column;gap:6px;">`;
    
    uniqueSecrets.forEach(s => {
      html += `<div style="display:flex;justify-content:space-between;align-items:center;background:var(--bg2);padding:6px 8px;border-radius:4px;border:1px dashed var(--border);">
        <div>
          <div style="font-size:10px;color:var(--text3);margin-bottom:2px;">${esc(s.type)}</div>
          <div style="font-family:var(--mono);font-size:12px;color:var(--red);word-break:break-all;">${esc(s.value)}</div>
        </div>
        <button class="btn btn-sm" style="padding:2px 6px;font-size:10px;" onclick="window.copyTextToClipboard('${esc(s.value).replace(/'/g,"\\'")}').then(()=>toast('Copied secret'))">Copy</button>
      </div>`;
    });
    
    html += `</div></div>`;
  }

  if (paths.length === 0 && urls.length === 0 && uniqueSecrets.length === 0) {
    html = `<div style="padding:16px;text-align:center;color:var(--text3);background:var(--bg);border:1px solid var(--border);border-radius:var(--r);">No paths, URLs, or obvious secrets found in the provided code.</div>`;
  }

  html += '</div>';
  out.innerHTML = html;
}
