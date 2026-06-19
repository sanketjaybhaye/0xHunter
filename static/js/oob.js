async function generateOobPayload() {
  const label = document.getElementById('oob-label').value.trim();
  const targetId = document.getElementById('oob-target').value;
  
  const res = await fetch('/api/oob/generate', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ label, targetId: targetId ? parseInt(targetId) : null })
  });
  const data = await res.json();
  if (data.success) {
    toast('OOB Payload generated', 'success');
    loadData().then(() => { if (typeof renderOobPage === 'function') renderOobPage(); });
  } else {
    toast('Failed to generate payload', 'error');
  }
}

async function deleteOobPayload(uid) {
  if (!confirm('Delete this payload and all its hits?')) return;
  const res = await fetch('/api/oob/' + uid, { method: 'DELETE' });
  const data = await res.json();
  if (data.success) {
    loadData().then(() => { if (typeof renderOobPage === 'function') renderOobPage(); });
  }
}

window.renderOobPage = function() {
  const ts = document.getElementById('oob-target');
  if (ts) {
    ts.innerHTML = '<option value="">- No specific target -</option>' +
      S.targets.map(t => `<option value="${t.id}">${esc(t.name)}</option>`).join('');
  }

  const plist = document.getElementById('oob-payloads-list');
  if (plist) {
    if (!S.oob_payloads || S.oob_payloads.length === 0) {
      plist.innerHTML = '<div class="oob-empty">No OOB payloads generated yet.</div>';
    } else {
      plist.innerHTML = S.oob_payloads.map(p => `
        <div style="display:flex;justify-content:space-between;align-items:center;background:linear-gradient(135deg, var(--bg3), var(--bg2));padding:15px;border-radius:8px;border:1px solid var(--border);border-left:4px solid var(--accent);margin-bottom:12px;box-shadow:0 4px 10px rgba(0,0,0,0.1);">
          <div>
            <div style="font-weight:600;font-size:14px;color:var(--text1);margin-bottom:6px;">${esc(p.label || 'Unnamed Payload')}</div>
            <div style="display:flex;align-items:center;gap:6px;background:var(--bg1);padding:4px 8px;border-radius:4px;border:1px solid var(--border);">
              <span style="color:var(--accent);">🔗</span>
              <span style="font-family:var(--mono);font-size:11px;color:var(--text2);">${window.location.protocol}//${window.location.host}/oob/${p.uid}</span>
            </div>
          </div>
          <div style="display:flex;gap:8px;">
            <button class="btn btn-sm" onclick="window.copyTextToClipboard('${window.location.protocol}//${window.location.host}/oob/${p.uid}').then(()=>toast('Copied payload URL','success'))" style="background:var(--bg4);border:1px solid var(--border);color:var(--text1);">Copy URL</button>
            <button class="btn btn-sm btn-danger" onclick="deleteOobPayload('${p.uid}')">🗑️</button>
          </div>
        </div>
      `).join('');
    }
  }

  const hlist = document.getElementById('oob-hits-list');
  if (hlist) {
    if (!S.oob_hits || S.oob_hits.length === 0) {
      hlist.innerHTML = '<div class="oob-empty">No hits received yet. Go inject some payloads!</div>';
    } else {
      hlist.innerHTML = S.oob_hits.map(h => {
        const payload = S.oob_payloads.find(p => p.uid === h.uid);
        const label = payload ? payload.label || payload.uid : h.uid;
        return `
        <div style="background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:16px;margin-bottom:12px;box-shadow:0 4px 10px rgba(0,0,0,0.1);">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;border-bottom:1px solid var(--bg4);padding-bottom:10px;">
            <div style="display:flex;align-items:center;gap:10px;">
              <span style="background:var(--green);color:var(--bg1);padding:4px 8px;border-radius:4px;font-family:var(--mono);font-size:11px;font-weight:bold;">${esc(h.method)}</span>
              <span style="font-weight:bold;color:var(--primary);font-size:14px;">Hit on [${esc(label)}]</span>
            </div>
            <div style="display:flex;align-items:center;gap:10px;">
              <div style="font-family:var(--mono);font-size:11px;color:var(--text2);background:var(--bg4);padding:4px 8px;border-radius:4px;">IP: ${esc(h.source_ip)}</div>
              <div style="color:var(--text3);font-size:11px;">${timeAgo(h.created)}</div>
            </div>
          </div>
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
            <div>
              <div style="font-size:11px;color:var(--text3);margin-bottom:4px;text-transform:uppercase;font-weight:bold;">Headers</div>
              <div style="background:var(--bg4);padding:10px;border-radius:6px;border:1px solid var(--border);font-family:var(--mono);font-size:11px;overflow-x:auto;color:var(--text2);max-height:150px;">
                ${esc(h.headers)}
              </div>
            </div>
            <div>
              <div style="font-size:11px;color:var(--text3);margin-bottom:4px;text-transform:uppercase;font-weight:bold;">Body</div>
              <div style="background:var(--bg4);padding:10px;border-radius:6px;border:1px solid var(--border);font-family:var(--mono);font-size:11px;overflow-x:auto;color:var(--text2);max-height:150px;white-space:pre-wrap;">
                ${esc(h.body) || '<i>No Body</i>'}
              </div>
            </div>
          </div>
        </div>
      `}).join('');
    }
  }
}
