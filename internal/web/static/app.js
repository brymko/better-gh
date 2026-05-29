let adminToken = '';

function api(method, path, body) {
  const opts = {
    method,
    headers: { 'Authorization': 'token ' + adminToken, 'Content-Type': 'application/json' },
  };
  if (body) opts.body = JSON.stringify(body);
  return fetch('/api' + path, opts).then(r => r.json().then(data => ({ ok: r.ok, status: r.status, data })));
}

function loadTokens() {
  adminToken = document.getElementById('admin-token').value;
  api('GET', '/tokens').then(res => {
    if (!res.ok) { alert('Auth failed'); return; }
    renderTokens(res.data);
    document.getElementById('token-list-section').style.display = '';
    document.getElementById('create-section').style.display = 'none';
    document.getElementById('detail-section').style.display = 'none';
  });
}

function renderTokens(tokens) {
  const tbody = document.getElementById('token-tbody');
  tbody.innerHTML = '';
  tokens.forEach(t => {
    const tr = document.createElement('tr');
    const statusCls = t.revoked ? 'status-revoked' : 'status-active';
    const statusText = t.revoked ? 'revoked' : 'active';
    const lastUsed = t.last_used || '-';
    tr.innerHTML = `
      <td>${esc(t.name)}</td>
      <td><code>${esc(t.id.substring(0,12))}</code></td>
      <td class="${statusCls}">${statusText}</td>
      <td>${esc(t.created_at)}</td>
      <td>${esc(lastUsed)}</td>
      <td>
        <button class="action-btn" onclick="showDetail('${esc(t.id)}')">view</button>
        ${!t.revoked ? `<button class="action-btn danger" onclick="revokeToken('${esc(t.id)}')">revoke</button>` : ''}
      </td>`;
    tbody.appendChild(tr);
  });
}

function showCreate() {
  document.getElementById('create-section').style.display = '';
  document.getElementById('org-rules').innerHTML = '';
  document.getElementById('repo-rules').innerHTML = '';
  document.getElementById('c-name').value = '';
  document.getElementById('c-default').value = 'deny';
}

function hideCreate() {
  document.getElementById('create-section').style.display = 'none';
}

function addOrgRule() {
  const div = document.getElementById('org-rules');
  const row = document.createElement('div');
  row.className = 'rule-row';
  row.innerHTML = '<input placeholder="org-name"><select><option value="read">read</option><option value="read-write">read-write</option><option value="none">none</option></select><button onclick="this.parentElement.remove()">x</button>';
  div.appendChild(row);
}

function addRepoRule() {
  const div = document.getElementById('repo-rules');
  const row = document.createElement('div');
  row.className = 'rule-row';
  row.innerHTML = '<input placeholder="owner/repo"><select><option value="read">read</option><option value="read-write">read-write</option><option value="none">none</option></select><button onclick="this.parentElement.remove()">x</button>';
  div.appendChild(row);
}

function createToken(e) {
  e.preventDefault();
  const name = document.getElementById('c-name').value;
  const def = document.getElementById('c-default').value;

  const orgRows = document.querySelectorAll('#org-rules .rule-row');
  const org = [];
  orgRows.forEach(r => {
    const n = r.querySelector('input').value.trim();
    const a = r.querySelector('select').value;
    if (n) org.push({ name: n, access: a });
  });

  const repoRows = document.querySelectorAll('#repo-rules .rule-row');
  const repo = [];
  repoRows.forEach(r => {
    const n = r.querySelector('input').value.trim();
    const a = r.querySelector('select').value;
    if (n) repo.push({ name: n, access: a });
  });

  api('POST', '/tokens', { name, policy: { default: def, org, repo } }).then(res => {
    if (!res.ok) { alert(res.data.error || 'Failed'); return; }
    document.getElementById('secret-value').textContent = res.data.secret;
    document.getElementById('secret-banner').style.display = '';
    hideCreate();
    loadTokens();
  });
  return false;
}

function copySecret() {
  const secret = document.getElementById('secret-value').textContent;
  navigator.clipboard.writeText(secret);
}

function dismissSecret() {
  document.getElementById('secret-banner').style.display = 'none';
}

function showDetail(id) {
  api('GET', '/tokens/' + id).then(res => {
    if (!res.ok) { alert('Not found'); return; }
    document.getElementById('detail-content').textContent = JSON.stringify(res.data, null, 2);
    document.getElementById('detail-section').style.display = '';
  });
}

function hideDetail() {
  document.getElementById('detail-section').style.display = 'none';
}

function revokeToken(id) {
  if (!confirm('Revoke this token?')) return;
  api('DELETE', '/tokens/' + id).then(res => {
    if (!res.ok) { alert('Failed'); return; }
    loadTokens();
  });
}

function esc(s) {
  const d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
}
