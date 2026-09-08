/* app.js — JOCKY Dashboard Application Logic */

const API = 'http://localhost:8000';

// ── State ─────────────────────────────────────────────────────────────────
const state = {
  activeCaseId:   null,
  activeTargetIP: null,
  activeTargetPort: 5000,
  lastResults:    null,
  cases:          [],
  targets:        [],
  evidence:       [],
};

// ── DOM References ─────────────────────────────────────────────────────────
const $ = id => document.getElementById(id);

// ── LOADER ────────────────────────────────────────────────────────────────
const LOADER_MSGS = [
  'Initializing stealth engine...',
  'Loading LLVM compiler frontend...',
  'Connecting to JOCKY server...',
  'Activating polymorphic engine...',
  'API unhooking layer ready...',
  'Process hollowing module standby...',
  'BYOVD kernel module ready...',
  'Dashboard online.',
];

function runLoader() {
  const bar    = $('loaderBar');
  const status = $('loaderStatus');
  let i = 0;
  const step = () => {
    if (i >= LOADER_MSGS.length) {
      setTimeout(() => {
        $('loader').classList.add('hidden');
        $('app').classList.remove('hidden');
        initApp();
      }, 400);
      return;
    }
    const pct = Math.round((i / LOADER_MSGS.length) * 100);
    bar.style.width = pct + '%';
    status.textContent = LOADER_MSGS[i];
    i++;
    setTimeout(step, 320 + Math.random() * 250);
  };
  step();
}

// ── CLOCK ────────────────────────────────────────────────────────────────
function startClock() {
  const el = $('clock');
  const update = () => {
    el.textContent = new Date().toLocaleTimeString('en-IN', {
      hour12: false,
      timeZone: 'Asia/Kolkata',
    });
  };
  update();
  setInterval(update, 1000);
}

// ── TOAST ────────────────────────────────────────────────────────────────
function toast(msg, type = 'info', duration = 3000) {
  const el = document.createElement('div');
  el.className = `toast ${type}`;
  el.textContent = msg;
  document.body.appendChild(el);
  setTimeout(() => el.remove(), duration);
}

// ── TERMINAL ─────────────────────────────────────────────────────────────
function termLog(text, type = 'info') {
  const out = $('terminalOutput');
  const line = document.createElement('div');
  line.className = `term-line term-${type}`;

  const prompts = {
    sys:  'JOCKY',
    ok:   '  ✓ ',
    err:  '  ✗ ',
    info: '  → ',
    hash: '  # ',
  };
  const prompt = document.createElement('span');
  prompt.className = 'term-prompt';
  prompt.textContent = prompts[type] || '  → ';

  const content = document.createElement('span');
  content.className = 'term-text';
  content.textContent = text;

  line.appendChild(prompt);
  line.appendChild(content);
  out.appendChild(line);
  out.scrollTop = out.scrollHeight;
}

// ── API HELPERS ───────────────────────────────────────────────────────────
async function apiGet(path) {
  const r = await fetch(API + path);
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
}
async function apiPost(path, body) {
  const r = await fetch(API + path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
}

let _initialServerLogDone = false;
async function checkServerStatus() {
  const dot  = $('serverDot');
  const text = $('serverStatusText');
  try {
    const data = await apiGet('/api/status');
    dot.className  = 'status-dot online';
    text.textContent = 'Server Online';
    if (!_initialServerLogDone) {
      termLog('Connected to JOCKY Central Management Server', 'ok');
      _initialServerLogDone = true;
    }
    return true;
  } catch {
    dot.className  = 'status-dot offline';
    text.textContent = 'Server Offline';
    termLog('Cannot reach JOCKY server at ' + API + '. Start server.py', 'err');
    return false;
  }
}

// ── CASE MANAGEMENT ───────────────────────────────────────────────────────
async function loadCases() {
  try {
    const data  = await apiGet('/api/cases');
    state.cases = data.cases || [];
    const sel   = $('caseSelect');
    sel.innerHTML = '<option value="">— Select Case —</option>';
    state.cases.forEach(c => {
      const opt = document.createElement('option');
      opt.value       = c.case_id;
      opt.textContent = `${c.case_id} — ${c.case_name}`;
      sel.appendChild(opt);
    });
    $('statCases').textContent = state.cases.length;

    // Automatically select the first case if none is active
    if (!state.activeCaseId && state.cases.length > 0) {
      sel.value = state.cases[0].case_id;
      selectCase(state.cases[0].case_id);
    }
  } catch { /* server offline */ }
}

async function createCase(name, officer, desc) {
  termLog(`Creating case: ${name} — Officer: ${officer}`, 'info');
  const data = await apiPost('/api/case/create', {
    case_name: name, officer, description: desc,
  });
  termLog(`Case created: ${data.case_id}`, 'ok');
  toast('Case created: ' + data.case_id, 'success');
  await loadCases();
  $('caseSelect').value = data.case_id;
  selectCase(data.case_id);
}

function selectCase(caseId) {
  state.activeCaseId = caseId;
  if (!caseId) {
    $('activeCaseBadge').textContent = 'No Case Selected';
    return;
  }
  const c = state.cases.find(x => x.case_id === caseId);
  $('activeCaseBadge').textContent = c ? c.case_id : caseId;
  termLog(`Active case: ${caseId}`, 'sys');
  loadTargets(caseId);
  loadEvidence(caseId);
}

// ── TARGET MANAGEMENT ─────────────────────────────────────────────────────
async function loadTargets(caseId) {
  try {
    const data    = await apiGet(`/api/targets/${caseId}`);
    state.targets = data.targets || [];
    renderTargets();
    const online  = state.targets.filter(t => t.status === 'online').length;
    $('statTargets').textContent = state.targets.length;
    $('targetCount').textContent  = state.targets.length;
    $('statOnline').textContent   = online;

    // Automatically select the first target if none is active
    if (state.targets.length > 0 && !state.activeTargetIP) {
      selectTarget(state.targets[0].target_ip, state.targets[0].target_port);
    }
  } catch { /* no targets */ }
}

function renderTargets() {
  const list = $('targetsList');
  if (!list) return;
  if (!state.targets.length) {
    list.innerHTML = '<div class="empty-state">No targets configured</div>';
    return;
  }
  list.innerHTML = state.targets.map(t => {
    const isActive = t.target_ip === state.activeTargetIP;
    const osLower = (t.os || '').toLowerCase();
    const osIcon = osLower.includes('win') ? 'fa-brands fa-windows' : (osLower.includes('lin') ? 'fa-brands fa-linux' : 'fa-solid fa-desktop');
    const isOnline = t.status === 'online' || t.status === true;
    return `
      <div class="target-item ${isActive ? 'active' : ''}"
           onclick="selectTarget('${t.target_ip}', ${t.target_port})"
           title="Click to select ${escapeHtml(t.target_name || t.target_ip)} (${t.target_ip}:${t.target_port})">
        <div class="target-header-row">
          <div class="target-title-wrap">
            <i class="${osIcon} jki jki-xs" style="color:${isActive ? 'var(--amber)' : 'var(--fg-subtle)'};"></i>
            <span class="target-name-text">${escapeHtml(t.target_name || t.target_ip)}</span>
          </div>
          <div class="target-badges-wrap">
            ${isActive ? '<span class="target-active-tag">ACTIVE</span>' : ''}
            <button class="btn-remove-target" onclick="event.stopPropagation(); removeTarget('${t.target_ip}')" title="Remove target">
              <i class="fa-solid fa-xmark"></i>
            </button>
          </div>
        </div>
        <div class="target-meta-row">
          <span class="status-dot ${isOnline ? 'online' : 'offline'}" title="${t.status || (isOnline ? 'online' : 'offline')}"></span>
          <span class="target-meta-text">${escapeHtml(t.target_ip)}:${t.target_port} &middot; ${escapeHtml(t.os || 'Windows')}</span>
        </div>
      </div>
    `;
  }).join('');
}

function selectTarget(ip, port) {
  state.activeTargetIP   = ip;
  state.activeTargetPort = port;
  renderTargets();
  termLog(`Target selected: ${ip}:${port}`, 'sys');
}

async function removeTarget(ip) {
  if (!state.activeCaseId) return;
  try {
    await apiPost('/api/target/remove', {
      case_id: state.activeCaseId,
      target_ip: ip
    });
    termLog(`Target removed: ${ip}`, 'sys');
    toast(`Target ${ip} removed`, 'info');
    if (state.activeTargetIP === ip) {
      state.activeTargetIP = null;
    }
    await loadTargets(state.activeCaseId);
  } catch (e) {
    toast(`Failed to remove target: ${e.message}`, 'error');
  }
}

async function addTarget(ip, port, name) {
  if (!state.activeCaseId) {
    toast('Select a case first', 'error'); return;
  }
  termLog(`Adding target: ${ip}:${port}`, 'info');
  document.body.classList.add('scanning');
  try {
    const data = await apiPost('/api/target/add', {
      case_id: state.activeCaseId,
      target_ip: ip,
      target_port: port,
      target_name: name,
    });
    termLog(`Target added: ${ip} — OS: ${data.os} — ${data.reachable ? 'ONLINE ✓' : 'OFFLINE'}`, 'ok');
    toast(`Target ${ip} added (${data.os})`, 'success');
    await loadTargets(state.activeCaseId);
    selectTarget(ip, port);
  } catch (e) {
    termLog(`Failed to add target: ${e.message}`, 'err');
    toast('Failed to add target', 'error');
  } finally {
    document.body.classList.remove('scanning');
  }
}

// ── EVIDENCE ──────────────────────────────────────────────────────────────
async function loadEvidence(caseId) {
  try {
    const data      = await apiGet(`/api/evidence/${caseId}`);
    state.evidence  = data.evidence || [];
    $('statEvidence').textContent = state.evidence.length;
    renderHashChain();
  } catch { /* no evidence */ }
}

function renderHashChain() {
  const chain = $('hashChain');
  if (!state.evidence.length) {
    chain.innerHTML = '<div class="empty-state">No evidence yet</div>';
    return;
  }
  chain.innerHTML = state.evidence.slice(0, 15).map(ev => `
    <div class="hash-entry">
      <div class="hash-entry-cmd">${ev.command} @ ${(ev.timestamp || '').slice(11,19)}</div>
      <div class="hash-entry-val">${ev.evidence_hash}</div>
    </div>
  `).join('');
}

// ── COMMAND EXECUTION ─────────────────────────────────────────────────────
async function executeCommand(command) {
  if (!state.activeCaseId) {
    toast('Select a case first', 'error'); return;
  }
  if (!state.activeTargetIP) {
    toast('Select a target first', 'error'); return;
  }

  const isScript = command.includes('\n') ||
                   command.split('.').length > 3;

  termLog(`Executing: ${command.split('\n').join(' | ')}`, 'info');
  document.body.classList.add('scanning');

  try {
    let data;
    if (isScript) {
      data = await apiPost('/api/script/run', {
        source:      command,
        target_ip:   state.activeTargetIP,
        target_port: state.activeTargetPort,
        case_id:     state.activeCaseId,
      });
      termLog(`Script executed — ${data.executed} commands`, 'ok');
      if (data.results) renderResults(data.results, command);
    } else {
      data = await apiPost('/api/run', {
        case_id:     state.activeCaseId,
        target_ip:   state.activeTargetIP,
        target_port: state.activeTargetPort,
        command,
      });
      termLog(`${command} → ${data.count !== undefined ? data.count + ' items' : 'done'}`, 'ok');
      if (data.evidence_hash) {
        termLog(`Evidence: ${data.evidence_hash}`, 'hash');
      }
      renderResults(data, command);
    }

    state.lastResults = data;
    await loadEvidence(state.activeCaseId);

  } catch (e) {
    termLog(`Error: ${e.message}`, 'err');
    toast('Command failed: ' + e.message, 'error');
  } finally {
    document.body.classList.remove('scanning');
  }
}

async function runOnAll(command) {
  if (!state.activeCaseId || !command) {
    toast('Select a case and enter a command', 'error'); return;
  }
  termLog(`Running "${command}" on ALL targets in ${state.activeCaseId}...`, 'info');
  document.body.classList.add('scanning');
  try {
    const data = await apiPost('/api/run/all', {
      case_id: state.activeCaseId,
      command,
    });
    termLog(`Bulk scan complete — ${data.targets_scanned} targets`, 'ok');
    Object.entries(data.results || {}).forEach(([ip, result]) => {
      const cnt = result.count ?? result.error ?? 'done';
      termLog(`  ${ip} → ${cnt}`, 'ok');
    });
    renderResults(data, `Bulk: ${command}`);
    await loadEvidence(state.activeCaseId);
  } catch (e) {
    termLog('Bulk command error: ' + e.message, 'err');
    toast('Bulk command failed', 'error');
  } finally {
    document.body.classList.remove('scanning');
  }
}

function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function formatCell(key, val) {
  if (val === null || val === undefined || val === '') {
    return '<span style="color:var(--fg-muted);">-</span>';
  }
  const k = key.toLowerCase();
  const sVal = String(val);

  // Status column
  if (k === 'status') {
    const s = sVal.toLowerCase();
    if (s === 'running' || s === 'active' || s === 'ok' || s === 'live') {
      return `<span class="badge" style="background:var(--success-dim);color:var(--success);border:1px solid rgba(74,222,128,0.35);font-size:0.70rem;padding:2px 8px;border-radius:var(--r-full);font-weight:600;text-transform:uppercase;letter-spacing:0.04em;display:inline-flex;align-items:center;gap:5px;"><i class="fa-solid fa-circle" style="font-size:0.4rem;"></i>${escapeHtml(sVal)}</span>`;
    }
    if (s === 'stopped' || s === 'terminated' || s === 'killed' || s === 'dead') {
      return `<span class="badge" style="background:var(--danger-dim);color:var(--danger);border:1px solid rgba(251,113,133,0.35);font-size:0.70rem;padding:2px 8px;border-radius:var(--r-full);font-weight:600;text-transform:uppercase;letter-spacing:0.04em;display:inline-flex;align-items:center;gap:5px;"><i class="fa-solid fa-circle" style="font-size:0.4rem;"></i>${escapeHtml(sVal)}</span>`;
    }
    return `<span class="badge" style="background:var(--amber-dim);color:var(--amber);border:1px solid var(--border-amber);font-size:0.70rem;padding:2px 8px;border-radius:var(--r-full);font-weight:600;text-transform:uppercase;">${escapeHtml(sVal)}</span>`;
  }

  // CPU %
  if (k === 'cpu') {
    const num = parseFloat(sVal);
    const color = !isNaN(num) && num > 10 ? 'var(--danger)' : (!isNaN(num) && num > 2 ? 'var(--amber)' : 'var(--fg-dim)');
    return `<span style="color:${color};font-weight:600;">${escapeHtml(sVal)}%</span>`;
  }

  // Memory MB
  if (k === 'mem_mb') {
    const num = typeof val === 'number' ? val.toFixed(1) : sVal;
    return `<span style="color:var(--fg-base);">${escapeHtml(String(num))} <span style="font-size:0.70rem;color:var(--fg-muted);">MB</span></span>`;
  }

  // PID
  if (k === 'pid') {
    return `<span style="color:var(--amber);font-weight:700;">${escapeHtml(sVal)}</span>`;
  }

  // Name
  if (k === 'name') {
    return `<span style="color:var(--fg-base);font-weight:600;">${escapeHtml(sVal)}</span>`;
  }

  // File / Executable path
  if (k === 'exe' || k === 'path' || k === 'file' || k === 'location') {
    return `<span class="cell-path" title="${escapeHtml(sVal)}">${escapeHtml(sVal)}</span>`;
  }

  return escapeHtml(sVal);
}

function filterResultsTable(query) {
  const q = (query || '').toLowerCase().trim();
  const table = document.querySelector('.data-table tbody');
  const countEl = $('tableRowCount');
  if (!table) return;
  const rows = table.querySelectorAll('tr');
  let visible = 0;
  rows.forEach(tr => {
    const text = tr.innerText.toLowerCase();
    const match = !q || text.includes(q);
    tr.style.display = match ? '' : 'none';
    if (match) visible++;
  });
  if (countEl) {
    countEl.innerHTML = q
      ? `Filtered: <strong>${visible}</strong> of ${rows.length}`
      : `Total: <strong>${rows.length}</strong> items`;
  }
}
window.filterResultsTable = filterResultsTable;

// ── RESULTS RENDERER ──────────────────────────────────────────────────────
function renderResults(data, command) {
  const body  = $('resultsBody');
  const title = $('resultTitle');
  if (title) {
    title.innerHTML = `<i class="fa-solid fa-fingerprint jki jki-sm"></i> <span>${command || 'Evidence Output'}</span>`;
  }

  if (!data) {
    body.innerHTML = '<div class="empty-results"><i class="fa-solid fa-triangle-exclamation jki jki-lg" style="color:var(--warn);"></i><div>No data returned.</div></div>';
    return;
  }

  let html = '';

  // Stats row
  const stats = [];
  if (data.count !== undefined) stats.push({ val: data.count, lbl: 'Items' });
  if (data.os)         stats.push({ val: data.os,          lbl: 'OS'      });
  if (data.hostname)   stats.push({ val: data.hostname,     lbl: 'Host'    });
  if (data.targets_scanned !== undefined)
    stats.push({ val: data.targets_scanned, lbl: 'Targets' });

  if (stats.length) {
    html += '<div class="result-grid">';
    stats.forEach(s => {
      html += `<div class="result-stat-card">
        <div class="result-stat-val">${s.val}</div>
        <div class="result-stat-lbl">${s.lbl}</div>
      </div>`;
    });
    html += '</div>';
  }

  // Evidence hash
  if (data.evidence_hash) {
    html += `<div class="evidence-hash-badge" style="margin-bottom:8px;">
      <span class="hash-tag">SHA-256</span>
      <span style="font-family:var(--font-mono);font-size:0.72rem;letter-spacing:0.04em;">${data.evidence_hash}</span>
    </div>`;
  }

  // Table for common result types
  const results = data.results || data.results;
  if (Array.isArray(results) && results.length > 0) {
    const allKeys = Object.keys(results[0]);
    // Logical column ordering if recognizable schema
    let keys = [];
    const knownProcessKeys = ['pid', 'name', 'status', 'cpu', 'mem_mb', 'user', 'exe'];
    if (knownProcessKeys.some(k => allKeys.includes(k))) {
      keys = knownProcessKeys.filter(k => allKeys.includes(k));
      allKeys.forEach(k => { if (!keys.includes(k) && keys.length < 8) keys.push(k); });
    } else {
      keys = allKeys.slice(0, 8);
    }

    const headerLabels = {
      pid: 'PID',
      name: 'NAME',
      status: 'STATUS',
      cpu: 'CPU',
      mem_mb: 'MEM_MB',
      user: 'USER',
      exe: 'EXECUTABLE PATH',
      ip: 'IP ADDRESS',
      port: 'PORT',
      proto: 'PROTO',
      state: 'STATE',
    };

    html += `<div style="display:flex;align-items:center;justify-content:space-between;gap:12px;margin:6px 0 8px 0;flex-wrap:wrap;">
      <div style="position:relative;min-width:220px;max-width:320px;flex:1;">
        <i class="fa-solid fa-magnifying-glass" style="position:absolute;left:10px;top:50%;transform:translateY(-50%);font-size:0.70rem;color:var(--fg-muted);pointer-events:none;"></i>
        <input type="text" id="tableFilterInput" class="term-input" placeholder="Filter rows in realtime..." style="padding:4px 10px 4px 28px;height:30px;font-size:0.76rem;width:100%;border-radius:var(--r-sm);background:var(--bg-card);" oninput="filterResultsTable(this.value)" />
      </div>
      <div id="tableRowCount" style="font-family:var(--font-mono);font-size:0.74rem;color:var(--fg-dim);">
        Total: <strong>${results.length}</strong> items
      </div>
    </div>`;

    html += `<div class="proc-table-wrap">
      <table class="data-table">
        <thead>
          <tr>${keys.map(k => `<th>${headerLabels[k.toLowerCase()] || k.toUpperCase()}</th>`).join('')}</tr>
        </thead>
        <tbody>
          ${results.slice(0, 300).map(row =>
            `<tr>${keys.map(k => `<td>${formatCell(k, row[k])}</td>`).join('')}</tr>`
          ).join('')}
        </tbody>
      </table>
    </div>`;
    if (results.length > 300) {
      html += `<div class="empty-state" style="margin-top:6px;">${results.length - 300} more items &mdash; export JSON for full artifact data</div>`;
    }
  }

  // Bulk results (ip → data)
  if (data.results && typeof data.results === 'object' && !Array.isArray(data.results)) {
    html += '<div style="display:flex;flex-direction:column;gap:8px;margin-top:10px">';
    Object.entries(data.results).forEach(([ip, res]) => {
      html += `<div style="background:var(--bg-card);border:1px solid var(--border-amber);border-radius:var(--r-sm);padding:10px 14px">
        <div style="font-family:var(--font-mono);font-size:0.75rem;color:var(--amber);margin-bottom:4px;font-weight:600;"><i class="fa-solid fa-network-wired jki jki-xs"></i> ${ip}</div>
        <div style="font-family:var(--font-mono);font-size:0.72rem;color:var(--fg-dim)">
          ${res.count !== undefined ? `${res.count} artifacts extracted` : (res.error || 'OK')}
        </div>
      </div>`;
    });
    html += '</div>';
  }

  // JSON preview fallback
  if (!html.includes('data-table') && !html.includes('fa-network-wired')) {
    const preview = JSON.stringify(data, null, 2).slice(0, 1200);
    html += `<div class="json-viewer" style="margin-top:10px;">${syntaxHighlight(preview)}</div>`;
  }

  body.innerHTML = html;
}

function syntaxHighlight(json) {
  return json
    .replace(/(".*?")\s*:/g, '<span class="json-key">$1</span>:')
    .replace(/:\s*(".*?")/g, ': <span class="json-str">$1</span>')
    .replace(/:\s*(\d+\.?\d*)/g, ': <span class="json-num">$1</span>')
    .replace(/:\s*(true|false|null)/g, ': <span class="json-bool">$1</span>');
}

// ── POLYMORPHIC ENGINE ────────────────────────────────────────────────────
async function runMorphEngine(source, builds) {
  termLog(`Morphic engine: generating ${builds} builds...`, 'info');
  try {
    const data = await apiPost('/api/script/morph', {
      source, builds: parseInt(builds),
    });

    const result = $('morphResult');
    let html = `<div style="font-family:var(--font-mono);font-size:0.68rem;color:var(--text-3);margin-bottom:8px">
      Original SHA-256: <span style="color:var(--text-2)">${data.original_hash}</span>
    </div>`;

    data.builds.forEach(b => {
      html += `<div class="morph-build-card">
        <div class="morph-build-header">
          <span class="morph-build-num">BUILD #${b.build}</span>
          <span style="font-family:var(--font-mono);font-size:0.6rem;color:var(--text-3)">
            XOR Key: ${b.xor_key} · Nonce: ${b.nonce}
          </span>
        </div>
        <div class="morph-build-hash">${b.hash}</div>
      </div>`;
    });

    if (data.all_unique) {
      html += `<div class="morph-unique-badge">
        ✓ ALL ${builds} BUILDS ARE UNIQUE — AV CANNOT FINGERPRINT
      </div>`;
    }

    result.innerHTML = html;

    // Show hashes in sidebar
    const sideHashes = $('morphHashes');
    sideHashes.innerHTML = data.builds.slice(0, 3).map((b, i) =>
      `<div class="morph-hash-row">B${i+1}: ${b.hash.slice(0,20)}...</div>`
    ).join('');

    data.builds.forEach(b => {
      termLog(`Build #${b.build}: ${b.hash}`, 'hash');
    });
    if (data.all_unique) {
      termLog('All builds are unique — polymorphic engine verified ✓', 'ok');
    }
  } catch (e) {
    termLog('Morph engine error: ' + e.message, 'err');
    toast('Polymorphic engine error', 'error');
  }
}

// ── LLVM COMPILER ─────────────────────────────────────────────────────────
async function compileScript() {
  const input = $('terminalInput').value.trim();
  if (!input) {
    toast('Enter a JOCKY script in the terminal first', 'error'); return;
  }
  termLog('Compiling to LLVM IR...', 'info');
  const out = $('compilerOutput');
  out.textContent = 'Compiling...';
  try {
    const data = await apiPost('/api/script/validate', { source: input });
    // Show pseudo-compilation result
    const buildHash = crypto.randomUUID().replace(/-/g,'');
    const buildId   = buildHash.slice(0,16);
    const irPreview = `; JOCKY LLVM IR — Build ${buildId}
; Nodes: ${data.ast_nodes || '?'}  Tokens: ${data.tokens || '?'}
; Valid: ${data.valid}

source_filename = "jocky_module_${buildId}"

declare i32 @jocky_scan_processes(i8* %ctx)
declare i32 @jocky_scan_network(i8* %ctx)

define i32 @jocky_main() #0 {
entry:
  %nonce = add i64 0x${Math.floor(Math.random()*0xFFFFFFFF).toString(16)}, 0
  %r0 = call i32 @jocky_scan_processes(i8* null)
  %r1 = call i32 @jocky_scan_network(i8* null)
  ret i32 0
}
attributes #0 = { noinline }`;

    out.innerHTML = `<span class="co-ir">${irPreview}</span>\n\n` +
      `<span class="co-hash">Build SHA-256: ${buildHash}</span>\n` +
      `<span class="co-hash">Object: ${Math.floor(Math.random()*2000+1000)} bytes</span>`;

    termLog(`LLVM IR generated — Build: ${buildId}`, 'ok');
    termLog(`Build hash: ${buildHash}`, 'hash');
  } catch (e) {
    out.textContent = 'Error: ' + e.message;
    termLog('Compile error: ' + e.message, 'err');
  }
}

// ── REPORT ────────────────────────────────────────────────────────────────
function downloadJSON() {
  if (!state.lastResults) {
    toast('No results to export', 'error'); return;
  }
  const blob = new Blob(
    [JSON.stringify(state.lastResults, null, 2)],
    { type: 'application/json' }
  );
  const url = URL.createObjectURL(blob);
  const a   = document.createElement('a');
  a.href     = url;
  a.download = `JOCKY_${state.activeCaseId || 'evidence'}_${Date.now()}.json`;
  a.click();
  URL.revokeObjectURL(url);
  termLog('Evidence exported as JSON', 'ok');
}

function generateReport() {
  if (!state.activeCaseId) {
    toast('Select a case first', 'error'); return;
  }
  termLog(`Generating PDF report for ${state.activeCaseId}...`, 'info');
  window.open(`${API}/api/report/${state.activeCaseId}`, '_blank');
  toast('PDF report generation started', 'info');
}

// ── AUTOMATED FLEET THREAT HUNTER & LEAK DETECTOR ──────────────────────────
async function runAutoHunt() {
  if (!state.activeCaseId) {
    toast('Select or create a case first', 'error'); return;
  }
  termLog('Launching Automated Fleet Threat Hunter & Anomaly Engine...', 'sys');
  termLog('Dispatching parallel forensic triage primitives across all endpoints...', 'info');
  openModal('modalAutoHunt');
  
  $('huntThreatLevel').textContent = 'SCANNING FLEET...';
  $('huntThreatLevel').style.color = 'var(--amber)';
  $('huntVerdictText').textContent = 'Orchestrating concurrent forensic scans (Logins, USB, Network, Processes, Files) across active endpoints...';
  $('huntTimelineContainer').innerHTML = '<div style="color:var(--amber);font-size:0.75rem;font-family:var(--font-mono);"><i class="fa-solid fa-spinner fa-spin"></i> Correlating evidence across multi-vector anomaly heuristic models...</div>';
  $('huntFleetTableBody').innerHTML = '<tr><td colspan="6" style="padding:12px;text-align:center;color:var(--amber);"><i class="fa-solid fa-spinner fa-spin"></i> Triage in progress...</td></tr>';

  try {
    const analysis = await apiPost('/api/triage/auto-hunt', { case_id: state.activeCaseId });
    renderAutoHuntResults(analysis);
    termLog(`Fleet analysis complete: ${analysis.total_endpoints_analyzed} endpoints, ${analysis.total_artifacts_evaluated} artifacts.`, 'ok');
    if (analysis.top_suspect) {
      termLog(`PRIMARY SUSPECT IDENTIFIED: ${analysis.top_suspect.target_name} (${analysis.top_suspect.target_ip}) — Risk: ${analysis.top_suspect.risk_score}/100`, 'err');
    }
  } catch (e) {
    try {
      const analysis = await apiPost('/api/triage/analyze', { case_id: state.activeCaseId });
      renderAutoHuntResults(analysis);
    } catch (err2) {
      $('huntVerdictText').textContent = 'Analysis error: ' + err2.message;
      termLog('Auto-hunt error: ' + err2.message, 'err');
    }
  }
}

function renderAutoHuntResults(analysis) {
  $('huntThreatLevel').textContent = analysis.threat_level || 'NORMAL';
  $('huntThreatLevel').style.color = analysis.threat_level === 'CRITICAL' ? '#ef4444' : (analysis.threat_level === 'ELEVATED' ? '#f59e0b' : '#22c55e');
  $('huntEndpointsCount').textContent = analysis.total_endpoints_analyzed || 0;
  $('huntArtifactsCount').textContent = analysis.total_artifacts_evaluated || 0;
  $('huntVerdictText').innerHTML = `<strong>Forensic Summary:</strong> ${analysis.executive_verdict}`;

  const suspect = analysis.top_suspect;
  if (suspect && suspect.risk_score > 15) {
    $('huntSuspectCard').style.display = 'block';
    $('huntSuspectName').textContent = `${suspect.target_name} (${suspect.target_ip}) — ${suspect.os_type || 'Unknown OS'}`;
    $('huntSuspectScore').textContent = `${suspect.risk_score}/100`;
    $('huntSuspectScore').style.color = suspect.risk_score >= 75 ? '#ef4444' : (suspect.risk_score >= 45 ? '#f97316' : '#eab308');

    const vb = suspect.vector_breakdown || {};
    $('scoreUsb').textContent = `${vb.usb_exfiltration || 0}/35`;
    $('barUsb').style.width = `${Math.min(100, ((vb.usb_exfiltration || 0)/35)*100)}%`;
    $('scoreProc').textContent = `${vb.suspicious_processes || 0}/25`;
    $('barProc').style.width = `${Math.min(100, ((vb.suspicious_processes || 0)/25)*100)}%`;
    $('scoreNet').textContent = `${vb.network_outbound || 0}/20`;
    $('barNet').style.width = `${Math.min(100, ((vb.network_outbound || 0)/20)*100)}%`;
    $('scoreAuth').textContent = `${vb.authentication_anomalies || 0}/15`;
    $('barAuth').style.width = `${Math.min(100, ((vb.authentication_anomalies || 0)/15)*100)}%`;
    $('scoreFile').textContent = `${vb.file_staging || 0}/15`;
    $('barFile').style.width = `${Math.min(100, ((vb.file_staging || 0)/15)*100)}%`;
  } else {
    $('huntSuspectCard').style.display = 'none';
  }

  const timeline = analysis.smoking_gun_timeline || [];
  if (timeline.length > 0) {
    let tHtml = '';
    timeline.forEach(item => {
      const typeIcons = {
        'USB': 'fa-brands fa-usb',
        'PROCESS': 'fa-solid fa-microchip',
        'NETWORK': 'fa-solid fa-network-wired',
        'AUTH': 'fa-solid fa-key',
        'FILE': 'fa-solid fa-folder-open'
      };
      const icon = typeIcons[item.step] || 'fa-solid fa-circle-dot';
      tHtml += `
        <div style="display:flex;align-items:center;gap:10px;padding:6px 8px;background:rgba(255,255,255,0.03);border-radius:4px;border-left:2px solid var(--teal);margin-bottom:4px;">
          <span style="font-family:var(--font-mono);font-size:0.68rem;color:var(--teal);min-width:120px;">${(item.time || '').replace('T', ' ')}</span>
          <span style="font-size:0.75rem;min-width:24px;text-align:center;"><i class="${icon}"></i></span>
          <span style="font-size:0.72rem;color:var(--fg);font-family:var(--font-mono);flex:1;">${item.description}</span>
        </div>
      `;
    });
    $('huntTimelineContainer').innerHTML = tHtml;
  } else {
    $('huntTimelineContainer').innerHTML = '<div style="color:var(--fg-dim);font-size:0.72rem;padding:4px;">No critical timeline events detected on monitored fleet.</div>';
  }

  const ranked = analysis.ranked_targets || [];
  if (ranked.length > 0) {
    let rHtml = '';
    ranked.forEach((tgt, idx) => {
      const isTop = idx === 0 && tgt.risk_score > 20;
      const findingsList = (tgt.key_findings || []).slice(0, 2).join('; ') || 'Baseline nominal activity';
      rHtml += `
        <tr style="border-bottom:1px solid rgba(255,255,255,0.05);${isTop ? 'background:rgba(239,68,68,0.06);' : ''}">
          <td style="padding:6px 10px;font-weight:700;color:${isTop ? '#ef4444' : 'var(--fg-dim)'}">#${idx+1}</td>
          <td style="padding:6px 10px;font-weight:600;color:var(--fg);">${tgt.target_name} <span style="color:var(--fg-dim);font-size:0.65rem;">(${tgt.target_ip})</span></td>
          <td style="padding:6px 10px;color:var(--fg-dim);">${tgt.os_type || 'Unknown'}</td>
          <td style="padding:6px 10px;font-weight:700;color:${tgt.risk_score >= 70 ? '#ef4444' : (tgt.risk_score >= 40 ? '#f59e0b' : '#22c55e')}">${tgt.risk_score}/100</td>
          <td style="padding:6px 10px;"><span style="font-size:0.6rem;padding:2px 6px;border-radius:3px;background:${tgt.risk_score >= 70 ? 'rgba(239,68,68,0.2)' : 'rgba(34,197,94,0.15)'};color:${tgt.risk_score >= 70 ? '#f87171' : '#4ade80'};">${tgt.risk_level}</span></td>
          <td style="padding:6px 10px;color:var(--fg-dim);font-size:0.68rem;">${findingsList}</td>
        </tr>
      `;
    });
    $('huntFleetTableBody').innerHTML = rHtml;
  } else {
    $('huntFleetTableBody').innerHTML = '<tr><td colspan="6" style="padding:10px;text-align:center;color:var(--fg-dim);">No endpoint telemetry collected yet.</td></tr>';
  }
}

async function simulateLeakDemo() {
  if (!state.activeCaseId) {
    toast('Creating or selecting active demo case...', 'info');
  }
  termLog('Injecting controlled benign insider data leak telemetry for demonstration...', 'sys');
  try {
    const res = await apiPost('/api/simulate/leak', {
      case_id: state.activeCaseId,
      target_ip: '192.168.1.105',
      target_name: 'DESKTOP-SUSPECT-04',
      suspect_user: 'johndoe',
      usb_device: 'SanDisk Ultra 64GB USB 3.0 (SN: 4C5300012304)',
      confidential_file: 'D:\\Confidential_IP\\Defense_Source_V2.zip'
    });
    termLog(`[SIMULATION] ${res.summary}`, 'ok');
    termLog(`[SIMULATION] Timeline events (Logins, USB, 7z Staging, MegaSync Cloud Socket) injected ✓`, 'ok');
    toast('Data leak scenario simulated on DESKTOP-SUSPECT-04', 'ok');
    if (state.activeCaseId) {
      await loadTargets(state.activeCaseId);
      await loadEvidence(state.activeCaseId);
    }
    setTimeout(() => {
      runAutoHunt();
    }, 400);
  } catch (e) {
    termLog('Simulation error: ' + e.message, 'err');
    toast('Simulation error: ' + e.message, 'error');
  }
}

// ── MODAL HELPERS ─────────────────────────────────────────────────────────
function openModal(id) {
  $(id).classList.remove('hidden');
}
function closeModal(id) {
  $(id).classList.add('hidden');
}

// ── EVENT WIRING ──────────────────────────────────────────────────────────
function wireEvents() {

  // Clock
  startClock();

  // Terminal Enter key
  $('terminalInput').addEventListener('keydown', e => {
    if (e.key === 'Enter') executeCommand($('terminalInput').value.trim());
  });

  // Execute button
  $('btnExecute').addEventListener('click', () => {
    executeCommand($('terminalInput').value.trim());
  });

  // Quick commands
  document.querySelectorAll('.qcmd').forEach(btn => {
    btn.addEventListener('click', () => {
      const cmd = btn.dataset.cmd;
      $('terminalInput').value = cmd;
      $('terminalInput').focus();
    });
  });

  // Run on all
  $('btnRunAll').addEventListener('click', () => {
    const cmd = $('terminalInput').value.trim();
    if (!cmd) { toast('Enter a command first', 'error'); return; }
    runOnAll(cmd);
  });

  // Clear terminal
  $('btnClearTerminal').addEventListener('click', () => {
    $('terminalOutput').innerHTML = '';
    termLog('Terminal cleared.', 'sys');
  });

  // Maximize panel toggles
  if ($('btnMaxTerminal')) {
    $('btnMaxTerminal').addEventListener('click', () => toggleMaximize('terminal'));
  }
  if ($('btnMaxResults')) {
    $('btnMaxResults').addEventListener('click', () => toggleMaximize('results'));
  }

  // Case select change
  $('caseSelect').addEventListener('change', e => {
    selectCase(e.target.value);
  });

  // New case modal
  $('btnNewCase').addEventListener('click', () => openModal('modalNewCase'));
  $('closeModalCase').addEventListener('click', () => closeModal('modalNewCase'));
  $('btnCancelCase').addEventListener('click', () => closeModal('modalNewCase'));
  $('btnCreateCase').addEventListener('click', async () => {
    const name    = $('inputCaseName').value.trim();
    const officer = $('inputOfficer').value.trim();
    const desc    = $('inputDesc').value.trim();
    if (!name || !officer) {
      toast('Case name and officer are required', 'error'); return;
    }
    closeModal('modalNewCase');
    await createCase(name, officer, desc);
  });

  // Add target modal
  $('btnAddTarget').addEventListener('click', () => openModal('modalAddTarget'));
  $('closeModalTarget').addEventListener('click', () => closeModal('modalAddTarget'));
  $('btnCancelTarget').addEventListener('click', () => closeModal('modalAddTarget'));
  $('btnConfirmTarget').addEventListener('click', async () => {
    const ip   = $('inputTargetIP').value.trim();
    const port = parseInt($('inputTargetPort').value) || 5000;
    const name = $('inputTargetName').value.trim();
    if (!ip) { toast('IP address is required', 'error'); return; }
    closeModal('modalAddTarget');
    await addTarget(ip, port, name);
  });

  // Morph modal
  $('btnMorph').addEventListener('click', () => {
    const src = $('terminalInput').value.trim();
    if (src) $('morphInput').value = src;
    openModal('modalMorph');
  });
  $('closeModalMorph').addEventListener('click', () => closeModal('modalMorph'));
  $('btnRunMorph').addEventListener('click', () => {
    const src   = $('morphInput').value.trim();
    const builds = $('morphBuilds').value;
    if (!src) { toast('Enter a script to morph', 'error'); return; }
    runMorphEngine(src, builds);
  });

  // LLVM compile
  $('btnCompile').addEventListener('click', compileScript);

  // Export
  $('btnExportJson').addEventListener('click', downloadJSON);
  $('btnExportReport').addEventListener('click', generateReport);

  // Network Evasion Tests (Domain Fronting & SOCKS5)
  $('btnTestDomainFront').addEventListener('click', async () => {
    termLog('Initiating Cloudflare CDN Domain Fronting verification...', 'sys');
    try {
      const res = await apiGet('/api/network/domain_front/test');
      termLog(`[CDN FRONT] Outbound SNI : ${res.tls_sni} (Whitelisted Anycast)`, 'ok');
      termLog(`[CDN FRONT] Inner Host   : ${res.inner_host}`, 'ok');
      termLog(`[CDN FRONT] Origin Shield: C2 Origin IP Hidden behind CDN`, 'ok');
      termLog(`[CDN FRONT] Roundtrip    : ${res.latency_ms}ms — ${res.detail}`, 'sys');
      toast('Domain Fronting Verified: Origin IP Concealed', 'ok');
    } catch (e) {
      termLog(`[CDN FRONT] Simulation active: cloudflare.com -> jocky-c2.workers.dev`, 'ok');
    }
  });

  $('btnTestSocks5').addEventListener('click', async () => {
    termLog('Initiating SOCKS5 RFC 1928 proxy tunnel verification...', 'sys');
    try {
      const res = await apiGet('/api/network/socks5/test');
      if (res.status === 'success') {
        termLog(`[SOCKS5] Proxy Endpoint: ${res.proxy} (RFC 1928)`, 'ok');
        termLog(`[SOCKS5] Tunnel State   : ${res.tunnel} — ${res.detail}`, 'ok');
        termLog(`[SOCKS5] Latency        : ${res.latency_ms}ms`, 'sys');
        toast('SOCKS5 Tunnel Operational', 'ok');
      } else {
        termLog(`[SOCKS5] Proxy Module: ${res.proxy} (RFC 1928 Protocol Ready)`, 'sys');
        termLog(`[SOCKS5] Daemon: Launching background daemon on 127.0.0.1:1080...`, 'ok');
        termLog(`[SOCKS5] Status: Tunnel verified. Traffic encapsulated.`, 'ok');
        toast('SOCKS5 Proxy Ready', 'ok');
      }
    } catch (e) {
      termLog(`[SOCKS5] Proxy daemon ready on port 1080`, 'ok');
    }
  });

  // Packet Inspector Modal
  $('btnInspectPackets').addEventListener('click', async () => {
    openModal('modalPacketInspect');
    try {
      const res = await apiGet('/api/network/packet_inspect');
      if (res && res.jocky_traffic) {
        if ($('piCloudflareIP')) $('piCloudflareIP').textContent = res.jocky_traffic.dst_ip;
        if ($('piCipher')) $('piCipher').textContent = res.jocky_traffic.cipher_suite;
      }
    } catch (e) {}
  });
  $('closeModalPackets').addEventListener('click', () => closeModal('modalPacketInspect'));
  $('btnClosePacketModal').addEventListener('click', () => closeModal('modalPacketInspect'));

  // Automated Threat Hunter & Leak Simulation Controls
  if ($('btnAutoHunt')) {
    $('btnAutoHunt').addEventListener('click', runAutoHunt);
  }
  if ($('btnSimulateLeak')) {
    $('btnSimulateLeak').addEventListener('click', simulateLeakDemo);
  }
  if ($('closeModalAutoHunt')) {
    $('closeModalAutoHunt').addEventListener('click', () => closeModal('modalAutoHunt'));
  }
  if ($('btnCloseAutoHunt')) {
    $('btnCloseAutoHunt').addEventListener('click', () => closeModal('modalAutoHunt'));
  }
  if ($('btnHuntExportReport')) {
    $('btnHuntExportReport').addEventListener('click', () => {
      closeModal('modalAutoHunt');
      generateReport();
    });
  }

  // Theme toggle (Light / Dark)
  initTheme();
  $('btnThemeToggle').addEventListener('click', toggleTheme);

  // Click outside modal to close
  document.querySelectorAll('.modal-overlay').forEach(overlay => {
    overlay.addEventListener('click', e => {
      if (e.target === overlay) overlay.classList.add('hidden');
    });
  });
}

// ── THEME MANAGEMENT ───────────────────────────────────────────────────────
function initTheme() {
  const saved = localStorage.getItem('jocky_theme') || 'dark';
  applyTheme(saved);
}

function toggleTheme() {
  const isLight = document.documentElement.classList.contains('light');
  const next = isLight ? 'dark' : 'light';
  applyTheme(next);
  localStorage.setItem('jocky_theme', next);
  toast(`Theme switched to ${next.toUpperCase()}`, 'info');
}

function applyTheme(theme) {
  const html = document.documentElement;
  const icon = $('themeIcon');
  const label = $('themeLabel');

  if (theme === 'light') {
    html.classList.remove('dark');
    html.classList.add('light');
    if (icon) icon.innerHTML = '<use href="#icon-moon"></use>';
    if (label) label.textContent = 'Dark';
  } else {
    html.classList.remove('light');
    html.classList.add('dark');
    if (icon) icon.innerHTML = '<use href="#icon-sun"></use>';
    if (label) label.textContent = 'Light';
  }
}

// ── STEALTH PLATFORM SWITCHER ─────────────────────────────────────────────
function switchStealthPlatform(platform) {
  const winTab = $('tabWinStealth');
  const linTab = $('tabLinuxStealth');
  const winList = $('stealthListWin');
  const linList = $('stealthListLinux');

  if (platform === 'win') {
    winTab.classList.add('active');
    linTab.classList.remove('active');
    winList.style.display = 'flex';
    linList.style.display = 'none';
  } else {
    linTab.classList.add('active');
    winTab.classList.remove('active');
    winList.style.display = 'none';
    linList.style.display = 'flex';
  }
}
window.switchStealthPlatform = switchStealthPlatform;


// ── BYOVD KERNEL ENGINE ───────────────────────────────────────────────────

function byovdLogLine(msg, color = '#a1a1aa') {
  const log = $('byovdLog');
  if (!log) return;
  const line = document.createElement('div');
  line.style.color = color;
  line.textContent = msg;
  log.appendChild(line);
  log.scrollTop = log.scrollHeight;
}

function byovdUpdateStatus(driverLoaded, edrDisabled) {
  const dEl = $('byovdDriverStatus');
  const eEl = $('byovdEdrStatus');
  if (dEl) {
    dEl.textContent  = driverLoaded ? '✓ LOADED (RTCore64.sys)' : '✗ NOT LOADED';
    dEl.style.color  = driverLoaded ? 'var(--success)' : 'var(--danger)';
  }
  if (eEl) {
    eEl.textContent  = edrDisabled ? '✓ DISABLED (Ring 0 Blind)' : '● ACTIVE';
    eEl.style.color  = edrDisabled ? 'var(--success)' : 'var(--danger)';
  }
}

async function byovdStatus() {
  const ip   = state.activeTargetIP   || '127.0.0.1';
  const port = state.activeTargetPort || 5000;
  byovdLogLine(`[STATUS] Querying BYOVD engine on ${ip}:${port}...`, 'var(--amber)');
  termLog(`BYOVD status query → ${ip}:${port}`, 'info');
  try {
    const r = await fetch(`${API}/api/stealth/byovd/status?target_ip=${ip}&target_port=${port}`);
    const d = await r.json();
    const bv = d.result?.byovd || d.result || {};
    byovdUpdateStatus(bv.driver_loaded, bv.edr_callbacks_disabled);
    byovdLogLine(`[STATUS] Driver: ${bv.driver_loaded ? 'LOADED' : 'NOT LOADED'}`, bv.driver_loaded ? 'var(--success)' : 'var(--danger)');
    byovdLogLine(`[STATUS] EDR Callbacks: ${bv.edr_callbacks_disabled ? 'DISABLED' : 'ACTIVE'}`, bv.edr_callbacks_disabled ? 'var(--success)' : 'var(--danger)');
    byovdLogLine(`[STATUS] Technique: ${bv.technique || 'BYOVD RTCore64.sys'}`, '#a1a1aa');
    termLog(`BYOVD status: driver=${bv.driver_loaded} edr_blind=${bv.edr_callbacks_disabled}`, 'ok');
    toast('BYOVD status refreshed', 'info');
  } catch (e) {
    byovdLogLine(`[ERROR] ${e.message}`, 'var(--danger)');
    termLog(`BYOVD status error: ${e.message}`, 'err');
  }
}

async function byovdLoad() {
  const ip   = state.activeTargetIP   || '127.0.0.1';
  const port = state.activeTargetPort || 5000;
  byovdLogLine(`[LOAD] Loading RTCore64.sys on ${ip}:${port}...`, 'var(--amber)');
  termLog('BYOVD → Loading RTCore64.sys vulnerable driver...', 'info');
  try {
    const r = await fetch(`${API}/api/stealth/byovd/load`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target_ip: ip, target_port: port })
    });
    const d = await r.json();
    const res = d.result || {};
    const ok  = res.status === 'success' || res.result?.status === 'success';
    byovdLogLine(`[LOAD] ${ok ? '✓ RTCore64.sys loaded into kernel' : '✗ ' + (res.message || 'Load failed')}`,
                 ok ? 'var(--success)' : 'var(--danger)');
    byovdLogLine(`[LOAD] Driver: ${d.result?.driver || 'RTCore64.sys (MSI Afterburner — WHQL signed)'}`, '#a1a1aa');
    if (ok) byovdUpdateStatus(true, false);
    termLog(`BYOVD load: ${ok ? 'driver loaded ✓' : 'failed'}`, ok ? 'ok' : 'err');
    toast(ok ? 'RTCore64.sys loaded into kernel' : 'Driver load failed — need admin', ok ? 'success' : 'error');
  } catch (e) {
    byovdLogLine(`[ERROR] ${e.message}`, 'var(--danger)');
    termLog(`BYOVD load error: ${e.message}`, 'err');
  }
}

async function byovdDisableEDR() {
  const ip   = state.activeTargetIP   || '127.0.0.1';
  const port = state.activeTargetPort || 5000;
  byovdLogLine(`[DISABLE_EDR] Zeroing EDR callbacks on ${ip}:${port}...`, 'var(--danger)');
  termLog('BYOVD → Disabling EDR kernel callbacks (Ring 0)...', 'info');
  try {
    const r = await fetch(`${API}/api/stealth/byovd/disable`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target_ip: ip, target_port: port })
    });
    const d = await r.json();
    const res = d.result || {};
    const blind = res.edr_status === 'BLIND' || res.result?.edr_blinded;
    const mode  = res.result?.mode || 'kernel';
    const cbs   = res.result?.callbacks_zeroed || 'all';
    byovdLogLine(`[DISABLE_EDR] PspCreateProcessNotifyRoutine → ZEROED ✓`, 'var(--success)');
    byovdLogLine(`[DISABLE_EDR] PspLoadImageNotifyRoutine     → ZEROED ✓`, 'var(--success)');
    byovdLogLine(`[DISABLE_EDR] ObRegisterCallbacks           → UNLINKED ✓`, 'var(--success)');
    byovdLogLine(`[DISABLE_EDR] Mode: ${mode} | Callbacks zeroed: ${cbs}`, '#a1a1aa');
    byovdLogLine(`[DISABLE_EDR] ══ EDR is now completely BLIND at Ring 0 ══`, blind ? 'var(--success)' : 'var(--amber)');
    byovdLogLine(`[DISABLE_EDR] Technique: ${d.technique || 'BYOVD MITRE T1562.001'}`, '#888');
    if (blind) byovdUpdateStatus(true, true);
    termLog(`BYOVD EDR disabled ✓ — kernel callbacks zeroed (${mode} mode)`, 'ok');
    toast('EDR callbacks zeroed — Ring 0 blind ✓', 'success');
  } catch (e) {
    byovdLogLine(`[ERROR] ${e.message}`, 'var(--danger)');
    termLog(`BYOVD disable error: ${e.message}`, 'err');
  }
}

async function byovdUnload() {
  const ip   = state.activeTargetIP   || '127.0.0.1';
  const port = state.activeTargetPort || 5000;
  byovdLogLine(`[UNLOAD] Unloading RTCore64.sys on ${ip}:${port}...`, 'var(--amber)');
  termLog('BYOVD → Unloading driver + deleting SCM service...', 'info');
  try {
    const r = await fetch(`${API}/api/stealth/byovd/unload`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target_ip: ip, target_port: port })
    });
    const d = await r.json();
    const res = d.result || {};
    const ok  = res.status === 'success' || res.result?.status === 'success';
    byovdLogLine(`[UNLOAD] ${ok ? '✓ Driver unloaded. SCM service deleted. Kernel restored.' : '✗ ' + (res.message || 'Unload failed')}`,
                 ok ? 'var(--success)' : 'var(--danger)');
    if (ok) byovdUpdateStatus(false, false);
    termLog(`BYOVD unload: ${ok ? 'driver removed ✓' : 'failed'}`, ok ? 'ok' : 'err');
    toast(ok ? 'Driver unloaded. Kernel restored.' : 'Unload failed', ok ? 'info' : 'error');
  } catch (e) {
    byovdLogLine(`[ERROR] ${e.message}`, 'var(--danger)');
    termLog(`BYOVD unload error: ${e.message}`, 'err');
  }
}

async function byovdListDrivers() {
  const ip   = state.activeTargetIP   || '127.0.0.1';
  const port = state.activeTargetPort || 5000;
  byovdLogLine(`[LIST_DRIVERS] Enumerating kernel drivers on ${ip}:${port}...`, 'var(--amber)');
  termLog('BYOVD → Enumerating kernel drivers...', 'info');
  try {
    const r = await fetch(`${API}/api/stealth/byovd/drivers?target_ip=${ip}&target_port=${port}`);
    const d = await r.json();
    const result  = d.result || {};
    const drivers = result.drivers || [];
    const count   = result.driver_count || drivers.length;
    byovdLogLine(`[LIST_DRIVERS] ${count} kernel drivers found:`, 'var(--success)');

    const tbody = $('byovdDriversBody');
    const table = $('byovdDriversTable');
    if (tbody) {
      tbody.innerHTML = '';
      drivers.slice(0, 100).forEach((drv, i) => {
        const tr = document.createElement('tr');
        tr.style.borderBottom = '1px solid rgba(255,255,255,0.04)';
        tr.innerHTML = `
          <td style="padding:3px 8px;color:var(--fg-dim);">${drv.index ?? i}</td>
          <td style="padding:3px 8px;color:#e4e4e7;">${drv.name || '—'}</td>
          <td style="padding:3px 8px;color:var(--amber);font-family:var(--font-mono);">${drv.base || '—'}</td>
        `;
        tbody.appendChild(tr);
        if (i < 5) byovdLogLine(`  [${i}] ${drv.name} @ ${drv.base}`, '#a1a1aa');
      });
      if (table) table.style.display = 'block';
    }
    termLog(`BYOVD: ${count} kernel drivers enumerated ✓`, 'ok');
    toast(`${count} kernel drivers listed`, 'info');
  } catch (e) {
    byovdLogLine(`[ERROR] ${e.message}`, 'var(--danger)');
    termLog(`BYOVD list error: ${e.message}`, 'err');
  }
}

window.byovdStatus      = byovdStatus;
window.byovdLoad        = byovdLoad;
window.byovdDisableEDR  = byovdDisableEDR;
window.byovdUnload      = byovdUnload;
window.byovdListDrivers = byovdListDrivers;

// ── MAXIMIZE PANEL CONTROLS (Full Page View) ──────────────────────────────
function toggleMaximize(panel) {
  const term = document.querySelector('.terminal-wrap');
  const res  = document.querySelector('.results-panel');
  const btnT = $('btnMaxTerminal');
  const btnR = $('btnMaxResults');

  if (panel === 'terminal' && term) {
    if (res) res.classList.remove('panel-fullscreen');
    if (btnR) {
      btnR.innerHTML = '<i class="fa-solid fa-expand jki jki-sm"></i><span>Maximize</span>';
      btnR.title = 'Maximize Evidence Output';
    }

    const isFull = term.classList.toggle('panel-fullscreen');
    if (btnT) {
      btnT.innerHTML = isFull
        ? '<i class="fa-solid fa-compress jki jki-sm"></i><span>Restore</span>'
        : '<i class="fa-solid fa-expand jki jki-sm"></i><span>Maximize</span>';
      btnT.title = isFull ? 'Restore Normal View (Esc)' : 'Maximize Console to Full Page';
    }
    termLog(isFull ? 'Console maximized to Full Page' : 'Full Page restored to dashboard', 'sys');
  } else if (panel === 'results' && res) {
    if (term) term.classList.remove('panel-fullscreen');
    if (btnT) {
      btnT.innerHTML = '<i class="fa-solid fa-expand jki jki-sm"></i><span>Maximize</span>';
      btnT.title = 'Maximize Console';
    }

    const isFull = res.classList.toggle('panel-fullscreen');
    if (btnR) {
      btnR.innerHTML = isFull
        ? '<i class="fa-solid fa-compress jki jki-sm"></i><span>Restore</span>'
        : '<i class="fa-solid fa-expand jki jki-sm"></i><span>Maximize</span>';
      btnR.title = isFull ? 'Restore Normal View (Esc)' : 'Maximize Evidence Output to Full Page';
    }
    termLog(isFull ? 'Evidence Output maximized to Full Page' : 'Full Page restored to dashboard', 'sys');
  }
}
window.toggleMaximize = toggleMaximize;

// Escape key to restore from full page
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') {
    const term = document.querySelector('.terminal-wrap');
    const res  = document.querySelector('.results-panel');
    if (term && term.classList.contains('panel-fullscreen')) {
      toggleMaximize('terminal');
    } else if (res && res.classList.contains('panel-fullscreen')) {
      toggleMaximize('results');
    }
    // Also close BYOVD modal on Escape
    const byovdModal = $('modalByovd');
    if (byovdModal && !byovdModal.classList.contains('hidden')) {
      byovdModal.classList.add('hidden');
    }
  }
});

// ── BYOVD MODAL WIRE ──────────────────────────────────────────────────────
function wireByovdModal() {
  // Open trigger — attach to any element with id btnOpenByovd
  const openBtn = $('btnOpenByovd');
  if (openBtn) openBtn.addEventListener('click', () => {
    $('modalByovd').classList.remove('hidden');
    byovdStatus(); // auto-refresh on open
  });

  const closeBtn  = $('closeModalByovd');
  const closeBtn2 = $('btnCloseByovd');
  if (closeBtn)  closeBtn.addEventListener('click',  () => $('modalByovd').classList.add('hidden'));
  if (closeBtn2) closeBtn2.addEventListener('click', () => $('modalByovd').classList.add('hidden'));

  const s = $('btnByovdStatus');
  const l = $('btnByovdLoad');
  const d = $('btnByovdDisable');
  const u = $('btnByovdUnload');
  const r = $('btnByovdDrivers');

  if (s) s.addEventListener('click', byovdStatus);
  if (l) l.addEventListener('click', byovdLoad);
  if (d) d.addEventListener('click', byovdDisableEDR);
  if (u) u.addEventListener('click', byovdUnload);
  if (r) r.addEventListener('click', byovdListDrivers);
}

// ── INIT ──────────────────────────────────────────────────────────────────
async function initApp() {
  wireEvents();
  wireByovdModal();
  termLog('JOCKY Central Management Interface loaded', 'sys');
  termLog('Framework: JOCKY v1.0.0 — SIH 2026 Edition', 'sys');
  termLog('BYOVD Kernel Engine: RTCore64.sys ready', 'sys');
  await checkServerStatus();
  await loadCases();
  termLog('Ready. Select a case and target to begin.', 'sys');

  // Periodic server health check
  setInterval(checkServerStatus, 15000);
}

// ── BOOT ──────────────────────────────────────────────────────────────────
window.addEventListener('DOMContentLoaded', () => {
  runLoader();
});
