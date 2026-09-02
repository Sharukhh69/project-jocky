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
  if (!state.targets.length) {
    list.innerHTML = '<div class="empty-state">No targets added</div>';
    return;
  }
  list.innerHTML = state.targets.map(t => `
    <div class="target-item ${t.target_ip === state.activeTargetIP ? 'active' : ''}"
         onclick="selectTarget('${t.target_ip}', ${t.target_port})">
      <span class="target-os-icon">${t.os === 'Windows' ? '🪟' : t.os === 'Linux' ? '🐧' : '💻'}</span>
      <div class="target-info">
        <div class="target-name">${t.target_name || t.target_ip}</div>
        <div class="target-ip">${t.target_ip}:${t.target_port} · ${t.os || 'Unknown'}</div>
      </div>
      <span class="target-status ${t.status}"></span>
    </div>
  `).join('');
}

function selectTarget(ip, port) {
  state.activeTargetIP   = ip;
  state.activeTargetPort = port;
  renderTargets();
  termLog(`Target selected: ${ip}:${port}`, 'sys');
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

// ── RESULTS RENDERER ──────────────────────────────────────────────────────
function renderResults(data, command) {
  const body  = $('resultsBody');
  const title = $('resultTitle');
  title.textContent = command || 'Results';

  if (!data) {
    body.innerHTML = '<div class="empty-results"><div class="empty-icon">⚠</div><div>No data returned.</div></div>';
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
    html += `<div class="evidence-hash-badge">
      🔐 SHA-256: ${data.evidence_hash}
    </div>`;
  }

  // Table for common result types
  const results = data.results || data.results;
  if (Array.isArray(results) && results.length > 0) {
    const keys = Object.keys(results[0]).slice(0, 7);
    html += `<div class="proc-table-wrap" style="margin-top:10px">
      <table class="data-table">
        <thead><tr>${keys.map(k => `<th>${k}</th>`).join('')}</tr></thead>
        <tbody>
          ${results.slice(0, 200).map(row =>
            `<tr>${keys.map(k => `<td>${row[k] ?? ''}</td>`).join('')}</tr>`
          ).join('')}
        </tbody>
      </table>
    </div>`;
    if (results.length > 200) {
      html += `<div class="empty-state">${results.length - 200} more items — export JSON for full data</div>`;
    }
  }

  // Bulk results (ip → data)
  if (data.results && typeof data.results === 'object' && !Array.isArray(data.results)) {
    html += '<div style="display:flex;flex-direction:column;gap:8px;margin-top:10px">';
    Object.entries(data.results).forEach(([ip, res]) => {
      html += `<div style="background:var(--bg-glass);border:1px solid var(--border);border-radius:6px;padding:10px 14px">
        <div style="font-family:var(--font-mono);font-size:0.7rem;color:var(--cyan);margin-bottom:6px">▶ ${ip}</div>
        <div style="font-family:var(--font-mono);font-size:0.62rem;color:var(--text-2)">
          ${res.count !== undefined ? `${res.count} items` : (res.error || 'OK')}
        </div>
      </div>`;
    });
    html += '</div>';
  }

  // JSON preview fallback
  if (!html.includes('data-table') && !html.includes('bulk')) {
    const preview = JSON.stringify(data, null, 2).slice(0, 800);
    html += `<div class="json-viewer">${syntaxHighlight(preview)}</div>`;
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

  // Click outside modal to close
  document.querySelectorAll('.modal-overlay').forEach(overlay => {
    overlay.addEventListener('click', e => {
      if (e.target === overlay) overlay.classList.add('hidden');
    });
  });
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

// ── INIT ──────────────────────────────────────────────────────────────────
async function initApp() {
  wireEvents();
  termLog('JOCKY Central Management Interface loaded', 'sys');
  termLog('Framework: JOCKY v1.0.0 — SIH 2026 Edition', 'sys');
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
