/* OmniRecon Web UI — client-side interactions */

// ── SSE scan streaming ────────────────────────────────────────────────────────

let _activeSource = null;

function startScanStream(token) {
  const terminal  = document.getElementById('terminal');
  const statusEl  = document.getElementById('scan-status');
  const statusHdr = document.getElementById('scan-status-hdr');
  const startBtn  = document.getElementById('start-btn');
  const panel     = document.getElementById('terminal-panel');

  if (!terminal) return;
  if (panel) panel.style.display = 'block';
  if (startBtn) startBtn.disabled = true;

  function setStatus(msg) {
    if (statusEl)  statusEl.textContent  = msg;
    if (statusHdr) statusHdr.textContent = msg;
  }

  setStatus('Running…');

  // Save token so we can reconnect if user navigates away
  sessionStorage.setItem('activeToken', token);

  if (_activeSource) _activeSource.close();
  _activeSource = new EventSource('/api/scan/' + token + '/stream');

  _activeSource.onmessage = function(e) {
    const line = e.data;

    if (line === '[DONE]') {
      _activeSource.close();
      _activeSource = null;
      sessionStorage.removeItem('activeToken');
      setStatus('Complete. Redirecting to dashboard…');
      setTimeout(() => { window.location.href = '/'; }, 1800);
      return;
    }

    if (line === '[scan not found]') {
      _activeSource.close();
      _activeSource = null;
      sessionStorage.removeItem('activeToken');
      setStatus('Scan stream not found.');
      if (startBtn) startBtn.disabled = false;
      return;
    }

    const span = document.createElement('span');
    span.textContent = line + '\n';

    if      (line.includes('✓') || line.includes('[MONITOR]')) span.className = 't-ok';
    else if (line.includes('⚠') || line.includes('WARN'))      span.className = 't-warn';
    else if (line.includes('✗') || line.includes('Error'))     span.className = 't-err';
    else if (line.match(/^\s+\[\d/))                            span.className = 't-accent';

    terminal.appendChild(span);
    terminal.scrollTop = terminal.scrollHeight;
  };

  _activeSource.onerror = function() {
    // Connection dropped — check if scan is still running
    _activeSource.close();
    _activeSource = null;
    fetch('/api/scan/' + token + '/status')
      .then(r => r.json())
      .then(s => {
        if (s.running) {
          setStatus('Stream interrupted — reconnecting…');
          setTimeout(() => startScanStream(token), 2000);
        } else {
          setStatus('Scan finished (exit ' + s.exit_code + '). Redirecting…');
          sessionStorage.removeItem('activeToken');
          setTimeout(() => { window.location.href = '/'; }, 2000);
        }
      })
      .catch(() => {
        setStatus('Connection lost.');
        if (startBtn) startBtn.disabled = false;
      });
  };
}

// On page load: resume active scan if token is in sessionStorage
document.addEventListener('DOMContentLoaded', function() {
  // Explicit token embedded in page (from URL param)
  const meta = document.getElementById('scan-token');
  if (meta) {
    startScanStream(meta.dataset.token);
    return;
  }

  // Reconnect to an in-progress scan from a previous page visit
  const saved = sessionStorage.getItem('activeToken');
  if (saved && document.getElementById('terminal')) {
    fetch('/api/scan/' + saved + '/status')
      .then(r => r.json())
      .then(s => {
        if (s.running) {
          startScanStream(saved);
        } else {
          sessionStorage.removeItem('activeToken');
        }
      })
      .catch(() => sessionStorage.removeItem('activeToken'));
  }
});

// ── Scan form submission ──────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', function() {
  const form = document.getElementById('scan-form');
  if (!form) return;

  form.addEventListener('submit', async function(e) {
    e.preventDefault();

    const authCb = document.getElementById('auth-cb');
    const discoverCb = form.querySelector('[name="discover"]');
    const authMsg = document.getElementById('auth-required-msg');

    // Require auth for any active scanning
    if (discoverCb && discoverCb.checked && authCb && !authCb.checked) {
      if (authMsg) authMsg.style.display = 'block';
      return;
    }
    if (authMsg) authMsg.style.display = 'none';

    const btn = document.getElementById('start-btn');
    if (btn) btn.disabled = true;

    // Collect all form values
    const data = {};
    // Set all checkboxes to false first
    form.querySelectorAll('input[type="checkbox"]').forEach(cb => {
      data[cb.name] = false;
    });
    // Then set checked ones to true, and collect text/select values
    new FormData(form).forEach((v, k) => {
      const el = form.querySelector('[name="' + k + '"]');
      if (el && el.type === 'checkbox') data[k] = true;
      else data[k] = v;
    });

    const resp = await fetch('/api/scan/start', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(data),
    });

    const json = await resp.json();
    if (json.error) {
      alert('Error: ' + json.error);
      if (btn) btn.disabled = false;
      return;
    }

    startScanStream(json.token);
  });
});

// ── Asset ack / ignore ────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', function() {
  document.querySelectorAll('[data-action]').forEach(btn => {
    btn.addEventListener('click', async function(e) {
      e.stopPropagation();
      const action = btn.dataset.action;
      const key    = btn.dataset.key;
      const row    = btn.closest('tr');

      const resp = await fetch('/api/assets/' + encodeURIComponent(key) + '/' + action, {
        method: 'POST',
      });

      if (resp.ok) {
        const badge = row && row.querySelector('[class^="badge badge-"]');
        if (badge) {
          badge.className = 'badge badge-' + (action === 'ack' ? 'trusted' : 'ignored');
          badge.textContent = action === 'ack' ? 'trusted' : 'ignored';
        }
        row && row.querySelectorAll('[data-action]').forEach(b => b.style.display = 'none');
      }
    });
  });
});

// ── Expandable history rows ───────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', function() {
  document.querySelectorAll('.scan-row').forEach(row => {
    row.addEventListener('click', function() {
      const id  = row.dataset.scanId;
      const sub = document.getElementById('sub-' + id);
      if (!sub) return;
      row.classList.toggle('open');
      sub.classList.toggle('open');
    });
  });
});
