const $ = id => document.getElementById(id);

// ── Terminal typewriter effect ──────────────────────────────────────────────
const termMessages = [
  'Awaiting authentication...',
  'Encrypting channel... AES-256',
  'Verifying agent credentials...',
  'Loading operational database...',
  'All systems nominal.',
];
let termIdx = 0, charIdx = 0;
const termEl = $('terminal-text');

function typeNext() {
  const msg = termMessages[termIdx % termMessages.length];
  if (charIdx <= msg.length) {
    termEl.textContent = msg.slice(0, charIdx++);
    setTimeout(typeNext, 55);
  } else {
    setTimeout(() => { charIdx = 0; termIdx++; typeNext(); }, 2200);
  }
}
if (termEl) typeNext();

// ── Random session ID ────────────────────────────────────────────────────────
const sessionEl = $('session-id');
if (sessionEl) {
  sessionEl.textContent =
    Math.random().toString(36).slice(2, 10).toUpperCase() + '-' +
    Date.now().toString(16).toUpperCase().slice(-6);
}

// ── SQL injection detection heuristic ───────────────────────────────────────
// Flags common SQL meta-characters that indicate an injection attempt
const INJECT_RE = /['";]|--|\bOR\b|\bAND\b|\b1=1\b|\bDROP\b|\bSELECT\b|\bUNION\b/i;

function looksInjected(val) {
  return INJECT_RE.test(val);
}

// Escape HTML for safe DOM insertion
function esc(str) {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// Highlight injection characters in a value string (red)
function highlightVal(val) {
  if (!looksInjected(val)) {
    return `<span class="sql-val">${esc(val)}</span>`;
  }
  // Colour the whole thing red if it contains injection chars
  return `<span class="sql-inject">${esc(val)}</span>`;
}

// ── Live SQL query preview (updates on every keypress) ──────────────────────
const monitor   = $('sql-monitor');
const badge     = $('sql-status-badge');
const evalLine  = $('sql-eval-line');
const sqUser    = $('sq-user');
const sqPass    = $('sq-pass');

function updateSqlPreview() {
  const userVal = $('username').value;
  const passVal = $('password').value;

  // Rebuild the coloured pre block
  const pre = monitor.querySelector('#sql-preview');
  pre.innerHTML =
    `<span class="sql-kw">SELECT</span> * <span class="sql-kw">FROM</span> users\n` +
    `<span class="sql-kw">WHERE</span>  password = '${highlightVal(passVal)}'\n` +
    `  <span class="sql-kw">AND</span>  username = '${highlightVal(userVal)}'`;

  const injected = looksInjected(userVal) || looksInjected(passVal);

  if (injected) {
    monitor.classList.add('sql-monitor--danger');
    badge.textContent = 'INJECTION DETECTED';
    badge.classList.add('sql-monitor-badge--danger');
    evalLine.innerHTML =
      `<span class="eval-bypass">⚠ SQL meta-characters detected — query logic may be altered</span>`;
  } else {
    monitor.classList.remove('sql-monitor--danger');
    badge.textContent = 'SAFE';
    badge.classList.remove('sql-monitor-badge--danger');
    evalLine.innerHTML =
      `<span class="eval-safe">✔ No injection characters detected</span>`;
  }
}

$('username').addEventListener('input', updateSqlPreview);
$('password').addEventListener('input', updateSqlPreview);
updateSqlPreview(); // initial render

// ── Show/hide password ──────────────────────────────────────────────────────
$('show-password').onclick = () => {
  const show = $('password').type === 'password';
  $('password').type = show ? 'text' : 'password';
  $('show-password').textContent = show ? 'HIDE' : 'SHOW';
  $('show-password').setAttribute('aria-label', show ? 'Hide password' : 'Show password');
};

// ── Login form submit ───────────────────────────────────────────────────────
$('login-form').addEventListener('submit', async event => {
  event.preventDefault();
  $('submit').disabled = true;
  $('error').hidden = true;

  try {
    const response = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: $('username').value,
        password: $('password').value,
      }),
    });
    const data = await response.json();
    if (!response.ok) throw Error('Unable to authenticate. Please try again.');
    if (!data.ok) {
      // Show the failed query in the monitor footer
      evalLine.innerHTML =
        `<span class="eval-error">✘ Query returned 0 rows — authentication failed</span>`;
      throw Error(data.message);
    }

    // ── Success: populate profile ──────────────────────────────────────────
    $('name').textContent = data.user.name.split(' ').slice(-1)[0];
    $('account-name').textContent = data.user.username;
    $('account-email').textContent = data.user.email;

    // Show the actual executed SQL in the profile panel
    const execPre = $('sql-executed-query');
    if (execPre && data.sql) {
      // Colour keyword tokens for display
      const coloured = esc(data.sql)
        .replace(/\b(SELECT|FROM|WHERE|AND|OR)\b/g, '<span class="sql-kw">$1</span>');
      execPre.innerHTML = coloured;

      // Label whether it was a bypass or a legit login
      const wasInjected = looksInjected($('username').value) || looksInjected($('password').value);
      const resultBadge = $('result-badge');
      if (resultBadge) {
        resultBadge.textContent = wasInjected ? '🔓 BYPASSED' : '✔ LEGITIMATE';
        resultBadge.style.color = wasInjected ? 'var(--accent-red)' : 'var(--accent-green)';
      }
    }

    $('password').value = '';
    $('login-panel').hidden = true;
    $('profile').hidden = false;

    if (termEl) termEl.textContent = `ACCESS GRANTED — ${data.user.username.toUpperCase()}`;

  } catch (error) {
    $('error').textContent = error instanceof TypeError
      ? '⚠ CONNECTION ERROR — Unable to reach auth server.'
      : `⚠ ${error.message}`;
    $('error').hidden = false;
  } finally {
    $('submit').disabled = false;
  }
});

// ── Logout ──────────────────────────────────────────────────────────────────
$('logout').onclick = () => {
  $('profile').hidden = true;
  $('login-panel').hidden = false;
  $('login-form').reset();
  $('password').type = 'password';
  $('show-password').textContent = 'SHOW';
  $('show-password').setAttribute('aria-label', 'Show password');
  $('error').hidden = true;
  $('username').focus();
  updateSqlPreview();

  if (termEl) { charIdx = 0; termIdx = 0; typeNext(); }
};
