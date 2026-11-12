const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { URL } = require('url');

const PORT = 3001;
const ALLOWED_ORIGIN = `http://localhost:${PORT}`;
const COOKIE = 'sid_sec';

const DEFAULT_USERS = {
  alice: { password: 'alice123', email: 'alice@example.com' },
  bob:   { password: 'bob123',   email: 'bob@example.com' },
};

const users = {
  alice: { ...DEFAULT_USERS.alice, lastUpdated: 'Never' },
  bob:   { ...DEFAULT_USERS.bob,   lastUpdated: 'Never' },
};
const sessions = {}; // sid -> { username, csrfToken }

const escapeHtml = (str) =>
  String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');

const view = (name, vars = {}) => {
  let html = fs.readFileSync(path.join(__dirname, 'views', name), 'utf8');
  for (const [k, v] of Object.entries(vars)) {
    html = html.split(`{{${k}}}`).join(v);
  }
  return html;
};

const parseCookies = (req) =>
  Object.fromEntries(
    (req.headers.cookie || '')
      .split(';')
      .filter(Boolean)
      .map((c) => {
        const i = c.indexOf('=');
        return [c.slice(0, i).trim(), c.slice(i + 1).trim()];
      })
  );

const currentSession = (req) => sessions[parseCookies(req)[COOKIE]];

const send = (res, code, body, headers = {}) => {
  res.writeHead(code, { 'Content-Type': 'text/html; charset=utf-8', ...headers });
  res.end(body);
};

const redirect = (res, to, headers = {}) => {
  res.writeHead(302, { Location: to, ...headers });
  res.end();
};

const readBody = (req) =>
  new Promise((resolve) => {
    let data = '';
    req.on('data', (c) => (data += c));
    req.on('end', () => resolve(new URLSearchParams(data)));
  });

const tokensMatch = (expected, actual) => {
  if (typeof expected !== 'string' || typeof actual !== 'string') return false;
  const a = Buffer.from(expected, 'utf8');
  const b = Buffer.from(actual, 'utf8');
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
};

const isValidOrigin = (req) => {
  const origin = req.headers.origin;
  if (origin) return origin === ALLOWED_ORIGIN;
  const referer = req.headers.referer;
  if (referer) return referer.startsWith(`${ALLOWED_ORIGIN}/`);
  return false;
};

const sendBlocked = (res, reason) =>
  send(
    res,
    403,
    `<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>403 Forbidden — CSRF Blocked</title>
<style>
  body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#f8fafc;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;padding:20px}
  .box{background:#fff;border:2px solid #16a34a;border-radius:14px;padding:32px;max-width:520px;box-shadow:0 12px 30px rgba(0,0,0,.08)}
  .tag{display:inline-block;background:#dcfce7;color:#15803d;font-weight:700;font-size:12px;padding:4px 10px;border-radius:999px;margin-bottom:10px}
  h1{margin:0 0 10px;color:#0f172a;font-size:22px}
  p{color:#475569;line-height:1.6;font-size:14px}
  code{background:#f1f5f9;padding:2px 6px;border-radius:4px;color:#b91c1c}
  a{display:inline-block;margin-top:14px;padding:10px 16px;background:#16a34a;color:#fff;text-decoration:none;border-radius:8px;font-weight:600;font-size:14px}
</style></head>
<body><div class="box">
  <span class="tag">403 FORBIDDEN · SECURED APP</span>
  <h1>🛡️ CSRF Attack Blocked!</h1>
  <p>The server rejected this state-changing <code>POST</code> request and protected your account.</p>
  <p><strong>Reason:</strong> ${escapeHtml(reason)}</p>
  <a href="/profile">Return to Secured Profile</a>
</div></body></html>`
  );

http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const session = currentSession(req);
  const user = session ? session.username : null;
  console.log(
    `[SECURE] ${req.method} ${url.pathname}  user=${user || '-'}  origin=${req.headers.origin || '-'}  referer=${req.headers.referer || '-'}`
  );

  if (req.method === 'GET' && url.pathname === '/') {
    return redirect(res, user ? '/profile' : '/login');
  }

  if (req.method === 'GET' && url.pathname === '/login') {
    return send(res, 200, view('login.html', { errorBlock: '' }));
  }

  if (req.method === 'POST' && url.pathname === '/login') {
    const body = await readBody(req);
    const u = body.get('username');
    const p = body.get('password');
    if (users[u] && users[u].password === p) {
      const sid = crypto.randomBytes(24).toString('hex');
      const csrfToken = crypto.randomBytes(32).toString('hex');
      sessions[sid] = { username: u, csrfToken };
      // SECURED: SameSite=Strict prevents cross-site cookie transmission; HttpOnly prevents JS access
      return redirect(res, '/profile', {
        'Set-Cookie': `${COOKIE}=${sid}; HttpOnly; Path=/; SameSite=Strict`,
      });
    }
    return send(
      res,
      401,
      view('login.html', { errorBlock: '<div class="alert error">Invalid username or password</div>' })
    );
  }

  if (req.method === 'GET' && url.pathname === '/api/account') {
    if (!session) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'Unauthorized' }));
    }
    const account = users[user];
    res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
    return res.end(JSON.stringify({
      user,
      email: account.email,
      password: account.password,
      lastUpdated: account.lastUpdated,
    }));
  }

  if (req.method === 'GET' && url.pathname === '/profile') {
    if (!session) return redirect(res, '/login');
    const account = users[user];
    const updated = url.searchParams.get('updated') === '1';
    const reset = url.searchParams.get('reset') === '1';

    let banner = '';
    if (updated) {
      banner = `<div class="alert ok"><strong>Account Updated Safely!</strong> Verified Anti-CSRF token &amp; Origin. Email is now <code>${escapeHtml(account.email)}</code> (${escapeHtml(account.lastUpdated)}).</div>`;
    } else if (reset) {
      banner = `<div class="alert info"><strong>Demo Reset:</strong> Account restored to default email and password.</div>`;
    }

    return send(
      res,
      200,
      view('profile.html', {
        user: escapeHtml(user),
        email: escapeHtml(account.email),
        password: escapeHtml(account.password),
        lastUpdated: escapeHtml(account.lastUpdated),
        csrfToken: escapeHtml(session.csrfToken),
        csrfPreview: escapeHtml(session.csrfToken.slice(0, 16) + '...'),
        banner,
      })
    );
  }

  // SECURED ENDPOINT: Validates Origin/Referer AND per-session Anti-CSRF token
  if (req.method === 'POST' && url.pathname === '/account/update') {
    if (!session) {
      console.log('[SECURE] >>> BLOCKED: No valid session cookie (SameSite=Strict or not logged in)');
      return sendBlocked(res, 'Missing or unauthenticated session (SameSite=Strict blocked cross-site cookie, or you are not logged in).');
    }

    if (!isValidOrigin(req)) {
      console.log(`[SECURE] >>> BLOCKED: Invalid Origin/Referer (${req.headers.origin || req.headers.referer || 'none'})`);
      return sendBlocked(res, `Untrusted Origin (${req.headers.origin || req.headers.referer || 'none'}). Expected ${ALLOWED_ORIGIN}.`);
    }

    const body = await readBody(req);
    const submittedToken = body.get('csrfToken') || '';
    if (!tokensMatch(session.csrfToken, submittedToken)) {
      console.log('[SECURE] >>> BLOCKED: Missing or invalid Anti-CSRF token');
      return sendBlocked(res, 'Missing or invalid Anti-CSRF synchronizer token.');
    }

    const newEmail = (body.get('email') || '').trim();
    const newPassword = (body.get('newPassword') || '').trim();
    if (newEmail) users[user].email = newEmail;
    if (newPassword) users[user].password = newPassword;
    users[user].lastUpdated = new Date().toLocaleTimeString();

    console.log(
      `[SECURE] Account updated legitimately for "${user}": email="${users[user].email}"`
    );
    return redirect(res, '/profile?updated=1');
  }

  if (req.method === 'POST' && url.pathname === '/account/reset') {
    if (!session) return redirect(res, '/login');
    const body = await readBody(req);
    if (!isValidOrigin(req) || !tokensMatch(session.csrfToken, body.get('csrfToken') || '')) {
      return sendBlocked(res, 'Missing or invalid Anti-CSRF token on reset.');
    }
    if (DEFAULT_USERS[user]) {
      users[user].email = DEFAULT_USERS[user].email;
      users[user].password = DEFAULT_USERS[user].password;
      users[user].lastUpdated = 'Never';
    }
    return redirect(res, '/profile?reset=1');
  }

  if (req.method === 'GET' && url.pathname === '/logout') {
    delete sessions[parseCookies(req)[COOKIE]];
    return redirect(res, '/login', { 'Set-Cookie': `${COOKIE}=; Max-Age=0; Path=/` });
  }

  send(res, 404, '<h1>404 Not Found</h1>');
}).listen(PORT, () => console.log(`Secured app running on http://localhost:${PORT}`));
