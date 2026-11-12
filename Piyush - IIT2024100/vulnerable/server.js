const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { URL } = require('url');

const PORT = 3000;
const COOKIE = 'sid_vuln';

const DEFAULT_USERS = {
  alice: { password: 'alice123', email: 'alice@example.com' },
  bob:   { password: 'bob123',   email: 'bob@example.com' },
};

const users = {
  alice: { ...DEFAULT_USERS.alice, lastUpdated: 'Never' },
  bob:   { ...DEFAULT_USERS.bob,   lastUpdated: 'Never' },
};
const sessions = {}; // sid -> username

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

const currentUser = (req) => sessions[parseCookies(req)[COOKIE]];

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

http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const user = currentUser(req);
  console.log(
    `[VULN] ${req.method} ${url.pathname}  user=${user || '-'}  origin=${req.headers.origin || '-'}  referer=${req.headers.referer || '-'}`
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
      sessions[sid] = u;
      // VULNERABLE: No SameSite=Strict/Lax attribute set
      return redirect(res, '/profile', { 'Set-Cookie': `${COOKIE}=${sid}; HttpOnly; Path=/` });
    }
    return send(
      res,
      401,
      view('login.html', { errorBlock: '<div class="alert error">Invalid username or password</div>' })
    );
  }

  if (req.method === 'GET' && url.pathname === '/api/account') {
    if (!user) {
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
    if (!user) return redirect(res, '/login');
    const account = users[user];
    const updated = url.searchParams.get('updated') === '1';
    const reset = url.searchParams.get('reset') === '1';

    let banner = '';
    if (updated) {
      banner = `<div class="alert warn"><strong>Account Updated!</strong> Email is now <code>${escapeHtml(account.email)}</code> and password was updated (${escapeHtml(account.lastUpdated)}).</div>`;
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
        banner,
      })
    );
  }

  // VULNERABLE ENDPOINT: Accepts cross-origin POST with only a session cookie.
  // No Anti-CSRF token, no Origin/Referer check, no current password verification.
  if (req.method === 'POST' && url.pathname === '/account/update') {
    if (!user) return redirect(res, '/login');
    const body = await readBody(req);
    const newEmail = (body.get('email') || '').trim();
    const newPassword = (body.get('newPassword') || '').trim();

    if (newEmail) users[user].email = newEmail;
    if (newPassword) users[user].password = newPassword;
    users[user].lastUpdated = new Date().toLocaleTimeString();

    console.log(
      `[VULN] >>> ACCOUNT UPDATED for "${user}": email="${users[user].email}", password="${users[user].password}" (origin=${req.headers.origin || '-'})`
    );
    return redirect(res, '/profile?updated=1');
  }

  if (req.method === 'POST' && url.pathname === '/account/reset') {
    if (!user) return redirect(res, '/login');
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
}).listen(PORT, () => console.log(`Vulnerable app running on http://localhost:${PORT}`));
