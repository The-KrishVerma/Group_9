# CSRF – POST-Based Account Takeover (Email & Password Change)

A clean, dependency-free Node.js demonstration comparing a **vulnerable** web app, an **attacker** site, and a **secured** web app.

## Project structure

```
csrf-assignment/
├── vulnerable/   server.js + views/{login,profile}.html   -> http://localhost:3000
├── attacker/     attacker.html + server.js                -> http://localhost:4000
├── secured/      server.js + views/{login,profile}.html   -> http://localhost:3001
├── package.json
└── README.md
```

No `npm install` needed: only built-in Node.js modules are used (Node 16+).

## How to run

Open three terminals in the project folder:

```bash
node vulnerable/server.js    # Vulnerable app on port 3000
node secured/server.js       # Secured app on port 3001
node attacker/server.js      # Attacker site on port 4000
```

Demo users: `alice / alice123`, `bob / bob123`.

## Demonstration steps

### 1. Exploit (Vulnerable App — Port 3000)
1. Open `http://localhost:3000` and log in as `alice / alice123`.
2. Note the current email (`alice@example.com`) and password (`alice123`) on the dashboard.
3. In the **same browser**, open `http://localhost:4000` (the attacker's lure page).
4. Click **Claim Prize Now!**.
   - A hidden `<form method="POST" action="http://localhost:3000/account/update">` is submitted.
   - The browser automatically attaches `alice`'s `sid_vuln` session cookie.
   - You are redirected back to `http://localhost:3000/profile?updated=1`, and the UI immediately shows:
     - **Email:** `hacker@evil.com`
     - **Password:** `hacked123`
   - The vulnerable server console logs `[VULN] >>> ACCOUNT UPDATED for "alice"`.
5. Click **Reset Account to Default** on the dashboard whenever you want to re-run the demo.

### 2. Mitigation (Secured App — Port 3001)
1. Open `http://localhost:3001` and log in as `alice / alice123`.
2. Go back to `http://localhost:4000` and click **Test Same Attack on Secured App (:3001)**.
3. Result: **403 Forbidden — CSRF Attack Blocked!**
   - The server rejects the request because the `Origin` (`http://localhost:4000`) is untrusted and the per-session `csrfToken` is missing.
   - `alice`'s email and password remain unchanged.
4. Legitimate updates from `http://localhost:3001/profile` still work because the form includes the secret `csrfToken` and comes from `http://localhost:3001`.

## Root cause (Vulnerable)
- `POST /account/update` authenticates solely via the `sid_vuln` session cookie, which the browser attaches automatically.
- Moving from `GET` to `POST` alone does **not** prevent CSRF, because an attacker can submit a hidden HTML `<form method="POST">` cross-origin.

## Defenses implemented (Secured)
1. **Anti-CSRF Synchronizer Token:** Each session generates a cryptographically random `csrfToken` (`crypto.randomBytes(32)`), embedded in forms as a hidden field and verified on every `POST` using `crypto.timingSafeEqual`. An attacker on `:4000` cannot read this token due to the Same-Origin Policy.
2. **Origin / Referer Validation:** `POST` requests must originate from `http://localhost:3001`.
3. **SameSite=Strict Cookie:** `sid_sec` is issued with `SameSite=Strict; HttpOnly; Path=/` to block cross-site cookie transmission.
