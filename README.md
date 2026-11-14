
# Group 9 – Web Server Security Assignment

**Indian Institute of Information Technology Allahabad**  
Department of Information Technology  
**Cyber Security (IT-30001) | Autumn Semester 2026**  
Instructor: Dr. Soumyadev Maity

**Assignment:** Exploitation and Mitigation of Four Vulnerability Categories  
(SQL Injection, OS Command Injection, Cross-Site Scripting, and Cross-Site Request Forgery)

> **Educational use only.** These applications are intentionally vulnerable and are designed for local demonstrations. Run them only on your own machine and do not expose them to public networks or test systems you do not own.

---

## 1. Video Demonstration

Group video: [Google Drive folder – Group 9 demo video]([https://drive.google.com/drive/u/1/folders/1UqiPTHgZ4gHbqMFIInNPc-ukGVCcjbTj](https://drive.google.com/drive/u/1/folders/1tQSRSo6csBleAgcxlFaMvYwT-cLpGdDu))

---

## 2. Ownership Declaration

| S. No. | Member Name | Roll Number | Category | Variant Implemented |
|:---:|---|---|---|---|
| 1 | Vishal | IIT2024058 | SQL Injection | Authentication bypass |
| 2 | Vardaan Gupta | IIT2024046 | OS Command Injection | Blind, time-based |
| 3 | Bhavay | IIT2024057 | Cross-Site Scripting (XSS) | Reflected XSS |
| 4 | Krish Verma | IIT2024050 | Cross-Site Scripting (XSS) | Stored XSS |
| 5 | Piyush | IIT2024100 | Cross-Site Request Forgery (CSRF) | POST-based account update (email and password change) |

**Group-size note:** The group has five members. XSS is implemented by two members using different variants: Reflected XSS and Stored XSS. All four required vulnerability categories are covered, and no two members implement the same variant.

---

## 3. Repository Structure

```text
Group-9-Cyber-Security/
├── Vishal - IIT2024058/
│   ├── app.py                         SQL injection lab
│   ├── static/                        Frontend assets
│   ├── tests/                         Authentication tests
│   ├── docs/ASSIGNMENT_REPORT.md
│   └── Screenshots/
│
├── Vardaan Gupta - IIT2024046/
│   ├── app.py                         Blind OS command injection
│   ├── templates/
│   │   ├── index.html
│   │   ├── vulnerable.html
│   │   └── secured.html
│   ├── requirements.txt
│   └── screenshots/
│
├── Bhavay - IIT2024057/
│   └── Bhavay - IIT2024057/
│       ├── app.py                     Reflected XSS lab
│       └── README.md
│
├── Krish Verma - IIT2024050/
│   ├── Stored_XSS_Vulnerable/
│   │   ├── app.py
│   │   ├── database.py
│   │   ├── templates/
│   │   ├── static/
│   │   ├── tests/
│   │   └── docs/
│   ├── Stored_XSS_Secured/
│   │   ├── app.py
│   │   ├── database.py
│   │   ├── templates/
│   │   ├── static/
│   │   ├── tests/
│   │   └── docs/
│   └── Screenshots/
│
└── Piyush - IIT2024100/
    ├── vulnerable/
    │   ├── server.js
    │   └── views/
    ├── secured/
    │   ├── server.js
    │   └── views/
    ├── attacker/
    │   ├── server.js
    │   └── attacker.html
    ├── package.json
    └── screenshots/
```

---

## 4. Summary of All Implemented Variants

### 4.1 SQL Injection – Authentication Bypass (Vishal, IIT2024058)

| Item | Details |
|---|---|
| **(a) Vulnerable code** | `authenticate()` in `app.py` constructs an SQL query using string interpolation. The query checks the password and username using values directly inserted into the SQL statement. |
| **(b) Exploit** | Enter username/Agent ID `' OR '1'='1` and any non-empty password, such as `wrong-password`. |
| **(c) Root cause** | User input is concatenated into the SQL query. The injected tautology changes the query's logic. In this implementation, the password condition appears before the username condition, and SQL operator precedence allows the final `OR '1'='1` expression to make the condition true. |
| **(d) Mitigation implemented** | Parameterized SQL query, binding submitted values separately so they are treated as data rather than SQL syntax. The secured authentication flow rejects the same injection payload. |
| **(e) Other mitigations (theory)** | Allow-list input validation, least-privilege database accounts, password hashing, and generic error messages with detailed diagnostics restricted to protected logs. |

**Run:** Python 3.10+ is required. The project uses the Python standard library.

```bash
cd "Vishal - IIT2024058"
python app.py
```

Open `http://127.0.0.1:8001`.

Demo accounts:
- `agent.chen` / `RedAlert#99`
- `director.hayes` / `Sector7!Top`

Tests:

```bash
python -m unittest discover -s tests -v
```

### 4.2 OS Command Injection – Blind, Time-Based (Vardaan Gupta, IIT2024046)

| Item | Details |
|---|---|
| **(a) Vulnerable code** | `/vulnerable` route in `app.py` builds a ping command using the submitted host and executes it with `shell=True`. Command output is suppressed. |
| **(b) Exploit** | On macOS/Linux, submit `127.0.0.1; sleep 3`. The additional command introduces a delay, which is observed through the elapsed response time rather than command output. |
| **(c) Root cause** | Untrusted input is concatenated into a command string interpreted by the shell. Shell metacharacters can therefore change the command sequence. |
| **(d) Mitigation implemented** | `/secured` validates the submitted value as an IP address or hostname and invokes ping using an argument vector with `shell=False`. The same injected input is rejected. |
| **(e) Other mitigations (theory)** | Avoid shell execution where possible, use argument-vector execution, allow-list validation, and run the application with least OS privilege. |

**Run:**

```bash
cd "Vardaan Gupta - IIT2024046"
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5001/`.

Demonstration:
1. Submit `127.0.0.1` on the vulnerable endpoint as the baseline.
2. Submit `127.0.0.1; sleep 3` and compare the elapsed time.
3. Submit the same payload on the secured endpoint; it should be rejected.
4. Submit `127.0.0.1` on the secured endpoint to verify normal functionality.

The time-based payload is intended for macOS/Linux shell syntax.

### 4.3 Reflected XSS (Bhavay, IIT2024057)

| Item | Details |
|---|---|
| **(a) Vulnerable code** | `/search/vulnerable` reflects the `q` query parameter into the HTML without encoding it (`query_display = query`). |
| **(b) Exploit** | Use a search query such as `<script>alert('XSS')</script>` on the vulnerable search page. |
| **(c) Root cause** | Request-controlled input is inserted into the HTML response without output encoding, allowing the browser to parse injected markup and event handlers. |
| **(d) Mitigation implemented** | `/search/safe` applies HTML escaping using `html_mod.escape(query)`, so the same payload is displayed as text rather than executed. |
| **(e) Other mitigations (theory)** | Framework auto-escaping, HTML sanitization for rich content, Content Security Policy (CSP), HttpOnly cookies, and safe DOM sinks such as `textContent`. |

**Run:**

```bash
cd "Bhavay - IIT2024057/Bhavay - IIT2024057"
pip install flask
python app.py
```

Open `http://127.0.0.1:5000/`.

The interface provides vulnerable and mitigated search modes, a request inspector, and an exploit drawer containing demonstration payloads.

### 4.4 Stored XSS (Krish Verma, IIT2024050)

| Item | Details |
|---|---|
| **(a) Vulnerable code** | `templates/discussion.html` in `Stored_XSS_Vulnerable` renders comments using `{{ c.comment \| safe }}`. |
| **(b) Exploit** | Submit a script payload as a discussion comment, for example `<script>alert('Stored XSS Successfully Executed');</script>`. |
| **(c) Root cause** | The comment is stored in SQLite and later rendered without HTML escaping because the Jinja2 `safe` filter disables auto-escaping for that value. The script can execute for visitors who open the discussion page. |
| **(d) Mitigation implemented** | The secured build renders the comment using `{{ c.comment }}`. Jinja2 auto-escaping encodes HTML-sensitive characters, so the same stored payload is displayed as harmless text. |
| **(e) Other mitigations (theory)** | Framework auto-escaping, HTML sanitization when rich HTML is required, CSP, HttpOnly cookies, and safe DOM sinks such as `textContent`. |

**Run the vulnerable build:**

```bash
cd "Krish Verma - IIT2024050/Stored_XSS_Vulnerable"
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 app.py
```

Open `http://127.0.0.1:5001`.

**Run the secured build in a separate terminal:**

```bash
cd "Krish Verma - IIT2024050/Stored_XSS_Secured"
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 app.py
```

Open `http://127.0.0.1:5002`.

The vulnerable and secured builds use separate SQLite database files. The comment is stored in both builds; the security difference is how it is rendered.

### 4.5 CSRF – POST-Based Account Update (Piyush, IIT2024100)

| Item | Details |
|---|---|
| **(a) Vulnerable code** | `vulnerable/server.js` accepts `POST /account/update` based on the session cookie and changes the user's email and password. |
| **(b) Exploit** | Log in to the vulnerable application, then open the attacker site in the same browser and click **Claim Prize Now!**. The attacker page submits a hidden cross-origin POST form to the vulnerable account-update endpoint. |
| **(c) Root cause** | The vulnerable endpoint relies on the automatically attached session cookie and does not verify that the state-changing request was intentionally initiated by the legitimate application. Changing a state-changing request from GET to POST alone does not prevent CSRF. |
| **(d) Mitigation implemented** | The secured application checks a per-session synchronizer CSRF token and validates the request Origin/Referer. Its session cookie also uses `SameSite=Strict` and `HttpOnly`. The same attacker request is rejected. |
| **(e) Other mitigations (theory)** | Synchronizer CSRF tokens, SameSite cookies, Origin/Referer validation, and re-authentication for sensitive account changes. |

**Run:** Node.js 16+ is required. No `npm install` is needed because the project uses built-in Node.js modules.

Open three terminals from `Piyush - IIT2024100`:

```bash
node vulnerable/server.js
```

```bash
node secured/server.js
```

```bash
node attacker/server.js
```

Endpoints:
- Vulnerable application: `http://localhost:3000`
- Secured application: `http://localhost:3001`
- Attacker site: `http://localhost:4000`

Demo users:
- `alice` / `alice123`
- `bob` / `bob123`

### Port Summary

| Project | Port |
|---|---:|
| SQL Injection – Vishal | 8001 |
| Blind OS Command Injection – Vardaan | 5001 |
| Reflected XSS – Bhavay | 5000 |
| Stored XSS – Krish (vulnerable) | 5001 |
| Stored XSS – Krish (secured) | 5002 |
| CSRF – Piyush (vulnerable) | 3000 |
| CSRF – Piyush (secured) | 3001 |
| CSRF – Piyush (attacker) | 4000 |

**Port conflict:** Vardaan's OS command injection app and Krish's vulnerable Stored XSS app both use port 5001. Run these applications one at a time, or change one application's port consistently in its code and documentation before running both simultaneously.

---

## 5. Evidence

Screenshots are included in the respective member ZIP folders:

- `Vishal - IIT2024058/Screenshots/`
- `Vardaan Gupta - IIT2024046/screenshots/`
- `Bhavay - IIT2024057/Bhavay - IIT2024057/` (the ZIP's top-level listing does not show a separate screenshots directory)
- `Krish Verma - IIT2024050/Screenshots/`
- `Piyush - IIT2024100/screenshots/`

---

## 6. Viva Readiness

Each member should be prepared to demonstrate and explain:

1. The vulnerable code path.
2. The exact demonstration payload.
3. The root cause of the vulnerability.
4. The mitigation implemented in the secured version.
5. Why the mitigation blocks the demonstrated payload.
6. Other relevant mitigations and their limitations.

---

## 7. Academic Integrity and Safety

All demonstrations are intended for the group's own local applications. Keep the servers bound to localhost and do not deploy intentionally vulnerable builds publicly. Use the applications only for the authorized classroom assignment.
