# ClearanceNet — local SQL injection lab

This intentionally vulnerable classroom demo uses an in-memory SQLite database
and binds its HTTP server to `127.0.0.1`. Run it locally only.

## Run

Python 3.10 or newer is required; no extra packages are needed.

```powershell
python app.py
```

Open <http://127.0.0.1:8001>. On Windows, `Start Demo.bat` starts the same
server. Press Ctrl+C to stop it.

## Demo accounts

| Agent ID | Access code |
|---|---|
| `agent.chen` | `RedAlert#99` |
| `director.hayes` | `Sector7!Top` |

## Demonstrate the screenshot's tautology

1. In Agent ID, enter `' OR '1'='1`.
2. Enter any non-empty access code, such as `wrong-password`.
3. Click **REQUEST ACCESS**.

The live query monitor shows the constructed SQL. Because the query puts the
password condition before the username condition, the injected expression is:

```sql
SELECT * FROM users
WHERE password = 'wrong-password' AND username = '' OR '1'='1'
```

SQLite evaluates `AND` before `OR`, so the final tautology makes the condition
true and the demo opens the first sample profile. Use the live monitor to
compare this with a normal failed login. The returned profile omits the
password field; the database and service remain local to the demo process.

## Tests

```powershell
python -m unittest discover -s tests -v
```
