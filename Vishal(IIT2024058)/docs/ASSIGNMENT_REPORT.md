# SQL Injection: Authentication Bypass

## Application

ClearanceNet is a local classroom demonstration of an authentication bypass.
It seeds two fictional sample accounts into an in-memory SQLite database for
each login request. The HTTP server listens only on `127.0.0.1`.

## Vulnerable query

The demo intentionally interpolates submitted values into this query:

```python
raw_sql = (
    f"SELECT * FROM users WHERE "
    f"password = '{password}' AND username = '{username}'"
)
```

This is deliberately unsafe: input is treated as part of the SQL syntax
instead of as data. The live query monitor displays the query as values are
entered, and the submitted query is shown after successful authentication.

## Authentication bypass

Enter `' OR '1'='1` as the Agent ID and any non-empty access code. For example,
with `wrong-password`, the resulting condition is:

```sql
password = 'wrong-password' AND username = '' OR '1'='1'
```

SQLite evaluates `AND` before `OR`, so the expression is equivalent to
`(password is correct AND username is correct) OR true`. The final condition
is therefore true, and SQLite returns the first sample user. The profile view
shows that the login succeeded without valid credentials.

The application returns only the account fields needed by the profile; it
does not return the stored password. This does not make the query safe—the
bypass remains intentional for the local demonstration.

## Fix

Use a parameterized query so SQLite treats user input as data:

```python
row = db.execute(
    "SELECT id, username, name, email FROM users WHERE username = ? AND password = ?",
    (username, password),
).fetchone()
```

With bound parameters, the tautology is searched as a literal username and
does not alter the query's logic. Production systems should also store
password hashes and use appropriate session management.

## Verification

Run the app with `python app.py` and open <http://127.0.0.1:8001>. Run the
automated checks with:

```powershell
python -m unittest discover -s tests -v
```

This is an intentionally vulnerable example and should be run locally only.
