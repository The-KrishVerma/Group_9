"""Local classroom lab. Standard library only; no external services."""
import json
import sqlite3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).parent / 'static'
PORT = 8001


def authenticate(username, password):
    with sqlite3.connect(':memory:') as db:
        db.row_factory = sqlite3.Row
        db.execute('CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, name TEXT, email TEXT)')
        db.executemany('INSERT INTO users VALUES (?, ?, ?, ?, ?)', [
            (1, 'agent.chen', 'RedAlert#99', 'Dr. Mei Chen', 'mchen@clearancenet.gov'),
            (2, 'director.hayes', 'Sector7!Top', 'Director James Hayes', 'jhayes@clearancenet.gov')])

        # ⚠️  VULNERABILITY: raw string interpolation — susceptible to SQL injection.
        # NOTE: password is checked FIRST so that injecting `' OR '1'='1` into the
        # username field produces:
        #   WHERE password = '...' AND username = '' OR '1'='1'
        # which evaluates as (FALSE AND FALSE) OR TRUE = TRUE — bypass!
        raw_sql = (
            f"SELECT * FROM users WHERE "
            f"password = '{password}' AND username = '{username}'"
        )
        try:
            row = db.execute(raw_sql).fetchone()
        except sqlite3.Error:
            row = None
        user = dict(row) if row else None
        if user:
            user.pop('password', None)
        return dict(
            ok=bool(row),
            user=user,
            message='Access granted. Welcome, Agent.' if row else 'Authentication failed. Access denied.',
            sql=raw_sql,          # ← returned to frontend for the live SQL monitor
        )


class Handler(BaseHTTPRequestHandler):
    def reply(self, status, data, content_type='application/json'):
        payload = json.dumps(data).encode() if content_type == 'application/json' else data
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(payload)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'")
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        route = urlsplit(self.path).path
        files = {'/': ('index.html', 'text/html; charset=utf-8'),
                 '/style.css': ('style.css', 'text/css; charset=utf-8'),
                 '/app.js': ('app.js', 'text/javascript; charset=utf-8')}
        if route not in files:
            return self.reply(404, {'error': 'Not found'})
        name, mime = files[route]
        self.reply(200, (ROOT / name).read_bytes(), mime)

    def do_POST(self):
        if self.path != '/api/login':
            return self.reply(404, {'error': 'Not found'})
        if self.headers.get('Origin') not in (None, f'http://127.0.0.1:{PORT}', f'http://localhost:{PORT}'):
            return self.reply(403, {'error': 'Foreign origin rejected'})
        try:
            size = int(self.headers.get('Content-Length', '0'))
            if not 0 < size <= 4096:
                raise ValueError()
            body = json.loads(self.rfile.read(size))
            username, password = body['username'], body['password']
            if not all(isinstance(x, str) and len(x) <= 256 for x in (username, password)):
                raise ValueError()
        except (ValueError, KeyError, TypeError):
            return self.reply(400, {'error': 'Invalid request'})
        result = authenticate(username, password)
        self.reply(200, result)


if __name__ == '__main__':
    print(f'ClearanceNet running at http://127.0.0.1:{PORT} (Ctrl+C to stop)', flush=True)
    ThreadingHTTPServer(('127.0.0.1', PORT), Handler).serve_forever()
