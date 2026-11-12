/** Attacker web server (http://localhost:4000) - serves attacker.html.
 *  Running on port 4000 makes it a DIFFERENT origin from :3000 (vulnerable) and :3001 (secured). */
const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = 4000;

http.createServer((req, res) => {
  console.log(`[ATTACKER] ${req.method} ${req.url}`);
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(fs.readFileSync(path.join(__dirname, 'attacker.html')));
}).listen(PORT, () => console.log(`Attacker page running on http://localhost:${PORT}`));
