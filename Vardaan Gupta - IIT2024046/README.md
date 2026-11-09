# OS Command Injection — Blind (Time-Based) Variant

**Assignment category:** OS command injection  
**Variant:** Variant 2 — Blind, time-based

This Flask application demonstrates a deliberately vulnerable local ping diagnostic and a secured counterpart. In the vulnerable endpoint, submitted input is concatenated into a command string executed through the shell. Command output is suppressed, so a successful injected delay is observed through elapsed response time rather than returned output.

## Run on macOS / Linux

```bash
cd IIT2024046_CYBERSECURITY
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5001/`.

## Demonstration flow

1. Open **Vulnerable endpoint** and submit `127.0.0.1` as a baseline. Note the elapsed time.
2. Submit `127.0.0.1; sleep 3`. The shell interprets the semicolon as a command separator and runs the delay after ping. The page suppresses command output; compare elapsed time with the baseline.
3. Open **Secured endpoint** and submit the exact same `127.0.0.1; sleep 3` input. The allow-list rejects it because it is not a valid hostname or IP address.
4. Submit `127.0.0.1` on the secured endpoint to show that normal functionality remains available.

The time-based demonstration payload is intended for macOS/Linux, matching the shell syntax used by the demonstration. The app itself selects the platform-appropriate ping count flag.

## Vulnerability and mitigation

- **Root cause:** untrusted host input is concatenated into a command string and passed to `subprocess.run(..., shell=True)`. Shell metacharacters therefore alter the command sequence.
- **Implemented mitigation:** validate the input against an IP/hostname allow-list, then invoke ping as an argument vector with `shell=False`. The shell never parses the submitted value as command syntax.
