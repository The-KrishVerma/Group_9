import ipaddress
import platform
import re
import subprocess
import time
from flask import Flask, render_template, request

app = Flask(__name__)
PING_FLAG = "-n" if platform.system() == "Windows" else "-c"


def ping_arguments(host):
    return ["ping", PING_FLAG, "1", host]


def is_valid_host(value):
    value = value.strip()
    if not value or len(value) > 253:
        return False
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        pass
    hostname_pattern = re.compile(
        r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*$"
    )
    return bool(hostname_pattern.fullmatch(value))


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/vulnerable", methods=["GET", "POST"])
def vulnerable():
    host = ""
    elapsed = None
    status = None

    if request.method == "POST":
        host = request.form.get("host", "").strip()
        command = f"ping {PING_FLAG} 1 {host}"
        started = time.perf_counter()
        try:
            # Intentionally vulnerable: user input is interpreted by the shell.
            subprocess.run(
                command,
                shell=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
                check=False,
            )
            status = "Request completed. No command output is displayed in this blind variant."
        except subprocess.TimeoutExpired:
            status = "Execution exceeded the 10-second safety timeout."
        except OSError as exc:
            status = f"Execution error: {exc}"
        elapsed = round(time.perf_counter() - started, 2)

    return render_template("vulnerable.html", host=host, elapsed=elapsed, status=status)


@app.route("/secured", methods=["GET", "POST"])
def secured():
    host = ""
    elapsed = None
    status = None
    rejected = False

    if request.method == "POST":
        host = request.form.get("host", "").strip()
        if not is_valid_host(host):
            rejected = True
            status = "Rejected: enter only a valid IP address or hostname."
        else:
            started = time.perf_counter()
            try:
                # Mitigation: argument-vector execution; no shell interpretation.
                subprocess.run(
                    ping_arguments(host),
                    shell=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=8,
                    check=False,
                )
                status = "Accepted as a valid host. Ping completed; no command output is displayed."
            except subprocess.TimeoutExpired:
                status = "Ping timed out."
            except OSError as exc:
                status = f"Execution error: {exc}"
            elapsed = round(time.perf_counter() - started, 2)

    return render_template(
        "secured.html", host=host, elapsed=elapsed, status=status, rejected=rejected
    )


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, debug=False)
