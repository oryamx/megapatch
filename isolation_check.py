"""Observable check of what the Nebius sandbox can see and reach.

It runs a few read-only commands inside the same sandbox the judge uses, with the
same uploaded files, and records the output in evidence/isolation_check.json.
Nothing in here modifies anything; it exists so that claims about isolation are
backed by something a reader can inspect. The only network action is one TCP
connect to pypi.org:443, which sends no application data (the TCP handshake itself
still exchanges control packets), to observe whether outbound traffic is possible.

Needs Nebius credentials.  Usage: python isolation_check.py
"""
import json
from datetime import datetime, timezone
from pathlib import Path

from sandbox_judge import APP, SUPPORT_FILES, WORK, _environment

OUT = Path("evidence/isolation_check.json")

CHECKS = {
    "operating system": "uname -sr; (head -2 /etc/os-release || true)",
    "running as": "id",
    "environment variable NAMES (values are not recorded)": "env | cut -d= -f1 | sort | tr '\\n' ' '",
    "variables that look like credentials": "env | cut -d= -f1 | grep -i -E 'nebius|tavily|api|key|token|secret|pass' || echo none",
    "files in the working directory": f"find {WORK} -type f | sort",
    "home directories": "ls -A /root /home 2>&1 | head -5",
    "host drives or mounts from the developer's machine": "ls /c /mnt /host 2>&1 | head -3; mount | grep -i -E 'vboxsf|9p|virtiofs|host' || echo none",
    # One TCP connect to a host pip already uses, sending no application data: it only tells
    # us whether outbound traffic is possible, without touching any system we do not already use.
    "outbound TCP connection (pypi.org:443, the host pip uses)": (
        "python -c \"import socket; socket.create_connection(('pypi.org', 443), 5); print('reachable')\" 2>&1 | tail -1"
    ),
}


def main():
    env = _environment()
    files = {f"{WORK}/{name}": name for name in SUPPORT_FILES}
    files[f"{WORK}/{APP}/app.py"] = "target_app/app.py"  # the same upload the judge makes

    results = {}
    for name, command in CHECKS.items():
        res = env.run(shell=command, files=files, timeout=60).wait()
        results[name] = ((res.stdout or "") + (res.stderr or "")).strip()
        print(f"- {name}:\n    " + results[name].replace("\n", "\n    "))

    OUT.parent.mkdir(exist_ok=True)
    OUT.write_text(
        json.dumps({"checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "results": results}, indent=2),
        encoding="utf-8",
    )
    print(f"\nWritten {OUT}")


if __name__ == "__main__":
    main()
