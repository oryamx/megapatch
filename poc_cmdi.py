"""PoC: OS command injection on /lookup (practice app only).

Usage: python poc_cmdi.py [app_dir]        (default: target_app)

The payload only runs `echo` to print a marker; it touches nothing else.
Exit 1 + "VULNERABLE" -> the injected command ran      (RED)
Exit 0 + "SAFE"       -> it did not                    (GREEN)
Exit 2 + "BROKEN"     -> the normal feature is gone, so "safe" would be fake
"""
import sys

from harness import load_app

PAYLOAD = "x && echo MARK_EXECUTED"
MARKER = "MARK_EXECUTED"


def main():
    app_dir = sys.argv[1] if len(sys.argv) > 1 else "target_app"
    client = load_app(app_dir).test_client()

    normal = (client.get("/lookup", query_string={"host": "example.test"}).get_json() or {})
    attack = (client.get("/lookup", query_string={"host": PAYLOAD}).get_json() or {})
    normal_out = normal.get("output", "").strip()
    attack_lines = [line.strip() for line in attack.get("output", "").splitlines()]

    print(f"app under test      : {app_dir}")
    print(f"normal  'example.test' -> {normal_out!r}")
    print(f"payload {PAYLOAD!r} -> lines {attack_lines!r}")

    if normal_out != "example.test":
        print("BROKEN: the legitimate lookup no longer echoes the host.")
        sys.exit(2)
    if MARKER in attack_lines:
        print("VULNERABLE: the injected command ran (marker printed on its own line).")
        sys.exit(1)
    print("SAFE: the payload was treated as plain text.")


if __name__ == "__main__":
    main()
