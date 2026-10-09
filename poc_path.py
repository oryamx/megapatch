"""PoC: path traversal on /files (practice app only).

Usage: python poc_path.py [app_dir]        (default: target_app)

Reads only the app's own fake secret file.
Exit 1 + "VULNERABLE" -> the private file was returned  (RED)
Exit 0 + "SAFE"       -> it was not                    (GREEN)
Exit 2 + "BROKEN"     -> the normal feature is gone, so "safe" would be fake
"""
import sys

from harness import load_app

PAYLOAD = "../secret.txt"
SECRET = "FAKE-SECRET-TOKEN"


def main():
    app_dir = sys.argv[1] if len(sys.argv) > 1 else "target_app"
    client = load_app(app_dir).test_client()

    normal = (client.get("/files", query_string={"name": "readme.txt"}).get_json() or {})
    attack = (client.get("/files", query_string={"name": PAYLOAD}).get_json() or {})
    normal_content = normal.get("content", "")
    attack_content = attack.get("content", "")

    print(f"app under test      : {app_dir}")
    print(f"normal  'readme.txt' -> {normal_content.strip()!r}")
    print(f"payload {PAYLOAD!r} -> {attack_content.strip()!r}")

    if "Welcome" not in normal_content:
        print("BROKEN: the legitimate file is no longer served.")
        sys.exit(2)
    if SECRET in attack_content:
        print("VULNERABLE: a file outside the public folder was returned.")
        sys.exit(1)
    print("SAFE: the private file was not returned.")


if __name__ == "__main__":
    main()
