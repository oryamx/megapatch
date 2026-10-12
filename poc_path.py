"""PoC: path traversal on /files (practice app only).

Usage: python poc_path.py [app_dir]        (default: target_app)

Two escapes are tried, both reading only the app's own fake files:
  1. ../secret.txt                 a plain parent-directory escape
  2. ../public_backup/backup.txt   a SIBLING directory whose name starts with "public";
                                   a string-prefix check (startswith) wrongly accepts it

Exit 1 + "VULNERABLE" -> a private file was returned  (RED)
Exit 0 + "SAFE"       -> neither was returned         (GREEN)
Exit 2 + "BROKEN"     -> the normal feature is gone, so "safe" would be fake
"""
import sys

from harness import load_app

ATTACKS = [
    ("parent directory", "../secret.txt", "FAKE-SECRET-TOKEN"),
    ("sibling with the same prefix", "../public_backup/backup.txt", "FAKE-BACKUP-SECRET"),
]


def main():
    app_dir = sys.argv[1] if len(sys.argv) > 1 else "target_app"
    client = load_app(app_dir).test_client()

    normal = (client.get("/files", query_string={"name": "readme.txt"}).get_json() or {})
    normal_content = normal.get("content", "")
    print(f"app under test      : {app_dir}")
    print(f"normal  'readme.txt' -> {normal_content.strip()!r}")

    if "Welcome" not in normal_content:
        print("BROKEN: the legitimate file is no longer served.")
        sys.exit(2)

    leaked = []
    for label, payload, marker in ATTACKS:
        content = (client.get("/files", query_string={"name": payload}).get_json() or {}).get("content", "")
        print(f"payload {payload!r} ({label}) -> {content.strip()!r}")
        if marker in content:
            leaked.append(label)

    if leaked:
        print(f"VULNERABLE: a file outside the public folder was returned via: {', '.join(leaked)}.")
        sys.exit(1)
    print("SAFE: neither escape returned a private file.")


if __name__ == "__main__":
    main()
