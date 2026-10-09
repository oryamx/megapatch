"""PoC: SQL injection on /users/search (practice app only).

Usage: python poc_sqli.py [app_dir]        (default: target_app)

Exit 1 + "VULNERABLE"  -> the exploit worked           (RED)
Exit 0 + "SAFE"        -> the exploit failed           (GREEN)
Exit 2 + "BROKEN"      -> the normal feature is gone, so "safe" would be fake
"""
import sys

from harness import load_app

PAYLOAD = "' OR '1'='1"


def main():
    app_dir = sys.argv[1] if len(sys.argv) > 1 else "target_app"
    client = load_app(app_dir).test_client()

    normal = client.get("/users/search", query_string={"name": "alice"}).get_json()
    attack = client.get("/users/search", query_string={"name": PAYLOAD}).get_json()
    normal_rows = normal.get("users", [])
    attack_rows = attack.get("users", [])

    print(f"app under test      : {app_dir}")
    print(f"normal  'alice'     -> {len(normal_rows)} row(s)")
    print(f"payload {PAYLOAD!r} -> {len(attack_rows)} row(s)")

    if len(normal_rows) != 1:
        print("BROKEN: the legitimate search no longer returns exactly 1 user.")
        sys.exit(2)
    if len(attack_rows) > len(normal_rows):
        print("VULNERABLE: the payload returned rows it should not.")
        sys.exit(1)
    print("SAFE: the payload did not leak extra rows.")


if __name__ == "__main__":
    main()
