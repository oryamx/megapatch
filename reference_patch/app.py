"""Hand-written correct fixes for all three vulnerabilities, used ONLY to prove
our PoCs and tests can go green. Nemotron writes its own patches; this is the
ground truth that the test harness works in both directions.
"""
import atexit
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

from flask import Flask, jsonify, request


def create_app():
    app = Flask(__name__)

    db = sqlite3.connect(":memory:", check_same_thread=False)
    db.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, email TEXT)")
    db.executemany(
        "INSERT INTO users (username, email) VALUES (?, ?)",
        [
            ("alice", "alice@example.test"),
            ("bob", "bob@example.test"),
            ("carol", "carol@example.test"),
        ],
    )
    db.commit()

    root = Path(tempfile.mkdtemp(prefix="megapatch_"))
    atexit.register(shutil.rmtree, root, ignore_errors=True)
    public = root / "public"
    public.mkdir()
    (public / "readme.txt").write_text("Welcome to the demo app.\n", encoding="utf-8")
    (root / "secret.txt").write_text("FAKE-SECRET-TOKEN-0000\n", encoding="utf-8")

    @app.get("/users/search")
    def search_users():
        name = request.args.get("name", "")
        # FIXED (CWE-89): parameterized query, the driver treats the input as data.
        rows = db.execute(
            "SELECT id, username, email FROM users WHERE username = ?", (name,)
        ).fetchall()
        return jsonify(
            users=[{"id": r[0], "username": r[1], "email": r[2]} for r in rows]
        )

    @app.get("/lookup")
    def lookup():
        host = request.args.get("host", "")
        # FIXED (CWE-78): no shell; the input is one argument, never parsed as a command.
        result = subprocess.run(
            [sys.executable, "-c", "import sys; print(sys.argv[1])", host],
            capture_output=True, text=True, timeout=10,
        )
        return jsonify(output=result.stdout)

    @app.get("/files")
    def read_file():
        name = request.args.get("name", "")
        # FIXED (CWE-22): resolve the path and require it to stay inside public/.
        path = (public / name).resolve()
        if not path.is_relative_to(public.resolve()):
            return jsonify(error="not found"), 404
        try:
            return jsonify(content=path.read_text(encoding="utf-8"))
        except OSError:
            return jsonify(error="not found"), 404

    return app
