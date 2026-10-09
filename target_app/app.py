"""Tiny practice app with three deliberate vulnerabilities.

  CWE-89  SQL injection      GET /users/search?name=
  CWE-78  Command injection  GET /lookup?host=
  CWE-22  Path traversal     GET /files?name=

Local only: in-memory database, temp files, fake secrets. Never deploy this.
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

    # Data for /users/search (in-memory).
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

    # Data for /files: public/ is meant to be served, secret.txt must stay private.
    root = Path(tempfile.mkdtemp(prefix="megapatch_"))
    atexit.register(shutil.rmtree, root, ignore_errors=True)
    public = root / "public"
    public.mkdir()
    (public / "readme.txt").write_text("Welcome to the demo app.\n", encoding="utf-8")
    (root / "secret.txt").write_text("FAKE-SECRET-TOKEN-0000\n", encoding="utf-8")

    @app.get("/users/search")
    def search_users():
        name = request.args.get("name", "")
        # VULNERABLE (CWE-89): user input is concatenated straight into the SQL string.
        query = f"SELECT id, username, email FROM users WHERE username = '{name}'"
        try:
            rows = db.execute(query).fetchall()
        except sqlite3.Error as exc:
            return jsonify(error=str(exc)), 400
        return jsonify(
            users=[{"id": r[0], "username": r[1], "email": r[2]} for r in rows]
        )

    @app.get("/lookup")
    def lookup():
        host = request.args.get("host", "")
        # VULNERABLE (CWE-78): user input becomes part of a shell command line.
        cmd = f'"{sys.executable}" -c "import sys; print(sys.argv[1])" {host}'
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        return jsonify(output=result.stdout)

    @app.get("/files")
    def read_file():
        name = request.args.get("name", "")
        # VULNERABLE (CWE-22): the name is joined to the public folder without
        # checking where the resulting path really points.
        path = public / name
        try:
            return jsonify(content=path.read_text(encoding="utf-8"))
        except OSError:
            return jsonify(error="not found"), 404

    return app
