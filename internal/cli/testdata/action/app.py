"""Sample repository for the GitHub Action self-test (ADR 0023).

Test fixture for creep: a deliberately injectable route. Never run it.
"""

import sqlite3

from flask import Flask, request

app = Flask(__name__)


@app.get("/notes")
def notes():
    owner = request.args.get("owner", "")
    rows = sqlite3.connect("notes.db").execute("SELECT * FROM notes WHERE owner = '" + owner + "'").fetchall()
    return {"notes": [list(r) for r in rows]}
