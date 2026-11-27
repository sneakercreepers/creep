"""Notes service.

Test fixture for creep. Do not deploy it or run it outside the creep sandbox.
"""

from flask import Flask, g, jsonify, request, send_from_directory

from db import connect

app = Flask(__name__)
UPLOAD_DIR = "/app/uploads"


def db():
    if "db" not in g:
        g.db = connect()
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


@app.get("/notes/search")
def search_notes():
    term = request.args.get("q", "")
    cur = db().cursor()
    cur.execute("SELECT id, title FROM notes WHERE title LIKE %s", (f"%{term}%",))
    return jsonify([{"id": row[0], "title": row[1]} for row in cur.fetchall()])


@app.get("/attachments/<path:name>")
def download_attachment(name):
    return send_from_directory(UPLOAD_DIR, name)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
