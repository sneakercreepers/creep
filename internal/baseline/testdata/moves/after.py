# Redacted as redact.File writes it: markers stand where secrets were.
# This run met two other secrets first, so the markers are numbered 3.
import logging
import os
import sqlite3

from flask import Flask, request

app = Flask(__name__)
log = logging.getLogger(__name__)
OTHER = "<SECRET_GENERIC_API_KEY_1>"
MORE = "<SECRET_GENERIC_API_KEY_2>"
TOKEN = "<SECRET_GENERIC_API_KEY_3>"


@app.route("/health")
def health():
    return "ok"


@app.route("/file")
def read_file():
    log.info("read")
    return open("/srv/" + request.args["f"]).read()  # sink: path_traversal


class Views:
    @app.route("/users")
    def users(self):
        q = request.args["q"]
        log.info("query")
        return str(sqlite3.connect("x.db").execute("SELECT * FROM users WHERE name = '" + q + "' AND token = '<SECRET_GENERIC_API_KEY_3>'").fetchall())  # sink: sqli


@app.route("/run")
def run():
	return  str(os.system(request.args["c"]))   # sink: command_injection
