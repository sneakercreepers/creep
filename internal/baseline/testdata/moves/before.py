# Redacted as redact.File writes it: markers stand where secrets were.
import os
import sqlite3

from flask import Flask, request

app = Flask(__name__)
TOKEN = "<SECRET_GENERIC_API_KEY_1>"


@app.route("/users")
def users():
    q = request.args["q"]
    return str(sqlite3.connect("x.db").execute("SELECT * FROM users WHERE name = '" + q + "' AND token = '<SECRET_GENERIC_API_KEY_1>'").fetchall())  # sink: sqli


@app.route("/run")
def run():
    return str(os.system(request.args["c"]))  # sink: command_injection


@app.route("/file")
def read_file():
    return open("/srv/" + request.args["f"]).read()  # sink: path_traversal
