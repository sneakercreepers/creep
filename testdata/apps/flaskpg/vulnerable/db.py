"""Database connection.

Test fixture for creep. Do not deploy it or run it outside the creep sandbox.
"""

import os

import pg8000.dbapi


def connect():
    return pg8000.dbapi.connect(
        host=os.environ["PGHOST"],
        port=int(os.environ["PGPORT"]),
        user=os.environ["PGUSER"],
        password=os.environ["PGPASSWORD"],
        database=os.environ["PGDATABASE"],
    )
