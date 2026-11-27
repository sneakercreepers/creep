"""Schema and seed data.

Test fixture for creep. Do not deploy it or run it outside the creep sandbox.
"""

from db import connect

SCHEMA = """
CREATE TABLE IF NOT EXISTS notes (
    id serial PRIMARY KEY,
    owner_id integer NOT NULL,
    title text NOT NULL,
    body text NOT NULL
)
"""

SEED = "INSERT INTO notes (owner_id, title, body) VALUES (1, 'groceries', 'milk'), (2, 'todo', 'call the bank')"


def main():
    conn = connect()
    cur = conn.cursor()
    cur.execute(SCHEMA)
    cur.execute(SEED)
    conn.commit()
    conn.close()


if __name__ == "__main__":
    main()
