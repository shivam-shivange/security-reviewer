import sqlite3
import subprocess
import os
from flask import Flask, request, redirect, make_response

app = Flask(__name__)
DB = "app.db"


def get_db():
    conn = sqlite3.connect(DB)
    return conn


def init_db():
    conn = get_db()
    conn.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT)")
    conn.execute("DELETE FROM users")
    conn.executemany("INSERT INTO users (name) VALUES (?)", [("alice",), ("bob",), ("carol",)])
    conn.commit()
    conn.close()


init_db()


@app.route("/user")
def user():
    name = request.args.get("name", "")
    conn = get_db()
    cur = conn.cursor()
    query = "SELECT id, name FROM users WHERE name = '" + name + "'"
    cur.execute(query)
    rows = cur.fetchall()
    return {"rows": rows}


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    output = subprocess.getoutput("ping -c 1 " + host)
    return output


@app.route("/greet")
def greet():
    name = request.args.get("name", "")
    return make_response("<h1>Hello " + name + "</h1>")


@app.route("/go")
def go():
    target = request.args.get("url", "/")
    return redirect(target)


@app.route("/read")
def read_file():
    fname = request.args.get("file", "readme.txt")
    with open(os.path.join("data", fname)) as f:
        return f.read()


if __name__ == "__main__":
    app.run(debug=True)
