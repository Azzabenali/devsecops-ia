import sqlite3
import subprocess
from flask import Flask, request, render_template_string

app = Flask(__name__)


# Secret volontairement présent pour tester Gitleaks
API_TOKEN = "ghp_demo_fake_token_123456789"


def db():
    return sqlite3.connect("users.db")


# 1. Injection SQL volontaire
@app.route("/user")
def user():
    name = request.args.get("name", "")

    query = "SELECT * FROM users WHERE name = '" + name + "'"

    cur = db().execute(query)

    return str(cur.fetchall())


# 2. XSS volontaire
@app.route("/hello")
def hello():
    name = request.args.get("name", "")

    return render_template_string(
        "<h1>Bonjour " + name + "</h1>"
    )


# 3. Command Injection volontaire
@app.route("/ping")
def ping():
    host = request.args.get("host", "")

    return subprocess.check_output(
        "ping -n 1 " + host,
        shell=True
    )


if __name__ == "__main__":
    app.run(debug=False)