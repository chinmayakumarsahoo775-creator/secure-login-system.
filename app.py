
import os
import hmac
import secrets
import sqlite3
from functools import wraps
from flask import (
    Flask, request, redirect, url_for,
    session, render_template_string, abort
)
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY")

if not app.secret_key:
    raise RuntimeError("Set the SECRET_KEY environment variable first.")

DB_NAME = "users.db"


def get_db():
    db = sqlite3.connect(DB_NAME)
    db.row_factory = sqlite3.Row
    return db


def init_db():
    with get_db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            )
        """)


def csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


def verify_csrf():
    token = request.form.get("csrf_token", "")
    saved = session.get("csrf_token", "")
    if not saved or not hmac.compare_digest(token, saved):
        abort(400, "Invalid form token. Refresh and try again.")


def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return func(*args, **kwargs)
    return wrapper


PAGE = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Secure Login System</title>
<style>
body{font-family:Arial,sans-serif;background:#eef2ff;margin:0;padding:30px}
main{max-width:420px;margin:40px auto;background:white;padding:25px;
border-radius:12px;box-shadow:0 4px 15px #ccd}
input,button{box-sizing:border-box;width:100%;padding:12px;margin:8px 0}
button{background:#1769e0;color:white;border:0;border-radius:6px;cursor:pointer}
a{color:#1769e0} .msg{color:#b42318} .ok{color:#087443}
</style>
</head>
<body><main>
<h2>Secure Login System</h2>
{% if message %}<p class="{{ category }}">{{ message }}</p>{% endif %}
{{ content|safe }}
</main></body></html>
"""


def page(content, message="", category="msg"):
    return render_template_string(
        PAGE, content=content, message=message, category=category
    )


FORM = """
<form method="post">
<input type="hidden" name="csrf_token" value="{{ token }}">
<label>Username</label>
<input name="username" required minlength="3" maxlength="30"
       pattern="[A-Za-z0-9_]+" autocomplete="username">
<label>Password</label>
<input type="password" name="password" required minlength="8"
       maxlength="128" autocomplete="{{ autocomplete }}">
<button type="submit">{{ button }}</button>
</form>
"""


@app.route("/")
def home():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return page('<p>Register a new account or log in.</p>'
                '<a href="/register">Register</a> | '
                '<a href="/login">Login</a>')


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        verify_csrf()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not (3 <= len(username) <= 30):
            return page("Username must be 3–30 characters.")
        if not username.replace("_", "").isalnum():
            return page("Use only letters, numbers, and underscores.")
        if len(password) < 8 or len(password) > 128:
            return page("Password must be 8–128 characters.")

        hashed = generate_password_hash(password)
        try:
            with get_db() as db:
                db.execute(
                    "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                    (username, hashed)
                )
        except sqlite3.IntegrityError:
            return page("That username is already registered.")

        return page(
            '<a href="/login">Go to login</a>',
            "Registration successful!", "ok"
        )

    return page(render_template_string(
        FORM, token=csrf_token(), button="Register",
        autocomplete="new-password"
    ))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        verify_csrf()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        with get_db() as db:
            user = db.execute(
                "SELECT id, username, password_hash FROM users WHERE username = ?",
                (username,)
            ).fetchone()

        if not user or not check_password_hash(
            user["password_hash"], password
        ):
            return page("Invalid username or password.")

        session.clear()
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session["csrf_token"] = secrets.token_urlsafe(32)
        return redirect(url_for("dashboard"))

    return page(render_template_string(
        FORM, token=csrf_token(), button="Login",
        autocomplete="current-password"
    ))


@app.route("/dashboard")
@login_required
def dashboard():
    content = (
        "<h3>Welcome, " + session["username"] + "!</h3>"
        "<p>You are logged in.</p>"
        '<form method="post" action="/logout">'
        '<input type="hidden" name="csrf_token" value="'
        + csrf_token() + '">'
        '<button type="submit">Logout</button></form>'
    )
    return page(content, "Login successful!", "ok")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    verify_csrf()
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    init_db()
    app.run(debug=False)
