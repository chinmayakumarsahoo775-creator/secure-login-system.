
# Secure Login System

A beginner-friendly Python web application demonstrating
user registration, secure password hashing, SQLite,
input validation, CSRF protection, and session management.

## Features

- User registration and login
- Password hashing using Werkzeug
- SQLite database
- Parameterized SQL queries
- Input validation
- Session-based authentication
- CSRF protection
- Logout functionality

## Requirements

- Python 3.10 or newer
- pip

## Installation

1. Download or clone this repository.
2. Open a terminal inside the project folder.
3. Create a virtual environment:

   python -m venv .venv

4. Activate it on Windows:

   .venv\Scripts\activate

5. Install dependencies:

   pip install -r requirements.txt

6. Set a random secret key in PowerShell:

   $env:SECRET_KEY = python -c "import secrets; print(secrets.token_hex(32))"

7. Run the application:

   python app.py

8. Open this address in your browser:

   http://127.0.0.1:5000

Register an account, log in, and test the logout feature.

## Security Notes

This is a learning project, not a production-ready
authentication service. Before public deployment, add
HTTPS, login rate limiting, secure cookie settings,
account recovery, and appropriate production configuration.
Do not commit secret keys, passwords, or user databases.
Two-factor authentication is not implemented in this version.
