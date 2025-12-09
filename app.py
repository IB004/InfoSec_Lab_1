from time import timezone
from flask import Flask, request, g, jsonify
import sqlite3
from dotenv import load_dotenv
import os
import bcrypt
import jwt
from datetime import datetime, timedelta, timezone
from functools import wraps

app = Flask(__name__)

load_dotenv()

DATABASE = os.getenv("DATABASE")
JWT_SECRET = os.getenv("JWT_SECRET")
JWT_ALGORITHM = "HS256"
JWT_EXP_SECONDS = int(os.getenv("JWT_EXP_SECONDS"))


# -------------------------
# Database helpers
# -------------------------
def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row  # dict-like access to rows
        g._database = db
    return db


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, "_database", None)
    if db:
        db.close()


def init_db():
    db = get_db()
    cur = db.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
        """
    )
    db.commit()



# -------------------------
# JWT helpers
# -------------------------
def create_token(user_id: int) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user_id,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=JWT_EXP_SECONDS)).timestamp()),
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return token


def decode_token(token: str):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return {"error": "token_expired"}
    except jwt.InvalidTokenError:
        return {"error": "invalid_token"}


def get_auth_token_from_header():
    auth = request.headers.get("Authorization", "")
    if not auth:
        return None
    parts = auth.split()
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1]
    return None


# -------------------------
# Decorator for protected endpoints
# -------------------------
def jwt_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = get_auth_token_from_header()
        if not token:
            return jsonify({"error": "Authorization header required"}), 401
        payload = decode_token(token)
        if "error" in payload:
            if payload["error"] == "token_expired":
                return jsonify({"error": "token expired"}), 401
            return jsonify({"error": "invalid token"}), 401
        g.current_user_id = {"id": payload["sub"]}
        return f(*args, **kwargs)

    return decorated


# -------------------------
# Routes
# -------------------------
@app.route("/auth/login", methods=["POST"])
def login_or_register():
    data = request.get_json()

    username = (data.get("username", "")).strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"error": "username and password required"}), 400

    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT id, username, password_hash FROM users WHERE username = ?", (username,))
    row = cur.fetchone()

    if row:
        # user exists, verify password
        stored_hash = row["password_hash"]
        try:
            matched = bcrypt.checkpw(password.encode("utf-8"), stored_hash.encode("utf-8"))
        except Exception:
            matched = False
        if not matched:
            return jsonify({"error": "invalid credentials"}), 401
        user_id = row["id"]
    else:
        # create new user
        pw_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
        try:
            cur.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, pw_hash.decode("utf-8")),
            )
            db.commit()
            user_id = cur.lastrowid
        except sqlite3.IntegrityError:
            return jsonify({"error": "username already exists"}), 400

    token = create_token(user_id)
    return jsonify({"token": token, "user": {"id": user_id, "username": username}}), 200



@app.route('/')
def index():
    return "Hello!"

@app.route('/greet/<name>')
def greet(name):
    return f'Hello {name}!'

@app.route('/add/<int:n1>/<int:n2>')
def add(n1, n2):
    return f'{n1} + {n2} = {n1 + n2}!'

@app.route('/params', methods=['GET', 'POST'])
def params():
    if (request.method == 'GET'):
        return str(request.args)
    return 'POST!'


@app.route('/auth/login', methods=['POST'])
def login():
    username = request.json['username']
    return f'POST: {username}?!'


if __name__ == '__main__':
    with app.app_context():
        init_db()
    app.run(host='0.0.0.0', debug=True)

