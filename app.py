\
import os
import uuid
import requests
from flask import jsonify
from flask import Response, stream_with_context
from dataclasses import dataclass
from typing import Dict

from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_login import (
    LoginManager, UserMixin, login_user, login_required, logout_user, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

load_dotenv()

def parse_users(env_value: str | None) -> Dict[str, str]:
    """
    Parse SUPPORT_USERS env in the format "user1:pass1,user2:pass2".
    Returns dict of username -> hashed_password (hashed at startup).
    """
    users: Dict[str, str] = {}
    if not env_value:
        env_value = "support:support123,agent:agent123"
    for pair in env_value.split(","):
        pair = pair.strip()
        if not pair:
            continue
        if ":" not in pair:
            continue
        u, p = pair.split(":", 1)
        u = u.strip()
        p = p.strip()
        if u and p:
            users[u] = generate_password_hash(p)
    return users

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-secret-change-me")
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
# In production, set SESSION_COOKIE_SECURE=True behind HTTPS.

login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

# In-memory demo users (username -> hashed password)
USER_STORE = parse_users(os.getenv("SUPPORT_USERS"))

@dataclass
class User(UserMixin):
    id: str

@login_manager.user_loader
def load_user(user_id: str):
    if user_id in USER_STORE:
        return User(id=user_id)
    return None

@app.route("/", methods=["GET"])
def root():
    if current_user.is_authenticated:
        return redirect(url_for("chat"))
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")
    # POST
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    if not username or not password:
        flash("Please enter both username and password.")
        return redirect(url_for("login"))

    hashed = USER_STORE.get(username)
    if not hashed or not check_password_hash(hashed, password):
        flash("Invalid username or password.")
        return redirect(url_for("login"))

    login_user(User(id=username))
    # Ensure a per-session identifier exists
    session["session_id"] = session.get("session_id") or str(uuid.uuid4())
    return redirect(url_for("chat"))

@app.route("/logout", methods=["GET"])
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

@app.route("/chat", methods=["GET"])
@login_required
def chat():
    # Reset session id on new page load (treat as new conversation)
    session["session_id"] = str(uuid.uuid4())
    return render_template("chat.html", session_id=session["session_id"])

N8N_WEBHOOK_URL = os.getenv("N8N_WEBHOOK_URL", "").strip()
N8N_AUTH_HEADER_NAME = os.getenv("N8N_AUTH_HEADER_NAME", "").strip()
N8N_AUTH_HEADER_VALUE = os.getenv("N8N_AUTH_HEADER_VALUE", "").strip()

@app.route("/api/ask", methods=["POST"])
@login_required
def api_ask():
    if not N8N_WEBHOOK_URL:
        return ("Server not configured: set N8N_WEBHOOK_URL in your .env", 500)

    payload = request.get_json(silent=True) or {}
    question = (payload.get("question") or "").strip()
    if not question:
        return ("Missing 'question' in JSON body.", 400)

    headers = {"Content-Type": "application/json"}
    if N8N_AUTH_HEADER_NAME and N8N_AUTH_HEADER_VALUE:
        headers[N8N_AUTH_HEADER_NAME] = N8N_AUTH_HEADER_VALUE

    # Ensure session id exists for this user session
    sid = session.get("session_id") or str(uuid.uuid4())
    session["session_id"] = sid

    body = {"question": question, "user": current_user.id, "session_id": sid}

    try:
        # Enable streaming from upstream; we'll decide to proxy as a stream or buffer
        resp = requests.post(
            N8N_WEBHOOK_URL,
            json=body,
            headers=headers,
            timeout=300,
            stream=True,
        )
    except requests.RequestException as e:
        return (f"Upstream error contacting n8n: {e}", 502)

    content_type = (resp.headers.get("content-type") or "").lower()
    transfer_encoding = (resp.headers.get("transfer-encoding") or "").lower()

    # If upstream is clearly streaming (SSE or chunked text), proxy as a stream
    is_streaming_like = (
        ("text/event-stream" in content_type)
        or ("chunked" in transfer_encoding)  # stream regardless of content type when chunked
        or ("application/x-ndjson" in content_type)
    )

    if is_streaming_like:
        def generate():
            try:
                for chunk in resp.iter_content(chunk_size=1024):
                    if not chunk:
                        continue
                    yield chunk
            finally:
                try:
                    resp.close()
                except Exception:
                    pass

        # Pass through the upstream content-type if present; default to text/event-stream
        passthrough_ct = resp.headers.get("content-type", "text/event-stream; charset=utf-8")
        headers_out = {"Content-Type": passthrough_ct}
        # Avoid buffering by proxies like nginx (should they be in front)
        headers_out["X-Accel-Buffering"] = "no"
        # Keep connection alive during streaming
        headers_out["Cache-Control"] = "no-cache"
        headers_out["Connection"] = "keep-alive"
        return Response(stream_with_context(generate()), status=resp.status_code, headers=headers_out)

    # Otherwise, buffer and try JSON-first for backward compatibility
    if "application/json" in content_type:
        try:
            return jsonify(resp.json()), resp.status_code
        except Exception:
            pass

    # Fallback: read full text
    try:
        text_body = resp.text
    except Exception:
        text_body = ""
    return (text_body, resp.status_code, {"Content-Type": "text/plain; charset=utf-8"})


@app.route("/api/new_session", methods=["POST"])
@login_required
def api_new_session():
    """Create a new session id, return it, and use it for subsequent asks."""
    sid = str(uuid.uuid4())
    session["session_id"] = sid
    return jsonify({"session_id": sid})

if __name__ == "__main__":
    # For local development only
    app.run(debug=True)
