# Support UI (Flask) — Starter

This is a minimal Flask app with a login page and a protected "chat" page.
We'll iterate from here to wire up your n8n backend next.

## Quickstart

```bash
# 1) Create and activate a virtualenv (macOS/Linux)
python3 -m venv .venv
source .venv/bin/activate

# ...or on Windows (PowerShell)
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1

# 2) Install deps
pip install -r requirements.txt

# 3) Configure env
cp .env.example .env
# Edit .env and set a strong SECRET_KEY and your demo users

# 4) Run
flask --app app run --debug
# then open http://127.0.0.1:5000/
```

## Default demo users

The `.env.example` includes:
```
agent:agent123
support:support123
```
These are plaintext in `.env` and are hashed in-memory at startup.
**Do not use in production.**

## Structure

```
support_ui_flask/
  app.py
  requirements.txt
  .env.example
  templates/
    base.html
    login.html
    chat.html
  static/
    app.css
```

## Next steps
- Replace the demo auth with your identity provider (e.g., SSO/OAuth) or a user DB.
- Build the full-screen chat UI and call your n8n workflow from the protected route.
