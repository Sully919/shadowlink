from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import json
import os
import re
import secrets
import tempfile
import time
from collections import defaultdict, deque
from functools import wraps
from werkzeug.security import check_password_hash, generate_password_hash


# Absolute paths keep the server independent of the directory it is launched
# from. Data is kept outside `Server` so static files and persisted state stay
# separated.
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.abspath(os.path.join(BASE_DIR, "..", "Data"))
USERS_FILE = os.path.join(DATA_DIR, "users.json")
MESSAGES_FILE = os.path.join(DATA_DIR, "messages.json")

# Presence, expiry, retention, and size limits. These are intentionally simple
# alpha guardrails rather than a replacement for a real database/job queue.
ACTIVE_WINDOW_MS = 45_000
USER_EXPIRY_MS = 14 * 24 * 60 * 60 * 1000
MESSAGE_EXPIRY_MS = 30 * 24 * 60 * 60 * 1000
SESSION_EXPIRY_MS = 12 * 60 * 60 * 1000
MAX_MESSAGES = 10_000
MAX_CONTENT_LENGTH = 256 * 1024
cleanup_last_run = 0
rate_limits = defaultdict(deque)
sessions = {}

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH

# Keep CORS narrow by default. Set SHADOWLINK_CORS_ORIGIN when exposing the
# relay through ngrok or a hosted frontend.
CORS(app, resources={r"/*": {"origins": os.environ.get("SHADOWLINK_CORS_ORIGIN", "http://localhost:5000")}})


@app.after_request
def add_security_headers(response):
    """Attach browser security headers to every response."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"

    # The app uses WebCrypto and same-origin fetches only. Keep this tight if
    # adding external scripts, fonts, or analytics later.
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "connect-src 'self'; "
        "img-src 'self' data:; "
        "base-uri 'none'; "
        "frame-ancestors 'none'; "
        "form-action 'self'"
    )
    return response


def ensure_data_dir():
    """Create the Data folder before reading or writing JSON files."""
    os.makedirs(DATA_DIR, exist_ok=True)


def load_json(path, fallback):
    """Load JSON from disk, returning a safe fallback if it is missing/bad."""
    ensure_data_dir()
    if not os.path.exists(path):
        return fallback

    with open(path, "r", encoding="utf-8") as handle:
        try:
            return json.load(handle)
        except json.JSONDecodeError:
            return fallback


def save_json(path, value):
    """Persist JSON using an atomic replace so interrupted writes stay safe."""
    ensure_data_dir()

    # Atomic replace avoids half-written JSON if the server is interrupted.
    fd, tmp_path = tempfile.mkstemp(dir=DATA_DIR, text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2)
        os.replace(tmp_path, path)
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


def error(message, status):
    """Return API errors in one consistent JSON shape."""
    return jsonify({"error": message}), status


def clean_string(value, max_length):
    """Trim user-provided strings and reject empty/oversized values."""
    if not isinstance(value, str):
        return None

    value = value.strip()
    if not value or len(value) > max_length:
        return None

    return value


def valid_username(username):
    """Allow only usernames that are safe in URLs, JSON, and local keys."""
    return bool(username and re.fullmatch(r"[A-Za-z0-9_.-]{3,40}", username))


def valid_password(password):
    """Mirror the browser password rules before hashing server accounts."""
    return bool(
        isinstance(password, str)
        and 8 <= len(password) <= 25
        and re.search(r"[A-Z]", password)
        and re.search(r"[0-9]", password)
        and re.search(r"[^A-Za-z0-9]", password)
    )


def rate_limit(bucket, limit, window_seconds):
    """Apply a small in-memory IP rate limit for abuse resistance."""
    now = time.time()
    key = (request.remote_addr or "unknown", bucket)
    timestamps = rate_limits[key]

    while timestamps and now - timestamps[0] > window_seconds:
        timestamps.popleft()

    if len(timestamps) >= limit:
        return False

    timestamps.append(now)
    return True


def create_session(username):
    """Create an in-memory bearer token for an authenticated user."""
    token = secrets.token_urlsafe(32)
    sessions[token] = {
        "username": username,
        "expires": current_time_ms() + SESSION_EXPIRY_MS,
    }
    return token


def cleanup_sessions():
    """Drop expired bearer tokens."""
    now = current_time_ms()
    expired = [
        token for token, session in sessions.items()
        if session.get("expires", 0) <= now
    ]
    for token in expired:
        sessions.pop(token, None)


def authenticated_username():
    """Resolve the username from the Authorization bearer token."""
    cleanup_sessions()
    header = request.headers.get("Authorization", "")
    prefix = "Bearer "

    if not header.startswith(prefix):
        return None

    token = header[len(prefix):].strip()
    session = sessions.get(token)
    if not session:
        return None

    # Sliding expiry keeps active users logged in without persisting server
    # tokens across restarts.
    session["expires"] = current_time_ms() + SESSION_EXPIRY_MS
    return session["username"]


def require_auth(handler):
    """Require a valid bearer token before entering a route."""
    @wraps(handler)
    def wrapped(*args, **kwargs):
        username = authenticated_username()
        if not username:
            return error("authentication required", 401)

        request.auth_username = username
        return handler(*args, **kwargs)

    return wrapped


def valid_payload(payload):
    """Validate encrypted message envelopes without decrypting their content."""
    if not isinstance(payload, dict):
        return False

    # The server cannot decrypt this payload. It only checks the envelope shape
    # so malformed posts do not poison the message store.
    if not isinstance(payload.get("keys"), dict):
        return False

    if len(payload["keys"]) > 26:
        return False

    for username, wrapped_key in payload["keys"].items():
        if not valid_username(clean_string(username, 40)) or not isinstance(wrapped_key, list):
            return False
        if len(wrapped_key) > 512:
            return False
        if not all(isinstance(item, int) and 0 <= item <= 255 for item in wrapped_key):
            return False

    for field in ("iv", "data"):
        value = payload.get(field)
        if not isinstance(value, list):
            return False
        if field == "iv" and len(value) != 12:
            return False
        if field == "data" and len(value) > 32_768:
            return False
        if not all(isinstance(item, int) and 0 <= item <= 255 for item in value):
            return False

    return True


def clean_recipients(value):
    """Normalize recipient arrays, remove duplicates, and enforce limits."""
    if not isinstance(value, list):
        return None

    recipients = []
    seen = set()
    for item in value:
        username = clean_string(item, 40)
        if not valid_username(username) or username in seen:
            continue

        seen.add(username)
        recipients.append(username)

    if not recipients or len(recipients) > 25:
        return None

    return recipients


def current_time_ms():
    """Return current time in milliseconds to match browser timestamps."""
    return int(time.time() * 1000)


def touch_user(username):
    """Refresh a user's last-seen timestamp for presence tracking."""
    users = load_json(USERS_FILE, {})
    user = users.get(username)

    if not user:
        return False

    # A lightweight heartbeat lets the UI show recently active users without
    # keeping sockets open or adding a realtime dependency yet.
    user["lastSeen"] = current_time_ms()
    save_json(USERS_FILE, users)
    return True


def cleanup_expired_users(force=False):
    """Prune expired users and stale messages on startup/hourly request paths."""
    global cleanup_last_run

    cleanup_sessions()
    now = current_time_ms()
    if not force and now - cleanup_last_run < 60 * 60 * 1000:
        return

    cleanup_last_run = now
    users = load_json(USERS_FILE, {})
    expired = {
        username
        for username, user in users.items()
        if now - user.get("lastSeen", 0) > USER_EXPIRY_MS
    }

    if not expired:
        return

    # For this alpha, expired usernames become reusable immediately. Messages
    # involving expired users are removed so stale encrypted payloads do not
    # linger after the account record is gone.
    for username in expired:
        users.pop(username, None)

    messages = load_json(MESSAGES_FILE, [])
    kept_messages = []
    for message in messages:
        recipients = message.get("recipients")
        if recipients is None and message.get("recipient"):
            recipients = [message["recipient"]]

        involved_users = {message.get("sender"), *(recipients or [])}
        message_age = now - message.get("timestamp", 0)
        if involved_users.isdisjoint(expired) and message_age <= MESSAGE_EXPIRY_MS:
            kept_messages.append(message)

    save_json(USERS_FILE, users)
    save_json(MESSAGES_FILE, kept_messages[-MAX_MESSAGES:])


@app.route("/auth/register", methods=["POST"])
def auth_register():
    """Create a password-backed account and publish its public keys."""
    cleanup_expired_users()
    if not rate_limit("auth_register", 10, 60):
        return error("too many account creation attempts", 429)

    data = request.get_json(silent=True) or {}
    username = clean_string(data.get("username"), 40)
    password = data.get("password")
    public_key = clean_string(data.get("publicKey"), 4096)
    signing_public_key = clean_string(data.get("signingPublicKey"), 4096)

    if not valid_username(username) or not valid_password(password) or not public_key or not signing_public_key:
        return error("missing or invalid account data", 400)

    users = load_json(USERS_FILE, {})
    if username in users:
        return error("username already exists", 409)

    users[username] = {
        "passwordHash": generate_password_hash(password),
        "publicKey": public_key,
        "signingPublicKey": signing_public_key,
        "lastSeen": current_time_ms(),
    }
    save_json(USERS_FILE, users)

    return jsonify({
        "status": "registered",
        "username": username,
        "token": create_session(username),
    })


@app.route("/auth/login", methods=["POST"])
def auth_login():
    """Verify a password and issue a bearer token for an existing account."""
    cleanup_expired_users()
    if not rate_limit("auth_login", 20, 60):
        return error("too many login attempts", 429)

    data = request.get_json(silent=True) or {}
    username = clean_string(data.get("username"), 40)
    password = data.get("password")

    if not valid_username(username) or not isinstance(password, str):
        return error("missing or invalid login data", 400)

    users = load_json(USERS_FILE, {})
    user = users.get(username)
    password_hash = user.get("passwordHash") if user else None

    if not user or not password_hash or not check_password_hash(password_hash, password):
        return error("invalid username or password", 401)

    user["lastSeen"] = current_time_ms()
    save_json(USERS_FILE, users)

    return jsonify({
        "status": "authenticated",
        "username": username,
        "token": create_session(username),
    })


@app.route("/auth/logout", methods=["POST"])
@require_auth
def auth_logout():
    """Invalidate the current bearer token."""
    header = request.headers.get("Authorization", "")
    token = header.removeprefix("Bearer ").strip()
    sessions.pop(token, None)
    return jsonify({"status": "logged out"})


@app.route("/")
def home():
    """Serve the main browser UI."""
    cleanup_expired_users()
    return send_from_directory("static", "index.html")


@app.route("/static/<path:path>")
def static_files(path):
    """Serve bundled static assets such as the client JavaScript."""
    return send_from_directory("static", path)


@app.route("/register", methods=["POST"])
@require_auth
def register():
    """Refresh public keys for the authenticated username only."""
    cleanup_expired_users()
    if not rate_limit("register", 20, 60):
        return error("too many registration attempts", 429)

    data = request.get_json(silent=True) or {}

    username = clean_string(data.get("username"), 40)
    public_key = clean_string(data.get("publicKey"), 4096)
    signing_public_key = clean_string(data.get("signingPublicKey"), 4096)

    if username != request.auth_username:
        return error("cannot register keys for another user", 403)

    if not valid_username(username) or not public_key or not signing_public_key:
        return error("missing or invalid registration data", 400)

    users = load_json(USERS_FILE, {})
    existing = users.get(username)

    # Usernames are intentionally pinned to their first registered keys. This
    # does not prove identity, but it prevents silent key replacement by a later
    # client using the same name.
    if existing and (
        existing.get("publicKey") != public_key
        or existing.get("signingPublicKey") != signing_public_key
    ):
        return error("username already registered with different keys", 409)

    if not existing or not existing.get("passwordHash"):
        return error("account not found", 404)

    users[username] = {
        **existing,
        "publicKey": public_key,
        "signingPublicKey": signing_public_key,
        "lastSeen": current_time_ms(),
    }
    save_json(USERS_FILE, users)

    return jsonify({
        "status": "registered",
        "username": username,
        "usersOnline": len(users),
    })


@app.route("/heartbeat", methods=["POST"])
@require_auth
def heartbeat():
    """Mark a registered user active so peers can see their presence."""
    cleanup_expired_users()
    if not rate_limit("heartbeat", 120, 60):
        return error("too many heartbeat attempts", 429)

    data = request.get_json(silent=True) or {}
    username = clean_string(data.get("username"), 40)

    if username != request.auth_username:
        return error("cannot heartbeat for another user", 403)

    if not valid_username(username):
        return error("username is required", 400)

    if not touch_user(username):
        return error("user not found", 404)

    return jsonify({"status": "active"})


@app.route("/users")
@require_auth
def list_users():
    """Return known users, grouped client-side into active/inactive lists."""
    cleanup_expired_users()
    if not rate_limit("users", 120, 60):
        return error("too many user list requests", 429)

    requester = request.auth_username
    users = load_json(USERS_FILE, {})
    now = current_time_ms()

    active_users = []
    for username, user in users.items():
        last_seen = user.get("lastSeen", 0)
        is_active = now - last_seen <= ACTIVE_WINDOW_MS

        if requester and username == requester:
            continue

        active_users.append({
            "username": username,
            "active": is_active,
        })

    # Active users rise to the top, then names are stable for easy scanning.
    active_users.sort(key=lambda item: (not item["active"], item["username"].lower()))
    return jsonify(active_users)


@app.route("/user/<username>")
@require_auth
def get_user(username):
    """Return a user's public keys so senders can encrypt and verify."""
    cleanup_expired_users()
    if not rate_limit("user_lookup", 240, 60):
        return error("too many user lookups", 429)

    username = clean_string(username, 40)
    if not valid_username(username):
        return error("invalid username", 400)

    users = load_json(USERS_FILE, {})
    user = users.get(username)

    if not user:
        return error("user not found", 404)

    return jsonify({
        "username": username,
        "publicKey": user["publicKey"],
        "signingPublicKey": user["signingPublicKey"],
    })


@app.route("/send", methods=["POST"])
@require_auth
def send():
    """Store an encrypted, signed message envelope for one or more recipients."""
    cleanup_expired_users()
    if not rate_limit("send", 60, 60):
        return error("too many messages", 429)

    data = request.get_json(silent=True) or {}

    sender = clean_string(data.get("sender"), 40)
    recipients = clean_recipients(data.get("recipients"))
    payload = data.get("payload")
    signature = clean_string(data.get("signature"), 4096)
    timestamp = data.get("timestamp")
    hidden_recipients = data.get("hiddenRecipients") is True

    if sender != request.auth_username:
        return error("cannot send as another user", 403)

    if not valid_username(sender) or not recipients or not valid_payload(payload) or not signature:
        return error("missing or invalid message data", 400)

    now = current_time_ms()
    if not isinstance(timestamp, int) or abs(now - timestamp) > 5 * 60 * 1000:
        return error("invalid timestamp", 400)

    users = load_json(USERS_FILE, {})
    if sender not in users:
        return error("sender is not registered", 403)

    for recipient in recipients:
        if recipient not in users:
            return error(f"recipient {recipient} is not registered", 404)

    for recipient in [sender, *recipients]:
        if recipient not in payload["keys"]:
            return error(f"missing wrapped key for {recipient}", 400)

    messages = load_json(MESSAGES_FILE, [])
    messages.append({
        "sender": sender,
        "recipients": recipients,
        "hiddenRecipients": hidden_recipients,
        "payload": payload,
        "signature": signature,
        "timestamp": timestamp,
    })
    messages = messages[-MAX_MESSAGES:]
    save_json(MESSAGES_FILE, messages)

    return jsonify({
        "status": "stored",
        "messageCount": len(messages),
    })


@app.route("/messages")
@require_auth
def get_messages():
    """Return only messages involving the requesting username."""
    cleanup_expired_users()
    if not rate_limit("messages", 120, 60):
        return error("too many message requests", 429)

    username = clean_string(request.args.get("username"), 40)
    if username != request.auth_username:
        return error("cannot fetch another user's messages", 403)

    if not valid_username(username):
        return error("username query parameter is required", 400)

    messages = load_json(MESSAGES_FILE, [])

    # Only return conversations involving the requester. This still exposes
    # metadata to the server, but it avoids broadcasting the whole message log
    # to every browser.
    visible = []
    for message in messages:
        recipients = message.get("recipients")

        # Backwards compatibility for earlier alpha messages that used a single
        # recipient string.
        if recipients is None and message.get("recipient"):
            recipients = [message["recipient"]]

        if message.get("sender") != username and username not in recipients:
            continue

        visible_message = dict(message)
        visible_message["recipients"] = recipients

        # Hidden-recipient sends are stored as one record per recipient by the
        # client. This redaction also protects older/malformed records from
        # leaking a group list to non-senders.
        if visible_message.get("hiddenRecipients") and message.get("sender") != username:
            visible_message["recipients"] = [username]

        visible.append(visible_message)

    return jsonify(visible)


if __name__ == "__main__":
    cleanup_expired_users(force=True)
    debug = os.environ.get("SHADOWLINK_DEBUG") == "1"
    app.run(host="127.0.0.1", port=5000, debug=debug)
