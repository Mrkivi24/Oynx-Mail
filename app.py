# app.py
import os
import sqlite3
import uuid
from datetime import datetime
from functools import wraps
from io import BytesIO
# -------------------- Config --------------------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "app.db")
KEY_PATH = os.path.join(BASE_DIR, "fernet.key")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")

# Automatically initialize database if missing
from subprocess import run
if not os.path.exists(DB_PATH):
    print("🔧 Database not found — initializing new database...")
    run(["python", os.path.join(BASE_DIR, "init_db.py")], check=True)

os.makedirs(UPLOAD_FOLDER, exist_ok=True)


from flask import (
    Flask, g, render_template, request, redirect, url_for, session, flash, send_file, abort
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet



# -------------------- Config --------------------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "app.db")
KEY_PATH = os.path.join(BASE_DIR, "fernet.key")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Encryption key
if not os.path.exists(KEY_PATH):
    key = Fernet.generate_key()
    with open(KEY_PATH, "wb") as f:
        f.write(key)
else:
    with open(KEY_PATH, "rb") as f:
        key = f.read()

fernet = Fernet(key)

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB

# -------------------- Helpers --------------------
def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
        g._database = db
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, "_database", None)
    if db:
        db.close()

def login_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login', next=request.path))
        return f(*args, **kwargs)
    return wrapped

def admin_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        user = get_user(session['user_id'])
        if not user or not user['is_admin']:
            abort(403)
        return f(*args, **kwargs)
    return wrapped

def get_user(user_id):
    db = get_db()
    return db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()

def get_user_by_username(username):
    db = get_db()
    return db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

def encrypt_text(plaintext: str) -> bytes:
    return fernet.encrypt((plaintext or "").encode('utf-8'))

def decrypt_text(ciphertext: bytes) -> str:
    if not ciphertext:
        return ""
    try:
        return fernet.decrypt(ciphertext).decode('utf-8')
    except Exception:
        return "[decryption error]"

def save_and_encrypt_file(file_storage):
    if not file_storage or file_storage.filename == "":
        return None, None
    original = secure_filename(file_storage.filename)
    stored_name = str(uuid.uuid4()) + ".enc"
    stored_path = os.path.join(app.config['UPLOAD_FOLDER'], stored_name)
    data = file_storage.read()
    enc = fernet.encrypt(data)
    with open(stored_path, "wb") as f:
        f.write(enc)
    return original, stored_name

def decrypt_file_to_bytes(stored_filename):
    stored_path = os.path.join(app.config['UPLOAD_FOLDER'], stored_filename)
    if not os.path.exists(stored_path):
        return None
    with open(stored_path, "rb") as f:
        enc = f.read()
    try:
        return fernet.decrypt(enc)
    except Exception:
        return None

def _delete_email_and_attachments_by_row(r):
    """Helper: deletes attachments files and DB attachments rows, then DB email row.
    Expects r to be a sqlite Row for email (with id)."""
    db = get_db()
    # delete attachments files
    atts = db.execute("SELECT * FROM attachments WHERE email_id = ?", (r['id'],)).fetchall()
    for att in atts:
        try:
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], att['stored_filename']))
        except Exception:
            pass
    db.execute("DELETE FROM attachments WHERE email_id = ?", (r['id'],))
    db.execute("DELETE FROM emails WHERE id = ?", (r['id'],))
    db.commit()

# -------------------- Routes --------------------
@app.route("/")
def index():
    if 'user_id' in session:
        return redirect(url_for('inbox'))
    return redirect(url_for('login'))

# Registration
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not username or not password:
            flash("Provide username and password.", "danger")
            return render_template("register.html")
        db = get_db()
        if db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone():
            flash("Username already taken.", "danger")
            return render_template("register.html")
        db.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, generate_password_hash(password))
        )
        db.commit()
        flash("Registered. Please login.", "success")
        return redirect(url_for('login'))
    return render_template("register.html")

# Login
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if user and check_password_hash(user['password_hash'], password):
            session.clear()
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['is_admin'] = bool(user['is_admin'])
            flash("Logged in.", "success")
            return redirect(request.args.get('next') or url_for('inbox'))
        flash("Invalid credentials.", "danger")
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for('login'))

# Compose
@app.route("/compose", methods=["GET", "POST"])
@login_required
def compose():
    db = get_db()
    users = db.execute("SELECT id, username FROM users WHERE id != ?", (session['user_id'],)).fetchall()
    if request.method == "POST":
        recipient_username = request.form.get("recipient", "").strip()
        subject = request.form.get("subject", "")
        body = request.form.get("body", "")
        # whisper options
        is_whisper = 1 if request.form.get("is_whisper") == "on" or request.form.get("is_whisper") == "1" else 0
        whisper_code = request.form.get("whisper_code", "") if is_whisper else None
        self_destruct = 1 if request.form.get("self_destruct") == "on" or request.form.get("self_destruct") == "1" else 0

        recipient = get_user_by_username(recipient_username)
        if not recipient:
            flash("Recipient not found.", "danger")
            return render_template("compose.html", users=users)

        enc_subject = encrypt_text(subject)
        enc_body = encrypt_text(body)

        # hash whisper code if provided
        whisper_hash = None
        if is_whisper and whisper_code:
            whisper_hash = generate_password_hash(whisper_code)

        timestamp = datetime.utcnow().isoformat(timespec='seconds')
        db.execute(
            """INSERT INTO emails
               (sender_id, recipient_id, subject, body, timestamp, is_whisper, whisper_code_hash, self_destruct)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (session['user_id'], recipient['id'], enc_subject, enc_body, timestamp, is_whisper, whisper_hash, self_destruct)
        )
        db.commit()
        email_id = db.execute("SELECT last_insert_rowid() AS id").fetchone()['id']

        # attachments - expecting input name "attachments" (multiple)
        for f in request.files.getlist("attachments"):
            if f and f.filename:
                orig, stored = save_and_encrypt_file(f)
                if orig and stored:
                    db.execute(
                        "INSERT INTO attachments (email_id, original_filename, stored_filename) VALUES (?, ?, ?)",
                        (email_id, orig, stored)
                    )
        db.commit()
        flash("Email sent.", "success")
        return redirect(url_for('sent'))

    return render_template("compose.html", users=users)

# Inbox
@app.route("/inbox")
@login_required
def inbox():
    db = get_db()
    rows = db.execute("""
        SELECT e.*, u.username as sender_username
        FROM emails e JOIN users u ON e.sender_id = u.id
        WHERE e.recipient_id = ? AND e.trashed = 0
        ORDER BY e.timestamp DESC
    """, (session['user_id'],)).fetchall()
    emails = [{
        'id': r['id'],
        'sender_id': r['sender_id'],
        'sender_username': r['sender_username'],
        'subject': decrypt_text(r['subject']),
        'body_preview': (decrypt_text(r['body'])[:300] + '...') if len(decrypt_text(r['body'])) > 300 else decrypt_text(r['body']),
        'timestamp': r['timestamp'],
        'is_read': bool(r['is_read']),
        'is_whisper': bool(r['is_whisper'])
    } for r in rows]
    return render_template("inbox.html", emails=emails, active_page='inbox')

# Sent
@app.route("/sent")
@login_required
def sent():
    db = get_db()
    rows = db.execute("""
        SELECT e.*, u.username as recipient_username
        FROM emails e JOIN users u ON e.recipient_id = u.id
        WHERE e.sender_id = ? AND e.trashed = 0
        ORDER BY e.timestamp DESC
    """, (session['user_id'],)).fetchall()
    emails = [{
        'id': r['id'],
        'recipient_username': r['recipient_username'],
        'subject': decrypt_text(r['subject']),
        'body_preview': (decrypt_text(r['body'])[:300] + '...') if len(decrypt_text(r['body'])) > 300 else decrypt_text(r['body']),
        'timestamp': r['timestamp'],
        'is_read': bool(r['is_read']),
        'is_whisper': bool(r['is_whisper'])
    } for r in rows]
    return render_template("sent.html", emails=emails, active_page='sent')

# Trash
@app.route("/trash")
@login_required
def trash():
    db = get_db()
    rows = db.execute("""
        SELECT e.*, su.username as sender_username, ru.username as recipient_username
        FROM emails e
        JOIN users su ON e.sender_id = su.id
        JOIN users ru ON e.recipient_id = ru.id
        WHERE (e.sender_id = ? OR e.recipient_id = ?) AND e.trashed = 1
        ORDER BY e.timestamp DESC
    """, (session['user_id'], session['user_id'])).fetchall()
    emails = [{
        'id': r['id'],
        'sender_username': r['sender_username'],
        'recipient_username': r['recipient_username'],
        'subject': decrypt_text(r['subject']),
        'timestamp': r['timestamp'],
        'is_read': bool(r['is_read']),
        'is_whisper': bool(r['is_whisper'])
    } for r in rows]
    return render_template("trash.html", emails=emails, active_page='trash')

# View Email (with whisper unlock & self-destruct)
@app.route("/email/<int:email_id>", methods=["GET", "POST"])
@login_required
def view_email(email_id):
    db = get_db()
    r = db.execute("""
        SELECT e.*, su.username as sender_username, ru.username as recipient_username
        FROM emails e
        JOIN users su ON e.sender_id = su.id
        JOIN users ru ON e.recipient_id = ru.id
        WHERE e.id = ?
    """, (email_id,)).fetchone()
    if not r:
        abort(404)

    # permission check: sender or recipient or admin
    if session['user_id'] not in (r['sender_id'], r['recipient_id']) and not session.get('is_admin'):
        abort(403)

    # If whisper and the viewer is recipient and not admin, enforce code
    is_whisper = bool(r['is_whisper'])
    whisper_hash = r['whisper_code_hash'] if 'whisper_code_hash' in r.keys() else None
    self_destruct = bool(r['self_destruct']) if 'self_destruct' in r.keys() else False

    # Admins can bypass whisper code
    if is_whisper and (session['user_id'] == r['recipient_id']) and not session.get('is_admin'):
        # If POST, verify code
        if request.method == "POST":
            provided = request.form.get("whisper_code", "")
            if not whisper_hash or not provided or not check_password_hash(whisper_hash, provided):
                flash("Incorrect whisper code.", "danger")
                return render_template("unlock_whisper.html", email_id=email_id)
            # correct code: proceed to show and optionally self-destruct
        else:
            # GET -> show unlock form
            return render_template("unlock_whisper.html", email_id=email_id)

    # Mark read if recipient opened (only when actually viewing)
    if session['user_id'] == r['recipient_id'] and not r['is_read']:
        db.execute("UPDATE emails SET is_read = 1 WHERE id = ?", (email_id,))
        db.commit()

    # Prepare decrypted content for rendering
    subject = decrypt_text(r['subject'])
    body = decrypt_text(r['body'])

    # Gather attachments (we will show links; if self-destruct requested we will remove DB rows after preparing content)
    attachments = db.execute("SELECT * FROM attachments WHERE email_id = ?", (email_id,)).fetchall()

    # If whisper + self_destruct and recipient opened successfully, delete email record and attachments after capturing data to render
    deleted_for_self_destruct = False
    if is_whisper and self_destruct and session['user_id'] == r['recipient_id'] and not session.get('is_admin'):
        # capture attachments (we won't delete files until after render; but to simplify we will delete DB rows and files now)
        # capture filenames for possible temporary serving (note: after deletion attachment route may fail)
        att_rows = [dict(a) for a in attachments]
        # delete attachments files and DB rows and email row
        for att in att_rows:
            try:
                os.remove(os.path.join(app.config['UPLOAD_FOLDER'], att['stored_filename']))
            except Exception:
                pass
        db.execute("DELETE FROM attachments WHERE email_id = ?", (email_id,))
        db.execute("DELETE FROM emails WHERE id = ?", (email_id,))
        db.commit()
        deleted_for_self_destruct = True

    return render_template("view_email.html", email={
        'id': r['id'],
        'sender_username': r['sender_username'],
        'recipient_username': r['recipient_username'],
        'subject': subject,
        'body': body,
        'timestamp': r['timestamp'],
        'is_read': bool(r['is_read']),
        'is_whisper': is_whisper,
        'self_destructed': deleted_for_self_destruct
    }, attachments=attachments)

# Serve isolated HTML body inside iframe (prevents CSS/JS bleed)
@app.route("/email/<int:email_id>/body")
@login_required
def email_body(email_id):
    db = get_db()
    r = db.execute("""
        SELECT e.*, su.username as sender_username, ru.username as recipient_username
        FROM emails e
        JOIN users su ON e.sender_id = su.id
        JOIN users ru ON e.recipient_id = ru.id
        WHERE e.id = ?
    """, (email_id,)).fetchone()

    if not r:
        abort(404)

    # Permission check: sender, recipient, or admin only
    if session['user_id'] not in (r['sender_id'], r['recipient_id']) and not session.get('is_admin'):
        abort(403)

    # Decrypt and return only the email HTML body (no layout, no styling from site)
    body = decrypt_text(r['body'])

    # Return with proper headers so browsers render it as HTML
    return body, 200, {"Content-Type": "text/html"}


# Download attachment
@app.route("/attachment/<int:att_id>")
@login_required
def attachment(att_id):
    db = get_db()
    a = db.execute("""
        SELECT a.*, e.sender_id, e.recipient_id
        FROM attachments a JOIN emails e ON a.email_id = e.id
        WHERE a.id = ?
    """, (att_id,)).fetchone()
    if not a:
        abort(404)
    if session['user_id'] not in (a['sender_id'], a['recipient_id']) and not session.get('is_admin'):
        abort(403)
    data = decrypt_file_to_bytes(a['stored_filename'])
    if data is None:
        abort(404)
    return send_file(BytesIO(data), download_name=a['original_filename'], as_attachment=True)

# Trash / Restore / Delete email
@app.route("/email/<int:email_id>/trash", methods=["POST"])
@login_required
def toggle_trash(email_id):
    action = request.form.get("action")
    db = get_db()
    r = db.execute("SELECT * FROM emails WHERE id = ?", (email_id,)).fetchone()
    if not r:
        abort(404)
    if session['user_id'] not in (r['sender_id'], r['recipient_id']) and not session.get('is_admin'):
        abort(403)
    if action == "trash":
        db.execute("UPDATE emails SET trashed = 1 WHERE id = ?", (email_id,))
    elif action == "restore":
        db.execute("UPDATE emails SET trashed = 0 WHERE id = ?", (email_id,))
    elif action == "delete":
        atts = db.execute("SELECT * FROM attachments WHERE email_id = ?", (email_id,)).fetchall()
        for att in atts:
            path = os.path.join(app.config['UPLOAD_FOLDER'], att['stored_filename'])
            try:
                os.remove(path)
            except Exception:
                pass
        db.execute("DELETE FROM attachments WHERE email_id = ?", (email_id,))
        db.execute("DELETE FROM emails WHERE id = ?", (email_id,))
    db.commit()
    flash("Action completed.", "info")
    return redirect(request.referrer or url_for('inbox'))

# Search
@app.route("/search")
@login_required
def search():
    q = request.args.get("q", "").strip().lower()
    folder = request.args.get("folder", "all")
    db = get_db()
    if session.get('is_admin'):
        rows = db.execute("""
            SELECT e.*, su.username as sender_username, ru.username as recipient_username
            FROM emails e
            JOIN users su ON e.sender_id = su.id
            JOIN users ru ON e.recipient_id = ru.id
            ORDER BY e.timestamp DESC
        """).fetchall()
    else:
        rows = db.execute("""
            SELECT e.*, su.username as sender_username, ru.username as recipient_username
            FROM emails e
            JOIN users su ON e.sender_id = su.id
            JOIN users ru ON e.recipient_id = ru.id
            WHERE e.sender_id = ? OR e.recipient_id = ?
            ORDER BY e.timestamp DESC
        """, (session['user_id'], session['user_id'])).fetchall()
    results = []
    for r in rows:
        if folder == 'inbox' and r['recipient_id'] != session['user_id']:
            continue
        if folder == 'sent' and r['sender_id'] != session['user_id']:
            continue
        if folder == 'trash' and r['trashed'] == 0:
            continue
        if folder == 'not_trash' and r['trashed'] == 1:
            continue
        subject = decrypt_text(r['subject'])
        body = decrypt_text(r['body'])
        sender = r['sender_username']
        if (q in subject.lower()) or (q in body.lower()) or (q in sender.lower()):
            results.append({
                'id': r['id'],
                'subject': subject,
                'body_preview': (body[:300] + '...') if len(body) > 300 else body,
                'sender_username': sender,
                'recipient_username': r['recipient_username'],
                'timestamp': r['timestamp'],
                'is_read': bool(r['is_read']),
                'trashed': bool(r['trashed']),
                'is_whisper': bool(r['is_whisper'])
            })
    return render_template("search.html", q=q, results=results)

# Admin Dashboard
@app.route("/admin")
@admin_required
def admin_dashboard():
    db = get_db()
    users = db.execute("SELECT id, username, is_admin, created_at FROM users ORDER BY username").fetchall()
    emails = db.execute("""
        SELECT e.*, su.username as sender_username, ru.username as recipient_username
        FROM emails e
        JOIN users su ON e.sender_id = su.id
        JOIN users ru ON e.recipient_id = ru.id
        ORDER BY e.timestamp DESC
    """).fetchall()
    emails_out = [{
        'id': r['id'],
        'sender_username': r['sender_username'],
        'recipient_username': r['recipient_username'],
        'subject': decrypt_text(r['subject']),
        'body_preview': (decrypt_text(r['body'])[:300] + '...') if len(decrypt_text(r['body'])) > 300 else decrypt_text(r['body']),
        'timestamp': r['timestamp'],
        'is_read': bool(r['is_read']),
        'trashed': bool(r['trashed']),
        'is_whisper': bool(r['is_whisper'])
    } for r in emails]
    return render_template("admin_dashboard.html", users=users, emails=emails_out)

# Admin - view a single user and purge (delete account + emails they sent)
@app.route("/admin/user/<int:user_id>")
@admin_required
def admin_view_user(user_id):
    db = get_db()
    u = db.execute("SELECT id, username, is_admin, created_at FROM users WHERE id = ?", (user_id,)).fetchone()
    if not u:
        abort(404)
    # fetch emails they sent
    sent = db.execute("""
        SELECT e.*, ru.username as recipient_username
        FROM emails e
        JOIN users ru ON e.recipient_id = ru.id
        WHERE e.sender_id = ?
        ORDER BY e.timestamp DESC
    """, (user_id,)).fetchall()
    # decrypt subject previews
    sent_out = [{
        'id': r['id'],
        'recipient_username': r['recipient_username'],
        'subject': decrypt_text(r['subject']),
        'timestamp': r['timestamp'],
        'is_whisper': bool(r['is_whisper'])
    } for r in sent]
    return render_template("admin_user.html", user=u, sent=sent_out)

# Purge specific user (delete user and their sent emails)
@app.route("/admin/purge_user/<int:user_id>", methods=["POST"])
@admin_required
def purge_user(user_id):
    db = get_db()
    db.execute("DELETE FROM attachments WHERE email_id IN (SELECT id FROM emails WHERE sender_id = ?)", (user_id,))
    db.execute("DELETE FROM emails WHERE sender_id = ?", (user_id,))
    db.execute("DELETE FROM users WHERE id = ? AND is_admin = 0", (user_id,))
    db.commit()
    flash("User purged successfully.", "info")
    return redirect(url_for('admin_dashboard'))

# Purge all trashed emails
@app.route("/admin/purge_trash", methods=["POST"])
@admin_required
def purge_trash():
    db = get_db()
    atts = db.execute("SELECT stored_filename FROM attachments WHERE email_id IN (SELECT id FROM emails WHERE trashed = 1)").fetchall()
    for att in atts:
        try:
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], att['stored_filename']))
        except Exception:
            pass
    db.execute("DELETE FROM attachments WHERE email_id IN (SELECT id FROM emails WHERE trashed = 1)")
    db.execute("DELETE FROM emails WHERE trashed = 1")
    db.commit()
    flash("All trashed emails permanently deleted.", "success")
    return redirect(url_for('admin_dashboard'))


# Admin set password
@app.route("/admin/set_password", methods=["GET", "POST"])
@admin_required
def admin_set_password():
    if request.method == "POST":
        newpwd = request.form.get("new_password", "")
        if not newpwd:
            flash("Provide a new password.", "danger")
            return render_template("admin_set_password.html")
        db = get_db()
        db.execute("UPDATE users SET password_hash = ? WHERE username = ?", (generate_password_hash(newpwd), "Admin"))
        db.commit()
        flash("Admin password updated.", "success")
        return redirect(url_for('admin_dashboard'))
    return render_template("admin_set_password.html")

# -------------------- Context --------------------
@app.context_processor
def inject_user():
    return dict(
        current_user_id=session.get('user_id'),
        current_username=session.get('username'),
        is_admin=session.get('is_admin', False),
        current_year=datetime.now().year
    )

# -------------------- Run --------------------
if __name__ == "__main__":
    app.run(debug=True)
