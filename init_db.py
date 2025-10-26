# init_db.py
import sqlite3, os
from werkzeug.security import generate_password_hash

DB_PATH = "app.db"

if os.path.exists(DB_PATH):
    os.remove(DB_PATH)

conn = sqlite3.connect(DB_PATH)
c = conn.cursor()

# ---------------- USERS ----------------
c.execute("""
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    is_admin INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
""")

# ---------------- EMAILS ----------------
# Now includes:
# - is_whisper (int)
# - whisper_code_hash (for hashed unlock code)
# - self_destruct (int)
c.execute("""
CREATE TABLE emails (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id INTEGER NOT NULL,
    recipient_id INTEGER NOT NULL,
    subject BLOB,
    body BLOB,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_read INTEGER DEFAULT 0,
    trashed INTEGER DEFAULT 0,
    is_whisper INTEGER DEFAULT 0,
    whisper_code_hash TEXT,
    self_destruct INTEGER DEFAULT 0,
    FOREIGN KEY(sender_id) REFERENCES users(id),
    FOREIGN KEY(recipient_id) REFERENCES users(id)
)
""")

# ---------------- ATTACHMENTS ----------------
c.execute("""
CREATE TABLE attachments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email_id INTEGER,
    original_filename TEXT,
    stored_filename TEXT,
    FOREIGN KEY(email_id) REFERENCES emails(id)
)
""")

# ---------------- INSERT ADMIN ----------------
admin_password = generate_password_hash("admin123")
c.execute(
    "INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, 1)",
    ("XNYO", admin_password)
)

conn.commit()
conn.close()
print("✅ Database initialized with whisper support")
