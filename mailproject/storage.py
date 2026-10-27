"""Thread-safe SQLite and raw-message storage shared by SMTP and POP3."""
import hashlib
import hmac
import os
import secrets
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path


class Storage:
    def __init__(self, root):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.messages = self.root / 'messages'
        self.messages.mkdir(exist_ok=True)
        self.db = self.root / 'mail.sqlite3'
        self._locks_guard = threading.Lock()
        self._mailbox_locks = {}
        with self.connect() as c:
            c.executescript('''
            CREATE TABLE IF NOT EXISTS users (address TEXT PRIMARY KEY, salt BLOB NOT NULL, password_hash BLOB NOT NULL);
            CREATE TABLE IF NOT EXISTS messages (id TEXT PRIMARY KEY, sender TEXT NOT NULL, received_at TEXT NOT NULL, path TEXT NOT NULL, size INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS deliveries (uid TEXT PRIMARY KEY, message_id TEXT NOT NULL REFERENCES messages(id), recipient TEXT NOT NULL REFERENCES users(address));
            CREATE INDEX IF NOT EXISTS deliveries_recipient ON deliveries(recipient);
            ''')

    @contextmanager
    def connect(self):
        conn = sqlite3.connect(self.db, timeout=30)
        try:
            conn.execute('PRAGMA foreign_keys=ON')
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    @staticmethod
    def normalize(address):
        return address.strip().lower()

    def add_user(self, address, password):
        address = self.normalize(address)
        if not address or not address.isascii() or address.count('@') != 1 or not password or any(c.isspace() for c in address) or '\r' in password or '\n' in password:
            raise ValueError('需要有效的邮箱地址和非空密码')
        salt = os.urandom(16)
        digest = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 300_000)
        with self.connect() as c:
            c.execute('INSERT INTO users VALUES (?, ?, ?)', (address, salt, digest))

    def has_user(self, address):
        with self.connect() as c:
            return c.execute('SELECT 1 FROM users WHERE address=?', (self.normalize(address),)).fetchone() is not None

    def authenticate(self, address, password):
        with self.connect() as c:
            row = c.execute('SELECT salt, password_hash FROM users WHERE address=?', (self.normalize(address),)).fetchone()
        if not row:
            return False
        return hmac.compare_digest(row[1], hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), row[0], 300_000))

    def deliver(self, sender, recipients, raw):
        # Canonical line endings are necessary for POP3 octet counts and dot-stuffing.
        raw = raw.replace(b'\r\n', b'\n').replace(b'\r', b'\n').replace(b'\n', b'\r\n')
        if not raw.endswith(b'\r\n'):
            raw += b'\r\n'
        mid = uuid.uuid4().hex
        path = self.messages / (mid + '.eml')
        unique = list(dict.fromkeys(map(self.normalize, recipients)))
        try:
            with path.open('xb') as f:
                f.write(raw)
            with self.connect() as c:
                c.execute('INSERT INTO messages VALUES (?,?,?,?,?)', (mid, sender, datetime.now(timezone.utc).isoformat(), path.name, len(raw)))
                c.executemany('INSERT INTO deliveries VALUES (?,?,?)', [(uuid.uuid4().hex, mid, x) for x in unique])
        except Exception:
            path.unlink(missing_ok=True)
            raise

    def mailbox_lock(self, user):
        with self._locks_guard:
            return self._mailbox_locks.setdefault(self.normalize(user), threading.Lock())

    def list_mail(self, user):
        with self.connect() as c:
            return c.execute('''SELECT d.uid, m.path, m.size FROM deliveries d JOIN messages m ON d.message_id=m.id WHERE d.recipient=? ORDER BY m.received_at, d.uid''', (self.normalize(user),)).fetchall()

    def read_mail(self, filename):
        return (self.messages / filename).read_bytes()

    def delete_mail(self, user, uids):
        with self.connect() as c:
            c.executemany('DELETE FROM deliveries WHERE recipient=? AND uid=?', [(self.normalize(user), uid) for uid in uids])
