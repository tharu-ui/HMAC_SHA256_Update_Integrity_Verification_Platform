import hashlib
import json
import sqlite3
from pathlib import Path
from datetime import datetime, timezone

DB_PATH = Path("data/platform.db")


def connect():
    DB_PATH.parent.mkdir(exist_ok=True)
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    return db


def init_db():
    with connect() as db:
        db.execute("""CREATE TABLE IF NOT EXISTS audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL, event TEXT NOT NULL,
            app_name TEXT, version TEXT, status TEXT NOT NULL, detail TEXT)""")
        cols = {r[1] for r in db.execute("PRAGMA table_info(audit)")}
        for col in ("prev_hash", "entry_hash"):  # migrate older databases
            if col not in cols:
                db.execute(f"ALTER TABLE audit ADD COLUMN {col} TEXT")
        db.execute("""CREATE TABLE IF NOT EXISTS accepted_updates (
            app_name TEXT PRIMARY KEY, version TEXT NOT NULL, update_id TEXT NOT NULL, accepted_at TEXT NOT NULL)""")
        db.execute("""CREATE TABLE IF NOT EXISTS seen_updates (
            update_id TEXT PRIMARY KEY, first_seen TEXT NOT NULL)""")


def _entry_hash(prev, created_at, event, app_name, version, status, detail):
    raw = "|".join([prev or "", created_at, event, app_name or "", version or "", status, detail])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def log_event(event, status, app_name="", version="", detail=None):
    """Append an audit row chained to the previous row's hash (tamper-evident log)."""
    created = datetime.now(timezone.utc).isoformat()
    detail_json = json.dumps(detail or {}, ensure_ascii=False)
    with connect() as db:
        row = db.execute("SELECT entry_hash FROM audit WHERE entry_hash IS NOT NULL ORDER BY id DESC LIMIT 1").fetchone()
        prev = row[0] if row else ""
        digest = _entry_hash(prev, created, event, app_name, version, status, detail_json)
        db.execute("INSERT INTO audit(created_at,event,app_name,version,status,detail,prev_hash,entry_hash) VALUES(?,?,?,?,?,?,?,?)",
                   (created, event, app_name, version, status, detail_json, prev, digest))


def verify_chain():
    with connect() as db:
        rows = db.execute("SELECT * FROM audit WHERE entry_hash IS NOT NULL ORDER BY id ASC").fetchall()
    prev = ""
    for r in rows:
        expected = _entry_hash(prev, r["created_at"], r["event"], r["app_name"], r["version"], r["status"], r["detail"])
        if r["prev_hash"] != prev or r["entry_hash"] != expected:
            return {"valid": False, "checked": len(rows), "broken_at": r["id"]}
        prev = r["entry_hash"]
    return {"valid": True, "checked": len(rows), "broken_at": None}


def get_audit(limit=100):
    with connect() as db:
        rows = db.execute("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]


def get_stats():
    with connect() as db:
        q = lambda sql: db.execute(sql).fetchone()[0]
        return {
            "total": q("SELECT COUNT(*) FROM audit WHERE event='verification'"),
            "passed": q("SELECT COUNT(*) FROM audit WHERE event='verification' AND status='ACCEPTED'"),
            "blocked": q("SELECT COUNT(*) FROM audit WHERE event='verification' AND status!='ACCEPTED'"),
            "replay": q("SELECT COUNT(*) FROM audit WHERE status='REPLAY_BLOCKED'"),
            "rollback": q("SELECT COUNT(*) FROM audit WHERE status='ROLLBACK_BLOCKED'"),
            "published": q("SELECT COUNT(*) FROM audit WHERE event='publication'"),
            "tampered": q("SELECT COUNT(*) FROM audit WHERE status='REJECTED'"),
            "expired": q("SELECT COUNT(*) FROM audit WHERE status='EXPIRED'"),
        }


def get_latest_version(app_name):
    with connect() as db:
        row = db.execute("SELECT version FROM accepted_updates WHERE app_name=?", (app_name,)).fetchone()
        return row["version"] if row else None


def was_seen(update_id):
    with connect() as db:
        return db.execute("SELECT 1 FROM seen_updates WHERE update_id=?", (update_id,)).fetchone() is not None


def accept_update(app_name, version, update_id):
    now = datetime.now(timezone.utc).isoformat()
    with connect() as db:
        db.execute("INSERT OR IGNORE INTO seen_updates(update_id,first_seen) VALUES(?,?)", (update_id, now))
        db.execute("""INSERT INTO accepted_updates(app_name,version,update_id,accepted_at) VALUES(?,?,?,?)
            ON CONFLICT(app_name) DO UPDATE SET version=excluded.version, update_id=excluded.update_id,
            accepted_at=excluded.accepted_at""", (app_name, version, update_id, now))


def reset_app(app_name):
    with connect() as db:
        db.execute("DELETE FROM accepted_updates WHERE app_name=?", (app_name,))


# ------------------------------------------------------------ users & sessions
def init_auth_tables():
    with connect() as db:
        db.execute("""CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL COLLATE NOCASE,
            password_hash TEXT NOT NULL, role TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1,
            failed_attempts INTEGER NOT NULL DEFAULT 0, locked_until REAL NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL, last_login TEXT)""")
        db.execute("""CREATE TABLE IF NOT EXISTS sessions (
            token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL, created_at TEXT NOT NULL, expires_at REAL NOT NULL)""")


def user_count():
    with connect() as db:
        return db.execute("SELECT COUNT(*) FROM users").fetchone()[0]


def create_user(username, password_hash, role):
    with connect() as db:
        db.execute("INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)",
                   (username, password_hash, role, datetime.now(timezone.utc).isoformat()))


def get_user_by_name(username):
    with connect() as db:
        row = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        return dict(row) if row else None


def get_user(user_id):
    with connect() as db:
        row = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        return dict(row) if row else None


def list_users():
    with connect() as db:
        rows = db.execute("SELECT id,username,role,active,created_at,last_login FROM users ORDER BY id").fetchall()
        return [dict(r) for r in rows]


def set_password(user_id, password_hash):
    with connect() as db:
        db.execute("UPDATE users SET password_hash=?, failed_attempts=0, locked_until=0 WHERE id=?", (password_hash, user_id))
        db.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))  # force re-login everywhere


def set_active(user_id, active):
    with connect() as db:
        db.execute("UPDATE users SET active=? WHERE id=?", (1 if active else 0, user_id))
        if not active:
            db.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))


def register_failure(user_id, max_failures, lock_seconds, now):
    with connect() as db:
        n = db.execute("SELECT failed_attempts FROM users WHERE id=?", (user_id,)).fetchone()[0] + 1
        if n >= max_failures:
            db.execute("UPDATE users SET failed_attempts=0, locked_until=? WHERE id=?", (now + lock_seconds, user_id))
        else:
            db.execute("UPDATE users SET failed_attempts=? WHERE id=?", (n, user_id))


def register_success(user_id):
    with connect() as db:
        db.execute("UPDATE users SET failed_attempts=0, locked_until=0, last_login=? WHERE id=?",
                   (datetime.now(timezone.utc).isoformat(), user_id))


def create_session(token_hash, user_id, ttl, now):
    with connect() as db:
        db.execute("DELETE FROM sessions WHERE expires_at < ?", (now,))
        db.execute("INSERT INTO sessions(token_hash,user_id,created_at,expires_at) VALUES(?,?,?,?)",
                   (token_hash, user_id, datetime.now(timezone.utc).isoformat(), now + ttl))


def get_session_user(token_hash, now):
    with connect() as db:
        row = db.execute("""SELECT u.id,u.username,u.role FROM sessions s JOIN users u ON u.id=s.user_id
                            WHERE s.token_hash=? AND s.expires_at>? AND u.active=1""", (token_hash, now)).fetchone()
        return dict(row) if row else None


def delete_session(token_hash):
    with connect() as db:
        db.execute("DELETE FROM sessions WHERE token_hash=?", (token_hash,))
