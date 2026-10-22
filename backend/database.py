import sqlite3
from backend.config import settings

def connect():
    path = settings.path(settings.database_path); path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path); db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    return db

def init_db():
    with connect() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, created_at TEXT NOT NULL, severity TEXT NOT NULL, event_type TEXT NOT NULL, detail TEXT NOT NULL, client TEXT);
        CREATE TABLE IF NOT EXISTS transfers(id INTEGER PRIMARY KEY, created_at TEXT NOT NULL, filename TEXT NOT NULL, sha256 TEXT NOT NULL, status TEXT NOT NULL, request_id TEXT);
        CREATE TABLE IF NOT EXISTS nonces(request_id TEXT PRIMARY KEY, created_at TEXT NOT NULL);
        """)

def event(severity, kind, detail, client=None):
    from datetime import datetime, timezone
    with connect() as db: db.execute("INSERT INTO events(created_at,severity,event_type,detail,client) VALUES(?,?,?,?,?)", (datetime.now(timezone.utc).isoformat(),severity,kind,detail[:500],client))

def transfer(filename, digest, status, request_id):
    from datetime import datetime, timezone
    with connect() as db: db.execute("INSERT INTO transfers(created_at,filename,sha256,status,request_id) VALUES(?,?,?,?,?)",(datetime.now(timezone.utc).isoformat(),filename[:255],digest,status,request_id))
