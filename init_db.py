import os
import sqlite3
import shutil
from datetime import datetime

# ── BASE DIRECTORY ────────────────────────────────────────────────
# Always resolve DB paths relative to this file's location so that
# Flask started from any CWD still finds the correct database files.
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, 'data')

# Ensure data directory exists
if not os.path.exists(DATA_DIR):
    os.makedirs(DATA_DIR)

MASTER_DB_PATH = os.environ.get(
    'MASTER_DB_PATH',
    os.path.join(DATA_DIR, 'master.sqlite')
)
LEGACY_DB_PATH = os.path.join(BASE_DIR, 'database.sqlite')


def get_master_conn():
    return sqlite3.connect(MASTER_DB_PATH)


def get_workspace_conn(db_name):
    """Return a connection to a workspace DB.
    If db_name is already an absolute path, use it as-is; otherwise
    resolve it relative to DATA_DIR so we never accidentally create
    DB files in the process CWD.
    """
    if not os.path.isabs(db_name):
        db_name = os.path.join(DATA_DIR, db_name)
    return sqlite3.connect(db_name)


def abs_db_path(db_name):
    """Return the absolute path for a workspace db_name."""
    if os.path.isabs(db_name):
        return db_name
    return os.path.join(DATA_DIR, db_name)


def migrate_legacy():
    legacy_abs = LEGACY_DB_PATH
    default_abs = abs_db_path('ws_default.sqlite')
    if os.path.exists(legacy_abs) and not os.path.exists(MASTER_DB_PATH):
        print("Migrating legacy database.sqlite to native workspaces...")
        conn_legacy = sqlite3.connect(legacy_abs)
        c_leg = conn_legacy.cursor()

        # Check if users table exists
        c_leg.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
        has_users = c_leg.fetchone()

        users_data = []
        if has_users:
            c_leg.execute("SELECT username, password_hash, api_key FROM users")
            users_data = c_leg.fetchall()

        conn_legacy.close()

        # Rename to ws_default.sqlite
        os.rename(legacy_abs, default_abs)

        # Create master
        init_master_db()

        conn_master = get_master_conn()
        cm = conn_master.cursor()

        # Insert users
        for u in users_data:
            cm.execute("INSERT INTO users (username, password_hash, api_key) VALUES (?, ?, ?)", u)

        # Insert workspace
        cm.execute("INSERT INTO workspaces (name, db_name, created) VALUES (?, ?, ?)",
                   ('Default Workspace', 'ws_default.sqlite', datetime.now().isoformat()))
        conn_master.commit()
        conn_master.close()
        print("Migration complete!")


def init_master_db():
    conn = get_master_conn()
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            api_key TEXT UNIQUE
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS workspaces (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            db_name TEXT UNIQUE NOT NULL,
            created TEXT
        )
    ''')
    conn.commit()
    conn.close()


def init_workspace_db(db_name):
    conn = get_workspace_conn(db_name)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS targets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            scope TEXT,
            outScope TEXT,
            platform TEXT,
            status TEXT,
            bounty TEXT,
            url TEXT,
            notes TEXT,
            created TEXT,
            tags TEXT,
            deadline TEXT,
            sessionTime INTEGER DEFAULT 0
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            severity TEXT,
            type TEXT,
            host TEXT,
            status TEXT,
            endpoint TEXT,
            cvss TEXT,
            desc TEXT,
            payload TEXT,
            bountyEarned TEXT,
            targetId INTEGER,
            created TEXT,
            tags TEXT,
            screenshots TEXT,
            remediation TEXT
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            category TEXT,
            target TEXT,
            content TEXT,
            created TEXT,
            tags TEXT
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS checklist (
            cid TEXT PRIMARY KEY,
            checked BOOLEAN,
            notes TEXT
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            targetId INTEGER NOT NULL,
            value TEXT NOT NULL,
            type TEXT,
            status TEXT,
            notes TEXT,
            created TEXT
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS config (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS activity (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            html TEXT,
            icon TEXT,
            created INTEGER
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            targetId INTEGER NOT NULL,
            startTime INTEGER,
            endTime INTEGER,
            FOREIGN KEY(targetId) REFERENCES targets(id)
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS oob_payloads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            uid TEXT UNIQUE NOT NULL,
            label TEXT,
            targetId INTEGER,
            created TEXT
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS oob_hits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            uid TEXT NOT NULL,
            source_ip TEXT,
            method TEXT,
            headers TEXT,
            body TEXT,
            created TEXT
        )
    ''')

    # Create indexes for optimized querying
    c.execute('CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(targetId)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_assets_target ON assets(targetId)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_sessions_target ON sessions(targetId)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_oob_payloads_target ON oob_payloads(targetId)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_oob_hits_uid ON oob_hits(uid)')

    # Run the dynamic migrations for older databases
    migrate_workspace_schema(conn)

    conn.commit()
    conn.close()


def migrate_workspace_schema(conn):
    c = conn.cursor()
    c.execute("PRAGMA table_info(findings)")
    cols = {row[1] for row in c.fetchall()}
    if 'targetId' not in cols:
        c.execute('ALTER TABLE findings ADD COLUMN targetId INTEGER')
    if 'tags' not in cols:
        c.execute('ALTER TABLE findings ADD COLUMN tags TEXT')
    if 'screenshots' not in cols:
        c.execute('ALTER TABLE findings ADD COLUMN screenshots TEXT')
    if 'remediation' not in cols:
        c.execute('ALTER TABLE findings ADD COLUMN remediation TEXT')

    c.execute("PRAGMA table_info(checklist)")
    cl_cols = {row[1] for row in c.fetchall()}
    if 'notes' not in cl_cols:
        c.execute('ALTER TABLE checklist ADD COLUMN notes TEXT')

    c.execute("PRAGMA table_info(targets)")
    target_cols = {row[1] for row in c.fetchall()}
    if 'tags' not in target_cols:
        c.execute('ALTER TABLE targets ADD COLUMN tags TEXT')
    if 'deadline' not in target_cols:
        c.execute('ALTER TABLE targets ADD COLUMN deadline TEXT')
    if 'sessionTime' not in target_cols:
        c.execute('ALTER TABLE targets ADD COLUMN sessionTime INTEGER DEFAULT 0')

    c.execute("PRAGMA table_info(notes)")
    note_cols = {row[1] for row in c.fetchall()}
    if 'tags' not in note_cols:
        c.execute('ALTER TABLE notes ADD COLUMN tags TEXT')

    c.execute('''
        CREATE TABLE IF NOT EXISTS oob_payloads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            uid TEXT UNIQUE NOT NULL,
            label TEXT,
            targetId INTEGER,
            created TEXT
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS oob_hits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            uid TEXT NOT NULL,
            source_ip TEXT,
            method TEXT,
            headers TEXT,
            body TEXT,
            created TEXT
        )
    ''')


def init_all():
    migrate_legacy()
    init_master_db()
    # Check if any workspaces exist, if not create default
    conn = get_master_conn()
    c = conn.cursor()
    c.execute("SELECT count(*) FROM workspaces")
    count = c.fetchone()[0]
    if count == 0:
        c.execute("INSERT INTO workspaces (name, db_name, created) VALUES (?, ?, ?)",
                  ('Default Workspace', 'ws_default.sqlite', datetime.now().isoformat()))
        conn.commit()

    c.execute("SELECT db_name FROM workspaces")
    for row in c.fetchall():
        init_workspace_db(row[0])

    # Generate API keys for master users if missing
    c.execute("PRAGMA table_info(users)")
    user_cols = {r[1] for r in c.fetchall()}
    if 'api_key' not in user_cols:
        c.execute('ALTER TABLE users ADD COLUMN api_key TEXT')
    import secrets as _secrets
    c.execute('SELECT id FROM users WHERE api_key IS NULL')
    for r in c.fetchall():
        c.execute('UPDATE users SET api_key = ? WHERE id = ?', (_secrets.token_hex(16), r[0]))
    conn.commit()

    conn.close()
    print('Databases initialized successfully!')


if __name__ == '__main__':
    init_all()
