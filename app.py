import os
import re
import html
import json
import queue
import secrets
import sqlite3
import subprocess
import threading
import urllib.request
import urllib.error
import platform
import uuid
import base64
import gzip
import io
from datetime import datetime
from functools import wraps

from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session, Response, send_from_directory
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash

from init_db import init_all, get_master_conn, get_workspace_conn, MASTER_DB_PATH, init_workspace_db, abs_db_path

# ── APP SETUP ─────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, 'data')
SECRET_KEY_FILE = os.path.join(DATA_DIR, '.secret_key')

def _load_or_generate_secret_key():
    """Load SECRET_KEY from env, .secret_key file, or generate a new one."""
    env_key = os.environ.get('SECRET_KEY')
    if env_key and env_key != 'change-me-in-production-0xhunter':
        return env_key
    if os.path.exists(SECRET_KEY_FILE):
        with open(SECRET_KEY_FILE, 'r') as f:
            key = f.read().strip()
        if key:
            return key
    key = secrets.token_hex(32)
    try:
        with open(SECRET_KEY_FILE, 'w') as f:
            f.write(key)
    except Exception:
        pass
    return key

app = Flask(__name__)
app.config['SECRET_KEY'] = _load_or_generate_secret_key()
app.config['DEBUG'] = os.environ.get('FLASK_DEBUG', '0') == '1'
app.config['TEMPLATES_AUTO_RELOAD'] = True

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@app.after_request
def optimize_responses(response):
    # 1. Cache-Control optimization for static resources
    if request.path.startswith('/static/'):
        response.headers['Cache-Control'] = 'public, max-age=31536000, immutable'
    else:
        # Dynamically request new data for APIs and dynamic HTML pages
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'

    # 2. Native Gzip Compression for large text/JSON content
    accept_encoding = request.headers.get('Accept-Encoding', '')
    if (
        response.status_code < 200 or response.status_code >= 300 or
        'gzip' not in accept_encoding.lower() or
        response.headers.get('Content-Encoding')
    ):
        return response

    content_type = response.headers.get('Content-Type', '')
    is_compressible = (
        'text/' in content_type or
        'javascript' in content_type or
        'json' in content_type or
        'xml' in content_type
    )

    if not is_compressible:
        return response

    # Skip compression for tiny payloads
    response.direct_passthrough = False
    data = response.get_data()
    if len(data) < 500:
        return response

    # Perform compression using built-in gzip
    gzip_buffer = io.BytesIO()
    with gzip.GzipFile(mode='wb', fileobj=gzip_buffer) as gzip_file:
        gzip_file.write(data)

    response.set_data(gzip_buffer.getvalue())
    response.headers['Content-Encoding'] = 'gzip'
    response.headers['Content-Length'] = len(response.get_data())
    response.headers['Vary'] = 'Accept-Encoding'

    return response


class User(UserMixin):
    def __init__(self, id_, username):
        self.id = id_
        self.username = username


@login_manager.user_loader
def load_user(user_id):
    conn = get_master_conn()
    c = conn.cursor()
    c.execute('SELECT id, username FROM users WHERE id = ?', (user_id,))
    row = c.fetchone()
    conn.close()
    if row:
        return User(row[0], row[1])
    return None


def get_db():
    db_name = session.get('active_workspace_db', 'ws_default.sqlite')
    conn = get_workspace_conn(db_name)
    conn.row_factory = sqlite3.Row
    return conn


def api_login_required(f):
    """Decorator that authenticates via session (Flask-Login) OR Bearer API key.
    When using a Bearer token, current_user is explicitly set so downstream
    code can use current_user.id safely.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        if current_user.is_authenticated:
            return f(*args, **kwargs)

        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            api_key = auth_header.split(' ', 1)[1]
            conn = get_master_conn()
            c = conn.cursor()
            c.execute('SELECT id, username FROM users WHERE api_key = ?', (api_key,))
            row = c.fetchone()
            conn.close()
            if row:
                # Set Flask-Login context for this request
                user = User(row[0], row[1])
                login_user(user)
                return f(*args, **kwargs)

        return jsonify({'error': 'Unauthorized'}), 401
    return decorated


def api_key_required(f):
    """Decorator that enforces strict Bearer API key authentication only (no session).
    Used for ingest API to prevent CSRF.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            api_key = auth_header.split(' ', 1)[1]
            conn = get_master_conn()
            c = conn.cursor()
            c.execute('SELECT id, username FROM users WHERE api_key = ?', (api_key,))
            row = c.fetchone()
            conn.close()
            if row:
                user = User(row[0], row[1])
                login_user(user)
                return f(*args, **kwargs)

        return jsonify({'error': 'Strict Bearer API key authentication required'}), 401
    return decorated


def truncate(val, limit=50000):
    if val is None:
        return None
    s = str(val)
    return s[:limit] if len(s) > limit else s


# ── SAFE HTML for activity feed ────────────────────────────────────
def sanitize_activity_html(raw_html):
    """Strip all HTML tags except a safe allowlist, and strip ALL attributes to prevent XSS."""
    if not raw_html:
        return ''
    safe = re.sub(r'<(?!/?(?:strong|em|b|i|span|a)\b)[^>]+>', '', str(raw_html), flags=re.IGNORECASE)
    safe = re.sub(r'<(/?[a-zA-Z0-9]+)\s+[^>]+>', r'<\1>', safe)
    return safe


# ─────────────────────────────────────────────────────────────────
# AUTH ROUTES
# ─────────────────────────────────────────────────────────────────
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        password = request.form.get('password') or ''
        conn = get_master_conn()
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute('SELECT id, username, password_hash FROM users WHERE username = ?', (username,))
        row = c.fetchone()
        conn.close()
        if row and check_password_hash(row['password_hash'], password):
            login_user(User(row['id'], row['username']), remember=True)
            next_url = request.args.get('next') or url_for('index')
            return redirect(next_url)
        flash('Invalid username or password', 'error')
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/')
@login_required
def index():
    active_ws = session.get('active_workspace_db', 'ws_default.sqlite')
    conn = get_master_conn()
    c = conn.cursor()
    c.execute("SELECT name FROM workspaces WHERE db_name = ?", (active_ws,))
    ws_row = c.fetchone()
    ws_name = ws_row[0] if ws_row else "Workspace"
    conn.close()
    return render_template('index.html', active_workspace_name=ws_name, username=current_user.username)


# ─────────────────────────────────────────────────────────────────
# WORKSPACES API
# ─────────────────────────────────────────────────────────────────
@app.route('/api/workspaces', methods=['GET'])
@api_login_required
def get_workspaces():
    conn = get_master_conn()
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT id, name, db_name, created FROM workspaces ORDER BY id ASC")
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    active = session.get('active_workspace_db', 'ws_default.sqlite')
    return jsonify({"workspaces": rows, "active": active})


@app.route('/api/workspaces', methods=['POST'])
@api_login_required
def create_workspace():
    data = request.json or {}
    name = data.get('name', '').strip()
    if not name:
        return jsonify({'error': 'Name is required'}), 400

    db_name = f"ws_{uuid.uuid4().hex[:8]}.sqlite"

    conn = get_master_conn()
    c = conn.cursor()
    c.execute("INSERT INTO workspaces (name, db_name, created) VALUES (?, ?, ?)",
              (name, db_name, datetime.now().isoformat()))
    conn.commit()
    conn.close()

    init_workspace_db(db_name)
    return jsonify({"success": True, "db_name": db_name})


@app.route('/api/workspaces/switch', methods=['POST'])
@api_login_required
def switch_workspace():
    data = request.json or {}
    db_name = data.get('db_name')
    if not db_name:
        return jsonify({'error': 'db_name required'}), 400

    conn = get_master_conn()
    c = conn.cursor()
    c.execute("SELECT id FROM workspaces WHERE db_name = ?", (db_name,))
    if not c.fetchone():
        conn.close()
        return jsonify({'error': 'Workspace not found'}), 404
    conn.close()

    session['active_workspace_db'] = db_name
    return jsonify({"success": True})


@app.route('/api/workspaces/<int:ws_id>', methods=['DELETE'])
@api_login_required
def delete_workspace(ws_id):
    conn = get_master_conn()
    c = conn.cursor()
    c.execute("SELECT db_name FROM workspaces WHERE id = ?", (ws_id,))
    row = c.fetchone()
    if not row:
        conn.close()
        return jsonify({'error': 'Not found'}), 404

    db_name = row[0]
    if db_name == 'ws_default.sqlite':
        conn.close()
        return jsonify({'error': 'Cannot delete default workspace'}), 400

    c.execute("DELETE FROM workspaces WHERE id = ?", (ws_id,))
    conn.commit()
    conn.close()

    # Switch session if active
    if session.get('active_workspace_db') == db_name:
        session['active_workspace_db'] = 'ws_default.sqlite'

    # Use absolute path to safely delete the file
    abs_path = abs_db_path(db_name)
    try:
        if os.path.exists(abs_path):
            os.remove(abs_path)
    except Exception as e:
        print("Failed to delete sqlite file:", e)

    return jsonify({"success": True})


# ─────────────────────────────────────────────────────────────────
# DATA API
# ─────────────────────────────────────────────────────────────────
@app.route('/api/data', methods=['GET'])
@api_login_required
def get_data():
    conn = get_db()
    c = conn.cursor()

    c.execute('SELECT * FROM targets ORDER BY id DESC')
    targets = [dict(row) for row in c.fetchall()]

    c.execute('SELECT * FROM findings ORDER BY id DESC')
    findings = [dict(row) for row in c.fetchall()]

    c.execute('SELECT * FROM notes ORDER BY id DESC')
    notes = [dict(row) for row in c.fetchall()]

    c.execute('SELECT * FROM assets ORDER BY id DESC')
    assets = [dict(row) for row in c.fetchall()]

    c.execute('SELECT cid, checked, notes FROM checklist')
    checklist = {row['cid']: {'checked': bool(row['checked']), 'notes': row['notes'] or ''} for row in c.fetchall()}

    c.execute('CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT)')
    c.execute('SELECT key, value FROM config')
    config = {row['key']: row['value'] for row in c.fetchall()}

    c.execute('SELECT html, icon, created FROM activity ORDER BY created DESC LIMIT 50')
    activity = [{'html': r['html'], 'icon': r['icon'], 'time': r['created']} for r in c.fetchall()]

    c.execute('CREATE TABLE IF NOT EXISTS oob_payloads (id INTEGER PRIMARY KEY AUTOINCREMENT, uid TEXT UNIQUE NOT NULL, label TEXT, targetId INTEGER, created TEXT)')
    c.execute('SELECT * FROM oob_payloads ORDER BY id DESC')
    oob_payloads = [dict(row) for row in c.fetchall()]

    c.execute('CREATE TABLE IF NOT EXISTS oob_hits (id INTEGER PRIMARY KEY AUTOINCREMENT, uid TEXT NOT NULL, source_ip TEXT, method TEXT, headers TEXT, body TEXT, created TEXT)')
    c.execute('SELECT * FROM oob_hits ORDER BY id DESC')
    oob_hits = [dict(row) for row in c.fetchall()]

    api_key = ''
    if current_user.is_authenticated:
        mconn = get_master_conn()
        mconn.row_factory = sqlite3.Row
        mc = mconn.cursor()
        mc.execute('SELECT api_key FROM users WHERE id = ?', (current_user.id,))
        row = mc.fetchone()
        if row and row['api_key']:
            api_key = row['api_key']
        mconn.close()

    conn.close()
    return jsonify({
        'targets': targets,
        'findings': findings,
        'notes': notes,
        'assets': assets,
        'checklist': checklist,
        'config': config,
        'activity': activity,
        'oob_payloads': oob_payloads,
        'oob_hits': oob_hits,
        'api_key': api_key
    })


@app.route('/api/config', methods=['GET'])
@api_login_required
def get_config():
    conn = get_db()
    c = conn.cursor()
    c.execute('CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT)')
    c.execute('SELECT key, value FROM config')
    config = {row['key']: row['value'] for row in c.fetchall()}
    conn.close()
    return jsonify(config)


@app.route('/api/config', methods=['POST'])
@api_login_required
def save_config():
    data = request.get_json(silent=True) or {}
    conn = get_db()
    c = conn.cursor()
    c.execute('CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT)')
    for k, v in data.items():
        c.execute('INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)', (k, v))
    conn.commit()
    conn.close()
    return jsonify({'success': True})


@app.route('/api/stats', methods=['GET'])
@api_login_required
def get_stats():
    import time, calendar
    conn = get_db()
    c = conn.cursor()

    # Monthly earnings for last 6 months
    c.execute('SELECT bountyEarned, created FROM findings WHERE bountyEarned IS NOT NULL AND bountyEarned != ""')
    rows = c.fetchall()

    monthly = {}
    for row in rows:
        amount_raw = str(row['bountyEarned'] or '').replace(',', '')
        nums = re.findall(r'[0-9]+(?:\.[0-9]+)?', amount_raw)
        amount = float(nums[0]) if nums else 0
        if amount <= 0:
            continue
        try:
            ts = int(str(row['created'])[:13]) / 1000
            import datetime as _dt
            dt = _dt.datetime.fromtimestamp(ts)
            key = dt.strftime('%Y-%m')
            monthly[key] = monthly.get(key, 0) + amount
        except Exception:
            pass

    import datetime as _dt
    now = _dt.datetime.now()
    labels = []
    values = []
    for i in range(5, -1, -1):
        d = now - _dt.timedelta(days=30 * i)
        key = d.strftime('%Y-%m')
        labels.append(d.strftime('%b %Y'))
        values.append(monthly.get(key, 0))

    c.execute('SELECT status, COUNT(*) as cnt FROM findings GROUP BY status')
    status_counts = {row['status']: row['cnt'] for row in c.fetchall()}

    c.execute('SELECT platform, COUNT(*) as cnt FROM targets GROUP BY platform')
    platform_counts = {row['platform']: row['cnt'] for row in c.fetchall()}

    c.execute('SELECT severity, COUNT(*) as cnt FROM findings GROUP BY severity')
    sev_counts = {row['severity']: row['cnt'] for row in c.fetchall()}

    conn.close()
    return jsonify({
        'monthly_labels': labels,
        'monthly_values': values,
        'status_counts': status_counts,
        'platform_counts': platform_counts,
        'sev_counts': sev_counts
    })


@app.route('/api/targets/<int:tid>/session', methods=['POST'])
@api_login_required
def update_session_time(tid):
    data = request.get_json(silent=True) or {}
    seconds = data.get('seconds', 0)
    conn = get_db()
    c = conn.cursor()
    c.execute('UPDATE targets SET sessionTime = COALESCE(sessionTime, 0) + ? WHERE id = ?', (max(0, int(seconds)), tid))
    conn.commit()
    conn.close()
    return jsonify({'success': True})


# ─────────────────────────────────────────────────────────────────
# INGEST API (CLI piping)
# ─────────────────────────────────────────────────────────────────
@app.route('/api/ingest', methods=['POST'])
@api_key_required
def ingest_data():
    import time
    data = request.get_data(as_text=True)
    if not data:
        return jsonify({'error': 'No data provided'}), 400

    target_id = request.args.get('targetId') or 0
    conn = get_db()
    c = conn.cursor()

    lines = data.strip().split('\n')
    added_assets = 0
    added_findings = 0

    for line in lines:
        line = line.strip()
        if not line:
            continue

        try:
            j = json.loads(line)
            if 'template-id' in j or 'info' in j:
                title = j.get('info', {}).get('name', j.get('template-id', 'Unknown Vulnerability'))
                severity = j.get('info', {}).get('severity', 'info').lower()
                host = j.get('host', j.get('matched-at', ''))
                desc = j.get('info', {}).get('description', '')

                # Use AUTOINCREMENT — no id specified
                c.execute('''
                    INSERT INTO findings (title, severity, type, host, status, endpoint, cvss, desc, payload, bountyEarned, targetId, created)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    truncate(title, 500), truncate(severity, 50),
                    'Scanner', truncate(host, 2000), 'Found', truncate(host, 2000),
                    '', truncate(desc), '', '', target_id, str(int(time.time() * 1000))
                ))
                added_findings += 1
            else:
                val = j.get('host', j.get('url', str(j)))
                c.execute('INSERT OR IGNORE INTO assets (targetId, value, type, status, notes, created) VALUES (?, ?, ?, ?, ?, ?)',
                          (target_id, truncate(val, 2000), 'url', 'new', '', str(int(time.time() * 1000))))
                added_assets += 1
        except json.JSONDecodeError:
            c.execute('INSERT OR IGNORE INTO assets (targetId, value, type, status, notes, created) VALUES (?, ?, ?, ?, ?, ?)',
                      (target_id, truncate(line, 2000), 'url', 'new', '', str(int(time.time() * 1000))))
            added_assets += 1

    conn.commit()
    conn.close()

    return jsonify({
        'success': True,
        'added_assets': added_assets,
        'added_findings': added_findings
    })


# ─────────────────────────────────────────────────────────────────
# IMPORT / EXPORT
# ─────────────────────────────────────────────────────────────────
@app.route('/api/import', methods=['POST'])
@api_login_required
def import_data():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({'error': 'Invalid JSON'}), 400

    # BUG FIX #5: Require explicit confirmation flag to prevent accidental wipe
    if not data.get('confirm_wipe'):
        return jsonify({'error': 'confirm_wipe flag required. Set confirm_wipe: true to replace all workspace data.'}), 400

    conn = get_db()
    c = conn.cursor()
    try:
        c.execute('DELETE FROM targets')
        c.execute('DELETE FROM findings')
        c.execute('DELETE FROM notes')
        c.execute('DELETE FROM checklist')
        c.execute('DELETE FROM assets')
        c.execute('DELETE FROM activity')

        for t in data.get('targets', []):
            c.execute('''
                INSERT INTO targets (name, scope, outScope, platform, status, bounty, url, notes, created, tags, deadline, sessionTime)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                truncate(t.get('name'), 500), truncate(t.get('scope')),
                truncate(t.get('outScope')), truncate(t.get('platform'), 100),
                truncate(t.get('status'), 50), truncate(t.get('bounty'), 100),
                truncate(t.get('url'), 2000), truncate(t.get('notes')),
                str(t.get('created', '')),
                truncate(t.get('tags'), 1000), truncate(t.get('deadline'), 50),
                int(t.get('sessionTime', 0) or 0),
            ))

        for f in data.get('findings', []):
            c.execute('''
                INSERT INTO findings (title, severity, type, host, status, endpoint, cvss, desc, payload, bountyEarned, targetId, created, tags, screenshots, remediation)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                truncate(f.get('title'), 500), truncate(f.get('severity'), 50),
                truncate(f.get('type'), 100), truncate(f.get('host'), 2000),
                truncate(f.get('status'), 50), truncate(f.get('endpoint'), 2000),
                truncate(f.get('cvss'), 50), truncate(f.get('desc')),
                truncate(f.get('payload')), truncate(f.get('bountyEarned'), 100),
                f.get('targetId'), str(f.get('created', '')),
                truncate(f.get('tags'), 1000),
                truncate(f.get('screenshots')),
                truncate(f.get('remediation')),
            ))

        for n in data.get('notes', []):
            c.execute('''
                INSERT INTO notes (title, category, target, content, created, tags)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                truncate(n.get('title'), 500), truncate(n.get('category'), 100),
                truncate(n.get('target'), 500), truncate(n.get('content')),
                str(n.get('created', '')),
                truncate(n.get('tags'), 1000),
            ))

        for a in data.get('assets', []):
            c.execute('''
                INSERT INTO assets (targetId, value, type, status, notes, created)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                a.get('targetId'), truncate(a.get('value'), 2000),
                truncate(a.get('type'), 50), truncate(a.get('status'), 50),
                truncate(a.get('notes')), str(a.get('created', '')),
            ))

        checklist = data.get('checklist', {})
        for cid, val in checklist.items():
            if isinstance(val, bool):
                checked = val
                notes = ''
            else:
                checked = val.get('checked', False)
                notes = val.get('notes', '')
            c.execute('INSERT INTO checklist (cid, checked, notes) VALUES (?, ?, ?)',
                      (str(cid)[:200], bool(checked), str(notes)))

        for act in data.get('activity', [])[:50]:
            c.execute('INSERT INTO activity (html, icon, created) VALUES (?, ?, ?)',
                      (truncate(sanitize_activity_html(act.get('html')), 2000),
                       truncate(act.get('icon'), 20), act.get('time') or 0))

        conn.commit()
    except Exception as e:
        conn.rollback()
        conn.close()
        return jsonify({'error': str(e)}), 500
    conn.close()
    return jsonify({'success': True})


@app.route('/api/activity', methods=['POST'])
@api_login_required
def add_activity():
    data = request.get_json(silent=True) or {}
    # Sanitize the html before storing to prevent stored XSS in activity feed
    safe_html = sanitize_activity_html(data.get('html', ''))
    conn = get_db()
    c = conn.cursor()
    c.execute('INSERT INTO activity (html, icon, created) VALUES (?, ?, ?)',
              (truncate(safe_html, 2000), truncate(data.get('icon'), 20), data.get('time') or 0))
    c.execute('SELECT id FROM activity ORDER BY created DESC LIMIT -1 OFFSET 50')
    stale = [r[0] for r in c.fetchall()]
    for sid in stale:
        c.execute('DELETE FROM activity WHERE id = ?', (sid,))
    conn.commit()
    conn.close()
    return jsonify({'success': True})


# ─────────────────────────────────────────────────────────────────
# TARGETS
# ─────────────────────────────────────────────────────────────────
@app.route('/api/targets', methods=['POST'])
@api_login_required
def save_target():
    data = request.get_json(silent=True) or {}
    conn = get_db()
    c = conn.cursor()
    c.execute('''
        INSERT OR REPLACE INTO targets
        (id, name, scope, outScope, platform, status, bounty, url, notes, created, tags, deadline, sessionTime)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        data.get('id'), truncate(data.get('name'), 500), truncate(data.get('scope')),
        truncate(data.get('outScope')), truncate(data.get('platform'), 100),
        truncate(data.get('status'), 50), truncate(data.get('bounty'), 100),
        truncate(data.get('url'), 2000), truncate(data.get('notes')),
        str(data.get('created', '')),
        truncate(data.get('tags'), 1000), truncate(data.get('deadline'), 50),
        int(data.get('sessionTime', 0) or 0),
    ))
    conn.commit()
    conn.close()
    return jsonify({'success': True})


@app.route('/api/targets/<int:tid>', methods=['DELETE'])
@api_login_required
def delete_target(tid):
    conn = get_db()
    c = conn.cursor()
    c.execute('DELETE FROM targets WHERE id = ?', (tid,))
    c.execute('DELETE FROM assets WHERE targetId = ?', (tid,))
    conn.commit()
    conn.close()
    return jsonify({'success': True})


# ─────────────────────────────────────────────────────────────────
# FINDINGS
# ─────────────────────────────────────────────────────────────────
@app.route('/api/findings', methods=['POST'])
@api_login_required
def save_finding():
    data = request.get_json(silent=True) or {}
    conn = get_db()
    c = conn.cursor()
    c.execute('''
        INSERT OR REPLACE INTO findings
        (id, title, severity, type, host, status, endpoint, cvss, desc, payload, bountyEarned, targetId, created, tags, screenshots, remediation)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        data.get('id'), truncate(data.get('title'), 500), truncate(data.get('severity'), 50),
        truncate(data.get('type'), 100), truncate(data.get('host'), 2000),
        truncate(data.get('status'), 50), truncate(data.get('endpoint'), 2000),
        truncate(data.get('cvss'), 50), truncate(data.get('desc')),
        truncate(data.get('payload')), truncate(data.get('bountyEarned'), 100),
        data.get('targetId'), str(data.get('created', '')),
        truncate(data.get('tags'), 1000),
        truncate(data.get('screenshots')),
        truncate(data.get('remediation')),
    ))
    conn.commit()

    # Webhook Trigger on New High/Critical findings
    is_new = data.get('id') is None
    sev = str(data.get('severity', '')).lower()
    if is_new and sev in ['high', 'critical']:
        try:
            c.execute("CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT)")
            c.execute("SELECT value FROM config WHERE key = 'webhook_url'")
            row = c.fetchone()
            if row and row['value']:
                payload = {
                    "embeds": [{
                        "title": f"🚨 New {sev.upper()} Finding Logged!",
                        "description": f"**Title:** {data.get('title')}\n**Type:** {data.get('type')}\n**Target:** {data.get('host')}",
                        "color": 15158332 if sev == 'critical' else 15105570
                    }]
                }
                req = urllib.request.Request(row['value'], data=json.dumps(payload).encode('utf-8'),
                                             headers={'Content-Type': 'application/json'}, method='POST')
                urllib.request.urlopen(req, timeout=5)
        except Exception as e:
            print(f"Webhook trigger failed: {e}")

    conn.close()
    return jsonify({'success': True})


@app.route('/api/findings/<int:fid>', methods=['DELETE'])
@api_login_required
def delete_finding(fid):
    conn = get_db()
    c = conn.cursor()
    c.execute('DELETE FROM findings WHERE id = ?', (fid,))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

# ─────────────────────────────────────────────────────────────────
# IMAGE UPLOADS
# ─────────────────────────────────────────────────────────────────
@app.route('/api/upload_image', methods=['POST'])
@api_login_required
def upload_image():
    data = request.json or {}
    if 'image_base64' in data:
        try:
            header, encoded = data['image_base64'].split(',', 1)
            ext = header.split('/')[1].split(';')[0]
            if ext.lower() not in ['png', 'jpg', 'jpeg', 'gif', 'webp']:
                return jsonify({'error': 'Invalid image format'}), 400
            filename = f"{uuid.uuid4().hex}.{ext}"
            img_dir = os.path.join(DATA_DIR, 'images')
            os.makedirs(img_dir, exist_ok=True)
            with open(os.path.join(img_dir, filename), 'wb') as f:
                f.write(base64.b64decode(encoded))
            return jsonify({'url': f'/api/images/{filename}'})
        except Exception as e:
            return jsonify({'error': str(e)}), 400
    return jsonify({'error': 'No image provided'}), 400

@app.route('/api/images/<filename>')
@api_login_required
def serve_image(filename):
    return send_from_directory(os.path.join(DATA_DIR, 'images'), filename)

# ─────────────────────────────────────────────────────────────────
# FILE UPLOADS (PDF, Documents, etc.)
# ─────────────────────────────────────────────────────────────────
import werkzeug.utils
@app.route('/api/upload_file', methods=['POST'])
@api_login_required
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    if file:
        filename = werkzeug.utils.secure_filename(file.filename)
        ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
        if ext in ['js', 'php']:
            return jsonify({'error': 'File type not allowed'}), 400
        # prepend uuid to avoid collisions
        unique_filename = f"{uuid.uuid4().hex}_{filename}"
        files_dir = os.path.join(DATA_DIR, 'files')
        os.makedirs(files_dir, exist_ok=True)
        file.save(os.path.join(files_dir, unique_filename))
        return jsonify({'url': f'/api/files/{unique_filename}'})
    return jsonify({'error': 'Upload failed'}), 500

@app.route('/api/files/<filename>')
@api_login_required
def serve_file(filename):
    # Try local uploaded files first
    local_path = os.path.join(DATA_DIR, 'files', filename)
    if os.path.exists(local_path):
        return send_from_directory(os.path.join(DATA_DIR, 'files'), filename)
    
    # Fallback to git-tracked static/cheat_sheets if missing locally
    clean_name = filename
    if len(filename) > 33 and filename[32] == '_':
        clean_name = filename[33:]
    
    static_cs_path = os.path.join(BASE_DIR, 'static', 'cheat_sheets', clean_name)
    if os.path.exists(static_cs_path):
        return send_from_directory(os.path.join(BASE_DIR, 'static', 'cheat_sheets'), clean_name)
        
    return "File not found", 404

# ─────────────────────────────────────────────────────────────────
# NOTES
# ─────────────────────────────────────────────────────────────────
@app.route('/api/notes', methods=['POST'])
@api_login_required
def save_note():
    data = request.get_json(silent=True) or {}
    conn = get_db()
    c = conn.cursor()
    c.execute('''
        INSERT OR REPLACE INTO notes (id, title, category, target, content, created, tags)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (
        data.get('id'), truncate(data.get('title'), 500), truncate(data.get('category'), 100),
        truncate(data.get('target'), 500), truncate(data.get('content')),
        str(data.get('created', '')),
        truncate(data.get('tags'), 1000),
    ))
    conn.commit()
    conn.close()
    return jsonify({'success': True})


@app.route('/api/notes/<int:nid>', methods=['DELETE'])
@api_login_required
def delete_note(nid):
    conn = get_db()
    c = conn.cursor()
    c.execute('DELETE FROM notes WHERE id = ?', (nid,))
    conn.commit()
    conn.close()
    return jsonify({'success': True})


# ─────────────────────────────────────────────────────────────────
# ASSETS
# ─────────────────────────────────────────────────────────────────
@app.route('/api/assets', methods=['POST'])
@api_login_required
def save_asset():
    data = request.get_json(silent=True) or {}
    conn = get_db()
    c = conn.cursor()
    c.execute('''
        INSERT OR REPLACE INTO assets (id, targetId, value, type, status, notes, created)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (
        data.get('id'), data.get('targetId'), truncate(data.get('value'), 2000),
        truncate(data.get('type'), 50), truncate(data.get('status'), 50),
        truncate(data.get('notes')), str(data.get('created', '')),
    ))
    conn.commit()
    conn.close()
    return jsonify({'success': True})


@app.route('/api/assets/bulk', methods=['POST'])
@api_login_required
def bulk_assets():
    """Bulk insert assets using AUTOINCREMENT (no explicit id) with dedup via INSERT OR IGNORE."""
    data = request.get_json(silent=True) or {}
    target_id = data.get('targetId')
    lines = data.get('lines', [])
    if not target_id:
        return jsonify({'error': 'targetId required'}), 400
    conn = get_db()
    c = conn.cursor()
    import time
    created = []
    for line in lines:
        val = truncate(str(line).strip(), 2000)
        if not val:
            continue
        # INSERT OR IGNORE deduplicates by (targetId, value)
        c.execute('''
            INSERT OR IGNORE INTO assets (targetId, value, type, status, notes, created)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (target_id, val, data.get('type', 'url'), 'new', '', str(int(time.time() * 1000))))
        if c.lastrowid:
            created.append(c.lastrowid)
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'count': len(created)})


@app.route('/api/assets/dedup', methods=['POST'])
@api_login_required
def dedup_assets():
    """Remove duplicate asset entries (same targetId + value) keeping the latest id."""
    data = request.get_json(silent=True) or {}
    target_id = data.get('targetId')
    conn = get_db()
    c = conn.cursor()
    if target_id:
        c.execute('''
            DELETE FROM assets WHERE id NOT IN (
                SELECT MAX(id) FROM assets WHERE targetId = ?
                GROUP BY targetId, value
            ) AND targetId = ?
        ''', (target_id, target_id))
    else:
        c.execute('''
            DELETE FROM assets WHERE id NOT IN (
                SELECT MAX(id) FROM assets GROUP BY targetId, value
            )
        ''')
    removed = c.rowcount
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'removed': removed})


@app.route('/api/assets/<int:aid>', methods=['DELETE'])
@api_login_required
def delete_asset(aid):
    conn = get_db()
    c = conn.cursor()
    c.execute('DELETE FROM assets WHERE id = ?', (aid,))
    conn.commit()
    conn.close()
    return jsonify({'success': True})


# ─────────────────────────────────────────────────────────────────
# CHECKLIST
# ─────────────────────────────────────────────────────────────────
@app.route('/api/checklist', methods=['POST'])
@api_login_required
def save_checklist():
    data = request.get_json(silent=True) or {}
    conn = get_db()
    c = conn.cursor()
    c.execute('DELETE FROM checklist')
    for cid, val in data.items():
        if isinstance(val, bool):
            checked = val
            notes = ''
        else:
            checked = val.get('checked', False)
            notes = val.get('notes', '')
        c.execute('INSERT INTO checklist (cid, checked, notes) VALUES (?, ?, ?)',
                  (str(cid)[:200], bool(checked), str(notes)))
    conn.commit()
    conn.close()
    return jsonify({'success': True})


# ─────────────────────────────────────────────────────────────────
# RECON RUNNER  (with SSE streaming)
# ─────────────────────────────────────────────────────────────────

# Per-job output queues: { job_id: queue.Queue }
_recon_queues = {}
_recon_lock = threading.Lock()

def _run_recon_task(tool, target, target_id, workspace_db, job_id):
    ping_flag = '-n' if platform.system().lower() == 'windows' else '-c'
    cmd_map = {
        'subfinder': ['subfinder', '-d', target, '-silent'],
        'httpx': ['httpx', '-u', target, '-silent'],
        'nmap': ['nmap', '-F', target],
        'ping': ['ping', ping_flag, '4', target]
    }

    cmd = cmd_map.get(tool)
    q = _recon_queues.get(job_id)
    if not cmd:
        if q:
            q.put({'type': 'error', 'line': f'Unknown tool: {tool}'})
            q.put({'type': 'done'})
        return

    stdout_lines = []
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        # Stream stdout line-by-line
        for line in proc.stdout:
            line = line.strip()
            if line:
                stdout_lines.append(line)
                if q:
                    q.put({'type': 'line', 'line': line})

        proc.wait()
        stderr = proc.stderr.read()

        # Save results to DB using absolute path
        conn = get_workspace_conn(workspace_db)
        c = conn.cursor()
        created = datetime.now().isoformat()

        if tool == 'ping':
            c.execute('INSERT INTO assets (targetId, value, type, status, created) VALUES (?, ?, ?, ?, ?)',
                      (target_id, f"Ping Results for {target}", "Note", "Alive", created))
            c.execute('INSERT INTO notes (title, category, target, content, created) VALUES (?, ?, ?, ?, ?)',
                      (f"{tool.upper()} scan: {target}", "Tool Output", target, '\n'.join(stdout_lines), created))
        else:
            for line in stdout_lines:
                val_type = "Domain" if tool == "subfinder" else "URL" if tool == "httpx" else "Host"
                c.execute('INSERT OR IGNORE INTO assets (targetId, value, type, status, created) VALUES (?, ?, ?, ?, ?)',
                          (target_id, line, val_type, "Alive", created))

        conn.commit()
        conn.close()

        if q:
            q.put({'type': 'done', 'line': f'[+] Completed. {len(stdout_lines)} results saved.'})

    except FileNotFoundError:
        error_msg = f"Error: '{tool}' not found in system PATH. Please install it."
        conn = get_workspace_conn(workspace_db)
        c = conn.cursor()
        c.execute('INSERT INTO notes (title, category, target, content, created) VALUES (?, ?, ?, ?, ?)',
                  (f"{tool.upper()} scan failed: {target}", "Tool Output", target, error_msg, datetime.now().isoformat()))
        conn.commit()
        conn.close()
        if q:
            q.put({'type': 'error', 'line': error_msg})
            q.put({'type': 'done'})
        return

    # Fire webhook if configured
    try:
        conn = get_workspace_conn(workspace_db)
        c = conn.cursor()
        c.execute("CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT)")
        c.execute("SELECT value FROM config WHERE key = 'webhook_url'")
        row = c.fetchone()
        conn.close()
        if row and row[0]:
            output_preview = '\n'.join(stdout_lines[:20])
            payload = {
                "content": f"🤖 **Recon Runner Finished**\n**Tool:** {tool.upper()}\n**Target:** {target}\n```\n{output_preview[:1500]}\n```"
            }
            req = urllib.request.Request(row[0], data=json.dumps(payload).encode('utf-8'),
                                         headers={'Content-Type': 'application/json'}, method='POST')
            urllib.request.urlopen(req, timeout=5)
    except Exception as e:
        print(f"Webhook trigger failed: {e}")
    finally:
        # Clean up queue after a delay
        def _cleanup():
            import time
            time.sleep(30)
            with _recon_lock:
                _recon_queues.pop(job_id, None)
        threading.Thread(target=_cleanup, daemon=True).start()


@app.route('/api/recon/run', methods=['POST'])
@api_login_required
def run_recon():
    data = request.get_json(silent=True) or {}
    tool = data.get('tool')
    target = data.get('target')
    target_id = data.get('targetId')

    if not tool or not target or not target_id:
        return jsonify({'error': 'Missing required parameters'}), 400
    
    if str(target).startswith('-'):
        return jsonify({'error': 'Target cannot start with a hyphen'}), 400

    workspace_db = session.get('active_workspace_db', 'ws_default.sqlite')
    job_id = uuid.uuid4().hex

    q = queue.Queue()
    with _recon_lock:
        _recon_queues[job_id] = q

    thread = threading.Thread(target=_run_recon_task, args=(tool, target, target_id, workspace_db, job_id))
    thread.daemon = True
    thread.start()

    return jsonify({'success': True, 'job_id': job_id,
                    'message': f'Started {tool} scan on {target}. Connect to /api/recon/stream/{job_id} for live output.'})


@app.route('/api/recon/stream/<job_id>')
@api_login_required
def recon_stream(job_id):
    """SSE endpoint — streams recon output line by line as the tool runs."""
    def generate():
        with _recon_lock:
            q = _recon_queues.get(job_id)
        if not q:
            yield "data: {\"type\":\"error\",\"line\":\"Job not found or already completed\"}\n\n"
            return
        while True:
            try:
                msg = q.get(timeout=60)
                yield f"data: {json.dumps(msg)}\n\n"
                if msg.get('type') == 'done' or msg.get('type') == 'error':
                    break
            except queue.Empty:
                yield "data: {\"type\":\"heartbeat\"}\n\n"

    return Response(generate(), mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})


# ─────────────────────────────────────────────────────────────────
# OOB CATCHER
# ─────────────────────────────────────────────────────────────────
@app.route('/api/oob/generate', methods=['POST'])
@api_login_required
def generate_oob_payload():
    data = request.json or {}
    uid = uuid.uuid4().hex[:12]
    label = truncate(data.get('label', ''), 200)
    target_id = data.get('targetId')
    
    conn = get_db()
    c = conn.cursor()
    c.execute('INSERT INTO oob_payloads (uid, label, targetId, created) VALUES (?, ?, ?, ?)',
              (uid, label, target_id, str(int(datetime.now().timestamp() * 1000))))
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'uid': uid, 'url': f"{request.host_url.rstrip('/')}/oob/{uid}"})


@app.route('/oob/<uid>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'])
def catch_oob(uid):
    # Find the workspace containing this uid
    conn_master = get_master_conn()
    cm = conn_master.cursor()
    cm.execute('SELECT db_name FROM workspaces')
    dbs = [r[0] for r in cm.fetchall()]
    conn_master.close()
    
    target_db = None
    target_id = None
    for db in dbs:
        try:
            conn = get_workspace_conn(db)
            c = conn.cursor()
            c.execute('CREATE TABLE IF NOT EXISTS oob_payloads (id INTEGER PRIMARY KEY AUTOINCREMENT, uid TEXT UNIQUE NOT NULL, label TEXT, targetId INTEGER, created TEXT)')
            c.execute('SELECT targetId FROM oob_payloads WHERE uid = ?', (uid,))
            row = c.fetchone()
            if row:
                target_db = db
                target_id = row[0]
                conn.close()
                break
            conn.close()
        except Exception:
            pass

    if not target_db:
        # Silently drop if UID is unknown
        return Response('Not Found', status=404)

    # Insert hit into the specific workspace
    source_ip = request.remote_addr
    method = request.method
    headers = '\\n'.join([f"{k}: {v}" for k, v in request.headers.items()])
    body = request.get_data(as_text=True)
    created = str(int(datetime.now().timestamp() * 1000))

    conn = get_workspace_conn(target_db)
    c = conn.cursor()
    c.execute('CREATE TABLE IF NOT EXISTS oob_hits (id INTEGER PRIMARY KEY AUTOINCREMENT, uid TEXT NOT NULL, source_ip TEXT, method TEXT, headers TEXT, body TEXT, created TEXT)')
    c.execute('INSERT INTO oob_hits (uid, source_ip, method, headers, body, created) VALUES (?, ?, ?, ?, ?, ?)',
              (uid, truncate(source_ip, 100), method, truncate(headers, 5000), truncate(body, 50000), created))
    
    # Auto-generate a Critical finding!
    f_title = f"Blind OOB Hit Received ({method})"
    f_desc = f"Out-of-band interaction caught.\\n\\n**Source IP:** {source_ip}\\n**Method:** {method}\\n\\n**Headers:**\\n```\\n{truncate(headers, 1000)}\\n```\\n\\n**Body:**\\n```\\n{truncate(body, 2000)}\\n```"
    c.execute('''
        INSERT INTO findings (title, severity, type, host, status, endpoint, cvss, desc, payload, bountyEarned, targetId, created, tags, screenshots, remediation)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        truncate(f_title, 500), 'critical', 'Blind OOB',
        truncate(source_ip, 2000), 'Found', f"/oob/{uid}", '',
        truncate(f_desc), '', '', target_id, created, 'OOB, Blind', '', ''
    ))
    
    # Fire webhook if configured
    try:
        c.execute("CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT)")
        c.execute("SELECT value FROM config WHERE key = 'webhook_url'")
        webhook_row = c.fetchone()
        if webhook_row and webhook_row[0]:
            payload = {
                "embeds": [{
                    "title": f"🚨 OOB CATCHER HIT: {uid}",
                    "description": f"**IP:** {source_ip}\\n**Method:** {method}",
                    "color": 15158332
                }]
            }
            req = urllib.request.Request(webhook_row[0], data=json.dumps(payload).encode('utf-8'),
                                         headers={'Content-Type': 'application/json'}, method='POST')
            urllib.request.urlopen(req, timeout=5)
    except Exception:
        pass

    conn.commit()
    conn.close()

    # Respond properly to common blind tests to provoke more data
    if request.method == 'OPTIONS':
        return Response('', status=200, headers={'Allow': 'OPTIONS, GET, HEAD, POST'})
    return Response('OK', status=200)


@app.route('/api/oob/<uid>', methods=['DELETE'])
@api_login_required
def delete_oob_payload(uid):
    conn = get_db()
    c = conn.cursor()
    c.execute('DELETE FROM oob_payloads WHERE uid = ?', (uid,))
    c.execute('DELETE FROM oob_hits WHERE uid = ?', (uid,))
    conn.commit()
    conn.close()
    return jsonify({'success': True})


# ─────────────────────────────────────────────────────────────────
# AI REPORT WRITER
# ─────────────────────────────────────────────────────────────────

@app.route('/api/user/regenerate-key', methods=['POST'])
@login_required
def regenerate_api_key():
    """Generate a new API key for the current user."""
    new_key = secrets.token_hex(16)
    conn = get_master_conn()
    c = conn.cursor()
    c.execute('UPDATE users SET api_key = ? WHERE id = ?', (new_key, current_user.id))
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'api_key': new_key})


# ─────────────────────────────────────────────────────────────────
# BURP SUITE XML IMPORT
# ─────────────────────────────────────────────────────────────────
@app.route('/api/import/burp', methods=['POST'])
@api_login_required
def import_burp():
    """Parse a Burp Suite XML export and import findings into the workspace."""
    import xml.etree.ElementTree as ET
    import time

    xml_data = request.get_data(as_text=True)
    if not xml_data:
        return jsonify({'error': 'No XML data provided'}), 400

    try:
        root = ET.fromstring(xml_data)
    except ET.ParseError as e:
        return jsonify({'error': f'Invalid XML: {e}'}), 400

    conn = get_db()
    c = conn.cursor()
    added = 0

    # Burp XML structure: <issues> or root <issue>
    issues = root.findall('.//issue') or (root.findall('issue') if root.tag != 'issues' else [root])
    if root.tag == 'issues':
        issues = list(root)

    for issue in issues:
        def _text(tag):
            el = issue.find(tag)
            return el.text.strip() if el is not None and el.text else ''

        title = _text('name') or _text('type') or 'Burp Finding'
        host = _text('host') or _text('url') or ''
        severity_raw = _text('severity').lower()
        severity_map = {'high': 'high', 'medium': 'medium', 'low': 'low',
                        'information': 'info', 'informational': 'info', 'critical': 'critical'}
        severity = severity_map.get(severity_raw, 'info')
        desc = _text('issueDetail') or _text('issueBackground') or ''
        remediation = _text('remediationDetail') or _text('remediationBackground') or ''
        endpoint = _text('path') or ''

        c.execute('''
            INSERT INTO findings (title, severity, type, host, status, endpoint, desc, remediation, created)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            truncate(title, 500), severity, 'Burp Import',
            truncate(host, 2000), 'Found',
            truncate(endpoint, 2000), truncate(desc), truncate(remediation),
            str(int(time.time() * 1000))
        ))
        added += 1

    conn.commit()
    conn.close()
    return jsonify({'success': True, 'imported': added})


# ─────────────────────────────────────────────────────────────────
# TOOLS REFERENCE ROUTES
# ─────────────────────────────────────────────────────────────────
@app.route('/tools/subfinder_cs')
@login_required
def subfinder_cs():
    """Serve the Subfinder Cheat Sheet wrapped in 0xHunter theme."""
    return render_template('subfinder_cs.html')


# ─────────────────────────────────────────────────────────────────
# PASSIVE OSINT API ENDPOINTS
# ─────────────────────────────────────────────────────────────────

@app.route('/api/osint/dns', methods=['POST'])
@api_login_required
def osint_dns():
    import urllib.parse
    import ssl
    data = request.get_json(silent=True) or {}
    domain = data.get('domain', '').strip()
    if not domain:
        return jsonify({'error': 'Domain parameter is required'}), 400
    
    domain = re.sub(r'^https?://', '', domain).split('/')[0].split(':')[0]
    if not domain:
        return jsonify({'error': 'Invalid domain'}), 400
        
    record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA']
    results = {}
    
    # Create unverified SSL context to bypass system CA store issues
    ctx = ssl._create_unverified_context()
    
    for rtype in record_types:
        try:
            url = f"https://cloudflare-dns.com/dns-query?name={urllib.parse.quote(domain)}&type={rtype}"
            req = urllib.request.Request(url, headers={'Accept': 'application/dns-json'})
            with urllib.request.urlopen(req, timeout=4, context=ctx) as response:
                dns_data = json.loads(response.read().decode('utf-8'))
                results[rtype] = dns_data.get('Answer', [])
        except Exception as e:
            results[rtype] = [{'error': str(e)}]
            
    return jsonify({'success': True, 'domain': domain, 'records': results})


@app.route('/api/osint/whois', methods=['POST'])
@api_login_required
def osint_whois():
    import urllib.parse
    import ssl
    data = request.get_json(silent=True) or {}
    domain = data.get('domain', '').strip()
    if not domain:
        return jsonify({'error': 'Domain parameter is required'}), 400
    
    domain = re.sub(r'^https?://', '', domain).split('/')[0].split(':')[0]
    if not domain:
        return jsonify({'error': 'Invalid domain'}), 400
        
    url = f"https://rdap.org/domain/{urllib.parse.quote(domain)}"
    req = urllib.request.Request(url, headers={
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'application/json'
    })
    
    ctx = ssl._create_unverified_context()
    try:
        with urllib.request.urlopen(req, timeout=6, context=ctx) as response:
            rdap_data = json.loads(response.read().decode('utf-8'))
            
            # Registrar
            registrar = "Unknown"
            entities = rdap_data.get('entities', [])
            for ent in entities:
                roles = ent.get('roles', [])
                if 'registrar' in roles:
                    vcard = ent.get('vcardArray', [])
                    if len(vcard) > 1:
                        for item in vcard[1]:
                            if item[0] == 'fn':
                                registrar = item[3]
                                break
            
            # Events (created, updated, expired)
            events = {}
            for ev in rdap_data.get('events', []):
                action = ev.get('eventAction', '')
                date = ev.get('eventDate', '')
                if action and date:
                    events[action] = date
            
            # Name Servers
            nameservers = []
            for ns in rdap_data.get('nameservers', []):
                nameservers.append(ns.get('ldhName', ''))
            nameservers = [n for n in nameservers if n]
            
            # Status
            status = rdap_data.get('status', [])
            
            return jsonify({
                'success': True,
                'domain': domain,
                'registrar': registrar,
                'events': events,
                'nameservers': nameservers,
                'status': status,
                'raw': rdap_data
            })
    except urllib.error.HTTPError as he:
        if he.code == 404:
            return jsonify({'error': 'Domain not found in RDAP database'}), 404
        return jsonify({'error': f'RDAP server returned HTTP {he.code}'}), 500
    except Exception as e:
        return jsonify({'error': f'Failed to query RDAP: {str(e)}'}), 500


@app.route('/api/osint/portscan', methods=['POST'])
@api_login_required
def osint_portscan():
    import socket
    import concurrent.futures
    
    data = request.get_json(silent=True) or {}
    target_ip = data.get('ip', '').strip()
    if not target_ip:
        return jsonify({'error': 'IP address/host is required'}), 400
        
    target_ip = re.sub(r'^https?://', '', target_ip).split('/')[0].split(':')[0]
    if not target_ip:
        return jsonify({'error': 'Invalid target IP'}), 400
        
    ports = {
        21: 'FTP',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        80: 'HTTP',
        110: 'POP3',
        143: 'IMAP',
        443: 'HTTPS',
        445: 'SMB',
        3389: 'RDP',
        8080: 'HTTP-Alt'
    }
    
    def check_port(port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.2)
        try:
            result = s.connect_ex((target_ip, port))
            return port, result == 0
        except Exception:
            return port, False
        finally:
            s.close()
            
    scan_results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(ports)) as executor:
        futures = {executor.submit(check_port, p): p for p in ports}
        for future in concurrent.futures.as_completed(futures):
            port, is_open = future.result()
            scan_results.append({
                'port': port,
                'service': ports[port],
                'status': 'open' if is_open else 'closed'
            })
            
    scan_results.sort(key=lambda x: x['port'])
    
    return jsonify({
        'success': True,
        'ip': target_ip,
        'ports': scan_results
    })


@app.route('/api/osint/username-check', methods=['POST'])
@api_login_required
def osint_username_check():
    data = request.get_json(silent=True) or {}
    username = data.get('username', '').strip()
    platform_name = data.get('platform', '').strip()
    
    if not username or not platform_name:
        return jsonify({'error': 'Username and platform parameters are required'}), 400
        
    platforms = {
        'GitHub': {
            'url': f'https://github.com/{username}',
            'method': 'status'
        },
        'Twitter/X': {
            'url': f'https://twitter.com/{username}',
            'method': 'status'
        },
        'Reddit': {
            'url': f'https://www.reddit.com/user/{username}',
            'method': 'status'
        },
        'Instagram': {
            'url': f'https://instagram.com/{username}',
            'method': 'status'
        },
        'Medium': {
            'url': f'https://medium.com/@{username}',
            'method': 'status'
        },
        'Pinterest': {
            'url': f'https://pinterest.com/{username}',
            'method': 'status'
        },
        'Dev.to': {
            'url': f'https://dev.to/{username}',
            'method': 'status'
        },
        'GitLab': {
            'url': f'https://gitlab.com/{username}',
            'method': 'status'
        },
        'Behance': {
            'url': f'https://behance.net/{username}',
            'method': 'status'
        },
        'Dribbble': {
            'url': f'https://dribbble.com/{username}',
            'method': 'status'
        },
        'Keybase': {
            'url': f'https://keybase.io/{username}',
            'method': 'status'
        },
        'Steam': {
            'url': f'https://steamcommunity.com/id/{username}',
            'method': 'content_not_present',
            'neg_string': 'The specified profile could not be found'
        },
        'Spotify': {
            'url': f'https://open.spotify.com/user/{username}',
            'method': 'status'
        },
        'Patreon': {
            'url': f'https://patreon.com/{username}',
            'method': 'status'
        },
        'DockerHub': {
            'url': f'https://hub.docker.com/u/{username}',
            'method': 'status'
        },
        'Linktree': {
            'url': f'https://linktr.ee/{username}',
            'method': 'status'
        },
        'TryHackMe': {
            'url': f'https://tryhackme.com/p/{username}',
            'method': 'status'
        },
        'HackerOne': {
            'url': f'https://hackerone.com/{username}',
            'method': 'status'
        },
        'Bugcrowd': {
            'url': f'https://bugcrowd.com/{username}',
            'method': 'status'
        },
        'CodePen': {
            'url': f'https://codepen.io/{username}',
            'method': 'status'
        },
        'Threads': {
            'url': f'https://www.threads.net/@{username}',
            'method': 'status'
        },
        'Snapchat': {
            'url': f'https://www.snapchat.com/add/{username}',
            'method': 'status'
        },
        'Mastodon': {
            'url': f'https://mastodon.social/@{username}',
            'method': 'status'
        },
        'Quora': {
            'url': f'https://www.quora.com/profile/{username}',
            'method': 'status'
        },
        'Clubhouse': {
            'url': f'https://www.clubhouse.com/@{username}',
            'method': 'status'
        },
        'About.me': {
            'url': f'https://about.me/{username}',
            'method': 'status'
        },
        'Vero': {
            'url': f'https://vero.co/{username}',
            'method': 'status'
        },
        'DeviantArt': {
            'url': f'https://www.deviantart.com/{username}',
            'method': 'status'
        },
        'Wattpad': {
            'url': f'https://www.wattpad.com/user/{username}',
            'method': 'status'
        },
        'Goodreads': {
            'url': f'https://www.goodreads.com/{username}',
            'method': 'status'
        },
        'Foursquare': {
            'url': f'https://foursquare.com/user/{username}',
            'method': 'status'
        }
    }
    
    spec = platforms.get(platform_name)
    if not spec:
        return jsonify({'status': 'manual', 'message': 'Verification required (CORS/No proxy sig)'})
        
    url = spec['url']
    req = urllib.request.Request(url, headers={
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept-Language': 'en-US,en;q=0.9'
    })
    
    import ssl
    ctx = ssl._create_unverified_context()
    try:
        with urllib.request.urlopen(req, timeout=4.0, context=ctx) as response:
            status_code = response.getcode()
            if spec['method'] == 'status':
                if status_code == 200:
                    return jsonify({'status': 'found', 'url': url})
                else:
                    return jsonify({'status': 'notfound'})
            elif spec['method'] == 'content_not_present':
                html_content = response.read().decode('utf-8', errors='ignore')
                if spec['neg_string'] in html_content:
                    return jsonify({'status': 'notfound'})
                else:
                    return jsonify({'status': 'found', 'url': url})
    except urllib.error.HTTPError as he:
        if he.code == 404:
            return jsonify({'status': 'notfound'})
        elif he.code in [403, 429]:
            return jsonify({'status': 'manual', 'message': f'Protected (HTTP {he.code})'})
        else:
            return jsonify({'status': 'manual', 'message': f'HTTP {he.code}'})
    except Exception as e:
        return jsonify({'status': 'notfound', 'message': str(e)})



# ─────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    init_all()
    port = int(os.environ.get('PORT', 5000))
    
    cert_file = '192.168.0.106+3.pem'
    key_file = '192.168.0.106+3-key.pem'
    
    if os.path.exists(cert_file) and os.path.exists(key_file):
        app.run(debug=app.config['DEBUG'], host='0.0.0.0', port=port, ssl_context=(cert_file, key_file))
    else:
        app.run(debug=app.config['DEBUG'], host='0.0.0.0', port=port)
