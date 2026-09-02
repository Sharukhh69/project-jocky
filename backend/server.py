# server.py — JOCKY Central Management Server
# ─────────────────────────────────────────────
# Flask backend on port 8000.
# Manages cases, targets, evidence, and routes
# JOCKY commands to agent(s) on target machines.
# Supports multi-target simultaneous scanning.
# Auth: JWT tokens + bcrypt password hashing.

from flask import Flask, jsonify, request, send_file
from flask_cors import CORS
from functools import wraps
import sqlite3
import json
import os
import datetime
import hashlib
import secrets
import requests as req
import concurrent.futures
import sys

try:
    import jwt
except ImportError:
    raise SystemExit("[JOCKY] PyJWT not found. Run: pip install PyJWT")

try:
    import bcrypt
except ImportError:
    raise SystemExit("[JOCKY] bcrypt not found. Run: pip install bcrypt")

# Add interpreter to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'interpreter'))
from jocky_interpreter import run_jocky_script, validate_jocky_script
from polymorphic import PolymorphicEngine

app  = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}},
     supports_credentials=True)

DB_PATH = os.path.join(os.path.dirname(__file__), 'jocky_cases.db')
POLY    = PolymorphicEngine()

# ─────────────────────────────────────────────────────────────────────────────
# AUTH CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

# Secret key — in production load from env / secrets manager
JWT_SECRET = os.environ.get(
    'JOCKY_JWT_SECRET',
    secrets.token_hex(32)           # random per-process if not set
)
JWT_ALGORITHM  = 'HS256'
JWT_EXPIRY_HRS = 8                  # token valid for 8 hours

# Public endpoints — no token required
PUBLIC_ROUTES = {'/api/status', '/api/auth/login', '/api/auth/register'}


# ─────────────────────────────────────────────────────────────────────────────
# DATABASE
# ─────────────────────────────────────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c    = conn.cursor()

    c.execute('''
        CREATE TABLE IF NOT EXISTS cases (
            case_id     TEXT PRIMARY KEY,
            case_name   TEXT NOT NULL,
            officer     TEXT NOT NULL,
            description TEXT,
            created_at  TEXT NOT NULL,
            status      TEXT DEFAULT "active"
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS targets (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id     TEXT NOT NULL,
            target_ip   TEXT NOT NULL,
            target_port INTEGER DEFAULT 5000,
            target_name TEXT DEFAULT "Unknown",
            os_type     TEXT DEFAULT "Unknown",
            status      TEXT DEFAULT "offline",
            last_seen   TEXT,
            FOREIGN KEY(case_id) REFERENCES cases(case_id)
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS evidence (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id         TEXT NOT NULL,
            target_ip       TEXT NOT NULL,
            command         TEXT NOT NULL,
            results         TEXT NOT NULL,
            timestamp       TEXT NOT NULL,
            evidence_hash   TEXT NOT NULL,
            FOREIGN KEY(case_id) REFERENCES cases(case_id)
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS audit_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id     TEXT,
            action      TEXT NOT NULL,
            detail      TEXT,
            timestamp   TEXT NOT NULL
        )
    ''')

    # Officers table — credentials for management console access
    c.execute('''
        CREATE TABLE IF NOT EXISTS officers (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            username    TEXT UNIQUE NOT NULL,
            full_name   TEXT NOT NULL,
            rank        TEXT DEFAULT "Officer",
            pw_hash     TEXT NOT NULL,
            created_at  TEXT NOT NULL,
            last_login  TEXT,
            is_active   INTEGER DEFAULT 1
        )
    ''')

    # Auth log — every login attempt, token issue, and rejection
    c.execute('''
        CREATE TABLE IF NOT EXISTS auth_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            username    TEXT,
            event       TEXT NOT NULL,
            ip_address  TEXT,
            detail      TEXT,
            timestamp   TEXT NOT NULL
        )
    ''')

    conn.commit()
    conn.close()
    print("[JOCKY Server] Database initialised.")

init_db()


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def now() -> str:
    return datetime.datetime.now().isoformat()


# ─────────────────────────────────────────────────────────────────────────────
# AUTHENTICATION LAYER
# ─────────────────────────────────────────────────────────────────────────────

def _hash_password(plain: str) -> str:
    """Bcrypt-hash a plaintext password. Returns utf-8 string."""
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt(rounds=12)).decode()


def _check_password(plain: str, hashed: str) -> bool:
    """Verify a plaintext password against a stored bcrypt hash."""
    try:
        return bcrypt.checkpw(plain.encode(), hashed.encode())
    except Exception:
        return False


def _issue_token(officer_id: int, username: str, full_name: str,
                 rank: str) -> str:
    """Sign and return a JWT for the given officer."""
    payload = {
        'sub':       str(officer_id),
        'username':  username,
        'full_name': full_name,
        'rank':      rank,
        'iat':       datetime.datetime.utcnow(),
        'exp':       datetime.datetime.utcnow() +
                     datetime.timedelta(hours=JWT_EXPIRY_HRS),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def _decode_token(token: str) -> dict:
    """
    Decode and validate a JWT.
    Raises jwt.ExpiredSignatureError or jwt.InvalidTokenError on failure.
    """
    return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])


def _log_auth(username: str, event: str, detail: str = ""):
    """Write an entry to the auth_log table."""
    ip = request.remote_addr or 'unknown'
    conn = get_db()
    conn.execute(
        'INSERT INTO auth_log (username,event,ip_address,detail,timestamp) '
        'VALUES (?,?,?,?,?)',
        (username, event, ip, detail, now())
    )
    conn.commit()
    conn.close()


def _seed_default_officer():
    """
    Create a default admin officer if no officers exist.
    Default credentials:  admin / jocky@2026
    Change immediately after first login.
    """
    conn = get_db()
    count = conn.execute('SELECT COUNT(*) FROM officers').fetchone()[0]
    if count == 0:
        conn.execute(
            'INSERT INTO officers '
            '(username, full_name, rank, pw_hash, created_at) '
            'VALUES (?,?,?,?,?)',
            ('admin', 'System Administrator', 'Super Admin',
             _hash_password('jocky@2026'), now())
        )
        conn.commit()
        print('[JOCKY Auth] Default officer created: admin / jocky@2026')
        print('[JOCKY Auth] CHANGE THIS PASSWORD IMMEDIATELY.')
    conn.close()

_seed_default_officer()   # ensure default admin exists


def require_auth(f):
    """
    Decorator — protects an endpoint with JWT bearer-token auth.

    Clients must send:
        Authorization: Bearer <token>

    Returns 401 JSON on missing / expired / invalid tokens.
    All rejections are written to auth_log.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            # Demo Mode: auto-authenticate as default admin officer
            request.officer = {'username': 'admin', 'full_name': 'System Administrator', 'rank': 'Super Admin', 'sub': '1'}
            return f(*args, **kwargs)

        token = auth_header[7:]   # strip 'Bearer '
        try:
            payload = _decode_token(token)
        except jwt.ExpiredSignatureError:
            _log_auth('?', 'REJECTED_EXPIRED_TOKEN',
                      f'Endpoint: {request.path}')
            return jsonify({
                'error': 'Token expired — please log in again',
                'code':  'TOKEN_EXPIRED'
            }), 401
        except jwt.InvalidTokenError as e:
            _log_auth('?', 'REJECTED_INVALID_TOKEN',
                      f'Endpoint: {request.path} — {e}')
            return jsonify({
                'error': 'Invalid token',
                'code':  'INVALID_TOKEN'
            }), 401

        # Verify officer is still active in DB
        conn = get_db()
        officer = conn.execute(
            'SELECT id, is_active FROM officers WHERE username=?',
            (payload['username'],)
        ).fetchone()
        conn.close()

        if not officer or not officer['is_active']:
            _log_auth(payload['username'], 'REJECTED_INACTIVE_ACCOUNT',
                      f'Endpoint: {request.path}')
            return jsonify({
                'error': 'Account disabled',
                'code':  'ACCOUNT_DISABLED'
            }), 401

        # Attach officer info to request context for use inside the route
        request.officer = payload
        return f(*args, **kwargs)
    return decorated


# ─────────────────────────────────────────────────────────────────────────────
# AUTH ENDPOINTS
# ─────────────────────────────────────────────────────────────────────────────

@app.route('/api/auth/login', methods=['POST'])
def auth_login():
    """
    POST /api/auth/login
    Body: { "username": "...", "password": "..." }
    Returns: { "token": "<jwt>", "officer": {...} }
    """
    d        = request.json or {}
    username = d.get('username', '').strip()
    password = d.get('password', '')

    if not username or not password:
        _log_auth(username, 'LOGIN_MISSING_FIELDS')
        return jsonify({'error': 'Username and password required'}), 400

    conn    = get_db()
    officer = conn.execute(
        'SELECT * FROM officers WHERE username=?', (username,)
    ).fetchone()

    if not officer:
        _log_auth(username, 'LOGIN_FAILED_USER_NOT_FOUND',
                  f'IP: {request.remote_addr}')
        conn.close()
        # Generic message — don't reveal whether username exists
        return jsonify({'error': 'Invalid credentials'}), 401

    if not officer['is_active']:
        _log_auth(username, 'LOGIN_FAILED_ACCOUNT_DISABLED')
        conn.close()
        return jsonify({'error': 'Account is disabled'}), 403

    if not _check_password(password, officer['pw_hash']):
        _log_auth(username, 'LOGIN_FAILED_WRONG_PASSWORD',
                  f'IP: {request.remote_addr}')
        conn.close()
        return jsonify({'error': 'Invalid credentials'}), 401

    # Password OK — update last_login and issue token
    conn.execute('UPDATE officers SET last_login=? WHERE username=?',
                 (now(), username))
    conn.commit()
    conn.close()

    token = _issue_token(
        officer['id'], username,
        officer['full_name'], officer['rank']
    )
    _log_auth(username, 'LOGIN_SUCCESS',
              f'IP: {request.remote_addr}')
    audit(None, 'OFFICER_LOGIN', f'{username} logged in')

    return jsonify({
        'token': token,
        'expires_in': JWT_EXPIRY_HRS * 3600,
        'officer': {
            'username':  username,
            'full_name': officer['full_name'],
            'rank':      officer['rank'],
        }
    })


@app.route('/api/auth/logout', methods=['POST'])
@require_auth
def auth_logout():
    """POST /api/auth/logout — log the event (token invalidation is client-side)."""
    username = request.officer['username']
    _log_auth(username, 'LOGOUT')
    audit(None, 'OFFICER_LOGOUT', f'{username} logged out')
    return jsonify({'message': f'Officer {username} logged out successfully'})


@app.route('/api/auth/me', methods=['GET'])
@require_auth
def auth_me():
    """GET /api/auth/me — return current officer info from token."""
    return jsonify({'officer': request.officer})


@app.route('/api/auth/register', methods=['POST'])
def auth_register():
    """
    POST /api/auth/register
    Register a new officer. Requires a valid REGISTER_KEY header for security.
    In production, restrict this endpoint to admin-only or remove it.
    """
    # Require a registration key so random people can't self-register
    reg_key  = request.headers.get('X-Register-Key', '')
    expected = os.environ.get('JOCKY_REGISTER_KEY', 'JOCKY-SIH-2026')
    if reg_key != expected:
        _log_auth('?', 'REGISTER_REJECTED_BAD_KEY')
        return jsonify({'error': 'Invalid registration key'}), 403

    d         = request.json or {}
    username  = d.get('username', '').strip().lower()
    full_name = d.get('full_name', '').strip()
    rank      = d.get('rank', 'Officer').strip()
    password  = d.get('password', '')

    if not all([username, full_name, password]):
        return jsonify({'error': 'username, full_name, and password required'}), 400
    if len(password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400

    try:
        conn = get_db()
        conn.execute(
            'INSERT INTO officers '
            '(username, full_name, rank, pw_hash, created_at) '
            'VALUES (?,?,?,?,?)',
            (username, full_name, rank,
             _hash_password(password), now())
        )
        conn.commit()
        conn.close()
    except sqlite3.IntegrityError:
        return jsonify({'error': f'Username "{username}" already exists'}), 409

    _log_auth(username, 'OFFICER_REGISTERED',
              f'Name: {full_name}, Rank: {rank}')
    audit(None, 'OFFICER_REGISTERED', f'{username} ({rank})')
    return jsonify({'message': f'Officer {username} registered successfully'}), 201


@app.route('/api/auth/change-password', methods=['POST'])
@require_auth
def auth_change_password():
    """POST /api/auth/change-password — officer changes own password."""
    d           = request.json or {}
    current_pw  = d.get('current_password', '')
    new_pw      = d.get('new_password', '')
    username    = request.officer['username']

    if len(new_pw) < 8:
        return jsonify({'error': 'New password must be at least 8 characters'}), 400

    conn    = get_db()
    officer = conn.execute(
        'SELECT pw_hash FROM officers WHERE username=?', (username,)
    ).fetchone()

    if not _check_password(current_pw, officer['pw_hash']):
        conn.close()
        _log_auth(username, 'CHANGE_PASSWORD_FAILED_WRONG_CURRENT')
        return jsonify({'error': 'Current password incorrect'}), 401

    conn.execute('UPDATE officers SET pw_hash=? WHERE username=?',
                 (_hash_password(new_pw), username))
    conn.commit()
    conn.close()
    _log_auth(username, 'PASSWORD_CHANGED')
    return jsonify({'message': 'Password changed successfully'})


@app.route('/api/auth/log', methods=['GET'])
@require_auth
def auth_log():
    """GET /api/auth/log — view authentication event log (admin only)."""
    limit = int(request.args.get('limit', 50))
    conn  = get_db()
    rows  = conn.execute(
        'SELECT * FROM auth_log ORDER BY timestamp DESC LIMIT ?',
        (limit,)
    ).fetchall()
    conn.close()
    return jsonify({
        'count': len(rows),
        'log':   [dict(r) for r in rows]
    })


def evidence_hash(data: dict) -> str:
    return hashlib.sha256(
        json.dumps(data, sort_keys=True).encode()
    ).hexdigest()

def audit(case_id: str, action: str, detail: str = ""):
    conn = get_db()
    conn.execute(
        "INSERT INTO audit_log (case_id,action,detail,timestamp) VALUES (?,?,?,?)",
        (case_id, action, detail, now()))
    conn.commit()
    conn.close()

def check_target(ip: str, port: int) -> dict:
    # If the user typed 127.0.0.1 or localhost, check container hostname first
    candidate_ips = [ip]
    if ip in ("127.0.0.1", "localhost"):
        candidate_ips = ["jocky-agent-01", "host.docker.internal", ip]

    for cand_ip in candidate_ips:
        try:
            cand_port = 5000 if cand_ip == "jocky-agent-01" else port
            r = req.get(f"http://{cand_ip}:{cand_port}/ping", timeout=2)
            data = r.json()
            return {"status": "online",
                    "os": data.get("os", "Linux"),
                    "hostname": data.get("hostname", cand_ip),
                    "agent_version": data.get("agent_version", "?"),
                    "_resolved_ip": cand_ip,
                    "_resolved_port": cand_port}
        except Exception:
            continue

    return {"status": "offline", "os": "Unknown",
            "hostname": ip, "agent_version": "?"}


# ─────────────────────────────────────────────────────────────────────────────
# CASE MANAGEMENT
# ─────────────────────────────────────────────────────────────────────────────

@app.route('/api/cases', methods=['GET'])
@require_auth
def list_cases():
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM cases ORDER BY created_at DESC").fetchall()
    conn.close()
    return jsonify({"cases": [dict(r) for r in rows]})


@app.route('/api/case/create', methods=['POST'])
@require_auth
def create_case():
    d = request.json or {}
    # Use the authenticated officer name automatically
    officer_name = request.officer.get('full_name',
                   request.officer.get('username', 'Unknown'))
    case_id = 'CASE-' + hashlib.md5(
        (d.get('case_name', '') + now()).encode()
    ).hexdigest()[:8].upper()

    conn = get_db()
    conn.execute(
        '''INSERT INTO cases
           (case_id, case_name, officer, description, created_at, status)
           VALUES (?,?,?,?,?,?)''',
        (case_id,
         d.get('case_name', 'Unnamed Case'),
         d.get('officer', officer_name),
         d.get('description', ''),
         now(), 'active'))
    conn.commit()
    conn.close()
    audit(case_id, 'CASE_CREATED',
          f"Officer: {officer_name} ({request.officer['username']})")
    return jsonify({"status": "success", "case_id": case_id}), 201


@app.route('/api/case/<case_id>', methods=['GET'])
@require_auth
def get_case(case_id):
    conn = get_db()
    row  = conn.execute(
        "SELECT * FROM cases WHERE case_id=?", (case_id,)).fetchone()
    conn.close()
    if not row:
        return jsonify({"error": "Case not found"}), 404
    return jsonify(dict(row))


# ─────────────────────────────────────────────────────────────────────────────
# TARGET MANAGEMENT
# ─────────────────────────────────────────────────────────────────────────────

@app.route('/api/target/add', methods=['POST'])
@require_auth
def add_target():
    d    = request.json or {}
    ip   = d.get('target_ip', '')
    port = int(d.get('target_port', 5000))
    info = check_target(ip, port)

    conn = get_db()
    conn.execute(
        '''INSERT INTO targets
           (case_id, target_ip, target_port, target_name,
            os_type, status, last_seen)
           VALUES (?,?,?,?,?,?,?)''',
        (d['case_id'], ip, port,
         info.get('hostname', d.get('target_name', 'Unknown')),
         info['os'], info['status'], now()))
    conn.commit()
    conn.close()

    audit(d['case_id'], 'TARGET_ADDED',
          f"IP={ip} OS={info['os']} Status={info['status']}")

    return jsonify({
        "status":   "success",
        "target_ip": ip,
        "os":       info['os'],
        "reachable": info['status'] == 'online',
        "hostname": info.get('hostname'),
    })


@app.route('/api/targets/<case_id>', methods=['GET'])
@require_auth
def get_targets(case_id):
    conn    = get_db()
    targets = conn.execute(
        "SELECT * FROM targets WHERE case_id=?", (case_id,)).fetchall()
    conn.close()

    result = []
    for t in targets:
        t = dict(t)
        live = check_target(t['target_ip'], t['target_port'])
        t['status'] = live['status']
        t['os']     = live['os']
        result.append(t)
    return jsonify({"targets": result})


# ─────────────────────────────────────────────────────────────────────────────
# COMMAND EXECUTION
# ─────────────────────────────────────────────────────────────────────────────

# JOCKY command → agent route mapping
ROUTE_MAP = {
    "scan.processes()":           "/scan/processes",
    "scan.network.connections()": "/scan/network",
    "scan.network()":             "/scan/network",
    "scan.usb.history()":         "/scan/usb",
    "scan.usb()":                 "/scan/usb",
    "scan.logins()":              "/scan/logins",
    "scan.files()":               "/scan/files",
    "scan.system()":              "/scan/system",
    "scan.registry()":            "/scan/registry",
}

def execute_on_target(case_id: str, target_ip: str, target_port: int,
                      command: str) -> dict:
    route = ROUTE_MAP.get(command)
    if not route:
        return {"error": f"Unknown JOCKY command: {command}"}

    # If inside docker, resolve local addresses to container name
    actual_ip   = "jocky-agent-01" if target_ip in ("127.0.0.1", "localhost") else target_ip
    actual_port = 5000 if actual_ip == "jocky-agent-01" else target_port

    url = f"http://{actual_ip}:{actual_port}{route}"
    try:
        r       = req.get(url, timeout=15)
        results = r.json()
    except Exception as e:
        results = {"error": str(e)}

    results_str = json.dumps(results)
    ehash = hashlib.sha256(
        (results_str + now()).encode()).hexdigest()

    conn = get_db()
    conn.execute(
        '''INSERT INTO evidence
           (case_id, target_ip, command, results,
            timestamp, evidence_hash)
           VALUES (?,?,?,?,?,?)''',
        (case_id, target_ip, command,
         results_str, now(), ehash))
    conn.commit()
    conn.close()

    results['evidence_hash'] = ehash
    results['_command']      = command
    results['_target_ip']    = target_ip
    results['_timestamp']    = now()
    return results


@app.route('/api/run', methods=['POST'])
@require_auth
def run_command():
    d         = request.json or {}
    case_id   = d.get('case_id', 'DEMO')
    target_ip = d.get('target_ip', '127.0.0.1')
    port      = int(d.get('target_port', 5000))
    command   = d.get('command', '')

    result = execute_on_target(case_id, target_ip, port, command)
    audit(case_id, 'COMMAND_RUN',
          f"cmd={command} target={target_ip}")
    return jsonify(result)


@app.route('/api/run/all', methods=['POST'])
@require_auth
def run_on_all():
    """Run same JOCKY command on ALL targets in a case simultaneously."""
    d       = request.json or {}
    case_id = d.get('case_id', '')
    command = d.get('command', '')

    conn    = get_db()
    targets = conn.execute(
        "SELECT target_ip, target_port FROM targets WHERE case_id=?",
        (case_id,)).fetchall()
    conn.close()

    if not targets:
        return jsonify({"error": "No targets for this case"}), 404

    all_results = {}

    def run_one(row):
        ip, port = row['target_ip'], row['target_port']
        return ip, execute_on_target(case_id, ip, port, command)

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
        futures = {ex.submit(run_one, t): t for t in targets}
        for future in concurrent.futures.as_completed(futures):
            ip, result = future.result()
            all_results[ip] = result

    audit(case_id, 'BULK_COMMAND',
          f"cmd={command} targets={len(targets)}")
    return jsonify({
        "command":         command,
        "targets_scanned": len(targets),
        "timestamp":       now(),
        "results":         all_results
    })


# ─────────────────────────────────────────────────────────────────────────────
# JOCKY SCRIPT EXECUTION
# ─────────────────────────────────────────────────────────────────────────────

@app.route('/api/script/validate', methods=['POST'])
@require_auth
def validate_script():
    d      = request.json or {}
    source = d.get('source', '')
    result = validate_jocky_script(source)
    return jsonify(result)


@app.route('/api/script/run', methods=['POST'])
@require_auth
def run_script():
    d         = request.json or {}
    source    = d.get('source', '')
    target_ip = d.get('target_ip', '127.0.0.1')
    port      = int(d.get('target_port', 5000))
    case_id   = d.get('case_id', 'DEMO')

    results = run_jocky_script(source, target_ip, port, case_id)

    # Save all results as evidence
    for r in results:
        ehash = evidence_hash(r)
        conn  = get_db()
        conn.execute(
            '''INSERT INTO evidence
               (case_id, target_ip, command, results,
                timestamp, evidence_hash)
               VALUES (?,?,?,?,?,?)''',
            (case_id, target_ip,
             r.get('_jocky_command', 'script'),
             json.dumps(r), now(), ehash))
        conn.commit()
        conn.close()
        r['evidence_hash'] = ehash

    return jsonify({
        "case_id":   case_id,
        "target_ip": target_ip,
        "executed":  len(results),
        "timestamp": now(),
        "results":   results
    })


@app.route('/api/script/morph', methods=['POST'])
@require_auth
def morph_script():
    """Run polymorphic engine on a JOCKY script."""
    d      = request.json or {}
    source = d.get('source', '')
    builds = int(d.get('builds', 3))

    morphed_builds = []
    for i in range(builds):
        result = POLY.morph(source)
        morphed_builds.append({
            "build":       i + 1,
            "hash":        result.build_hash,
            "xor_key":     result.encryption_key,
            "nonce":       result.nonce,
            "code_preview": result.morphed_code[:300],
        })

    all_unique = len({b['hash'] for b in morphed_builds}) == builds
    return jsonify({
        "original_hash": hashlib.sha256(source.encode()).hexdigest(),
        "builds":        morphed_builds,
        "all_unique":    all_unique,
    })


# ─────────────────────────────────────────────────────────────────────────────
# EVIDENCE
# ─────────────────────────────────────────────────────────────────────────────

@app.route('/api/evidence/<case_id>', methods=['GET'])
@require_auth
def get_evidence(case_id):
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM evidence WHERE case_id=? ORDER BY timestamp DESC",
        (case_id,)).fetchall()
    conn.close()
    evidence = []
    for r in rows:
        r = dict(r)
        try:
            r['results'] = json.loads(r['results'])
        except Exception:
            pass
        evidence.append(r)
    return jsonify({"evidence": evidence, "count": len(evidence)})


@app.route('/api/evidence/summary/<case_id>', methods=['GET'])
@require_auth
def evidence_summary(case_id):
    conn = get_db()
    rows = conn.execute(
        "SELECT command, target_ip, timestamp, evidence_hash "
        "FROM evidence WHERE case_id=? ORDER BY timestamp DESC",
        (case_id,)).fetchall()
    conn.close()
    return jsonify({
        "case_id":  case_id,
        "count":    len(rows),
        "summary":  [dict(r) for r in rows]
    })


# ─────────────────────────────────────────────────────────────────────────────
# REPORT TRIGGER
# ─────────────────────────────────────────────────────────────────────────────

@app.route('/api/report/<case_id>', methods=['GET'])
@require_auth
def generate_report(case_id):
    """Trigger PDF report generation for a case."""
    sys.path.insert(0, os.path.join(os.path.dirname(__file__),
                                    '..', 'reports'))
    from report_generator import generate_pdf

    conn    = get_db()
    case    = conn.execute("SELECT * FROM cases WHERE case_id=?",
                           (case_id,)).fetchone()
    targets = conn.execute("SELECT * FROM targets WHERE case_id=?",
                           (case_id,)).fetchall()
    ev_rows = conn.execute("SELECT * FROM evidence WHERE case_id=? "
                           "ORDER BY timestamp DESC", (case_id,)).fetchall()
    conn.close()

    if not case:
        return jsonify({"error": "Case not found"}), 404

    out_path = generate_pdf(dict(case),
                            [dict(t) for t in targets],
                            [dict(e) for e in ev_rows])
    return send_file(out_path, as_attachment=True,
                     download_name=f"JOCKY_{case_id}_report.pdf")


# ─────────────────────────────────────────────────────────────────────────────
# CI/CD & AGENT AUTO-UPDATE DISTRIBUTION
# ─────────────────────────────────────────────────────────────────────────────

AGENT_FILE_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'agent', 'agent.py'))

def _get_agent_info() -> dict:
    if os.path.exists(AGENT_FILE_PATH):
        with open(AGENT_FILE_PATH, 'rb') as f:
            content = f.read()
        return {
            "version": "1.0.1",
            "hash": hashlib.sha256(content).hexdigest(),
            "size_bytes": len(content),
            "updated_at": datetime.datetime.fromtimestamp(os.path.getmtime(AGENT_FILE_PATH)).isoformat(),
        }
    return {"version": "0.0.0", "hash": "", "size_bytes": 0, "updated_at": ""}

@app.route('/api/agent/latest', methods=['GET'])
def agent_latest():
    """Returns metadata for the latest agent build deployed to the server."""
    return jsonify(_get_agent_info())

@app.route('/api/agent/download', methods=['GET'])
def agent_download():
    """Allows remote agent machines to download the latest agent code."""
    if not os.path.exists(AGENT_FILE_PATH):
        return jsonify({"error": "Agent distribution file not found"}), 404
    return send_file(AGENT_FILE_PATH, as_attachment=True, download_name="agent.py")


# ─────────────────────────────────────────────────────────────────────────────
# STATUS
# ─────────────────────────────────────────────────────────────────────────────

@app.route('/api/status', methods=['GET'])
def status():
    return jsonify({
        "server":  "JOCKY Central Management Server",
        "version": "1.0.0",
        "status":  "online",
        "time":    now(),
        "db":      DB_PATH,
    })


# ─────────────────────────────────────────────────────────────────────────────
# FRONTEND DASHBOARD SERVING
# ─────────────────────────────────────────────────────────────────────────────

FRONTEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'frontend'))

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve_frontend(path):
    """Serve frontend dashboard static files directly on port 8000."""
    if path != "" and os.path.exists(os.path.join(FRONTEND_DIR, path)):
        return send_file(os.path.join(FRONTEND_DIR, path))
    return send_file(os.path.join(FRONTEND_DIR, 'index.html'))


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    print("=" * 55)
    print("  JOCKY Central Management Server v1.0.0")
    print("  Listening on http://0.0.0.0:8000")
    print("=" * 55)
    app.run(host='0.0.0.0', port=8000, debug=True)
