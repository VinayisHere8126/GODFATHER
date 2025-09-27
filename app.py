from dbm import sqlite3
import os
import platform
import shlex
import subprocess
import sys
import uuid
import argparse
import json
import base64
import uuid
import paramiko
from datetime import datetime
from utils import run_ssh_command

from flask import Flask, jsonify, render_template, request, abort, redirect, url_for, flash, send_file, Response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from flask_dance.contrib.google import make_google_blueprint, google
import psutil
import shutil
import getpass



# cryptography
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from dateutil import tz


# -------------------------
# Config
# -------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "disk_manager.db")
KEY_DIR = os.path.join(BASE_DIR, "keys")
PRIVATE_KEY_PATH = os.path.join(KEY_DIR, "private.pem")
PUBLIC_KEY_PATH = os.path.join(KEY_DIR, "public.pem")
PROOF_DIR = os.path.join(BASE_DIR, "proofs")
os.makedirs(KEY_DIR, exist_ok=True)
os.makedirs(PROOF_DIR, exist_ok=True)

app = Flask(__name__, static_folder="static", template_folder="templates")
app.config["SECRET_KEY"] = os.environ.get("DM_SECRET", "dev-secret-change-me")
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + DB_PATH
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# DEVICE_WHITELIST: comma-separated env var or empty list by default (safe default = no destructive)
raw_wl = os.environ.get("DM_WHITELIST", "")
app.config["DEVICE_WHITELIST"] = [x.strip() for x in raw_wl.split(",") if x.strip()]


# -------------------------
# Google OAuth setup
# -------------------------
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "<58137741976-o13l1kj20qelmnhi1msp66p72n2gnail.apps.googleusercontent.com>")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "<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>")

google_bp = make_google_blueprint(
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    scope=["profile", "email"],
    redirect_url="/login/google/authorized"
)
app.register_blueprint(google_bp, url_prefix="/login")

# -------------------------
# Extensions & DB models
# -------------------------
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

    def set_password(self, pwd):
        self.password_hash = generate_password_hash(pwd)

    def check_password(self, pwd):
        return check_password_hash(self.password_hash, pwd)

class Audit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=True)
    username = db.Column(db.String(80), nullable=True)
    device = db.Column(db.String(200), nullable=False)
    method = db.Column(db.String(80), nullable=False)
    simulated = db.Column(db.Boolean, default=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    outcome = db.Column(db.String(32), nullable=True)  # done / error / aborted / started
    returncode = db.Column(db.Integer, nullable=True)
    stdout = db.Column(db.Text, nullable=True)
    stderr = db.Column(db.Text, nullable=True)
    confirm_phrase = db.Column(db.String(256), nullable=True)

    # proof fields
    proof_uuid = db.Column(db.String(64), nullable=True, unique=True)
    proof_path = db.Column(db.String(512), nullable=True)
    verification_status = db.Column(db.String(32), nullable=True)  # signed|verified|failed

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# -------------------------
# Utilities: platform & disk discovery
# -------------------------
def is_root():
    sys_plat = platform.system().lower()
    if sys_plat in ("linux", "darwin"):
        try:
            return os.geteuid() == 0
        except AttributeError:
            return False
    elif sys_plat == "windows":
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    return False

def get_disks():
    disks = []
    try:
        parts = psutil.disk_partitions(all=False)
        for p in parts:
            try:
                usage = psutil.disk_usage(p.mountpoint)
                total = usage.total
                used = usage.used
                free = usage.free
            except Exception:
                total = used = free = None

            # SMART info (Linux/macOS using smartctl)
            health = "N/A"
            try:
                if platform.system().lower() in ["linux", "darwin"]:
                    cmd = ["smartctl", "-H", p.device]
                    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    if proc.returncode == 0:
                        for line in proc.stdout.splitlines():
                            if "overall-health" in line.lower() or "health" in line.lower():
                                health = line.split(":")[-1].strip()
            except Exception:
                health = "Unavailable"

            disks.append({
                "device": p.device,
                "mountpoint": p.mountpoint,
                "fstype": p.fstype,
                "opts": p.opts,
                "total_bytes": total,
                "used_bytes": used,
                "free_bytes": free,
                "health": health
            })
    except Exception as e:
        return {"error": str(e)}
    return disks

def build_wipe_command(device: str, method: str):
    """
    Build platform-specific command list (no 'sudo' included; server should already be privileged).
    """
    sys_plat = platform.system().lower()
    if method == "simulate":
        return (["echo", "SIMULATED WIPE"], "Simulated wipe (no changes)")

    if sys_plat == "linux":
        if method == "zero":
            return (["dd", "if=/dev/zero", f"of={device}", "bs=1M", "status=progress"], "Zero-fill with dd")
        if method == "shred":
            return (["shred", "-v", "-n", "3", device], "shred (3 passes)")
        if method == "nwipe":
            return (["nwipe", "-f", device], "nwipe interactive")
    elif sys_plat == "darwin":
        if method == "diskutil_zero":
            return (["diskutil", "eraseDisk", "Free", "NULL", device], "diskutil eraseDisk")
        if method == "diskutil_secure":
            return (["diskutil", "secureErase", "0", device], "diskutil secureErase")
    elif sys_plat == "windows":
        if method == "clean_all":
            # expects device to be disk number string like '1'
            script = f"select disk {device}\nclean all\nexit\n"
            ps_cmd = f"$p = [System.IO.Path]::GetTempFileName(); Set-Content $p -Value {shlex.quote(script)}; diskpart /s $p; Remove-Item $p"
            return (["powershell", "-Command", ps_cmd], "diskpart clean all")
    raise ValueError("Unsupported platform/method combination or method unknown")

def allowed_device(device):
    wl = app.config.get("DEVICE_WHITELIST") or []
    if not wl:
        return False
    return device in wl

# -------------------------
# Signing helpers (RSA-PSS + SHA256)
# -------------------------
def load_or_create_keys():
    if not os.path.exists(PRIVATE_KEY_PATH) or not os.path.exists(PUBLIC_KEY_PATH):
        from cryptography.hazmat.primitives.asymmetric import rsa
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        priv_pem = priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        pub = priv.public_key()
        pub_pem = pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(PRIVATE_KEY_PATH, "wb") as f:
            f.write(priv_pem)
        with open(PUBLIC_KEY_PATH, "wb") as f:
            f.write(pub_pem)
        try:
            os.chmod(PRIVATE_KEY_PATH, 0o600)
        except Exception:
            pass

def sign_proof_blob(blob_bytes: bytes) -> bytes:
    load_or_create_keys()
    with open(PRIVATE_KEY_PATH, "rb") as f:
        priv = serialization.load_pem_private_key(f.read(), password=None)
    sig = priv.sign(
        blob_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return sig

def verify_proof_blob(blob_bytes: bytes, signature: bytes) -> bool:
    load_or_create_keys()
    with open(PUBLIC_KEY_PATH, "rb") as f:
        pub = serialization.load_pem_public_key(f.read())
    try:
        pub.verify(
            signature,
            blob_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

def public_key_fingerprint_hex():
    if not os.path.exists(PUBLIC_KEY_PATH):
        return None
    pub_pem = open(PUBLIC_KEY_PATH, "rb").read()
    digest = hashes.Hash(hashes.SHA256())
    digest.update(pub_pem)
    return digest.finalize().hex()

# -------------------------
# Audit / proof creation
# -------------------------
def record_audit(user, device, method, simulated, confirm_phrase=None, outcome=None, returncode=None, stdout=None, stderr=None):
    entry = Audit(
        user_id = user.id if user else None,
        username = user.username if user else None,
        device = device,
        method = method,
        simulated = simulated,
        confirm_phrase = confirm_phrase,
        outcome = outcome,
        returncode = returncode,
        stdout = stdout,
        stderr = stderr
    )
    db.session.add(entry)
    db.session.commit()
    return entry

def create_and_attach_proof(audit_entry: Audit):
    """
    Build proof JSON, sign it, save to file, and update audit entry.
    """
    # ensure keys exist
    load_or_create_keys()

    # public key fingerprint
    pub_fp_hex = public_key_fingerprint_hex()

    # canonical timestamp
    ts = audit_entry.timestamp if audit_entry.timestamp else datetime.utcnow()
    ts_iso = ts.replace(tzinfo=tz.tzutc()).isoformat()

    proof_uuid = audit_entry.proof_uuid or str(uuid.uuid4())
    proof_obj = {
        "proof_uuid": proof_uuid,
        "device": audit_entry.device,
        "method": audit_entry.method,
        "nist_reference": "NIST SP 800-88 Rev.1",
        "sanitization_type": audit_entry.method,
        "user": audit_entry.username,
        "user_id": audit_entry.user_id,
        "timestamp_utc": ts_iso,
        "simulated": bool(audit_entry.simulated),
        "outcome": audit_entry.outcome,
        "returncode": audit_entry.returncode,
        "stdout": (audit_entry.stdout or "")[:20000],
        "stderr": (audit_entry.stderr or "")[:20000],
        "confirm_phrase": audit_entry.confirm_phrase,
        "public_key_fingerprint_sha256": pub_fp_hex
    }

    # canonical JSON bytes
    proof_json_bytes = json.dumps(proof_obj, sort_keys=True, indent=2).encode("utf-8")
    signature = sign_proof_blob(proof_json_bytes)
    signature_b64 = base64.b64encode(signature).decode("ascii")

    signed_proof = {
        "proof": proof_obj,
        "signature": signature_b64,
        "signature_algo": "RSA-PSS-SHA256"
    }

    fname = f"proof_{proof_uuid}.json"
    fpath = os.path.join(PROOF_DIR, fname)
    with open(fpath, "w", encoding="utf-8") as f:
        json.dump(signed_proof, f, indent=2)

    # update DB
    audit_entry.proof_uuid = proof_uuid
    audit_entry.proof_path = fpath
    audit_entry.verification_status = "signed"
    db.session.commit()
    return fpath

# -------------------------
# Routes: auth
# -------------------------
@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            flash("Logged in.", "success")
            return redirect(url_for("index"))
        flash("Invalid credentials", "danger")
    return render_template("login.html")

@app.route("/login/google/authorized")
def google_authorized():
    if not google.authorized:
        return redirect(url_for("google.login"))

    resp = google.get("/oauth2/v2/userinfo")
    if not resp.ok:
        flash("Failed to fetch user info from Google.", "danger")
        return redirect(url_for("login"))

    info = resp.json()
    email = info["email"]
    username = email.split("@")[0]

    # Check if user exists
    user = User.query.filter_by(username=username).first()
    if not user:
        # Auto-create user (non-admin)
        user = User(username=username)
        user.set_password(uuid.uuid4().hex)  # Random password
        db.session.add(user)
        db.session.commit()

    login_user(user)
    flash(f"Logged in as {username} via Google.", "success")
    return redirect(url_for("index"))


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not username or not password:
            flash("Username and password are required.", "danger")
            return redirect(url_for("signup"))

        # Check if user exists
        if User.query.filter_by(username=username).first():
            flash("Username already exists.", "danger")
            return redirect(url_for("signup"))

        # Create user
        new_user = User(username=username)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        flash("Account created successfully! Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("signup.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out", "info")
    return redirect(url_for("login"))



@app.route('/remote_hosts')
def remote_hosts():
    conn = sqlite3.connect('disk_manager.db')
    cur = conn.cursor()
    cur.execute("SELECT id, name, ip, username, platform FROM remote_hosts")
    hosts = cur.fetchall()
    conn.close()
    
    # hosts is a list of tuples; convert to list of dicts
    hosts_list = [
        {"id": h[0], "name": h[1], "ip": h[2], "username": h[3], "platform": h[4]}
        for h in hosts
    ]
    return render_template('remote_hosts.html', hosts=hosts_list)

@app.route('/remote_hosts/<int:host_id>/run', methods=['POST'])
def run_command(host_id):
    command = request.form.get('command')
    if not command:
        return jsonify({"error": "No command provided"}), 400
    
    # Fetch host details from DB
    conn = sqlite3.connect('disk_manager.db')
    cur = conn.cursor()
    cur.execute("SELECT ip, username, ssh_key FROM remote_hosts WHERE id = ?", (host_id,))
    row = cur.fetchone()
    conn.close()
    
    if not row:
        return jsonify({"error": "Host not found"}), 404
    
    ip, username, ssh_key = row
    output, error = run_ssh_command(ip, username, ssh_key, command)
    return jsonify({"output": output, "error": error})


# -------------------------
# Routes: UI & API
# -------------------------
@app.route("/")
@login_required
def index():
    disks = get_disks()
    return render_template("index.html", disks=disks, whitelist=app.config.get("DEVICE_WHITELIST"))

@app.route("/audit")
@login_required
def audit_view():
    if not current_user.is_admin:
        abort(403)
    logs = Audit.query.order_by(Audit.timestamp.desc()).limit(500).all()
    return render_template("audit.html", logs=logs)

@app.route("/api/disks", methods=["GET"])
@login_required
def api_disks():
    return jsonify(get_disks())

import os
from flask import Flask, request, jsonify

@app.route("/api/wipe", methods=["POST"])
def api_wipe():
    data = request.json or {}
    device = data.get("device")  # e.g. "D:"
    method = data.get("method", "simulate")

    if method == "simulate":
        # Try scanning the disk
        try:
            file_list = []
            for root, dirs, files in os.walk(device + "\\"):
                for name in files:
                    path = os.path.join(root, name)
                    size = os.path.getsize(path) // 1024  # KB
                    file_list.append(f"{path} ({size} KB)")
                    if len(file_list) > 50:  # limit to 50 for speed
                        break
                if len(file_list) > 50:
                    break
            return jsonify({"status": "ok", "files": file_list})
        except Exception as e:
            return jsonify({"status": "error", "error": str(e)}), 500

    # other wipe methods...
    return jsonify({"status": "pending"})


    return jsonify({"success": True, "device": device, "method": method, "message": result})


# Proof download + verify
@app.route("/proof/<proof_uuid>")
@login_required
def download_proof(proof_uuid):
    entry = Audit.query.filter_by(proof_uuid=proof_uuid).first_or_404()
    if not entry.proof_path or not os.path.exists(entry.proof_path):
        abort(404)
    # Only admins or the creator can download by default
    if not (current_user.is_admin or current_user.id == entry.user_id):
        abort(403)
    return send_file(entry.proof_path, as_attachment=True, download_name=os.path.basename(entry.proof_path))

@app.route("/proof/<proof_uuid>/verify")
@login_required
def verify_proof_route(proof_uuid):
    entry = Audit.query.filter_by(proof_uuid=proof_uuid).first_or_404()
    if not entry.proof_path or not os.path.exists(entry.proof_path):
        return jsonify({"error": "Proof not found"}), 404
    payload = json.load(open(entry.proof_path, "r", encoding="utf-8"))
    proof_json = json.dumps(payload["proof"], sort_keys=True, indent=2).encode("utf-8")
    signature = base64.b64decode(payload["signature"])
    ok = verify_proof_blob(proof_json, signature)
    entry.verification_status = "verified" if ok else "failed"
    db.session.commit()
    return jsonify({"verified": ok, "verification_status": entry.verification_status})

# CSV export (admin)
@app.route("/export_audit.csv")
@login_required
def export_audit_csv():
    if not current_user.is_admin:
        abort(403)
    logs = Audit.query.order_by(Audit.timestamp.desc()).all()
    def generate():
        header = "id,timestamp_utc,username,device,method,simulated,outcome,returncode,proof_uuid\n"
        yield header
        for l in logs:
            row = f'{l.id},"{l.timestamp.isoformat()}","{l.username}","{l.device}","{l.method}",{int(bool(l.simulated))},"{l.outcome}",{l.returncode or ""},"{l.proof_uuid or ""}"\n'
            yield row
    return Response(generate(), mimetype="text/csv", headers={"Content-Disposition":"attachment; filename=audit_export.csv"})

# -------------------------
# CLI helpers
# -------------------------
def init_db():
    with app.app_context():
        db.create_all()
        print("DB initialized at", DB_PATH)

def create_admin_interactive():
    with app.app_context():  # ⚡ Wrap everything that uses the DB
        init_db()  # DB initialization is safe here
        username = input("Enter admin username: ").strip()
        if not username:
            print("Username required")
            return

        if User.query.filter_by(username=username).first():
            print("User exists")
            return

        import getpass
        password = getpass.getpass("Password: ")
        password2 = getpass.getpass("Confirm Password: ")
        if password != password2:
            print("Passwords do not match")
            return

        u = User(username=username, is_admin=True)
        u.set_password(password)  # Make sure your User model has this method
        db.session.add(u)
        db.session.commit()
        print("Admin user created.")


# -------------------------
# Run
# -------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--init-db", action="store_true")
    parser.add_argument("--create-admin", action="store_true")
    args = parser.parse_args()

    if args.init_db:
        init_db(); sys.exit(0)
    if args.create_admin:
        create_admin_interactive(); sys.exit(0)

    host = "127.0.0.1"
    port = int(os.environ.get("PORT", 5000))
    print("Disk Manager starting. WARNING: destructive operations require admin/root and whitelist.")
    print("Visit http://%s:%d (login required)" % (host, port))
    app.run(host=host, port=port, debug=True)
