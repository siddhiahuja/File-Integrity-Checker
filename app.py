
import os, sqlite3, hashlib, secrets
from pathlib import Path
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

ROOT = Path(__file__).resolve().parent
DB_PATH = ROOT / "file_integrity.db"
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-only-change-before-deployment")
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024

def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db

@app.teardown_appcontext
def close_db(error=None):
    conn = g.pop("db", None)
    if conn is not None: conn.close()

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS users(
      id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE COLLATE NOCASE, password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('admin','user')),
      created_at TEXT DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS baselines(
      id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
      filename TEXT NOT NULL, sha256 TEXT NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE);
    CREATE TABLE IF NOT EXISTS scans(
      id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
      filename TEXT NOT NULL, sha256 TEXT NOT NULL, status TEXT NOT NULL,
      scanned_at TEXT DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE);
    """)
    conn.commit(); conn.close()

def csrf():
    if "_csrf" not in session: session["_csrf"] = secrets.token_hex(24)
    return session["_csrf"]
app.jinja_env.globals["csrf_token"] = csrf

@app.before_request
def csrf_check():
    if request.method == "POST":
        token = request.form.get("_csrf", "")
        if not session.get("_csrf") or not secrets.compare_digest(token, session["_csrf"]):
            flash("Form expired. Please try again.", "error")
            return redirect(request.referrer or url_for("login"))

@app.context_processor
def context_user(): return {"current_user": session.get("user")}

def login_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        if not session.get("user"):
            flash("Please log in first.", "error")
            return redirect(url_for("login"))
        return fn(*a, **kw)
    return wrapper

def admin_required(fn):
    @wraps(fn)
    @login_required
    def wrapper(*a, **kw):
        if session["user"]["role"] != "admin":
            flash("Admin permission required.", "error")
            return redirect(url_for("dashboard"))
        return fn(*a, **kw)
    return wrapper

@app.route("/")
def home(): return redirect(url_for("dashboard") if session.get("user") else url_for("login"))

@app.route("/signup", methods=["GET","POST"])
def signup():
    if session.get("user"): return redirect(url_for("dashboard"))
    if request.method == "POST":
        name=request.form.get("name","").strip()
        email=request.form.get("email","").strip().lower()
        pw=request.form.get("password","")
        confirm=request.form.get("confirm_password","")
        if not name or not email or not pw: flash("Complete all fields.", "error")
        elif len(pw)<8: flash("Password must be at least 8 characters.", "error")
        elif pw!=confirm: flash("Passwords do not match.", "error")
        else:
            try:
                db().execute("INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,'user')",
                             (name,email,generate_password_hash(pw)))
                db().commit()
                flash("Account created. Please log in.", "success")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError: flash("That email is already registered.", "error")
    return render_template("signup.html")

@app.route("/login", methods=["GET","POST"])
def login():
    if session.get("user"): return redirect(url_for("dashboard"))
    if request.method=="POST":
        email=request.form.get("email","").strip().lower()
        pw=request.form.get("password","")
        row=db().execute("SELECT * FROM users WHERE email=?",(email,)).fetchone()
        if row and check_password_hash(row["password_hash"],pw):
            session.clear()
            session["user"]={"id":row["id"],"name":row["name"],"email":row["email"],"role":row["role"]}
            flash("Welcome, "+row["name"]+".","success")
            return redirect(url_for("dashboard"))
        flash("Invalid email or password.", "error")
    return render_template("login.html")

@app.post("/logout")
@login_required
def logout():
    session.clear(); flash("You have logged out.", "success")
    return redirect(url_for("login"))

@app.route("/dashboard")
@login_required
def dashboard():
    u=session["user"]; conn=db()
    if u["role"]=="admin":
        stats=conn.execute("""SELECT COUNT(*) total,
          SUM(status='Verified') verified,SUM(status='Modified') modified FROM scans""").fetchone()
        rows=conn.execute("""SELECT s.*,u.name owner FROM scans s JOIN users u ON u.id=s.user_id
          ORDER BY s.id DESC LIMIT 20""").fetchall()
    else:
        stats=conn.execute("""SELECT COUNT(*) total,SUM(status='Verified') verified,
          SUM(status='Modified') modified FROM scans WHERE user_id=?""",(u["id"],)).fetchone()
        rows=conn.execute("SELECT *,NULL owner FROM scans WHERE user_id=? ORDER BY id DESC LIMIT 20",(u["id"],)).fetchall()
    return render_template("dashboard.html",stats=stats,history=rows)

@app.post("/scan")
@login_required
def scan():
    f=request.files.get("file"); action=request.form.get("action","verify")
    if not f or not f.filename: flash("Choose a file first.", "error"); return redirect(url_for("dashboard"))
    filename=secure_filename(f.filename)
    if not filename: flash("Invalid filename.", "error"); return redirect(url_for("dashboard"))
    h=hashlib.sha256()
    for chunk in iter(lambda:f.stream.read(1024*1024),b""): h.update(chunk)
    digest=h.hexdigest(); uid=session["user"]["id"]; conn=db()
    if action=="save":
        conn.execute("INSERT INTO baselines(user_id,filename,sha256) VALUES(?,?,?)",(uid,filename,digest))
        status="Baseline saved"; flash("Trusted baseline saved for "+filename+".", "success")
    else:
        base=conn.execute("SELECT sha256 FROM baselines WHERE user_id=? AND filename=? ORDER BY id DESC LIMIT 1",(uid,filename)).fetchone()
        if not base: status="No baseline"; flash("No baseline found. Save a baseline first.", "error")
        elif secrets.compare_digest(base["sha256"],digest):
            status="Verified"; flash("Hashes match. No content change detected.", "success")
        else:
            status="Modified"; flash("Hashes differ. File modification detected.", "error")
    conn.execute("INSERT INTO scans(user_id,filename,sha256,status) VALUES(?,?,?,?)",(uid,filename,digest,status))
    conn.commit()
    return redirect(url_for("dashboard"))

@app.route("/admin/users")
@admin_required
def users():
    rows=db().execute("SELECT id,name,email,role,created_at FROM users ORDER BY id").fetchall()
    return render_template("users.html",users=rows)

@app.post("/admin/users/<int:uid>/role")
@admin_required
def role(uid):
    new=request.form.get("role")
    if new not in ("admin","user"): flash("Invalid role.", "error")
    elif uid==session["user"]["id"]: flash("You cannot change your own role.", "error")
    else:
        db().execute("UPDATE users SET role=? WHERE id=?",(new,uid)); db().commit()
        flash("Role updated.", "success")
    return redirect(url_for("users"))

@app.cli.command("create-admin")
def create_admin():
    init_db()
    name=input("Admin name: ").strip(); email=input("Admin email: ").strip().lower()
    pw=input("Admin password (8+ characters): ")
    if not name or not email or len(pw)<8: print("Invalid details."); return
    conn=sqlite3.connect(DB_PATH)
    try:
        conn.execute("INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,'admin')",
                     (name,email,generate_password_hash(pw)))
        conn.commit(); print("Admin account created.")
    except sqlite3.IntegrityError: print("That email already exists.")
    finally: conn.close()

@app.errorhandler(413)
def too_big(e):
    flash("File exceeds the 16 MB limit.", "error")
    return redirect(url_for("dashboard"))

if __name__=="__main__":
    init_db()
    app.run(debug=True)
