import os, re, sqlite3
from functools import wraps
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from werkzeug.security import generate_password_hash, check_password_hash

BASE = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.environ.get("DB_PATH", os.path.join(BASE, "digital_od.sqlite3"))
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "local-development-secret-change-before-deployment")
REGISTRATION_CODE = os.environ.get("REGISTRATION_CODE", "ruban2009@")
RESET_PIN = os.environ.get("RESET_PIN", "6899")

def db_conn():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db

@app.teardown_appcontext
def close_db(error=None):
    conn = g.pop("db", None)
    if conn:
        conn.close()

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys=ON")
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS users(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      full_name TEXT NOT NULL,
      email TEXT NOT NULL COLLATE NOCASE UNIQUE,
      register_id TEXT UNIQUE,
      role TEXT NOT NULL CHECK(role IN ('student','adviser','hod')),
      password_hash TEXT NOT NULL,
      adviser_id INTEGER,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(adviser_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS od_requests(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      student_id INTEGER NOT NULL,
      event_name TEXT NOT NULL,
      reason TEXT NOT NULL,
      from_date TEXT NOT NULL,
      to_date TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'Pending Adviser',
      adviser_id INTEGER,
      adviser_comment TEXT DEFAULT '',
      hod_comment TEXT DEFAULT '',
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(student_id) REFERENCES users(id),
      FOREIGN KEY(adviser_id) REFERENCES users(id)
    );
    """)
    conn.commit()
    conn.close()

@app.before_request
def ensure_db():
    if not os.path.exists(DB_PATH):
        init_db()

def login_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please log in to continue.", "error")
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapped

def current_user():
    return db_conn().execute("SELECT * FROM users WHERE id=?", (session.get("user_id"),)).fetchone()

@app.route("/")
def home():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))
    return render_template("home.html")

@app.route("/register", methods=["GET","POST"])
def register():
    conn = db_conn()
    advisers = conn.execute("SELECT id,full_name,email FROM users WHERE role='adviser' ORDER BY full_name").fetchall()
    if request.method == "POST":
        name = request.form.get("full_name","").strip()
        email = request.form.get("email","").strip().lower()
        role = request.form.get("role","")
        password = request.form.get("password","")
        confirm = request.form.get("confirm_password","")
        access = request.form.get("registration_code","")
        register_id = request.form.get("register_id","").strip() or None
        adviser_email = request.form.get("adviser_email","").strip().lower() or None

        if access != REGISTRATION_CODE:
            flash("Incorrect registration password. Registration was not completed.", "error")
        elif not name or not re.match(r"^[^\s@]+@[^\s@]+\.[^\s@]+$", email):
            flash("Enter your full name and a valid email address.", "error")
        elif role not in ("student","adviser","hod"):
            flash("Choose Student, Adviser or HOD.", "error")
        elif len(password) < 8:
            flash("Password must contain at least 8 characters.", "error")
        elif password != confirm:
            flash("Password and confirm password do not match.", "error")
        elif role == "student" and not register_id:
            flash("Enter your register number.", "error")
        elif role == "student" and not adviser_email:
            flash("Select your class adviser.", "error")
        else:
            adviser = None
            if role == "student":
                adviser = conn.execute("SELECT id FROM users WHERE email=? AND role='adviser'", (adviser_email,)).fetchone()
                if not adviser:
                    flash("Selected adviser account was not found.", "error")
                    return render_template("register.html", advisers=advisers)
            try:
                conn.execute("""INSERT INTO users(full_name,email,register_id,role,password_hash,adviser_id)
                                VALUES(?,?,?,?,?,?)""",
                             (name,email,register_id,role,generate_password_hash(password), adviser["id"] if adviser else None))
                conn.commit()
                flash("Registration successful. You can now log in.", "success")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("This email or register number is already registered.", "error")
    return render_template("register.html", advisers=advisers)

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email","").strip().lower()
        password = request.form.get("password","")
        user = db_conn().execute("SELECT * FROM users WHERE email=? COLLATE NOCASE", (email,)).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["role"] = user["role"]
            session["full_name"] = user["full_name"]
            return redirect(url_for("dashboard"))
        flash("Incorrect email or password. Please try again.", "error")
    return render_template("login.html")

@app.route("/forgot-password", methods=["GET","POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email","").strip().lower()
        pin = request.form.get("pin","")
        new_password = request.form.get("new_password","")
        confirm = request.form.get("confirm_password","")
        if pin != RESET_PIN:
            flash("Incorrect reset PIN.", "error")
        elif len(new_password) < 8:
            flash("New password must contain at least 8 characters.", "error")
        elif new_password != confirm:
            flash("Passwords do not match.", "error")
        else:
            cur = db_conn().execute("UPDATE users SET password_hash=? WHERE email=? COLLATE NOCASE",
                (generate_password_hash(new_password),email))
            db_conn().commit()
            if cur.rowcount:
                flash("Password reset successful. Please log in.", "success")
                return redirect(url_for("login"))
            flash("No account was found with that email address.", "error")
    return render_template("forgot.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("You have logged out.", "success")
    return redirect(url_for("home"))

@app.route("/dashboard")
@login_required
def dashboard():
    user = current_user()
    if not user:
        session.clear()
        return redirect(url_for("login"))
    conn = db_conn()
    if user["role"] == "student":
        rows = conn.execute("SELECT * FROM od_requests WHERE student_id=? ORDER BY created_at DESC",(user["id"],)).fetchall()
    elif user["role"] == "adviser":
        rows = conn.execute("""SELECT r.*,u.full_name AS student_name,u.email AS student_email
            FROM od_requests r JOIN users u ON r.student_id=u.id
            WHERE u.adviser_id=? ORDER BY r.created_at DESC""",(user["id"],)).fetchall()
    else:
        rows = conn.execute("""SELECT r.*,u.full_name AS student_name,u.email AS student_email,
            a.full_name AS adviser_name FROM od_requests r
            JOIN users u ON r.student_id=u.id LEFT JOIN users a ON r.adviser_id=a.id
            WHERE r.status IN ('Pending HOD','Approved','Rejected by HOD')
            ORDER BY r.created_at DESC""").fetchall()
    return render_template("dashboard.html", user=user, requests=rows)

@app.route("/apply", methods=["POST"])
@login_required
def apply():
    user = current_user()
    if user["role"] != "student":
        flash("Only students can submit OD applications.", "error")
        return redirect(url_for("dashboard"))
    event = request.form.get("event_name","").strip()
    reason = request.form.get("reason","").strip()
    start = request.form.get("from_date","")
    end = request.form.get("to_date","")
    try:
        d1 = datetime.strptime(start,"%Y-%m-%d").date()
        d2 = datetime.strptime(end,"%Y-%m-%d").date()
        if d2 < d1 or not event or not reason:
            raise ValueError()
    except ValueError:
        flash("Enter valid details. To Date must be on or after From Date.", "error")
        return redirect(url_for("dashboard"))
    if not user["adviser_id"]:
        flash("No adviser is assigned to your account. Please contact the administrator.", "error")
        return redirect(url_for("dashboard"))
    db_conn().execute("""INSERT INTO od_requests(student_id,event_name,reason,from_date,to_date,adviser_id)
                         VALUES(?,?,?,?,?,?)""",(user["id"],event,reason,start,end,user["adviser_id"]))
    db_conn().commit()
    flash("OD request submitted to your adviser.", "success")
    return redirect(url_for("dashboard"))

@app.route("/decision/<int:request_id>", methods=["POST"])
@login_required
def decision(request_id):
    user = current_user()
    choice = request.form.get("decision")
    comment = request.form.get("comment","").strip()
    if choice not in ("accept","reject"):
        flash("Invalid decision.", "error")
        return redirect(url_for("dashboard"))
    conn = db_conn()
    row = conn.execute("""SELECT r.*,s.adviser_id AS assigned_adviser FROM od_requests r
                          JOIN users s ON r.student_id=s.id WHERE r.id=?""",(request_id,)).fetchone()
    if not row:
        flash("OD request not found.", "error")
    elif user["role"] == "adviser":
        if row["assigned_adviser"] != user["id"] or row["status"] != "Pending Adviser":
            flash("This request is not awaiting your review.", "error")
        else:
            status = "Pending HOD" if choice == "accept" else "Rejected by Adviser"
            conn.execute("UPDATE od_requests SET status=?,adviser_id=?,adviser_comment=?,updated_at=CURRENT_TIMESTAMP WHERE id=?",
                         (status,user["id"],comment,request_id))
            conn.commit()
            flash("Request forwarded to HOD." if choice=="accept" else "Request rejected.", "success")
    elif user["role"] == "hod":
        if row["status"] != "Pending HOD":
            flash("This request is not awaiting HOD approval.", "error")
        else:
            status = "Approved" if choice == "accept" else "Rejected by HOD"
            conn.execute("UPDATE od_requests SET status=?,hod_comment=?,updated_at=CURRENT_TIMESTAMP WHERE id=?",
                         (status,comment,request_id))
            conn.commit()
            flash("Final decision saved.", "success")
    else:
        flash("You are not authorized to make approval decisions.", "error")
    return redirect(url_for("dashboard"))

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT",5000)), debug=False)
