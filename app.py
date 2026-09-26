from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
    send_from_directory
)

import sqlite3
import os
import hashlib
from datetime import datetime


# ============================================================
# APP CONFIGURATION
# ============================================================

app = Flask(
    __name__,
    static_folder="static",
    static_url_path="/static"
)

app.secret_key = "CHANGE_THIS_SECRET_KEY_LATER"

DATABASE = "veridoc.db"
UPLOAD_FOLDER = "uploads"

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

os.makedirs(UPLOAD_FOLDER, exist_ok=True)


# ============================================================
# ADMISSION DOCUMENTS
# ============================================================

ADMISSION_DOCUMENTS = [
    ("document_sslc", "10th / SSLC Certificate"),
    ("document_puc", "12th / PUC Certificate"),
    ("document_transfer", "Transfer Certificate"),
    ("document_migration", "Migration Certificate"),
    ("document_caste", "Caste Certificate"),
    ("document_income", "Income Certificate")
]


# ============================================================
# DATABASE CONNECTION
# ============================================================

def get_db():
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    return db


# ============================================================
# DATABASE MIGRATION HELPER
# ============================================================

def ensure_column(db, table_name, column_name, column_definition):
    columns = db.execute(
        f"PRAGMA table_info({table_name})"
    ).fetchall()

    existing_columns = [column["name"] for column in columns]

    if column_name not in existing_columns:
        db.execute(
            f"ALTER TABLE {table_name} ADD COLUMN "
            f"{column_name} {column_definition}"
        )


# ============================================================
# INITIALIZE DATABASE
# ============================================================

def init_database():

    db = get_db()

    # --------------------------------------------------------
    # USERS TABLE
    # --------------------------------------------------------
    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    # --------------------------------------------------------
    # TRUSTED RECORDS TABLE
    # Kept for compatibility with earlier versions.
    # --------------------------------------------------------
    db.execute("""
        CREATE TABLE IF NOT EXISTS trusted_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT,
            dob TEXT,
            roll_number TEXT,
            passing_year TEXT,
            board TEXT,
            certificate_type TEXT,
            certificate_number TEXT,
            created_at TEXT
        )
    """)

    # --------------------------------------------------------
    # VERIFICATION REQUESTS TABLE
    # --------------------------------------------------------
    db.execute("""
        CREATE TABLE IF NOT EXISTS verification_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            full_name TEXT NOT NULL,
            dob TEXT NOT NULL,
            roll_number TEXT NOT NULL,
            passing_year TEXT NOT NULL,
            board TEXT NOT NULL,
            certificate_type TEXT NOT NULL,
            filename TEXT NOT NULL,
            file_hash TEXT NOT NULL,
            status TEXT NOT NULL,
            reason TEXT,
            created_at TEXT NOT NULL
        )
    """)

    # --------------------------------------------------------
    # ADD NEW COLUMNS TO OLD DATABASES
    # --------------------------------------------------------
    ensure_column(
        db,
        "verification_requests",
        "batch_id",
        "TEXT"
    )

    ensure_column(
        db,
        "verification_requests",
        "approval_status",
        "TEXT"
    )

    ensure_column(
        db,
        "verification_requests",
        "approved_at",
        "TEXT"
    )

    ensure_column(
        db,
        "verification_requests",
        "approved_by",
        "INTEGER"
    )

    # --------------------------------------------------------
    # OLD RECORDS -> PENDING
    # --------------------------------------------------------
    db.execute("""
        UPDATE verification_requests
        SET approval_status = 'PENDING'
        WHERE approval_status IS NULL
           OR approval_status = ''
    """)

    # --------------------------------------------------------
    # GIVE OLD RECORDS A BATCH ID
    # --------------------------------------------------------
    old_rows = db.execute("""
        SELECT id, user_id
        FROM verification_requests
        WHERE batch_id IS NULL
           OR batch_id = ''
        ORDER BY user_id, id
    """).fetchall()

    current_user_id = None
    current_batch_id = None

    for row in old_rows:

        if row["user_id"] != current_user_id:

            current_user_id = row["user_id"]

            current_batch_id = (
                "OLD-"
                + str(row["user_id"])
                + "-"
                + datetime.now().strftime("%Y%m%d%H%M%S%f")
            )

        db.execute("""
            UPDATE verification_requests
            SET batch_id = ?
            WHERE id = ?
        """, (
            current_batch_id,
            row["id"]
        ))

    # --------------------------------------------------------
    # CREATE DEFAULT ADMIN
    # --------------------------------------------------------
    admin = db.execute("""
        SELECT id
        FROM users
        WHERE email = ?
    """, ("admin@veridoc.local",)).fetchone()

    if not admin:

        db.execute("""
            INSERT INTO users
            (name, email, password, created_at)
            VALUES (?, ?, ?, ?)
        """, (
            "Administrator",
            "admin@veridoc.local",
            "admin123",
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ))

    db.commit()
    db.close()


# ============================================================
# HOME PAGE
# ============================================================

@app.route("/")
def home():
    return render_template("index.html")


# ============================================================
# REGISTER
# ============================================================

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "").strip()

        if not name or not email or not password:
            flash("Please fill all fields.")
            return render_template("register.html")

        db = get_db()

        existing_user = db.execute("""
            SELECT id
            FROM users
            WHERE email = ?
        """, (email,)).fetchone()

        if existing_user:

            db.close()

            flash("Email already registered.")
            return render_template("register.html")

        db.execute("""
            INSERT INTO users
            (name, email, password, created_at)
            VALUES (?, ?, ?, ?)
        """, (
            name,
            email,
            password,
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ))

        db.commit()
        db.close()

        flash("Registration successful. Please login.")

        return redirect(url_for("login"))

    return render_template("register.html")


# ============================================================
# LOGIN
# ============================================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "").strip()

        db = get_db()

        user = db.execute("""
            SELECT *
            FROM users
            WHERE email = ?
              AND password = ?
        """, (
            email,
            password
        )).fetchone()

        db.close()

        if not user:

            flash("Invalid email or password.")
            return render_template("login.html")

        session["user_id"] = user["id"]
        session["user_name"] = user["name"]
        session["user_email"] = user["email"]

        if user["email"] == "admin@veridoc.local":
            session["admin_id"] = user["id"]
            return redirect(url_for("admin_dashboard"))

        return redirect(url_for("verify"))

    return render_template("login.html")


# ============================================================
# LOGOUT
# ============================================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect(url_for("home"))


# ============================================================
# VERIFY / DOCUMENT UPLOAD
# ============================================================

@app.route("/verify", methods=["GET", "POST"])
def verify():

    if "user_id" not in session:
        return redirect(url_for("login"))

    # Prevent administrator from using student verification form
    if session.get("user_email") == "admin@veridoc.local":
        return redirect(url_for("admin_dashboard"))

    if request.method == "POST":

        full_name = request.form.get("full_name", "").strip()
        dob = request.form.get("dob", "").strip()
        roll_number = request.form.get("roll_number", "").strip()

        # These are retained because the existing database expects them.
        passing_year = request.form.get(
            "passing_year",
            "Not Provided"
        ).strip()

        board = request.form.get(
            "board",
            "Not Provided"
        ).strip()

        if not full_name or not dob or not roll_number:
            flash("Please fill all student details.")
            return render_template("verify.html")

        # ----------------------------------------------------
        # CREATE A UNIQUE SUBMISSION BATCH
        # ----------------------------------------------------
        batch_id = (
            "VD-"
            + datetime.now().strftime("%Y%m%d%H%M%S")
            + "-"
            + str(session["user_id"])
        )

        db = get_db()

        uploaded_any = False

        # ----------------------------------------------------
        # SAVE ALL SIX DOCUMENTS
        # ----------------------------------------------------
        for field_name, document_label in ADMISSION_DOCUMENTS:

            file = request.files.get(field_name)

            if not file or not file.filename:
                continue

            uploaded_any = True

            original_filename = file.filename

            # Make a safe filename
            safe_filename = os.path.basename(original_filename)

            timestamp = datetime.now().strftime(
                "%Y%m%d%H%M%S%f"
            )

            stored_filename = (
                str(session["user_id"])
                + "_"
                + timestamp
                + "_"
                + safe_filename
            )

            file_path = os.path.join(
                app.config["UPLOAD_FOLDER"],
                stored_filename
            )

            file.save(file_path)

            # ------------------------------------------------
            # CALCULATE FILE HASH
            # ------------------------------------------------
            sha256 = hashlib.sha256()

            with open(file_path, "rb") as saved_file:

                while True:

                    chunk = saved_file.read(8192)

                    if not chunk:
                        break

                    sha256.update(chunk)

            file_hash = sha256.hexdigest()

            # ------------------------------------------------
            # SAVE RECORD
            # ------------------------------------------------
            db.execute("""
                INSERT INTO verification_requests
                (
                    user_id,
                    full_name,
                    dob,
                    roll_number,
                    passing_year,
                    board,
                    certificate_type,
                    filename,
                    file_hash,
                    status,
                    reason,
                    created_at,
                    batch_id,
                    approval_status,
                    approved_at,
                    approved_by
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                session["user_id"],
                full_name,
                dob,
                roll_number,
                passing_year,
                board,
                document_label,
                stored_filename,
                file_hash,
                "UPLOADED",
                None,
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                batch_id,
                "PENDING",
                None,
                None
            ))

        if not uploaded_any:

            db.close()

            flash("Please upload at least one document.")
            return render_template("verify.html")

        db.commit()
        db.close()

        session["last_batch_id"] = batch_id

        return redirect(
            url_for("admission_result")
        )

    return render_template("verify.html")


# ============================================================
# ADMISSION RESULT / STUDENT STATUS
# ============================================================

@app.route("/result")
def admission_result():

    if "user_id" not in session:
        return redirect(url_for("login"))

    if session.get("user_email") == "admin@veridoc.local":
        return redirect(url_for("admin_dashboard"))

    db = get_db()

    batch_id = session.get("last_batch_id")

    # --------------------------------------------------------
    # Get latest batch for this student
    # --------------------------------------------------------
    if batch_id:

        submissions = db.execute("""
            SELECT *
            FROM verification_requests
            WHERE user_id = ?
              AND batch_id = ?
            ORDER BY id ASC
        """, (
            session["user_id"],
            batch_id
        )).fetchall()

    else:

        latest = db.execute("""
            SELECT batch_id
            FROM verification_requests
            WHERE user_id = ?
            ORDER BY id DESC
            LIMIT 1
        """, (
            session["user_id"],
        )).fetchone()

        if latest and latest["batch_id"]:

            batch_id = latest["batch_id"]

            session["last_batch_id"] = batch_id

            submissions = db.execute("""
                SELECT *
                FROM verification_requests
                WHERE user_id = ?
                  AND batch_id = ?
                ORDER BY id ASC
            """, (
                session["user_id"],
                batch_id
            )).fetchall()

        else:

            submissions = []

    db.close()

    approval_status = "PENDING"

    if submissions:

        statuses = [
            row["approval_status"]
            for row in submissions
        ]

        if all(status == "APPROVED" for status in statuses):
            approval_status = "APPROVED"

        elif any(status == "REJECTED" for status in statuses):
            approval_status = "REJECTED"

        else:
            approval_status = "PENDING"

    approved_count = sum(
        1
        for row in submissions
        if row["approval_status"] == "APPROVED"
    )

    pending_count = sum(
        1
        for row in submissions
        if row["approval_status"] == "PENDING"
    )

    rejected_count = sum(
        1
        for row in submissions
        if row["approval_status"] == "REJECTED"
    )

    return render_template(
        "result.html",
        submissions=submissions,
        approval_status=approval_status,
        approved_count=approved_count,
        pending_count=pending_count,
        rejected_count=rejected_count
    )


# ============================================================
# ADMIN DASHBOARD
# ============================================================

@app.route("/admin")
def admin_dashboard():

    if "admin_id" not in session:
        return redirect(url_for("login"))

    db = get_db()

    rows = db.execute("""
        SELECT *
        FROM verification_requests
        ORDER BY id DESC
    """).fetchall()

    db.close()

    # --------------------------------------------------------
    # GROUP DOCUMENTS BY BATCH ID
    # Each student submission becomes one card.
    # --------------------------------------------------------
    grouped = {}

    for row in rows:

        key = row["batch_id"]

        if not key:
            key = "ROW-" + str(row["id"])

        if key not in grouped:

            grouped[key] = {
                "primary_id": row["id"],
                "batch_id": row["batch_id"],
                "user_id": row["user_id"],
                "full_name": row["full_name"],
                "dob": row["dob"],
                "roll_number": row["roll_number"],
                "passing_year": row["passing_year"],
                "board": row["board"],
                "approval_status": row["approval_status"],
                "approved_at": row["approved_at"],
                "approved_by": row["approved_by"],
                "created_at": row["created_at"],
                "documents": []
            }

        grouped[key]["documents"].append(row)

        # If the current row carries approval information,
        # use that information for the group.
        if row["approval_status"]:
            grouped[key]["approval_status"] = row["approval_status"]

        if row["approved_at"]:
            grouped[key]["approved_at"] = row["approved_at"]

        if row["approved_by"]:
            grouped[key]["approved_by"] = row["approved_by"]

    submissions = list(grouped.values())

    return render_template(
        "admin.html",
        submissions=submissions
    )


# ============================================================
# ADMIN APPROVE STUDENT
# ============================================================

@app.route(
    "/admin/approve-request/<int:request_id>",
    methods=["POST"]
)
def approve_request(request_id):

    if "admin_id" not in session:
        return redirect(url_for("login"))

    db = get_db()

    # --------------------------------------------------------
    # FIND THE SELECTED DOCUMENT
    # --------------------------------------------------------
    row = db.execute("""
        SELECT
            id,
            user_id,
            batch_id
        FROM verification_requests
        WHERE id = ?
    """, (
        request_id,
    )).fetchone()

    if not row:

        db.close()

        flash("Submission not found.")

        return redirect(
            url_for("admin_dashboard")
        )

    approval_time = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    # --------------------------------------------------------
    # IMPORTANT:
    # Approve the COMPLETE STUDENT SUBMISSION.
    # --------------------------------------------------------

    if row["batch_id"]:

        db.execute("""
            UPDATE verification_requests
            SET
                approval_status = 'APPROVED',
                approved_at = ?,
                approved_by = ?
            WHERE batch_id = ?
        """, (
            approval_time,
            session["admin_id"],
            row["batch_id"]
        ))

    else:

        db.execute("""
            UPDATE verification_requests
            SET
                approval_status = 'APPROVED',
                approved_at = ?,
                approved_by = ?
            WHERE user_id = ?
        """, (
            approval_time,
            session["admin_id"],
            row["user_id"]
        ))

    db.commit()
    db.close()

    flash("Student approved successfully.")

    return redirect(
        url_for("admin_dashboard")
    )


# ============================================================
# ADMIN REJECT STUDENT
# ============================================================

@app.route(
    "/admin/reject-request/<int:request_id>",
    methods=["POST"]
)
def reject_request(request_id):

    if "admin_id" not in session:
        return redirect(url_for("login"))

    db = get_db()

    row = db.execute("""
        SELECT
            id,
            user_id,
            batch_id
        FROM verification_requests
        WHERE id = ?
    """, (
        request_id,
    )).fetchone()

    if not row:

        db.close()

        flash("Submission not found.")

        return redirect(
            url_for("admin_dashboard")
        )

    reason = request.form.get(
        "reason",
        "Documents rejected by administrator."
    ).strip()

    if not reason:
        reason = "Documents rejected by administrator."

    if row["batch_id"]:

        db.execute("""
            UPDATE verification_requests
            SET
                approval_status = 'REJECTED',
                status = 'REJECTED',
                reason = ?,
                approved_at = NULL,
                approved_by = ?
            WHERE batch_id = ?
        """, (
            reason,
            session["admin_id"],
            row["batch_id"]
        ))

    else:

        db.execute("""
            UPDATE verification_requests
            SET
                approval_status = 'REJECTED',
                status = 'REJECTED',
                reason = ?,
                approved_at = NULL,
                approved_by = ?
            WHERE user_id = ?
        """, (
            reason,
            session["admin_id"],
            row["user_id"]
        ))

    db.commit()
    db.close()

    flash("Student rejected.")

    return redirect(
        url_for("admin_dashboard")
    )


# ============================================================
# VIEW UPLOADED DOCUMENT
# ============================================================

@app.route("/uploads/<filename>")
def uploaded_file(filename):

    if "admin_id" not in session:
        return redirect(url_for("login"))

    return send_from_directory(
        app.config["UPLOAD_FOLDER"],
        filename
    )


# ============================================================
# OPTIONAL AUTHORIZE PAGE
# ============================================================

@app.route("/authorize")
def authorize():

    if "user_id" not in session:
        return redirect(url_for("login"))

    return render_template("authorize.html")


# ============================================================
# ERROR HANDLERS
# ============================================================

@app.errorhandler(404)
def page_not_found(error):
    return "Page not found.", 404


@app.errorhandler(500)
def internal_server_error(error):
    return "Internal server error.", 500


# ============================================================
# START APPLICATION
# ============================================================

if __name__ == "__main__":

    init_database()

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )