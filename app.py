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
import secrets
import smtplib
from email.message import EmailMessage
from datetime import datetime, timedelta

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

from werkzeug.utils import secure_filename


# ============================================================
# APP CONFIGURATION
# ============================================================

app = Flask(
    __name__,
    static_folder="static",
    static_url_path="/static"
)


# ============================================================
# SECURITY SETTINGS
# ============================================================

SECRET_KEY = os.environ.get(
    "VERIDOC_SECRET_KEY",
    "CHANGE_THIS_TO_A_LONG_RANDOM_SECRET"
)

ADMIN_EMAIL = os.environ.get(
    "VERIDOC_ADMIN_EMAIL",
    "admin@veridoc.local"
)

ADMIN_PASSWORD = os.environ.get(
    "VERIDOC_ADMIN_PASSWORD",
    "CHANGE_THIS_ADMIN_PASSWORD"
)

app.secret_key = SECRET_KEY


# ============================================================
# EMAIL OTP SETTINGS
# ============================================================

MAIL_EMAIL = os.environ.get(
    "VERIDOC_MAIL_EMAIL",
    ""
)

MAIL_APP_PASSWORD = os.environ.get(
    "VERIDOC_MAIL_APP_PASSWORD",
    ""
)

MAIL_SMTP_HOST = os.environ.get(
    "VERIDOC_MAIL_SMTP_HOST",
    "smtp.gmail.com"
)

MAIL_SMTP_PORT = int(
    os.environ.get(
        "VERIDOC_MAIL_SMTP_PORT",
        "587"
    )
)

OTP_EXPIRY_MINUTES = 10


# ============================================================
# DATABASE / UPLOAD SETTINGS
# ============================================================

DATABASE = "veridoc.db"

UPLOAD_FOLDER = "uploads"

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

app.config["MAX_CONTENT_LENGTH"] = (
    25 * 1024 * 1024
)

os.makedirs(
    UPLOAD_FOLDER,
    exist_ok=True
)


# ============================================================
# ALLOWED FILE TYPES
# ============================================================

ALLOWED_EXTENSIONS = {
    "pdf",
    "jpg",
    "jpeg",
    "png"
}


def allowed_file(filename):

    if not filename:
        return False

    if "." not in filename:
        return False

    extension = filename.rsplit(
        ".",
        1
    )[1].lower()

    return extension in ALLOWED_EXTENSIONS


# ============================================================
# ADMISSION DOCUMENTS
# ============================================================

ADMISSION_DOCUMENTS = [
    (
        "document_sslc",
        "10th / SSLC Certificate"
    ),
    (
        "document_puc",
        "12th / PUC Certificate"
    ),
    (
        "document_transfer",
        "Transfer Certificate"
    ),
    (
        "document_migration",
        "Migration Certificate"
    ),
    (
        "document_caste",
        "Caste Certificate"
    ),
    (
        "document_income",
        "Income Certificate"
    )
]


# ============================================================
# DATABASE CONNECTION
# ============================================================

def get_db():

    db = sqlite3.connect(
        DATABASE
    )

    db.row_factory = sqlite3.Row

    return db


# ============================================================
# DATABASE MIGRATION HELPER
# ============================================================

def ensure_column(
    db,
    table_name,
    column_name,
    column_definition
):

    columns = db.execute(
        f"PRAGMA table_info({table_name})"
    ).fetchall()

    existing_columns = [
        column["name"]
        for column in columns
    ]

    if column_name not in existing_columns:

        db.execute(
            f"""
            ALTER TABLE {table_name}
            ADD COLUMN {column_name}
            {column_definition}
            """
        )


# ============================================================
# PASSWORD HELPERS
# ============================================================

def is_password_hashed(password):

    if not password:
        return False

    return (
        password.startswith("scrypt:")
        or password.startswith("pbkdf2:")
    )


def verify_user_password(
    stored_password,
    entered_password
):

    if not stored_password:
        return False

    if is_password_hashed(
        stored_password
    ):

        try:

            return check_password_hash(
                stored_password,
                entered_password
            )

        except Exception:

            return False

    # Old plaintext admin passwords
    return (
        stored_password
        == entered_password
    )


# ============================================================
# EMAIL OTP HELPERS
# ============================================================

def generate_otp():

    return f"{secrets.randbelow(1000000):06d}"


def send_email_otp(
    recipient_email,
    otp,
    purpose="login"
):

    if (
        not MAIL_EMAIL
        or not MAIL_APP_PASSWORD
    ):

        return (
            False,
            "Email sending is not configured yet."
        )

    if purpose == "registration":

        subject = (
            "Your VeriDoc Registration OTP"
        )

        message_text = f"""Hello,

Welcome to VeriDoc.

Your registration OTP is: {otp}

This OTP is valid for {OTP_EXPIRY_MINUTES} minutes.

Do not share this OTP with anyone.

If you did not request this, you can ignore this email.

Regards,
VeriDoc
Jain College of Engineering and Research
"""

    else:

        subject = (
            "Your VeriDoc Login OTP"
        )

        message_text = f"""Hello,

Your VeriDoc login OTP is: {otp}

This OTP is valid for {OTP_EXPIRY_MINUTES} minutes.

Do not share this OTP with anyone.

If you did not request this login, you can ignore this email.

Regards,
VeriDoc
Jain College of Engineering and Research
"""


    message = EmailMessage()

    message["Subject"] = subject

    message["From"] = MAIL_EMAIL

    message["To"] = recipient_email

    message.set_content(
        message_text
    )


    try:

        with smtplib.SMTP(
            MAIL_SMTP_HOST,
            MAIL_SMTP_PORT,
            timeout=20
        ) as smtp:

            smtp.starttls()

            smtp.login(
                MAIL_EMAIL,
                MAIL_APP_PASSWORD
            )

            smtp.send_message(
                message
            )

        return True, None


    except Exception as error:

        print(
            "EMAIL OTP ERROR:",
            error
        )

        return (
            False,
            str(error)
        )


# ============================================================
# INITIALIZE DATABASE
# ============================================================

def init_database():

    db = get_db()


    # ========================================================
    # USERS
    # ========================================================

    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)


    ensure_column(
        db,
        "users",
        "role",
        "TEXT DEFAULT 'student'"
    )


    db.execute("""
        UPDATE users
        SET role = 'student'
        WHERE role IS NULL
           OR role = ''
    """)


    ensure_column(
        db,
        "users",
        "email_verified",
        "INTEGER DEFAULT 0"
    )


    ensure_column(
        db,
        "users",
        "otp",
        "TEXT"
    )


    ensure_column(
        db,
        "users",
        "otp_created_at",
        "TEXT"
    )


    # Existing accounts remain usable.
    db.execute("""
        UPDATE users
        SET email_verified = 1
        WHERE email_verified IS NULL
    """)


    db.execute("""
        UPDATE users
        SET email_verified = 1
        WHERE role = 'admin'
    """)


    # ========================================================
    # TRUSTED RECORDS
    # ========================================================

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


    # ========================================================
    # VERIFICATION REQUESTS
    # ========================================================

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


    # ========================================================
    # MIGRATE OLD VERIFICATION DATABASE
    # ========================================================

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


    # ========================================================
    # OLD RECORDS -> PENDING
    # ========================================================

    db.execute("""
        UPDATE verification_requests
        SET approval_status = 'PENDING'
        WHERE approval_status IS NULL
           OR approval_status = ''
    """)


    # ========================================================
    # GIVE OLD RECORDS BATCH IDS
    # ========================================================

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
                + datetime.now().strftime(
                    "%Y%m%d%H%M%S%f"
                )
            )


        db.execute("""
            UPDATE verification_requests
            SET batch_id = ?
            WHERE id = ?
        """, (
            current_batch_id,
            row["id"]
        ))


    # ========================================================
    # CREATE / UPDATE ADMIN
    # ========================================================

    admin = db.execute("""
        SELECT *
        FROM users
        WHERE email = ?
    """, (
        ADMIN_EMAIL.lower(),
    )).fetchone()


    if not admin:

        if (
            not ADMIN_PASSWORD
            or ADMIN_PASSWORD
            == "CHANGE_THIS_ADMIN_PASSWORD"
        ):

            print(
                "\nWARNING:"
                "\nAdmin account does not exist."
                "\nSet VERIDOC_ADMIN_PASSWORD before creating it."
                "\n"
            )

        else:

            admin_password_hash = (
                generate_password_hash(
                    ADMIN_PASSWORD
                )
            )

            db.execute("""
                INSERT INTO users
                (
                    name,
                    email,
                    password,
                    created_at,
                    role,
                    email_verified
                )
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                "Administrator",
                ADMIN_EMAIL.lower(),
                admin_password_hash,
                datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
                "admin",
                1
            ))

    else:

        db.execute("""
            UPDATE users
            SET role = 'admin',
                email_verified = 1
            WHERE email = ?
        """, (
            ADMIN_EMAIL.lower(),
        ))


        # Upgrade old plaintext admin password
        if (
            admin["password"]
            and not is_password_hashed(
                admin["password"]
            )
        ):

            new_hash = generate_password_hash(
                admin["password"]
            )

            db.execute("""
                UPDATE users
                SET password = ?
                WHERE id = ?
            """, (
                new_hash,
                admin["id"]
            ))


    db.commit()

    db.close()


# ============================================================
# HOME
# ============================================================

@app.route("/")
def home():

    return render_template(
        "index.html"
    )


# ============================================================
# REGISTER
# ============================================================

@app.route(
    "/register",
    methods=["GET", "POST"]
)
def register():

    if request.method == "POST":

        name = request.form.get(
            "name",
            ""
        ).strip()

        email = request.form.get(
            "email",
            ""
        ).strip().lower()


        # ----------------------------------------------------
        # PASSWORD IS NO LONGER REQUIRED FOR STUDENTS
        # ----------------------------------------------------

        if not name or not email:

            flash(
                "Please enter your name and email address."
            )

            return render_template(
                "register.html"
            )


        # Basic email validation

        if (
            "@" not in email
            or "." not in email.split("@")[-1]
        ):

            flash(
                "Please enter a valid email address."
            )

            return render_template(
                "register.html"
            )


        db = get_db()


        existing_user = db.execute("""
            SELECT *
            FROM users
            WHERE email = ?
        """, (
            email,
        )).fetchone()


        # ====================================================
        # EXISTING USER
        # ====================================================

        if existing_user:

            # ------------------------------------------------
            # Existing unverified student
            # ------------------------------------------------

            if (
                existing_user["role"] != "admin"
                and not existing_user["email_verified"]
            ):

                otp = generate_otp()

                now = datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S"
                )


                db.execute("""
                    UPDATE users
                    SET
                        otp = ?,
                        otp_created_at = ?
                    WHERE id = ?
                """, (
                    otp,
                    now,
                    existing_user["id"]
                ))


                db.commit()


                sent, error = send_email_otp(
                    email,
                    otp,
                    "registration"
                )


                if not sent:

                    db.close()

                    flash(
                        "OTP could not be sent. Please check your Gmail configuration."
                    )

                    return render_template(
                        "register.html"
                    )


                db.close()


                session.clear()

                session[
                    "pending_verification_email"
                ] = email

                session[
                    "otp_purpose"
                ] = "registration"


                flash(
                    "A new OTP has been sent to your email."
                )


                return redirect(
                    url_for(
                        "verify_email"
                    )
                )


            db.close()


            flash(
                "Email already registered. Please login using OTP."
            )


            return render_template(
                "register.html"
            )


        # ====================================================
        # CREATE NEW STUDENT
        # ====================================================

        # ----------------------------------------------------
        # The database still has a password column because
        # older VeriDoc databases require it.
        #
        # Students never see or use this password.
        # A random secure value is stored instead.
        # ----------------------------------------------------

        internal_password = (
            secrets.token_urlsafe(32)
        )

        password_hash = (
            generate_password_hash(
                internal_password
            )
        )


        otp = generate_otp()


        now = datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )


        db.execute("""
            INSERT INTO users
            (
                name,
                email,
                password,
                created_at,
                role,
                email_verified,
                otp,
                otp_created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            name,
            email,
            password_hash,
            now,
            "student",
            0,
            otp,
            now
        ))


        db.commit()


        # ====================================================
        # SEND REGISTRATION OTP
        # ====================================================

        sent, error = send_email_otp(
            email,
            otp,
            "registration"
        )


        if not sent:

            db.execute("""
                DELETE FROM users
                WHERE email = ?
            """, (
                email,
            ))

            db.commit()

            db.close()


            flash(
                "Registration could not send the verification email. Please check your Gmail configuration."
            )


            return render_template(
                "register.html"
            )


        db.close()


        session.clear()

        session[
            "pending_verification_email"
        ] = email

        session[
            "otp_purpose"
        ] = "registration"


        flash(
            "OTP sent to your email. Enter it to complete registration."
        )


        return redirect(
            url_for(
                "verify_email"
            )
        )


    return render_template(
        "register.html"
    )


# ============================================================
# EMAIL OTP VERIFICATION
# ============================================================

@app.route(
    "/verify-email",
    methods=["GET", "POST"]
)
def verify_email():

    registration_email = session.get(
        "pending_verification_email"
    )

    login_email = session.get(
        "pending_login_email"
    )


    # Determine which flow is active.

    if login_email:

        email = login_email

        purpose = "login"

    elif registration_email:

        email = registration_email

        purpose = "registration"

    else:

        flash(
            "Please start the registration or login process first."
        )

        return redirect(
            url_for("login")
        )


    if request.method == "POST":

        otp = request.form.get(
            "otp",
            ""
        ).strip()


        if (
            not otp
            or len(otp) != 6
            or not otp.isdigit()
        ):

            flash(
                "Please enter the 6-digit OTP."
            )

            return render_template(
                "verify_email.html",
                email=email
            )


        db = get_db()


        user = db.execute("""
            SELECT *
            FROM users
            WHERE email = ?
        """, (
            email,
        )).fetchone()


        if not user:

            db.close()

            session.pop(
                "pending_verification_email",
                None
            )

            session.pop(
                "pending_login_email",
                None
            )

            session.pop(
                "otp_purpose",
                None
            )

            flash(
                "Account not found. Please register first."
            )

            return redirect(
                url_for("register")
            )


        # ====================================================
        # OTP EXPIRY
        # ====================================================

        created_text = user[
            "otp_created_at"
        ]


        try:

            created_at = datetime.strptime(
                created_text,
                "%Y-%m-%d %H:%M:%S"
            )

        except Exception:

            created_at = datetime.min


        if (
            datetime.now()
            - created_at
            > timedelta(
                minutes=OTP_EXPIRY_MINUTES
            )
        ):

            db.close()

            flash(
                "OTP expired. Please request a new OTP."
            )

            return render_template(
                "verify_email.html",
                email=email
            )


        # ====================================================
        # CHECK OTP
        # ====================================================

        if user["otp"] != otp:

            db.close()

            flash(
                "Invalid OTP. Please try again."
            )

            return render_template(
                "verify_email.html",
                email=email
            )


        # ====================================================
        # LOGIN OTP
        # ====================================================

        if purpose == "login":

            # Student only
            if user["role"] == "admin":

                db.close()

                session.pop(
                    "pending_login_email",
                    None
                )

                session.pop(
                    "otp_purpose",
                    None
                )

                flash(
                    "Administrator accounts must use administrator login."
                )

                return redirect(
                    url_for("login")
                )


            # Mark email verified as well
            db.execute("""
                UPDATE users
                SET
                    email_verified = 1,
                    otp = NULL,
                    otp_created_at = NULL
                WHERE id = ?
            """, (
                user["id"],
            ))


            db.commit()

            db.close()


            # Clear OTP state
            session.pop(
                "pending_login_email",
                None
            )

            session.pop(
                "pending_verification_email",
                None
            )

            session.pop(
                "otp_purpose",
                None
            )


            # =================================================
            # CREATE STUDENT LOGIN SESSION
            # =================================================

            session.clear()

            session["user_id"] = (
                user["id"]
            )

            session["user_name"] = (
                user["name"]
            )

            session["user_email"] = (
                user["email"]
            )

            session["user_role"] = "student"


            flash(
                "Login successful."
            )


            return redirect(
                url_for("verify")
            )


        # ====================================================
        # REGISTRATION OTP
        # ====================================================

        db.execute("""
            UPDATE users
            SET
                email_verified = 1,
                otp = NULL,
                otp_created_at = NULL
            WHERE id = ?
        """, (
            user["id"],
        ))


        db.commit()

        db.close()


        session.pop(
            "pending_verification_email",
            None
        )

        session.pop(
            "pending_login_email",
            None
        )

        session.pop(
            "otp_purpose",
            None
        )


        flash(
            "Email verified successfully. You can now login using your email and OTP."
        )


        return redirect(
            url_for("login")
        )


    return render_template(
        "verify_email.html",
        email=email
    )


# ============================================================
# RESEND OTP
# ============================================================

@app.route(
    "/resend-otp",
    methods=["GET", "POST"]
)
def resend_otp():

    registration_email = session.get(
        "pending_verification_email"
    )

    login_email = session.get(
        "pending_login_email"
    )


    if login_email:

        email = login_email

        purpose = "login"

    elif registration_email:

        email = registration_email

        purpose = "registration"

    else:

        flash(
            "No OTP request is currently active."
        )

        return redirect(
            url_for("login")
        )


    db = get_db()


    user = db.execute("""
        SELECT *
        FROM users
        WHERE email = ?
    """, (
        email,
    )).fetchone()


    if not user:

        db.close()

        session.clear()

        flash(
            "Account not found."
        )

        return redirect(
            url_for("register")
        )


    if (
        purpose == "login"
        and user["role"] == "admin"
    ):

        db.close()

        session.clear()

        flash(
            "Administrator accounts use password login."
        )

        return redirect(
            url_for("login")
        )


    new_otp = generate_otp()

    now = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )


    db.execute("""
        UPDATE users
        SET
            otp = ?,
            otp_created_at = ?
        WHERE id = ?
    """, (
        new_otp,
        now,
        user["id"]
    ))


    db.commit()


    sent, error = send_email_otp(
        email,
        new_otp,
        purpose
    )


    if not sent:

        db.close()

        flash(
            "Could not send a new OTP. Please check your Gmail configuration."
        )

        return render_template(
            "verify_email.html",
            email=email
        )


    db.close()


    flash(
        "A new OTP has been sent to your email."
    )


    return redirect(
        url_for(
            "verify_email"
        )
    )


# ============================================================
# LOGIN
# ============================================================

@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    if request.method == "POST":

        email = request.form.get(
            "email",
            ""
        ).strip().lower()


        password = request.form.get(
            "password",
            ""
        ).strip()


        admin_mode = (
            request.form.get(
                "admin_mode"
            )
            == "on"
        )


        # ====================================================
        # EMAIL REQUIRED
        # ====================================================

        if not email:

            flash(
                "Please enter your email address."
            )

            return render_template(
                "login.html"
            )


        db = get_db()


        user = db.execute("""
            SELECT *
            FROM users
            WHERE email = ?
        """, (
            email,
        )).fetchone()


        # ====================================================
        # USER NOT FOUND
        # ====================================================

        if not user:

            db.close()

            flash(
                "Email is not registered. Please create an account first."
            )

            return render_template(
                "login.html"
            )


        # ====================================================
        # ADMIN LOGIN
        # ====================================================

        if admin_mode:

            if user["role"] != "admin":

                db.close()

                flash(
                    "This email is not an administrator account."
                )

                return render_template(
                    "login.html"
                )


            if not password:

                db.close()

                flash(
                    "Administrator password is required."
                )

                return render_template(
                    "login.html"
                )


            if not verify_user_password(
                user["password"],
                password
            ):

                db.close()

                flash(
                    "Invalid administrator password."
                )

                return render_template(
                    "login.html"
                )


            # Upgrade old plaintext password

            if not is_password_hashed(
                user["password"]
            ):

                new_hash = (
                    generate_password_hash(
                        password
                    )
                )


                db.execute("""
                    UPDATE users
                    SET password = ?
                    WHERE id = ?
                """, (
                    new_hash,
                    user["id"]
                ))


                db.commit()


            db.close()


            session.clear()


            session["user_id"] = (
                user["id"]
            )

            session["user_name"] = (
                user["name"]
            )

            session["user_email"] = (
                user["email"]
            )

            session["user_role"] = "admin"

            session["admin_id"] = (
                user["id"]
            )


            flash(
                "Administrator login successful."
            )


            return redirect(
                url_for(
                    "admin_dashboard"
                )
            )


        # ====================================================
        # STUDENT LOGIN
        # ====================================================

        # If the user is an admin but didn't select
        # Administrator login, do not send a student OTP.

        if user["role"] == "admin":

            db.close()

            flash(
                "Please select Administrator login."
            )

            return render_template(
                "login.html"
            )


        # ====================================================
        # STUDENT MUST VERIFY EMAIL
        # ====================================================

        if not user["email_verified"]:

            db.close()


            session.clear()


            session[
                "pending_verification_email"
            ] = email

            session[
                "otp_purpose"
            ] = "registration"


            flash(
                "Please verify your email before logging in."
            )


            return redirect(
                url_for(
                    "verify_email"
                )
            )


        # ====================================================
        # GENERATE LOGIN OTP
        # ====================================================

        otp = generate_otp()


        now = datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )


        db.execute("""
            UPDATE users
            SET
                otp = ?,
                otp_created_at = ?
            WHERE id = ?
        """, (
            otp,
            now,
            user["id"]
        ))


        db.commit()


        # ====================================================
        # SEND LOGIN OTP
        # ====================================================

        sent, error = send_email_otp(
            email,
            otp,
            "login"
        )


        if not sent:

            # Remove the OTP if email failed.
            db.execute("""
                UPDATE users
                SET
                    otp = NULL,
                    otp_created_at = NULL
                WHERE id = ?
            """, (
                user["id"],
            ))

            db.commit()

            db.close()


            print(
                "LOGIN OTP SEND ERROR:",
                error
            )


            flash(
                "Login OTP could not be sent. Please check your Gmail configuration."
            )


            return render_template(
                "login.html"
            )


        db.close()


        # ====================================================
        # STORE LOGIN OTP SESSION
        # ====================================================

        session.clear()


        session[
            "pending_login_email"
        ] = email


        session[
            "otp_purpose"
        ] = "login"


        flash(
            "Login OTP has been sent to your email."
        )


        return redirect(
            url_for(
                "verify_email"
            )
        )


    return render_template(
        "login.html"
    )


# ============================================================
# LOGOUT
# ============================================================

@app.route("/logout")
def logout():

    session.clear()


    flash(
        "You have been logged out."
    )


    return redirect(
        url_for("home")
    )


# ============================================================
# LOGIN REQUIRED HELPER
# ============================================================

def login_required():

    return (
        "user_id" in session
        and session.get(
            "user_role"
        ) in (
            "student",
            "admin"
        )
    )


# ============================================================
# ADMIN REQUIRED HELPER
# ============================================================

def admin_required():

    return (
        "user_id" in session
        and session.get(
            "user_role"
        ) == "admin"
    )


# ============================================================
# VERIFY / DOCUMENT UPLOAD PAGE
# ============================================================

@app.route("/verify", methods=["GET", "POST"])
def verify():

    # --------------------------------------------------------
    # STUDENT MUST BE LOGGED IN
    # --------------------------------------------------------
    if "user_id" not in session:
        flash("Please login first.")
        return redirect(url_for("login"))

    # --------------------------------------------------------
    # ADMIN USES ADMIN DASHBOARD
    # --------------------------------------------------------
    if session.get("user_role") == "admin":
        return redirect(url_for("admin_dashboard"))

    user_id = session["user_id"]
    db = get_db()

    # ========================================================
    # FIND LATEST SUBMISSION FOR THIS STUDENT
    # ========================================================
    latest = db.execute("""
        SELECT batch_id
        FROM verification_requests
        WHERE user_id = ?
          AND batch_id IS NOT NULL
          AND batch_id != ''
        ORDER BY id DESC
        LIMIT 1
    """, (user_id,)).fetchone()

    submission = None
    submission_status = None

    if latest:
        batch_id = latest["batch_id"]
        session["last_batch_id"] = batch_id

        batch_rows = db.execute("""
            SELECT *
            FROM verification_requests
            WHERE user_id = ?
              AND batch_id = ?
            ORDER BY id ASC
        """, (user_id, batch_id)).fetchall()

        if batch_rows:
            submission = batch_rows[0]
            statuses = [
                (row["approval_status"] or row["status"] or "PENDING").upper()
                for row in batch_rows
            ]

            if all(status == "APPROVED" for status in statuses):
                submission_status = "APPROVED"
            elif any(status == "REJECTED" for status in statuses):
                submission_status = "REJECTED"
            else:
                submission_status = "PENDING"

    # ========================================================
    # GET REQUEST
    # ========================================================
    if request.method == "GET":
        db.close()
        return render_template(
            "verify.html",
            submission_status=submission_status,
            submission=submission
        )

    # ========================================================
    # DO NOT ALLOW DUPLICATE SUBMISSION WHILE PENDING
    # ========================================================
    if submission_status == "PENDING":
        db.close()
        return render_template(
            "verify.html",
            submission_status="PENDING",
            submission=submission
        )

    # --------------------------------------------------------
    # Already approved: keep student on approved page.
    # --------------------------------------------------------
    if submission_status == "APPROVED":
        db.close()
        return render_template(
            "verify.html",
            submission_status="APPROVED",
            submission=submission
        )

    # ========================================================
    # STUDENT INFORMATION
    # ========================================================
    full_name = request.form.get("full_name", "").strip()
    dob = request.form.get("dob", "").strip()
    roll_number = request.form.get("roll_number", "").strip()
    passing_year = request.form.get("passing_year", "").strip()
    board = request.form.get("board", "").strip()

    if not full_name or not dob or not roll_number:
        db.close()
        return render_template(
            "verify.html",
            error="Please fill your name, date of birth and PUC register number.",
            submission_status=None,
            submission=None
        )

    # ========================================================
    # GENERATE BATCH ID
    # ========================================================
    batch_id = (
        "VD-"
        + datetime.now().strftime("%Y%m%d%H%M%S")
        + "-"
        + secrets.token_hex(3).upper()
    )

    saved_files = []
    uploaded_documents = []

    try:
        # ====================================================
        # RECEIVE ALL SIX REQUIRED DOCUMENTS FIRST
        # ====================================================
        for field_name, label in ADMISSION_DOCUMENTS:
            file = request.files.get(field_name)

            if not file or not file.filename:
                db.close()
                return render_template(
                    "verify.html",
                    error=f"Please upload {label}.",
                    submission_status=None,
                    submission=None
                )

            if not allowed_file(file.filename):
                db.close()
                return render_template(
                    "verify.html",
                    error=f"Invalid file type for {label}. Please upload PDF, JPG, JPEG or PNG.",
                    submission_status=None,
                    submission=None
                )

            original_name = secure_filename(file.filename)

            if not original_name:
                db.close()
                return render_template(
                    "verify.html",
                    error=f"Invalid filename for {label}.",
                    submission_status=None,
                    submission=None
                )

            unique_name = (
                batch_id
                + "_"
                + field_name
                + "_"
                + original_name
            )

            file_path = os.path.join(
                UPLOAD_FOLDER,
                unique_name
            )

            file.save(file_path)
            saved_files.append(file_path)

            # ------------------------------------------------
            # SHA-256 HASH
            # ------------------------------------------------
            sha256 = hashlib.sha256()

            with open(file_path, "rb") as saved_file:
                while True:
                    chunk = saved_file.read(8192)
                    if not chunk:
                        break
                    sha256.update(chunk)

            uploaded_documents.append(
                (
                    label,
                    unique_name,
                    sha256.hexdigest()
                )
            )

        # ====================================================
        # SAVE ALL SIX DOCUMENT RECORDS
        # ====================================================
        created_at = datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        for label, filename, file_hash in uploaded_documents:
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
                user_id,
                full_name,
                dob,
                roll_number,
                passing_year,
                board,
                label,
                filename,
                file_hash,
                "PENDING",
                None,
                created_at,
                batch_id,
                "PENDING",
                None,
                None
            ))

        db.commit()

        session["last_batch_id"] = batch_id

        new_submission = db.execute("""
            SELECT *
            FROM verification_requests
            WHERE user_id = ?
              AND batch_id = ?
            ORDER BY id ASC
            LIMIT 1
        """, (user_id, batch_id)).fetchone()

        db.close()

        # ----------------------------------------------------
        # Immediately show processing status on VERIFY PAGE
        # ----------------------------------------------------
        return render_template(
            "verify.html",
            submission_status="PENDING",
            submission=new_submission
        )

    except Exception as error:
        db.rollback()

        for file_path in saved_files:
            try:
                if os.path.exists(file_path):
                    os.remove(file_path)
            except Exception:
                pass

        db.close()

        print("DOCUMENT UPLOAD ERROR:", error)

        return render_template(
            "verify.html",
            error="There was a problem submitting your documents. Please try again.",
            submission_status=None,
            submission=None
        )


# ============================================================
# RESULT / STATUS PAGE
# ============================================================

@app.route("/result")
def result():

    if not login_required():

        flash(
            "Please login first."
        )

        return redirect(
            url_for("login")
        )


    if session.get(
        "user_role"
    ) == "admin":

        return redirect(
            url_for(
                "admin_dashboard"
            )
        )


    db = get_db()


    rows = db.execute("""
        SELECT *
        FROM verification_requests
        WHERE user_id = ?
        ORDER BY id DESC
    """, (
        session["user_id"],
    )).fetchall()


    db.close()


    latest_batch_id = session.get(
        "last_batch_id"
    )


    if latest_batch_id:

        batch_rows = [
            row
            for row in rows
            if row["batch_id"]
            == latest_batch_id
        ]

    else:

        batch_rows = rows


    return render_template(
        "result.html",
        requests=batch_rows,
        batch_id=latest_batch_id
    )


# ============================================================
# ADMIN DASHBOARD
# ============================================================

@app.route("/admin")
def admin_dashboard():

    if (
        "admin_id" not in session
        or session.get("user_role") != "admin"
    ):
        return redirect(url_for("login"))

    db = get_db()

    requests = db.execute("""
        SELECT
            vr.*,
            u.email AS student_email,
            u.name AS student_name
        FROM verification_requests vr
        LEFT JOIN users u
            ON u.id = vr.user_id
        ORDER BY vr.id DESC
    """).fetchall()

    db.close()

    return render_template(
        "admin_dashboard.html",
        requests=requests
    )


# ============================================================
# ADMIN APPROVE STUDENT
# ============================================================

@app.route(
    "/admin/approve-request/<int:request_id>",
    methods=["POST"]
)
def approve_request(request_id):

    if (
        "admin_id" not in session
        or session.get("user_role") != "admin"
    ):

        return redirect(
            url_for("login")
        )


    db = get_db()


    request_row = db.execute("""
        SELECT *
        FROM verification_requests
        WHERE id = ?
    """, (
        request_id,
    )).fetchone()


    if not request_row:

        db.close()

        flash(
            "Verification request not found."
        )

        return redirect(
            url_for("admin_dashboard")
        )


    batch_id = request_row["batch_id"]


    if batch_id:

        db.execute("""
            UPDATE verification_requests
            SET
                approval_status = 'APPROVED',
                status = 'APPROVED',
                approved_at = ?,
                approved_by = ?
            WHERE batch_id = ?
        """, (
            datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
            session["admin_id"],
            batch_id
        ))

    else:

        db.execute("""
            UPDATE verification_requests
            SET
                approval_status = 'APPROVED',
                status = 'APPROVED',
                approved_at = ?,
                approved_by = ?
            WHERE id = ?
        """, (
            datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
            session["admin_id"],
            request_id
        ))


    db.commit()

    db.close()


    flash(
        "Verification request approved successfully."
    )


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

    if (
        "admin_id" not in session
        or session.get("user_role") != "admin"
    ):

        return redirect(
            url_for("login")
        )


    reason = request.form.get(
        "reason",
        ""
    ).strip()


    if not reason:

        reason = "Rejected by administrator."


    db = get_db()


    request_row = db.execute("""
        SELECT *
        FROM verification_requests
        WHERE id = ?
    """, (
        request_id,
    )).fetchone()


    if not request_row:

        db.close()

        flash(
            "Verification request not found."
        )

        return redirect(
            url_for("admin_dashboard")
        )


    batch_id = request_row["batch_id"]


    if batch_id:

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
            batch_id
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
            WHERE id = ?
        """, (
            reason,
            session["admin_id"],
            request_id
        ))


    db.commit()

    db.close()


    flash(
        "Verification request rejected."
    )


    return redirect(
        url_for("admin_dashboard")
    )


# ============================================================
# ADMIN DOWNLOAD DOCUMENT
# ============================================================

@app.route(
    "/admin/document/<filename>"
)
def admin_document(filename):

    if (
        "admin_id" not in session
        or session.get("user_role") != "admin"
    ):

        return redirect(
            url_for("login")
        )


    safe_filename = secure_filename(
        filename
    )


    if not safe_filename:

        flash(
            "Invalid document."
        )

        return redirect(
            url_for("admin_dashboard")
        )


    file_path = os.path.join(
        app.config["UPLOAD_FOLDER"],
        safe_filename
    )


    if not os.path.isfile(
        file_path
    ):

        flash(
            "Document not found."
        )

        return redirect(
            url_for("admin_dashboard")
        )


    return send_from_directory(
        app.config["UPLOAD_FOLDER"],
        safe_filename,
        as_attachment=False
    )


# ============================================================
# STUDENT DOCUMENT DOWNLOAD
# ============================================================

@app.route(
    "/document/<filename>"
)
def student_document(filename):

    if "user_id" not in session:

        return redirect(
            url_for("login")
        )


    safe_filename = secure_filename(
        filename
    )


    if not safe_filename:

        return redirect(
            url_for("result")
        )


    db = get_db()


    document = db.execute("""
        SELECT *
        FROM verification_requests
        WHERE filename = ?
          AND user_id = ?
    """, (
        safe_filename,
        session["user_id"]
    )).fetchone()


    db.close()


    if not document:

        flash(
            "You are not authorized to access this document."
        )

        return redirect(
            url_for("result")
        )


    return send_from_directory(
        app.config["UPLOAD_FOLDER"],
        safe_filename,
        as_attachment=False
    )


# ============================================================
# FILE TOO LARGE
# ============================================================

@app.errorhandler(413)
def file_too_large(error):

    flash(
        "The uploaded file is too large. Please upload a smaller file."
    )

    return redirect(
        url_for("verify")
    )


# ============================================================
# INITIALIZE DATABASE
# ============================================================

init_database()


# ============================================================
# RUN APPLICATION
# ============================================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )