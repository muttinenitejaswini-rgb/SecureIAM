
import os
import sqlite3
import bcrypt

from flask import (
    Flask, render_template, request, redirect,
    session, flash, abort
)
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
csrf = CSRFProtect(app)

app.secret_key = os.environ.get("SECRET_KEY")

if not app.secret_key:
    raise RuntimeError(
        "SECRET_KEY environment variable is not set."
    )

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = False


# ---------------- DATABASE ----------------

def create_database():
    connection = sqlite3.connect("database.db")
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user'
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS security_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            event TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    connection.commit()
    connection.close()


create_database()


# ---------------- SECURITY LOGGING ----------------

def log_event(username, event):
    connection = sqlite3.connect("database.db")
    cursor = connection.cursor()

    cursor.execute(
        "INSERT INTO security_logs (username, event) VALUES (?, ?)",
        (username, event)
    )

    connection.commit()
    connection.close()


def check_failed_logins(username):
    connection = sqlite3.connect("database.db")
    cursor = connection.cursor()

    cursor.execute("""
        SELECT COUNT(*)
        FROM security_logs
        WHERE username = ?
          AND event = 'Failed login attempt'
          AND timestamp >= datetime('now', '-10 minutes')
    """, (username,))

    failed_attempts = cursor.fetchone()[0]
    connection.close()

    return failed_attempts


def admin_required():
    return (
        "user_id" in session
        and session.get("role") == "admin"
    )


# ---------------- HOME ----------------

@app.route("/")
def home():
    return render_template("home.html")


# ---------------- REGISTRATION ----------------

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        if len(username) < 3:
            flash("Username must contain at least 3 characters.", "error")
            return redirect("/register")

        if len(username) > 30:
            flash("Username cannot exceed 30 characters.", "error")
            return redirect("/register")

        
        if len(password) < 8:
            flash("Password must contain at least 8 characters.", "error")
            return redirect("/register")

        if len(password.encode("utf-8")) > 72:
            flash("Password cannot exceed 72 UTF-8 bytes.", "error")
            return redirect("/register")

        if not any(char.isupper() for char in password):
            flash("Password must contain at least one uppercase letter.", "error")
            return redirect("/register")

        if not any(char.islower() for char in password):
            flash("Password must contain at least one lowercase letter.", "error")
            return redirect("/register")

        if not any(char.isdigit() for char in password):
            flash("Password must contain at least one number.", "error")
            return redirect("/register")


        hashed_password = bcrypt.hashpw(
            password.encode("utf-8"),
            bcrypt.gensalt()
        )

        connection = sqlite3.connect("database.db")
        cursor = connection.cursor()

        try:
            cursor.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                (username, hashed_password.decode("utf-8"))
            )
            connection.commit()

        except sqlite3.IntegrityError:
            connection.close()
            flash("Username already exists.", "error")
            return redirect("/register")

        connection.close()

        log_event(username, "User registered")

        flash("Registration successful! Please login.", "success")
        return redirect("/login")

    return render_template("register.html")


# ---------------- LOGIN ----------------

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        connection = sqlite3.connect("database.db")
        cursor = connection.cursor()

        cursor.execute(
            "SELECT id, username, password, role FROM users WHERE username = ?",
            (username,)
        )

        user = cursor.fetchone()
        connection.close()

        if user:
            stored_password = user[2]

            if bcrypt.checkpw(
                password.encode("utf-8"),
                stored_password.encode("utf-8")
            ):
                session["user_id"] = user[0]
                session["username"] = user[1]
                session["role"] = user[3]

                log_event(username, "Successful login")

                flash("Login successful!", "success")
                return redirect("/dashboard")

        # Record this failed login exactly once.
        log_event(username, "Failed login attempt")

        # Generate one alert when the count reaches five.
        failed_attempts = check_failed_logins(username)

        if failed_attempts == 5:
            log_event(
                username,
                "ALERT: Possible brute-force attack - "
                "5 failed login attempts within 10 minutes"
            )

        flash("Invalid username or password.", "error")
        return redirect("/login")

    return render_template("login.html")


# ---------------- USER DASHBOARD ----------------

@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect("/login")

    return render_template(
        "dashboard.html",
        username=session["username"],
        role=session["role"]
    )


# ---------------- LOGOUT ----------------

@app.route("/logout", methods=["POST"])
def logout():
    username = session.get("username")

    if username:
        log_event(username, "User logout")

    session.clear()

    flash("You have been logged out successfully.", "success")
    return redirect("/login")


# ---------------- ADMIN DASHBOARD ----------------

@app.route("/admin")
def admin():
    if "user_id" not in session:
        return redirect("/login")

    if not admin_required():
        abort(403)

    connection = sqlite3.connect("database.db")
    cursor = connection.cursor()

    cursor.execute("SELECT COUNT(*) FROM users")
    total_users = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'")
    total_admins = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'user'")
    total_normal_users = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*)
        FROM security_logs
        WHERE event = 'Failed login attempt'
    """)
    failed_logins = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*)
        FROM security_logs
        WHERE event = 'Successful login'
    """)
    successful_logins = cursor.fetchone()[0]

    cursor.execute("""
        SELECT username, event, timestamp
        FROM security_logs
        ORDER BY id DESC
        LIMIT 5
    """)
    recent_logs = cursor.fetchall()

    connection.close()

    return render_template(
        "admin.html",
        username=session["username"],
        total_users=total_users,
        total_admins=total_admins,
        total_normal_users=total_normal_users,
        failed_logins=failed_logins,
        successful_logins=successful_logins,
        recent_logs=recent_logs
    )


# ---------------- USER MANAGEMENT ----------------

@app.route("/users")
def users():
    if "user_id" not in session:
        return redirect("/login")

    if not admin_required():
        abort(403)

    connection = sqlite3.connect("database.db")
    cursor = connection.cursor()

    cursor.execute("SELECT id, username, role FROM users")
    users_list = cursor.fetchall()

    connection.close()

    return render_template("users.html", users=users_list)


@app.route("/change-role/<int:user_id>", methods=["POST"])
def change_role(user_id):
    if "user_id" not in session:
        return redirect("/login")

    if not admin_required():
        abort(403)

    if user_id == session["user_id"]:
        return "You cannot change your own role!", 400

    new_role = request.form.get("role")

    if new_role not in ["admin", "user"]:
        return "Invalid role!", 400

    connection = sqlite3.connect("database.db")
    cursor = connection.cursor()

    cursor.execute(
        "UPDATE users SET role = ? WHERE id = ?",
        (new_role, user_id)
    )

    updated = cursor.rowcount
    connection.commit()
    connection.close()

    if updated == 0:
        return "User not found!", 404

    log_event(
        session["username"],
        f"Changed role of user ID {user_id} to {new_role}"
    )

    return redirect("/users")


@app.route("/delete-user/<int:user_id>", methods=["POST"])
def delete_user(user_id):
    if "user_id" not in session:
        return redirect("/login")

    if not admin_required():
        abort(403)

    if user_id == session["user_id"]:
        return "You cannot delete your own admin account!", 400

    connection = sqlite3.connect("database.db")
    cursor = connection.cursor()

    cursor.execute(
        "SELECT username FROM users WHERE id = ?",
        (user_id,)
    )
    user = cursor.fetchone()

    if user is None:
        connection.close()
        return "User not found!", 404

    deleted_username = user[0]

    cursor.execute(
        "DELETE FROM users WHERE id = ?",
        (user_id,)
    )

    connection.commit()
    connection.close()

    log_event(
        session["username"],
        f"Deleted user {deleted_username}"
    )

    return redirect("/users")


# ---------------- SECURITY LOGS ----------------

@app.route("/security-logs")
def security_logs():
    if "user_id" not in session:
        return redirect("/login")

    if not admin_required():
        abort(403)

    connection = sqlite3.connect("database.db")
    cursor = connection.cursor()

    cursor.execute("""
        SELECT username, event, timestamp
        FROM security_logs
        ORDER BY id DESC
    """)

    logs = cursor.fetchall()
    connection.close()

    return render_template("security_logs.html", logs=logs)


# ---------------- SECURITY ALERTS ----------------

@app.route("/security-alerts")
def security_alerts():
    if "user_id" not in session:
        return redirect("/login")

    if not admin_required():
        abort(403)

    connection = sqlite3.connect("database.db")
    cursor = connection.cursor()

    cursor.execute("""
        SELECT username, event, timestamp
        FROM security_logs
        WHERE event LIKE 'ALERT:%'
        ORDER BY id DESC
    """)

    alerts = cursor.fetchall()
    connection.close()

    return render_template(
        "security_alerts.html",
        alerts=alerts
    )


# ---------------- ERROR HANDLERS ----------------

@app.errorhandler(404)
def page_not_found(error):
    return """
    <h1>404 - Page Not Found</h1>
    <p>The requested page does not exist.</p>
    <a href="/dashboard">Return to Dashboard</a>
    """, 404


@app.errorhandler(403)
def access_denied(error):
    return """
    <h1>403 - Access Denied</h1>
    <p>You do not have permission to access this page.</p>
    <a href="/dashboard">Return to Dashboard</a>
    """, 403


# ---------------- RUN APPLICATION ----------------

if __name__ == "__main__":
    app.run(debug=False)
