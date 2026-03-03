from flask import Flask, render_template, request, redirect, url_for, session, flash
import mysql.connector
from mysql.connector import Error
from werkzeug.security import generate_password_hash, check_password_hash
import random, smtplib
import re
from email.mime.text import MIMEText
from functools import wraps
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
import requests
from authlib.integrations.flask_client import OAuth
import pickle
import numpy as np
from flask import request, render_template, redirect, url_for, session
from flask import send_file
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import inch
import io
from werkzeug.utils import secure_filename
import numpy as np
import os
from werkzeug.utils import secure_filename
import os, uuid
import numpy as np
from flask import request, render_template, session, redirect, url_for
from feature_extractor import extract_fingerprint_features
import joblib
from io import BytesIO



# Load ML Model & Scaler
model = pickle.load(open('diabetes_model.pkl', 'rb'))
scaler = pickle.load(open('scaler.pkl', 'rb'))


app = Flask(__name__)
app.secret_key = 'super_secret_key_change_this'




# ================= DATABASE CONFIG =================
def get_db_connection():
    try:
        conn = mysql.connector.connect(
            host=os.environ.get("DB_HOST"),
            user=os.environ.get("DB_USER"),
            password=os.environ.get("DB_PASSWORD"),
            database=os.environ.get("DB_NAME"),
            port=int(os.environ.get("DB_PORT")),
        )
        return conn
    except Error as e:
        print("Database connection failed:", e)
        return None


@app.route('/')
def home():
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        if not username or not email or not password:
            flash("All fields are required!", "danger")
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)

        conn = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor(dictionary=True)  # ✅ same style everywhere

            # Check if email already exists
            cursor.execute("SELECT id FROM userss WHERE email = %s", (email,))
            if cursor.fetchone():
                flash("Email already registered!", "danger")
                return redirect(url_for('register'))

            # Insert new user
            cursor.execute("""
                INSERT INTO userss (username, email, password)
                VALUES (%s, %s, %s)
            """, (username, email, hashed_password))

            conn.commit()
            cursor.close()

            flash("Registration successful! Please login.", "success")
            return redirect(url_for('login'))

        except Exception as e:
            print("Registration Error:", e)
            flash("Something went wrong. Try again.", "danger")
            return redirect(url_for('register'))

        finally:
            if conn:
                conn.close()

    return render_template('register.html')
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        if not email or not password:
            flash("Please enter email and password.", "danger")
            return redirect(url_for('login'))

        conn = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor(dictionary=True)

            cursor.execute("SELECT * FROM userss WHERE email = %s", (email,))
            user = cursor.fetchone()
            cursor.close()

            if user and check_password_hash(user['password'], password):
                session.clear()
                session['loggedin'] = True
                session['id'] = user['id']
                session['username'] = user['username']

                flash("Login successful!", "success")
                return redirect(url_for('dashboard'))
            else:
                flash("Invalid email or password!", "danger")
                return redirect(url_for('login'))

        except Exception as e:
            print("Login Error:", e)
            flash("Login failed. Please try again.", "danger")
            return redirect(url_for('login'))

        finally:
            if conn:
                conn.close()

    return render_template('login.html')

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM userss WHERE email=%s", (email,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        if user:
            session['reset_email'] = email
            return redirect(url_for('reset_password'))
        else:
            flash("Email not found in users table!", "danger")

    return render_template('forgot_password.html')
from werkzeug.security import generate_password_hash

@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    email = session.get('reset_email')

    if not email:
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        new_password = request.form.get('password')
        hashed_password = generate_password_hash(new_password)

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE userss SET password=%s WHERE email=%s",
            (hashed_password, email)
        )
        conn.commit()
        cursor.close()
        conn.close()

        session.pop('reset_email', None)
        flash("Password updated successfully!", "success")
        return redirect(url_for('login'))

    return render_template('reset_password.html')

@app.route('/dashboard')
def dashboard():
    if 'loggedin' not in session or not session.get('id'):
        flash("Please login first to access the dashboard.", "warning")
        return redirect(url_for('login'))

    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute(
            "SELECT username, email FROM userss WHERE id = %s",
            (session['id'],)
        )
        user = cursor.fetchone()
        cursor.close()

        if not user:
            session.clear()
            flash("User not found. Please login again.", "danger")
            return redirect(url_for('login'))

        flash(f"Welcome back, {user['username']}!", "info")
        return render_template('dashboard.html', user=user)

    except Exception as e:
        print("Dashboard Error:", e)
        flash("Something went wrong.", "danger")
        return redirect(url_for('login'))

    finally:
        if conn:
            conn.close()



@app.route('/prediction', methods=['GET', 'POST'])
def prediction():
    if 'loggedin' not in session:
        return redirect(url_for('login'))

    result = None

    if request.method == 'POST':
        try:
            # Get form values
            gender = int(request.form['gender'])
            age = float(request.form['age'])
            hypertension = int(request.form['hypertension'])
            heart_disease = int(request.form['heart_disease'])
            smoking = int(request.form['smoking'])
            bmi = float(request.form['bmi'])
            hba1c = float(request.form['hba1c'])
            glucose = float(request.form['glucose'])

            # Prepare data
            user_data = np.array([[gender, age, hypertension, heart_disease,
                                   smoking, bmi, hba1c, glucose]])
            user_data = scaler.transform(user_data)

            # Predict
            prediction_val = model.predict(user_data)[0]

            result = "⚠️ User has Diabetes" if prediction_val == 1 else "✅ User does NOT have Diabetes"

            # Save in MySQL
            conn = get_db_connection()
            cursor = conn.cursor()
            user_id = session['id']   # logged-in user ka ID

            cursor.execute("""
                       INSERT INTO predictions 
                        (user_id, gender, age, hypertension, heart_disease, smoking, bmi, hba1c, glucose, result)
                         VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        """, (user_id, gender, age, hypertension, heart_disease,
                              smoking, bmi, hba1c, glucose, result))
            conn.commit()
            cursor.close()
            conn.close()

        except Exception as e:
            result = f"Error in prediction: {str(e)}"

    # Fetch user info
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT username, email FROM userss WHERE id=%s", (session['id'],))
    user = cursor.fetchone()
    cursor.close()
    conn.close()

    return render_template('prediction.html', user=user, prediction=result)


@app.route('/suggestion')
def suggestion():
    if 'loggedin' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT username, email FROM userss WHERE id=%s", (session['id'],))
    user = cursor.fetchone()
    cursor.close()
    conn.close()

    return render_template('suggestion.html', user=user)

@app.route('/contactus', methods=['GET', 'POST'])
def contactus():
    if request.method == 'POST':

        # ---------------- GET FORM DATA ----------------
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        subject = request.form.get('subject', '').strip()
        message = request.form.get('message', '').strip()

        # ---------------- BASIC VALIDATION ----------------
        if not name or not email or not subject or not message:
            flash("All fields are required!", "danger")
            return redirect(url_for('contactus'))

        conn = None
        cursor = None

        try:
            # ---------------- DATABASE INSERT ----------------
            conn = get_db_connection()
            cursor = conn.cursor()

            cursor.execute("""
                INSERT INTO contact_messages (name, email, subject, message)
                VALUES (%s, %s, %s, %s)
            """, (name, email, subject, message))

            conn.commit()

            # ---------------- EMAIL TO ADMIN ----------------
            admin_subject = "New Contact Form Message"
            admin_message = f"""
            <h3>New Contact Message</h3>
            <p><b>Name:</b> {name}</p>
            <p><b>Email:</b> {email}</p>
            <p><b>Subject:</b> {subject}</p>
            <p><b>Message:</b><br>{message}</p>
            """

            send_email("dpshealth26@gmail.com", admin_subject, admin_message)

            # ---------------- EMAIL TO USER ----------------
            user_subject = "We received your message"
            user_message = f"""
            <h3 style="color:#5b21b6;">DSP Health</h3>
            <p>Hi {name},</p>
            <p>Thank you for contacting us. We will reply shortly.</p>
            """

            send_email(email, user_subject, user_message)

            flash("Your message has been sent successfully!", "success")
            return redirect(url_for('contactus'))

        except Exception as e:
            if conn:
                conn.rollback()
            print("Contact Form Error:", e)
            flash("Something went wrong. Please try again.", "danger")
            return redirect(url_for('contactus'))

        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()

    # ✅ GET request
    return render_template('contactus.html')

# ================= PROFILE PAGE =================
@app.route('/profile')
def profile():
    if 'loggedin' not in session or 'id' not in session:
        return redirect(url_for('login'))

    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # ✅ Email included + correct table name
        cursor.execute(
            "SELECT username, email FROM userss WHERE id=%s",
        (session['id'],)
          
        )
        user = cursor.fetchone()

        cursor.close()
        conn.close()

        # ✅ If user not found (safety check)
        if not user:
            session.clear()
            return redirect(url_for('login'))

        return render_template('profile.html', user=user)

    except Exception as e:
        print("Profile Error:", e)
        return "Something went wrong", 500
# ================= LOGOUT =================
@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out successfully", "success")
    return redirect(url_for('login'))





# ================= ADMIN LOGIN =================
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    error = None

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        try:
            conn = get_db_connection()
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT * FROM admins WHERE username=%s", (username,))
            admin = cursor.fetchone()
            cursor.close()
            conn.close()

            if admin and admin['password'] == password:
                session['admin_logged_in'] = True
                session['admin_username'] = admin['username']
                flash("Welcome to Admin Panel!", "success")
                return redirect(url_for('admin_dashboard'))
            else:
                error = "Invalid username or password"

        except Exception as e:
            error = "Database Error: " + str(e)

    return render_template('admin/admin_login.html', error=error)


# ================= ADMIN REQUIRED DECORATOR =================
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_logged_in' not in session:
            flash("Please login as admin first", "danger")
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function
@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    session.pop('admin_username', None)
    flash("Logged out successfully", "success")
    return redirect(url_for('admin_login'))


# ================= ADMIN DASHBOARD =================
@app.route('/admin/dashboard')
def admin_dashboard():
    if 'admin_logged_in' not in session:
        return redirect(url_for('admin_login'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Total Users (UPDATED TABLE NAME)
    cursor.execute("SELECT COUNT(*) AS total_users FROM userss")
    total_users = cursor.fetchone()['total_users']

    # Total Messages
    cursor.execute("SELECT COUNT(*) AS total_messages FROM contact_messages")
    total_messages = cursor.fetchone()['total_messages']

    cursor.execute("""
        SELECT 
            (SELECT COUNT(*) FROM predictions) +
            (SELECT COUNT(*) FROM finger_predictions)
            AS total_prediction
    """)
    total_prediction = cursor.fetchone()['total_prediction']

    cursor.close()
    conn.close()

    return render_template(
        'admin/admin_dashboard.html',
        total_users=total_users,
        total_messages=total_messages,
        total_prediction=total_prediction
    )


# ================= VIEW USERS =================
@app.route('/admin/users')
@admin_required
def admin_users():

    search = request.args.get('search', '').strip()
    sort = request.args.get('sort', 'latest')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Base Query
    query = "SELECT id, username, email FROM userss"
    conditions = []
    values = []

    # 🔎 Search Filter
    if search:
        conditions.append("(username LIKE %s OR email LIKE %s)")
        values.extend([f"%{search}%", f"%{search}%"])

    if conditions:
        query += " WHERE " + " AND ".join(conditions)

    # 🔤 Sorting
    if sort == "az":
        query += " ORDER BY username ASC"
    elif sort == "za":
        query += " ORDER BY username DESC"
    else:
        query += " ORDER BY id DESC"

    cursor.execute(query, values)
    users = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template(
        'admin/admin_users.html',
        users=users,
        search=search,
        sort=sort
    )
from flask import session

@app.route('/admin/delete-user/<int:id>', methods=['POST'])
@admin_required
def delete_user(id):

    if id == session.get("admin_id"):
        flash("You cannot delete yourself!", "danger")
        return redirect(url_for('admin_users'))

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("DELETE FROM userss WHERE id = %s", (id,))
    conn.commit()

    cursor.close()
    conn.close()

    flash("User deleted successfully!", "success")
    return redirect(url_for('admin_users'))
# ============= Admin messages ====================
@app.route('/admin/messages')
@admin_required
def admin_messages():

    search = request.args.get('search', '').strip()
    sort = request.args.get('sort', 'latest')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    query = """
        SELECT 
            id, 
            name, 
            email, 
            subject, 
            message, 
            status, 
            is_read, 
            created_at
        FROM contact_messages
    """

    conditions = []
    values = []

    # 🔎 SEARCH FILTER
    if search:
        conditions.append("""
            (name LIKE %s OR email LIKE %s OR subject LIKE %s)
        """)
        values.extend([f"%{search}%", f"%{search}%", f"%{search}%"])

    if conditions:
        query += " WHERE " + " AND ".join(conditions)

    # 🎯 SORTING LOGIC
    # Unread first (0), then pending first
    query += """
        ORDER BY 
            is_read ASC,
            CASE 
                WHEN status = 'pending' THEN 0
                WHEN status = 'resolved' THEN 1
                ELSE 2
            END
    """

    if sort == "oldest":
        query += ", created_at ASC"
    else:
        query += ", created_at DESC"

    cursor.execute(query, values)
    messages = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template(
        'admin/admin_messages.html',
        messages=messages,
        search=search,
        sort=sort
    )
@app.route('/admin/message-read/<int:id>')
@admin_required
def mark_message_read(id):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE contact_messages
        SET is_read = 1
        WHERE id = %s
    """, (id,))

    conn.commit()
    cursor.close()
    conn.close()

    return redirect(url_for('admin_messages'))
@app.route('/admin/delete-message/<int:id>', methods=['POST'])
@admin_required
def delete_message(id):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "DELETE FROM contact_messages WHERE id = %s",
        (id,)
    )

    conn.commit()
    cursor.close()
    conn.close()

    flash("Message deleted successfully", "success")
    return redirect(url_for('admin_messages'))
# ----------------------------
# Admin Prediction Page
# ----------------------------
# ----------------------------
# Admin Prediction Page
# ----------------------------
@app.route('/admin/prediction')
@admin_required
def admin_prediction():
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        query = """
        SELECT 
            p.id,
            p.gender,
            p.age,
            p.hypertension,
            p.heart_disease,
            p.smoking,
            p.bmi,
            p.hba1c,
            p.glucose,
            p.result,
            p.created_at,
            u.email
        FROM predictions p
        LEFT JOIN userss u ON u.id = p.user_id
        ORDER BY p.created_at DESC
        """

        cursor.execute(query)
        predictions = cursor.fetchall()
        total_count = len(predictions)

        cursor.close()
        conn.close()

        return render_template(
            'admin/admin_prediction.html',
            predictions=predictions,
            total_count=total_count
        )

    except Exception as e:
        print("ERROR IN ADMIN PREDICTION:", e)
        return "Internal Server Error"
# ----------------------------
# Delete Prediction
# ----------------------------
# ----------------------------
# Delete Prediction
# ----------------------------
@app.route('/admin/prediction/delete/<int:id>', methods=['POST'])
@admin_required
def delete_prediction(id):
    conn = None
    cursor = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Check if record exists first
        cursor.execute("SELECT id FROM predictions WHERE id = %s", (id,))
        prediction = cursor.fetchone()

        if not prediction:
            flash("Prediction not found.", "danger")
            return redirect(url_for('admin_prediction'))

        # Delete record
        cursor.execute("DELETE FROM predictions WHERE id = %s", (id,))
        conn.commit()

        flash("Prediction deleted successfully.", "success")
        return redirect(url_for('admin_prediction'))

    except Exception as e:
        print("DELETE ERROR:", e)
        flash("Something went wrong while deleting.", "danger")
        return redirect(url_for('admin_prediction'))

    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.route('/admin/user-analytics')
@admin_required
def admin_user_analytics():

    search = request.args.get('search', '').strip()
    sort = request.args.get('sort', 'az')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    query = """
        SELECT id, username, email
        FROM userss
    """

    conditions = []
    values = []

    # 🔎 Search Filter
    if search:
        conditions.append("(username LIKE %s OR email LIKE %s)")
        values.extend([f"%{search}%", f"%{search}%"])

    if conditions:
        query += " WHERE " + " AND ".join(conditions)

    # 🎯 Sorting (created_at removed)
    if sort == "az":
        query += " ORDER BY username ASC"
    elif sort == "za":
        query += " ORDER BY username DESC"
    else:
        query += " ORDER BY id DESC"   # fallback latest by id

    cursor.execute(query, values)
    users = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template(
        'admin/admin_user_analytics.html',
        users=users,
        search=search,
        sort=sort
    )
@app.route('/admin/user-analytics/<int:user_id>')
@admin_required
def admin_user_detail(user_id):

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # =========================
        # 1️⃣ USER INFO
        # =========================
        cursor.execute("""
            SELECT id, username, email
            FROM userss
            WHERE id = %s
        """, (user_id,))
        user = cursor.fetchone()

        if not user:
            flash("User not found", "danger")
            return redirect(url_for('admin_user_analytics'))

        # =========================
        # 2️⃣ USER MESSAGES
        # =========================
        cursor.execute("""
            SELECT id, name, email, subject,
                   message, created_at,
                   is_read, status
            FROM contact_messages
            WHERE email = %s
            ORDER BY created_at DESC
        """, (user['email'],))

        messages_list = cursor.fetchall()
        total_messages = len(messages_list)

        # =========================
        # 3️⃣ CLINICAL PREDICTIONS
        # =========================
        cursor.execute("""
            SELECT id, gender, age, hypertension,
                   heart_disease, smoking,
                   bmi, hba1c, glucose,
                   result, created_at, user_id
            FROM predictions
            WHERE user_id = %s
            ORDER BY created_at DESC
        """, (user_id,))

        clinical_list = cursor.fetchall()
        total_clinical = len(clinical_list)

        # =========================
        # 4️⃣ FINGER PREDICTIONS
        # =========================
        cursor.execute("""
            SELECT id, gender, age, smoking,
                   bmi, hba1c, glucose,
                   fingerprint_image,
                   ridge_density, complexity_score,
                   pattern_type,
                   result, created_at, user_id
            FROM finger_predictions
            WHERE user_id = %s
            ORDER BY created_at DESC
        """, (user_id,))

        finger_list = cursor.fetchall()
        total_finger = len(finger_list)

        # =========================
        # 5️⃣ VALUE MAPPING
        # =========================
        def gender_label(val):
            return "Male" if val == 1 else "Female" if val == 0 else "Unknown"

        def yes_no(val):
            return "Yes" if val == 1 else "No"

        def smoking_label(val):
            if val == 0:
                return "Non-Smoker"
            elif val == 1:
                return "Former Smoker"
            elif val == 2:
                return "Current Smoker"
            return "Unknown"

        def pattern_label(val):
            if val == 0:
                return "Loop"
            elif val == 1:
                return "Whorl"
            elif val == 2:
                return "Arch"
            return "Unknown"

        # Apply mapping to clinical
        for c in clinical_list:
            c['gender_label'] = gender_label(c.get('gender'))
            c['hypertension_label'] = yes_no(c.get('hypertension'))
            c['heart_label'] = yes_no(c.get('heart_disease'))
            c['smoking_label'] = smoking_label(c.get('smoking'))
            c['type'] = "Report"

        # Apply mapping to finger
        for f in finger_list:
            f['gender_label'] = gender_label(f.get('gender'))
            f['smoking_label'] = smoking_label(f.get('smoking'))
            f['pattern_label'] = pattern_label(f.get('pattern_type'))
            f['type'] = "Finger"

        # =========================
        # 6️⃣ COMBINED DATA
        # =========================
        total_predictions = total_clinical + total_finger

        combined_list = clinical_list + finger_list
        combined_list = sorted(
            combined_list,
            key=lambda x: x.get('created_at'),
            reverse=True
        )

        # =========================
        # 7️⃣ GRAPH DATA
        # =========================
        cursor.execute("""
            SELECT day, COUNT(*) as count FROM (
                SELECT DATE(created_at) as day
                FROM predictions
                WHERE user_id = %s

                UNION ALL

                SELECT DATE(created_at) as day
                FROM finger_predictions
                WHERE user_id = %s
            ) AS combined
            GROUP BY day
            ORDER BY day ASC
        """, (user_id, user_id))

        graph_data = cursor.fetchall()

        return render_template(
            'admin/admin_user_detail.html',
            user=user,
            messages=total_messages,
            clinical=total_clinical,
            finger=total_finger,
            total_predictions=total_predictions,
            messages_list=messages_list,
            clinical_list=clinical_list,
            finger_list=finger_list,
            combined_list=combined_list,
            graph_data=graph_data
        )

    except Exception as e:
        print("DATABASE ERROR:", e)
        flash(f"Database Error: {str(e)}", "danger")
        return redirect(url_for('admin_user_analytics'))

    finally:
        cursor.close()
        conn.close()


@app.route('/report/download/<int:user_id>')
def download_report(user_id):

    # --------- LOGIN CHECK ----------
    if 'loggedin' not in session:
        return redirect(url_for('login'))

    # Optional: Prevent downloading other user's report
    if session.get('id') != user_id:
        flash("Unauthorized access", "danger")
        return redirect(url_for('dashboard'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # ---------- USER INFO ----------
        cursor.execute(
            "SELECT username, email FROM userss WHERE id = %s",
            (user_id,)
        )
        user = cursor.fetchone()

        # ---------- LATEST PREDICTION ----------
        cursor.execute("""
            SELECT *
            FROM predictions
            WHERE user_id = %s
            ORDER BY created_at DESC
            LIMIT 1
        """, (user_id,))
        pred = cursor.fetchone()

        if not user or not pred:
            flash("No report data found", "warning")
            return redirect(url_for('dashboard'))

    finally:
        cursor.close()
        conn.close()

    # ---------- VALUE MAPPING ----------
    def yes_no(val):
        return "Yes" if val == 1 else "No"

    def smoking_label(val):
        if val == 0:
            return "Non-Smoker"
        elif val == 1:
            return "Former Smoker"
        elif val == 2:
            return "Current Smoker"
        return "Unknown"

    # ---------- PDF SETUP ----------
    buffer = io.BytesIO()
    pdf = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )

    styles = getSampleStyleSheet()

    styles.add(ParagraphStyle(
        name='HeaderTitle',
        fontSize=20,
        textColor=colors.HexColor("#065f46"),
        spaceAfter=12,
        fontName='Helvetica-Bold'
    ))

    styles.add(ParagraphStyle(
        name='SubTitle',
        fontSize=12,
        textColor=colors.grey,
        spaceAfter=20
    ))

    elements = []

    # ---------- HEADER ----------
    elements.append(Paragraph(
        "Diabetes Prediction Medical Report",
        styles['HeaderTitle']
    ))
    elements.append(Paragraph(
        "Generated using AI & Clinical Analytics",
        styles['SubTitle']
    ))
    elements.append(Spacer(1, 20))

    # ---------- USER INFO ----------
    report_date = (
        pred['created_at'].strftime("%d-%b-%Y %H:%M")
        if hasattr(pred['created_at'], 'strftime')
        else pred['created_at']
    )

    patient_info = f"""
    <b>Patient Name:</b> {user.get('username')}<br/>
    <b>Email:</b> {user.get('email')}<br/>
    <b>Report Date:</b> {report_date}<br/>
    <b>Assessment Type:</b> Report-Based Diabetes Prediction
    """

    elements.append(Paragraph(patient_info, styles['Normal']))
    elements.append(Spacer(1, 25))

    # ---------- MEDICAL DATA TABLE ----------
    data_table = [
        ["Clinical Metric", "Observed Value"],
        ["Age", pred.get("age")],
        ["BMI", pred.get("bmi")],
        ["Glucose", pred.get("glucose")],
        ["HbA1c", pred.get("hba1c")],
        ["Hypertension", yes_no(pred.get("hypertension"))],
        ["Heart Disease", yes_no(pred.get("heart_disease"))],
        ["Smoking", smoking_label(pred.get("smoking"))],
        ["Prediction Result", pred.get("result")],
    ]

    table = Table(data_table, colWidths=[220, 240])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#064e3b")),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONT', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('GRID', (0, 0), (-1, -1), 0.6, colors.grey),
        ('BACKGROUND', (0, 1), (-1, -1), colors.whitesmoke),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
    ]))

    elements.append(table)
    elements.append(Spacer(1, 30))

    # ---------- MEDICAL NOTE ----------
    note_text = """
    <b>Clinical Interpretation:</b><br/>
    This assessment uses predictive analytics based on clinical parameters 
    to estimate diabetes risk. This report is for informational purposes only 
    and does not replace professional medical advice.
    """

    elements.append(Paragraph(note_text, styles['Normal']))
    elements.append(Spacer(1, 25))

    elements.append(Paragraph(
        "<b>Authorized Medical Officer</b><br/>Dr. AI Clinical System<br/>DSP Health",
        styles['Normal']
    ))

    elements.append(Spacer(1, 40))

    elements.append(Paragraph(
        "Signature: _______________________________",
        styles['Normal']
    ))

    elements.append(Spacer(1, 25))

    elements.append(Paragraph(
        "DSP Health AI • Secure Medical Intelligence Platform",
        styles['Italic']
    ))

    # ---------- BUILD PDF ----------
    pdf.build(elements)
    buffer.seek(0)

    return send_file(
        buffer,
        as_attachment=True,
        download_name=f"{user['username']}_diabetes_report.pdf",
        mimetype="application/pdf"
    )
# ---------------- LOAD FINGERPRINT MODEL ----------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

FINGER_MODEL_PATH = os.path.join(
    BASE_DIR,
    'models',
    'diabetes_fingerprint_model.pkl'
)

finger_model = joblib.load(FINGER_MODEL_PATH)


@app.route('/finger_prediction', methods=['GET', 'POST'])
def finger_prediction():

    if 'loggedin' not in session:
        return redirect(url_for('login'))

    # ================= GET =================
    if request.method == 'GET':
        return render_template('finger_prediction.html')

    try:
        # ================= FORM DATA =================
        gender   = int(request.form.get('gender', 0))
        age      = int(request.form.get('age', 0))
        smoking  = int(request.form.get('smoking', 0))
        bmi      = float(request.form.get('bmi', 0))
        hba1c    = float(request.form.get('hba1c', 0))
        glucose  = float(request.form.get('glucose', 0))

        # ================= IMAGE =================
        file = request.files.get('fingerprint')
        if not file or file.filename == '':
            return "Fingerprint image is required", 400

        upload_folder = app.config.get(
            'UPLOAD_FOLDER',
            'static/uploads/fingerprints'
        )
        os.makedirs(upload_folder, exist_ok=True)

        filename = f"{uuid.uuid4().hex}_{secure_filename(file.filename)}"
        fingerprint_image = os.path.join(upload_folder, filename)
        file.save(fingerprint_image)

        # ================= FEATURE EXTRACTION =================
        fp = extract_fingerprint_features(fingerprint_image)

        ridge_density    = float(fp['ridge_density'])
        complexity_score = float(fp['complexity_score'])
        pattern_type     = int(fp['pattern_type'])

        # ================= MODEL INPUT =================
        model_input = np.array([[
            gender,
            age,
            smoking,
            bmi,
            hba1c,
            glucose,
            ridge_density,
            complexity_score,
            pattern_type
        ]])

        pred = int(finger_model.predict(model_input)[0])

        result_map = {
            0: "LOW DIABETES RISK",
            1: "MEDIUM DIABETES RISK",
            2: "HIGH DIABETES RISK"
        }
        result = result_map.get(pred, "UNKNOWN")

        # ================= DATABASE =================
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO finger_predictions
            (user_id, gender, age, smoking, bmi, hba1c, glucose,
             ridge_density, complexity_score, pattern_type,
             result, fingerprint_image)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """, (
            session['id'],   # Make sure this exists in login session
            gender,
            age,
            smoking,
            bmi,
            hba1c,
            glucose,
            ridge_density,
            complexity_score,
            pattern_type,
            result,
            fingerprint_image
        ))

        conn.commit()
        cursor.close()
        conn.close()

        return render_template(
            'finger_prediction.html',
            finger_prediction=result
        )

    except Exception as e:
        print("ERROR IN FINGER PREDICTION:", str(e))
        return "Internal Server Error - Check logs", 500
@app.route('/download_finger_report/<int:user_id>')
def download_finger_report(user_id):

    if 'loggedin' not in session:
        return redirect(url_for('login'))

    # Optional: prevent other users downloading someone else's report
    if session.get('role') != 'admin' and session.get('id') != user_id:
        return "Unauthorized access", 403

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT fp.*, u.username, u.email
        FROM finger_predictions fp
        JOIN userss u ON u.id = fp.user_id
        WHERE fp.user_id = %s
        ORDER BY fp.created_at DESC
        LIMIT 1
    """, (user_id,))

    report = cursor.fetchone()

    cursor.close()
    conn.close()

    if not report:
        return "No fingerprint report found", 404

    # ---------------- PDF SETUP ----------------
    buffer = io.BytesIO()
    pdf = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )

    styles = getSampleStyleSheet()
    elements = []

    # ---------------- CUSTOM STYLES ----------------
    styles.add(ParagraphStyle(
        name='HeaderTitle',
        fontSize=20,
        textColor=colors.HexColor("#065f46"),
        spaceAfter=12,
        fontName='Helvetica-Bold'
    ))

    styles.add(ParagraphStyle(
        name='SubTitle',
        fontSize=11,
        textColor=colors.grey,
        spaceAfter=20
    ))

    # ---------------- HEADER ----------------
    elements.append(Paragraph(
        "Fingerprint-Based Diabetes Risk Medical Report",
        styles['HeaderTitle']
    ))

    elements.append(Paragraph(
        "Generated using Advanced Biometric AI & Clinical Analytics",
        styles['SubTitle']
    ))

    elements.append(Spacer(1, 20))

    # ---------------- PATIENT INFO ----------------
    patient_info = f"""
    <b>Patient Name:</b> {report.get('username','N/A')}<br/>
    <b>Email:</b> {report.get('email','N/A')}<br/>
    <b>Report Date:</b> {report.get('created_at','N/A')}<br/>
    <b>Assessment Type:</b> Fingerprint-Based AI Diagnosis
    """

    elements.append(Paragraph(patient_info, styles['Normal']))
    elements.append(Spacer(1, 25))

    # ---------------- MEDICAL DATA TABLE ----------------
    data_table = [
        ["Clinical Metric", "Observed Value"],
        ["Age", report.get("age", "N/A")],
        ["BMI", report.get("bmi", "N/A")],
        ["Glucose Level", report.get("glucose", "N/A")],
        ["HbA1c", report.get("hba1c", "N/A")],
        ["Smoking Status", report.get("smoking_label", report.get("smoking", "N/A"))],
        ["Ridge Density", report.get("ridge_density", "N/A")],
        ["Pattern Complexity", report.get("complexity_score", "N/A")],
        ["Fingerprint Pattern Type", report.get("pattern_label", report.get("pattern_type", "N/A"))],
        ["Final Risk Assessment", report.get("result", "N/A")],
    ]

    table = Table(data_table, colWidths=[220, 240])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#064e3b")),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONT', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('GRID', (0, 0), (-1, -1), 0.6, colors.grey),
        ('BACKGROUND', (0, 1), (-1, -1), colors.whitesmoke),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
    ]))

    elements.append(table)
    elements.append(Spacer(1, 30))

    # ---------------- MEDICAL NOTE ----------------
    elements.append(Paragraph(
        """
        <b>Clinical Interpretation:</b><br/>
        This fingerprint-based assessment combines biometric ridge analysis 
        with metabolic indicators to estimate diabetes risk probability.
        This report is for preventive screening purposes only and does not 
        replace professional medical consultation.
        """,
        styles['Normal']
    ))

    elements.append(Spacer(1, 30))

    # ---------------- SIGNATURE ----------------
    elements.append(Paragraph(
        "<b>Authorized Medical Officer</b><br/>Dr. AI Clinical System<br/>DSP Health",
        styles['Normal']
    ))

    elements.append(Spacer(1, 40))

    elements.append(Paragraph(
        "Signature: ___________________________",
        styles['Normal']
    ))

    elements.append(Spacer(1, 30))

    # ---------------- FOOTER ----------------
    elements.append(Paragraph(
        "DSP Health AI • Secure Medical Intelligence Platform",
        styles['Italic']
    ))

    # ---------------- BUILD PDF ----------------
    pdf.build(elements)
    buffer.seek(0)

    return send_file(
        buffer,
        as_attachment=True,
        download_name="Fingerprint_Diabetes_Medical_Report.pdf",
        mimetype="application/pdf"
    )
@app.route('/download_current_report/<int:user_id>')
def download_current_report(user_id):
    if 'loggedin' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Check latest prediction type
    cursor.execute("""
        SELECT 'finger' as type, created_at
        FROM finger_predictions
        WHERE user_id=%s
        ORDER BY created_at DESC
        LIMIT 1
    """, (user_id,))
    finger_latest = cursor.fetchone()

    cursor.execute("""
        SELECT 'diabetes' as type, created_at
        FROM predictions
        WHERE user_id=%s
        ORDER BY created_at DESC
        LIMIT 1
    """, (user_id,))
    diabetes_latest = cursor.fetchone()

    cursor.close()
    conn.close()

    # Decide latest
    if finger_latest and diabetes_latest:
        latest = finger_latest if finger_latest['created_at'] > diabetes_latest['created_at'] else diabetes_latest
    else:
        latest = finger_latest or diabetes_latest

    if not latest:
        flash("No report found", "warning")
        return redirect(url_for('dashboard'))

    # Redirect to proper PDF generator
    if latest['type'] == 'finger':
        return redirect(url_for('download_finger_report', user_id=user_id))
    else:
        return redirect(url_for('download_report', user_id=user_id))

# ================= ADMIN FINGER PREDICTIONS =================

@app.route('/admin/finger-predictions')
@admin_required
def admin_finger_predictions():

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT fp.*, u.email
        FROM finger_predictions fp
        JOIN userss u ON u.id = fp.user_id
        ORDER BY fp.created_at DESC
    """)

    predictions = cursor.fetchall()
    total_count = len(predictions)

    cursor.close()
    conn.close()

    return render_template(
        'admin/admin_finger_predictions.html',
        predictions=predictions,
        total_count=total_count
    )


# ================= DELETE =================

@app.route('/admin/finger/delete/<int:id>', methods=['POST'])
@admin_required
def delete_finger_prediction(id):

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "DELETE FROM finger_predictions WHERE id=%s",
        (id,)
    )

    conn.commit()
    cursor.close()
    conn.close()

    flash("Fingerprint prediction deleted successfully.", "success")
    return redirect(url_for('admin_finger_predictions'))

@app.route('/admin/export-user-report/<int:user_id>')
@admin_required
def export_user_activity_pdf(user_id):

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # ================= USER =================
        cursor.execute("SELECT username, email FROM userss WHERE id = %s", (user_id,))
        user = cursor.fetchone()

        if not user:
            flash("User not found", "danger")
            return redirect(url_for('admin_user_analytics'))

        # ================= CLINICAL =================
        cursor.execute("""
            SELECT result, age, bmi, hba1c, glucose,
                   hypertension, heart_disease,
                   smoking, gender, created_at
            FROM predictions
            WHERE user_id = %s
            ORDER BY created_at DESC
        """, (user_id,))
        clinical_list = cursor.fetchall()

        # ================= FINGER =================
        cursor.execute("""
            SELECT result, age, bmi, hba1c, glucose,
                   smoking, gender,
                   ridge_density, complexity_score,
                   pattern_type, created_at
            FROM finger_predictions
            WHERE user_id = %s
            ORDER BY created_at DESC
        """, (user_id,))
        finger_list = cursor.fetchall()

        cursor.close()
        conn.close()

        # ================= DAYWISE CALCULATION =================
        from collections import defaultdict
        daywise = defaultdict(int)

        for c in clinical_list:
            day = c["created_at"].strftime("%Y-%m-%d")
            daywise[day] += 1

        for f in finger_list:
            day = f["created_at"].strftime("%Y-%m-%d")
            daywise[day] += 1

        # ================= HELPERS =================
        def yes_no(val):
            return "Yes" if val == 1 else "No"

        def gender_label(val):
            return "Male" if val == 1 else "Female" if val == 0 else "Unknown"

        def pattern_label(val):
            return {1: "Arch", 2: "Loop", 3: "Whorl"}.get(val, "Unknown")

        # ================= PDF =================
        buffer = BytesIO()
        pdf = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            rightMargin=40,
            leftMargin=40,
            topMargin=40,
            bottomMargin=40
        )

        styles = getSampleStyleSheet()
        elements = []

        styles.add(ParagraphStyle(
            name='HeaderTitle',
            fontSize=22,
            textColor=colors.HexColor("#065f46"),
            spaceAfter=12,
            fontName='Helvetica-Bold'
        ))

        styles.add(ParagraphStyle(
            name='SubTitle',
            fontSize=11,
            textColor=colors.grey,
            spaceAfter=20
        ))

        # ================= HEADER =================
        elements.append(Paragraph("DPS Medical Report", styles['HeaderTitle']))
        elements.append(Paragraph(
            "Comprehensive AI-Based Report & Biometric Assessment",
            styles['SubTitle']
        ))
        elements.append(Spacer(1, 20))

        # ================= PATIENT INFO =================
        patient_info = f"""
        <b>Patient Name:</b> {user['username']}<br/>
        <b>Email:</b> {user['email']}<br/>
        <b>Generated On:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br/>
        <b>Assessment Type:</b> Combined Report + Fingerprint AI Diagnosis
        """

        elements.append(Paragraph(patient_info, styles['Normal']))
        elements.append(Spacer(1, 25))

        # ==========================================================
        # DAYWISE SUMMARY SECTION
        # ==========================================================
        elements.append(Paragraph("<b>Daywise Prediction Summary</b>", styles['Heading2']))
        elements.append(Spacer(1, 10))

        table_data = [["Date", "Total Predictions"]]

        for day, count in sorted(daywise.items(), reverse=True):
            table_data.append([day, str(count)])

        if len(table_data) == 1:
            table_data.append(["No Data", "0"])

        day_table = Table(table_data, colWidths=[220, 220])
        day_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0),colors.HexColor("#064e3b")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONT', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 0.6, colors.grey),
            ('BACKGROUND', (0, 1), (-1, -1), colors.whitesmoke),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
        ]))

        elements.append(day_table)
        elements.append(Spacer(1, 30))

        # ==========================================================
        # CLINICAL SECTION
        # ==========================================================
        elements.append(Paragraph("<b>Report AI Predictions</b>", styles['Heading2']))
        elements.append(Spacer(1, 15))

        for c in clinical_list:
            data = [
                ["Report Metric", "Observed Value"],
                ["Date", str(c["created_at"])],
                ["Result", c["result"]],
                ["Age", c["age"]],
                ["BMI", c["bmi"]],
                ["HbA1c", c["hba1c"]],
                ["Glucose", c["glucose"]],
                ["Hypertension", yes_no(c["hypertension"])],
                ["Heart Disease", yes_no(c["heart_disease"])],
                ["Smoking", yes_no(c["smoking"])],
                ["Gender", gender_label(c["gender"])]
            ]

            table = Table(data, colWidths=[220, 240])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#064e3b")),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONT', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('GRID', (0, 0), (-1, -1), 0.6, colors.grey),
                ('BACKGROUND', (0, 1), (-1, -1), colors.whitesmoke),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                ('TOPPADDING', (0, 0), (-1, -1), 8),
            ]))

            elements.append(table)
            elements.append(Spacer(1, 25))

        # ==========================================================
        # FINGER SECTION
        # ==========================================================
        elements.append(Paragraph("<b>Fingerprint AI Predictions</b>", styles['Heading2']))
        elements.append(Spacer(1, 15))

        for f in finger_list:
            data = [
                ["Reports Metric", "Observed Value"],
                ["Date", str(f["created_at"])],
                ["Result", f["result"]],
                ["Age", f["age"]],
                ["BMI", f["bmi"]],
                ["HbA1c", f["hba1c"]],
                ["Glucose", f["glucose"]],
                ["Smoking", yes_no(f["smoking"])],
                ["Gender", gender_label(f["gender"])],
                ["Ridge Density", f["ridge_density"]],
                ["Pattern Complexity", f["complexity_score"]],
                ["Fingerprint Pattern", pattern_label(f["pattern_type"])]
            ]

            table = Table(data, colWidths=[220, 240])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#064e3b")),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONT', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('GRID', (0, 0), (-1, -1), 0.6, colors.grey),
                ('BACKGROUND', (0, 1), (-1, -1), colors.whitesmoke),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                ('TOPPADDING', (0, 0), (-1, -1), 8),
            ]))

            elements.append(table)
            elements.append(Spacer(1, 25))

        # ================= DISCLAIMER =================
        elements.append(Paragraph("""
        <b>Clinical Interpretation:</b><br/>
        This AI-generated report combines metabolic indicators and fingerprint ridge analysis
        to assess diabetes risk probability.
        This report is for screening purposes only and does not replace certified medical diagnosis.
        """, styles['Normal']))

        elements.append(Spacer(1, 40))

        elements.append(Paragraph(
            "<b>Authorized Medical Officer</b><br/>Dr. AI Clinical System<br/>DPS Health",
            styles['Normal']
        ))

        elements.append(Spacer(1, 30))
        elements.append(Paragraph("Signature: ___________________________", styles['Normal']))
        elements.append(Spacer(1, 20))
        elements.append(Paragraph(
            "DPS Health AI • Secure Medical Intelligence Platform",
            styles['Italic']
        ))

        # ================= BUILD PDF =================
        pdf.build(elements)
        buffer.seek(0)

        return send_file(
            buffer,
            as_attachment=True,
            download_name="DPS_Medical_Report.pdf",
            mimetype="application/pdf"
        )

    except Exception as e:
        print("PDF ERROR:", e)
        flash("Failed to generate PDF", "danger")
        return redirect(url_for('admin_user_analytics'))

@app.route('/admin/download/finger-report/<int:user_id>')
@admin_required
def admin_download_finger_report(user_id):

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT fp.*, u.username, u.email
        FROM finger_predictions fp
        JOIN userss u ON u.id = fp.user_id
        WHERE fp.user_id = %s
        ORDER BY fp.created_at DESC
        LIMIT 1
    """, (user_id,))

    report = cursor.fetchone()
    cursor.close()
    conn.close()

    if not report:
        flash("No fingerprint report found for this user.", "warning")
        return redirect(url_for('admin_user_analytics'))

    # -------- SAFE HELPER --------
    def safe(val):
        return val if val not in (None, "", "NULL") else "N/A"

    report_date = report['created_at'].strftime("%d-%b-%Y %H:%M") \
        if hasattr(report['created_at'], 'strftime') else report['created_at']

    # -------- PDF SETUP --------
    buffer = io.BytesIO()
    pdf = SimpleDocTemplate(buffer, pagesize=A4,
                            rightMargin=40, leftMargin=40,
                            topMargin=40, bottomMargin=40)

    styles = getSampleStyleSheet()
    elements = []

    styles.add(ParagraphStyle(
        name='MainTitle',
        fontSize=20,
        textColor=colors.HexColor("#064e3b"),
        fontName='Helvetica-Bold',
        spaceAfter=10
    ))

    styles.add(ParagraphStyle(
        name='SubTitle',
        fontSize=11,
        textColor=colors.grey,
        spaceAfter=20
    ))

    # -------- HEADER --------
    elements.append(Paragraph("Fingerprint-Based Diabetes Risk Report", styles['MainTitle']))
    elements.append(Paragraph("DSP Health AI Clinical Intelligence System", styles['SubTitle']))
    elements.append(Spacer(1, 20))

    # -------- PATIENT INFO --------
    patient_info = f"""
    <b>Patient Name:</b> {safe(report['username'])}<br/>
    <b>Email:</b> {safe(report['email'])}<br/>
    <b>Report Date:</b> {report_date}<br/>
    <b>Assessment Type:</b> Fingerprint Biometric Analysis
    """

    elements.append(Paragraph(patient_info, styles['Normal']))
    elements.append(Spacer(1, 25))

    # -------- TABLE DATA --------
    data = [
        ["Clinical Metric", "Observed Value"],
        ["Age", safe(report.get("age"))],
        ["BMI", safe(report.get("bmi"))],
        ["Glucose Level", safe(report.get("glucose"))],
        ["HbA1c", safe(report.get("hba1c"))],
        ["Smoking Status", safe(report.get("smoking"))],
        ["Ridge Density", safe(report.get("ridge_density"))],
        ["Pattern Complexity", safe(report.get("complexity_score"))],
        ["Fingerprint Pattern", safe(report.get("pattern_type"))],
        ["Final Risk Assessment", safe(report.get("result"))],
    ]

    table = Table(data, colWidths=[220, 240])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#065f46")),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('GRID', (0, 0), (-1, -1), 0.6, colors.grey),
        ('BACKGROUND', (0, 1), (-1, -1), colors.whitesmoke),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
    ]))

    elements.append(table)
    elements.append(Spacer(1, 30))

    # -------- INTERPRETATION --------
    elements.append(Paragraph("""
    <b>Clinical Interpretation:</b><br/>
    This fingerprint-based biometric assessment is generated using
    AI-driven ridge density and metabolic correlation algorithms.
    It is intended for early screening purposes only and does not
    replace professional medical diagnosis.
    """, styles['Normal']))

    elements.append(Spacer(1, 30))
    elements.append(Paragraph("<b>Authorized Medical Officer</b><br/>Dr. AI Clinical System<br/>DSP Health", styles['Normal']))
    elements.append(Spacer(1, 40))
    elements.append(Paragraph("Signature: _______________________________", styles['Normal']))
    elements.append(Spacer(1, 20))
    elements.append(Paragraph("DSP Health AI • Secure Medical Intelligence Platform", styles['Italic']))

    pdf.build(elements)
    buffer.seek(0)

    filename = f"Fingerprint_Report_{report['username']}.pdf"

    return send_file(buffer, as_attachment=True,
                     download_name=filename,
                     mimetype="application/pdf")
@app.route('/admin/report/download/<int:user_id>')
@admin_required
def admin_download_report(user_id):

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT username, email FROM userss WHERE id=%s", (user_id,))
    user = cursor.fetchone()

    cursor.execute("""
        SELECT *
        FROM predictions
        WHERE user_id=%s
        ORDER BY created_at DESC
        LIMIT 1
    """, (user_id,))
    pred = cursor.fetchone()

    cursor.close()
    conn.close()

    if not user or not pred:
        flash("No report data found for this user.", "warning")
        return redirect(url_for('admin_dashboard'))

    def safe(val):
        return val if val not in (None, "", "NULL") else "N/A"

    report_date = pred['created_at'].strftime("%d-%b-%Y %H:%M") \
        if hasattr(pred['created_at'], 'strftime') else pred['created_at']

    buffer = io.BytesIO()
    pdf = SimpleDocTemplate(buffer, pagesize=A4,
                            rightMargin=40, leftMargin=40,
                            topMargin=40, bottomMargin=40)

    styles = getSampleStyleSheet()
    elements = []

    styles.add(ParagraphStyle(
        name='MainTitle',
        fontSize=20,
        textColor=colors.HexColor("#064e3b"),
        fontName='Helvetica-Bold',
        spaceAfter=10
    ))

    styles.add(ParagraphStyle(
        name='SubTitle',
        fontSize=11,
        textColor=colors.grey,
        spaceAfter=20
    ))

    elements.append(Paragraph("Diabetes Clinical Prediction Report", styles['MainTitle']))
    elements.append(Paragraph("Generated using AI & Clinical Analytics", styles['SubTitle']))
    elements.append(Spacer(1, 20))

    patient_info = f"""
    <b>Patient Name:</b> {safe(user['username'])}<br/>
    <b>Email:</b> {safe(user['email'])}<br/>
    <b>Report Date:</b> {report_date}<br/>
    <b>Assessment Type:</b> Clinical Parameter-Based Prediction
    """

    elements.append(Paragraph(patient_info, styles['Normal']))
    elements.append(Spacer(1, 25))

    data = [
        ["Clinical Metric", "Observed Value"],
        ["Age", safe(pred.get("age"))],
        ["BMI", safe(pred.get("bmi"))],
        ["Glucose Level", safe(pred.get("glucose"))],
        ["HbA1c", safe(pred.get("hba1c"))],
        ["Hypertension", "Yes" if pred.get("hypertension") else "No"],
        ["Heart Disease", "Yes" if pred.get("heart_disease") else "No"],
        ["Smoking Status", safe(pred.get("smoking"))],
        ["Final Prediction", safe(pred.get("result"))],
    ]

    table = Table(data, colWidths=[220, 240])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#065f46")),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('GRID', (0, 0), (-1, -1), 0.6, colors.grey),
        ('BACKGROUND', (0, 1), (-1, -1), colors.whitesmoke),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
    ]))

    elements.append(table)
    elements.append(Spacer(1, 30))

    elements.append(Paragraph("""
    <b>Clinical Interpretation:</b><br/>
    This report is generated using predictive analytics on metabolic
    and cardiovascular parameters. It is intended for screening
    purposes and does not substitute medical consultation.
    """, styles['Normal']))

    elements.append(Spacer(1, 30))
    elements.append(Paragraph("<b>Authorized Medical Officer</b><br/>Dr. AI Clinical System<br/>DSP Health", styles['Normal']))
    elements.append(Spacer(1, 40))
    elements.append(Paragraph("Signature: _______________________________", styles['Normal']))
    elements.append(Spacer(1, 20))
    elements.append(Paragraph("DSP Health AI • Secure Medical Intelligence Platform", styles['Italic']))

    pdf.build(elements)
    buffer.seek(0)

    filename = f"{user['username']}_Clinical_Report.pdf"

    return send_file(buffer, as_attachment=True,
                     download_name=filename,
                     mimetype="application/pdf")
@app.route('/admin/messages/download/pdf')
@admin_required
def admin_download_messages_pdf():

    search = request.args.get('search', '').strip()

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    query = """
        SELECT name, email, subject, message, status, is_read, created_at
        FROM contact_messages
    """

    conditions = []
    values = []

    # 🔎 Apply search filter (same as admin_messages)
    if search:
        conditions.append("""
            (name LIKE %s OR email LIKE %s OR subject LIKE %s)
        """)
        values.extend([f"%{search}%", f"%{search}%", f"%{search}%"])

    if conditions:
        query += " WHERE " + " AND ".join(conditions)

    query += " ORDER BY created_at DESC"

    cursor.execute(query, values)
    messages = cursor.fetchall()

    cursor.close()
    conn.close()

    # 📄 PDF file path
    filename = f"messages_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    filepath = os.path.join("static", filename)

    doc = SimpleDocTemplate(filepath, pagesize=A4)
    elements = []

    styles = getSampleStyleSheet()
    elements.append(Paragraph("<b>Contact Messages Report</b>", styles['Heading1']))
    elements.append(Spacer(1, 0.5 * inch))

    data = [["Name", "Email", "Subject", "Status", "Read", "Date"]]

    for msg in messages:
        data.append([
            msg['name'],
            msg['email'],
            msg['subject'],
            msg['status'],
            "Yes" if msg['is_read'] else "No",
            msg['created_at'].strftime("%Y-%m-%d %H:%M")
        ])

    table = Table(data, repeatRows=1)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
        ('FONTSIZE', (0, 0), (-1, -1), 8),
    ]))

    elements.append(table)
    doc.build(elements)

    return send_file(filepath, as_attachment=True)
@app.route('/admin/export-user-combined/<int:user_id>')
@admin_required
def export_user_combined_pdf(user_id):

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # ================= USER =================
    cursor.execute("SELECT id, username, email FROM userss WHERE id=%s", (user_id,))
    user = cursor.fetchone()

    if not user:
        abort(404)

    # ================= MESSAGES =================
    cursor.execute("""
        SELECT message, created_at 
        FROM contact_messages 
        WHERE user_id=%s
        ORDER BY created_at DESC
    """, (user_id,))
    messages = cursor.fetchall()

    # ================= CLINICAL =================
    cursor.execute("""
        SELECT result, created_at 
        FROM predictions 
        WHERE user_id=%s
        ORDER BY created_at DESC
    """, (user_id,))
    clinical = cursor.fetchall()

    # ================= FINGERPRINT =================
    cursor.execute("""
        SELECT finger_type, result, created_at 
        FROM fingerprint_predictions 
        WHERE user_id=%s
        ORDER BY created_at DESC
    """, (user_id,))
    finger = cursor.fetchall()

    cursor.close()
    conn.close()

    # ================= CREATE PDF =================
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4)
    elements = []
    styles = getSampleStyleSheet()

    elements.append(Paragraph("<b>Complete User Report</b>", styles['Heading1']))
    elements.append(Spacer(1, 0.3 * inch))

    elements.append(Paragraph(f"Username: {user['username']}", styles['Normal']))
    elements.append(Paragraph(f"Email: {user['email']}", styles['Normal']))
    elements.append(Paragraph(f"Joined: {user['created_at']}", styles['Normal']))
    elements.append(Spacer(1, 0.4 * inch))

    # Messages
    elements.append(Paragraph("<b>Messages</b>", styles['Heading2']))
    elements.append(Spacer(1, 0.2 * inch))

    if messages:
        for m in messages:
            elements.append(
                Paragraph(f"{m['created_at']} - {m['message']}", styles['Normal'])
            )
            elements.append(Spacer(1, 0.1 * inch))
    else:
        elements.append(Paragraph("No messages found.", styles['Normal']))

    elements.append(Spacer(1, 0.4 * inch))

    # Clinical
    elements.append(Paragraph("<b>Clinical Predictions</b>", styles['Heading2']))
    elements.append(Spacer(1, 0.2 * inch))

    if clinical:
        for c in clinical:
            elements.append(
                Paragraph(f"{c['created_at']} - {c['result']}", styles['Normal'])
            )
            elements.append(Spacer(1, 0.1 * inch))
    else:
        elements.append(Paragraph("No clinical predictions found.", styles['Normal']))

    elements.append(Spacer(1, 0.4 * inch))

    # Fingerprint
    elements.append(Paragraph("<b>Fingerprint Predictions</b>", styles['Heading2']))
    elements.append(Spacer(1, 0.2 * inch))

    if finger:
        for f in finger:
            elements.append(
                Paragraph(f"{f['created_at']} - {f['finger_type']} - {f['result']}", styles['Normal'])
            )
            elements.append(Spacer(1, 0.1 * inch))
    else:
        elements.append(Paragraph("No fingerprint predictions found.", styles['Normal']))

    doc.build(elements)
    buffer.seek(0)

    return send_file(
        buffer,
        as_attachment=True,
        download_name=f"user_{user_id}_complete_report.pdf",
        mimetype='application/pdf'
    )




# ================= RUN =================
if __name__ == '__main__':
    app.run(debug=True)
