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
@app.route('/admin/prediction')
@admin_required
def admin_prediction():

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
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
    LEFT JOIN users u ON u.id = p.user_id
    ORDER BY p.created_at DESC
    """)

    predictions = cursor.fetchall()

    total_count = len(predictions)   # 👈 ADD THIS

    cursor.close()
    conn.close()

    return render_template(
        'admin/admin_prediction.html',
        predictions=predictions,
        total_count=total_count   # 👈 PASS TO TEMPLATE
    )


# ----------------------------
# Delete a prediction
# ----------------------------
@app.route('/admin/prediction/delete/<int:id>', methods=['POST'])
@admin_required
def delete_prediction(id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM predictions WHERE id=%s", (id,))
    conn.commit()
    cursor.close()
    conn.close()
    flash("Prediction deleted successfully.", "success")
    return redirect(url_for('admin_prediction'))
@app.route('/admin/user-analytics')
@admin_required
def admin_user_analytics():

    search = request.args.get('search', '').strip()
    sort = request.args.get('sort', 'latest')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    query = """
        SELECT id, username, email, created_at
        FROM users
    """

    conditions = []
    values = []

    # 🔎 Search Filter
    if search:
        conditions.append("(username LIKE %s OR email LIKE %s)")
        values.extend([f"%{search}%", f"%{search}%"])

    if conditions:
        query += " WHERE " + " AND ".join(conditions)

    # 🎯 Sorting
    if sort == "az":
        query += " ORDER BY username ASC"
    elif sort == "za":
        query += " ORDER BY username DESC"
    elif sort == "latest":
        query += " ORDER BY created_at DESC"
    else:
        query += " ORDER BY username ASC"

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
            FROM users
            WHERE id = %s
        """, (user_id,))
        user = cursor.fetchone()

        if not user:
            flash("User not found", "danger")
            return redirect(url_for('admin_user_analytics'))

        # =========================
        # 2️⃣ USER MESSAGES (ALL COLUMNS)
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
        # 3️⃣ CLINICAL PREDICTIONS (ALL COLUMNS)
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
        # 4️⃣ FINGER PREDICTIONS (ALL COLUMNS)
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
            if val == 1:
                return "Male"
            elif val == 0:
                return "Female"
            return "Unknown"

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
            c['gender_label'] = gender_label(c['gender'])
            c['hypertension_label'] = yes_no(c['hypertension'])
            c['heart_label'] = yes_no(c['heart_disease'])
            c['smoking_label'] = smoking_label(c['smoking'])
            c['type'] = "Report"

        # Apply mapping to finger
        for f in finger_list:
            f['gender_label'] = gender_label(f['gender'])
            f['smoking_label'] = smoking_label(f['smoking'])
            f['pattern_label'] = pattern_label(f['pattern_type'])
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
    if 'loggedin' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # ---------- USER INFO ----------
    cursor.execute("SELECT username, email FROM userss WHERE id=%s", (user_id,))
    user = cursor.fetchone()

    # ---------- LATEST PREDICTION ----------
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
        flash("No report data found", "warning")
        return redirect(url_for('dashboard'))

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

    # Custom styles
    styles.add(ParagraphStyle(
        name='HeaderTitle',
        fontSize=20,
        textColor=colors.HexColor("#065f46"),  # Emerald dark green
        spaceAfter=12,
        fontName='Helvetica-Bold'
    ))

    styles.add(ParagraphStyle(
        name='SubTitle',
        fontSize=12,
        textColor=colors.grey,
        spaceAfter=20
    ))

    styles.add(ParagraphStyle(
        name='Footer',
        fontSize=9,
        textColor=colors.grey,
        alignment=1  # center
    ))

    elements = []

    # ---------- HEADER ----------
    elements.append(Paragraph("Diabetes Prediction Medical Report", styles['HeaderTitle']))
    elements.append(Paragraph("Generated using AI & Clinical Analytics", styles['SubTitle']))
    elements.append(Spacer(1, 20))

    # ---------- USER INFO ----------
    report_date = pred['created_at'].strftime("%d-%b-%Y %H:%M") if hasattr(pred['created_at'], 'strftime') else pred['created_at']
    patient_info = f"""
    <b>Patient Name:</b> {user['username']}<br/>
    <b>Email:</b> {user['email']}<br/>
    <b>Report Date:</b> {report_date}<br/>
    <b>Assessment Type:</b> Report-Based Diabetes Prediction
    """
    elements.append(Paragraph(patient_info, styles['Normal']))
    elements.append(Spacer(1, 25))

    # ---------- MEDICAL DATA TABLE ----------
    data_table = [
        ["Clinical Metric", "Observed Value"],
        ["Age", pred["age"]],
        ["BMI", pred["bmi"]],
        ["Glucose", pred["glucose"]],
        ["HbA1c", pred["hba1c"]],
        ["Hypertension", "Yes" if pred["hypertension"] else "No"],
        ["Heart Disease", "Yes" if pred["heart_disease"] else "No"],
        ["Smoking", pred["smoking"]],
        ["Prediction Result", pred["result"]],
    ]

    table = Table(data_table, colWidths=[220, 240])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#064e3b")),  # Emerald header
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
    This Report-based assessment uses predictive analytics based on clinical parameters to estimate 
    diabetes risk. The report is for informational purposes only and does not replace professional 
    medical advice.
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
    

    # ---------- FOOTER ----------
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

    # ---------- PAGE LOAD (GET) ----------
    if request.method == 'GET':
        return render_template('finger_prediction.html')

    # ---------- FORM SUBMIT (POST) ----------
    gender   = int(request.form['gender'])
    age      = int(request.form['age'])
    smoking  = int(request.form['smoking'])
    bmi      = float(request.form['bmi'])
    hba1c    = float(request.form['hba1c'])
    glucose  = float(request.form['glucose'])

    # ---------- IMAGE ----------
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

    # ---------- FEATURE EXTRACTION ----------
    fp = extract_fingerprint_features(fingerprint_image)

    ridge_density    = float(fp['ridge_density'])
    complexity_score = float(fp['complexity_score'])
    pattern_type     = int(fp['pattern_type'])

    # ---------- MODEL INPUT ----------
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

    # ---------- DATABASE ----------
    # ---------- DATABASE ----------
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
    INSERT INTO finger_predictions
    (user_id, gender, age, smoking, bmi, hba1c, glucose,
     ridge_density, complexity_score, pattern_type,
     result, fingerprint_image)
    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
     """, (
    session['id'],
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
@app.route('/download_finger_report/<int:user_id>')
def download_finger_report(user_id):

    if 'loggedin' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT fp.*, u.username, u.email
        FROM finger_predictions fp
        JOIN users u ON u.id = fp.user_id
        WHERE fp.user_id = %s
        ORDER BY fp.created_at DESC
        LIMIT 1
    """, (user_id,))
    report = cursor.fetchone()

    cursor.close()
    conn.close()

    if not report:
        return "No fingerprint report found", 404

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
    elements = []

    # ---------- CUSTOM STYLES ----------
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

   

    # ---------- HEADER ----------
    elements.append(Paragraph(
        "Fingerprint-Based Diabetes Risk Medical Report",
        styles['HeaderTitle']
    ))

    elements.append(Paragraph(
        "Generated using Advanced Biometric AI & Clinical Analytics",
        styles['SubTitle']
    ))

    elements.append(Spacer(1, 20))

    # ---------- PATIENT INFO ----------
    patient_info = f"""
    <b>Patient Name:</b> {report['username']}<br/>
    <b>Email:</b> {report['email']}<br/>
    <b>Report Date:</b> {report['created_at']}<br/>
    <b>Assessment Type:</b> Fingerprint-Based AI Diagnosis
    """

    elements.append(Paragraph(patient_info, styles['Normal']))
    elements.append(Spacer(1, 25))

    # ---------- MEDICAL DATA TABLE ----------
    data_table = [
        ["Clinical Metric", "Observed Value"],
        ["Age", report["age"]],
        ["BMI", report["bmi"]],
        ["Glucose Level", report["glucose"]],
        ["HbA1c", report["hba1c"]],
        ["Smoking Status", report["smoking"]],
        ["Ridge Density", report["ridge_density"]],
        ["Pattern Complexity", report["complexity_score"]],
        ["Fingerprint Pattern Type", report["pattern_type"]],
        ["Final Risk Assessment", report["result"]],
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
    elements.append(Paragraph(
        """
        <b>Clinical Interpretation:</b><br/>
        This fingerprint-based assessment uses biometric ridge analysis combined with
        metabolic indicators to estimate diabetes risk. The result is intended for
        preventive screening and should not replace professional medical diagnosis.
        """,
        styles['Normal']
    ))

    elements.append(Spacer(1, 25))
    # ---------------- DOCTOR SIGNATURE ----------------
    elements.append(Paragraph(
    "<b>Authorized Medical Officer</b><br/>Dr. AI Clinical System<br/>DSP Health",
    styles['Normal']
    ))

    elements.append(Spacer(1, 40))

    elements.append(Paragraph(
     "Signature: ___________________________",
     styles['Normal']
    ))

    elements.append(Spacer(1, 25))
   
    # ---------- FOOTER ----------
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

@app.route('/admin/finger-predictions')
@admin_required
def admin_finger_predictions():

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT fp.*, u.email
        FROM finger_predictions fp
        JOIN users u ON u.id = fp.user_id
        ORDER BY fp.created_at DESC
    """)

    predictions = cursor.fetchall()
    total_count = len(predictions)   # 👈 COUNT

    cursor.close()
    conn.close()

    return render_template(
        'admin/admin_finger_predictions.html',
        predictions=predictions,
        total_count=total_count   # 👈 SEND TO TEMPLATE
    )

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
        cursor.execute("SELECT username, email FROM users WHERE id = %s", (user_id,))
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
        JOIN users u ON u.id = fp.user_id
        WHERE fp.user_id = %s
        ORDER BY fp.created_at DESC
        LIMIT 1
    """, (user_id,))

    report = cursor.fetchone()

    cursor.close()
    conn.close()

    if not report:
        flash("No fingerprint report found for this user.", "danger")
        return redirect(url_for('admin_user_analytics'))

    # ---------- PDF BUFFER ----------
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

    # ---------- CUSTOM STYLES ----------
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

    # ---------- HEADER ----------
    elements.append(Paragraph(
        "Fingerprint-Based Diabetes Risk Medical Report",
        styles['HeaderTitle']
    ))

    elements.append(Paragraph(
        "Generated by DSP Health AI Clinical Intelligence System",
        styles['SubTitle']
    ))

    elements.append(Spacer(1, 20))

    # ---------- PATIENT INFO ----------
    patient_info = f"""
    <b>Patient Name:</b> {report['username']}<br/>
    <b>Email:</b> {report['email']}<br/>
    <b>Report Date:</b> {report['created_at']}<br/>
    <b>Generated By:</b> Admin Panel
    """

    elements.append(Paragraph(patient_info, styles['Normal']))
    elements.append(Spacer(1, 25))

    # ---------- SAFE VALUES ----------
    def safe(value):
        return value if value else "N/A"

    # ---------- TABLE ----------
    data_table = [
        ["Clinical Metric", "Observed Value"],
        ["Age", safe(report.get("age"))],
        ["BMI", safe(report.get("bmi"))],
        ["Glucose Level", safe(report.get("glucose"))],
        ["HbA1c", safe(report.get("hba1c"))],
        ["Smoking Status", safe(report.get("smoking"))],
        ["Ridge Density", safe(report.get("ridge_density"))],
        ["Pattern Complexity", safe(report.get("complexity_score"))],
        ["Fingerprint Pattern Type", safe(report.get("pattern_type"))],
        ["Final Risk Assessment", safe(report.get("result"))],
    ]

    table = Table(data_table, colWidths=[220, 240])

    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#064e3b")),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('GRID', (0, 0), (-1, -1), 0.6, colors.grey),
        ('BACKGROUND', (0, 1), (-1, -1), colors.whitesmoke),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
    ]))

    elements.append(table)
    elements.append(Spacer(1, 30))

    # ---------- MEDICAL NOTE ----------
    elements.append(Paragraph(
        """
        <b>Clinical Interpretation:</b><br/>
        This fingerprint-based biometric assessment is generated using 
        AI-powered ridge density and metabolic correlation analysis.
        It is intended for screening purposes only and should not replace
        professional medical consultation.
        """,
        styles['Normal']
    ))

    elements.append(Spacer(1, 30))

    elements.append(Paragraph(
        "<b>Authorized Medical Officer</b><br/>Dr. AI Clinical System<br/>DSP Health",
        styles['Normal']
    ))

    elements.append(Spacer(1, 40))

    elements.append(Paragraph(
        "Signature: ___________________________",
        styles['Normal']
    ))

    elements.append(Spacer(1, 25))

    elements.append(Paragraph(
        "DSP Health AI • Secure Medical Intelligence Platform",
        styles['Italic']
    ))

    # ---------- BUILD ----------
    pdf.build(elements)
    buffer.seek(0)

    return send_file(
        buffer,
        as_attachment=True,
        download_name=f"Fingerprint_Report_{report['username']}.pdf",
        mimetype="application/pdf"
    )
@app.route('/admin/report/download/<int:user_id>', methods=['GET'])
def admin_download_report(user_id):
  

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # ----- GET USER INFO -----
    cursor.execute("SELECT username, email FROM users WHERE id=%s", (user_id,))
    user = cursor.fetchone()

    # ----- GET LATEST PREDICTION -----
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

    # ----- CREATE PDF -----
    buffer = io.BytesIO()
    pdf = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=40)
    styles = getSampleStyleSheet()

    # Custom styles
    styles.add(ParagraphStyle(name='HeaderTitle', fontSize=20, textColor=colors.HexColor("#065f46"), spaceAfter=12, fontName='Helvetica-Bold'))
    styles.add(ParagraphStyle(name='SubTitle', fontSize=12, textColor=colors.grey, spaceAfter=20))

    elements = []

    # Header
    elements.append(Paragraph("Diabetes Prediction Medical Report", styles['HeaderTitle']))
    elements.append(Paragraph("Generated using AI & Clinical Analytics", styles['SubTitle']))
    elements.append(Spacer(1, 20))

    # Patient info
    report_date = pred['created_at'].strftime("%d-%b-%Y %H:%M") if hasattr(pred['created_at'], 'strftime') else pred['created_at']
    patient_info = f"""
    <b>Patient Name:</b> {user['username']}<br/>
    <b>Email:</b> {user['email']}<br/>
    <b>Report Date:</b> {report_date}<br/>
    <b>Assessment Type:</b> Report-Based Diabetes Prediction
    """
    elements.append(Paragraph(patient_info, styles['Normal']))
    elements.append(Spacer(1, 25))

    # Medical Data Table
    data_table = [
        ["Clinical Metric", "Observed Value"],
        ["Age", pred["age"]],
        ["BMI", pred["bmi"]],
        ["Glucose", pred["glucose"]],
        ["HbA1c", pred["hba1c"]],
        ["Hypertension", "Yes" if pred["hypertension"] else "No"],
        ["Heart Disease", "Yes" if pred["heart_disease"] else "No"],
        ["Smoking", pred["smoking"]],
        ["Prediction Result", pred["result"]],
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

    # Medical Note
    note_text = """
    <b>Clinical Interpretation:</b><br/>
    This Admin-accessed report uses predictive analytics based on clinical parameters 
    to estimate diabetes risk. For medical guidance, consult a licensed healthcare professional.
    """
    elements.append(Paragraph(note_text, styles['Normal']))
    elements.append(Spacer(1, 25))
    elements.append(Paragraph("<b>Authorized Medical Officer</b><br/>Dr. AI Clinical System<br/>DSP Health", styles['Normal']))
    elements.append(Spacer(1, 40))
    elements.append(Paragraph("Signature: _______________________________", styles['Normal']))
    elements.append(Spacer(1, 25))
    elements.append(Paragraph("DSP Health AI • Secure Medical Intelligence Platform", styles['Italic']))

    pdf.build(elements)
    buffer.seek(0)

    # ----- SEND PDF FILE -----
    return send_file(
        buffer,
        as_attachment=True,
        download_name=f"{user['username']}_diabetes_report_admin.pdf",
        mimetype="application/pdf"
    )
@app.route('/admin/report/send/<int:user_id>', methods=['GET'])
def admin_send_report_email(user_id):
   

    # ----------------- FETCH USER AND PREDICTION -----------------
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT username, email FROM users WHERE id=%s", (user_id,))
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

    # ----------------- CREATE PDF -----------------
    buffer = io.BytesIO()
    pdf = SimpleDocTemplate(buffer, pagesize=(595, 842), rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=40)

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name='HeaderTitle', fontSize=20, textColor=colors.HexColor("#065f46"), spaceAfter=12, fontName='Helvetica-Bold'))
    styles.add(ParagraphStyle(name='SubTitle', fontSize=12, textColor=colors.grey, spaceAfter=20))

    elements = []

    # Header
    elements.append(Paragraph("Diabetes Prediction Medical Report", styles['HeaderTitle']))
    elements.append(Paragraph("Generated using AI & Clinical Analytics", styles['SubTitle']))
    elements.append(Spacer(1, 20))

    # Patient Info
    report_date = pred['created_at'].strftime("%d-%b-%Y %H:%M") if isinstance(pred['created_at'], datetime) else pred['created_at']
    patient_info = f"""
    <b>Patient Name:</b> {user['username']}<br/>
    <b>Email:</b> {user['email']}<br/>
    <b>Report Date:</b> {report_date}<br/>
    <b>Assessment Type:</b> Report-Based Diabetes Prediction
    """
    elements.append(Paragraph(patient_info, styles['Normal']))
    elements.append(Spacer(1, 25))

    # Medical Table
    data_table = [
        ["Clinical Metric", "Observed Value"],
        ["Age", pred["age"]],
        ["BMI", pred["bmi"]],
        ["Glucose", pred["glucose"]],
        ["HbA1c", pred["hba1c"]],
        ["Hypertension", "Yes" if pred["hypertension"] else "No"],
        ["Heart Disease", "Yes" if pred["heart_disease"] else "No"],
        ["Smoking", pred["smoking"]],
        ["Prediction Result", pred["result"]],
    ]
    table = Table(data_table, colWidths=[220, 240])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#064e3b")),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('FONT', (0,0), (-1,0), 'Helvetica-Bold'),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('GRID', (0,0), (-1,-1), 0.6, colors.grey),
        ('BACKGROUND', (0,1), (-1,-1), colors.whitesmoke),
        ('BOTTOMPADDING', (0,0), (-1,-1), 8),
        ('TOPPADDING', (0,0), (-1,-1), 8),
    ]))
    elements.append(table)
    elements.append(Spacer(1, 25))

    # Medical Note
    note_text = """
    <b>Clinical Interpretation:</b><br/>
    This report uses predictive analytics based on clinical parameters 
    to estimate diabetes risk. Consult a licensed healthcare professional for guidance.
    """
    elements.append(Paragraph(note_text, styles['Normal']))
    elements.append(Spacer(1, 25))
    elements.append(Paragraph("<b>Authorized Medical Officer</b><br/>Dr. AI Clinical System<br/>DSP Health", styles['Normal']))
    elements.append(Spacer(1, 25))

    pdf.build(elements)
    buffer.seek(0)
    pdf_bytes = buffer.read()

    # ----------------- SEND EMAIL -----------------
    subject = "Your Diabetes Prediction Report"

    body = f"""
<div style="font-family:Arial, sans-serif; color:#333;">
    <h3 style="color:#5b21b6;">Diabetes Prediction System</h3>
    <p>Hello <b>{user['username']}</b>,</p>
    <p>Please find attached your latest<b>Reports-based diabetes risk report</b>.</p>
   <p>This report is generated by DSP Health AI Clinical Intelligence System.</p>
    <br/>
    <p>Regards,<br/>DSP Health Team</p>
</div>
"""
    send_email(
        to_email=user['email'],
        subject=subject,
        message=body,
        attachment_bytes=pdf_bytes,
        attachment_filename=f"{user['username']}_diabetes_report.pdf"
    )

    flash(f"Report successfully sent to {user['email']}", "success")
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/send/finger-report/<int:user_id>')
@admin_required
def admin_send_finger_report_email(user_id):
    # ----------------- FETCH USER AND LATEST FINGER PREDICTION -----------------
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT fp.*, u.username, u.email
        FROM finger_predictions fp
        JOIN users u ON u.id = fp.user_id
        WHERE fp.user_id = %s
        ORDER BY fp.created_at DESC
        LIMIT 1
    """, (user_id,))

    report = cursor.fetchone()
    cursor.close()
    conn.close()

    if not report:
        flash("No fingerprint report found for this user.", "danger")
        return redirect(url_for('admin_user_analytics'))

    # ----------------- CREATE PDF IN MEMORY -----------------
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

    # Custom Styles
    styles.add(ParagraphStyle(name='HeaderTitle', fontSize=20, textColor=colors.HexColor("#065f46"), spaceAfter=12, fontName='Helvetica-Bold'))
    styles.add(ParagraphStyle(name='SubTitle', fontSize=11, textColor=colors.grey, spaceAfter=20))

    # Header
    elements.append(Paragraph("Fingerprint-Based Diabetes Risk Medical Report", styles['HeaderTitle']))
    elements.append(Paragraph("Generated by DSP Health AI Clinical Intelligence System", styles['SubTitle']))
    elements.append(Spacer(1, 20))

    # Patient Info
    patient_info = f"""
    <b>Patient Name:</b> {report['username']}<br/>
    <b>Email:</b> {report['email']}<br/>
    <b>Report Date:</b> {report['created_at']}<br/>
    <b>Generated By:</b>Finger-Based Diabetes Prediction 
    """
    elements.append(Paragraph(patient_info, styles['Normal']))
    elements.append(Spacer(1, 25))

    # Safe function
    def safe(value):
        return value if value else "N/A"

    # Table Data
    data_table = [
        ["Clinical Metric", "Observed Value"],
        ["Age", safe(report.get("age"))],
        ["BMI", safe(report.get("bmi"))],
        ["Glucose Level", safe(report.get("glucose"))],
        ["HbA1c", safe(report.get("hba1c"))],
        ["Smoking Status", safe(report.get("smoking"))],
        ["Ridge Density", safe(report.get("ridge_density"))],
        ["Pattern Complexity", safe(report.get("complexity_score"))],
        ["Fingerprint Pattern Type", safe(report.get("pattern_type"))],
        ["Final Risk Assessment", safe(report.get("result"))],
    ]

    table = Table(data_table, colWidths=[220, 240])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#064e3b")),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('GRID', (0,0), (-1,-1), 0.6, colors.grey),
        ('BACKGROUND', (0,1), (-1,-1), colors.whitesmoke),
        ('BOTTOMPADDING', (0,0), (-1,-1), 8),
        ('TOPPADDING', (0,0), (-1,-1), 8),
    ]))

    elements.append(table)
    elements.append(Spacer(1, 30))

    # Medical Note
    elements.append(Paragraph(
        """
        <b>Clinical Interpretation:</b><br/>
        This fingerprint-based biometric assessment is generated using 
        AI-powered ridge density and metabolic correlation analysis.
        It is intended for screening purposes only and should not replace
        professional medical consultation.
        """,
        styles['Normal']
    ))
    elements.append(Spacer(1, 30))
    elements.append(Paragraph("<b>Authorized Medical Officer</b><br/>Dr. AI Clinical System<br/>DSP Health", styles['Normal']))
    elements.append(Spacer(1, 40))
    elements.append(Paragraph("Signature: ___________________________", styles['Normal']))
    elements.append(Spacer(1, 25))
    elements.append(Paragraph("DSP Health AI • Secure Medical Intelligence Platform", styles['Italic']))

    # Build PDF
    pdf.build(elements)
    buffer.seek(0)
    pdf_bytes = buffer.read()

    # ----------------- SEND EMAIL -----------------
    subject = "Your Diabetes Prediction Report"
    body = f"""
    <div style="font-family:Arial, sans-serif; color:#333;">
        <h3 style="color:#5b21b6;">Fingerprint Diabetes Prediction System</h3>
        <p>Hello <b>{report['username']}</b>,</p>
        <p>Please find attached your latest <b>fingerprint-based diabetes risk report</b>.</p>
        <p>This report is generated by DSP Health AI Clinical Intelligence System.</p>
        <br/>
        <p>Regards,<br/>DSP Health Team</p>
    </div>
    """

    send_email(
        to_email=report['email'],
        subject=subject,
        message=body,
        attachment_bytes=pdf_bytes,
        attachment_filename=f"Fingerprint_Report_{report['username']}.pdf"
    )

    flash(f"Fingerprint report successfully sent to {report['email']}", "success")
    return redirect(url_for('admin_user_analytics'))
def apply_common_filters(base_query, search_field, sort_field, search, sort):
    conditions = []
    values = []

    if search:
        conditions.append(f"{search_field} LIKE %s")
        values.append(f"%{search}%")

    if conditions:
        base_query += " WHERE " + " AND ".join(conditions)

    if sort == "az":
        base_query += f" ORDER BY {search_field} ASC"
    elif sort == "za":
        base_query += f" ORDER BY {search_field} DESC"
    elif sort == "latest":
        base_query += f" ORDER BY {sort_field} DESC"

    return base_query, values




# ================= RUN =================
if __name__ == '__main__':
    app.run(debug=True)
