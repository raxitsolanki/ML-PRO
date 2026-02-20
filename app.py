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
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication

# Load ML Model & Scaler
model = pickle.load(open('diabetes_model.pkl', 'rb'))
scaler = pickle.load(open('scaler.pkl', 'rb'))


app = Flask(__name__)
app.secret_key = 'super_secret_key_change_this'

# ---------------- GOOGLE reCAPTCHA KEYS ----------------
app.config["RECAPTCHA_SITE_KEY"] = "6Ld8zVEsAAAAAJc2zFhJZhZxvcD1DIi0KrIfFD9Y"
app.config["RECAPTCHA_SECRET_KEY"] = "6Ld8zVEsAAAAAMY07J_W71tWimYAW1V3FRU8iD5H"


# ================= DATABASE CONFIG =================
db_config = {
    'host': 'localhost',
    'user': 'root',
    'password': 'Rakshit@18',
    'database': 'studyhub_db'
}

def get_db_connection():
    try:
        conn = mysql.connector.connect(**db_config)
        return conn
    except Error as e:
        print("Database connection failed:", e)
        return None

# ================= EMAIL FUNCTION =================
def send_email(to_email, subject, message, attachment_bytes=None, attachment_filename=None):
    sender_email = "dpshealth26@gmail.com"
    sender_password = "tqxm dyeu qtld xsdp"  # Gmail App Password

    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = to_email
    msg['Subject'] = subject
    msg.attach(MIMEText(message, 'html'))

    if attachment_bytes and attachment_filename:
        part = MIMEApplication(attachment_bytes, Name=attachment_filename)
        part['Content-Disposition'] = f'attachment; filename="{attachment_filename}"'
        msg.attach(part)
    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(sender_email, sender_password)
        server.send_message(msg)
        server.quit()
    except Exception as e:
        print("Email sending failed:", e)
        raise e

# ================= OTP FUNCTIONS =================
def generate_otp():
    return str(random.randint(100000, 999999))

def otp_expiry_time(minutes=5):
    return datetime.now() + timedelta(minutes=minutes)

# ================= LOGIN REQUIRED DECORATOR =================
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'loggedin' not in session:
            flash("Please login first!", "warning")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# ================= AUTHLIB GOOGLE OAUTH CONFIG =================
import os
from dotenv import load_dotenv

load_dotenv()

oauth = OAuth(app)

google = oauth.register(
    name='google',
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid email profile'
    }
)

# ================= ROUTES =================
@app.route('/')
def index():
    if 'loggedin' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


# ================= GOOGLE LOGIN =================
@app.route('/google-login')
def google_login():
    try:
        redirect_uri = url_for('google_authorize', _external=True)
        return google.authorize_redirect(redirect_uri)
    except Exception as e:
        flash("Google login failed. Try again.", "danger")
        return redirect(url_for('login'))


@app.route('/login/google/authorize')
def google_authorize():
    try:
        token = google.authorize_access_token()

        # Always fetch userinfo safely
        resp = google.get('https://openidconnect.googleapis.com/v1/userinfo')

        if resp.status_code != 200:
            flash("Failed to fetch Google user info.", "danger")
            return redirect(url_for('login'))

        user_info = resp.json()

        email = user_info.get('email')
        name = user_info.get('name', 'User')
        google_id = user_info.get('sub')  # ✅ FIX HERE

        if not email or not google_id:
            flash("Failed to retrieve Google account info.", "danger")
            return redirect(url_for('login'))

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # 1️⃣ Check if user exists via google_id
        cursor.execute("SELECT * FROM users WHERE google_id=%s", (google_id,))
        user = cursor.fetchone()

        if not user:
            # 2️⃣ Check by email
            cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
            user = cursor.fetchone()

            if user:
                cursor.execute(
                    "UPDATE users SET google_id=%s, is_verified=1 WHERE email=%s",
                    (google_id, email)
                )
            else:
                cursor.execute(
                    "INSERT INTO users (username, email, google_id, is_verified) VALUES (%s, %s, %s, 1)",
                    (name, email, google_id)
                )

            conn.commit()

            cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
            user = cursor.fetchone()

        cursor.close()
        conn.close()

        # ---------------- SESSION ----------------
       # ---------------- SESSION ----------------
        session.permanent = True
        session['loggedin'] = True
        session['id'] = user['id']          # ✅ THIS FIXES ERROR
        session['user_email'] = email
        session['username'] = user['username']


        flash(f"Welcome {name}! Logged in with Google.", "success")
        return redirect(url_for('dashboard'))

    except Exception as e:
        print("Google OAuth Error:", e)
        flash("Google login failed. Check console.", "danger")
        return redirect(url_for('login'))


# ================= REGISTER =================
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        raw_password = request.form['password']

        # 🔐 PASSWORD VALIDATION (SERVER SIDE)
        password_pattern = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&]).{6,}$'

        if not re.match(password_pattern, raw_password):
            flash(
                "Password must be at least 6 characters and include uppercase, lowercase, number & special symbol.",
                "danger"
            )
            return redirect(url_for('register'))

        # Hash password only after validation
        password = generate_password_hash(raw_password)

        otp = generate_otp()
        expiry = otp_expiry_time()

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # 1️⃣ Check if email already exists
        cursor.execute("SELECT id FROM users WHERE email=%s", (email,))
        if cursor.fetchone():
            flash("Email already registered!", "danger")
            cursor.close()
            conn.close()
            return redirect(url_for('register'))

        # 2️⃣ Send OTP email first
        subject = "Email Verification OTP"
        message = f"""
        <h3 style="color:#5b21b6;">Diabetes Prediction System</h3>
        <p>Thank you for registering with us!</p>
        <p>Your One-Time Password (OTP) to verify your email is:</p>
        <h2 style="color:#5b21b6;">{otp}</h2>
        <p>This OTP is valid for <b>5 minutes</b>.</p>
        <p>If you did not register, please ignore this email.</p>
        """

        try:
            send_email(email, subject, message)
        except Exception:
            flash("Your network is poor. Could not send OTP. Try again later.", "danger")
            cursor.close()
            conn.close()
            return redirect(url_for('register'))

        # 3️⃣ Insert user after successful email
        cursor.execute("""
            INSERT INTO users (username, email, password, otp, otp_expiry, is_verified)
            VALUES (%s, %s, %s, %s, %s, 0)
        """, (username, email, password, otp, expiry))
        conn.commit()

        cursor.close()
        conn.close()

        # 4️⃣ Session for OTP verification
        session['otp_email'] = email
        session['otp_type'] = 'verify'

        flash("OTP sent to your email for verification!", "info")
        return redirect(url_for('verify_otp'))

    return render_template('register.html')

# ================= LOGIN =================
@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'loggedin' in session:
       return redirect(url_for('dashboard'))


    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
        user = cursor.fetchone()

        if not user or not check_password_hash(user['password'], password):
            flash("Invalid email or password!", "error")
            cursor.close()
            conn.close()
            return redirect(url_for('login'))

        # Email must be verified
        if user['is_verified'] == 0:
            flash("Please verify your email first!", "warning")
            cursor.close()
            conn.close()
            return redirect(url_for('login'))

        # Send login OTP
        otp = generate_otp()
        expiry = otp_expiry_time()

        cursor.execute(
            "UPDATE users SET otp=%s, otp_expiry=%s WHERE email=%s",
            (otp, expiry, email)
        )
        conn.commit()

        subject = "Login OTP"

        message = f"""
<h3 style="color:#5b21b6;">Diabetes Prediction System</h3>

<p>You are trying to <b>login</b> to your account.</p>

<p>Your One-Time Password (OTP) is:</p>
<h2 style="color:#5b21b6;">{otp}</h2>

<p>This OTP is valid for <b>5 minute</b>.</p>

<p>If you did not try to login, please ignore this email.</p>
"""
        send_email(email, subject, message)

        session['otp_email'] = email
        session['otp_type'] = 'login'

        cursor.close()
        conn.close()

        flash("OTP sent to your email. Please verify to login.", "info")
        return redirect(url_for('verify_otp'))

    return render_template('login.html')

# ================= FORGOT PASSWORD =================
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("SELECT id FROM users WHERE email=%s", (email,))
        user = cursor.fetchone()

        if not user:
            flash("Email not found!", "error")
            cursor.close()
            conn.close()
            return redirect(url_for('forgot_password'))

        # Send OTP
        otp = generate_otp()
        expiry = otp_expiry_time()

        cursor.execute(
            "UPDATE users SET otp=%s, otp_expiry=%s WHERE email=%s",
            (otp, expiry, email)
        )
        conn.commit()

        subject = "Password Reset OTP"
        message = f"""
<h3 style="color:#5b21b6;">Diabetes Prediction System</h3>
<p>You requested to reset your password.</p>

<p>Your OTP is:</p>
<h2 style="color:#5b21b6;">{otp}</h2>

<p><b>Password Requirements:</b></p>
<ul style="color:#5b21b6;">
    <li>Minimum 6 characters</li>
    <li>At least 1 uppercase letter (A-Z)</li>
    <li>At least 1 lowercase letter (a-z)</li>
    <li>At least 1 number (0-9)</li>
    <li>At least 1 special character (@$!%*?&)</li>
</ul>

<p>If you did not request this, please ignore this email.</p>
"""

        send_email(email, subject, message)


        session['otp_email'] = email
        session['otp_type'] = 'reset'

        cursor.close()
        conn.close()

        flash("OTP sent to your email!", "success")
        return redirect(url_for('verify_otp'))

    return render_template('forgot_password.html')

# ================= VERIFY OTP =================
@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    if 'otp_email' not in session or 'otp_type' not in session:
        return redirect(url_for('login'))

    email = session['otp_email']
    otp_type = session['otp_type']

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # ================= RESEND OTP =================
    if request.method == 'GET' and request.args.get('resend') == '1':
        new_otp = str(random.randint(100000, 999999))
        new_expiry = datetime.utcnow() + timedelta(minutes=5)

        cursor.execute(
            "UPDATE users SET otp=%s, otp_expiry=%s WHERE email=%s",
            (new_otp, new_expiry, email)
        )
        conn.commit()

        subject = "Your New OTP Code"
        message = f"""
        <h3 style="color:#5b21b6;">Diabetes Prediction System</h3>
        <p>Your new OTP is:</p>
        <h2 style="color:#5b21b6;">{new_otp}</h2>
        <p>This OTP is valid for <b>5 minutes</b>.</p>
        """

        send_email(email, subject, message)

        session.pop('otp_invalid', None)   # ✅ RESET INVALID STATE
        flash("OTP has been sent to your email.", "otp_success")

        cursor.close()
        conn.close()
        return redirect(url_for('verify_otp'))

    # ================= VERIFY OTP =================
    if request.method == 'POST':
        otp_input = request.form.get('otp', '').strip()

        cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
        user = cursor.fetchone()

        if not user:
            cursor.close()
            conn.close()
            return redirect(url_for('login'))

        # ❌ INVALID FORMAT (NOT 6 DIGIT)
        if not otp_input.isdigit() or len(otp_input) != 6:
            cursor.execute(
                "UPDATE users SET otp=NULL, otp_expiry=NULL WHERE email=%s",
                (email,)
            )
            conn.commit()

            session['otp_invalid'] = True
            flash("Invalid or expired OTP. Please try again.", "otp_error")

            cursor.close()
            conn.close()
            return redirect(url_for('verify_otp'))

        # ❌ WRONG / EXPIRED OTP
        if otp_input != user['otp'] or datetime.utcnow() > user['otp_expiry']:
            cursor.execute(
                "UPDATE users SET otp=NULL, otp_expiry=NULL WHERE email=%s",
                (email,)
            )
            conn.commit()

            session['otp_invalid'] = True
            flash("Invalid or expired OTP. Please try again.", "otp_error")

            cursor.close()
            conn.close()
            return redirect(url_for('verify_otp'))

        # ✅ OTP VERIFIED
        cursor.execute(
            "UPDATE users SET otp=NULL, otp_expiry=NULL WHERE email=%s",
            (email,)
        )
        conn.commit()

        session.pop('otp_invalid', None)

        # ===== HANDLE TYPES =====
        if otp_type == 'verify':
            cursor.execute(
                "UPDATE users SET is_verified=1 WHERE email=%s",
                (email,)
            )
            conn.commit()
            session.pop('otp_email')
            session.pop('otp_type')

            flash("Email verified successfully!", "otp_success")
            cursor.close()
            conn.close()
            return redirect(url_for('login'))

        elif otp_type == 'login':
            session['loggedin'] = True
            session['id'] = user['id']
            session['username'] = user['username']
            session.pop('otp_email')
            session.pop('otp_type')
            cursor.close()
            conn.close()
            return redirect(url_for('dashboard'))

        elif otp_type == 'reset':
            session['reset_email'] = email
            session.pop('otp_email')
            session.pop('otp_type')
            cursor.close()
            conn.close()
            return redirect(url_for('reset_password'))

        elif otp_type == 'update_email':
            cursor.execute(
                "UPDATE users SET email=%s WHERE id=%s",
                (email, session['id'])
            )
            conn.commit()
            session.pop('otp_email')
            session.pop('otp_type')

            flash("Email updated successfully!", "otp_success")
            cursor.close()
            conn.close()
            return redirect(url_for('profile'))

    cursor.close()
    conn.close()
    return render_template('verify_otp.html')


# ================= RESET PASSWORD =================
@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if 'reset_email' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        password = request.form.get('password', '').strip()
        confirm = request.form.get('password2', '').strip()

        # 1️⃣ Empty check
        if not password or not confirm:
            flash("Please fill all fields!", "danger")
            return redirect(url_for('reset_password'))

        # 2️⃣ Match check
        if password != confirm:
            flash("Passwords do not match!", "danger")
            return redirect(url_for('reset_password'))

        # 3️⃣ 🔐 PASSWORD STRENGTH VALIDATION
        password_pattern = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&]).{6,}$'

        if not re.match(password_pattern, password):
            flash(
                "Password must be at least 6 characters and include uppercase, lowercase, number & special symbol.",
                "danger"
            )
            return redirect(url_for('reset_password'))

        # 4️⃣ Hash password
        hashed_password = generate_password_hash(password)
        email = session['reset_email']

        # 5️⃣ Update password
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET password=%s WHERE email=%s",
            (hashed_password, email)
        )
        conn.commit()
        cursor.close()
        conn.close()

        # 6️⃣ Cleanup session
        session.pop('reset_email', None)

        flash("Password reset successfully!", "success")
        return redirect(url_for('login'))

    return render_template('reset_password.html')

# ================= HOME / DASHBOARD =================
@app.route('/dashboard')
def dashboard():
    # If user not logged in
    if 'loggedin' not in session:
        flash("Please login first to access the dashboard", "login")
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute(
        "SELECT username, email FROM users WHERE id=%s",
        (session['id'],)
    )
    user = cursor.fetchone()

    cursor.close()
    conn.close()

    # ✅ Dashboard-specific toast
    flash(f"Welcome back, {user['username']}!", "dashboard")

    return render_template('dashboard.html', user=user)



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
    cursor.execute("SELECT username, email FROM users WHERE id=%s", (session['id'],))
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
    cursor.execute("SELECT username, email FROM users WHERE id=%s", (session['id'],))
    user = cursor.fetchone()
    cursor.close()
    conn.close()

    return render_template('suggestion.html', user=user)

@app.route('/contactus', methods=['GET', 'POST'])
def contactus():
    if request.method == 'POST':
        conn = None
        cursor = None

        try:
            # ---------------- FORM DATA ----------------
            name = request.form.get('name', '').strip()
            email = request.form.get('email', '').strip()
            subject = request.form.get('subject', '').strip()
            message = request.form.get('message', '').strip()

            # ---------------- BASIC VALIDATION ----------------
            if not name or not email or not subject or not message:
                flash("All fields are required!", "error")
                return redirect(url_for('contactus'))

            # ---------------- CAPTCHA CHECK ----------------
            recaptcha_response = request.form.get('g-recaptcha-response')
            if not recaptcha_response:
                flash("Please complete the CAPTCHA.", "error")
                return redirect(url_for('contactus'))

            verify_url = "https://www.google.com/recaptcha/api/siteverify"
            payload = {
                "secret": app.config["RECAPTCHA_SECRET_KEY"],
                "response": recaptcha_response
            }

            r = requests.post(verify_url, data=payload, timeout=10)
            result = r.json()

            if not result.get("success"):
                flash("reCAPTCHA verification failed. Try again.", "error")
                return redirect(url_for('contactus'))

            # ---------------- DB INSERT ----------------
            conn = get_db_connection()
            if not conn:
                flash("Database connection failed!", "error")
                return redirect(url_for('contactus'))

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
            <h3 style="color:#5b21b6;">Diabetes Prediction System</h3>
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
            flash("Something went wrong. Please try again.", "error")
            return redirect(url_for('contactus'))

        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()

    return render_template('contactus.html',site_key=app.config["RECAPTCHA_SITE_KEY"])


@app.route('/profile')
def profile():
    if 'loggedin' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT username, email, created_at FROM users WHERE id=%s", (session['id'],))
    user = cursor.fetchone()
    cursor.close()
    conn.close()

    return render_template('profile.html', user=user)
# ================= UPDATE USERNAME =================
@app.route('/update-username', methods=['POST'])
def update_username():
    if 'loggedin' not in session:
        return redirect(url_for('login'))

    new_username = request.form['new_username']

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET username=%s WHERE id=%s", (new_username, session['id']))
    conn.commit()
    cursor.close()
    conn.close()

    flash("Username updated successfully!", "success")
    return redirect(url_for('profile'))

@app.route('/update-password', methods=['POST'])
def update_password():
    if 'loggedin' not in session:
        return redirect(url_for('login'))

    # Read form fields safely
    new_password = request.form.get('new_password', '').strip()
    confirm_password = request.form.get('confirm_password', '').strip()

    # 1) Required fields
    if not new_password or not confirm_password:
        flash("Please fill all fields!", "error")
        return redirect(url_for('profile'))

    # 2) Match check
    if new_password != confirm_password:
        flash("New password and confirm password do not match!", "error")
        return redirect(url_for('profile'))

    # 3) Strength checks
    import re
    errors = []
    if len(new_password) < 6:
        errors.append("Minimum 6 characters")
    if not re.search(r"[A-Z]", new_password):
        errors.append("At least 1 uppercase letter (A-Z)")
    if not re.search(r"[a-z]", new_password):
        errors.append("At least 1 lowercase letter (a-z)")
    if not re.search(r"[0-9]", new_password):
        errors.append("At least 1 number (0-9)")
    if not re.search(r"[@$!%*?&]", new_password):
        errors.append("At least 1 special character (@$!%*?&)")

    if errors:
        flash("Password must have: " + ", ".join(errors), "error")
        return redirect(url_for('profile'))

    # 4) Update password
    hashed = generate_password_hash(new_password)
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET password=%s WHERE id=%s", (hashed, session['id']))
   
    conn.commit()
    cursor.close()
    conn.close()

    flash("Password updated successfully!", "success")
    return redirect(url_for('profile'))

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
                # ✅ Flash success message
                flash("Welcome to Admin Panel!", "success")
                return redirect(url_for('admin_dashboard'))
            else:
                error = "Invalid username or password"

        except Exception as e:
            error = "Something went wrong: " + str(e)

    return render_template('admin/admin_login.html', error=error)

# ================= ADMIN AUTH DECORATOR =================
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_logged_in' not in session:
            flash("Please login as admin first", "danger")
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function


# ================= ADMIN DASHBOARD =================
@app.route('/admin/dashboard')
def admin_dashboard():
    if 'admin_logged_in' not in session:
        return redirect(url_for('admin_login'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Total Users
    cursor.execute("SELECT COUNT(*) AS total_users FROM users")
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
        total_prediction=total_prediction  # future use / predictions placeholder
    )



# ================= VIEW USERS =================
@app.route('/admin/users')
@admin_required
def admin_users():

    search = request.args.get('search', '').strip()
    sort = request.args.get('sort', 'latest')  # default latest

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    query = """
        SELECT id, username, email, is_verified, created_at
        FROM users
    """

    conditions = []
    values = []

    # 🔎 SEARCH FILTER
    if search:
        conditions.append("(username LIKE %s OR email LIKE %s)")
        values.append(f"%{search}%")
        values.append(f"%{search}%")

    if conditions:
        query += " WHERE " + " AND ".join(conditions)

    # 🔤 SORTING
    if sort == "az":
        query += " ORDER BY username ASC"
    elif sort == "za":
        query += " ORDER BY username DESC"
    elif sort == "latest":
        query += " ORDER BY created_at DESC"
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




# ================= DELETE USER (SECURE POST) =================
@app.route('/admin/delete-user/<int:id>', methods=['POST'])
@admin_required
def delete_user(id):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("DELETE FROM users WHERE id=%s", (id,))
    conn.commit()

    cursor.close()
    conn.close()

    flash("User deleted successfully", "success")
    return redirect(url_for('admin_users'))


# ================= ADMIN LOGOUT =================
@app.route('/admin/logout')
@admin_required
def admin_logout():
    # Clear session
    session.pop('admin_logged_in', None)
    session.pop('admin_username', None)

    # ✅ Flash logout toast message
    

    return redirect(url_for('admin_login'))


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
    # unread first, pending first always
    query += " ORDER BY is_read ASC, status ASC"

    if sort == "latest":
        query += ", created_at DESC"
    elif sort == "oldest":
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

    cursor.execute("DELETE FROM contact_messages WHERE id=%s", (id,))
    conn.commit()

    cursor.close()
    conn.close()

    flash("Message deleted successfully", "success")
    return redirect(url_for('admin_messages'))

@app.route('/admin/message-ready/<int:id>', methods=['POST'])
def mark_message_ready(id):
    if 'admin_logged_in' not in session:
        return redirect(url_for('admin_login'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Get user message
    cursor.execute("SELECT * FROM contact_messages WHERE id=%s", (id,))
    msg = cursor.fetchone()

    if not msg:
        flash("Message not found", "danger")
        return redirect(url_for('admin_messages'))

    # Email to user
    subject = "DPS Support Team"
    message = f"""
    <h3 style="color:#5b21b6;">Diabetes Prediction System</h3>
    <p>Hi <b>{msg['name']}</b>,</p>

    <p>Your message has been reviewed by our admin team.</p>

    <p><b>Subject:</b> {msg['subject']}</p>
    <p><b>Your Message:</b><br>{msg['message']}</p>

    <p>We will contact you shortly if needed.</p>

    <p style="color:#5b21b6;"><b>– DPS Support Team</b></p>
    """

    try:
        send_email(msg['email'], subject, message)

        # Update status
        cursor.execute("""
            UPDATE contact_messages 
            SET status='sent', is_read=1 
            WHERE id=%s
        """, (id,))
        conn.commit()

        flash("Email sent to user successfully!", "success")

    except Exception as e:
        print(e)
        flash("Email sending failed", "danger")

    cursor.close()
    conn.close()

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
    cursor.execute("SELECT username, email FROM users WHERE id=%s", (user_id,))
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
