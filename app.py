from flask import Flask, render_template, request, redirect, url_for, session
from datetime import timedelta, datetime, timezone
from urllib.parse import urlparse
import calendar
import hashlib
import hmac
import smtplib
import secrets
import base64
import re
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from supabase import create_client, Client
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# SECRET_KEY Vercel ke Environment Variables me zaroor set karein (lamba random).
_secret = os.environ.get("SECRET_KEY")
if not _secret:
    print("WARNING: SECRET_KEY set nahi hai! Vercel me set karein, warna OTP/login kharab ho sakta hai.")
    _secret = secrets.token_hex(32)
app.secret_key = _secret

# Supabase Configuration (Using Environment Variables securely)
SUPABASE_URL = os.environ.get("SUPABASE_URL", "https://ihcghpiezdvnomfxvetu.supabase.co")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY", "")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# Session ko 1 saal tak permanent rakhne ke liye
app.permanent_session_lifetime = timedelta(days=365)

# Cookie security
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    MAX_CONTENT_LENGTH=1 * 1024 * 1024,
)

PKT = timezone(timedelta(hours=5))
EMAIL_RE = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')


# ------------------------------------------------------------------
# Security hooks
# ------------------------------------------------------------------
@app.before_request
def security_checks():
    session.permanent = True
    # Dusri website se aayi POST request block (CSRF se bachav)
    if request.method == 'POST':
        origin = request.headers.get('Origin')
        if origin and urlparse(origin).netloc != request.host:
            return "Request blocked.", 403


@app.after_request
def add_security_headers(resp):
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['X-Frame-Options'] = 'DENY'
    resp.headers['Referrer-Policy'] = 'same-origin'
    resp.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    if request.endpoint != 'static':
        resp.headers['Cache-Control'] = 'no-store'
    return resp


def now_pkt():
    return datetime.now(PKT)


def today_pkt():
    return now_pkt().strftime("%Y-%m-%d")


def clip(value, n=200):
    """User input ko lambai tak kaat do."""
    if value is None:
        return None
    return str(value).strip()[:n]


# ------------------------------------------------------------------
# Rate limit (Supabase ke login_attempts table se; Vercel par bhi chalta hai)
# ------------------------------------------------------------------
LIMITS = {            # action: (kitni koshish, kitne second me)
    'login':  (5, 600),
    'forgot': (3, 900),
    'signup': (3, 900),
    'otp':    (5, 600),
}


def client_ip():
    fwd = request.headers.get('X-Forwarded-For', '')
    return fwd.split(',')[0].strip() or request.remote_addr or 'unknown'


def blocked(action, *idents):
    limit, window = LIMITS[action]
    since = (datetime.now(timezone.utc) - timedelta(seconds=window)).strftime("%Y-%m-%dT%H:%M:%SZ")
    for ident in idents:
        if not ident:
            continue
        try:
            res = (supabase.table('login_attempts').select("id")
                   .eq('bucket', f"{action}:{ident}").gte('created_at', since)
                   .limit(limit).execute())
            if len(res.data or []) >= limit:
                return True
        except Exception as e:
            print(f"Rate limit check failed: {e}")
    return False


def record(action, *idents):
    try:
        rows = [{'bucket': f"{action}:{i}"} for i in idents if i]
        if rows:
            supabase.table('login_attempts').insert(rows).execute()
        if secrets.randbelow(50) == 0:   # kabhi kabhi purani entries saaf
            old = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
            supabase.table('login_attempts').delete().lt('created_at', old).execute()
    except Exception as e:
        print(f"Rate limit record failed: {e}")


# ------------------------------------------------------------------
# Password + OTP helpers
# ------------------------------------------------------------------
def verify_password(user_row, password):
    stored = user_row.get('password') or ''
    password = password or ''
    if stored.startswith(('scrypt:', 'pbkdf2:')):
        return check_password_hash(stored, password)
    # Purana plain-text password: match hua to turant hash karke save kar do
    if hmac.compare_digest(stored.encode(), password.encode()):
        try:
            supabase.table('users').update(
                {'password': generate_password_hash(password)}
            ).eq('email', user_row['email']).execute()
        except Exception as e:
            print(f"Password upgrade failed: {e}")
        return True
    return False


def make_otp_hash(email, otp):
    # OTP session cookie me seedha nahi rakhte (cookie padhi ja sakti hai), uska hash rakhte hain
    msg = f"{email}:{otp}".encode()
    return hmac.new(app.secret_key.encode(), msg, hashlib.sha256).hexdigest()


def clear_otp_session():
    for k in ('otp_hash', 'otp_time', 'otp_tries', 'otp_verified', 'is_forgot', 'signup_email'):
        session.pop(k, None)


def new_otp_session(email, forgot):
    otp = secrets.randbelow(900000) + 100000
    clear_otp_session()
    session['signup_email'] = email
    session['otp_hash'] = make_otp_hash(email, otp)
    session['otp_time'] = now_pkt().timestamp()
    session['otp_tries'] = 0
    session['otp_verified'] = False
    if forgot:
        session['is_forgot'] = True
    send_email_otp(email, otp)


# ------------------------------------------------------------------
# Email OTP
# ------------------------------------------------------------------
def send_email_otp(receiver_email, otp):
    sender_email = os.environ.get("GMAIL_USER", "clipslip.official@gmail.com")
    sender_password = os.environ.get("GMAIL_APP_PASSWORD", "")

    message = MIMEMultipart("alternative")
    message["Subject"] = "CliqSlip - Verification Code"
    message["From"] = sender_email
    message["To"] = receiver_email

    html = f"""
    <h3>CliqSlip Clinic Management</h3>
    <p>Aapka tasdeeqi code (OTP) yeh hai:</p>
    <h2>{otp}</h2>
    <p>Yeh code sirf 2 minute ke liye karamad hai. Isay kisi ke sath share na karein.</p>
    """
    message.attach(MIMEText(html, "html"))

    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, receiver_email, message.as_string())
        server.quit()
        return True
    except Exception as e:
        print(f"Email sending failed error: {e}")
        return False


def load_profile_into_session(user_row):
    session['doctor_name'] = user_row.get('doctor_name') or 'Doctor'
    session['clinic_name'] = user_row.get('clinic_name') or 'CliqSlip Clinic'
    session['clinic_phone'] = user_row.get('clinic_phone') or ''
    session['clinic_address'] = user_row.get('clinic_address') or ''
    session['consultation_fee'] = user_row.get('consultation_fee') or ''
    session['specialization'] = user_row.get('specialization') or ''


# ------------------------------------------------------------------
# Auth routes
# ------------------------------------------------------------------
@app.route('/')
@app.route('/login', methods=['GET', 'POST'])
def login():
    if session.get('is_logged_in'):
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        email = (request.form.get('email') or '').strip()
        password = request.form.get('password') or ''
        ip = client_ip()

        if blocked('login', email.lower(), ip):
            return "Too many attempts! Please wait 10 minutes and try again.", 429

        response = supabase.table('users').select("*").eq('email', email).execute()
        users = response.data

        if users and verify_password(users[0], password):
            session.clear()
            session.permanent = True
            session['is_logged_in'] = True
            session['doctor_email'] = email
            load_profile_into_session(users[0])
            return redirect(url_for('dashboard'))

        record('login', email.lower(), ip)
        return "Invalid Email or Password! Please try again."
    return render_template('login.html')


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = (request.form.get('email') or '').strip()
        ip = client_ip()
        if not EMAIL_RE.match(email):
            return "Please enter a valid email address."
        if blocked('forgot', email.lower(), ip):
            return "Too many requests! Please wait 15 minutes and try again.", 429
        record('forgot', email.lower(), ip)

        response = supabase.table('users').select("email").eq('email', email).execute()
        if response.data:
            new_otp_session(email, forgot=True)
        else:
            clear_otp_session()   # email na mile tab bhi same page dikhao (email ka pata na chale)
        return redirect(url_for('verify_otp'))
    return render_template('forgot_password.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = (request.form.get('email') or '').strip()
        ip = client_ip()
        if not EMAIL_RE.match(email):
            return render_template('signup.html', error="Please enter a valid email address.")
        if blocked('signup', email.lower(), ip):
            return render_template('signup.html', error="Too many requests! Please wait 15 minutes."), 429
        record('signup', email.lower(), ip)

        existing_user = supabase.table('users').select("email").eq('email', email).execute()
        if existing_user.data:
            return render_template('signup.html', error="This email is already registered! Please sign in instead.")

        new_otp_session(email, forgot=False)
        return redirect(url_for('verify_otp'))
    return render_template('signup.html')


@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        email = session.get('signup_email')
        otp_hash = session.get('otp_hash')
        if not email or not otp_hash:
            return "Invalid OTP! Please try again."

        ip = client_ip()
        if session.get('otp_tries', 0) >= 5 or blocked('otp', email.lower(), ip):
            clear_otp_session()
            return "Too many wrong attempts! Please go back and request a new code.", 429

        if now_pkt().timestamp() - session.get('otp_time', 0) > 120:
            clear_otp_session()
            return "OTP has expired! Please go back and resend a new code."

        entered = (request.form.get('otp') or '').strip()
        if hmac.compare_digest(make_otp_hash(email, entered), otp_hash):
            session['otp_verified'] = True
            session.pop('otp_hash', None)
            return redirect(url_for('set_password'))

        session['otp_tries'] = session.get('otp_tries', 0) + 1
        record('otp', email.lower(), ip)
        return "Invalid OTP! Please try again."
    return render_template('verify_otp.html')


@app.route('/set-password', methods=['GET', 'POST'])
def set_password():
    # OTP verify kiye bina is page par aana mana hai
    if not session.get('otp_verified') or not session.get('signup_email'):
        return redirect(url_for('login'))

    if request.method == 'POST':
        password = request.form.get('password') or ''
        confirm_password = request.form.get('confirm_password') or ''
        if password != confirm_password:
            return "Passwords do not match! Please try again."
        if len(password) < 8:
            return "Password must be at least 8 characters long."

        email = session.get('signup_email')
        is_forgot = session.get('is_forgot')

        existing = None
        try:
            existing = supabase.table('users').select("*").eq('email', email).execute()
            hashed = generate_password_hash(password)
            if existing.data:
                supabase.table('users').update({'password': hashed}).eq('email', email).execute()
            else:
                supabase.table('users').insert({'email': email, 'password': hashed}).execute()
        except Exception as e:
            print(f"Database Error: {e}")
            return "Something went wrong! Please try again."

        profile_row = existing.data[0] if (existing is not None and existing.data) else None

        session.clear()
        session.permanent = True
        session['is_logged_in'] = True
        session['doctor_email'] = email

        if is_forgot:
            if profile_row:
                load_profile_into_session(profile_row)
            return redirect(url_for('dashboard'))

        return redirect(url_for('doctor_form'))
    return render_template('set_password.html')


@app.route('/doctor-form', methods=['GET', 'POST'])
def doctor_form():
    if not session.get('is_logged_in'):
        return redirect(url_for('login'))
    if request.method == 'POST':
        doctor_name = request.form.get('doctor_name')
        clinic_name = request.form.get('clinic_name')
        clinic_phone = request.form.get('clinic_phone')
        clinic_address = request.form.get('clinic_address') or ''
        consultation_fee = request.form.get('fee')
        specialization = request.form.get('specialization')

        session['doctor_name'] = doctor_name
        session['clinic_name'] = clinic_name
        session['clinic_phone'] = clinic_phone
        session['clinic_address'] = clinic_address
        session['consultation_fee'] = consultation_fee
        session['specialization'] = specialization

        email = session.get('doctor_email')
        try:
            supabase.table('users').update({
                'doctor_name': doctor_name,
                'clinic_name': clinic_name,
                'clinic_phone': clinic_phone,
                'clinic_address': clinic_address,
                'consultation_fee': consultation_fee,
                'specialization': specialization
            }).eq('email', email).execute()
        except Exception as e:
            print(f"Profile full update failed: {e}")
            supabase.table('users').update({
                'doctor_name': doctor_name,
                'clinic_name': clinic_name
            }).eq('email', email).execute()

        return redirect(url_for('dashboard'))
    return render_template('doctor_form.html')


# ------------------------------------------------------------------
# Live token helpers
# ------------------------------------------------------------------
def read_current_token(email):
    try:
        res = supabase.table('queue_status').select("*").eq('doctor_email', email).execute()
        if res.data and res.data[0].get('date') == today_pkt():
            return res.data[0].get('current_token') or 0
    except Exception as e:
        print(f"read_current_token error: {e}")
    return 0


def doctor_from_device(mac, key):
    if not mac or not key:
        return None
    mac = mac.strip().upper()
    res = supabase.table('users').select("email, device_key").eq('esp_mac', mac).execute()
    if res.data and hmac.compare_digest(str(res.data[0].get('device_key') or ''), str(key)):
        return res.data[0]['email']
    return None


@app.route('/dashboard')
def dashboard():
    if not session.get('is_logged_in'):
        return redirect(url_for('login'))
    clinic_name = session.get('clinic_name', 'CliqSlip Clinic')
    doctor_name = session.get('doctor_name', 'Doctor')
    current_token = read_current_token(session.get('doctor_email'))
    return render_template('dashboard.html', clinic_name=clinic_name,
                           doctor_name=doctor_name, current_token=current_token)


@app.route('/bluetooth')
def bluetooth():
    if not session.get('is_logged_in'):
        return redirect(url_for('login'))
    clinic_name = session.get('clinic_name', 'CliqSlip Clinic')
    doctor_name = session.get('doctor_name', 'Doctor')
    return render_template('bluetooth.html', clinic_name=clinic_name, doctor_name=doctor_name)


@app.route('/api/next-token', methods=['POST'])
def api_next_token():
    data = request.get_json(silent=True) or {}
    email = doctor_from_device(data.get('mac'), data.get('key'))
    if not email:
        return {'ok': False, 'error': 'unauthorized'}, 401
    new_token = read_current_token(email) + 1
    supabase.table('queue_status').upsert({
        'doctor_email': email,
        'current_token': new_token,
        'date': today_pkt()
    }).execute()
    return {'ok': True, 'current_token': new_token}


@app.route('/api/current-token')
def api_current_token():
    email = doctor_from_device(request.args.get('mac'), request.args.get('key'))
    if not email and session.get('is_logged_in'):
        email = session.get('doctor_email')
    if not email:
        return {'ok': False}, 401
    return {'ok': True, 'current_token': read_current_token(email)}


@app.route('/manual-next-token', methods=['POST'])
def manual_next_token():
    if not session.get('is_logged_in'):
        return {'ok': False}, 401
    email = session.get('doctor_email')
    new_token = read_current_token(email) + 1
    supabase.table('queue_status').upsert({
        'doctor_email': email,
        'current_token': new_token,
        'date': today_pkt()
    }).execute()
    return {'ok': True, 'current_token': new_token}


# ------------------------------------------------------------------
# Slip generate + print (Safe DB Insert & Live Queue Sync)
# ------------------------------------------------------------------
@app.route('/generate-slip', methods=['POST'])
def generate_slip():
    if not session.get('is_logged_in'):
        return redirect(url_for('login'))

    now = now_pkt()
    current_date = now.strftime("%Y-%m-%d")
    current_time = now.strftime("%I:%M %p")
    email = session.get('doctor_email')

    token_number = 1
    try:
        res = supabase.table('patients').select("token").eq('doctor_email', email).eq('date', current_date).execute()
        nums = [int(r['token']) for r in (res.data or []) if str(r.get('token', '')).isdigit()]
        token_number = max(nums, default=0) + 1
    except Exception as e:
        print(f"Token read error: {e}")

    slip_data = {
        'token_number': token_number,
        'date': current_date,
        'time': current_time,
        'patient_name': clip(request.form.get('patient_name'), 100),
        'patient_age': clip(request.form.get('patient_age'), 50),
        'gender': clip(request.form.get('patient_gender'), 50),
        'patient_phone': clip(request.form.get('patient_phone'), 50),
        'blood_pressure': clip(request.form.get('blood_pressure'), 50),
        'heart_rate': clip(request.form.get('heart_rate'), 50),
        'sugar': clip(request.form.get('sugar'), 50),
        'notes': clip(request.form.get('notes'), 1000),
        'saved': True
    }

    try:
        insert_data = {
            'doctor_email': email,
            'token': str(token_number),
            'date': current_date,
            'patient_name': slip_data.get('patient_name'),
            'phone': slip_data.get('patient_phone'),
            'bp': slip_data.get('blood_pressure'),
            'sugar': slip_data.get('sugar'),
            'time': current_time,
            'patient_age': slip_data.get('patient_age'),
            'gender': slip_data.get('gender'),
            'heart_rate': slip_data.get('heart_rate'),
            'notes': slip_data.get('notes')
        }

        supabase.table('patients').insert(insert_data).execute()

        supabase.table('queue_status').upsert({
            'doctor_email': email,
            'current_token': token_number,
            'date': current_date
        }).execute()

    except Exception as e:
        print(f"Patient save error: {e}")
        slip_data['saved'] = False

    session['latest_slip'] = slip_data
    return redirect(url_for('print_slip'))


def clean_doctor_name(name):
    return re.sub(r'^\s*dr\.?\s*', '', name or '', flags=re.I).strip() or 'Doctor'


def build_escpos(slip, clinic_name, doctor_name, clinic_phone, specialization, fee):
    W = 32

    def enc(s):
        return str(s).encode('ascii', 'replace')

    def line(s=''):
        return enc(s) + b'\n'

    def val(v):
        return v if v not in (None, '') else 'N/A'

    sep = line('-' * W)
    BOLD_ON, BOLD_OFF = b'\x1b\x45\x01', b'\x1b\x45\x00'
    BIG_ON, BIG_OFF = b'\x1d\x21\x11', b'\x1d\x21\x00'
    CENTER, LEFT = b'\x1b\x61\x01', b'\x1b\x61\x00'

    out = b'\x1b\x40'
    out += CENTER
    out += BOLD_ON + BIG_ON + line(f"TOKEN {slip['token_number']}") + BIG_OFF + BOLD_OFF
    out += sep
    out += BOLD_ON + line(clinic_name) + BOLD_OFF
    out += line(f"Dr. {doctor_name}")
    if specialization:
        out += line(specialization)
    if clinic_phone:
        out += line(f"Ph: {clinic_phone}")
    out += LEFT
    out += sep
    out += line(f"Patient: {val(slip.get('patient_name'))}")
    out += line(f"Age/Sex: {val(slip.get('patient_age'))} / {val(slip.get('gender'))}")
    out += line(f"Phone: {val(slip.get('patient_phone'))}")
    out += line(f"Date: {slip.get('date')} {slip.get('time')}")
    out += sep
    out += line(f"BP: {val(slip.get('blood_pressure'))}")
    out += line(f"Sugar: {val(slip.get('sugar'))}")
    out += line(f"Pulse: {val(slip.get('heart_rate'))}")
    out += line(f"Symptoms: {val(slip.get('notes'))}")
    out += sep
    out += line(f"Fee: {val(fee)} Rs")
    out += CENTER
    out += line('Thank you! Get well soon.')
    out += b'\n\n\n'
    return out


@app.route('/print-slip')
def print_slip():
    if not session.get('is_logged_in'):
        return redirect(url_for('login'))
    slip_data = session.get('latest_slip')
    if not slip_data:
        return redirect(url_for('dashboard'))

    clinic_name = session.get('clinic_name') or 'CliqSlip Clinic'
    doctor_name = clean_doctor_name(session.get('doctor_name'))
    clinic_phone = session.get('clinic_phone') or ''
    consultation_fee = session.get('consultation_fee') or ''
    specialization = session.get('specialization') or ''

    raw = build_escpos(slip_data, clinic_name, doctor_name, clinic_phone, specialization, consultation_fee)
    rawbt_data = base64.b64encode(raw).decode('ascii')

    return render_template('print_slip.html',
                           slip=slip_data,
                           clinic_name=clinic_name,
                           doctor_name=doctor_name,
                           clinic_phone=clinic_phone,
                           consultation_fee=consultation_fee,
                           specialization=specialization,
                           rawbt_data=rawbt_data)


# ------------------------------------------------------------------
# Database pages
# ------------------------------------------------------------------
@app.route('/database')
def database():
    if not session.get('is_logged_in'):
        return redirect(url_for('login'))

    doctor_email = session.get('doctor_email')
    clinic_name = session.get('clinic_name', 'CliqSlip Clinic')

    res = supabase.table('patients').select("*").eq('doctor_email', doctor_email).execute()
    PATIENT_RECORDS = res.data or []

    current_year = now_pkt().year
    selected_year = request.args.get('year', str(current_year))
    try:
        selected_year = int(selected_year)
    except Exception:
        selected_year = current_year

    years_set = {current_year, 2026}
    for r in PATIENT_RECORDS:
        try:
            dt = datetime.strptime(r['date'], "%Y-%m-%d")
            years_set.add(dt.year)
        except Exception:
            pass

    available_years = sorted(list(years_set))

    months_list = []
    for month_num in range(1, 13):
        month_name = calendar.month_name[month_num]
        month_key = f"{month_name} {selected_year}"

        count = 0
        for r in PATIENT_RECORDS:
            try:
                dt = datetime.strptime(r['date'], "%Y-%m-%d")
                if dt.year == selected_year and dt.month == month_num:
                    count += 1
            except Exception:
                pass

        months_list.append({
            'name': month_name,
            'month_year': month_key,
            'month_num': month_num,
            'count': count
        })

    return render_template('database_month.html',
                           months=months_list,
                           selected_year=selected_year,
                           available_years=available_years,
                           clinic_name=clinic_name)


@app.route('/database/month/<path:month_year>')
def database_month_detail(month_year):
    if not session.get('is_logged_in'):
        return redirect(url_for('login'))

    doctor_email = session.get('doctor_email')
    clinic_name = session.get('clinic_name', 'CliqSlip Clinic')
    res = supabase.table('patients').select("*").eq('doctor_email', doctor_email).execute()
    PATIENT_RECORDS = res.data or []

    try:
        cleaned_month_year = month_year.replace('%20', ' ')
        parts = cleaned_month_year.split()
        month_name = parts[0]
        year = int(parts[1])
        month_num = list(calendar.month_name).index(month_name)
    except Exception as e:
        print(f"Error parsing month_year: {e}")
        return "Invalid month.", 400

    num_days = calendar.monthrange(year, month_num)[1]
    dates_list = []
    for day in range(1, num_days + 1):
        dt = datetime(year, month_num, day)
        date_str = dt.strftime("%Y-%m-%d")
        display_date = dt.strftime("%d %b %Y")
        day_records = [r for r in PATIENT_RECORDS if r.get('date') == date_str or str(r.get('date', '')).startswith(date_str)]

        dates_list.append({
            'date_str': date_str,
            'display_date': display_date,
            'count': len(day_records)
        })

    return render_template('database_dates.html',
                           month_year=month_year,
                           dates=dates_list,
                           clinic_name=clinic_name)


@app.route('/database/date/<date_str>')
def database_date_detail(date_str):
    if not session.get('is_logged_in'):
        return redirect(url_for('login'))

    doctor_email = session.get('doctor_email')
    clinic_name = session.get('clinic_name', 'CliqSlip Clinic')

    res = supabase.table('patients').select("*").eq('doctor_email', doctor_email).execute()
    all_records = res.data or []

    date_records = []
    for r in all_records:
        r_date = str(r.get('date', ''))
        if r_date == date_str or r_date.startswith(date_str):
            r['token_number'] = r.get('token')
            r['patient_phone'] = r.get('phone')
            r['blood_pressure'] = r.get('bp')
            date_records.append(r)

    total_patients = len(date_records)

    return render_template('database_patients.html',
                           date_str=date_str,
                           records=date_records,
                           total_patients=total_patients,
                           clinic_name=clinic_name)


# ------------------------------------------------------------------
# Settings / ESP32 MAC
# ------------------------------------------------------------------
@app.route('/save-mac', methods=['POST'])
def save_mac():
    if not session.get('is_logged_in'):
        return redirect(url_for('login'))
    esp_mac = (request.form.get('esp_mac') or '').strip().upper()[:32]
    doctor_email = session.get('doctor_email')

    try:
        update = {'esp_mac': esp_mac}
        cur = supabase.table('users').select("device_key").eq('email', doctor_email).execute()
        if not (cur.data and cur.data[0].get('device_key')):
            update['device_key'] = secrets.token_hex(16)
        supabase.table('users').update(update).eq('email', doctor_email).execute()
    except Exception as e:
        print(f"Error saving MAC: {e}")

    return redirect(url_for('settings'))


@app.route('/settings')
def settings():
    if not session.get('is_logged_in'):
        return redirect(url_for('login'))

    doctor_email = session.get('doctor_email')
    esp_mac = ""
    device_key = ""
    try:
        res = supabase.table('users').select("*").eq('email', doctor_email).execute()
        if res.data:
            esp_mac = res.data[0].get('esp_mac') or ''
            device_key = res.data[0].get('device_key') or ''
    except Exception as e:
        print(f"Settings read error: {e}")

    return render_template('settings.html', esp_mac=esp_mac, device_key=device_key)


@app.route('/about')
def about():
    return render_template('about.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=os.environ.get('FLASK_DEBUG') == '1', host='0.0.0.0', port=5000)