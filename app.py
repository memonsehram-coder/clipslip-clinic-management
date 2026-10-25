from flask import Flask, render_template, request, redirect, url_for, session
from datetime import timedelta, datetime, timezone
import calendar
import random
import smtplib
import secrets
import base64
import re
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from supabase import create_client, Client

app = Flask(__name__)
# Vercel > Settings > Environment Variables mein SECRET_KEY zaroor set karein
app.secret_key = os.environ.get("SECRET_KEY", "change-this-secret-in-vercel")

# Supabase Configuration
SUPABASE_URL = os.environ.get("SUPABASE_URL", "https://ihcghpiezdvnomfxvetu.supabase.co")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY", "YAHAN_APNI_SUPABASE_ANON_KEY_PASTE_KAREIN")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# Session ko 1 saal tak permanent rakhne ke liye
app.permanent_session_lifetime = timedelta(days=365)

PKT = timezone(timedelta(hours=5))


@app.before_request
def make_session_permanent():
    session.permanent = True


def now_pkt():
    return datetime.now(PKT)


def today_pkt():
    return now_pkt().strftime("%Y-%m-%d")


# ------------------------------------------------------------------
# Email OTP (password ab environment variable se aayega, code mein nahi)
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
        email = request.form.get('email')
        password = request.form.get('password')

        response = supabase.table('users').select("*").eq('email', email).execute()
        users = response.data

        if users and users[0]['password'] == password:
            session['is_logged_in'] = True
            session['doctor_email'] = email
            load_profile_into_session(users[0])
            return redirect(url_for('dashboard'))
        else:
            return "Invalid Email or Password! Please try again."
    return render_template('login.html')


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        response = supabase.table('users').select("*").eq('email', email).execute()
        if response.data:
            otp = random.randint(100000, 999999)
            session['signup_email'] = email
            session['email_otp'] = otp
            session['is_forgot'] = True
            session['otp_time'] = now_pkt().timestamp()
            send_email_otp(email, otp)
            return redirect(url_for('verify_otp'))
        else:
            return "Email not found in database! Please check again."
    return render_template('forgot_password.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')

        existing_user = supabase.table('users').select("*").eq('email', email).execute()
        if existing_user.data:
            return render_template('signup.html', error="This email is already registered! Please sign in instead.")

        session['signup_email'] = email
        otp = random.randint(100000, 999999)
        session['email_otp'] = otp
        session['otp_time'] = now_pkt().timestamp()

        send_email_otp(email, otp)
        return redirect(url_for('verify_otp'))
    return render_template('signup.html')


@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        user_entered_otp = request.form.get('otp')
        otp_time = session.get('otp_time', 0)
        current_time = now_pkt().timestamp()

        if current_time - otp_time > 120:
            return "OTP has expired! Please go back and resend a new code."

        try:
            entered = int(user_entered_otp)
        except (TypeError, ValueError):
            return "Invalid OTP! Please try again."

        if entered == session.get('email_otp'):
            return redirect(url_for('set_password'))
        else:
            return "Invalid OTP! Please try again."
    return render_template('verify_otp.html')


@app.route('/set-password', methods=['GET', 'POST'])
def set_password():
    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        if password != confirm_password:
            return "Passwords do not match! Please try again."

        email = session.get('signup_email')
        if not email:
            return "Session expired! Please go back to signup or login and try again."

        existing = None
        try:
            existing = supabase.table('users').select("*").eq('email', email).execute()

            if existing.data:
                supabase.table('users').update({'password': password}).eq('email', email).execute()
            else:
                supabase.table('users').insert({'email': email, 'password': password}).execute()
        except Exception as e:
            return f"Database Error: {str(e)}"

        session['is_logged_in'] = True
        session['doctor_email'] = email

        if session.get('is_forgot'):
            session.pop('is_forgot', None)
            if existing and existing.data:
                load_profile_into_session(existing.data[0])
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
            # Agar naye columns abhi Supabase mein nahi bane to kam az kam naam save ho jaye
            print(f"Profile full update failed: {e}")
            supabase.table('users').update({
                'doctor_name': doctor_name,
                'clinic_name': clinic_name
            }).eq('email', email).execute()

        return redirect(url_for('dashboard'))
    return render_template('doctor_form.html')


# ------------------------------------------------------------------
# Live token (serving token) helpers - ESP32 + website yahin se sync hote hain
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
    if res.data and res.data[0].get('device_key') == key:
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


# Button wala ESP32 yeh route call karega (POST JSON: mac, key)
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


# LCD wala ESP32 (?mac=...&key=...) aur website dashboard (login session) dono yeh call karte hain
@app.route('/api/current-token')
def api_current_token():
    email = doctor_from_device(request.args.get('mac'), request.args.get('key'))
    if not email and session.get('is_logged_in'):
        email = session.get('doctor_email')
    if not email:
        return {'ok': False}, 401
    return {'ok': True, 'current_token': read_current_token(email)}


# ------------------------------------------------------------------
# Slip generate + print
# ------------------------------------------------------------------
@app.route('/generate-slip', methods=['POST'])
def generate_slip():
    if not session.get('is_logged_in'):
        return redirect(url_for('login'))

    now = now_pkt()
    current_date = now.strftime("%Y-%m-%d")
    current_time = now.strftime("%I:%M %p")
    email = session.get('doctor_email')

    # Aaj ka agla token database se nikalo (global variable Vercel par kaam nahi karta)
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
        'patient_name': request.form.get('patient_name'),
        'patient_age': request.form.get('patient_age'),
        'gender': request.form.get('patient_gender'),
        'patient_phone': request.form.get('patient_phone'),
        'blood_pressure': request.form.get('blood_pressure'),
        'heart_rate': request.form.get('heart_rate'),
        'sugar': request.form.get('sugar'),
        'notes': request.form.get('notes'),
        'saved': True
    }

    # Database mein save karo. Fail ho bhi jaye to print block nahi hoga.
    try:
        supabase.table('patients').insert({
            'doctor_email': email,
            'token': str(token_number),
            'date': current_date,
            'time': current_time,
            'patient_name': slip_data['patient_name'],
            'patient_age': slip_data['patient_age'],
            'gender': slip_data['gender'],
            'phone': slip_data['patient_phone'],
            'bp': slip_data['blood_pressure'],
            'heart_rate': slip_data['heart_rate'],
            'sugar': slip_data['sugar'],
            'notes': slip_data['notes']
        }).execute()
    except Exception as e:
        print(f"Patient save error: {e}")
        slip_data['saved'] = False

    session['latest_slip'] = slip_data
    return redirect(url_for('print_slip'))


def clean_doctor_name(name):
    # "Dr. Ali Khan" likha ho to "Dr. Dr. Ali Khan" na bane
    return re.sub(r'^\s*dr\.?\s*', '', name or '', flags=re.I).strip() or 'Doctor'


def build_escpos(slip, clinic_name, doctor_name, clinic_phone, specialization, fee):
    """58mm thermal printer ke liye asli ESC/POS bytes (RawBT inhein seedha print karta hai)."""
    W = 32  # 58mm printer par aam taur par 32 characters per line

    def enc(s):
        # Urdu/special characters thermal printer par garbage na bane, is liye '?' ban jayenge
        return str(s).encode('ascii', 'replace')

    def line(s=''):
        return enc(s) + b'\n'

    def val(v):
        return v if v not in (None, '') else 'N/A'

    sep = line('-' * W)
    BOLD_ON, BOLD_OFF = b'\x1b\x45\x01', b'\x1b\x45\x00'
    BIG_ON, BIG_OFF = b'\x1d\x21\x11', b'\x1d\x21\x00'
    CENTER, LEFT = b'\x1b\x61\x01', b'\x1b\x61\x00'

    out = b'\x1b\x40'  # printer reset
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
# Database (records) pages
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
        return f"Routing Error: {e} (Value received: {month_year})"

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
            # Template ke purane naam (token_number, patient_phone, blood_pressure) ke saath match
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
    esp_mac = (request.form.get('esp_mac') or '').strip().upper()
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
    app.run(debug=True, host='0.0.0.0', port=5000)