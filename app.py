from flask import Flask, render_template, request, redirect, url_for, session
from datetime import timedelta, datetime
import calendar
import random
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

app = Flask(__name__)
app.secret_key = 'cliqslip_secure_clinic_secret_key'

# Session ko 1 saal tak permanent rakhne ke liye
app.permanent_session_lifetime = timedelta(days=365)

@app.before_request
def make_session_permanent():
    session.permanent = True

USER_DATABASE = {} 
PATIENT_RECORDS = []

DAILY_TOKEN_COUNTER = 0
LAST_TOKEN_DATE = None

# Email OTP bhejne ka function (Backend Sender Server)
def send_email_otp(receiver_email, otp):
    # Yahan apni woh Gmail ID aur uska Google App Password likhein jo email bhejegi
    sender_email = "clipslip.official@gmail.com"     
    sender_password = "lscurvemsqtgzsfn"     
    
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

@app.route('/')
@app.route('/login', methods=['GET', 'POST'])
def login():
    if session.get('is_logged_in'):
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        if email in USER_DATABASE and USER_DATABASE[email]['password'] == password:
            session['is_logged_in'] = True
            session['doctor_email'] = email
            session['doctor_name'] = USER_DATABASE[email].get('doctor_name', 'Doctor')
            session['clinic_name'] = USER_DATABASE[email].get('clinic_name', 'CliqSlip Clinic')
            return redirect(url_for('dashboard'))
        else:
            return "Invalid Email or Password! Please try again."
    return render_template('login.html')

# Forgot Password Route
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        if email in USER_DATABASE:
            otp = random.randint(100000, 999999)
            session['signup_email'] = email
            session['email_otp'] = otp
            session['otp_time'] = datetime.now().timestamp()
            send_email_otp(email, otp)
            return redirect(url_for('verify_otp'))
        else:
            return "Email not found in database! Please check again."
    return render_template('forgot_password.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        session['signup_email'] = email
        otp = random.randint(100000, 999999)
        session['email_otp'] = otp
        session['otp_time'] = datetime.now().timestamp()
        
        # User ki di gayi email par OTP bhejna
        send_email_otp(email, otp)
        
        return redirect(url_for('verify_otp'))
    return render_template('signup.html')

@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        user_entered_otp = request.form.get('otp')
        
        # 2 minute (120 seconds) expiry check
        otp_time = session.get('otp_time', 0)
        current_time = datetime.now().timestamp()
        
        if current_time - otp_time > 120:
            return "OTP has expired (Time limit exceeded)! Please go back and resend a new code."
        
        if int(user_entered_otp) == session.get('email_otp'):
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
        USER_DATABASE[email] = {'password': password}
        session['is_logged_in'] = True
        session['doctor_email'] = email
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
        clinic_address = request.form.get('clinic_address')
        consultation_fee = request.form.get('fee')
        specialization = request.form.get('specialization')
        
        session['doctor_name'] = doctor_name
        session['clinic_name'] = clinic_name
        session['clinic_phone'] = clinic_phone
        session['clinic_address'] = clinic_address
        session['consultation_fee'] = consultation_fee
        session['specialization'] = specialization
        
        email = session.get('doctor_email')
        if email in USER_DATABASE:
            USER_DATABASE[email]['doctor_name'] = doctor_name
            USER_DATABASE[email]['clinic_name'] = clinic_name
        return redirect(url_for('dashboard'))
    return render_template('doctor_form.html')

@app.route('/dashboard')
def dashboard():
    if not session.get('is_logged_in'):
        return redirect(url_for('login'))
    clinic_name = session.get('clinic_name', 'CliqSlip Clinic')
    doctor_name = session.get('doctor_name', 'Doctor')
    return render_template('dashboard.html', clinic_name=clinic_name, doctor_name=doctor_name)

@app.route('/bluetooth')
def bluetooth():
    if not session.get('is_logged_in'):
        return redirect(url_for('login'))
    clinic_name = session.get('clinic_name', 'CliqSlip Clinic')
    doctor_name = session.get('doctor_name', 'Doctor')
    return render_template('bluetooth.html', clinic_name=clinic_name, doctor_name=doctor_name)

@app.route('/generate-slip', methods=['POST'])
def generate_slip():
    if not session.get('is_logged_in'):
        return redirect(url_for('login'))
    global DAILY_TOKEN_COUNTER, LAST_TOKEN_DATE, PATIENT_RECORDS
    
    now = datetime.now()
    current_date = now.strftime("%Y-%m-%d")
    current_time = now.strftime("%I:%M %p")
    
    if LAST_TOKEN_DATE != current_date:
        DAILY_TOKEN_COUNTER = 1
        LAST_TOKEN_DATE = current_date
    else:
        DAILY_TOKEN_COUNTER += 1
        
    token_number = DAILY_TOKEN_COUNTER
    
    patient_name = request.form.get('patient_name')
    patient_age = request.form.get('patient_age')
    patient_phone = request.form.get('patient_phone')
    blood_pressure = request.form.get('blood_pressure')
    heart_rate = request.form.get('heart_rate')
    sugar = request.form.get('sugar')
    notes = request.form.get('notes')
    
    slip_data = {
        'token_number': token_number,
        'date': current_date,
        'time': current_time,
        'patient_name': patient_name,
        'patient_age': patient_age,
        'patient_phone': patient_phone,
        'blood_pressure': blood_pressure,
        'heart_rate': heart_rate,
        'sugar': sugar,
        'notes': notes
    }
    
    session['latest_slip'] = slip_data
    PATIENT_RECORDS.insert(0, slip_data)
    return redirect(url_for('print_slip'))

@app.route('/print-slip')
def print_slip():
    if not session.get('is_logged_in'):
        return redirect(url_for('login'))
    slip_data = session.get('latest_slip')
    if not slip_data:
        return redirect(url_for('dashboard'))
        
    clinic_name = session.get('clinic_name', 'CliqSlip Clinic')
    doctor_name = session.get('doctor_name', 'Doctor')
    clinic_phone = session.get('clinic_phone', '0300-0000000')
    clinic_address = session.get('clinic_address', 'Clinic Address')
    consultation_fee = session.get('consultation_fee', '500')
    
    return render_template('print_slip.html', 
                           slip=slip_data, 
                           clinic_name=clinic_name, 
                           doctor_name=doctor_name, 
                           clinic_phone=clinic_phone, 
                           clinic_address=clinic_address, 
                           consultation_fee=consultation_fee)

# --- DATABASE HIERARCHY ROUTES ---

@app.route('/database')
def database():
    if not session.get('is_logged_in'):
        return redirect(url_for('login'))
    
    clinic_name = session.get('clinic_name', 'CliqSlip Clinic')
    current_year = datetime.now().year
    selected_year = request.args.get('year', str(current_year))
    try:
        selected_year = int(selected_year)
    except:
        selected_year = current_year
        
    years_set = {current_year, 2026}
    for r in PATIENT_RECORDS:
        try:
            dt = datetime.strptime(r['date'], "%Y-%m-%d")
            years_set.add(dt.year)
        except:
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
            except:
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
        
    clinic_name = session.get('clinic_name', 'CliqSlip Clinic')
    try:
        parts = month_year.split()
        month_name = parts[0]
        year = int(parts[1])
        month_num = list(calendar.month_name).index(month_name)
    except:
        return redirect(url_for('database'))
        
    num_days = calendar.monthrange(year, month_num)[1]
    dates_list = []
    for day in range(1, num_days + 1):
        dt = datetime(year, month_num, day)
        date_str = dt.strftime("%Y-%m-%d")
        display_date = dt.strftime("%d %b %Y")
        day_records = [r for r in PATIENT_RECORDS if r['date'] == date_str]
        
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
        
    clinic_name = session.get('clinic_name', 'CliqSlip Clinic')
    date_records = [r for r in PATIENT_RECORDS if r['date'] == date_str]
    total_patients = len(date_records)
    
    return render_template('database_patients.html', 
                           date_str=date_str, 
                           records=date_records, 
                           total_patients=total_patients, 
                           clinic_name=clinic_name)

@app.route('/settings')
def settings():
    if not session.get('is_logged_in'):
        return redirect(url_for('login'))
    return render_template('settings.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)