from flask import Flask, render_template, url_for, request, redirect, session
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from cryptography.fernet import Fernet
from werkzeug.security import check_password_hash, generate_password_hash
from sqlalchemy.orm import aliased


import hashlib     # for HMAC hashing
import hmac        # for HMAC function

from config import FERNET_KEY, SECRET_KEY, DATABASE_URI, HMAC_KEY


# HMAC FUNCTION TO COMPUTE HMAC OF A KEYWORD
def compute_hmac(keyword: str):
    return hmac.new(
        HMAC_KEY.encode(),
        keyword.encode(),
        hashlib.sha256
    ).hexdigest()
# LOGGING FUNCTION
def log_action(user_id, action, record_id=None):
    timestamp = datetime.utcnow()

    log_hash = compute_log_hash(user_id, record_id, action, timestamp)

    log = AuditLog(
        user_id=user_id,
        action=action,
        record_id=record_id,
        timestamp=timestamp,
        ip_address=request.remote_addr,
        log_hash=log_hash
    )
    db.session.add(log)
    db.session.commit()

 # Compute tamper-evident hash
def compute_log_hash(user_id, record_id, action, timestamp):
    message = f"{user_id}|{record_id}|{action}|{timestamp}"
    return hmac.new(
        HMAC_KEY.encode(),
        message.encode(),
        hashlib.sha256
    ).hexdigest()

# FLASK APP BASIC CONFIGURATION
# 1. APP
app=Flask(__name__)
# 2. DB
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URI
db=SQLAlchemy(app)
# 3. FERNET KEY
fernet = Fernet(FERNET_KEY.encode())
# 4. SESSION KEY
app.secret_key = SECRET_KEY


# USER COLUMN IN DB
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True,autoincrement=True)
    username = db.Column(db.String(80), unique=True)
    password_hash = db.Column(db.String(128))
    role = db.Column(db.String(10))  # 'doctor', 'nurse', 'patient'
    def __repr__(self):
        return f"<User {self.username} ({self.role})>"

# RECORD COLUMN IN DB
class MedicalRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True,autoincrement=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    name = db.Column(db.LargeBinary)
    symptoms = db.Column(db.LargeBinary)
    diagnosis = db.Column(db.LargeBinary)
    doctor_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    nurse_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    keywords_hmac = db.Column(db.Text)
    

    patient = db.relationship('User', foreign_keys=[patient_id], backref='patient_records')
    doctor = db.relationship('User', foreign_keys=[doctor_id], backref='doctor_records')
    nurse = db.relationship('User', foreign_keys=[nurse_id], backref='nurse_records')


    def __repr__(self):
        return f"<MedicalRecord id={self.id} patient_id={self.patient_id}>"


@app.route('/', methods=['GET', 'POST'])
def login():
    user = None   # ← FIX: define user so it's always available

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['role'] = user.role

            log_action(user.id, "Login successful")
            return redirect(url_for('dashboard'))
        else:
            log_action(None, f"Failed login for username={username}")
            return render_template('login.html', error="Invalid username or password")

    return render_template('login.html')


# 2. DISPLAY DASHBOARD FOR CURRENT USER
@app.route('/dashboard')
def dashboard():
    role = session.get('role')
    if role == 'doctor':
        return redirect(url_for('doctor_dashboard'))
    elif role == 'nurse':
        return redirect(url_for('nurse_dashboard'))
    elif role == 'patient':
        return redirect(url_for('patient_dashboard'))
    else:
        return redirect(url_for('login'))
    
# 2.1 DR DASHBOARD
@app.route('/doctor', methods=['GET', 'POST'])
def doctor_dashboard():
    if session.get('role') != 'doctor':
        return "Access Denied", 403

    # ⭐ ADD THIS — Log dashboard access
    log_action(session['user_id'], "Accessed doctor dashboard")

    if request.method == 'POST':
        doctor_id = session.get('user_id')
        name = request.form['name']
        symptoms = request.form['symptoms']
        diagnosis = request.form['diagnosis']
        keywords = request.form['keywords']
        nurse_id = int(request.form['nurse_id'])
        patient_id = int(request.form['patient_id'])

        # Encrypt fields
        encrypted_name = fernet.encrypt(name.encode())
        encrypted_symptoms = fernet.encrypt(symptoms.encode())
        encrypted_diagnosis = fernet.encrypt(diagnosis.encode())

        # Hash keywords
        keyword_list = [k.strip().lower() for k in keywords.split(',')]
        keyword_hmacs = [compute_hmac(k) for k in keyword_list]
        keyword_hmac_string = ",".join(keyword_hmacs)

        # Create record
        record = MedicalRecord(
            patient_id=patient_id,
            doctor_id=doctor_id,
            nurse_id=nurse_id,
            name=encrypted_name,
            symptoms=encrypted_symptoms,
            diagnosis=encrypted_diagnosis,
            keywords_hmac=keyword_hmac_string
        )

        db.session.add(record)
        db.session.commit()
        log_action(doctor_id, "Created medical record", record.id)

        return redirect(url_for('doctor_dashboard'))

    patients = User.query.filter_by(role='patient').all()
    nurses = User.query.filter_by(role='nurse').all()
    records = MedicalRecord.query.all()

    return render_template(
        'doctor_dashboard.html',
        records=records,
        decrypt=fernet.decrypt,
        patients=patients,
        nurses=nurses
    )

# 4. AUDIT LOG MODEL
class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer)
    record_id = db.Column(db.Integer, nullable=True)
    action = db.Column(db.String(255))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(50))
    log_hash = db.Column(db.String(128))  #  Tamper-evident hash
    def __repr__(self):
        return f"<AuditLog {self.user_id} - {self.action}>"

# 2.1.A. DR ADDS PATIENT
@app.route('/register_patient', methods=['POST'])
def register_patient():
    if session.get('role') != 'doctor':
        return "Access Denied", 403

    username = request.form['username']
    password = request.form['password']

    # Check if username already exists
    if User.query.filter_by(username=username).first():
        # Redirect back with flash message
        return redirect(url_for('doctor_dashboard', error="Username already exists"))

    hashed_pw = generate_password_hash(password)
    new_patient = User(username=username, password_hash=hashed_pw, role='patient')
    db.session.add(new_patient)
    db.session.commit()
    log_action(session['user_id'], f"Registered patient username={username}")
    return redirect(url_for('doctor_dashboard'))

#2.1.B. DR REMOVES PATIENT
@app.route('/remove_patient/<int:id>')
def remove_patient(id):
    if session.get('role') != 'doctor':
        return "Access Denied", 403

    patient = User.query.get_or_404(id)
    if patient.role != 'patient':
        return "Only patients can be removed.", 400

    try:
        # Records + Patient delete
        MedicalRecord.query.filter_by(patient_id=patient.id).delete()
        db.session.delete(patient)

        db.session.commit()
        log_action(session['user_id'], f"Removed patient_id={id}")
        return redirect(url_for('doctor_dashboard'))
    except:
        return redirect(url_for('doctor_dashboard'))

# 2.1.C. DR DELETES RECORD
@app.route('/delete_record/<int:id>')
def delete_record(id):
    record_to_delete=MedicalRecord.query.get_or_404(id)
    try:
        db.session.delete(record_to_delete)
        db.session.commit()
        log_action(session['user_id'], "Deleted record", id)

        return redirect("/doctor")
    except: 
        return "There was a problem deleting this record"

# 2.1.D DR UPDATES RECORD
@app.route('/update_record/<int:id>', methods=['GET', 'POST'])
def update_record(id):
    if session.get('role') != 'doctor':
        return "Access Denied", 403

    record = MedicalRecord.query.get_or_404(id)

    if request.method == 'POST':
        name = request.form['name']
        symptoms = request.form['symptoms']
        diagnosis = request.form['diagnosis']
        keywords = request.form.get('keywords', '').strip()

        # Encrypt updated fields 
        record.name = fernet.encrypt(name.encode())
        record.symptoms = fernet.encrypt(symptoms.encode())
        record.diagnosis = fernet.encrypt(diagnosis.encode())

        # Update keywords ONLY if user entered new ones
        if keywords != "":
            key_list = [k.strip().lower() for k in keywords.split(',') if k.strip()]
            record.keywords_hmac = ",".join([compute_hmac(k) for k in key_list])

        try:
            db.session.commit()
            log_action(session['user_id'], "Updated record", id)

            return redirect(url_for('doctor_dashboard'))
        except Exception as e:
            return f"There was a problem updating this record: {e}"

    return render_template('update_record.html', record=record, decrypt=fernet.decrypt)

# 2.1.E. DR SEARCHES RECORD
@app.route('/search_record', methods=['GET', 'POST'])
def search_record():
    if session.get('role') != 'doctor':
        log_action(session.get('user_id'), "Unauthorized doctor panel access attempt")
        
        return "Access Denied", 403
        log_action(session['user_id'], "Accessed doctor dashboard")

    matched_records = []
    if request.method == 'POST':
        keyword = request.form['keyword'].strip().lower()
        keyword_hmac = compute_hmac(keyword)
        log_action(session['user_id'], f"Searched keyword={keyword}")

        matched_records = MedicalRecord.query.filter(
            MedicalRecord.keywords_hmac.like(f"%{keyword_hmac}%")
        ).all()

    return render_template('search_record.html', records=matched_records, decrypt=fernet.decrypt)

@app.route('/nurse')
def nurse_dashboard():
    if session.get('role') != 'nurse':
        return "Access Denied", 403
    log_action(session['user_id'], "Accessed nurse dashboard")

    nurse_id = session.get('user_id')

    # Fetch ONLY records assigned to this nurse
    records = MedicalRecord.query.filter_by(nurse_id=nurse_id).all()

    return render_template(
        'nurse_dashboard.html',
        records=records,
        decrypt=fernet.decrypt
    )




# 2.3 PATIENT DASHBOARD
@app.route('/patient')
def patient_dashboard():
    if session.get('role') != 'patient':
        return "Access Denied", 403
    log_action(session['user_id'], "Accessed patient dashboard")
    patient_id = session.get('user_id')
    records = MedicalRecord.query.filter_by(patient_id=patient_id).all()

    return render_template('patient_dashboard.html', records=records, decrypt=fernet.decrypt)


# 3. LOGOUT
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))
@app.route('/debug_hmac')
def debug_hmac():
    records = MedicalRecord.query.all()
    html = "<h2>HMAC Tokens</h2>"
    for r in records:
        html += f"<p>Record {r.id}: {r.keywords_hmac}</p>"
    return html
# 4. AUDIT LOGS VIEWER
@app.route('/audit_logs')
def audit_logs():
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).all()
    html = "<h2>Audit Logs</h2><hr>"
    for log in logs:
        html += f"<p><b>User:</b> {log.user_id} | <b>Action:</b> {log.action} | <b>IP:</b> {log.ip_address} | <b>Time:</b> {log.timestamp}</p>"
    return html
@app.route('/verify_audit_logs')
def verify_logs():
    logs = AuditLog.query.all()
    result = "<h2>Audit Log Verification</h2><hr>"

    for log in logs:
        recalculated = compute_log_hash(
            log.user_id, log.record_id, log.action, log.timestamp
        )

        if recalculated == log.log_hash:
            result += f"<p style='color:green;'>✔ Log {log.id} OK</p>"
        else:
            result += f"<p style='color:red;'>❌ Log {log.id} TAMPERED!</p>"

    return result



if __name__=="__main__":
    app.run(debug=True)


## --- WORK LEFT ---

# 1. Nurse Dashboard: Only assigned records (excluding diagnosis)✔️
# 2. Nurse or Dr IDs ki jgh onke names dikhany in html tables using SQL JOINS statements ✔️
# 3. Use HMAC instead of SHA256 everywhere => concept of SSE used i.e. search tokens using HMAC ✔️
# 4. Audit Logs - Detail Below ✔️
# 5. Record Integrity Hashing - Detail Below
# 6. Dummy Keywords - Detail Below



##  --- INFO SECURITY MEASURES ---

# 1. CONFIDENTIALITY:
        # 1. Role-Based Access Control (RBAC): Each user sees only permitted data
                # - Doctor: All records and fields
                # - Nurse: Only assigned records (excluding diagnosis)
                # - Patient: Only their own records
        # 2. Field-Level Encryption: All sensitive fields (name, symptoms, diagnosis) are encrypted using Fernet (AES-128)
        # 3. Secure Keyword Search:
                # - Real keywords are hashed using HMAC with a secret key
                # - Dummy keyword hashes are added to prevent offline guessing and frequency analysis

# 2. INTEGRITY:
        # 1. Record Integrity Hashing:
                # integrity_hash = SHA256(patient_id + doctor_id + nurse_id + encrypted_fields)
                # On access, the hash is recomputed and verified to detect tampering
        # 2. Controlled Updates: Only doctors can modify records; others have read-only access
        # 3. Tamper-Evident Audit Logs:
                # Each access/modification is logged with:
                # log_hash = HMAC(secret_key, f"{user_id}|{record_id}|{action}|{timestamp}")

# 3. AVAILABILITY:
        # 1. Role-Specific Dashboards: Separate views for doctor, nurse, and patient ensure focused access
        # 2. Lightweight Database: SQLite used for simplicity; can be upgraded to PostgreSQL for scalability


# --- INNOVATIVE FEATURES ---

# 1. Dummy Keyword Padding: Prevents keyword count leakage & frequency analysis
# 2. Record Integrity Hashing: Detects tampering of encrypted fields
# 3. Search Tokens (SSE-lite): Secure keyword search using HMAC tokens
