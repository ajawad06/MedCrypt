from flask import Flask,render_template,url_for,request,redirect,session
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from cryptography.fernet import Fernet
import hashlib
from werkzeug.security import check_password_hash,generate_password_hash
from config import FERNET_KEY, SECRET_KEY, DATABASE_URI

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
    keywords_hash = db.Column(db.Text)
    def __repr__(self):
        return f"<MedicalRecord id={self.id} patient_id={self.patient_id}>"


# 1. BASE PAGE i.e. Login 
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['role'] = user.role
            return redirect(url_for('dashboard'))
        else:
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

        # Hash each keyword individually
        keyword_list = [k.strip().lower() for k in keywords.split(',')]
        keyword_hashes = [hashlib.sha256(k.encode()).hexdigest() for k in keyword_list]
        keyword_hash_string = ','.join(keyword_hashes)

        # Create record with doctor and nurse assignment
        record = MedicalRecord(
            patient_id=patient_id,
            doctor_id=doctor_id,
            nurse_id=nurse_id,
            name=encrypted_name,
            symptoms=encrypted_symptoms,
            diagnosis=encrypted_diagnosis,
            keywords_hash=keyword_hash_string
        )

        db.session.add(record)
        db.session.commit()
        return redirect(url_for('doctor_dashboard'))

    patients = User.query.filter_by(role='patient').all()
    nurses = User.query.filter_by(role='nurse').all()
    records = MedicalRecord.query.all()
    return render_template('doctor_dashboard.html', records=records, decrypt=fernet.decrypt, patients=patients, nurses=nurses)

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
        # Update keywords if user entered something
        if keywords != "":
            # Split by comma → hash individually
            key_list = [k.strip().lower() for k in keywords.split(',') if k.strip()]
            key_hashes = [hashlib.sha256(k.encode()).hexdigest() for k in key_list]
            # Save comma-separated list of hashes
            record.keywords_hash = ",".join(key_hashes)
        try:
            db.session.commit()
            return redirect(url_for('doctor_dashboard'))
        except Exception as e:
            return f"There was a problem updating this record: {e}"

    return render_template('update_record.html', record=record, decrypt=fernet.decrypt)



# 2.1.E. DR SEARCHES RECORD
@app.route('/search_record', methods=['GET', 'POST'])
def search_record():
    if session.get('role') != 'doctor':
        return "Access Denied", 403

    matched_records = []
    if request.method == 'POST':
        keyword = request.form['keyword'].strip().lower()
        keyword_hash = hashlib.sha256(keyword.encode()).hexdigest()
        # Match any record where the hash appears in the comma-separated string
        matched_records = MedicalRecord.query.filter(
            MedicalRecord.keywords_hash.like(f"%{keyword_hash}%")
        ).all()

    return render_template('search_record.html', records=matched_records, decrypt=fernet.decrypt) 

# 2.2 NURSE DASHBOARD --- ye complete krne wla
@app.route('/nurse')
def nurse_dashboard():
    pass


# 2.3 PATIENT DASHBOARD
@app.route('/patient')
def patient_dashboard():
    if session.get('role') != 'patient':
        return "Access Denied", 403

    patient_id = session.get('user_id')
    records = MedicalRecord.query.filter_by(patient_id=patient_id).all()

    return render_template('patient_dashboard.html', records=records, decrypt=fernet.decrypt)


# 3. LOGOUT
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__=="__main__":
    app.run(debug=True)


## --- WORK LEFT ---

# 1. Nurse Dashboard: Only assigned records (excluding diagnosis)
# 2. Nurse or Dr IDs ki jgh onke names dikhany in html tables using SQL JOINS statements 
# 3. Use HMAC instead of SHA256 everywhere => concept of SSE used i.e. search tokens using HMAC
# 4. Audit Logs - Detail Below
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
