from flask import Flask, render_template, url_for, request, redirect, session
from flask_sqlalchemy import SQLAlchemy
from cryptography.fernet import Fernet
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime, timezone
from config import FERNET_KEY, SECRET_KEY, DATABASE_URI, HMAC_KEY
import hmac, hashlib, base64

# === FLASK APP BASIC CONFIGURATION ===

# 1. APP
app = Flask(__name__)
# 2. DB
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URI
db = SQLAlchemy(app)
# 3. FERNET KEY
fernet = Fernet(FERNET_KEY.encode())
# 4. SESSION KEY
app.secret_key = SECRET_KEY

# === SEARCHABLE SYMMETRIC ENCRYPTION (SSE) ===
#
# Encrypted inverted-index construction (Curtmola et al., SSE-1 style).
#
# Instead of storing every keyword-token of a record together in one blob
# (which leaks the co-occurrence structure of each document), the index is a
# flat table of (label, value) rows where:
#
#   trapdoor t  = PRF_K(w)                 secret token for keyword w
#   label       = PRF_t(counter)           pseudorandom, UNLINKABLE per entry
#   value       = Enc_t(record_id)         encrypted document id
#
# Because both the label and the value are keyed by the per-keyword trapdoor,
# the server cannot tell which entries share a keyword or a document until a
# search reveals it. To search for w the client hands over only t; the server
# walks counters 0,1,2,... until a label is missing, decrypting the matching
# record ids as it goes. Search cost is O(#matches), not a full table scan.
#
# Known/accepted leakage (inherent to efficient SSE): search access pattern
# and result size once a query is issued. Hiding those needs ORAM-class
# machinery, which is out of scope for this system.

def _keyword_list(raw):
    # Normalise a comma-separated user string into clean, deduped keywords.
    if not raw:
        return []
    seen, out = set(), []
    for k in raw.split(','):
        k = k.strip().lower()
        if k and k not in seen:
            seen.add(k)
            out.append(k)
    return out

def sse_trapdoor(keyword):
    # PRF_K(w): the per-keyword secret token. Requires the master HMAC key.
    return hmac.new(HMAC_KEY, keyword.strip().lower().encode(), hashlib.sha256).hexdigest()

def sse_label(trapdoor, counter):
    # PRF_t(counter): pseudorandom label, unlinkable across keywords/records.
    return hmac.new(trapdoor.encode(), f"label|{counter}".encode(), hashlib.sha256).hexdigest()

def sse_cipher(trapdoor):
    # Fernet instance keyed by the trapdoor, used to encrypt/decrypt record ids.
    key = hashlib.sha256((trapdoor + "|value").encode()).digest()  # 32 bytes
    return Fernet(base64.urlsafe_b64encode(key))

def sse_add_entry(trapdoor, record_id):
    # Append record_id to keyword's counter sequence at the next free slot.
    c = 0
    while SearchIndex.query.filter_by(label=sse_label(trapdoor, c)).first() is not None:
        c += 1
    db.session.add(SearchIndex(
        label=sse_label(trapdoor, c),
        value=sse_cipher(trapdoor).encrypt(str(record_id).encode())
    ))

def sse_remove_entry(trapdoor, record_id):
    # Drop record_id from a keyword's sequence and rewrite it contiguously so
    # the stop-at-gap search stays correct after deletions.
    cipher = sse_cipher(trapdoor)
    remaining = []
    c = 0
    while True:
        entry = SearchIndex.query.filter_by(label=sse_label(trapdoor, c)).first()
        if entry is None:
            break
        rid = int(cipher.decrypt(entry.value).decode())
        if rid != record_id:
            remaining.append(rid)
        db.session.delete(entry)
        c += 1
    db.session.flush()  # apply deletes before reusing labels
    for i, rid in enumerate(remaining):
        db.session.add(SearchIndex(
            label=sse_label(trapdoor, i),
            value=cipher.encrypt(str(rid).encode())
        ))

def sse_index_record(record_id, keywords):
    for w in keywords:
        sse_add_entry(sse_trapdoor(w), record_id)

def sse_deindex_record(record_id, keywords):
    for w in keywords:
        sse_remove_entry(sse_trapdoor(w), record_id)

def sse_search(keyword):
    # Return the list of record ids indexed under keyword.
    t = sse_trapdoor(keyword)
    cipher = sse_cipher(t)
    ids, c = [], 0
    while True:
        entry = SearchIndex.query.filter_by(label=sse_label(t, c)).first()
        if entry is None:
            break
        ids.append(int(cipher.decrypt(entry.value).decode()))
        c += 1
    return ids

def get_record_keywords(record):
    # Decrypt the record's stored keyword set (needed to re-index on edit/delete).
    if not record.enc_keywords:
        return []
    return _keyword_list(fernet.decrypt(record.enc_keywords).decode())

# Logging Actions Function
def log_action(user_id, action, record_id=None):
    timestamp = datetime.now(timezone.utc).replace(microsecond=0)
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

# Compute tamper-evident hash (Audit Log Integrity)
def compute_log_hash(user_id, record_id, action, timestamp):
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    timestamp = timestamp.replace(microsecond=0)
    timestamp_str = timestamp.isoformat()
    message = f"{user_id}|{record_id}|{action}|{timestamp_str}"
    return hmac.new(HMAC_KEY, message.encode(), hashlib.sha256).hexdigest()

# Record Integrity Hash computation (Data Integrity)
def compute_record_integrity(patient_id, doctor_id, nurse_id, enc_name, enc_symptoms, enc_diagnosis, enc_keywords):
    data_string = (
        f"{patient_id}|{doctor_id}|{nurse_id}|"
        f"{enc_name.hex()}|{enc_symptoms.hex()}|{enc_diagnosis.hex()}|"
        f"{enc_keywords.hex() if enc_keywords else ''}"
    )
    
    return hmac.new(
        HMAC_KEY,
        data_string.encode(),
        hashlib.sha256
    ).hexdigest()

# === DATABASE ===

# USER TABLE IN DB
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True,autoincrement=True)
    username = db.Column(db.String(80), unique=True)
    password_hash = db.Column(db.String(128))
    role = db.Column(db.String(10))  # 'doctor', 'nurse', 'patient'
    def __repr__(self):
        return f"<User {self.username} ({self.role})>"

# RECORD TABLE IN DB
class MedicalRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True,autoincrement=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    name = db.Column(db.LargeBinary)
    symptoms = db.Column(db.LargeBinary)
    diagnosis = db.Column(db.LargeBinary)
    doctor_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    nurse_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    enc_keywords = db.Column(db.LargeBinary)  # Fernet-encrypted keyword set (for re-indexing on edit/delete)

    integrity_hash = db.Column(db.String(128))
    
    patient = db.relationship('User', foreign_keys=[patient_id], backref='patient_records')
    doctor = db.relationship('User', foreign_keys=[doctor_id], backref='doctor_records')
    nurse = db.relationship('User', foreign_keys=[nurse_id], backref='nurse_records')

    def is_tampered(self):
        current_hash = compute_record_integrity(
            self.patient_id, 
            self.doctor_id, 
            self.nurse_id, 
            self.name, 
            self.symptoms,
            self.diagnosis,
            self.enc_keywords  # Include keyword set in check
        )
        return current_hash != self.integrity_hash

    def __repr__(self):
        return f"<MedicalRecord id={self.id} patient_id={self.patient_id}>"

# ENCRYPTED SEARCH INDEX TABLE IN DB (the SSE inverted index)
class SearchIndex(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    label = db.Column(db.String(64), unique=True, index=True)  # pseudorandom PRF_t(counter)
    value = db.Column(db.LargeBinary)                          # Enc_t(record_id)

    def __repr__(self):
        return f"<SearchIndex {self.label[:8]}...>"

# AUDIT LOG TABLES IN DB
class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer)
    record_id = db.Column(db.Integer, nullable=True)
    action = db.Column(db.String(255))
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc).replace(microsecond=0))
    ip_address = db.Column(db.String(50))
    log_hash = db.Column(db.String(128))

    def __repr__(self):
        return f"<AuditLog {self.user_id} - {self.action}>"


# === BACKEND ===

# 1. LOGIN 
@app.route('/', methods=['GET', 'POST'])
def login():
    user = None   
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


# 1.1 PATIENT SELF-REGISTRATION (public sign-up)
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']

        if not username or not password:
            return render_template('register.html', error="Username and password are required")

        if User.query.filter_by(username=username).first():
            return render_template('register.html', error="That username is already taken")

        db.session.add(User(
            username=username,
            password_hash=generate_password_hash(password),
            role='patient'
        ))
        db.session.commit()
        log_action(None, f"Self-registered patient username={username}")
        return render_template('login.html', notice="Account created — please sign in.")

    return render_template('register.html')


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
    # i. Verify doctor 
    if session.get('role') != 'doctor':
        return "Access Denied", 403

    # ii. Log action
    log_action(session['user_id'], "Accessed doctor dashboard")

    # iii. Add record
    if request.method == 'POST':
        doctor_id = session.get('user_id')
        patient_id = int(request.form['patient_id'])
        nurse_id = int(request.form['nurse_id'])
        symptoms = request.form['symptoms']
        diagnosis = request.form['diagnosis']
        keywords_raw = request.form['keywords']

        # Get the patient object
        patient = User.query.get(patient_id)
        if not patient or patient.role != 'patient':
            return "Invalid patient selected", 400

        # Encrypt fields
        encrypted_name = fernet.encrypt(patient.username.encode())
        encrypted_symptoms = fernet.encrypt(symptoms.encode())
        encrypted_diagnosis = fernet.encrypt(diagnosis.encode())

        # Encrypt the keyword set so it can be re-indexed later on edit/delete
        keywords = _keyword_list(keywords_raw)
        encrypted_keywords = fernet.encrypt(",".join(keywords).encode())

        # Compute Integrity
        integrity_val = compute_record_integrity(
            patient_id, doctor_id, nurse_id,
            encrypted_name, encrypted_symptoms, encrypted_diagnosis,
            encrypted_keywords
        )

        # Create MedicalRecord
        record = MedicalRecord(
            patient_id=patient_id,
            doctor_id=doctor_id,
            nurse_id=nurse_id,
            name=encrypted_name,
            symptoms=encrypted_symptoms,
            diagnosis=encrypted_diagnosis,
            enc_keywords=encrypted_keywords,
            integrity_hash=integrity_val
        )

        db.session.add(record)
        db.session.commit()  # commit first so record.id exists

        # Add the record's keywords to the encrypted search index
        sse_index_record(record.id, keywords)
        db.session.commit()

        log_action(doctor_id, "Created medical record", record.id)
        return redirect(url_for('doctor_dashboard'))
    
    # iv. Display tables
    patients = User.query.filter_by(role='patient').all() 
    nurses = User.query.filter_by(role='nurse').all() 
    records = MedicalRecord.query.all() 
    return render_template( 'doctor_dashboard.html', records=records, decrypt=fernet.decrypt, patients=patients, nurses=nurses )


# 2.1.A. DR ADDS PATIENT
@app.route('/register_patient', methods=['POST'])
def register_patient():
    if session.get('role') != 'doctor':
        return "Access Denied", 403

    username = request.form['username']
    password = request.form['password']
    
    if User.query.filter_by(username=username).first():
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
        # De-index then delete each of the patient's records
        for rec in MedicalRecord.query.filter_by(patient_id=patient.id).all():
            sse_deindex_record(rec.id, get_record_keywords(rec))
            db.session.delete(rec)
        db.session.delete(patient)
        db.session.commit()
        log_action(session['user_id'], f"Removed patient_id={id}")
        return redirect(url_for('doctor_dashboard'))
    except Exception:
        # Roll back so a partial de-index/delete never leaves the index inconsistent
        db.session.rollback()
        return redirect(url_for('doctor_dashboard', error="Could not remove that patient."))

# 2.1.C. DR DELETES RECORD
@app.route('/delete_record/<int:id>')
def delete_record(id):
    if session.get('role') != 'doctor':
        log_action(session.get('user_id'), f"Unauthorized delete attempt on record_id={id}")
        return "Access Denied", 403

    record_to_delete=MedicalRecord.query.get_or_404(id)
    try:
        # Remove this record's entries from the encrypted search index first
        sse_deindex_record(record_to_delete.id, get_record_keywords(record_to_delete))
        db.session.delete(record_to_delete)
        db.session.commit()
        log_action(session['user_id'], "Deleted record", id)
        return redirect("/doctor")
    except Exception:
        # Roll back so a partial de-index never leaves the index inconsistent
        db.session.rollback()
        return redirect(url_for('doctor_dashboard', error="There was a problem deleting this record."))

# 2.1.D. DR UPDATES RECORD
@app.route('/update_record/<int:id>', methods=['GET', 'POST'])
def update_record(id):
    if session.get('role') != 'doctor':
        return "Access Denied", 403

    record = MedicalRecord.query.get_or_404(id)

    if request.method == 'POST':
        patient_id = int(request.form['patient_id'])
        symptoms = request.form['symptoms']
        diagnosis = request.form['diagnosis']
        keywords_raw = request.form.get('keywords', '').strip()

        patient = User.query.get(patient_id)
        if not patient or patient.role != 'patient':
            return "Invalid patient selected", 400

        # Encrypt updated fields
        record.name = fernet.encrypt(patient.username.encode())
        record.symptoms = fernet.encrypt(symptoms.encode())
        record.diagnosis = fernet.encrypt(diagnosis.encode())

        # Re-index the search index only if the keyword set actually changed.
        # An empty keywords field means "keep existing keywords".
        if keywords_raw != "":
            old_keywords = get_record_keywords(record)
            new_keywords = _keyword_list(keywords_raw)
            if new_keywords != old_keywords:
                sse_deindex_record(record.id, old_keywords)
                sse_index_record(record.id, new_keywords)
                record.enc_keywords = fernet.encrypt(",".join(new_keywords).encode())

        # Update IDs
        record.patient_id = patient_id
        if 'nurse_id' in request.form:
            record.nurse_id = int(request.form['nurse_id'])

        # Re-compute integrity hash
        record.integrity_hash = compute_record_integrity(
            record.patient_id,
            record.doctor_id,
            record.nurse_id,
            record.name,
            record.symptoms,
            record.diagnosis,
            record.enc_keywords
        )

        try:
            db.session.commit()
            log_action(session['user_id'], "Updated record", id)
            return redirect(url_for('doctor_dashboard'))
        except Exception as e:
            return f"There was a problem updating this record: {e}"

    patients = User.query.filter_by(role='patient').all()
    nurses = User.query.filter_by(role='nurse').all()
    return render_template(
        'update_record.html',
        record=record,
        decrypt=fernet.decrypt,
        patients=patients,
        nurses=nurses
    )


# 2.1.E DR SEARCHES RECORD (SSE SEARCH)
@app.route('/search_record', methods=['GET', 'POST'])
def search_record():
    if session.get('role') != 'doctor':
        log_action(session.get('user_id'), "Unauthorized doctor panel access attempt")
        return "Access Denied", 403
    
    matched_records = []
    if request.method == 'POST':
        # 1. User inputs a keyword
        keyword = request.form['keyword'].strip().lower()

        log_action(session['user_id'], f"Searched keyword={keyword}")

        # 2. SSE search: derive the trapdoor and walk the encrypted inverted
        #    index to recover the matching record ids (no table scan).
        if keyword:
            matched_ids = sse_search(keyword)
            if matched_ids:
                matched_records = MedicalRecord.query.filter(
                    MedicalRecord.id.in_(matched_ids)
                ).all()

    return render_template(
        'search_record.html',
        records=matched_records,
        decrypt=fernet.decrypt
    )

# 2.1.F DR VIEW AUDIT LOGS
@app.route('/audit_logs')
def audit_logs():
    if session.get('role') != 'doctor':
        log_action(session.get('user_id'), "Unauthorized audit log access attempt")
        return "Access Denied", 403

    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).all()
    return render_template('audit_logs.html', logs=logs)

# 2.1.G DR VERIFIES AUDIT LOGS
@app.route('/verify_audit_logs')
def verify_logs():
    if session.get('role') != 'doctor':
        log_action(session.get('user_id'), "Unauthorized audit verification attempt")
        return "Access Denied", 403

    logs = AuditLog.query.all()
    results = [
        {"id": log.id, "ok": compute_log_hash(log.user_id, log.record_id, log.action, log.timestamp) == log.log_hash}
        for log in logs
    ]
    return render_template('verify_audit_logs.html', results=results)


# 2.2 PATIENT DASHBOARD
@app.route('/patient')
def patient_dashboard():
    if session.get('role') != 'patient':
        return "Access Denied", 403
    log_action(session['user_id'], "Accessed patient dashboard")
    
    patient_id = session.get('user_id')
    records = MedicalRecord.query.filter_by(patient_id=patient_id).all()
    return render_template('patient_dashboard.html', records=records, decrypt=fernet.decrypt)


# 2.3 NURSE DASHBOARD
@app.route('/nurse')
def nurse_dashboard():
    if session.get('role') != 'nurse':
        return "Access Denied", 403
    log_action(session['user_id'], "Accessed nurse dashboard")

    nurse_id = session.get('user_id')
    records = MedicalRecord.query.filter_by(nurse_id=nurse_id).all()
    return render_template(
        'nurse_dashboard.html',
        records=records,
        decrypt=fernet.decrypt
    )

# 3. LOGOUT
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__=="__main__":
    # use_reloader=False: the stat reloader spawns a second process that
    # re-imports everything, which is painfully slow here (Defender scans the
    # venv on each file read). One process starts fine and stays up.
    app.run(debug=True, use_reloader=False)

## --- WORK LEFT ---

# 1. Nurse Dashboard: Only assigned records (excluding diagnosis) ✔️
# 2. Nurse or Dr IDs ki jgh onke names dikhany in html tables using SQL JOINS statements ✔️
# 3. Use HMAC instead of SHA256 everywhere => concept of SSE used i.e. search tokens using HMAC ✔️
# 4. Audit Logs - Detail Below ✔️
# 5. Record Integrity Hashing - Detail Below ✔️
# 6. Dummy Keywords - Detail Below - MARYAM ...



##  --- INFO SECURITY MEASURES ---

# 1. CONFIDENTIALITY:
        # 1. Role-Based Access Control (RBAC): Each user sees only permitted data
                # - Doctor: All records and fields
                # - Nurse: Only assigned records (excluding diagnosis)
                # - Patient: Only their own records
        # 2. Field-Level Encryption: All sensitive fields (name, symptoms, diagnosis) are encrypted using Fernet (AES-128)
        # 3. Searchable Symmetric Encryption (SSE):
                # - Encrypted inverted index (Curtmola et al. SSE-1 style)
                # - Per-entry labels = PRF_trapdoor(counter): pseudorandom & unlinkable
                # - Record ids stored encrypted under the keyword trapdoor
                # - Search is O(#matches), not a full table scan
                # - Accepted leakage: search access pattern + result size (inherent to efficient SSE)

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

# 1. Encrypted Inverted Index (real SSE): unlinkable (label, Enc(id)) entries;
#    sublinear search via per-keyword trapdoors instead of a LIKE table scan
# 2. Record Integrity Hashing: Detects tampering of encrypted fields
# 3. Encrypted keyword sets per record enable clean re-indexing on edit/delete