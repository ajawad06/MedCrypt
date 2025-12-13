from app import app, db, User
from werkzeug.security import generate_password_hash

with app.app_context():
    # Drop all tables
    db.drop_all()

    # Recreate all tables
    db.create_all()

    # Seed users
    users = [
        # Doctors
        ('DR AHMAD ALVI', 'ahmad123', 'doctor'),
        ('DR FARHAN SAEED', 'farhan123', 'doctor'),
        ('DR MUBASHIR KHAN', 'mubashir123', 'doctor'),

        # Nurses
        ('NURSE SANA RIAZ', 'sana123', 'nurse'),
        ('NURSE HINA TARIQ', 'hina123', 'nurse'),
        ('NURSE ASMA JAVED', 'asma123', 'nurse'),
        ('NURSE SAIMA BILAL', 'saima123', 'nurse'),
        ('NURSE TAHIRA IQBAL', 'tahira123', 'nurse'),
        ('NURSE FARIHA ZUBAIR', 'fariha123', 'nurse'),
        ('NURSE MAHA YOUSAF', 'maha123', 'nurse'),
        ('NURSE RABIA SHAH', 'rabia123', 'nurse'),
        ('NURSE NIDA QURESHI', 'nida123', 'nurse'),
        ('NURSE SHAISTA NOOR', 'shaista123', 'nurse'),

        # Patients
        ('ABDULLAH AHMED', 'abdullah123', 'patient'),
        ('IBRAHIM RIZVI', 'ibrahim123', 'patient'),
        ('DANIYAL HUSSAIN', 'daniyal123', 'patient'),
        ('JAHANZEB BABAR', 'jahanzeb123', 'patient'),
        ('FAHAD SALEEM', 'fahad123', 'patient')
    ]

    for username, password, role in users:
        db.session.add(User(
            username=username,
            password_hash=generate_password_hash(password),
            role=role
        ))

    db.session.commit()
    print("Database created and users seeded.")