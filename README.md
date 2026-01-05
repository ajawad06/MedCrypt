# 🔒 MedCrypt

The **Searchable Encryption on Medical Records** system is a secure Electronic Health Record (EHR) platform designed to resolve the conflict between data privacy and searchability. Traditional encrypted databases require decryption for searching, which exposes sensitive data. This project implements **Searchable Symmetric Encryption (SSE)** using HMAC tokens and dummy keyword padding to allow secure searching while keeping Patient Health Information (PHI) encrypted at rest.

---

## 🚀 Key Features

- **Searchable Symmetric Encryption (SSE):**  
  Search encrypted records without decrypting the database, using HMAC-SHA256 tokens.

- **Dummy Keyword Padding:**  
  Prevents "Frequency Analysis" attacks by ensuring every record has a fixed number of keyword tokens (Real + Dummy), making all records appear uniform to an attacker.

- **Field-Level Encryption:**  
  Sensitive fields (Name, Symptoms, Diagnosis) are encrypted using **AES-128 (Fernet)**.

- **Tamper-Evident Integrity:**  
  Every record is protected by a cryptographic seal (Integrity Hash). Any unauthorized database manipulation triggers a **Security Alert**.

- **Chained Audit Logging:**  
  A tamper-proof log system where each entry is cryptographically linked to the previous one, ensuring non-repudiation.

- **Role-Based Access Control (RBAC):**  
  Distinct dashboards and permission levels for **Doctors, Nurses, and Patients**.

---

## 🛠 Tech Stack

- **Backend:** Python 3, Flask  
- **Database:** SQLite with SQLAlchemy ORM  
- **Cryptography:**
  - `cryptography` library (AES-128 / Fernet)
  - `hashlib` (HMAC-SHA256 for searching)
  - `werkzeug.security` (PBKDF2 for password hashing)
- **Frontend:** HTML5, CSS3, Jinja2 Templating

---

## 🛡️ Security Architecture (CIA Triad)

- **Confidentiality:** Data is encrypted at rest. Even if the `.db` file is stolen, attackers see only ciphertext.  
- **Integrity:** The `is_tampered()` function recalculates hashes on every access to ensure no unauthorized changes were made.  
- **Availability:** Role-specific dashboards ensure that medical staff can access relevant data quickly and reliably.

---

## 📋 Usage & Roles

| Role       | Permissions                                      |
|------------|--------------------------------------------------|
| **Doctor** | Create records, Search via keywords, View all records, Edit history |
| **Nurse**  | View-only access to assigned patient records    |
| **Patient**| View-only access to their own medical history   |

### How Search Works

1. The Doctor enters a keyword (e.g., "Flu").
2. The system generates an HMAC("Flu", Secret_Key).
3. The database matches this HMAC against the keywords_hmac column.
4. Only matching encrypted records are returned and decrypted for the Doctor.

---

## 💻 Installation & Setup

Clone the repository:

```bash
git clone https://github.com/ajawad06/MedCrypt.git
cd MedCrypt
```

Create a virtual environment:

```bash
./env/Scripts/Activate.ps1
```

Install dependencies:

```bash
pip install flask flask-sqlalchemy cryptography
```

Initialize the database:

```bash
python seed_users.py
```

Run the application:

```bash
python app.py
```

