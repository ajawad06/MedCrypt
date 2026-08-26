# 🔒 MedCrypt

**Searchable Encryption on Medical Records** is a secure EHR platform that allows encrypted medical records to be searched without decryption. It implements **Searchable Symmetric Encryption (SSE)** as an encrypted inverted index, so the database can answer keyword queries while storing no plaintext keywords at all.

> **Course:** Information Security

---

## 🚀 Key Features

- **Searchable Symmetric Encryption (SSE):**  
  A real encrypted inverted index (Curtmola et al., SSE-1 style). Keyword entries are stored as `(label, value)` rows where the label is a pseudorandom PRF output and the value is an encrypted record id — so entries are **unlinkable** and search is **O(number of matches)**, not a table scan.

- **Field-Level Encryption:**  
  Sensitive fields (Name, Symptoms, Diagnosis) are encrypted using **AES-128 (Fernet)**.

- **Tamper-Evident Integrity:**  
  Every record is protected by a cryptographic seal (Integrity Hash) covering all encrypted fields and the keyword set. Any unauthorized database manipulation triggers a **Security Alert** in the UI.

- **Tamper-Evident Audit Logging:**  
  Every access and change is logged with an HMAC seal, so a modified log entry can be detected and flagged on the verification page.

- **Role-Based Access Control (RBAC):**  
  Distinct dashboards and permission levels for **Doctors, Nurses, and Patients**, enforced on every route.

- **Patient Self-Registration:**  
  Patients can create their own account from the login page; doctors can also provision accounts directly.

---

## 🛠 Tech Stack

- **Backend:** Python 3, Flask  
- **Database:** SQLite with SQLAlchemy ORM  
- **Cryptography:**
  - `cryptography` library (AES-128 / Fernet)
  - `hmac` + `hashlib` (HMAC-SHA256 as the PRF for trapdoors and labels)
  - `werkzeug.security` (PBKDF2 for password hashing)
- **Frontend:** HTML5, CSS3, Jinja2 Templating

---

## 🛡️ Security Architecture (CIA Triad)

- **Confidentiality:** Data is encrypted at rest. Even if the `.db` file is stolen, an attacker sees only ciphertext — and the search index reveals no keywords, no plaintext, and no record groupings.  
- **Integrity:** `is_tampered()` recalculates each record's hash on every access to detect unauthorized changes; audit logs are independently verifiable.  
- **Availability:** Role-specific dashboards ensure medical staff can access relevant data quickly and reliably.

---

## 📋 Usage & Roles

| Role       | Permissions                                      |
|------------|--------------------------------------------------|
| **Doctor** | Create/edit/delete records, encrypted keyword search, manage patients, view & verify audit logs |
| **Nurse**  | View-only access to assigned patient records (diagnosis withheld) |
| **Patient**| View-only access to their own medical history; can self-register |

### How Search Actually Works

Search never touches a plaintext keyword. For a keyword `w`:

1. **Trapdoor:** the client derives `t = HMAC(masterKey, w)` — the secret search token.
2. **Labels:** each occurrence of `w` is stored under `label = HMAC(t, counter)` for `counter = 0, 1, 2, …`. Because the label is keyed by the trapdoor, entries for the same keyword look completely independent.
3. **Values:** the matching record id is stored as `Fernet(key derived from t).encrypt(record_id)` — so document ids are encrypted, and two entries for the same record are not byte-identical.
4. **Query:** the server is handed only `t`. It walks counters `0, 1, 2, …` until a label is missing, decrypting each matching record id along the way, then returns those records for decryption.

Deleting or editing a record re-indexes its keywords and rewrites the counter sequence contiguously, so the stop-at-gap search stays correct.

### Honest Threat Model & Known Leakage

This is stated explicitly because it is what separates real SSE from a hand-wave:

- **What it protects against:** a stolen database file or a snooping DBA. Without the master key, the index is opaque — no plaintext keywords, no way to recompute labels, and no visible link between entries sharing a keyword or a record.
- **Accepted leakage (inherent to all efficient SSE):** once a query is issued, the server learns the **access pattern** (which records matched) and the **result size**. Trapdoors are deterministic, so repeated searches for the same keyword are linkable. Eliminating this requires ORAM-class machinery, which is out of scope.
- **Client/server are the same process.** The master key lives in the Flask app's memory, so the guarantee is *"database compromise reveals almost nothing"* — **not** protection against compromise of the running application.
- **Audit logs are per-entry sealed, not hash-chained.** A modified entry is detected, but wholesale deletion of entries is not, since no entry commits to its predecessor.

---

## 💻 Installation & Setup

Clone the repository:

```bash
git clone https://github.com/ajawad06/MedCrypt.git
```

Create and activate a virtual environment:

```bash
python -m venv .venv
```

```bash
.\.venv\Scripts\Activate.ps1
```

Install dependencies:

```bash
pip install flask flask-sqlalchemy cryptography python-dotenv
```

Create a `.env` file in the project root with the three secrets the app requires:

```bash
python -c "from cryptography.fernet import Fernet; import base64, os; print('FERNET_KEY=' + Fernet.generate_key().decode()); print('FLASK_SECRET_KEY=' + os.urandom(24).hex()); print('HMAC_KEY=' + base64.b64encode(os.urandom(32)).decode())"
```

Paste that output into `.env` (it is gitignored and must never be committed):

```
FERNET_KEY=...
FLASK_SECRET_KEY=...
HMAC_KEY=...
```

> ⚠️ Changing `FERNET_KEY` or `HMAC_KEY` later makes existing records and the search index unreadable — reseed the database if you rotate them.

Initialize the database:

```bash
python seed_users.py
```

Run the application:

```bash
python app.py
```

Then open <http://127.0.0.1:5000>.

---

## 👥 Demo Accounts

Seeded by `seed_users.py` (usernames are case-sensitive and include the prefix):

| Role | Username | Password |
|---|---|---|
| Doctor | `DR AHMAD ALVI` | `ahmad123` |
| Nurse | `NURSE SANA RIAZ` | `sana123` |
| Patient | `ABDULLAH AHMED` | `abdullah123` |

Additional seeded users follow the same pattern (`<firstname>123`). New patients can also self-register from the login page.

---

## 🗄️ Data Model

| Table | Purpose |
|---|---|
| `user` | Accounts with role (`doctor` / `nurse` / `patient`) and PBKDF2 password hash |
| `medical_record` | Encrypted name, symptoms, diagnosis, encrypted keyword set, integrity hash |
| `search_index` | The encrypted inverted index: `(label, encrypted record id)` |
| `audit_log` | Action trail with HMAC seal, IP address, and timestamp |
