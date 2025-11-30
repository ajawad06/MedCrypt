import os
from dotenv import load_dotenv
import base64


load_dotenv()

FERNET_KEY = os.getenv("FERNET_KEY")
SECRET_KEY = os.getenv("FLASK_SECRET_KEY")
DATABASE_URI = os.getenv("DATABASE_URL", "sqlite:///medical.db")
HMAC_KEY = base64.b64decode(os.getenv("HMAC_KEY"))

