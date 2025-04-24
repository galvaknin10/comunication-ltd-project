import os
import hmac
import hashlib
import re
from config import PASSWORD_COMPLEXITY_REGEX, MIN_PASSWORD_LENGTH

def generate_salt() -> str:
    return os.urandom(16).hex()

def hash_password(password: str, salt: str) -> str:
    return hmac.new(salt.encode(), password.encode(), hashlib.sha256).hexdigest()

def is_password_valid(password: str) -> bool:
    return (
        len(password) >= MIN_PASSWORD_LENGTH and
        re.match(PASSWORD_COMPLEXITY_REGEX, password)
    )