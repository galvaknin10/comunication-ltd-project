from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from database import get_db
from crud import create_user, create_customer
from utils.security import is_password_valid, hash_password, generate_salt
from config import COMMON_PASSWORDS, PASSWORD_COMPLEXITY_REGEX, MIN_PASSWORD_LENGTH, GUIDLINE_DESCRIPTION, FORCE_PASSWORD_CHANGE_AFTER_LOGINS, MAX_LOGIN_ATTEMPTS
from models import User, Customer
import os, hmac, hashlib, re, pendulum
import hashlib
import time
import smtplib
from email.mime.text import MIMEText
from dotenv import load_dotenv
import os
from sqlalchemy import text
from sqlite3 import OperationalError

router = APIRouter()

class RegisterRequest(BaseModel):
    username: str
    email: str
    password: str

class LoginRequest(BaseModel):
    username: str
    password: str

class CustomerCreate(BaseModel):
    customer_id: str
    name: str
    email: str
    phone: str 

class ChangePasswordRequest(BaseModel):
    username: str
    new_password: str

class EmailRequest(BaseModel):
    email: str

class VerifyToken(BaseModel):
    token: str
    username: str

load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), '..', '.env'))
EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PASS = os.getenv("EMAIL_PASS")


@router.post("/register")
def register_user_vulnerable(request: RegisterRequest, db: Session = Depends(get_db)):
    # 1. Raw user inputs (no XSS protection)
    username = request.username
    password = request.password
    email    = request.email

    # 2. Raw SQL string interpolation (SQLi open)
    conn = db.connection().connection
    cur  = conn.cursor()
    cur.execute(
        f"SELECT 1 FROM users WHERE username = '{username}';"
    )
    exists = cur.fetchone()
    if exists:
        # Irresponsible error, disclosing if the username is taken
        raise HTTPException(status_code=409, detail="This Username is already exist")

    # 3. Password policy check (same as before)
    if password in COMMON_PASSWORDS:
        raise HTTPException(status_code=400, detail="Password too common")
    if not (len(password) >= MIN_PASSWORD_LENGTH and re.match(PASSWORD_COMPLEXITY_REGEX, password)):
        raise HTTPException(status_code=400, detail="Password doesn't meet policy")

    # 4. Hashing
    salt    = os.urandom(16).hex()
    pw_hash = hmac.new(salt.encode(), password.encode(), hashlib.sha256).hexdigest()

    # 5. Raw INSERT (SQLi open via executescript)
    raw_query = f"""
    INSERT INTO users (username, email, password_hash, salt)
    VALUES (
      '{username}',
      '{email}',
      '{pw_hash}',
      '{salt}'
    );
    """
    # grab the underlying SQLite connection and run the script
    conn.executescript(raw_query)
    db.commit()


    # 6. Response
    return {"message": "User registered successfully!"}


@router.post("/change-password")
def change_password_vulnerable(request: ChangePasswordRequest, db: Session = Depends(get_db)):
    # 1. Raw user inputs (no html.escape → XSS possible if rendered)
    username     = request.username
    old_password = request.old_password
    new_password = request.new_password

    # 2. Fetch stored hash & salt via raw SQL (SQLi on username)
    conn = db.connection().connection
    cur  = conn.cursor()
    cur.execute(
        f"SELECT password_hash, salt FROM users WHERE username = '{username}';"
    )
    row = cur.fetchone()
    if not row:
        # Irresponsible error leak
        raise HTTPException(status_code=400, detail="This username is not found")
    stored_hash, salt = row


    # 3. Verify the old password
    old_hash = hmac.new(salt.encode(), old_password.encode(), hashlib.sha256).hexdigest()
    if old_hash != stored_hash:
        raise HTTPException(status_code=400, detail="Invalid credentials")

    # 4. Ensure the new password differs from the old
    new_hash = hmac.new(salt.encode(), new_password.encode(), hashlib.sha256).hexdigest()
    if new_hash == stored_hash:
        raise HTTPException(status_code=400, detail="New password must differ from the old one")

    # 5. Password policy (same checks, but using raw input)
    if new_password in COMMON_PASSWORDS:
        raise HTTPException(status_code=400, detail="Password too common")
    if not (len(new_password) >= MIN_PASSWORD_LENGTH and re.match(PASSWORD_COMPLEXITY_REGEX, new_password)):
        raise HTTPException(status_code=400, detail="Password doesn't meet policy")

    # 6. Raw UPDATE via f‐string (SQLi on both username & new_hash)
    raw_query = f"""
    UPDATE users
       SET password_hash     = '{new_hash}',
           successful_logins = 0
     WHERE username = '{username}';
    """
    # executescript allows chaining, fully SQLi-exposed
    conn.executescript(raw_query)
    db.commit()

    # 7. Echo back generic success (raw message)
    return {"message": "Password updated successfully"}


@router.get("/password-policy")
def get_password_policy():
    # Returns current password policy configuration for client-side validation
    return {
        "min_length": MIN_PASSWORD_LENGTH,
        "common_passwords": list(COMMON_PASSWORDS),
        "regex": PASSWORD_COMPLEXITY_REGEX,
        "guidelines": GUIDLINE_DESCRIPTION
    }



@router.post("/login-vulnerable")
def login_user_vulnerable(request: LoginRequest, db: Session = Depends(get_db)):
    # 1. Raw inputs (no html.escape → XSS if ever rendered)
    username = request.username
    password = request.password

    # 2. Fetch everything via raw SQL (SQLi on username)
    conn = db.connection().connection
    cur  = conn.cursor()
    cur.execute(
        f"SELECT id, password_hash, salt, failed_attempts, locked_until, successful_logins "
        f"FROM users WHERE username = '{username}';"
    )
    row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=401, detail="This username is not found")

    # 2a. Unpack the tuple
    user_id, stored_hash, salt, failed_attempts, locked_until, successful_logins = row

    now_utc = pendulum.now("UTC")

    # 3. If account is locked, reject
    if locked_until and pendulum.instance(locked_until) > now_utc:
        locked_time = (
            pendulum.instance(locked_until)
            .in_timezone("Asia/Jerusalem")
            .format("HH:mm:ss")
        )
        raise HTTPException(status_code=403, detail=f"Account locked until {locked_time}")

    # 4. If lockout expired, reset counters
    if locked_until and pendulum.instance(locked_until) <= now_utc:
        conn.executescript(
            f"UPDATE users "
            f"SET locked_until = NULL, failed_attempts = 0 "
            f"WHERE id = '{user_id}';"
        )
        db.commit()

    # 5. Verify password
    hashed = hmac.new(salt.encode(), password.encode(), hashlib.sha256).hexdigest()
    if hashed != stored_hash:
        attempts = failed_attempts + 1

        # 5a. Lock account if too many failures
        if attempts >= MAX_LOGIN_ATTEMPTS:
            lock_ts = now_utc.add(minutes=3)
            conn.executescript(
                f"UPDATE users "
                f"SET failed_attempts = {attempts}, locked_until = '{lock_ts}' "
                f"WHERE id = '{user_id}';"
            )
            db.commit()
            raise HTTPException(status_code=403, detail="Account locked due to too many failed attempts.")

        # 5b. Warn one attempt before lock
        if attempts == MAX_LOGIN_ATTEMPTS - 1:
            conn.executescript(
                f"UPDATE users "
                f"SET failed_attempts = {attempts} "
                f"WHERE id = '{user_id}';"
            )
            db.commit()
            raise HTTPException(status_code=403, detail="Notice: 1 more failed attempt before lock.")

        # 5c. Otherwise just bump the counter
        conn.executescript(
            f"UPDATE users "
            f"SET failed_attempts = {attempts} "
            f"WHERE id = '{user_id}';"
        )
        db.commit()
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # 6. On success: reset failures & bump logins
    conn.executescript(
        f"UPDATE users "
        f"SET failed_attempts   = 0, "
        f"    successful_logins = {successful_logins + 1}, "
        f"    locked_until      = NULL "
        f"WHERE id = '{user_id}';"
    )
    db.commit()

    # 7. Return raw result
    return {
        "message": "Login successful",
        "force_password_change": successful_logins + 1 >= FORCE_PASSWORD_CHANGE_AFTER_LOGINS
    }




@router.post("/customers")
def add_customer_vulnerable(request: CustomerCreate, db: Session = Depends(get_db)):
    # 1. Raw user inputs (no html.escape → XSS possible if ever rendered)
    customer_id = request.customer_id
    name        = request.name
    email       = request.email
    phone       = request.phone

    # 2. Existence check via raw SQL string interpolation (SQLi possible)
    conn = db.connection().connection
    cur  = conn.cursor()
    cur.execute(
        f"SELECT 1 FROM customers WHERE customer_id = '{customer_id}';"
    )
    exists = cur.fetchone()
    if exists:
        # A message that reveals information
        raise HTTPException(status_code=409, detail="Customer already exists")

    # 3. Raw INSERT (SQLi on all fields)
    raw_query = f"""
    INSERT INTO customers (customer_id, name, email, phone)
    VALUES (
      '{customer_id}',
      '{name}',
      '{email}',
      '{phone}'
    );
    """
    conn.executescript(raw_query)
    db.commit()

    # 4. Echo back raw data (reflected XSS if frontend renders as HTML)
    return {
        "customer_id": customer_id,
        "name":        name,
        "email":       email,
        "phone":       phone
    }


@router.post("/request-password-reset")
def request_password_reset_vulnerable(request: EmailRequest, db: Session = Depends(get_db)):
    # 1. Raw email input (no html.escape → XSS possible if ever reflected)
    email = request.email

    # 2. Lookup via raw SQL string interpolation (SQLi on email)
    conn = db.connection().connection
    cur  = conn.cursor()
    cur.execute(
        f"SELECT id, username, email FROM users WHERE email = '{email}';"
    )
    row = cur.fetchone()
    id, username = row

    if row:
        # 3. Build token
        ts = str(time.time())
        raw = f"{email}{ts}{row.username}"
        token = hashlib.sha1(raw.encode()).hexdigest()

        # 4. Store token via raw SQL f-string (SQLi on token & id)
        now_utc = pendulum.now("UTC")
        raw_query = f"""
        UPDATE users
        SET reset_token             = '{token}',
            reset_token_created_at  = '{now_utc}'
        WHERE id = {id};
        """

        conn.executescript(raw_query)
        db.commit()

        # 5. Send the real reset email
        send_reset_email(email, token)

    return {
        # A message that may reveal safe information
        "message": "Token generated and sent via email",
    }


def send_reset_email(to_email: str, token: str):
    msg = MIMEText(f"Here’s your reset token: {token}")
    msg["Subject"] = "Password Reset Request"
    msg["From"] = EMAIL_USER
    msg["To"] = to_email

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(EMAIL_USER, EMAIL_PASS)
        server.send_message(msg)


@router.post("/verify-token")
def verify_token_vulnerable(request: VerifyToken, db: Session = Depends(get_db)):
    # 1. Raw token input (no html.escape → XSS possible if ever reflected)
    token = request.token

    # 2. Lookup via raw SQL string interpolation (SQLi on token)
    conn = db.connection().connection
    cur  = conn.cursor()
    cur.execute(
        f"SELECT username, reset_token_created_at "
        f"FROM users WHERE reset_token = '{token}';"
    )
    row = cur.fetchone()
    username, reset_token_created_at = row

    # 3. If no match → invalid token
    if not row:
        raise HTTPException(status_code=400, detail="Invalid token")

    # 4. Check token age (valid for 3 minutes)
    created_at = pendulum.instance(reset_token_created_at)
    if pendulum.now("UTC").diff(created_at).in_minutes() > 3:
        raise HTTPException(status_code=400, detail="Reset token expired")

    # 5. Success → return raw username (potential XSS if rendered)
    return {
        "message": "Token verified!",
        "user_name": username
    }


@router.get("/customers/{customer_id}")
def get_customer_vulnerable(customer_id: str, db: Session = Depends(get_db)):
    # 1. Raw path param (no html.escape → reflected XSS possible)
    cid = customer_id

    # 2. Raw SQL string interpolation (SQLi on customer_id)
    conn = db.connection().connection
    cur  = conn.cursor()
    cur.execute(
        f"SELECT name, email, phone "
        f"FROM customers "
        f"WHERE customer_id = '{cid}';"
    )
    row = cur.fetchone()
    name, email, phone = row


    # 3. 404 if missing
    if not row:
        raise HTTPException(status_code=404, detail="Customer not found")

    # 4. Return raw fields (reflected XSS if rendered)
    return {
        "name":  name,
        "email": email,
        "phone": phone
    }
