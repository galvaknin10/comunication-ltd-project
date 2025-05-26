from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.orm import Session
from security_config import DEMO_SECRET_KEY

from database import get_db
from config import (
    COMMON_PASSWORDS,
    PASSWORD_COMPLEXITY_REGEX,
    MIN_PASSWORD_LENGTH,
    GUIDLINE_DESCRIPTION,
    FORCE_PASSWORD_CHANGE_AFTER_LOGINS,
    MAX_LOGIN_ATTEMPTS
)

import os
import hmac
import hashlib
import html
import re
import time
import pendulum
import smtplib
from email.mime.text import MIMEText
from dotenv import load_dotenv


router = APIRouter()

# Request model for user registration
class RegisterRequest(BaseModel):
    username: str
    email: str
    password: str

# Request model for user login
class LoginRequest(BaseModel):
    username: str
    password: str

# Request model for creating a new customer
class CustomerCreate(BaseModel):
    customer_id: str
    name: str
    email: str
    phone: str 

# Request model for changing a user's password
class ChangePasswordRequest(BaseModel):
    username: str
    old_password: str
    new_password: str

# Request model for email-based operations (e.g., password reset)
class EmailRequest(BaseModel):
    email: str

# Request model for token verification during password reset
class VerifyToken(BaseModel):
    token: str

# Load environment variables from the .env file located in the project root
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), '..', '.env'))

# Retrieve email credentials from environment variables
EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PASS = os.getenv("EMAIL_PASS")


@router.post("/register")
def register_user(request: RegisterRequest, db: Session = Depends(get_db)):
    # 1. Escape user inputs to prevent XSS
    safe_username = html.escape(request.username)
    safe_email    = html.escape(request.email)
    safe_password = request.password

    whitelist_regex = re.compile(r"^[a-zA-Z0-9!@#$%^&*()_+\-=\[\]{}|\\;:',.?/`~]+$")
    if not whitelist_regex.match(safe_password):
        raise HTTPException(400, "Password contains invalid characters.")

    # 2. Check for existing username using a prepared parameters (prevents SQL injection)
    exists = db.execute(
        text("SELECT 1 FROM users WHERE username = :username"),
        {"username": safe_username}
    ).first()
    if exists:
        # Generic error to avoid disclosing if the username is taken
        raise HTTPException(status_code=409, detail="Invalid credentials")

    # 3. Validate password strength
    if safe_password in COMMON_PASSWORDS:
        raise HTTPException(status_code=400, detail="Password too common")
    if not (len(safe_password) >= MIN_PASSWORD_LENGTH  and re.match(PASSWORD_COMPLEXITY_REGEX, safe_password)):
        raise HTTPException(status_code=400, detail="Password doesn't meet policy")

    # 4.
    # Generate a cryptographic salt and hash the password using HMAC-SHA256.
    # This ensures a unique, collision-resistant fingerprint for each password,
    # with extremely high one-to-one likelihood and exponential difficulty to reverse.
    salt    = os.urandom(16).hex()
    pw_hash = hmac.new(DEMO_SECRET_KEY.encode(), (safe_password + salt).encode(), hashlib.sha256).hexdigest()

    # 5. Insert the new user securely via prepared parameters
    db.execute(
        text("""
            INSERT INTO users (
                username,
                email,
                password_hash,
                salt,
                failed_attempts,
                successful_logins,
                locked_until,
                reset_token,
                reset_token_created_at
            ) VALUES (
                :username,
                :email,
                :pw_hash,
                :salt,
                :failed_attempts,
                :successful_logins,
                :locked_until,
                :reset_token,
                :reset_token_created_at
            )
        """),
        {
            "username":            safe_username,
            "email":               safe_email,
            "pw_hash":             pw_hash,
            "salt":                salt,
            "failed_attempts":     0,
            "successful_logins":   0,
            "locked_until":        None,   
            "reset_token":         None,
            "reset_token_created_at": None,
        }
    )
    db.commit()


    # 6. Return success message
    return {"message": "User registered successfully!"}


@router.post("/change-password")
def change_password(request: ChangePasswordRequest, db: Session = Depends(get_db)):
    # 1. Escape user inputs to prevent XSS
    safe_username = html.escape(request.username)
    safe_old_password = request.old_password
    safe_new_password = request.new_password

    whitelist_regex = re.compile(r"^[a-zA-Z0-9!@#$%^&*()_+\-=\[\]{}|\\;:',.?/`~]+$")
    if not whitelist_regex.match(safe_old_password) or not whitelist_regex.match(safe_new_password):
        raise HTTPException(400, "Password contains invalid characters.")

    # 2. Fetch stored hash & salt using a prepared parameters (prevents SQL injection)
    row = db.execute(
        text("SELECT password_hash, salt FROM users WHERE username = :username"),
        {"username": safe_username}
    ).fetchone()
    if not row:
        # Generic error to avoid disclosing whether the user exists
        raise HTTPException(status_code=400, detail="Invalid credentials")

    stored_hash, salt = row.password_hash, row.salt

    # 3. Verify the old password
    old_hash = hmac.new(DEMO_SECRET_KEY.encode(), (safe_old_password + salt).encode(), hashlib.sha256).hexdigest()
    if old_hash != stored_hash:
        raise HTTPException(status_code=400, detail="Invalid credentials")

    # 4. Ensure the new password differs from the old
    new_hash = hmac.new(DEMO_SECRET_KEY.encode(), (safe_new_password + salt).encode(), hashlib.sha256).hexdigest()
    if new_hash == stored_hash:
        raise HTTPException(status_code=400, detail="New password must differ from the old one")

    # 5. Enforce password policies
    if safe_new_password in COMMON_PASSWORDS:
        raise HTTPException(status_code=400, detail="Password too common")
    if not (len(safe_new_password) >= MIN_PASSWORD_LENGTH and re.match(PASSWORD_COMPLEXITY_REGEX, safe_new_password)):
        raise HTTPException(status_code=400, detail="Password doesn't meet policy")

    # 6. Update hash and reset login counters securely via prepared parameters
    db.execute(
        text(
            """
            UPDATE users
            SET password_hash = :new_hash,
                successful_logins = 0
            WHERE username = :username
            """
        ),
        {"new_hash": new_hash, "username": safe_username}
    )
    db.commit()

    # 7. Return generic success message
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


@router.post("/login")
def login_user(request: LoginRequest, db: Session = Depends(get_db)):
    # 1. Escape user inputs to prevent XSS
    safe_username = html.escape(request.username)
    safe_password = request.password

    whitelist_regex = re.compile(r"^[a-zA-Z0-9!@#$%^&*()_+\-=\[\]{}|\\;:',.?/`~]+$")
    if not whitelist_regex.match(safe_password):
        raise HTTPException(400, "Password contains invalid characters.")
   
    # 2. Fetch the user record (with hash & salt) via a prepared parameters
    row = db.execute(
        text("SELECT id, password_hash, salt, failed_attempts, locked_until, successful_logins "
             "FROM users WHERE username = :username"),
        {"username": safe_username}
    ).fetchone()
    if not row:
        # Don’t reveal whether the user exists
        raise HTTPException(status_code=401, detail="Invalid credentials")

    TZ = "Asia/Jerusalem"
    now_local = pendulum.now(TZ)

    # if they’re currently locked…
    if row.locked_until:
        # 1. parse what came from the DB
        if isinstance(row.locked_until, str):
            locked_dt = pendulum.parse(row.locked_until, tz=TZ)
        else:
            locked_dt = pendulum.instance(row.locked_until)

        # 2. shift it to Jerusalem and compare
        locked_local = locked_dt
        if locked_local > now_local:
            locked_time = locked_local.format("HH:mm:ss")
            raise HTTPException(
                status_code=403,
                detail= f"Account locked until {locked_time}"
            )

        # 3. if lockout expired
        if locked_local <= now_local:
            db.execute(
                text("UPDATE users SET locked_until = NULL, failed_attempts = 0 WHERE id = :id"),
                {"id": row.id}
            )
            db.commit()

    # 5. Verify password
    hashed = hmac.new(DEMO_SECRET_KEY.encode(), (safe_password + row.salt).encode(), hashlib.sha256).hexdigest()

    if hashed != row.password_hash:
        attempts = row.failed_attempts + 1

        # 5a. If max attempts reached → lock account
        if attempts >= MAX_LOGIN_ATTEMPTS:
            lock_ts = now_local.add(minutes=3)
            lock_str = lock_ts.to_datetime_string()

            db.execute(
                text("UPDATE users SET failed_attempts = :a, locked_until= :lt WHERE id = :id"),
                {
                    "a": attempts,
                    "lt": lock_str,
                    "id": row.id
                }
            )
            db.commit()
            raise HTTPException(status_code=403, detail="Account locked due to too many failed attempts.")

        # 5b. If one attempt before lock → warn
        if attempts == MAX_LOGIN_ATTEMPTS - 1:
            db.execute(
                text("UPDATE users SET failed_attempts = :a WHERE id = :id"),
                {"a": attempts, "id": row.id}
            )
            db.commit()
            raise HTTPException(status_code=403, detail="Notice: 1 more failed attempt before lock.")

        # 5c. Otherwise, just increment the counter
        db.execute(
            text("UPDATE users SET failed_attempts = :a WHERE id = :id"),
            {"a": attempts, "id": row.id}
        )
        db.commit()
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # 6. On successful login: reset counters and bump login count via prepared parameters
    db.execute(
        text("""
            UPDATE users
               SET failed_attempts   = 0,
                   successful_logins = successful_logins + 1,
                   locked_until      = NULL
             WHERE id = :id
        """),
        {"id": row.id}
    )
    db.commit()

    # 7. Return success + whether to force a password change
    return {
        "message": "Login successful",
        "force_password_change": row.successful_logins + 1 >= FORCE_PASSWORD_CHANGE_AFTER_LOGINS
    }


@router.post("/customers")
def add_customer(request: CustomerCreate, db: Session = Depends(get_db)):
    # 1. Escape user inputs to prevent XSS
    safe_name        = html.escape(request.name)
    safe_email       = html.escape(request.email)
    safe_phone       = html.escape(request.phone)
    safe_customer_id = html.escape(request.customer_id)

    # 2. Check for existing customer using a prepared statement (prevents SQL injection)
    exists = db.execute(
        text("SELECT 1 FROM customers WHERE customer_id = :cid"),
        {"cid": safe_customer_id}
    ).first()
    if exists:
        # Generic error to avoid disclosing customer existence
        raise HTTPException(status_code=409, detail="Unable to create customer")

    # 3. Insert new customer securely via prepared parameters
    db.execute(
        text(
            """
            INSERT INTO customers (customer_id, name, email, phone)
            VALUES (:cid, :name, :email, :phone)
            """
        ),
        {
            "cid":   safe_customer_id,
            "name":  safe_name,
            "email": safe_email,
            "phone": safe_phone
        }
    )
    db.commit()

    # 4. Return customer details
    return {
        "customer_name": safe_name,
        "customer_id": safe_customer_id,
    }

@router.post("/request-password-reset")
def request_password_reset(request: EmailRequest, db: Session = Depends(get_db)):
    # 1. Escape the email to pre-empt any stored XSS if ever reflected
    safe_email = html.escape(request.email)

    # 2. Look up the user by email with a prepared statement (blocks SQLi)
    row = db.execute(
        text("SELECT id, username, email FROM users WHERE email = :email"),
        {"email": safe_email}
    ).fetchone()

    if row:
        # 3. Build a one-time token (SHA-1 of email + timestamp + username)
        ts = str(time.time())
        raw = f"{safe_email}{ts}{row.username}"
        token = hashlib.sha1(raw.encode()).hexdigest()

        # 4. Store token + creation time securely via prepared parameters
        db.execute(
            text("""
                UPDATE users
                   SET reset_token             = :token,
                       reset_token_created_at  = :now
                 WHERE id = :id
            """),
            {
                "token": token,
                "now": pendulum.now("UTC").to_iso8601_string(),
                "id":    row.id
            }
        )
        db.commit()

        # 5. Send the real reset email
        send_reset_email(row.email, token)

    # 6. Return the generic response to avoid account enumeration
    return {
        "message":"If an account with that email exists, you’ll receive password reset instructions shortly."
    }


# Sends a password reset token to the user's email using Gmail SMTP
def send_reset_email(to_email: str, token: str):
    # Compose the email content
    msg = MIMEText(f"Here’s your reset token: {token}")
    msg["Subject"] = "Password Reset Request"
    msg["From"] = EMAIL_USER
    msg["To"] = to_email

    # Send email over secure SMTP connection
    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(EMAIL_USER, EMAIL_PASS)
        server.send_message(msg)


@router.post("/verify-token")
def verify_token(request: VerifyToken, db: Session = Depends(get_db)):
    # 1. Escape the token to pre-empt any XSS if ever reflected
    safe_token = html.escape(request.token)

    # 2. Look up the user by reset_token (prepared param blocks SQLi)
    row = db.execute(
        text("SELECT username, reset_token_created_at FROM users WHERE reset_token = :token"),
        {"token": safe_token}
    ).fetchone()

    # 3. If no match → invalid token (same message for any miss)
    if not row:
        raise HTTPException(status_code=400, detail="Invalid token")

    # 4. Check token age (valid for 3 minutes)
    created_at = pendulum.parse(row.reset_token_created_at)
    if pendulum.now("UTC").diff(created_at).in_minutes() > 3:
        raise HTTPException(status_code=400, detail="Reset token expired")

    # 5. Success → return both message and the username for the next step
    return {
        "message":   "Token verified!",
        "user_name": row.username
    }


@router.get("/get-customer/{customer_id}")
def get_customer_by_id(customer_id: str, db: Session = Depends(get_db)):
    # 1. Escape the incoming ID to pre-empt any reflected XSS
    safe_id = html.escape(customer_id)

    # 2. Fetch customer via a prepared parameters (prevents SQLi)
    row = db.execute(
        text("""
            SELECT name, email, phone
              FROM customers
             WHERE customer_id = :id
        """),
        {"id": safe_id}
    ).fetchone()

    # 3. If no record → 404 (no info leak beyond “not found”)
    if not row:
        raise HTTPException(status_code=404, detail="Customer not found")

    # 4. HTML-escape each field on output to prevent any XSS
    name  = html.escape(row.name)
    email = html.escape(row.email)
    phone = html.escape(row.phone)

    # 5. Return the sanitized data
    return {
        "name":  name,
        "email": email,
        "phone": phone
    }

@router.get("/get-customers")
def get_all_customers(db: Session = Depends(get_db)):
    rows = db.execute(
        text("SELECT customer_id, name, email, phone FROM customers")
    ).fetchall()
    if not rows:
        raise HTTPException(status_code=404, detail="No customers found")
    return [
        {
            "customer_id": html.escape(r.customer_id),
            "name":          html.escape(r.name),
            "email":         html.escape(r.email),
            "phone":         html.escape(r.phone),
        }
        for r in rows
    ]