from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from database import get_db
from crud import create_user, create_customer
from utils.security import is_password_valid, hash_password
from config import COMMON_PASSWORDS, PASSWORD_COMPLEXITY_REGEX, MIN_PASSWORD_LENGTH, GUIDLINE_DESCRIPTION, FORCE_PASSWORD_CHANGE_AFTER_LOGINS, MAX_LOGIN_ATTEMPTS
from models import User, Customer
import pendulum
import hashlib
import time
import smtplib
from email.mime.text import MIMEText
from dotenv import load_dotenv
import os
import bleach

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
def register_user(request: RegisterRequest, db: Session = Depends(get_db)):
    existing_user = db.query(User).filter(User.username == request.username).first()
    if existing_user:
        raise HTTPException(status_code=409, detail="Username already exists")
    
    if request.password in COMMON_PASSWORDS:
        raise HTTPException(status_code=400, detail="Your password is too common. Try picking something more unique and secure.")

    if not is_password_valid(request.password):
        raise HTTPException(status_code=400, detail="Password doesn't meet our policy")


    return create_user(
        db=db,
        username=request.username,
        email=request.email,
        password=request.password
    )

@router.get("/password-policy")
def get_password_policy():
    return {
        "min_length": MIN_PASSWORD_LENGTH,
        "common_passwords": list(COMMON_PASSWORDS),
        "regex": PASSWORD_COMPLEXITY_REGEX,
        "guidelines": GUIDLINE_DESCRIPTION
    }

@router.post("/login")
def login_user(request: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == request.username).first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    now_utc = pendulum.now("UTC")

    # ⛔ Already locked?
    if user.locked_until and pendulum.instance(user.locked_until) > now_utc:
        locked_time = pendulum.instance(user.locked_until).in_timezone("Asia/Jerusalem").format("HH:mm:ss")
        raise HTTPException(status_code=403, detail=f"Account locked until {locked_time}")
    elif user.locked_until and pendulum.instance(user.locked_until) <= now_utc:
        # Lock expired — clear it and reset failed attempts
        user.locked_until = None
        user.failed_attempts = 0
        db.commit()

    # 🔐 Check password
    hashed = hash_password(request.password, user.salt)

    if hashed != user.password_hash:
        user.failed_attempts += 1

        if user.failed_attempts >= MAX_LOGIN_ATTEMPTS:
            user.locked_until = now_utc.add(minutes=3)
            db.commit()
            raise HTTPException(status_code=403, detail="Account locked due to too many failed attempts.")

        if user.failed_attempts == MAX_LOGIN_ATTEMPTS - 1:
            db.commit()
            raise HTTPException(status_code=403, detail="Notice: 1 more failed attempt before lock.")

        db.commit()
        raise HTTPException(status_code=401, detail="Incorrect password")

    # ✅ Successful login
    user.failed_attempts = 0
    user.successful_logins += 1
    user.locked_until = None
    db.commit()

    return {
        "message": "Login successful",
        "force_password_change": user.successful_logins >= FORCE_PASSWORD_CHANGE_AFTER_LOGINS
    }


@router.post("/customers")
def add_customer(request: CustomerCreate, db: Session = Depends(get_db)):
    existing_customer = db.query(Customer).filter(Customer.customer_id == request.customer_id).first()
    if existing_customer:
        raise HTTPException(status_code=409, detail="Customer already exists")

    return create_customer(
        db=db,
        customer_id=request.customer_id,
        name= bleach.clean(request.name), # Secure version
        email=request.email,
        phone=request.phone
    )


@router.post("/change-password")
def change_password(request: ChangePasswordRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == request.username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if request.new_password in COMMON_PASSWORDS:
        raise HTTPException(status_code=400, detail="Your password is too common. Try picking something more unique and secure.")

    if not is_password_valid(request.new_password):
        raise HTTPException(status_code=400, detail="Password doesn't meet our policy")
    
    if user.password_hash == hash_password(request.new_password, user.salt):
        raise HTTPException(status_code=400, detail="You must pick a new password!")

    user.password_hash = hash_password(request.new_password, user.salt)
    user.successful_logins = 0 
    db.commit()
    return {"message": "Password updated"}


@router.post("/request-password-reset")
def request_password_reset(request: EmailRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == request.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="Email not found")

    timestamp = str(time.time())
    raw_string = f"{request.email}{timestamp}{user.username}"
    token = hashlib.sha1(raw_string.encode()).hexdigest()

    user.reset_token = token
    user.reset_token_created_at = pendulum.now("UTC")
    db.commit()

    # Send the token by email
    send_reset_email(user.email, token)

    return {
        "message": "Token generated and sent via email",
        "username": user.username
    }

def send_reset_email(to_email: str, token: str):
    msg = MIMEText(f"Here’s your reset token: {token}")
    msg["Subject"] = "Password Reset Request"
    msg["From"] = "youremail@gmail.com"
    msg["To"] = to_email

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(EMAIL_USER, EMAIL_PASS)
        server.send_message(msg)


@router.post("/verify-token")
def verify_token(request: VerifyToken, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == request.username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user.reset_token != request.token:
        raise HTTPException(status_code=400, detail="Invalid token")

    created_at = pendulum.instance(user.reset_token_created_at)
    if pendulum.now("UTC").diff(created_at).in_minutes() > 3:
        raise HTTPException(status_code=400, detail="Reset token expired")

    return {
        "message": "Token verified"
    }


@router.get("/get-customer/{customer_id}")
def get_customer_by_id(customer_id: str, db: Session = Depends(get_db)):
    customer = db.query(Customer).filter(Customer.customer_id == customer_id).first()
    if not customer:
        raise HTTPException(status_code=404, detail="Customer not found")
    
    return {
        "name": customer.name,
        "email": customer.email,
        "phone": customer.phone
    }
