from sqlalchemy.orm import Session
from models import User, Customer
from utils.security import generate_salt, hash_password

def create_user(db: Session, username: str, email: str, password: str):
    salt = generate_salt()
    hashed_pw = hash_password(password, salt)
    user = User(username=username, email=email, password_hash=hashed_pw, salt=salt)
    db.add(user)
    db.commit()
    db.refresh(user)
    return user

def create_customer(db: Session, customer_id: int, name: str, email: str, phone: str):
    customer = Customer(customer_id=customer_id, name=name, email=email, phone=phone)
    db.add(customer)
    db.commit()
    db.refresh(customer)
    return customer

