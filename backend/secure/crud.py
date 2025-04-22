from sqlalchemy.orm import Session
from models import User
from utils.security import generate_salt, hash_password

def create_user(db: Session, username: str, email: str, password: str):
    salt = generate_salt()
    hashed_pw = hash_password(password, salt)
    user = User(username=username, email=email, password_hash=hashed_pw, salt=salt)
    db.add(user)
    db.commit()
    db.refresh(user)
    return user
