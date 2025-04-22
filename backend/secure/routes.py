from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from database import get_db
from crud import create_user
from utils.security import is_password_valid
from config import PASSWORD_COMPLEXITY_REGEX, MIN_PASSWORD_LENGTH, COMMON_PASSWORDS, GUIDLINE_DESCRIPTION


router = APIRouter()

class RegisterRequest(BaseModel):
    username: str
    email: str
    password: str

@router.post("/register")
def register_user(request: RegisterRequest, db: Session = Depends(get_db)):
    if request.password in COMMON_PASSWORDS:
        raise HTTPException(status_code=400, detail="Password is too common")

    if not is_password_valid(request.password):
        raise HTTPException(status_code=400, detail="Password must include lowercase, uppercase, digit, and special character")

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

