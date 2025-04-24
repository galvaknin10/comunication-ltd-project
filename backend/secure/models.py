from sqlalchemy import Column, Integer, String, DateTime
from database import Base
from datetime import datetime

# User model representing application users and their credentials/state
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    salt = Column(String, nullable=False)
    failed_attempts = Column(Integer, default=0)
    successful_logins = Column(Integer, default=0)
    locked_until = Column(DateTime, nullable=True)
    reset_token = Column(String, nullable=True)
    reset_token_created_at = Column(DateTime, nullable=True)

# Customer model representing external clients or system users
class Customer(Base):
    __tablename__ = "customers"

    id = Column(Integer, primary_key=True, index=True)
    customer_id = Column(String, unique=True, nullable=False)
    name = Column(String, nullable=False)
    email = Column(String, nullable=False)
    phone = Column(String, nullable=True)
