from sqlalchemy import Column, Integer, String, DateTime
from database import Base
from datetime import datetime

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=False, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    salt = Column(String, nullable=False)
    failed_attempts = Column(Integer, default=0)
    successful_logins = Column(Integer, default=0)
    locked_until = Column(DateTime, nullable=True)


class Customer(Base):
    __tablename__ = "customers"

    id = Column(Integer, primary_key=True, index=True)
    customer_id = Column(Integer, unique=True, nullable=False)
    name = Column(String, nullable=False)
    email = Column(String, unique=False, nullable=False)
    phone = Column(String, nullable=True)
