from fastapi import FastAPI
from database import Base, engine
from models import User, Customer
from routes import router

app = FastAPI()

# Create DB tables
Base.metadata.create_all(bind=engine)

app.include_router(router)
