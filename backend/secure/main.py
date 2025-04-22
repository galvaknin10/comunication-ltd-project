from fastapi import FastAPI
from models import User
from database import Base, engine
from routes import router

app = FastAPI()

# Create DB tables
Base.metadata.create_all(bind=engine)

app.include_router(router)
