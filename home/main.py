from fastapi import FastAPI
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
from . import models 
# from models import Base
from .routers.user_creation_router import user_creation_router
from .routers.password_add import password_save_router
from .routers.token_router import token_router
from .database import engine

app = FastAPI()
app.include_router(user_creation_router)
app.include_router(password_save_router)
app.include_router(token_router)

models.Base.metadata.create_all(bind=engine)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins
    allow_methods=["*"],  # Allow all methods
    allow_headers=["*"],  # Allow all headers
)