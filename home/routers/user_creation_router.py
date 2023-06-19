from fastapi import APIRouter, Form, Depends
from fastapi import FastAPI
from .. import models
from pydantic import BaseModel, EmailStr
from ..auth import auth_class 
from sqlalchemy.orm import Session
from ..database import SessionLocal
from fastapi.responses import JSONResponse
from passlib.context import CryptContext
from ..models import user_model
# from ...task_manager.main import get_db


user_creation_router = APIRouter()
app = FastAPI()
auth = auth_class()

# creating a function for db open and close
async def get_db():
    try: 
        db = SessionLocal()
        yield db 
    finally:
        db.close()


class user_instance(BaseModel):
    email : EmailStr = Form(...) #This is foreign key
    password : str = Form(...) 

# new user creation
@user_creation_router.post('/create_user/')
def create_user(user : user_instance, db: Session = Depends(get_db)):
    try: 
        user_model = models.user_model()

        token_concat = user.email+user.password
        # token = auth.token_hash(token_concat) 

        hashed = auth.password_hash(user.password)
       
        password_byte = hashed.get('encrypted_password')
        token_byte = hashed.get('key')

        password_string = password_byte.decode('utf-8')
        token_string = token_byte.decode('utf-8')

        user_model.email = user.email
        user_model.password = password_string
        user_model.token = token_string

        db.add(user_model)
        db.commit()
        
        return JSONResponse(content={
            "status":000,
            "message":f"User have been successfully created with {user.email}"
        }, status_code=200)

        
    except Exception as e:
        return JSONResponse(content={
            "error":"User has been already been created with same email id.",
            "status":999,
            "detail":str(e)
        },
         status_code=400) 
    

@user_creation_router.post('/login/')
def login(login_data:user_instance, db:Session = Depends(get_db),mid_data :dict = Depends(auth.mid)):

    user_obj = db.query(user_model).filter(user_model.email == login_data.email).first()


    if user_obj is not None:
        data = {
        "password" : user_obj.password,
        "token" : user_obj.token
        }
        password_byte = auth.validate_password(data)
        password_string = password_byte.decode('utf-8')


        if login_data.password == password_string:
            return JSONResponse(content={
                "status":000,
                "message":"user is valid. Password validated"
            }, status_code=200)
        else:
            return JSONResponse(content={
                "status":999,
                "message":"password is invalid."
            }, status_code=400)
    else:
        return JSONResponse(content={
            "status_code":999,
            "message":"Email id not found."
        },status_code=400)






