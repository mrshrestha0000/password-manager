from fastapi import APIRouter, Form, Depends, Response
from pydantic import EmailStr, BaseModel
from .. import models
from ..auth import auth_class 
from sqlalchemy.orm import Session
from ..database import SessionLocal
from datetime import datetime, timedelta
from fastapi.responses import JSONResponse
from ..models import user_model



token_router = APIRouter()
auth = auth_class()


class user_instance(BaseModel):
    email : EmailStr = Form(...) #This is foreign key
    password : str = Form(...)


# creating a function for db open and close
async def get_db():
    try: 
        db = SessionLocal()
        yield db 
    finally:
        db.close()


# API to create auth token using oauth
@token_router.post('/create_token')
def create_token(user :user_instance, db: Session = Depends(get_db)):

    user_obj = db.query(user_model).filter(user_model.email == user.email).first()

    if user_obj is not None:
        data = {
            "password" : user_obj.password,
            "token" : user_obj.token
        }
        password_byte = auth.validate_password(data)
        password_string = password_byte.decode('utf-8')

        if user.password == password_string:
            user_dict = {"email":user_obj.email,"password":user_obj.password}

            access_token = auth.create_access_token(user_dict)
            refresh_token = auth.create_refresh_token(user_dict)

            return {
                    "access_token":access_token,
                    "refresh_token":refresh_token,
                    "token_type":"bearer",
                    "expiry_on":datetime.utcnow() + timedelta(minutes=5)
                    }
        

        else:
            return JSONResponse(content={
                "status":999,
                "message":"Invalid password",
            }, status_code=400)


    else: 
        return JSONResponse(content={
                "status":999,
                "message":"Invalid email id."
            }, status_code=400)



        
# API to create refresh token 
class token(BaseModel):
    refresh_token : str
@token_router.post('/refresh_token')
def refresh_token(refresh_token : token, response: Response):
    try: 
        refresh_token = refresh_token.refresh_token.encode()
        data = auth.decode_token(refresh_token)

        if data['type'] == 'refresh':
            user_dict = {"email":data['email']}
            return {
                "access_token": auth.create_access_token(user_dict),
                "token_type":"bearer",
                "expiry_on":datetime.utcnow() + timedelta(minutes=5)
            }
        
        if data['type'] == 'access':
            response.status_code = 401
            return {"error":"Invalid refresh token. You are using access token"}
    
    except Exception as e:
        return JSONResponse(content={
            "error":"Invalid token",
            "exception":str(e)
        }, status_code=400 )