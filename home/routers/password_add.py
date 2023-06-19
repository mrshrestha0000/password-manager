from fastapi import APIRouter, Form, Depends
from fastapi import FastAPI
from .. import models
from pydantic import BaseModel, EmailStr
from ..auth import auth_class 
from sqlalchemy.orm import Session
from ..database import SessionLocal
from fastapi.responses import JSONResponse
from ..models import user_model, password_model
# from ...task_manager.main import get_db


password_save_router = APIRouter()
app = FastAPI()
auth = auth_class()

class password_instance(BaseModel):
    username : str = Form(...) 
    password : str = Form(...) 
    website : str = Form(...)

# creating a function for db open and close
async def get_db():
    try: 
        db = SessionLocal()
        yield db 
    finally:
        db.close()

# save password to db 
@password_save_router.post('/password_save/')
def password_save(password : password_instance, db: Session = Depends(get_db),mid_data :dict = Depends(auth.mid)):
    try: 
        password_model = models.password_model()
        
        user_obj = db.query(user_model).filter(user_model.email == mid_data['email']).first()

        user_password = password.password
        user_token = user_obj.token

        if user_obj.email == mid_data['email']:
            data = {
            "password":user_password,
            "token":user_token
            }

            encrypted_password_byte = auth.password_save_encryption(data)
            encrypted_password_string = encrypted_password_byte.decode('utf-8')

        # password = auth.password_hash(password.password)

            password_model.username = password.username
            password_model.password = encrypted_password_string
            password_model.website = password.website
            password_model.user_email = mid_data['email']

            db.add(password_model)
            db.commit()

        else:
            return JSONResponse(content={
                "status":999,
                "message":"Invalid Authorization"
            }, status_code=401)

        return {
            "message":f"Data have been successfully saved."
        }
        
    except Exception as e:
        return JSONResponse(content={
            "error":"User has been already been created with same email id.",
            "detail":str(e)
        },
         status_code=400 ) 
    

# retrive password from db 
class password_retrive_instance(BaseModel):
    password : str = Form(...) 

@password_save_router.post('/password_retrive/')
def password_retrive(password : password_retrive_instance, db: Session = Depends(get_db),mid_data :dict = Depends(auth.mid)):
    try: 
        # password_model = models.password_model()
        
        user_obj = db.query(user_model).filter(user_model.email == mid_data['email']).first()
        password_obj = db.query(password_model).filter(password_model.user_email == mid_data['email'])

        if user_obj is not None:
            data = {
            "password" : user_obj.password,
            "token" : user_obj.token
            }

            password_byte = auth.validate_password(data)
            password_string = password_byte.decode('utf-8')

            if password.password == password_string:

                print ("password_obj",vars(password_obj))
                if password_obj is not None: 

                    response_data_list = []

                    for i in password_obj:
                        password_password = i.password
                        user_token = user_obj.token

                        if user_obj.email == mid_data['email']:
                            data = {
                                "password":password_password,
                                "token":user_token
                            }

                            password_byte = auth.password_save_decryption(data)
                            password_string = password_byte.decode('utf-8')

                            password_data = {
                                "password":password_string,
                                "website":i.website,
                                "username":i.username
                            }

                            response_data_list.append(password_data)

                    return JSONResponse(content={
                                "status":000,
                                "message":"Password retrived.",
                                "data":response_data_list
                            },status_code=200)
                
                else:
                    return JSONResponse(content={
                    "status":999,
                    "message":"No saved password yet."
                })

            else:
                return JSONResponse(content={
                    "status":999,
                    "message":"Invalid password."
                })

        else:
            return JSONResponse(content={
                "status":999,
                "message":"Invalid user. Please register user first."
            }, status_code=401)

    except Exception as e:
        return JSONResponse(content={
            "status":999,
            "detail":str(e)
        },
         status_code=400 ) 




