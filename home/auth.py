import hashlib
from datetime import datetime, timedelta
import jwt
from fastapi import FastAPI, Request, HTTPException, Response
from .database import SessionLocal
from . import models
from passlib.context import CryptContext
from cryptography.fernet import Fernet
from . import settings

SECRET_KEY = settings.SECRET_KEY
ALGORITHM = settings.ALGORITHM

app = FastAPI()

class auth_class():
    # Function to hash the password using hashlip
    # def password_hash(self, password):
    #     hashed_password = hashlib.sha256(password.encode()).hexdigest()
    #     return (hashed_password)
    
    
    def password_hash(self, password):
        key = Fernet.generate_key()
        cipher_suite = Fernet(key)
        encrypted_password = cipher_suite.encrypt(password.encode())
        return {
            "encrypted_password":encrypted_password,
            "key":key
        }

    # Decrypt the password
    # def decrypt_password(encrypted_password, key):
    #     cipher_suite = Fernet(key)
    #     decrypted_password = cipher_suite.decrypt(encrypted_password.encode())
    #     return decrypted_password.decode()

    def validate_password(self, data):

        password_string = data.get('password')
        token_string = data.get('token')

        passsword_byte = password_string.encode('utf-8')
        token_byte = token_string.encode('utf-8')

        cipher_suite = Fernet(token_byte)
        decrypted_password = cipher_suite.decrypt(passsword_byte)
        return decrypted_password


    def password_save_encryption(self, data):

        password_string = data.get('password')
        token_string = data.get('token')
        token_byte = token_string.encode('utf-8')
        cipher_suite = Fernet(token_byte)
        encrypted_password = cipher_suite.encrypt(password_string.encode())
        return encrypted_password
    

    def password_save_decryption(self, data):
            
        password_string = data.get('password')
        token_string = data.get('token')
        passsword_byte = password_string.encode('utf-8')
        token_byte = token_string.encode('utf-8')
        cipher_suite = Fernet(token_byte)
        decrypted_password = cipher_suite.decrypt(passsword_byte)
        return decrypted_password



    # create access token
    def create_access_token(self, data:dict):
        expire = datetime.utcnow() + timedelta(minutes=100)
        data.update({"exp": expire, "type": "access"})
        encoded_jwt = jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)
        return encoded_jwt

    # create refresh token
    def create_refresh_token(self, data: dict):
        expire = datetime.utcnow() + timedelta(minutes=3600)
        data.update({"exp": expire, "type": "refresh"})
        encoded_jwt = jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)
        return encoded_jwt


    # decode tokens
    def decode_token(self, token):
        payload = jwt.decode(token, SECRET_KEY, algorithms=ALGORITHM)
        return payload


    # create middleware to authenticate
    def mid(self, request:Request):
        db = SessionLocal()
        token = request.headers.get('Authorization')
        user = db.query(models.user_model).all()

        try: 
            decode_auth = jwt.decode(token, SECRET_KEY, algorithms=ALGORITHM)
            type = decode_auth['type']
            email = decode_auth['email']
        except: 
            raise HTTPException (status_code=401, detail="Invalid Auth.")
        
        if type == "refresh":
            raise HTTPException (status_code=401, detail="Invalid Auth. You are using refresh token.")

        for i in user:
            if email == i.email and type == "access":
                return {"email":email, "type":"access"}

        Response.status_code = 401
        db.close()
