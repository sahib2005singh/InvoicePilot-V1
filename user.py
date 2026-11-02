
from unicodedata import name
from pydoc import describe
from enum import verify
from h11._abnf import status_code
from starlette.types import Message
from fastapi import File
from datetime import datetime , timedelta, timezone
from fastapi import FastAPI , Path , Query, HTTPException , Depends , Header
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordBearer,OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr,Field, SecretStr
from typing import Annotated, Literal, List, Dict
import json
import jwt
from jwt.exceptions import InvalidTokenError
import os
from pwdlib import PasswordHash
from dotenv import load_dotenv
load_dotenv()

class UserRegister(BaseModel):
    name: Annotated[str, Field(..., description = "The name of the user")]
    email: EmailStr
    gender: Annotated[Literal['male', 'female', 'other'], Field(..., description = 'Gender of the user')]
    password: Annotated[str, Field(..., description="enter password")]

class UserInternal(BaseModel):
    name : Annotated[str, Field(..., description= "Name Of The User")]
    email: Annotated[EmailStr, Field(..., description = "email of the user")]
    gender: Annotated[Literal['male', 'female', 'other'], Field(..., description="Gender of the user")]
    password: Annotated[SecretStr, Field(..., description="hashed password")]

class UserResponse(BaseModel):
    name: str
    email: EmailStr 
    gender: str
    

app = FastAPI()
SECRET_KEY = os.getenv("secret_key")
ALGORITHM = 'HS256'
TOKEN_EXPIRE = 30
PASSWORD_HASH = PasswordHash.recommended()
OAuth_scheme = OAuth2PasswordBearer(tokenUrl= 'token')

def load_data():
    with open("user_data.json", "r") as file:
        data = json.load(file)
        return data

def save_data(data):
    with open("user_data.json", "w") as file:
        json.dump(data, file)

def create_access_token(data:dict):
    expiration = datetime.now(timezone.utc) + timedelta(minutes=TOKEN_EXPIRE)
    payload = data.copy()
    payload["sub"] = data["email"]
    payload["exp"] = expiration
    encoded_token = jwt.encode(payload, SECRET_KEY , algorithm=ALGORITHM)
    return encoded_token

def get_current_user(encoded_token: Annotated[str, Depends(OAuth_scheme)]):
    try:
        
        decoded_token = jwt.decode(encoded_token , SECRET_KEY, algorithms=[ALGORITHM])
       
    except InvalidTokenError:
        raise HTTPException(status_code = 401 , detail = "Could not validate credentials")
    data = load_data()
    email = decoded_token.get("sub")
    if not email or not isinstance(email,str):
        raise HTTPException(status_code = 401, detail = "email empty/not in jwt")
    
    if not email in data:
        raise HTTPException(status_code = 401, detail = "User Does Not Exist")
    user = data[email]

    internal = UserInternal(
        name = user["name"],
        email= email,
        gender=user["gender"],
        password=user["password"]
    )
    return {
        "name": internal.name,
        "email": internal.email,
        "gender": internal.gender
    }


@app.post("/create_user", response_model= UserResponse)
def create_user(user: UserRegister):
    data = load_data()
    email = user.email.lower().strip()
    if email in data:
        raise HTTPException(status_code = 400, detail = 'User Already Exists')
    else:
        hashed_password = PASSWORD_HASH.hash(user.password)
        user_data = UserInternal(
            name = user.name, 
            email = email, 
            gender= user.gender,
            password= SecretStr(hashed_password))
        data[email] = {
            "name": user_data.name,
            "gender": user_data.gender,
            "password": user_data.password.get_secret_value()
        }
        save_data(data)
        return {
            "name": user_data.name,
            "gender": user_data.gender,
            "email": user_data.email   
            }

@app.post("/token")
def login(form_data: Annotated[OAuth2PasswordRequestForm , Depends()]):
    data = load_data()
    email = form_data.username.lower().strip()
    if not email in data:
        raise HTTPException(status_code = 401, detail = "invalid credentials")
    user = data[email]
    
    is_password_valid = PASSWORD_HASH.verify(form_data.password, user["password"])

    if not is_password_valid:
        raise HTTPException(status_code = 401, detail = "invalid credentials")
    create_token = create_access_token({"email": email})
    return {
        "access_token" : create_token,
        "token_type" : "bearer"
    }

@app.get("/profile", response_model= UserResponse)
def user_profile(current_user: Annotated[dict, Depends(get_current_user)]):
    return current_user
        
