import fastapi
from fastapi.security import OAuth2PasswordBearer
from fastapi import FastAPI, Body, Depends, HTTPException, status, Request
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import sessionmaker
from pydantic import BaseModel

from base_start import Users, Token, Directorys, session
from crypto import hash_password, check_password, generate_token, JWTBearer

app = fastapi.FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

class login_form(BaseModel):
    username: str
    password: str

@app.post("/login")
def login(data: login_form):
    user = session.query(Users).filter_by(username=data.username).first()
    if check_password(data.password, user.password) == True:
        token = generate_token()
        token_add = Token(token=token, username=data.username)
        session.add(token_add)
        session.commit()
        return {"login": "success", "token": token}
    else:
        return {"login": "failed"}

class logout_form(BaseModel):
    token: str

@app.post("/logout", dependencies=[Depends(JWTBearer())])
def logout(data: logout_form):
    token = session.query(Token).filter_by(token=data.token).first()
    session.delete(token)
    session.commit()
    return {"logout": "success"}

class adduser_form(BaseModel):
    username: str
    password: str
    email: str

@app.post("/adduser")
def adduser(data: adduser_form):
    user = Users(username=data.username, password=hash_password(data.password), type='user', email=data.email)
    session.add(user)
    session.commit()
    return {"adduser": "success"}

#add new directory to database
@app.post("/adddirectory", dependencies=[Depends(JWTBearer())])
def adddirectory(directory_name: str, directory_path: str, username: str):
    directory = Directorys(directory_name=directory_name, directory_path=directory_path, username=username)
    session.add(directory)
    session.commit()
    return {"adddirectory": "success"}

#list all directorys
@app.get("/listdirectorys", dependencies=[Depends(JWTBearer())])
def listdirectorys():
    directorys = session.query(Directorys).all()
    return {"listdirectorys": directorys}

#validate token
@app.post("/token", dependencies=[Depends(JWTBearer())])
def token():
    return {"token": "valid"}