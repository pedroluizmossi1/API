import fastapi
from fastapi import FastAPI, Body, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm, HTTPBearer, HTTPAuthorizationCredentials
import uvicorn
import os
import sqlalchemy
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import sessionmaker
from pydantic import BaseModel
import datetime
import time

from crypto import hash_password, check_password, generate_token

app = fastapi.FastAPI()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

@app.get("/")
def read_root():
    return {"Hello": "World"}

engine = sqlalchemy.create_engine('sqlite:///base.db', connect_args={'check_same_thread': False})
metadata = sqlalchemy.MetaData()
Base = declarative_base()
Session = sessionmaker(bind=engine)
session = Session()
#create users login table
class Users(Base):
    __tablename__ = 'users'
    id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
    username = sqlalchemy.Column(sqlalchemy.String, unique=True)
    password = sqlalchemy.Column(sqlalchemy.String)
    type = sqlalchemy.Column(sqlalchemy.String, default='user')
    email = sqlalchemy.Column(sqlalchemy.String)
    date = sqlalchemy.Column(sqlalchemy.DateTime, default=datetime.datetime.utcnow)

    def __repr__(self):
        return f"User(id={self.id}, username={self.username}, password={self.password}, type={self.type}, email={self.email})"

#create token check table
class Token(Base):
    __tablename__ = 'token'
    id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
    token = sqlalchemy.Column(sqlalchemy.String, unique=True)
    username = sqlalchemy.Column(sqlalchemy.String)
    date = sqlalchemy.Column(sqlalchemy.DateTime, default=datetime.datetime.utcnow)

    def __repr__(self):
        return f"Token(id={self.id}, token={self.token}, username={self.username})"

#create directorys table
class Directorys(Base):
    __tablename__ = 'directorys'
    id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
    directory_name = sqlalchemy.Column(sqlalchemy.String, unique=True)
    directory_path = sqlalchemy.Column(sqlalchemy.String, unique=True)
    username = sqlalchemy.Column(sqlalchemy.String)
    date = sqlalchemy.Column(sqlalchemy.DateTime, default=datetime.datetime.utcnow)

    def __repr__(self):
        return f"Directorys(id={self.id}, directory_name={self.directory_name}, directory_path={self.directory_path}, username={self.username})"

Base.metadata.create_all(engine)

#get token from database
class JWTBearer(HTTPBearer):
    def __init__(self, auto_error: bool = True):
        super(JWTBearer, self).__init__(auto_error=auto_error)

    async def __call__(self, request: Request):
        credentials: HTTPAuthorizationCredentials = await super(JWTBearer, self).__call__(request)
        if credentials:
            if not credentials.scheme == "Bearer":
                raise HTTPException(status_code=403, detail="Invalid authentication scheme.")
            if not self.verify_jwt(credentials.credentials):
                raise HTTPException(status_code=403, detail="Invalid token or expired token.")
            return credentials.credentials
        else:
            raise HTTPException(status_code=403, detail="Invalid authorization code.")

    def verify_token_from_db(self, token):
        token = session.query(Token).filter_by(token=token).first()
        if token != None:
            return True
        else:
            return False
    #verify token
    def verify_jwt(self, token):
        if self.verify_token_from_db(token):
            return True
        else:
            return False



#add admin user to database if not exist
if session.query(Users).filter_by(username="admin").first() == None:
    admin = Users(username='admin', password=hash_password('admin'), type='admin',email="pedroluizmossi@gmail.com",)
    session.add(admin)
    session.commit()


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

if __name__ == '__main__':
    uvicorn.run(app, host='0.0.0.0', port=8000)