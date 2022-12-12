import fastapi
from fastapi.security import OAuth2PasswordBearer
from fastapi import FastAPI, Body, Depends, HTTPException, status, Request, Response, Depends
from fastapi.responses import StreamingResponse
from fastapi.security import HTTPBearer
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import sessionmaker
import sqlalchemy
from pydantic import BaseModel
import os

from base_start import Users, Token, Directorys, session, check_user_type, check_username_with_token, check_admin_with_token, Config
from crypto import hash_password, check_password, generate_token, JWTBearer
from os_functions import listalldirectoryfiles, downloadfile_from_path, get_os_disk_space, get_os_folder_size

app = fastapi.FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

class login_form(BaseModel):
    username: str
    password: str

@app.post("/login")
def login(data: login_form):
    user = session.query(Users).filter_by(username=data.username).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username"
        )
    elif not check_password(data.password, user.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid password"
        )
    elif check_password(data.password, user.password) and user.autorized == False:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not autorized"
        )
    elif check_password(data.password, user.password) and user.autorized == True:
        token = generate_token()
        token_add = Token(token=token, username=data.username)
        session.add(token_add)
        session.commit()
        return {"login": "success", "token": token, "username": data.username, "type": user.type}

class logout_form(BaseModel):
    token: str

@app.post("/logout", dependencies=[Depends(JWTBearer())])
def logout(data: logout_form):
    token = session.query(Token).filter_by(token=data.token).first()
    if token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token"
        )

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
class adddirectory_form(BaseModel):
    directory_name: str
    directory_path: str
    username: str

@app.post("/adddirectory", dependencies=[Depends(JWTBearer())])
def adddirectory(data: adddirectory_form):
    new_directory = Directorys(
        directory_name=data.directory_name, 
        directory_path=data.directory_path, 
        username=data.username
    )
    with session.begin_nested():
        session.add(new_directory)
        try:
            session.commit()
            return {"adddirectory": "success"}
        except sqlalchemy.exc.IntegrityError:
            raise fastapi.HTTPException(
                status_code=422, 
                detail="directory already exists"
            )
        except sqlalchemy.exc.SQLAlchemyError:
            raise fastapi.HTTPException(
                status_code=422, 
                detail="error adding directory"
            )

#delete directory from database
class deletedirectory_form(BaseModel):
    directory_name: str
    username: str

@app.post("/deletedirectory", dependencies=[Depends(JWTBearer())])
def deletedirectory(data: deletedirectory_form):
    directory = session.query(Directorys).filter_by(
        directory_name=data.directory_name
    ).first()
    if directory is None:
        raise fastapi.HTTPException(
            status_code=422, 
            detail="directory does not exist"
        )
    session.delete(directory)
    session.commit()
    return {"deletedirectory": "success"}


#get all files in directory
class listdirectoryfiles_form(BaseModel):
    directory_name: str

@app.get("/listdirectoryfiles", dependencies=[Depends(JWTBearer())])
def listdirectoryfiles(data: listdirectoryfiles_form):
    directory_path = session.query(Directorys).filter_by(
        directory_name=data.directory_name
    ).first()
    if directory_path is None:
        raise fastapi.HTTPException(
            status_code=422, 
            detail="directory does not exist"
        )
    else:
        files = listalldirectoryfiles(directory_path.directory_path)
        return {"listdirectoryfiles": files}

#list all directorys
@app.get("/listdirectories", dependencies=[Depends(JWTBearer())])
def listdirectorys():
    directorys = session.query(Directorys).all()
    return {"listdirectories": directorys}

#validate token
@app.post("/token", dependencies=[Depends(JWTBearer())])
def token():
    return {"token": "valid"}

#download file
class downloadfile_form(BaseModel):
    file_path: str

@app.get("/downloadfile/{file_path}", dependencies=[Depends(JWTBearer())])
def downloadfile(file_path):
    #check if file exists
    if not os.path.isfile(file_path):
        raise fastapi.HTTPException(
            status_code=422, 
            detail="file does not exist"
        )
    else: 
        raise fastapi.HTTPException(
            status_code=200,
            detail="file exists"
        )

@app.get("/get_disk_space", dependencies=[Depends(JWTBearer())])
def get_disk_space():
    disk_space = get_os_disk_space()
    return {"total": disk_space[0], "used": disk_space[1], "free": disk_space[2]}

@app.get("/get_folder_size/{folder_name}", dependencies=[Depends(JWTBearer())])
def get_folder_size(folder_name):
    folder_path = session.query(Directorys).filter_by(directory_name=folder_name).first()
    if folder_path is None:
        raise fastapi.HTTPException(
            status_code=422, 
            detail="directory does not exist"
        )
    else:
        folder_size = get_os_folder_size(folder_path.directory_path)
        return {"folder_size": folder_size}

class change_user_password_form(BaseModel):
    username: str
    old_password: str
    new_password: str
    token: str

@app.post("/change_user_password", dependencies=[Depends(JWTBearer())])
def change_user_password(data: change_user_password_form):
    user = session.query(Users).filter_by(username=data.username).first()
    checked_password = check_password(data.old_password, user.password)
    checked_username = check_username_with_token(data.token)
    if user is None:
        raise fastapi.HTTPException(
            status_code=422, 
            detail="user does not exist"
        )
    elif checked_password is False:
        raise fastapi.HTTPException(
            status_code=422, 
            detail="incorrect password"
        )
    elif checked_password is True and data.username == checked_username:
        user.password = hash_password(data.new_password)
        session.commit()
        return {"change_user_password": "success"}
    else:
        raise fastapi.HTTPException(
            status_code=422, 
            detail="error changing password"
        )

class User(BaseModel):
    username: str
    user_type: str

@app.get("/list_users", dependencies=[Depends(JWTBearer())])
def list_users(token: str = Depends(check_admin_with_token)):
    users = session.query(Users).all()
    return {"list_users": users}

class change_user_type_form(BaseModel):
    username: str
    autorized: str

@app.post("/change_user_type", dependencies=[Depends(JWTBearer())])
def change_user_type(data: change_user_type_form, token: str = Depends(check_admin_with_token)):
    if check_user_type(data.username) == "admin":
        raise fastapi.HTTPException(
            status_code=422, 
            detail="user is admin"
        )
    user = session.query(Users).filter_by(username=data.username).first()
    if user is None:
        raise fastapi.HTTPException(
            status_code=422, 
            detail="user does not exist"
        )
    else:
        if data.autorized == "True":
            autorized = True
        elif data.autorized == "False":
            autorized = False
        user.autorized = autorized
        print(user.autorized)
        session.commit()
        return {"change_user_type": "success"}

class delete_user_form(BaseModel):
    username: str

@app.post("/delete_user", dependencies=[Depends(JWTBearer())])
def delete_user(data: delete_user_form, token: str = Depends(check_admin_with_token)):
    if check_user_type(data.username) == "admin":
        raise fastapi.HTTPException(
            status_code=422, 
            detail="user is admin"
        )
    user = session.query(Users).filter_by(username=data.username).first()
    if user is None:
        raise fastapi.HTTPException(
            status_code=422, 
            detail="user does not exist"
        )
    else:
        session.delete(user)
        session.commit()
        return {"delete_user": "success"}

@app.get("/all_folder_size", dependencies=[Depends(JWTBearer())])
def all_folder_size():
    folders_paths = session.query(Directorys).all()
    data=[]
    for folder in folders_paths:
        folder = {"folder_name": folder.directory_name, "folder_size": get_os_folder_size(folder.directory_path)}
        for key, value in folder.items():
            folder[key] = value
        data.append(folder)
    return {"all_folder_size": data}

@app.get("/get_all_configs", dependencies=[Depends(JWTBearer())])
def all_configs(token: str = Depends(check_admin_with_token)):
    configs = Config.get_all_configs()
    return {"all_configs": configs}