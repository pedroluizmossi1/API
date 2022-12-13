import fastapi
from fastapi.security import OAuth2PasswordBearer
from fastapi import FastAPI, Body, Depends, HTTPException, status, Request, Response, Depends
from pydantic import BaseModel
import os

from base_start import Users, Token, Directories, session, check_user_type, check_username_with_token, check_admin_with_token, Config, hash_password, check_password, generate_token, JWTBearer, check_user_exists
from os_functions import listalldirectoryfiles, downloadfile_from_path, get_os_disk_space, get_os_folder_size

app = fastapi.FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

@app.post("/login")
def login(data: Users.Api_login):
    user = Users.Api_login.login_user(data.username, data.password)
    if user is None:
        raise HTTPException(
            status_code=401,
            detail="Nome de usuário ou senha incorretos"
        )
    elif user is not None:
        print(user)
        return {"login": "success", "token": user["token"], "username": data.username, "type": user["type"]}

class logout_form(BaseModel):
    token: str

@app.post("/logout", dependencies=[Depends(JWTBearer())])
def logout(data: logout_form):
    token = session.query(Token).filter_by(token=data.token).first()
    if token is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid token"
        )

    session.delete(token)
    session.commit()
    return {"logout": "success"}



@app.post("/user")
def add_user(data: Users.Api_add):
    Users.Api_add.add_user(data.username, data.password, data.email)
    return {"adduser": "success"}

@app.get("/user/all", dependencies=[Depends(JWTBearer())])
def all_users(token: str = Depends(check_admin_with_token)):
    users = session.query(Users.username, Users.email, Users.type, Users.autorized).all()
    return {"users": users}

@app.put("/user/password", dependencies=[Depends(JWTBearer())])
def change_user_password(data: Users.Api_update_password):
    user = Users.Api_update_password.update_password(data.username, data.old_password, data.new_password, data.token)
    if user is None:
        raise fastapi.HTTPException(
            status_code=422, 
            detail="Senha incorreta"
        )
    elif user is not None:
        return {"detail": "Senha alterada com sucesso"}
    else:
        raise fastapi.HTTPException(
            status_code=422, 
            detail="Erro ao alterar senha"
        )

@app.put("/user/authorized", dependencies=[Depends(JWTBearer())])
def change_user_autorization(data: Users.Api_update_autorized, token: str = Depends(check_admin_with_token)):
    user = check_user_exists(data.username)
    autorized = Users.Api_check_admin.check_admin(data.username)
    if autorized is True:
        raise fastapi.HTTPException(
            status_code=422, 
            detail="Usuário é admin"
        )
    elif user is None:
        raise fastapi.HTTPException(
            status_code=422, 
            detail="Usuário não existe"
        )
    elif user is not None and autorized is False:
        print(user, autorized)
        Users.Api_update_autorized.update_autorized(data.username, data.autorized)
        return {"detail": "Autorização alterada com sucesso"}
    else:
        raise fastapi.HTTPException(
            status_code=422, 
            detail="Erro ao alterar autorização"
        )


@app.put("/user/type", dependencies=[Depends(JWTBearer())])
def change_user_type(data: Users.Api_update_type, token: str = Depends(check_admin_with_token)):
    user = check_user_exists(data.username)
    admin = Users.Api_check_admin.check_admin(data.username)
    if admin:
        raise fastapi.HTTPException(
            status_code=422, 
            detail="Usuário é admin"
        )
    elif user is None:
            raise fastapi.HTTPException(
                status_code=422, 
                detail="Usuário não existe"
            )
    elif user is not None and admin is False:
        Users.Api_update_type.update_type(data.username, data.type)
        return {"detail": "Tipo alterado com sucesso"}
    else:
        raise fastapi.HTTPException(
            status_code=422, 
            detail="Erro ao alterar tipo"
        )

@app.put("/user/email", dependencies=[Depends(JWTBearer())])
def change_user_email(data: Users.Api_update_email, token: str = Depends(check_admin_with_token)):
    user = check_user_exists(data.username)
    admin = Users.Api_check_admin.check_admin(data.username)
    if admin:
        raise fastapi.HTTPException(
            status_code=422, 
            detail="Usuário é admin"
        )
    elif user is None:
            raise fastapi.HTTPException(
                status_code=422, 
                detail="Usuário não existe"
            )
    elif user is not None and admin is False:
        Users.Api_update_email.update_email(data.username, data.email)
        return {"detail": "Email alterado com sucesso"}
    else:
        raise fastapi.HTTPException(
            status_code=422, 
            detail="Erro ao alterar email"
        )

@app.put("/user/name", dependencies=[Depends(JWTBearer())])
def change_user_name(data: Users.Api_update_username, token: str = Depends(check_admin_with_token)):
    user = check_user_exists(data.old_username)
    admin = Users.Api_check_admin.check_admin(data.old_username)
    if admin:
        raise fastapi.HTTPException(
            status_code=422, 
            detail="Usuário é admin"
        )
    elif user is None:
            raise fastapi.HTTPException(
                status_code=422, 
                detail="Usuário não existe"
            )
    elif user is not None and admin is False:
        Users.Api_update_username.update_username(data.old_username, data.new_username)
        return {"detail": "Nome de usuário alterado com sucesso"}
    else:
        raise fastapi.HTTPException(
            status_code=422, 
            detail="Erro ao alterar nome de usuário"
        )


@app.delete("/user", dependencies=[Depends(JWTBearer())])
def delete_user(data:Users.Api_delete, token: str = Depends(check_admin_with_token)):
    user = session.query(Users).filter_by(username=data.username).first()
    if check_user_type(data.username) == "admin":
        raise fastapi.HTTPException(
            status_code=422, 
            detail="user is admin"
        )
    elif user is None:
        raise fastapi.HTTPException(
            status_code=422, 
            detail="user does not exist"
        )
    elif user is not None and check_user_type(data.username) != "admin":
        Users.Api_delete.delete_user(data.username)
        return {"delete_user": "success"}
    else:
        raise fastapi.HTTPException(
            status_code=422, 
            detail="error deleting user"
        )

@app.post("/directory", dependencies=[Depends(JWTBearer())])
def add_directory(data: Directories.Api_add):
    directory = Directories.Api_add.add_directory(data.directory_name, data.directory_path, data.username)
    if directory is None:
        raise fastapi.HTTPException(
            status_code=422, 
            detail="Diretório já existe"
        )
    return {"add_directory": "Diretório criado com sucesso"}

@app.delete("/directory", dependencies=[Depends(JWTBearer())])
def delete_directory(data: Directories.Api_delete):
    directory = Directories.Api_delete.delete_directory(data.directory_name)
    if directory is None:
        raise fastapi.HTTPException(
            status_code=422, 
            detail="Diretório não existe"
        )
    return {"delete_directory": "Diretório deletado com sucesso"}


#get all files in directory

@app.get("/directory/file/all", dependencies=[Depends(JWTBearer())])
def all_directory_files(data: Directories.Api_list):
    directory_path = Directories.Api_list.list_directory(data.directory_name)
    if directory_path is None:
        raise fastapi.HTTPException(
            status_code=422, 
            detail="directory does not exist"
        )
    else:
        files = listalldirectoryfiles(directory_path.directory_path)
        return {"files": files}

@app.get("/directory/all", dependencies=[Depends(JWTBearer())])
def all_directories():
    directories = Directories.Api_list.list_all_directories()
    return {"directories": directories}

@app.get("/directory/size/", dependencies=[Depends(JWTBearer())])
def directory_size(folder_name):
    folder_path = session.query(Directories).filter_by(directory_name=folder_name).first()
    if folder_path is None:
        raise fastapi.HTTPException(
            status_code=422, 
            detail="directory does not exist"
        )
    else:
        folder_size = get_os_folder_size(folder_path.directory_path)
        return {"folder_size": folder_size}

@app.get("/directory/size/all", dependencies=[Depends(JWTBearer())])
def all_folder_size():
    folders_paths = Directories.Api_list.list_all_directories()
    data=[]
    if folders_paths is None:
        raise fastapi.HTTPException(
            status_code=422, 
            detail="Diretório não existe"
        )
    elif folders_paths is not None:
        for folder in folders_paths:
            folder = {"folder_name": folder.directory_name, "folder_size": get_os_folder_size(folder.directory_path)}
            for key, value in folder.items():
                folder[key] = value
            data.append(folder)
        return {"all_folder_size": data}
    else:
        raise fastapi.HTTPException(
            status_code=422, 
            detail="Erro ao listar diretórios"
        )

@app.get("/token", dependencies=[Depends(JWTBearer())])
def token():
    return {"token": "valid"}


class downloadfile_form(BaseModel):
    file_path: str

@app.get("/downloadfile", dependencies=[Depends(JWTBearer())])
def downloadfile(file_path):
    if not os.path.isfile(file_path):
        raise fastapi.HTTPException(
            status_code=422, 
            detail="file does not exist" + file_path
        )
    else: 
        raise fastapi.HTTPException(
            status_code=200,
            detail="file exists"
        )

@app.get("/disk/space", dependencies=[Depends(JWTBearer())])
def disk_space():
    disk_space = get_os_disk_space()
    return {"total": disk_space[0], "used": disk_space[1], "free": disk_space[2]}



@app.get("/config/all", dependencies=[Depends(JWTBearer())])
def all_configs(token: str = Depends(check_admin_with_token)):
    configs = Config.get_all_configs()
    return {"all_configs": configs}

@app.put("/config", dependencies=[Depends(JWTBearer())])
def update_config(data: Config.Api_update, token: str = Depends(check_admin_with_token)):
    username = check_username_with_token(token)
    config = Config.Api_update.update_config(data.config_name, data.config_value, username)
    if config is None:
        raise fastapi.HTTPException(
            status_code=422, 
            detail="Configuração não existe"
        )
    return {"detail": "Configuração alterada com sucesso"}