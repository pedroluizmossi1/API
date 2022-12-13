import sqlalchemy
import datetime
from sqlalchemy.orm import declarative_base, sessionmaker
import time
from fastapi import HTTPException, Header, status, Depends
import configparser
from pydantic import BaseModel
import bcrypt
from uuid import uuid4
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi import HTTPException, Request

timezone = datetime.timezone(datetime.timedelta(hours=-3))
timezone_br = datetime.datetime.now(timezone)

engine = sqlalchemy.create_engine(
    'sqlite:///base.db', connect_args={'check_same_thread': False})
metadata = sqlalchemy.MetaData()
Base = declarative_base()
Session = sessionmaker(bind=engine)
session = Session()


def hash_password(password):
    password = str(password).encode('utf-8')
    hashed = bcrypt.hashpw(password, bcrypt.gensalt())
    return hashed

def check_password(password, hashed):
    password = str(password).encode('utf-8')
    if bcrypt.checkpw(password, hashed):
        return True
    else:
        return False

#def to generate token from username and password
def generate_token():
    token = str(uuid4())
    return token

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


class Users(Base):
    __tablename__ = 'users'
    id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
    username = sqlalchemy.Column(sqlalchemy.String, unique=True)
    password = sqlalchemy.Column(sqlalchemy.String)
    type = sqlalchemy.Column(sqlalchemy.String, default='user')
    email = sqlalchemy.Column(sqlalchemy.String)
    date = sqlalchemy.Column(
    sqlalchemy.DateTime, default=datetime.datetime.utcnow),
    autorized = sqlalchemy.Column(sqlalchemy.Boolean, default=False)

    def __repr__(self):
        return f"User(id={self.id}, username={self.username}, password={self.password}, type={self.type}, email={self.email})"

    class Api_add(BaseModel):
        username: str
        password: str
        email: str

        def add_user(username, password, email):
            user = Users(username=username, password=hash_password(password), type='user', email=email)
            session.add(user)
            session.commit()
            return user

    class Api_delete(BaseModel):
        username: str

        def delete_user(username):
            user = session.query(Users).filter_by(username=username).first()
            if user is None:
                return None
            else:
                session.delete(user)
                session.commit()
                return user

    class Api_login(BaseModel):
        username: str
        password: str

        def login_user(username, password):
            user = session.query(Users).filter_by(username=username).first()
            if user is None:
                return None
            else:
                if check_password(password, user.password):
                    token = generate_token()
                    Token.add_token(token, username)
                    user_type = user.type
                    return {'token':token, 'type':user_type}
                else:
                    return None

    class Api_update_password(BaseModel):
        username: str
        old_password: str
        new_password: str
        token: str

        def update_password(username, old_password, new_password, token):
            user = session.query(Users).filter_by(username=username).first()
            checked_password = check_password(old_password, user.password)
            checked_username = check_username_with_token(token)
            if checked_password and checked_username:
                user.password = hash_password(new_password)
                session.commit()
                return user
            else:
                return None

    class Api_update_username(BaseModel):
        old_username: str
        new_username: str

        def update_username(old_username, new_username):
            try:
                user = session.query(Users).filter_by(username=old_username).first()
                user.username = new_username
                session.commit()
                return user
            except Exception as error:
                return None

    class Api_update_email(BaseModel):
        username: str
        email: str

        def update_email(username, email):
            try:
                user = session.query(Users).filter_by(username=username).first()
                user.email = email
                session.commit()
                return user
            except Exception as error:
                return None
    
    class Api_update_type(BaseModel):
        username: str
        type: str

        def update_type(username, type):
            user = session.query(Users).filter_by(username=username).first()
            try:
                user.type = type
                session.commit()
                return user
            except Exception as error:
                return None

    class Api_check_admin(BaseModel):
        username: str

        def check_admin(username):
            user = session.query(Users).filter_by(username=username).first()
            if user.type == 'admin':
                return True
            else:
                return False

    class Api_update_autorized(BaseModel):
        username: str
        autorized: bool

        def update_autorized(username, autorized):
            user = session.query(Users).filter_by(username=username).first()
            try:
                user.autorized = autorized
                session.commit()
                return user
            except Exception as error:
                return None


class Token(Base):
    __tablename__ = 'token'
    id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
    token = sqlalchemy.Column(sqlalchemy.String, unique=True)
    username = sqlalchemy.Column(sqlalchemy.String)
    date = sqlalchemy.Column(sqlalchemy.DateTime, default=timezone_br)

    def __repr__(self):
        return f"Token(id={self.id}, token={self.token}, username={self.username})"

    def add_token(token, username):
        token = Token(token=token, username=username)
        session.add(token)
        session.commit()
        return token

# create directorys table

class Directories(Base):
    __tablename__ = 'Directories'
    id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
    directory_name = sqlalchemy.Column(sqlalchemy.String, unique=True)
    directory_path = sqlalchemy.Column(sqlalchemy.String, unique=True)
    username = sqlalchemy.Column(sqlalchemy.String)
    date = sqlalchemy.Column(
        sqlalchemy.DateTime, default=datetime.datetime.utcnow)

    def __repr__(self):
        return f"Directories(id={self.id}, directory_name={self.directory_name}, directory_path={self.directory_path}, username={self.username})"

    class Api_add(BaseModel):
        directory_name: str
        directory_path: str
        username: str

        def add_directory(directory_name, directory_path, username):
            try:
                directory = Directories(directory_name=directory_name, directory_path=directory_path, username=username)
                session.add(directory)
                session.commit()
                return directory
            except Exception as error:
                session.flush()
                session.rollback()
                return None

    class Api_delete(BaseModel):
        directory_name: str

        def delete_directory(directory_name):
            directory = session.query(Directories).filter_by(directory_name=directory_name).first()
            if directory is None:
                return None
            else:
                session.delete(directory)
                session.commit()
                return directory

    class Api_list(BaseModel):
        directory_name: str

        def list_directory(directory_name):
            directory = session.query(Directories).filter_by(directory_name=directory_name).first()
            if directory is None:
                return None
            else:
                return directory
        
        def list_all_directories():
            directory = session.query(Directories).all()
            if directory is None:
                return None
            else:
                return directory



class Config(Base):
    __tablename__ = 'config'
    id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
    config_name = sqlalchemy.Column(sqlalchemy.String, unique=True)
    config_value = sqlalchemy.Column(sqlalchemy.String, unique=True)
    config_description = sqlalchemy.Column(sqlalchemy.String)
    username = sqlalchemy.Column(sqlalchemy.String)
    date = sqlalchemy.Column(
        sqlalchemy.DateTime, default=datetime.datetime.utcnow)

    def __repr__(self):
        return f"Config(id={self.id}, config_name={self.config_name}, config_value={self.config_value}, username={self.username})"

    def check_config(config_name):
        config = session.query(Config).filter_by(config_name=config_name).first()
        if config is None:
            return None
        else:
            return config.config_value

    def create_config(config_name, config_value, config_description, username):
        config = Config(config_name=config_name, config_value=config_value, config_description=config_description, username=username)
        session.add(config)
        session.commit()
        return config

    def update_config(config_name, config_value, username):
        config = session.query(Config).filter_by(config_name=config_name).first()
        config.config_value = config_value
        config.username = username
        config.date = timezone_br
        session.commit()
        return config
    
    def get_all_configs():
        config = session.query(Config).all()
        return config

Base.metadata.create_all(engine)

def check_user_type(username):
    user = session.query(Users).filter_by(username=username).first()
    if user is None:
        return None
    else:
        return user.type

def check_user_exists(username):
    user = session.query(Users).filter_by(username=username).first()
    if user is None:
        return False
    else:
        return True

def check_username_with_token(token):
    token = session.query(Token).filter_by(token=token).first()
    if token is None:
        return None
    else:
        return token.username

def check_admin_with_token(token: str):
    token = session.query(Token).filter_by(token=token).first()
    user = session.query(Users).filter_by(username=token.username).first()
    if token is None:
        return HTTPException(status_code=401, detail="Not authorized")
    elif user.type == 'admin':
        return True
    else:
        raise HTTPException(status_code=401, detail="Not authorized")


if Config.check_config('api_url') is None:
    config = configparser.ConfigParser()
    config.read('config.ini')
    api_url = config['FASTAPI']['api_url']
    Config.create_config('api_url', api_url, 'URL do FASTAPI', 'admin')

if  session.query(Users).filter_by(username="admin").first() == None:
    admin = Users(username='admin', password=hash_password('admin'), type='admin',email="pedroluizmossi@gmail.com", autorized=True)
    session.add(admin)
    session.commit()