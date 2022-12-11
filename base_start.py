import sqlalchemy
import datetime
from sqlalchemy.orm import declarative_base, sessionmaker
import time

timezone = datetime.timezone(datetime.timedelta(hours=-3))
timezone_br = datetime.datetime.now(timezone)

engine = sqlalchemy.create_engine(
    'sqlite:///base.db', connect_args={'check_same_thread': False})
metadata = sqlalchemy.MetaData()
Base = declarative_base()
Session = sessionmaker(bind=engine)
session = Session()

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

# create token check table

class Token(Base):
    __tablename__ = 'token'
    id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
    token = sqlalchemy.Column(sqlalchemy.String, unique=True)
    username = sqlalchemy.Column(sqlalchemy.String)
    date = sqlalchemy.Column(sqlalchemy.DateTime, default=timezone_br)

    def __repr__(self):
        return f"Token(id={self.id}, token={self.token}, username={self.username})"

# create directorys table

class Directorys(Base):
    __tablename__ = 'directorys'
    id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
    directory_name = sqlalchemy.Column(sqlalchemy.String, unique=True)
    directory_path = sqlalchemy.Column(sqlalchemy.String, unique=True)
    username = sqlalchemy.Column(sqlalchemy.String)
    date = sqlalchemy.Column(
        sqlalchemy.DateTime, default=datetime.datetime.utcnow)

    def __repr__(self):
        return f"Directorys(id={self.id}, directory_name={self.directory_name}, directory_path={self.directory_path}, username={self.username})"

Base.metadata.create_all(engine)

def check_user_type(username):
    user = session.query(Users).filter_by(username=username).first()
    if user is None:
        return None
    else:
        return user.type