import bcrypt
from uuid import uuid4

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
    