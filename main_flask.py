from flask import Flask, make_response, render_template, request, redirect, url_for, session
from flask_session import Session
import requests
from pydantic import BaseModel


api_url = 'http://127.0.0.1:8000'


app = Flask(__name__)
SESSION_TYPE = 'filesystem'
app.config.from_object(__name__)
Session(app)



def set_cookie(response):
    session['token'] = response.json()['token']

def validate_token():
    token = session.get('token', 'No token')
    response = requests.post(api_url + '/token', headers = {'Authorization': 'Bearer ' + token})
    if response.status_code == 200:
        return True
    else:
        return False

@app.route("/")
def index():
    if validate_token() == True:
        return redirect(url_for('startpage'))
    else:
        return render_template('index.html')
    


@app.route('/gettoken/')
def get():
    return session.get('token', 'No token')

@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user_object = {
            'username': username,
            'password': password
        }
        response = requests.post(api_url + '/login', json=user_object)
        if response.status_code == 200:
            set_cookie(response)
            return redirect(url_for('startpage'))
        else:
            raise Exception('Invalid credentials')

    return render_template('login.html')

@app.route("/logout", methods=['POST'])
def logout():
    token = session.get('token', 'No token')
    token_object = {
        'token': token
    }
    response = requests.post(api_url + '/logout', headers = {'Authorization': 'Bearer ' + token}, json=token_object)
    print("Status Code", response.status_code)
    print("JSON Response ", response.json())
    if response.status_code == 200:
        session.pop('token', None)
        return redirect(url_for('index'))
    else:
        raise Exception(response.json()['detail'])
    

@app.route("/adduser", methods=['GET', 'POST'])
def adduser():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']

        user_object = {
            'username': username,
            'password': password,
            'email': email
        }
        response = requests.post(api_url + '/adduser', json=user_object)
        if response.status_code == 200:
            return 'User added'
        else:
            return 'User not added'

    return render_template('adduser.html')

@app.route("/startpage", methods=['GET', 'POST'])
def startpage():
    if validate_token() == True:
        return render_template('start_page.html')
    else:
        return redirect(url_for('index'))
