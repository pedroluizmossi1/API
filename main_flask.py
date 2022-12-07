from flask import Flask, make_response, render_template, request, redirect, url_for, session
from flask_session import Session
import requests
from pydantic import BaseModel


api_url = 'http://localhost:8000'


app = Flask(__name__)
SESSION_TYPE = 'filesystem'
app.config.from_object(__name__)
Session(app)

@app.route("/")
def hello_world():
    #validade token
    token = session.get('token', 'No token')
    if token != 'No token':
        response = requests.get(api_url + '/listdirectorys', headers={'Authorization': 'Bearer ' + token})
        if response.status_code == 200:
            return response.json()
        else:
            return 'Token expired'
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
            session['token'] = response.json()['token']
            return 'Login successful'
        else:
            return 'Login failed'

    return render_template('login.html')


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