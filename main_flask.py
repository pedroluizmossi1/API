from flask import Flask, make_response, render_template, request, redirect, url_for, session, flash, send_file, stream_with_context, Response, stream_template
from flask_session import Session
import requests
from pydantic import BaseModel
import json
import datetime
import io
from flask_caching import Cache

api_url = 'http://127.0.0.1:8000'

config = {
    "DEBUG": True,          # some Flask specific configs
    "CACHE_TYPE": "SimpleCache",  # Flask-Caching related configs
    "CACHE_DEFAULT_TIMEOUT": 300
}

app = Flask(__name__)
SESSION_TYPE = 'filesystem'
app.config.from_object(__name__)

app.config.from_mapping(config)
cache = Cache(app)
cache.init_app(app)
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

def get_token():
    token = session.get('token', 'No token')
    return token

def get_username():
    username = session.get('login', 'No login')
    return username

@cache.cached(timeout=120, key_prefix='all_directories')
def get_all_directories():
    if validate_token() == True:
        token = get_token()
        response = requests.get(api_url + '/listdirectories', headers = {'Authorization': 'Bearer ' + token})
        directories_full = response.json().get('listdirectories', 'No directories')
        #get all directory_name from directories
        directories = [directory['directory_name'] for directory in directories_full]
        if response.status_code == 200:
            return directories, directories_full

def delete_all_directories_cache():
    cache.delete('all_directories')

@cache.cached(timeout=120, key_prefix='disk_space')
def get_disk_space():
    if validate_token() == True:
        token = get_token()
        response = requests.get(api_url + '/get_disk_space', headers = {'Authorization': 'Bearer ' + token})
        disk_space = response.json()
        return disk_space

def get_folder_size(directory):
    if validate_token() == True:
        token = get_token()
        response = requests.get(api_url + '/get_folder_size/' + directory, headers = {'Authorization': 'Bearer ' + token})
        folder_size = response.json()
        return folder_size

@app.route("/")
def index():
    if validate_token() == True:
        return redirect(url_for('startpage'))
    else:
        return render_template('index.html')
    

@app.template_filter('format_date')
def format_date(value, format):
    date = datetime.datetime.strptime(value, '%Y-%m-%d %H:%M:%S')
    if format == 'short':
        format = "%d/%m/%Y"
        return date.strftime(format)
    elif format == 'long':
        format = "%d/%m/%Y %H:%M:%S"
        return date.strftime(format)
    elif format == 'time':
        format = "%H:%M:%S"
        return date.strftime(format)

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
            session['login'] = username
            return redirect(url_for('startpage'))
        else:
            flash(response.json()['detail'])
            return redirect(url_for('login'))
    else:
        return render_template('login.html')

@app.route("/logout", methods=['POST'])
def logout():
    token = session.get('token', 'No token')
    token_object = {
        'token': token
    }
    response = requests.post(api_url + '/logout', headers = {'Authorization': 'Bearer ' + token}, json=token_object)
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
            flash('Usuário adicionado com sucesso!')
            return redirect(url_for('login'))
        else:
            flash('Erro ao adicionar usuário!')
            return redirect(url_for('adduser'))

    return render_template('adduser.html')

@app.route("/startpage", methods=['GET', 'POST'])
def startpage():
    if validate_token() == True:
        directories = get_all_directories()
        return render_template('start_page.html', directories=directories[0], directories_full=directories[1], chart_data=get_disk_space())
    else:
        return redirect(url_for('index'))

@app.route("/adddirectory", methods=['POST'])
def adddirectory():
    if validate_token() == True:
        directory_name = request.form['folderName']
        directory_path = request.form['folderPath']
        username = get_username()
        token = get_token()
        directory_object = {
            'directory_name': directory_name,
            'directory_path': directory_path,
            'username': username
        }
        response = requests.post(api_url + '/adddirectory', headers={'Authorization': 'Bearer ' + token}, json=directory_object)
        if response.status_code == 200:
            delete_all_directories_cache()
            flash('Directory added', 'success')
            return redirect(url_for('startpage'))
        else:
            flash(response.json()['detail'], 'error')
            return redirect(url_for('startpage'))

@app.route("/deletedirectory", methods=['POST'])
def deletedirectory():
    if validate_token() == True:
        directory_name = request.form['selected_directory']
        username = get_username()
        token = get_token()
        directory_object = {
            'directory_name': directory_name,
            'username': username
        }
        response = requests.post(api_url + '/deletedirectory', headers={'Authorization': 'Bearer ' + token}, json=directory_object)
        if response.status_code == 200:
            delete_all_directories_cache()
            return redirect(url_for('startpage'))
        else:
            flash(response.json()['detail'], 'error')
            return redirect(url_for('startpage'))

@app.route("/listdirectoryfiles", methods=['GET', 'POST'])
def listdirectoryfiles():
    if validate_token() == True:
        if request.method == 'GET':
            directory_name = request.args.get('directory_name')
            token = get_token()
            directory_object = {
                'directory_name': directory_name
            }
            directories = get_all_directories()
            folder_size = get_folder_size(directory_name)
            response = requests.get(api_url + '/listdirectoryfiles', headers={'Authorization': 'Bearer ' + token}, json=directory_object)
            if response.status_code == 200:
                files = response.json().get('listdirectoryfiles', 'No files')
                return render_template('files.html', files=files, directories=directories[0], directories_full=directories[1], folder_size=folder_size)
            else:
                flash("Pasta não encontrada", 'error')
                return redirect(url_for('startpage'))

@app.route("/downloadfile", methods=['GET', 'POST'])
def downloadfile():
    if validate_token() == True:
        if request.method == 'GET':
            file_path = request.args.get('file_path_download')
            file_name = request.args.get('file_name_download')
            token = get_token()
            response = requests.get(api_url + '/downloadfile/'+ file_path, headers={'Authorization': 'Bearer ' + token})
            if response.status_code == 200:
                return send_file(file_path, as_attachment=True, download_name=file_name)
            else:
                flash("Arquivo não encontrado", 'error')
                #keep user in the same page
                return redirect(request.referrer)

@app.route("/change_user_password", methods=['GET', 'POST'])
def change_user_password():
    if validate_token() == True:
        if request.method == 'POST':
            username = get_username()
            token = get_token()
            old_password = request.form['old_password']
            new_password = request.form['new_password']
            user_object = {
                'username': username,
                'old_password': old_password,
                'new_password': new_password
            }
            response = requests.post(api_url + '/change_user_password', headers={'Authorization': 'Bearer ' + token}, json=user_object)
            if response.status_code == 200:
                flash('Password changed', 'success')
                return redirect(url_for('startpage'))
            else:
                flash(response.json()['detail'], 'error')
                return redirect(url_for('startpage'))

@app.route("/config", methods=['GET', 'POST'])
def config():
    if validate_token() == True:
        if request.method == 'GET':
            users = list_users()
            return render_template('config.html', users=users)


@app.route("/config/<username>/<int:authorized>", methods=['POST'])
def config_user_authorized(username, authorized):
    if validate_token() == True:
        if request.method == 'POST':
            token = get_token()
            if authorized == 1:
                authorized_status = True
            else:
                authorized_status = False
            user_object = {
                'username': username,
                'autorized': authorized_status
            }
            response = requests.post(api_url + '/change_user_type', headers = {'Authorization': 'Bearer ' + token}, json=user_object)
            if response.status_code == 200:
                flash('User updated', 'success')
                return redirect(url_for('config'))
            else:
                flash(response.json()['detail'], 'error')
                return redirect(url_for('config'))


@app.route("/list_users", methods=['GET', 'POST'])
def list_users():
    if validate_token() == True:
        if request.method == 'GET':
            token = get_token()
            response = requests.get(api_url + '/list_users', headers={'Authorization': 'Bearer ' + token})
            if response.status_code == 200:
                users = response.json().get('list_users', 'No users')
                return users
            else:
                return response.json()['detail']
