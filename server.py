from flask import Flask, render_template, request, jsonify, session, redirect, url_for, send_from_directory
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, utils, padding
from cryptography.hazmat.primitives import serialization, hashes
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import json
import os
import hashlib
from datetime import datetime
import base64
import mimetypes
import gostcrypto
import secrets
from binascii import hexlify

app = Flask(__name__)
app.secret_key = secrets.token_bytes(24)
USER_DATA_FILE = 'data.json'
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
sign_obj = gostcrypto.gostsignature.new(gostcrypto.gostsignature.MODE_256,
    gostcrypto.gostsignature.CURVES_R_1323565_1_024_2019['id-tc26-gost-3410-2012-256-paramSetB'])

try:
    with open(USER_DATA_FILE, 'r', encoding='utf-8') as file:
        user_data = json.load(file)
except FileNotFoundError:
    user_data = {}

def save_user_data():
    with open(USER_DATA_FILE, 'w') as file:
        serializable_data = {key: value.hex() if isinstance(value, bytearray) else value for key, value in user_data.items()}
        json.dump(serializable_data, file, indent=2)

def generate_key_pair():
    private_key = bytearray(secrets.token_bytes(32))
    public_key = sign_obj.public_key_generate(private_key)
    return private_key, public_key

def read_user_public_keys(json_file, user_ids):
    puplick_key = []
    with open(json_file, 'r') as file:
        data = json.load(file)
    for id, user_info in data.items():
        if user_info['fio'] in user_ids:
            puplick_key.append(user_info['public_key'])
    return puplick_key

def read_user_private_keys(json_file, user_ids):
    puplick_key = []
    with open(json_file, 'r') as file:
        data = json.load(file)
    for id, user_info in data.items():
        if user_info['fio'] in user_ids:
            puplick_key.append(user_info['private_key'])
    return puplick_key

def sign_document_server(document_content, user_ids):
    with open(document_content, 'rb') as file:
        document = file.read()
        hash_value = hashlib.sha256(document).digest()[:32]
    private_key = read_user_private_keys(USER_DATA_FILE, user_ids)
    all_key = 1
    for id in private_key:
        key_int = int(id, 16)
        all_key *= key_int
    finally_key = all_key % (2**256)
    finally_key_bytes = finally_key.to_bytes(32, 'big')
    signature = sign_obj.sign(finally_key_bytes, hash_value)
    return signature

def verify_signature_server(file_content, signature, user_ids):
    with open(file_content, 'rb') as file:
        document = file.read()
        hash_value = hashlib.sha256(document).digest()[:32]
    public_keys = read_user_private_keys(USER_DATA_FILE, user_ids)
    all_key = 1
    for key in public_keys:
        key_int = int(key, 16)
        all_key *= key_int
    finally_key = all_key % (2**256)
    finally_key_bytes = finally_key.to_bytes(32, 'big')
    finally_key_1 = sign_obj.public_key_generate(finally_key_bytes)
    signature_dict = json.loads(signature)
    signature_value = signature_dict['signatures']
    signature_bytes = bytearray.fromhex(signature_value)
    if not sign_obj.verify(finally_key_1, hash_value, signature_bytes):
        return False
    return True

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('index'))


@app.route('/get_signature', methods=['POST'])
def get_signature():
    user_id = session.get('user_id')
    if user_id:
        user_fio = user_data[user_id]['fio']
        if 'private_key' not in user_data[user_id]:
            private_key, public_key = generate_key_pair()
            user_data[user_id]['private_key'] = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8')
            save_user_data()
        return jsonify({'user_data': {user_id: user_data[user_id]}})
    else:
        return jsonify({'error': 'User not authenticated'})


@app.route('/')
def index():
    user_id = session.get('user_id')
    return render_template('index.html', user_data=user_data, user_id=user_id)


@app.route('/add_user', methods=['POST'])
def add_user():
    user_id = request.form['add_user_id']
    user_fio = request.form['add_user_fio']
    password = request.form['add_user_password']
    if user_id not in user_data:
        hashed_password = generate_password_hash(password)
        private_key, public_key = generate_key_pair()
        public_key_hex = hexlify(public_key).decode('utf-8')
        private_key_hex = hexlify(private_key).decode('utf-8')
        user_data[user_id] = {
            'fio': user_fio,
            'public_key': public_key_hex,
            'private_key': private_key_hex,
            'password_hash': hashed_password
        }
        save_user_data()
        return jsonify({'message': 'User added successfully', 'user_data': user_data[user_id]})
    else:
        return jsonify({'error': 'User with this ID already exists'})

def save_user_data():
    with open(USER_DATA_FILE, 'w') as file:
        json.dump(user_data, file, indent=2)


def authenticate_user(username, password):
    if username in user_data and 'password_hash' in user_data[username]:
        hashed_password = user_data[username]['password_hash']
        return check_password_hash(hashed_password, password)
    return False

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if authenticate_user(username, password):
        session['user_id'] = username
        all_fio = [user.get('fio', '') for user in user_data.values()]
        user_data_response = {'all_fio': all_fio, 'status': 'AUTH_SUCCESS'}
        return jsonify(user_data_response)
    else:
        return jsonify({'status': 'AUTH_FAILED'})

@app.route('/upload_file', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return 'No file part'
    file = request.files['file']
    if file.filename == '':
        return 'No selected file'
    if file:
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        document_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        user_ids = request.form.getlist('user_ids')
        signatures = hexlify(sign_document_server(document_path, user_ids)).decode('utf-8')
        return jsonify({'signatures': signatures})

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/verify_signature', methods=['POST'])
def verify_signature():
    file_content = request.files['file'].read()
    signature_content = request.files['signature'].read()
    user_ids = request.form.getlist('user_ids')
    if not file_content or not signature_content or not user_ids:
        return jsonify({'error': 'Filename, signature, or user_ids missing'})
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(request.files['file'].filename))
    with open(file_path, 'wb') as file:
        file.write(file_content)
    if not os.path.exists(file_path):
        return jsonify({'error': 'File not found'})
    is_valid = verify_signature_server(file_path, signature_content, user_ids)
    return jsonify({'is_valid': is_valid})

def load_user_keys():
    try:
        with open(USER_DATA_FILE, 'r') as file:
            user_keys = json.load(file)
    except FileNotFoundError:
        user_keys = {}
    return user_keys

user_keys = load_user_keys()

if __name__ == '__main__':
    app.run(debug=True)
