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
from magic import Magic
import mimetypes

app = Flask(__name__)
app.secret_key = os.urandom(24)

USER_DATA_FILE = 'data.json'
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

try:
    with open(USER_DATA_FILE, 'r', encoding='utf-8') as file:
        user_data = json.load(file)
except FileNotFoundError:
    user_data = {}


def save_user_data():
    with open(USER_DATA_FILE, 'w') as file:
        json.dump(user_data, file, indent=2)


def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def sign_document_server(document_content, user_ids):
    signatures = {}
    metadata = {
        'signed_by': [],
        'timestamp': str(datetime.now())
    }
    file_type, _ = mimetypes.guess_type(document_content)
    if file_type is not None and 'text' in file_type:  
        with open(document_content, 'r', encoding='utf-8') as file:
            document = file.read()
            for user_id in user_ids:
                private_key_pem = user_keys.get(user_id, {}).get('private_key')
                if private_key_pem:
                    private_key = serialization.load_pem_private_key(
                        private_key_pem.encode('utf-8'),
                        password=None,
                        backend=default_backend()
                    )
                    document_hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
                    document_hash.update(document.encode('utf-8'))
                    signature = private_key.sign(
                        document_hash.finalize(),
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH
                        ),
                        hashes.SHA256()
                    )
                    signatures[user_id] = signature.hex()
                    metadata['signed_by'].append(user_id)
    else:  
        with open(document_content, 'rb') as file:
            document = file.read()
            for user_id in user_ids:
                private_key_pem = user_keys.get(user_id, {}).get('private_key')
                if private_key_pem:
                    private_key = serialization.load_pem_private_key(
                        private_key_pem.encode('utf-8'),
                        password=None,
                        backend=default_backend()
                    )
                    document_hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
                    document_hash.update(document)
                    signature = private_key.sign(
                        document_hash.finalize(),
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH
                        ),
                        hashes.SHA256()
                    )
                    signatures[user_id] = signature.hex()
                    metadata['signed_by'].append(user_id)
    signed_document = {
        "document_content": document,
        "signatures": signatures,
        "metadata": metadata
    }
    return signed_document

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
        with open('placeholder_file.txt', 'w') as f:
            f.write('This is a placeholder file.')
        document_path = 'placeholder_file.txt'
        document_hash = hashlib.sha256()
        with open(document_path, 'rb') as file:
            while chunk := file.read(8192):
                document_hash.update(chunk)
        document_digest = document_hash.digest()
        signature = private_key.sign(
            document_digest,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        user_data[user_id] = {
            'fio': user_fio,
            'public_key': public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8'),
            'private_key': private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8'),
            'signature': signature.hex(),  # Сохраните подпись
            'password_hash': hashed_password
        }
        save_user_data()
        os.remove('placeholder_file.txt')
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

@app.route('/sign_document', methods=['POST'])
def sign_document():
    data = request.get_json()
    document = data.get('document')
    user_ids = data.get('user_ids', [])
    signatures = sign_document_server(document, user_ids)
    return jsonify({'signatures': signatures})

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
        signatures = sign_document_server(document_path, user_ids)
        return jsonify({'signatures': signatures})

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

def load_user_keys():
    try:
        with open(USER_DATA_FILE, 'r') as file:
            user_keys = json.load(file)
    except FileNotFoundError:
        user_keys = {}
    return user_keys

user_keys = load_user_keys()

@app.route('/sign_and_download', methods=['POST'])
def sign_and_download():
    data = request.form
    user_ids = data.getlist('user_ids')
    file = request.files['file']
    signatures = {}
    for user_id in user_ids:
        private_key_pem = user_keys.get(user_id, {}).get('private_key')
        if private_key_pem:
            private_key = serialization.load_pem_private_key(
                private_key_pem.encode('utf-8'),
                password=None,
                backend=default_backend()
            )
            document = file.read()
            document_hash = hashlib.sha256(document).digest()
            signature = private_key.sign(
                document_hash,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            signatures[user_id] = signature
    return jsonify({'signatures': signatures})

if __name__ == '__main__':
    app.run(debug=True)
