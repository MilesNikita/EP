from flask import Flask, render_template, request, jsonify, session, redirect, url_for, send_from_directory
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, utils, padding
from cryptography.hazmat.primitives import serialization, hashes
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import json
import os
import hashlib
import gostcrypto
import secrets
from binascii import hexlify
import socket

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

def split_byte_string(byte_string, parts):
    segment_length = len(byte_string) // parts
    segments = [byte_string[i:i+segment_length] for i in range(0, len(byte_string), segment_length)]
    return segments

def verify_signature_server(file_content, signature, user_ids):
    save_id = 0
    with open(file_content, 'rb') as file:
        document = file.read()
        hash_value = hashlib.sha256(document).digest()[:32]
    public_keys = read_user_public_keys(USER_DATA_FILE, user_ids)
    signature_data = json.loads(signature)
    signatures = signature_data.get('signatures', '')
    signatures_list = split_byte_string(signatures, len(user_ids))
    for key, sign in zip(public_keys, signatures_list):
        key_bytes = bytearray(key)
        sign_bytes = bytearray(sign)
        if sign_obj.verify(key_bytes, hash_value, sign_bytes):
            save_id += 1
    if save_id == len(user_ids):
        return True
    else:
        return False

@app.route('/')
def index():
    user_id = session.get('user_id')
    return render_template('index.html', user_data=user_data, user_id=user_id)

@app.route('/add_user', methods=['POST'])
def add_user():
    data = request.get_json()
    user_id = data.get('username')
    user_fio = data.get('name')
    password = data.get('password')
    public_key_256 = data.get('public_key_256')
    public_key_512 = data.get('public_key_512')
    ip_address = data.get('ip')
    if user_id not in user_data:
        hashed_password = generate_password_hash(password)
        user_data[user_id] = {
                'fio': user_fio,
                'public_key_256': public_key_256,
                'public_key_512': public_key_512,
                'password_hash': hashed_password,
                'ip': ip_address
        }
        save_user_data()
        return jsonify({'status': 'CREATE_SUCCESS'})
    else:
        return jsonify({'status': 'CREATE_ERROR'})


def save_user_data():
    with open(USER_DATA_FILE, 'w') as file:
        json.dump(user_data, file, indent=2)


def authenticate_user(username, password):
    if username in user_data and 'password_hash' in user_data[username]:
        hashed_password = user_data[username]['password_hash']
        return check_password_hash(hashed_password, password)
    return False


@app.route('/signature', methods=['POST'])
def update_signature():
    data = request.get_json()
    signatures = bytes.fromhex(data.get('sign'))
    i_am_user = data.get('i_am')
    sign = b''
    sign_hex = signatures.hex()
    with open(USER_DATA_FILE, 'r') as file:
        users_info = json.load(file)
    user = users_info.get(i_am_user)
    ip = user.get('ip')
    print(ip)
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect((ip, 5002))
        data = {'sign': sign_hex}
        print(data)
        client_socket.send(json.dumps(data).encode()) 
    except ConnectionRefusedError:
        print(f"Не удалось подключиться к пользователю соединение отклонено")
    except TimeoutError:
        print(f"Таймаут при подключении к пользователю")
    except socket.error as e:
        print(f"Произошла ошибка при подключении к пользователю: {e}")
    finally:
        client_socket.close()
    return jsonify({'message': 'OK'})

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

@app.route('/sign', methods=['POST'])
def upload_file():
    hash_value = request.form.get('hash')
    user_ids = request.form.getlist('user_ids')
    type_key = request.form.get('key_type')
    i_am_user = request.form.get('i_am')
    with open(USER_DATA_FILE, 'r') as file:
        users_info = json.load(file)
    for user_id in user_ids:
        user_info = users_info.get(user_id)
        if user_info.get('fio') in user_ids:
            ip = user_info.get('ip')
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                client_socket.connect((ip, 5002))
                data = {
                    'hash' : hash_value,
                    'type_key' : type_key,
                    'user' : user_id,
                    'i_am' : i_am_user
                }
                client_socket.send(json.dumps(data).encode()) 
            except ConnectionRefusedError:
                print(f"Не удалось подключиться к пользователю {user_id}: соединение отклонено")
                return jsonify({'message': 'ERROR'})
                break
            except TimeoutError:
                print(f"Таймаут при подключении к пользователю {user_id}")
            except socket.error as e:
                print(f"Произошла ошибка при подключении к пользователю {user_id}: {e}")
            finally:
                client_socket.close()
    return jsonify({'message': 'OK'})

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
