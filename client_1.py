import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QWidget, QMessageBox, QFileDialog
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5 import QtCore, QtGui, QtWidgets
from gui import Ui_MainWindow
import requests
import json
import gostcrypto
import secrets
import os
import socket
import hashlib
import time
import threading
from urllib.parse import unquote

sign_obj_256 = gostcrypto.gostsignature.new(gostcrypto.gostsignature.MODE_256,
    gostcrypto.gostsignature.CURVES_R_1323565_1_024_2019['id-tc26-gost-3410-2012-256-paramSetB'])

sign_obj_512 = gostcrypto.gostsignature.new(gostcrypto.gostsignature.MODE_512,
    gostcrypto.gostsignature.CURVES_R_1323565_1_024_2019['id-tc26-gost-3410-12-512-paramSetB'])

class AppMainWindow(QMainWindow, Ui_MainWindow):
    def __init__(self):
        super(AppMainWindow, self).__init__()
        self.setupUi(self)
        self.action.triggered.connect(self.open_file)
        self.action_3.triggered.connect(self.show_program_info)
        self.pushButton.clicked.connect(self.click_add)
        self.pushButton_2.clicked.connect(self.click_del)
        self.pushButton_3.clicked.connect(self.sign_documet)
        self.pushButton_4.clicked.connect(self.verify_documet)
        self.server_ip = ''
        self.server_port = ''
        self.user_name = ''

    def get_line_edit_text(self):
        return self.lineEdit.text()

    def open_file(self):
        file_dialog = QFileDialog(self)
        file_path, _ = file_dialog.getOpenFileName(self, 'Открытие файла', '', 'Все файлы (*)')
        if file_path:
            self.lineEdit.setText(file_path)

    def show_program_info(self):
        info_message = "Данная программа предназначена для создание файлов с коллективной электронной подписью на основе ГОСТ-34.10-2012"
        QMessageBox.information(self, 'Информация о программе', info_message)

    def click_add(self):
        for i in range(self.listWidget.count()):
            existing_item = self.listWidget.item(i)
            if existing_item.text() == self.comboBox.currentText():
                return
        self.listWidget.addItem(self.comboBox.currentText())

    def click_del(self):
        selected_item = self.listWidget.currentItem()
        if selected_item:
            row = self.listWidget.row(selected_item)
            self.listWidget.takeItem(row)
    
    def verify_documet(self):
        file_path = self.lineEdit.text()
        file_dialog = QFileDialog(self)
        file_path_sert, _ = file_dialog.getOpenFileName(self, 'Выберите файл подписи', '', 'Файлы подписи (*.ezp)')
        if self.lineEdit.text() != 0:
            with open(self.lineEdit.text(), 'rb') as file:
                document = file.read()
            with open(file_path_sert, 'rb') as file1:
                sign = file1.read()
            type_key = None
            hash_value = None
            if self.switch.isChecked():
                type_key = 256
                hash_value = hashlib.sha256(document).digest()
            if self.switch2.isChecked():
                type_key = 512
                hash_value = hashlib.sha512(document).digest()
            if file_path_sert:
                if file_path:
                    url = f'http://{self.server_ip}:{self.server_port}/verify_signature'
                    files = {
                    'digest' : hash_value.hex(),
                    'signature': sign,
                    }
                    selected_users = [self.listWidget.item(i).text() for i in range(self.listWidget.count())]
                    if not selected_users:
                        QMessageBox.warning(self, 'Предупреждение', 'Выберите хотя бы одного пользователя для проверки подписи файла.')
                    data = {'user_ids' : selected_users, 
                            'type_key' : type_key
                            }
                    try:
                        response = requests.post(url, files=files, data=data)
                        if response.status_code == 200:
                            status_data = json.loads(response.content)
                            status = status_data.get('is_valid', '')
                            if status == True:
                                QMessageBox.information(self, 'Успех', 'Файл успешно проверен, подписи совпадают.')
                            else:
                                QMessageBox.critical(self, 'Ошибка', 'Подпись не совпадает.')
                        else:
                            QMessageBox.critical(self, 'Ошибка', 'Произошла ошибка при проверке подписи файла.')
                    except requests.exceptions.RequestException as e:
                        QMessageBox.critical(self, 'Ошибка', f"Произошла ошибка: {e}")
                else:
                    QMessageBox.warning(self, 'Предупреждение', 'Выберите файл для проверки подписи')
            else:
                QMessageBox.warning(self, 'Предупреждение', 'Выберите файл подписи')
        else:
            QMessageBox.warning(self, 'Ошибка', 'Выберите файл для проверки')

    def sign_documet(self):
        file_path = self.lineEdit.text()
        if file_path:
            with open(self.lineEdit.text(), 'rb') as file:
                document = file.read()
            url = f'http://{self.server_ip}:{self.server_port}/sign'
            selected_users = [self.listWidget.item(i).text() for i in range(self.listWidget.count())]
            if not selected_users:
                QMessageBox.warning(self, 'Ошибка', 'Выберите пользователей учавствующие в подписи файла.')
            hash_value = None
            if self.switch.isChecked():
                type_key = 256
                hash_value = hashlib.sha256(document).digest()
            if self.switch2.isChecked():
                type_key = 512
                hash_value = hashlib.sha512(document).digest()
            data = {
                'hash' : hash_value.hex(),
                'user_ids': selected_users,
                'key_type' : type_key,
                'i_am' : self.user_name
            }
            print(data)
            try:
                response = requests.post(url, data=data)
                if response.status_code == 200:
                    status_data = json.loads(response.content)
                    status = status_data.get('message')
                    if status == 'ERROR':
                        QMessageBox.critical(self, 'Ошибка', 'Один из пользователей не доступен для подписи')
            except requests.exceptions.RequestException as e:
                QMessageBox.critical(self, 'Ошибка', f"Произошла ошибка: {e}")
        else:
            QMessageBox.critical(self, 'Ошибка', 'Выберите файл для создания подписи')

    closed = QtCore.pyqtSignal()
    def closeEvent(self, event):
        self.closed.emit()
        super().closeEvent(event) 

class LoginWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.session = requests.Session()  
        self.init_ui()
        self.signature = []

    def init_ui(self):
        self.setWindowTitle('Вход')
        self.setGeometry(200, 250, 400, 200)
        self.central_widget = QWidget(self)
        self.setCentralWidget(self.central_widget)
        layout = QtWidgets.QVBoxLayout()
        self.ip_label = QtWidgets.QLabel('IP сервера:')
        self.ip_input = QtWidgets.QLineEdit(self)
        self.ip_input.setText('127.0.0.1') 
        self.port_label = QtWidgets.QLabel('Порт сервера:')
        self.port_input = QtWidgets.QLineEdit(self)
        self.port_input.setText('5000') 
        self.username_label = QtWidgets.QLabel('Логин:')
        self.username_input = QtWidgets.QLineEdit(self)
        self.password_label = QtWidgets.QLabel('Пароль:')
        self.password_input = QtWidgets.QLineEdit(self)
        self.password_input.setEchoMode(QtWidgets.QLineEdit.Password)
        self.login_button = QtWidgets.QPushButton('Войти')
        self.login_button.clicked.connect(self.login)
        self.register_button = QtWidgets.QPushButton('Зарегестрироваться')
        self.register_button.clicked.connect(self.open_regist_windoW)
        layout.addWidget(self.ip_label)
        layout.addWidget(self.ip_input)
        layout.addWidget(self.port_label)
        layout.addWidget(self.port_input)
        layout.addWidget(self.username_label)
        layout.addWidget(self.username_input)
        layout.addWidget(self.password_label)
        layout.addWidget(self.password_input)
        layout.addWidget(self.login_button)
        layout.addWidget(self.register_button)
        self.central_widget.setLayout(layout)
        self.setFixedSize(400,300)

    def login(self):
        self.server_ip_login = self.ip_input.text()
        self.server_port_login = self.port_input.text()
        username = self.username_input.text()
        self.user_name = username
        password = self.password_input.text()
        server_url = f'http://{self.server_ip_login}:{self.server_port_login}/login'
        data = {'username': username, 'password': password}
        try:
            with self.session.post(server_url, json=data) as response:
                response.raise_for_status()
                if response.json()['status'] == 'AUTH_SUCCESS':
                    fio = response.json().get('all_fio', '')
                    self.open_main_window(fio)
                else:
                    QMessageBox.critical(self, 'Ошибка', 'Проверьте логин/пароль')
        except requests.exceptions.RequestException as e:
            QMessageBox.critical(self, 'Ошибка', f'An error occurred: {e}')
        socket_thread = threading.Thread(target=self.create_socket, args=(self.app_main_window,))
        socket_thread.start()

    def open_main_window(self, fio):
        self.app_main_window = AppMainWindow()
        self.app_main_window.server_port = self.server_port_login
        self.app_main_window.server_ip = self.server_ip_login
        self.app_main_window.user_name = self.user_name
        self.app_main_window.show()
        self.app_main_window.setWindowTitle("Коллективная электронная подпись")
        for i in fio:
            self.app_main_window.comboBox.addItem(i)
        self.hide()
        self.app_main_window.closed.connect(self.show_login_window)
        socket_thread = threading.Thread(target=self.create_socket, args=(self.app_main_window,))
        socket_thread.start()
    

    def update_sign(self, i_am):
        sign = self.signature
        server_url = f'http://{self.server_ip_login}:{self.server_port_login}/signature'
        data = {'sign': sign,
                'i_am': i_am}
        print(data)
        try:
            response = requests.post(server_url, json=data)
        except requests.exceptions.RequestException as e:
            QMessageBox.critical(self, 'Ошибка', f"Произошла ошибка: {e}")


    def sign_document_client(self, key_type, hash, user):
        hash_value = bytes.fromhex(hash)
        if key_type == '256':
            private_key_file = user + "_key/private_key_256.key"
        if key_type == '512':
            private_key_file = user + "_key/private_key_512.key"
        with open(private_key_file, 'rb') as file:
            private_key = file.read()
        if key_type == '256':
            signature = sign_obj_256.sign(private_key, hash_value)
        elif key_type == '512':
            signature = sign_obj_512.sign(private_key, hash_value)
        return signature.hex()

    def create_socket(self, main_window_instance):
        client_socket = None
        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            hostname = socket.gethostname()
            client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            client_socket.bind((socket.gethostbyname(hostname), 5003))
            client_socket.listen(10)
            while True:
                conn, addr = client_socket.accept()
                data = conn.recv(1024)
                itog_data = json.loads(data.decode())
                if 'type_key' in itog_data:
                    print('type')
                    key_type = itog_data.get('type_key')
                    hash_value = itog_data.get('hash')
                    user = itog_data.get('user')
                    i_am = itog_data.get('i_am')
                    self.signature = self.sign_document_client(key_type, hash_value, user)
                    self.update_sign(i_am)
                elif 'sign' in itog_data:
                    signature = itog_data.get('sign')
                    sign_bytes = bytes.fromhex(signature)
                    print(sign_bytes)
                    if main_window_instance:
                        file_path = main_window_instance.get_line_edit_text()
                        if file_path:
                            file_extension = os.path.splitext(file_path)[1]
                            file_name = os.path.splitext(file_path)[0] + ".ezp"
                            if not os.path.exists(os.path.dirname(file_name)):
                                os.makedirs(os.path.dirname(file_name))
                            with open(file_name, 'ab') as file:
                                file.write(sign_bytes)
                                file.write(b"cola")
                        else:
                            print("Не удалось получить путь к файлу")
        except Exception as e:
            print(f"Произошла ошибка при создании файла: {e}")
        finally:
            if client_socket:
                client_socket.close()
        
    def open_regist_windoW(self):
        self.app_reigst_window = RegistWindow()
        self.app_reigst_window.show()
        self.app_reigst_window.setWindowTitle("Создание учетной записи")

    def show_login_window(self):
        self.show()

class RegistWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.session = requests.Session()  
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle('Создание учетной записи')
        self.setGeometry(200, 200, 400, 200)
        self.central_widget = QWidget(self)
        self.setCentralWidget(self.central_widget)
        layout = QtWidgets.QVBoxLayout()
        self.ip_label = QtWidgets.QLabel('IP сервера:')
        self.ip_input = QtWidgets.QLineEdit(self)
        self.ip_input.setText('127.0.0.1') 
        self.port_label = QtWidgets.QLabel('Порт сервера:')
        self.port_input = QtWidgets.QLineEdit(self)
        self.port_input.setText('5000') 
        self.username_label = QtWidgets.QLabel('Логин:')
        self.username_input = QtWidgets.QLineEdit(self)
        self.name_label = QtWidgets.QLabel('ФИО')
        self.name_input = QtWidgets.QLineEdit(self)
        self.password_label = QtWidgets.QLabel('Пароль:')
        self.password_input = QtWidgets.QLineEdit(self)
        self.password_input.setEchoMode(QtWidgets.QLineEdit.Password)
        self.regist_button = QtWidgets.QPushButton('Создать')
        self.regist_button.clicked.connect(self.create_user)
        layout.addWidget(self.ip_label)
        layout.addWidget(self.ip_input)
        layout.addWidget(self.port_label)
        layout.addWidget(self.port_input)
        layout.addWidget(self.username_label)
        layout.addWidget(self.username_input)
        layout.addWidget(self.name_label)
        layout.addWidget(self.name_input)
        layout.addWidget(self.password_label)
        layout.addWidget(self.password_input)
        layout.addWidget(self.regist_button)
        self.central_widget.setLayout(layout)
        self.setFixedSize(400,300)
    
    def create_user(self):
        server_ip_login = self.ip_input.text()
        server_port_login = self.port_input.text()
        username = self.username_input.text()
        name = self.name_input.text()
        password = self.password_input.text()
        key_privat_256 = bytearray(secrets.token_bytes(32))
        key_privat_512 = bytearray(secrets.token_bytes(64))
        key_public_256 = sign_obj_256.public_key_generate(key_privat_256)
        key_public_512 = sign_obj_512.public_key_generate(key_privat_512)
        os.mkdir(username+'_key')
        with open(username + "_key/private_key_256.key", 'wb') as f:
            f.write((key_privat_256))
        with open(username + "_key/private_key_512.key", 'wb') as f:
            f.write((key_privat_512))
        server_url = f'http://{server_ip_login}:{server_port_login}/add_user'
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        data = {'username' : username, 
                'name' : name, 
                'password' : password, 
                'public_key_256' : list(key_public_256), 
                'public_key_512' : list(key_public_512),
                'ip' : local_ip}
        try:
            with self.session.post(server_url, json=data) as response:
                response.raise_for_status()
                if response.json()['status'] == 'CREATE_SUCCESS':
                    QMessageBox.information(self, 'Успех', 'Пользователь добавлен.')
                else:
                    QMessageBox.critical(self, 'Ошибка', 'Пользователь с таким логином/фио уже существует.')
        except requests.exceptions.RequestException as e:
            QMessageBox.critical(self, 'Ошибка', f'An error occurred: {e}')

if __name__ == '__main__':
    app = QApplication(sys.argv)
    login_window = LoginWindow()
    login_window.show()
    sys.exit(app.exec_())
