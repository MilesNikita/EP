import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QWidget, QMessageBox, QFileDialog
from PyQt5.QtCore import Qt
from PyQt5 import QtCore, QtGui, QtWidgets
from gui import Ui_MainWindow
import requests
from OpenSSL import crypto

class AppMainWindow(QMainWindow, Ui_MainWindow):
    def __init__(self):
        super(AppMainWindow, self).__init__()
        self.setupUi(self)
        self.action.triggered.connect(self.open_file)
        self.action_3.triggered.connect(self.show_program_info)
        self.pushButton.clicked.connect(self.click_add)
        self.pushButton_2.clicked.connect(self.click_del)
        self.pushButton_3.clicked.connect(self.sign_document)
        self.pushButton_4.clicked.connect(self.verify_documet)
        self.server_ip = ''
        self.server_port = ''

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
    
    def sign_document(self):
        file_path = self.lineEdit.text()
        if file_path:
            selected_users = [self.listWidget.item(i).text() for i in range(self.listWidget.count())]
            if not selected_users:
                QMessageBox.warning(self, 'Предупреждение', 'Выберите хотя бы одного пользователя для подписи файла.')
                return
            url = f'http://{self.server_ip}:{self.server_port}/upload_file'
            files = {'file': open(file_path, 'rb')}
            data = {'user_ids': selected_users}
            try:
                response = requests.post(url, files=files, data=data)
                if response.status_code == 200:
                    new_file_name = file_path + '.ezp'
                    with open(new_file_name, 'wb') as f:
                        f.write(response.content)
                    QMessageBox.information(self, 'Успех', 'Файл успешно подписан и скачан.')
                else:
                    QMessageBox.critical(self, 'Ошибка', 'Произошла ошибка при подписании файла.')
            except requests.exceptions.RequestException as e:
                QMessageBox.critical(self, 'Ошибка', f"Произошла ошибка: {e}")
        else:
            QMessageBox.warning(self, 'Предупреждение', 'Выберите файл для осуществления подписи')

    def verify_documet(self):
        file_path = self.lineEdit.text()
        file_dialog = QFileDialog(self)
        file_path_sert, _ = file_dialog.getOpenFileName(self, 'Выберите файл подписи', '', 'Все файлы (*)')
        if file_path_sert:
            if file_path:
                url = f'http://{self.server_ip}:{self.server_port}/verify_signature'
                files = {
                'file': open(file_path, 'rb'),
                'signature': open(file_path_sert, 'rb')
                }
                selected_users = [self.listWidget.item(i).text() for i in range(self.listWidget.count())]
                if not selected_users:
                    QMessageBox.warning(self, 'Предупреждение', 'Выберите хотя бы одного пользователя для проверки подписи файла.')
                data = {'user_ids': selected_users}
                try:
                    response = requests.post(url, files=files, data=data)
                    if response.status_code == 200:
                        if response.content:
                            QMessageBox.information(self, 'Успех', 'Файл успешно подписан и скачан.')
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

    closed = QtCore.pyqtSignal()
    def closeEvent(self, event):
        self.closed.emit()
        super().closeEvent(event)

class LoginWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.session = requests.Session()  
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle('Вход')
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
        self.password_label = QtWidgets.QLabel('Пароль:')
        self.password_input = QtWidgets.QLineEdit(self)
        self.password_input.setEchoMode(QtWidgets.QLineEdit.Password)
        self.login_button = QtWidgets.QPushButton('Войти')
        self.login_button.clicked.connect(self.login)
        layout.addWidget(self.ip_label)
        layout.addWidget(self.ip_input)
        layout.addWidget(self.port_label)
        layout.addWidget(self.port_input)
        layout.addWidget(self.username_label)
        layout.addWidget(self.username_input)
        layout.addWidget(self.password_label)
        layout.addWidget(self.password_input)
        layout.addWidget(self.login_button)
        self.central_widget.setLayout(layout)
        self.setFixedSize(400,300)

    def login(self):
        self.server_ip_login = self.ip_input.text()
        self.server_port_login = self.port_input.text()
        username = self.username_input.text()
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

    def open_main_window(self, fio):
        self.app_main_window = AppMainWindow()
        self.app_main_window.server_port = self.server_port_login
        self.app_main_window.server_ip = self.server_ip_login
        self.app_main_window.show()
        self.app_main_window.setWindowTitle("Коллективная электронная подпись")
        for i in fio:
            self.app_main_window.comboBox.addItem(i)
        self.hide()
        self.app_main_window.closed.connect(self.show_login_window)
    
    def show_login_window(self):
        self.show()

if __name__ == '__main__':
    app = QApplication(sys.argv)
    login_window = LoginWindow()
    login_window.show()
    sys.exit(app.exec_())
