from PyQt5 import QtCore, QtGui, QtWidgets
class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(464, 420)
        MainWindow.setMinimumSize(QtCore.QSize(464, 420))
        MainWindow.setMaximumSize(QtCore.QSize(464, 420))
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.label_2 = QtWidgets.QLabel(self.centralwidget)
        self.label_2.setGeometry(QtCore.QRect(10, 10, 441, 16))
        self.label_2.setObjectName("label_2")
        self.lineEdit = QtWidgets.QLineEdit(self.centralwidget)
        self.lineEdit.setGeometry(QtCore.QRect(10, 30, 441, 22))
        self.lineEdit.setReadOnly(True)
        self.lineEdit.setObjectName("lineEdit")
        self.groupBox = QtWidgets.QGroupBox(self.centralwidget)
        self.groupBox.setGeometry(QtCore.QRect(10, 60, 441, 221))
        self.groupBox.setObjectName("groupBox")
        self.listWidget = QtWidgets.QListWidget(self.groupBox)
        self.listWidget.setGeometry(QtCore.QRect(10, 100, 421, 81))
        self.listWidget.setObjectName("listWidget")
        self.label_3 = QtWidgets.QLabel(self.groupBox)
        self.label_3.setGeometry(QtCore.QRect(10, 30, 421, 16))
        self.label_3.setObjectName("label_3")
        self.comboBox = QtWidgets.QComboBox(self.groupBox)
        self.comboBox.setGeometry(QtCore.QRect(10, 50, 301, 22))
        self.comboBox.setObjectName("comboBox")
        self.pushButton = QtWidgets.QPushButton(self.groupBox)
        self.pushButton.setGeometry(QtCore.QRect(350, 50, 75, 24))
        self.pushButton.setObjectName("pushButton")
        self.label_4 = QtWidgets.QLabel(self.groupBox)
        self.label_4.setGeometry(QtCore.QRect(10, 80, 301, 16))
        self.label_4.setObjectName("label_4")
        self.pushButton_2 = QtWidgets.QPushButton(self.groupBox)
        self.pushButton_2.setGeometry(QtCore.QRect(180, 190, 75, 24))
        self.pushButton_2.setObjectName("pushButton_2")
        self.pushButton_3 = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton_3.setGeometry(QtCore.QRect(100, 290, 241, 26))
        self.pushButton_3.setObjectName("pushButton_3")
        self.pushButton_4 = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton_4.setGeometry(QtCore.QRect(100, 325, 241, 26))
        self.pushButton_4.setObjectName("pushButton_3")
        self.switch = QtWidgets.QRadioButton(self.centralwidget)
        self.switch.setGeometry(QtCore.QRect(50, 370, 111, 17))
        self.switch.setObjectName("switch")
        self.switch2 = QtWidgets.QRadioButton(self.centralwidget)
        self.switch2.setGeometry(QtCore.QRect(300, 370, 111, 17))
        self.switch2.setObjectName("switch2")
        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 464, 23))
        self.menubar.setObjectName("menubar")
        self.menu = QtWidgets.QMenu(self.menubar)
        self.menu.setObjectName("menu")
        MainWindow.setMenuBar(self.menubar)
        self.action = QtWidgets.QAction(MainWindow)
        self.action.setObjectName("action")
        self.action_3 = QtWidgets.QAction(MainWindow)
        self.action_3.setObjectName("action_3")
        self.menu.addAction(self.action)
        self.menu.addSeparator()
        self.menu.addAction(self.action_3)
        self.menubar.addAction(self.menu.menuAction())

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "MainWindow"))
        self.label_2.setText(_translate("MainWindow", "Путь до файла:"))
        self.groupBox.setTitle(_translate("MainWindow", "Выбор пользователей для электронной подписи:"))
        self.label_3.setText(_translate("MainWindow", "Доступные пользователи:"))
        self.pushButton.setText(_translate("MainWindow", "Добавить"))
        self.label_4.setText(_translate("MainWindow", "Выбранная пользователи:"))
        self.pushButton_2.setText(_translate("MainWindow", "Удалить"))
        self.pushButton_3.setText(_translate("MainWindow", "Подписать документ"))
        self.pushButton_4.setText(_translate("MainWindow", "Проверить подпись"))
        self.switch.setText(_translate("MainWindow", "Ключ 256 бит"))
        self.switch2.setText(_translate("MainWindow", "Ключ 512 бит"))
        self.menu.setTitle(_translate("MainWindow", "Открыть"))
        self.action.setText(_translate("MainWindow", "Открыть файл"))
        self.action_3.setText(_translate("MainWindow", "Информация о программе"))