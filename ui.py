from PyQt5 import QtWidgets, QtGui, QtCore
from PyQt5.QtGui import QFont, QIcon
from PyQt5.QtWidgets import QMessageBox, QDialog, QFileDialog, QLabel, QVBoxLayout, QHBoxLayout, QSpacerItem, QSizePolicy
from encryption import generate_key, encrypt_file, decrypt_file
from cryptography.fernet import Fernet
import sys
import os
import hashlib

# Define the path to the encrypted files directory
ENCRYPTED_FILES_DIR = "encrypted_files"

# Create the directory if it doesn't exist
if not os.path.exists(ENCRYPTED_FILES_DIR):
    os.makedirs(ENCRYPTED_FILES_DIR)

class App(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.password_input = None
        self.password_attempts = 5
        self.selected_file = None
        self.initUI()

    def initUI(self):
        self.setWindowTitle('Kesh | Secure File Storage')
        self.setWindowIcon(QIcon('img/favicon.ico'))
        self.setStyleSheet(open('styles/style.css').read())

        layout = QVBoxLayout()

        # Add logo
        logo_label = QLabel(self)
        logo_pixmap = QtGui.QPixmap('img/favicon.png')
        logo_label.setPixmap(logo_pixmap)
        logo_label.setAlignment(QtCore.Qt.AlignCenter)

        self.password_label = QLabel("Enter Password:")
        self.password_input = QtWidgets.QLineEdit()
        self.password_input.setEchoMode(QtWidgets.QLineEdit.Password)
        self.password_input.setFont(QFont('Arial', 12))

        self.select_file_button = QtWidgets.QPushButton("Select File")
        self.encrypt_button = QtWidgets.QPushButton("Encrypt File")
        self.decrypt_button = QtWidgets.QPushButton("Decrypt File")

        self.select_file_button.clicked.connect(self.select_file)
        self.encrypt_button.clicked.connect(self.add_file)
        self.decrypt_button.clicked.connect(self.retrieve_file)

        layout.addWidget(logo_label)
        layout.addWidget(self.password_label)
        layout.addWidget(self.password_input)

        button_layout = QHBoxLayout()
        button_layout.addWidget(self.select_file_button)
        button_layout.addWidget(self.encrypt_button)
        button_layout.addWidget(self.decrypt_button)
        layout.addLayout(button_layout)

        # Info label
        self.info_label = QLabel("Select a file to encrypt or decrypt. Make sure to enter the correct password.")
        self.info_label.setAlignment(QtCore.Qt.AlignCenter)
        self.info_label.setFont(QFont('Arial', 10))
        layout.addWidget(self.info_label)

        # Add spacer
        layout.addSpacerItem(QSpacerItem(20, 40, QSizePolicy.Minimum, QSizePolicy.Expanding))

        # Copyright label
        self.copyright_label = QLabel("© Kesh 2024. All rights reserved.")
        self.copyright_label.setAlignment(QtCore.Qt.AlignCenter)
        self.copyright_label.setFont(QFont('Arial', 10))
        layout.addWidget(self.copyright_label)
        self.setLayout(layout)

        self.encrypt_button.setVisible(False)
        self.decrypt_button.setVisible(False)

        self.password_set = self.check_password_set()

        if not self.password_set:
            self.create_password()

        # Adjust window size
        self.adjust_window_size()

    def adjust_window_size(self):
        self.setFixedSize(500, 400)  # Adjust the size as needed

    def check_password_set(self):
        return os.path.isfile('config.dat')

    def create_password(self):
        msgBox = QMessageBox()
        msgBox.setIcon(QMessageBox.Information)
        msgBox.setWindowTitle("Kesh | Create Password")
        msgBox.setText("Welcome! To secure your files, please create a password.")
        msgBox.setStandardButtons(QMessageBox.Ok)
        msgBox.setStyleSheet(open('styles/popup_style.css').read())  # Using style for pop-ups
        msgBox.exec_()

        while not self.password_set:
            password_dialog = PasswordDialog()
            if password_dialog.exec_() == QtWidgets.QDialog.Accepted:
                self.password = password_dialog.get_password()
                if self.password:
                    hashed_password = hashlib.sha256(self.password.encode()).hexdigest()
                    with open('config.dat', 'w') as file:
                        file.write(hashed_password)
                    self.password_set = True
                    self.show_password_tips()

    def select_file(self):
        options = QFileDialog.Options()
        file_path, _ = QFileDialog.getOpenFileName(self, "Select a file", "", "All Files (*);;Encrypted Files (*.encrypted);;Text Files (*.txt)", options=options)
        if file_path:
            self.selected_file = file_path
            if file_path.endswith('.encrypted'):
                self.encrypt_button.setVisible(False)
                self.decrypt_button.setVisible(True)
            else:
                self.encrypt_button.setVisible(True)
                self.decrypt_button.setVisible(False)

    def add_file(self):
        if self.check_password():
            password = self.password_input.text()
            key = generate_key(password)
            fernet = Fernet(key)
            if self.selected_file:
                self.encrypt_button.setText("Encrypting...")
                encrypted_file_path = os.path.join(ENCRYPTED_FILES_DIR, os.path.basename(self.selected_file) + ".encrypted")
                encrypt_file(self.selected_file, fernet, encrypted_file_path)
                self.encrypt_button.setText("Encrypt File")
                QtWidgets.QMessageBox.information(self, "Success", f"File {self.selected_file} encrypted and stored securely.")
                self.selected_file = None
                self.encrypt_button.setVisible(False)

    def retrieve_file(self):
        if self.check_password():
            password = self.password_input.text()
            key = generate_key(password)
            fernet = Fernet(key)
            if self.selected_file:
                self.decrypt_button.setText("Decrypting...")
                decrypt_file(self.selected_file, fernet)
                self.decrypt_button.setText("Decrypt File")
                QtWidgets.QMessageBox.information(self, "Success", f"File {self.selected_file} decrypted and retrieved.")
                self.selected_file = None
                self.decrypt_button.setVisible(False)

    def check_password(self):
        entered_password = self.password_input.text()
        with open('config.dat', 'r') as file:
            hashed_password = file.readline().strip()
            entered_password_hash = hashlib.sha256(entered_password.encode()).hexdigest()
            if entered_password_hash == hashed_password:
                self.password_attempts = 5
                return True
            else:
                self.password_attempts -= 1
                if self.password_attempts == 0:
                    self.delete_all_encrypted_files()
                else:
                    message = f"Incorrect password. Remaining attempts: {self.password_attempts}"
                    QtWidgets.QMessageBox.warning(self, "Error", message)
                return False

    def delete_all_encrypted_files(self):
        pass

    def show_password_tips(self):
        msgBox = QMessageBox()
        msgBox.setIcon(QMessageBox.Warning)
        msgBox.setWindowTitle("Kesh | Security Tips")
        msgBox.setText("Welcome! You have successfully created your password.\n\nHere are some tips to keep your password secure:\n- Never share your password with anyone.\n- Use a unique password for this software.\n- Avoid using obvious or easy-to-guess passwords.\n- Use a combination of uppercase and lowercase letters, numbers, and symbols to create a strong password.\n- Memorize your password and do not write it down on paper or store it in an insecure location.\n- Regularly change your password to enhance security.\n\nClick 'Ok' to continue.")
        msgBox.setStandardButtons(QMessageBox.Ok)
        msgBox.setStyleSheet(open('styles/popup_style.css').read())  # Using style for pop-ups
        msgBox.exec_()

class PasswordDialog(QtWidgets.QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('Kesh | Create Password')
        self.setFixedSize(300, 150)

        layout = QVBoxLayout()

        self.password_label = QLabel("Password:")
        self.password_input = QtWidgets.QLineEdit()
        self.password_input.setEchoMode(QtWidgets.QLineEdit.Password)
        self.password_input.setFont(QFont('Arial', 12))

        self.submit_button = QtWidgets.QPushButton("Submit")
        self.submit_button.clicked.connect(self.accept)

        layout.addWidget(self.password_label)
        layout.addWidget(self.password_input)
        layout.addWidget(self.submit_button)

        self.setLayout(layout)

    def get_password(self):
        return self.password_input.text()

if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    app.setWindowIcon(QIcon('img/favicon.ico'))
    ex = App()
    ex.show()
    sys.exit(app.exec_())
