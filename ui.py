from PyQt5 import QtWidgets, QtGui
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import QMessageBox, QDialog, QFileDialog
from encryption import generate_key, encrypt_file, decrypt_file
from cryptography.fernet import Fernet
import sys
import os
import hashlib
import secrets

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
        self.initUI()

    def initUI(self):
        self.setWindowTitle('Secure File Storage')
        self.setGeometry(100, 100, 400, 200)
        self.setStyleSheet(open('styles/style.css').read())

        layout = QtWidgets.QVBoxLayout()

        self.password_label = QtWidgets.QLabel("Enter Password:")
        self.password_input = QtWidgets.QLineEdit()
        self.password_input.setEchoMode(QtWidgets.QLineEdit.Password)
        self.password_input.setFont(QFont('Arial', 12))

        self.encrypt_button = QtWidgets.QPushButton("Add File")
        self.decrypt_button = QtWidgets.QPushButton("Retrieve File")

        self.encrypt_button.clicked.connect(self.add_file)
        self.decrypt_button.clicked.connect(self.retrieve_file)

        layout.addWidget(self.password_label)
        layout.addWidget(self.password_input)
        layout.addWidget(self.encrypt_button)
        layout.addWidget(self.decrypt_button)

        self.setLayout(layout)

        self.password_set = self.check_password_set()

        if not self.password_set:
            self.create_password()

    def check_password_set(self):
        return os.path.isfile('config.dat')

    def create_password(self):
        msgBox = QMessageBox()
        msgBox.setIcon(QMessageBox.Information)
        msgBox.setWindowTitle("Create Password")
        msgBox.setText("Welcome! To secure your files, please create a password.")
        msgBox.setStandardButtons(QMessageBox.Ok)
        msgBox.setStyleSheet(open('popup_style.css').read())  # Using style for pop-ups
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

    def add_file(self):
        if self.check_password():
            password = self.password_input.text()
            key = generate_key(password)
            fernet = Fernet(key)
            options = QFileDialog.Options()
            file_path, _ = QFileDialog.getOpenFileName(self, "Select a file to secure", "", "All Files (*);;Text Files (*.txt)", options=options)
            if file_path:
                encrypted_file_path = os.path.join(ENCRYPTED_FILES_DIR, os.path.basename(file_path) + ".encrypted")
                encrypt_file(file_path, fernet, encrypted_file_path)
                QtWidgets.QMessageBox.information(self, "Success", f"File {file_path} encrypted and stored securely.")

    def retrieve_file(self):
        if self.check_password():
            password = self.password_input.text()
            key = generate_key(password)
            fernet = Fernet(key)
            options = QFileDialog.Options()
            file_path, _ = QFileDialog.getOpenFileName(self, "Select a file to retrieve", "", "Encrypted Files (*.encrypted);;All Files (*)", options=options)
            if file_path:
                decrypt_file(file_path, fernet)
                QtWidgets.QMessageBox.information(self, "Success", f"File {file_path} decrypted and retrieved.")

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
        msgBox.setWindowTitle("Security Tips")
        msgBox.setText("Welcome! You have successfully created your password.\n\nHere are some tips to keep your password secure:\n- Never share your password with anyone.\n- Use a unique password for this software.\n- Avoid using obvious or easy-to-guess passwords.\n- Use a combination of uppercase and lowercase letters, numbers, and symbols to create a strong password.\n- Memorize your password and do not write it down on paper or store it in an insecure location.\n- Regularly change your password to enhance security.\n\nClick 'My password will not be lost' to continue.")
        msgBox.setStandardButtons(QMessageBox.Ok)
        msgBox.setStyleSheet(open('popup_style.css').read())  # Using style for pop-ups
        msgBox.exec_()

class PasswordDialog(QtWidgets.QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('Create Password')
        self.setFixedSize(300, 150)

        layout = QtWidgets.QVBoxLayout()

        self.password_label = QtWidgets.QLabel("Password:")
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
    ex = App()
    ex.show()
    sys.exit(app.exec_())
