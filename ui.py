import os
import sys
import base64
import re
from PyQt5 import QtWidgets, QtGui, QtCore
from PyQt5.QtGui import QFont, QIcon
from PyQt5.QtWidgets import QMessageBox, QDialog, QFileDialog, QLabel, QVBoxLayout, QHBoxLayout, QSpacerItem, QSizePolicy
from PyQt5.QtWebEngineWidgets import QWebEngineView
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

ENCRYPTED_FILES_DIR = "encrypted_files"
CONFIG_FILE = os.path.join(os.getenv('APPDATA'), '.config_secure_storage', 'config.dat')

if not os.path.exists(os.path.dirname(CONFIG_FILE)):
    os.makedirs(os.path.dirname(CONFIG_FILE))

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
        self.setStyleSheet("""
            /* CSS du logo */
            #logo_label {
                text-align: center;
            }

            /* CSS du formulaire de mot de passe */
            #password_input {
                width: 200px;
                margin: 10px auto;
            }

            /* CSS des boutons */
            .action_button {
                width: 120px;
                margin: 10px;
            }

            /* CSS de l'étiquette d'information */
            #info_label {
                text-align: center;
                font-size: 14px;
            }

            /* CSS du pied de page */
            #copyright_label {
                text-align: center;
                font-size: 10px;
                margin-top: 20px;
            }
        """)

        layout = QVBoxLayout()

        # Ajouter le logo
        logo_label = QLabel(self)
        logo_pixmap = QtGui.QPixmap('img/favicon.png')
        logo_label.setPixmap(logo_pixmap)
        logo_label.setObjectName("logo_label")
        layout.addWidget(logo_label)

        # Entrée de mot de passe
        self.password_label = QLabel("Enter Password:")
        self.password_input = QtWidgets.QLineEdit()
        self.password_input.setObjectName("password_input")
        self.password_input.setEchoMode(QtWidgets.QLineEdit.Password)
        self.password_input.setFont(QFont('Arial', 12))

        # Boutons
        self.select_file_button = QtWidgets.QPushButton("Select File")
        self.encrypt_button = QtWidgets.QPushButton("Encrypt File")
        self.decrypt_button = QtWidgets.QPushButton("Decrypt File")
        self.change_password_button = QtWidgets.QPushButton("Change Password")
        self.select_file_button.setObjectName("action_button")
        self.encrypt_button.setObjectName("action_button")
        self.decrypt_button.setObjectName("action_button")
        self.change_password_button.setObjectName("action_button")

        # Connecter les boutons aux fonctions
        self.select_file_button.clicked.connect(self.select_file)
        self.encrypt_button.clicked.connect(self.add_file)
        self.decrypt_button.clicked.connect(self.retrieve_file)
        self.change_password_button.clicked.connect(self.change_password)

        layout.addWidget(self.password_label)
        layout.addWidget(self.password_input)

        button_layout = QHBoxLayout()
        button_layout.addWidget(self.select_file_button)
        button_layout.addWidget(self.encrypt_button)
        button_layout.addWidget(self.decrypt_button)
        button_layout.addWidget(self.change_password_button)
        layout.addLayout(button_layout)

        # Étiquette d'information
        self.info_label = QLabel("Select a file to encrypt or decrypt. Make sure to enter the correct password.")
        self.info_label.setObjectName("info_label")
        layout.addWidget(self.info_label)

        # Ajouter un espaceur
        layout.addSpacerItem(QSpacerItem(20, 40, QSizePolicy.Minimum, QSizePolicy.Expanding))

        # Pied de page
        self.copyright_label = QLabel("© Kesh 2024. All rights reserved.")
        self.copyright_label.setObjectName("copyright_label")
        layout.addWidget(self.copyright_label)

        # Message de développement
        self.dev_message_label = QLabel("This software is in development and will be further improved.")
        self.dev_message_label.setObjectName("dev_message_label")
        layout.addWidget(self.dev_message_label)

        self.setLayout(layout)

        self.encrypt_button.setVisible(False)
        self.decrypt_button.setVisible(False)

        self.password_set = self.check_password_set()

        if not self.password_set:
            self.create_password()

        self.adjust_window_size()

    def adjust_window_size(self):
        self.setFixedSize(500, 600)

    def check_password_set(self):
        return os.path.isfile(CONFIG_FILE)

    def create_password(self):
        msgBox = QMessageBox()
        msgBox.setIcon(QMessageBox.Information)
        msgBox.setWindowTitle("Kesh | Create Password")
        msgBox.setText("Welcome! To secure your files, please create a password.")
        msgBox.setStandardButtons(QMessageBox.Ok)
        msgBox.setStyleSheet(open('styles/popup_style.css').read())  
        msgBox.exec_()

        while not self.password_set:
            password_dialog = PasswordDialog()
            if password_dialog.exec_() == QtWidgets.QDialog.Accepted:
                self.password = password_dialog.get_password()
                if self.password and self.is_password_valid(self.password):
                    salt = os.urandom(16)
                    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1, backend=default_backend())
                    key = kdf.derive(self.password.encode())
                    hashed_password = base64.urlsafe_b64encode(salt + key).decode('utf-8')
                    with open(CONFIG_FILE, 'w') as file:
                        file.write(hashed_password)
                    self.password_set = True
                    self.show_password_tips()
                else:
                    QtWidgets.QMessageBox.warning(self, "Error", "Password does not meet the required conditions.")

    def is_password_valid(self, password):
        if len(password) < 8:
            return False
        if not re.search(r"[A-Za-z]", password):
            return False
        if not re.search(r"[0-9]", password):
            return False
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            return False
        return True

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
            key, salt = self.generate_key(password)
            if self.selected_file:
                self.encrypt_button.setText("Encrypting...")
                QtCore.QTimer.singleShot(5000, self.finish_encrypt)  
                encrypted_file_path = os.path.join(ENCRYPTED_FILES_DIR, os.path.basename(self.selected_file) + ".encrypted")
                self.encrypt_file(self.selected_file, key, salt, encrypted_file_path)
                os.remove(self.selected_file)  # Supprimer le fichier original
                self.encrypt_button.setText("Encrypt File")
                QtWidgets.QMessageBox.information(self, "Success", f"File {self.selected_file} encrypted and stored securely.")
                self.selected_file = None
                self.encrypt_button.setVisible(False)

    def finish_encrypt(self):
        pass  

    def retrieve_file(self):
        if self.check_password():
            password = self.password_input.text()
            salt = self.get_salt_from_file(self.selected_file)
            key = self.generate_key_with_salt(password, salt)
            if self.selected_file:
                self.decrypt_button.setText("Decrypting...")
                QtCore.QTimer.singleShot(5000, self.finish_decrypt)  
                self.decrypt_file(self.selected_file, key)
                os.remove(self.selected_file)  # Supprimer le fichier crypté
                self.decrypt_button.setText("Decrypt File")
                QtWidgets.QMessageBox.information(self, "Success", f"File {self.selected_file} decrypted and retrieved.")
                self.selected_file = None
                self.decrypt_button.setVisible(False)

    def finish_decrypt(self):
        pass  

    def check_password(self):
        entered_password = self.password_input.text()
        with open(CONFIG_FILE, 'r') as file:
            hashed_password = file.readline().strip()
            salt_key = base64.urlsafe_b64decode(hashed_password)
            salt = salt_key[:16]
            stored_key = salt_key[16:]
            kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1, backend=default_backend())
            try:
                kdf.verify(entered_password.encode(), stored_key)
                return True
            except Exception as e:
                self.password_attempts -= 1
                if self.password_attempts <= 0:
                    self.show_locked_message()
                else:
                    QtWidgets.QMessageBox.warning(self, "Error", f"Invalid password. Attempts remaining: {self.password_attempts}.")
                return False

    def show_locked_message(self):
        msgBox = QMessageBox()
        msgBox.setIcon(QMessageBox.Critical)
        msgBox.setWindowTitle("Kesh | Locked")
        msgBox.setText("Too many invalid password attempts. The application is now locked.")
        msgBox.setStandardButtons(QMessageBox.Ok)
        msgBox.setStyleSheet(open('styles/popup_style.css').read())  
        msgBox.exec_()
        sys.exit()

    def show_password_tips(self):
        tips = """
        <h2>Password Tips</h2>
        <ul>
            <li>Use at least 8 characters.</li>
            <li>Include both uppercase and lowercase letters.</li>
            <li>Include at least one number.</li>
            <li>Include at least one special character (e.g., !@#$%^&*).</li>
        </ul>
        """
        msgBox = QMessageBox()
        msgBox.setIcon(QMessageBox.Information)
        msgBox.setWindowTitle("Kesh | Password Tips")
        msgBox.setText(tips)
        msgBox.setStandardButtons(QMessageBox.Ok)
        msgBox.setStyleSheet(open('styles/popup_style.css').read())  
        msgBox.exec_()

    def change_password(self):
        if self.check_password():
            new_password_dialog = PasswordDialog()
            if new_password_dialog.exec_() == QtWidgets.QDialog.Accepted:
                new_password = new_password_dialog.get_password()
                if new_password and self.is_password_valid(new_password):
                    salt = os.urandom(16)
                    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1, backend=default_backend())
                    key = kdf.derive(new_password.encode())
                    hashed_password = base64.urlsafe_b64encode(salt + key).decode('utf-8')
                    with open(CONFIG_FILE, 'w') as file:
                        file.write(hashed_password)
                    QtWidgets.QMessageBox.information(self, "Success", "Password changed successfully.")
                else:
                    QtWidgets.QMessageBox.warning(self, "Error", "New password does not meet the required conditions.")

    def generate_key(self, password):
        salt = os.urandom(16)
        kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1, backend=default_backend())
        key = kdf.derive(password.encode())
        return key, salt

    def generate_key_with_salt(self, password, salt):
        kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1, backend=default_backend())
        key = kdf.derive(password.encode())
        return key

    def get_salt_from_file(self, file_path):
        with open(file_path, 'rb') as file:
            return file.read(16)

    def encrypt_file(self, file_path, key, salt, output_file_path):
        with open(file_path, 'rb') as file:
            plaintext = file.read()
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        with open(output_file_path, 'wb') as file:
            file.write(salt + iv + ciphertext)

    def decrypt_file(self, file_path, key):
        with open(file_path, 'rb') as file:
            salt = file.read(16)
            iv = file.read(16)
            ciphertext = file.read()
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        original_file_path = file_path.replace(".encrypted", "")
        with open(original_file_path, 'wb') as file:
            file.write(plaintext)

class PasswordDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Create Password")
        self.setFixedSize(300, 200)

        layout = QVBoxLayout()

        self.label = QLabel("Create a new password:")
        self.password_input = QtWidgets.QLineEdit()
        self.password_input.setEchoMode(QtWidgets.QLineEdit.Password)
        self.password_input.setFont(QFont('Arial', 12))
        
        self.confirm_label = QLabel("Confirm password:")
        self.confirm_input = QtWidgets.QLineEdit()
        self.confirm_input.setEchoMode(QtWidgets.QLineEdit.Password)
        self.confirm_input.setFont(QFont('Arial', 12))

        self.conditions_label = QLabel("""
        <h3>Password Conditions:</h3>
        <ul>
            <li>At least 8 characters long.</li>
            <li>Includes uppercase and lowercase letters.</li>
            <li>Includes at least one number.</li>
            <li>Includes at least one special character.</li>
        </ul>
        """)
        self.conditions_label.setWordWrap(True)
        
        self.submit_button = QtWidgets.QPushButton("Submit")
        self.submit_button.clicked.connect(self.submit)

        layout.addWidget(self.label)
        layout.addWidget(self.password_input)
        layout.addWidget(self.confirm_label)
        layout.addWidget(self.confirm_input)
        layout.addWidget(self.conditions_label)
        layout.addWidget(self.submit_button)

        self.setLayout(layout)

    def submit(self):
        if self.password_input.text() == self.confirm_input.text():
            if self.is_password_valid(self.password_input.text()):
                self.accept()
            else:
                QtWidgets.QMessageBox.warning(self, "Error", "Password does not meet the required conditions.")
        else:
            QtWidgets.QMessageBox.warning(self, "Error", "Passwords do not match.")

    def is_password_valid(self, password):
        if len(password) < 8:
            return False
        if not re.search(r"[A-Za-z]", password):
            return False
        if not re.search(r"[0-9]", password):
            return False
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            return False
        return True

    def get_password(self):
        return self.password_input.text()

if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)
    ex = App()
    ex.show()
    sys.exit(app.exec_())
