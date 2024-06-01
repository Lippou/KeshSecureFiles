import os
import sys
import base64
import requests
import json
import re
import subprocess
from PyQt5.QtCore import Qt, QSize
from PyQt5 import QtWidgets, QtGui, QtCore
from PyQt5.QtGui import QFont, QIcon, QPixmap, QMovie
from PyQt5.QtWidgets import QMessageBox, QDialog, QFileDialog, QLabel, QVBoxLayout, QHBoxLayout, QSpacerItem, QSizePolicy, QWidget
from PyQt5.QtWebEngineWidgets import QWebEngineView
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from PyQt5.QtWidgets import QApplication

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

    def check_for_updates(self, current_version):
        response = requests.get('https://api.github.com/repos/Lippou/KeshSecureFiles/releases/latest')
        latest_version = response.json()['tag_name']

        if latest_version > current_version:
            self.dev_message_label.setText(f'''This software is in development and will be further improved.<br>Version: {current_version}<br><a href="https://github.com/Lippou/KeshSecureFiles/releases/latest">Update available: {latest_version}</a>''')        
            self.dev_message_label.setOpenExternalLinks(True)
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
        logo_pixmap = logo_pixmap.scaled(200, 200, QtCore.Qt.KeepAspectRatio)  # Ajuster la taille du logo
        logo_label.setPixmap(logo_pixmap)
        logo_label.setAlignment(QtCore.Qt.AlignCenter)  # Centrer le logo
        logo_label.setObjectName("logo_label")
        layout.addWidget(logo_label)

        # Ajouter un titre en dessous du logo
        title_label = QLabel("Kesh Secure Files")
        title_label.setAlignment(QtCore.Qt.AlignCenter)  # Centrer le titre
        title_label.setStyleSheet("font-size: 24px")  # Augmenter la taille de la police
        layout.addWidget(title_label)

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
        self.open_encrypted_dir_button = QtWidgets.QPushButton("Open Encrypted Files Directory")
        self.select_file_button.setObjectName("action_button")
        self.encrypt_button.setObjectName("action_button")
        self.decrypt_button.setObjectName("action_button")
        self.change_password_button.setObjectName("action_button")
        self.open_encrypted_dir_button.setObjectName("action_button")

        # Connecter les boutons aux fonctions
        self.select_file_button.clicked.connect(self.select_file)
        self.encrypt_button.clicked.connect(self.add_file)
        self.decrypt_button.clicked.connect(self.retrieve_file)
        self.change_password_button.clicked.connect(self.change_password)
        self.open_encrypted_dir_button.clicked.connect(self.open_encrypted_files_directory)

        layout.addWidget(self.password_label)
        layout.addWidget(self.password_input)

        button_layout = QHBoxLayout()
        button_layout.addWidget(self.select_file_button)
        button_layout.addWidget(self.encrypt_button)
        button_layout.addWidget(self.decrypt_button)
        button_layout.addWidget(self.change_password_button)
        button_layout.addWidget(self.open_encrypted_dir_button)
        layout.addLayout(button_layout)

        # Étiquette d'information
        self.info_label = QLabel("Select a file to encrypt or decrypt. Make sure to enter the correct password.")
        self.info_label.setObjectName("info_label")
        layout.addWidget(self.info_label)

        # Ajouter un espaceur
        layout.addSpacerItem(QSpacerItem(20, 40, QSizePolicy.Minimum, QSizePolicy.Expanding))

        # Créer un layout horizontal pour les GIFs
        gif_layout = QHBoxLayout()

        # Ajouter le GIF d'encryption
        encryption_layout = QVBoxLayout()
        encryption_title = QLabel("Example Encryption :")
        encryption_title.setStyleSheet("font-size: 12px")  # Augmenter la taille de la police
        encryption_gif = QLabel()
        movie = QMovie("./img/encryption.gif")
        movie.setScaledSize(QSize(300, 170))  # Redimensionner le GIF
        encryption_gif.setMovie(movie)
        encryption_gif.setObjectName("encryption_gif")
        movie.start()  # Démarrer l'animation
        encryption_layout.addWidget(encryption_title)
        encryption_layout.addWidget(encryption_gif)
        gif_layout.addLayout(encryption_layout)
        
        # Ajouter le GIF de decryption
        decryption_layout = QVBoxLayout()
        decryption_title = QLabel("Example Decryption :")
        decryption_title.setStyleSheet("font-size: 12px")  # Augmenter la taille de la police
        decryption_gif = QLabel()
        movie = QMovie("./img/decryption.gif")
        movie.setScaledSize(QSize(300, 170))  # Redimensionner le GIF
        decryption_gif.setMovie(movie)
        decryption_gif.setObjectName("decryption_gif")
        gif_path = "./img/encryption.gif"  # Define the gif_path variable
        movie.start()  # Démarrer l'animation
        decryption_layout.addWidget(decryption_title)
        decryption_layout.addWidget(decryption_gif)
        gif_layout.addLayout(decryption_layout)

        # Ajouter le layout des GIFs au layout principal
        layout.addLayout(gif_layout)

        # Pied de page
        self.copyright_label = QLabel()
        self.copyright_label.setOpenExternalLinks(True)  # Permettre l'ouverture de liens externes
        self.copyright_label.setText('<a href="https://github.com/Lippou/KeshSecureFiles/blob/main/LICENSE">© Kesh 2024. All rights reserved.</a>')
        self.copyright_label.setObjectName("copyright_label")
        layout.addWidget(self.copyright_label)

        
        # Lire la version du fichier
        with open('.version', 'r') as version_file:
            version = version_file.read().strip()

        # Message de développement
        self.dev_message_label = QLabel(f"This software is in development and will be further improved.\nVersion: {version}.")
        self.dev_message_label.setObjectName("dev_message_label")
        layout.addWidget(self.dev_message_label)
        
        self.check_for_updates(version)
        
        self.setLayout(layout)
        self.encrypt_button.setVisible(False)
        self.decrypt_button.setVisible(False)
        self.password_set = self.check_password_set()
        if not self.password_set:
            self.create_password()
        self.adjust_window_size()

    def adjust_window_size(self):
        self.setFixedSize(600, 600)

    def check_password_set(self):
        return os.path.isfile(CONFIG_FILE)

    def create_password(self):
        msgBox = QMessageBox()
        msgBox.setIcon(QMessageBox.Information)
        msgBox.setWindowTitle("Kesh | Create Password")
        msgBox.setText("Welcome! To secure your files, please create a password.")
        msgBox.setStandardButtons(QMessageBox.Ok)
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
            except:
                self.password_attempts -= 1
                if self.password_attempts == 0:
                    QtWidgets.QMessageBox.critical(self, "Error", "Too many failed attempts. The application will exit.")
                    sys.exit()
                QtWidgets.QMessageBox.warning(self, "Error", f"Incorrect password. {self.password_attempts} attempts remaining.")
                self.password_input.clear()
                return False

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

    def generate_key(self, password):
        salt = os.urandom(16)
        kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1, backend=default_backend())
        key = kdf.derive(password.encode())
        return key, salt

    def get_salt_from_file(self, encrypted_file_path):
        with open(encrypted_file_path, 'rb') as f:
            salt = f.read(16)
        return salt

    def generate_key_with_salt(self, password, salt):
        kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1, backend=default_backend())
        key = kdf.derive(password.encode())
        return key

    def encrypt_file(self, file_path, key, salt, output_file_path):
        with open(file_path, 'rb') as f:
            plaintext = f.read()
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        with open(output_file_path, 'wb') as f:
            f.write(salt + iv + ciphertext)

    def decrypt_file(self, encrypted_file_path, key):
        with open(encrypted_file_path, 'rb') as f:
            salt = f.read(16)
            iv = f.read(16)
            ciphertext = f.read()
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        original_file_path = encrypted_file_path[:-10]
        with open(original_file_path, 'wb') as f:
            f.write(plaintext)

    def open_encrypted_files_directory(self):
        encrypted_files_path = os.path.abspath(ENCRYPTED_FILES_DIR)
        if sys.platform == 'win32':
            os.startfile(encrypted_files_path)
        elif sys.platform == 'darwin':
            subprocess.Popen(['open', encrypted_files_path])
        else:
            subprocess.Popen(['xdg-open', encrypted_files_path])

class PasswordDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Kesh | Create Password")
        self.setStyleSheet("""
            QLabel {
                font-size: 14px;
                margin-bottom: 5px;
            }
            QLineEdit {
                font-size: 12px;
                padding: 5px;
                margin-bottom: 10px;
            }
            QPushButton {
                font-size: 12px;
                padding: 5px 10px;
                background-color: #007BFF;
                color: #FFFFFF;
                border: none;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #0056b3;
            }
        """)

        self.password_label = QLabel("Enter new password:")
        self.password_input = QtWidgets.QLineEdit()
        self.password_input.setEchoMode(QtWidgets.QLineEdit.Password)
        self.password_confirm_label = QLabel("Confirm new password:")
        self.password_confirm_input = QtWidgets.QLineEdit()
        self.password_confirm_input.setEchoMode(QtWidgets.QLineEdit.Password)
        self.submit_button = QtWidgets.QPushButton("Submit")

        layout = QVBoxLayout()
        layout.addWidget(self.password_label)
        layout.addWidget(self.password_input)
        layout.addWidget(self.password_confirm_label)
        layout.addWidget(self.password_confirm_input)
        layout.addWidget(self.submit_button)

        self.setLayout(layout)

        self.submit_button.clicked.connect(self.verify_passwords)

    def verify_passwords(self):
        if self.password_input.text() == self.password_confirm_input.text():
            self.accept()
        else:
            QtWidgets.QMessageBox.warning(self, "Error", "Passwords do not match.")

    def get_password(self):
        return self.password_input.text()

if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)
    ex = App()
    ex.show()
    sys.exit(app.exec_())
