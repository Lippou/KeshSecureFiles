import os
import hashlib
import base64
from cryptography.fernet import Fernet, InvalidToken
from database import add_file_to_db, get_encrypted_filename

def generate_key(password, salt=None):
    if salt is None:
        salt = os.urandom(16)  # Générer un sel de 16 octets
    hash_password = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return base64.urlsafe_b64encode(hash_password[:32]), salt

def encrypt_file(file_path, password, dest_path):
    key, salt = generate_key(password)
    fernet = Fernet(key)
    try:
        with open(file_path, 'rb') as file:
            original = file.read()
        encrypted = fernet.encrypt(original)
        with open(dest_path, 'wb') as encrypted_file:
            encrypted_file.write(salt + encrypted)  # Préfixer l'encryption avec le sel
        add_file_to_db(file_path, dest_path)
    except FileNotFoundError:
        print(f"Erreur : Le fichier {file_path} n'a pas été trouvé.")
    except Exception as e:
        print(f"Erreur lors du chiffrement du fichier : {e}")

def decrypt_file(file_path, password):
    try:
        with open(file_path, 'rb') as encrypted_file:
            salt = encrypted_file.read(16)  # Lire les 16 premiers octets pour le sel
            encrypted = encrypted_file.read()
        key, _ = generate_key(password, salt)
        fernet = Fernet(key)
        decrypted = fernet.decrypt(encrypted)
        original_file_path = file_path.replace(".encrypted", "")
        with open(original_file_path, 'wb') as decrypted_file:
            decrypted_file.write(decrypted)
        os.remove(file_path)
    except FileNotFoundError:
        print(f"Erreur : Le fichier {file_path} n'a pas été trouvé.")
    except InvalidToken:
        print("Erreur : Mot de passe incorrect ou fichier corrompu.")
    except Exception as e:
        print(f"Erreur lors du déchiffrement du fichier : {e}")