import sqlite3
import os

def init_db():
    # Définir le chemin de la base de données dans le répertoire utilisateur
    db_dir = os.path.expanduser("~\\KeshSecureFiles")
    db_path = os.path.join(db_dir, 'secure_files.db')

    # Vérifier si le répertoire existe, sinon le créer
    if not os.path.exists(db_dir):
        os.makedirs(db_dir)

    # Connexion à la base de données
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            encrypted_filename TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

def add_file_to_db(filename, encrypted_filename):
    db_dir = os.path.expanduser("~\\KeshSecureFiles")
    db_path = os.path.join(db_dir, 'secure_files.db')

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO files (filename, encrypted_filename)
        VALUES (?, ?)
    ''', (filename, encrypted_filename))
    conn.commit()
    conn.close()

def get_encrypted_filename(filename):
    db_dir = os.path.expanduser("~\\KeshSecureFiles")
    db_path = os.path.join(db_dir, 'secure_files.db')

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT encrypted_filename FROM files WHERE filename = ?
    ''', (filename,))
    result = cursor.fetchone()
    conn.close()
    return result[0] if result else None
