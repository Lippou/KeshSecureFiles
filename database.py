import sqlite3

def init_db():
    conn = sqlite3.connect('secure_files.db')
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
    conn = sqlite3.connect('secure_files.db')
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO files (filename, encrypted_filename)
        VALUES (?, ?)
    ''', (filename, encrypted_filename))
    conn.commit()
    conn.close()

def get_encrypted_filename(filename):
    conn = sqlite3.connect('secure_files.db')
    cursor = conn.cursor()
    cursor.execute('''
        SELECT encrypted_filename FROM files WHERE filename = ?
    ''', (filename,))
    result = cursor.fetchone()
    conn.close()
    return result[0] if result else None
