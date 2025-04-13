import os
import hashlib
import mysql.connector
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, Text
from ttkthemes import ThemedTk
from cryptography.fernet import Fernet
import pyotp
import secrets
import logging
import re
import platform
import subprocess 
import tempfile
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# Set up logging for security events
logging.basicConfig(filename='security.log', level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Database setup with error handling and database creation
# XAMPP MySQL configuration
DB_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "",  # Default XAMPP password; update if set
    "database": "file_system_db"
}

def get_db_connection():
    return mysql.connector.connect(**DB_CONFIG)

def setup_database():
    try:
        conn = mysql.connector.connect(
            host="localhost",
            user="root",
            password=""
        )
        cursor = conn.cursor()
        cursor.execute("CREATE DATABASE IF NOT EXISTS file_system_db")
        conn.commit()
        conn.close()

        conn = mysql.connector.connect(
            host="localhost",
            user="root",
            password="",
            database="file_system_db"
        )
        cursor = conn.cursor()
        
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                            username VARCHAR(50) PRIMARY KEY,
                            password_hash VARCHAR(255),
                            salt VARCHAR(32),
                            two_factor_secret VARCHAR(32),
                            encryption_key BLOB,
                            session_token VARCHAR(64))''')
        
        cursor.execute('''CREATE TABLE IF NOT EXISTS files (
                            filename VARCHAR(255),
                            owner VARCHAR(50),
                            encrypted_data BLOB,
                            metadata TEXT,
                            FOREIGN KEY (owner) REFERENCES users(username))''')
        
        cursor.execute('''CREATE TABLE IF NOT EXISTS shared_files (
                            filename VARCHAR(255),
                            shared_with VARCHAR(50),
                            FOREIGN KEY (shared_with) REFERENCES users(username))''')
        
        conn.commit()
        logging.info("Database and tables created successfully")
    except mysql.connector.Error as err:
        logging.error(f"Database setup failed: {err}")
        raise
    finally:
        if 'conn' in locals():
            conn.close()

# Input validation to prevent injection attacks
def sanitize_input(value):
    return re.sub(r'[^a-zA-Z0-9_.-]', '', value)[:50]

# Malware detection (ClamAV or hash-based fallback)
def scan_for_malware(filepath=None, data=None):
    if filepath:
        try:
            import pyclamd
            cd = pyclamd.ClamdAgnostic()
            result = cd.scan_file(filepath)
            if result and result[filepath] != 'OK':
                logging.warning(f"Malware detected in {filepath}: {result}")
                return True
        except ImportError:
            with open(filepath, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
            known_malware_hashes = {'eicar_test_hash': '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'}
            if file_hash in known_malware_hashes.values():
                logging.warning(f"Malware detected in {filepath} (hash: {file_hash})")
                return True
        except Exception as e:
            logging.error(f"Malware scan failed for {filepath}: {e}")
    elif data:
        file_hash = hashlib.sha256(data.encode()).hexdigest()
        known_malware_hashes = {'eicar_test_hash': '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'}
        if file_hash in known_malware_hashes.values():
            logging.warning(f"Malware detected in text data (hash: {file_hash})")
            return True
    return False

# Authentication class with password hashing and 2FA
class Authentication:
    def hash_password(self, password, salt=None):
        if not salt:
            salt = secrets.token_hex(16)
        return hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000).hex(), salt

    def register_user(self, username, password, callback):
        username = sanitize_input(username)
        if not username or len(password) < 8:
            messagebox.showerror("Error", "Invalid username or password (min 8 chars)")
            return
        password_hash, salt = self.hash_password(password)
        two_factor_secret = pyotp.random_base32()
        encryption_key = Fernet.generate_key()
        session_token = secrets.token_hex(32)
        try:
            conn = mysql.connector.connect(
                host="localhost",
                user="root",
                password="",
                database="file_system_db"
            )
            cursor = conn.cursor()
            cursor.execute('INSERT INTO users (username, password_hash, salt, two_factor_secret, encryption_key, session_token) VALUES (%s, %s, %s, %s, %s, %s)', 
                          (username, password_hash, salt, two_factor_secret, encryption_key, session_token))
            conn.commit()
            callback(two_factor_secret)
            logging.info(f"User {username} registered successfully")
        except mysql.connector.IntegrityError:
            messagebox.showerror("Error", "Username already exists!")
            logging.warning(f"Registration failed for {username}: Username exists")
        except mysql.connector.Error as err:
            messagebox.showerror("Error", f"Database error: {err}")
            logging.error(f"Registration failed for {username}: {err}")
        finally:
            if 'conn' in locals():
                conn.close()

    def authenticate_user(self, username, password, totp_code):
        username = sanitize_input(username)
        try:
            conn = mysql.connector.connect(
                host="localhost",
                user="root",
                password="",
                database="file_system_db"
            )
            cursor = conn.cursor()
            cursor.execute('SELECT password_hash, salt, two_factor_secret FROM users WHERE username=%s', (username,))
            user_data = cursor.fetchone()
            if not user_data:
                messagebox.showerror("Error", "User not found!")
                logging.warning(f"Login failed: {username} not found")
                return False
            stored_hash, salt, two_factor_secret = user_data
            computed_hash, _ = self.hash_password(password, salt)
            totp = pyotp.TOTP(two_factor_secret)
            if stored_hash == computed_hash and totp.verify(totp_code):
                session_token = secrets.token_hex(32)
                cursor.execute('UPDATE users SET session_token=%s WHERE username=%s', (session_token, username))
                conn.commit()
                logging.info(f"User {username} authenticated successfully")
                return session_token
            messagebox.showerror("Error", "Authentication failed!")
            logging.warning(f"Authentication failed for {username}")
            return False
        except mysql.connector.Error as err:
            messagebox.showerror("Error", f"Database error: {err}")
            logging.error(f"Authentication failed for {username}: {err}")
            return False
        finally:
            if 'conn' in locals():
                conn.close()

# File management with encryption and access control
class FileManager:
    def __init__(self, username, session_token, app):
        self.app = app
        try:
            conn = mysql.connector.connect(
                host="localhost",
                user="root",
                password="",
                database="file_system_db"
            )
            cursor = conn.cursor()
            cursor.execute('SELECT encryption_key, session_token FROM users WHERE username=%s', (username,))
            data = cursor.fetchone()
            if data and data[1] == session_token:
                self.key = data[0]
                self.cipher = Fernet(self.key)
                self.username = username
                self.session_token = session_token
            else:
                raise ValueError("Invalid session token")
        except mysql.connector.Error as err:
            logging.error(f"FileManager init failed for {username}: {err}")
            raise
        finally:
            if 'conn' in locals():
                conn.close()

    def encrypt_file(self, filepath=None, data=None):
        if filepath:
            if scan_for_malware(filepath=filepath):
                raise ValueError("Malware detected in file!")
            try:
                with open(filepath, 'rb') as file:
                    file_data = file.read()
                if len(file_data) > 10 * 1024 * 1024:
                    raise ValueError("File too large (max 10MB)!")
                return self.cipher.encrypt(file_data)
            except Exception as e:
                messagebox.showerror("Error", f"Encryption failed: {e}")
                logging.error(f"Encryption failed for {filepath}: {e}")
                return None
        elif data:
            if scan_for_malware(data=data):
                raise ValueError("Malware detected in text data!")
            try:
                if len(data) > 10 * 1024 * 1024:
                    raise ValueError("Data too large (max 10MB)!")
                return self.cipher.encrypt(data.encode())
            except Exception as e:
                messagebox.showerror("Error", f"Encryption failed: {e}")
                logging.error(f"Encryption failed for text data: {e}")
                return None

    def decrypt_file(self, encrypted_data):
        try:
            return self.cipher.decrypt(encrypted_data)
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {e}")
            logging.error(f"Decryption failed: {e}")
            return None

    

if __name__ == "__main__":
    try:
        setup_database()
        root = ThemedTk(theme="breeze")
        app = App(root)
        root.mainloop()
    except Exception as e:
        messagebox.showerror("Startup Error", f"Failed to start application: {e}")
        logging.error(f"Application startup failed: {e}")