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
from datetime import datetime

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
        # First, connect without specifying a database to create file_system_db
        conn = mysql.connector.connect(
            host="localhost",
            user="root",
            password=""  # Your MySQL root password
        )
        cursor = conn.cursor()
        cursor.execute("CREATE DATABASE IF NOT EXISTS file_system_db")
        conn.commit()
        conn.close()

        # Now connect to file_system_db and create tables
        conn = mysql.connector.connect(
            host="localhost",
            user="root",
            password="",  # Your MySQL root password
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
                            uploader VARCHAR(50),
                            encrypted_data BLOB,
                            metadata TEXT,
                            FOREIGN KEY (uploader) REFERENCES users(username))''')
        
        cursor.execute('''CREATE TABLE IF NOT EXISTS shared_files (
                            filename VARCHAR(255),
                            shared_with VARCHAR(50),
                            shared_key BLOB,  -- Stores uploader's key for decryption
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
    return re.sub(r'[^a-zA-Z0-9_.-]', '', value)[:50]  # Limit to 50 chars, alphanumeric + some symbols

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
                password="",  # Your MySQL root password
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
                password="",  # Your MySQL root password
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
        self.app = app  # Reference to App instance for GUI refresh
        try:
            conn = mysql.connector.connect(
                host="localhost",
                user="root",
                password="",  # Your MySQL root password
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
                if len(file_data) > 10 * 1024 * 1024:  # 10MB limit to prevent buffer overflow
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
                if len(data) > 10 * 1024 * 1024:  # 10MB limit
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

    def save_file(self, filepath):
        encrypted_data = self.encrypt_file(filepath=filepath)
        if not encrypted_data:
            return
        mod_time = datetime.fromtimestamp(os.path.getmtime(filepath)).strftime('%Y-%m-%d %H:%M:%S')
        metadata = f"Size: {os.path.getsize(filepath)} bytes, Modified: {mod_time}"
        try:
            conn = mysql.connector.connect(
                host="localhost",
                user="root",
                password="",  # Your MySQL root password
                database="file_system_db"
            )
            cursor = conn.cursor()
            cursor.execute('INSERT INTO files (filename, uploader, encrypted_data, metadata) VALUES (%s, %s, %s, %s)', 
                          (sanitize_input(os.path.basename(filepath)), self.username, encrypted_data, metadata))
            conn.commit()
            messagebox.showinfo("Success", "File uploaded and encrypted successfully!")
            logging.info(f"File {filepath} uploaded by {self.username}")
        except mysql.connector.Error as err:
            messagebox.showerror("Error", f"Database error: {err}")
            logging.error(f"File save failed for {filepath}: {err}")
        finally:
            if 'conn' in locals():
                conn.close()

    def write_file(self, filename, data):
        encrypted_data = self.encrypt_file(data=data)
        if not encrypted_data:
            return
        mod_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        metadata = f"Size: {len(data)} bytes, Modified: {mod_time}"
        try:
            conn = mysql.connector.connect(
                host="localhost",
                user="root",
                password="",  # Your MySQL root password
                database="file_system_db"
            )
            cursor = conn.cursor()
            cursor.execute('INSERT INTO files (filename, uploader, encrypted_data, metadata) VALUES (%s, %s, %s, %s)', 
                          (sanitize_input(filename), self.username, encrypted_data, metadata))
            conn.commit()
            messagebox.showinfo("Success", "File written and encrypted successfully!")
            logging.info(f"File {filename} written by {self.username}")
        except mysql.connector.Error as err:
            messagebox.showerror("Error", f"Database error: {err}")
            logging.error(f"File write failed for {filename}: {err}")
        finally:
            if 'conn' in locals():
                conn.close()

    def share_file(self, filename, share_with):
        share_with = sanitize_input(share_with)
        try:
            conn = mysql.connector.connect(
                host="localhost",
                user="root",
                password="",  # Your MySQL root password
                database="file_system_db"
            )
            cursor = conn.cursor()
            # Check if user exists
            cursor.execute('SELECT encryption_key FROM users WHERE username=%s', (share_with,))
            recipient_key_data = cursor.fetchone()
            if not recipient_key_data:
                messagebox.showerror("Error", f"User {share_with} not found!")
                return
            # Get the uploader's key
            cursor.execute('SELECT uploader FROM files WHERE filename=%s', (filename,))
            uploader = cursor.fetchone()
            if not uploader:
                messagebox.showerror("Error", "File not found!")
                return
            uploader_name = uploader[0]
            cursor.execute('SELECT encryption_key FROM users WHERE username=%s', (uploader_name,))
            uploader_key = cursor.fetchone()[0]
            # Check if already shared
            cursor.execute('SELECT 1 FROM shared_files WHERE filename=%s AND shared_with=%s', (filename, share_with))
            if cursor.fetchone():
                messagebox.showwarning("Warning", "File already shared with this user!")
                return
            # Record sharing with uploader's key
            cursor.execute('INSERT INTO shared_files (filename, shared_with, shared_key) VALUES (%s, %s, %s)', 
                          (filename, share_with, uploader_key))
            conn.commit()
            messagebox.showinfo("Success", f"File shared with {share_with}")
            logging.info(f"File {filename} shared with {share_with} by {self.username}")
        except mysql.connector.Error as err:
            messagebox.showerror("Error", f"Database error: {err}")
            logging.error(f"File share failed for {filename}: {err}")
        finally:
            if 'conn' in locals():
                conn.close()

    def delete_file(self, filename):
        try:
            conn = mysql.connector.connect(
                host="localhost",
                user="root",
                password="",  # Your MySQL root password
                database="file_system_db"
            )
            cursor = conn.cursor()
            # Check if the file was uploaded by the user or shared with them
            cursor.execute('SELECT uploader FROM files WHERE filename=%s', (filename,))
            uploader = cursor.fetchone()
            if uploader and uploader[0] == self.username:
                # User can delete their own file
                pass
            else:
                # Check if the user has access via sharing
                cursor.execute('SELECT shared_with FROM shared_files WHERE filename=%s AND shared_with=%s', (filename, self.username))
                has_shared_access = cursor.fetchone()
                if not has_shared_access:
                    messagebox.showerror("Error", "You can only delete files you uploaded or were shared with you!")
                    return
            # Delete from files table
            cursor.execute('DELETE FROM files WHERE filename=%s', (filename,))
            # Delete sharing records
            cursor.execute('DELETE FROM shared_files WHERE filename=%s', (filename,))
            conn.commit()
            messagebox.showinfo("Success", f"File {filename} deleted successfully!")
            logging.info(f"File {filename} deleted by {self.username}")
            self.app.show_files()  # Refresh the file list
        except mysql.connector.Error as err:
            messagebox.showerror("Error", f"Database error: {err}")
            logging.error(f"Delete failed for {filename}: {err}")
        finally:
            if 'conn' in locals():
                conn.close()

    def get_files(self):
        try:
            conn = mysql.connector.connect(
                host="localhost",
                user="root",
                password="",  # Your MySQL root password
                database="file_system_db"
            )
            cursor = conn.cursor()
            cursor.execute('SELECT filename FROM files WHERE uploader=%s', (self.username,))
            uploaded_files = [row[0] for row in cursor.fetchall() or []]
            cursor.execute('SELECT filename FROM shared_files WHERE shared_with=%s', (self.username,))
            shared_files = [row[0] for row in cursor.fetchall() or []]
            return uploaded_files + shared_files  # All files the user can access
        except mysql.connector.Error as err:
            messagebox.showerror("Error", f"Database error: {err}")
            logging.error(f"Get files failed for {self.username}: {err}")
            return []
        finally:
            if 'conn' in locals():
                conn.close()

    def get_metadata(self, filename):
        try:
            conn = mysql.connector.connect(
                host="localhost",
                user="root",
                password="",  # Your MySQL root password
                database="file_system_db"
            )
            cursor = conn.cursor()
            # Check if the user uploaded the file or has shared access
            cursor.execute('SELECT uploader FROM files WHERE filename=%s', (filename,))
            uploader = cursor.fetchone()
            if uploader and uploader[0] == self.username:
                pass
            else:
                cursor.execute('SELECT shared_with FROM shared_files WHERE filename=%s AND shared_with=%s', (filename, self.username))
                has_shared_access = cursor.fetchone()
                if not has_shared_access:
                    messagebox.showerror("Error", "You can only view metadata for files you uploaded or were shared with you!")
                    return "Access denied"
            # Retrieve metadata
            cursor.execute('SELECT metadata FROM files WHERE filename=%s', (filename,))
            data = cursor.fetchone()
            return data[0] if data else "No metadata available"
        except mysql.connector.Error as err:
            messagebox.showerror("Error", f"Database error: {err}")
            logging.error(f"Get metadata failed for {filename}: {err}")
            return "Error retrieving metadata"
        finally:
            if 'conn' in locals():
                conn.close()

# GUI Application
class App:
    def __init__(self, root):
        self.root = root
        self.auth = Authentication()
        self.username = ""
        self.session_token = ""
        self.root.title("Secure File Management System (MySQL)")
        self.root.geometry("600x500")
        self.show_login_page()

    def show_login_page(self):
        for widget in self.root.winfo_children():
            widget.destroy()
        tk.Label(self.root, text="Username").pack(pady=5)
        self.username_entry = tk.Entry(self.root)
        self.username_entry.pack(pady=5)
        tk.Label(self.root, text="Password").pack(pady=5)
        self.password_entry = tk.Entry(self.root, show="*")
        self.password_entry.pack(pady=5)
        tk.Label(self.root, text="TOTP Code").pack(pady=5)
        self.totp_entry = tk.Entry(self.root)
        self.totp_entry.pack(pady=5)
        tk.Button(self.root, text="Login", command=self.login).pack(pady=5)
        tk.Button(self.root, text="Register", command=self.register).pack(pady=5)

    def show_file_page(self):
        for widget in self.root.winfo_children():
            widget.destroy()
        try:
            self.file_manager = FileManager(self.username, self.session_token, self)
            tk.Label(self.root, text=f"Welcome, {self.username}", font=("Arial", 14)).pack(pady=10)
            tk.Button(self.root, text="Upload File", command=self.upload_file).pack(pady=5)
            tk.Button(self.root, text="Write File", command=self.write_file_gui).pack(pady=5)
            tk.Button(self.root, text="View Files", command=self.show_files).pack(pady=5)
            tk.Button(self.root, text="Logout", command=self.logout).pack(pady=5)
        except ValueError:
            messagebox.showerror("Error", "Session expired. Please log in again.")
            self.show_login_page()

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        totp_code = self.totp_entry.get()
        session_token = self.auth.authenticate_user(username, password, totp_code)
        if session_token:
            self.username = username
            self.session_token = session_token
            self.show_file_page()

    def register(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        self.auth.register_user(username, password, self.show_two_factor_secret)

    def show_two_factor_secret(self, secret):
        for widget in self.root.winfo_children():
            widget.destroy()
        tk.Label(self.root, text="Registration Successful! Your TOTP Secret:").pack(pady=10)
        secret_entry = tk.Entry(self.root, width=40)
        secret_entry.insert(0, secret)
        secret_entry.pack(pady=5)
        tk.Label(self.root, text="Use this in an authenticator app (e.g., Google Authenticator)").pack(pady=5)
        tk.Button(self.root, text="Copy to Clipboard", command=lambda: [self.root.clipboard_clear(), self.root.clipboard_append(secret)]).pack(pady=5)
        tk.Button(self.root, text="Back to Login", command=self.show_login_page).pack(pady=5)

    def logout(self):
        self.username = ""
        self.session_token = ""
        self.show_login_page()
        logging.info("User logged out")

    def upload_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.file_manager.save_file(file_path)

    def write_file_gui(self):
        for widget in self.root.winfo_children():
            widget.destroy()
        tk.Label(self.root, text="Write a New File", font=("Arial", 14)).pack(pady=10)
        
        tk.Label(self.root, text="Filename").pack(pady=5)
        filename_entry = tk.Entry(self.root)
        filename_entry.pack(pady=5)
        
        tk.Label(self.root, text="Content").pack(pady=5)
        content_text = Text(self.root, height=10, width=50)
        content_text.pack(pady=5)
        
        def save_written_file():
            filename = filename_entry.get()
            data = content_text.get("1.0", tk.END).strip()
            if filename and data:
                self.file_manager.write_file(filename, data)
                self.show_file_page()
            else:
                messagebox.showerror("Error", "Filename and content cannot be empty!")
        
        tk.Button(self.root, text="Save", command=save_written_file).pack(pady=5)
        tk.Button(self.root, text="Back", command=self.show_file_page).pack(pady=5)

    def show_files(self):
        for widget in self.root.winfo_children():
            widget.destroy()
        tk.Label(self.root, text=f"Files for {self.username}", font=("Arial", 14)).pack(pady=10)
        files = self.file_manager.get_files()
        if not files:
            tk.Label(self.root, text="No files available").pack(pady=5)
        for file in files:
            frame = tk.Frame(self.root)
            frame.pack(pady=2)
            tk.Label(frame, text=file, width=20).pack(side=tk.LEFT)
            tk.Button(frame, text="Read", command=lambda f=file: self.read_file(f)).pack(side=tk.LEFT, padx=5)
            tk.Button(frame, text="Share", command=lambda f=file: self.share_file(f)).pack(side=tk.LEFT, padx=5)
            tk.Button(frame, text="Delete", command=lambda f=file: self.file_manager.delete_file(f)).pack(side=tk.LEFT, padx=5)
            tk.Button(frame, text="Metadata", command=lambda f=file: self.show_metadata(f)).pack(side=tk.LEFT, padx=5)
        tk.Button(self.root, text="Back", command=self.show_file_page).pack(pady=10)

    def read_file(self, filename):
        try:
            conn = mysql.connector.connect(
                host="localhost",
                user="root",
                password="",  # Your MySQL root password
                database="file_system_db"
            )
            cursor = conn.cursor()
            # Check if the user uploaded the file or has shared access
            cursor.execute('SELECT uploader FROM files WHERE filename=%s', (filename,))
            uploader = cursor.fetchone()
            if not uploader or uploader[0] != self.username:
                # Check if the user has shared access
                cursor.execute('SELECT shared_key FROM shared_files WHERE filename=%s AND shared_with=%s', (filename, self.username))
                shared_key_data = cursor.fetchone()
                if not shared_key_data:
                    messagebox.showerror("Error", "File not found or access denied!")
                    return
                # Use the uploader's key for decryption
                self.file_manager.cipher = Fernet(shared_key_data[0])

            # Proceed with reading
            cursor.execute('SELECT encrypted_data FROM files WHERE filename=%s', (filename,))
            data = cursor.fetchone()
            if not data:
                messagebox.showerror("Error", "File not found or access denied!")
                return

            # Decrypt the file data
            decrypted = self.file_manager.decrypt_file(data[0])
            if not decrypted:
                return  # Decryption failure already logged in decrypt_file

            # Determine file extension
            file_ext = os.path.splitext(filename)[1].lower()
            if not file_ext:
                file_ext = '.bin'

            # Use a temporary file to store decrypted content
            with tempfile.NamedTemporaryFile(delete=False, suffix=file_ext) as temp_file:
                temp_file.write(decrypted)
                temp_file_path = temp_file.name

            # Open the file with the default application based on OS
            system = platform.system()
            if system == "Windows":
                os.startfile(temp_file_path)
            elif system == "Darwin":
                subprocess.run(["open", temp_file_path], check=True)
            elif system == "Linux":
                subprocess.run(["xdg-open", temp_file_path], check=True)
            else:
                messagebox.showwarning(f"Unsupported OS: {system}. File saved as {temp_file_path}")
                logging.info(f"File {filename} decrypted and saved to {temp_file_path}")

            logging.info(f"File {filename} decrypted and opened by {self.username}")

            # Optional cleanup (uncomment to delete after opening)
            # os.unlink(temp_file_path)

        except mysql.connector.Error as err:
            messagebox.showerror("Error", f"Database error: {err}")
            logging.error(f"Read failed for {filename}: {err}")
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Error", f"Failed to open file: {e}")
            logging.error(f"Failed to open {temp_file_path}: {e}")
        except Exception as e:
            messagebox.showerror("Error", f"Unexpected error: {e}")
            logging.error(f"Read failed for {filename}: {e}")
        finally:
            if 'conn' in locals():
                conn.close()

    def share_file(self, filename):
        share_with = simpledialog.askstring("Share", "Enter username to share with:")
        if share_with:
            self.file_manager.share_file(filename, share_with)

    def show_metadata(self, filename):
        metadata = self.file_manager.get_metadata(filename)
        messagebox.showinfo("Metadata", metadata)

if __name__ == "__main__":
    try:
        setup_database()
        root = ThemedTk(theme="breeze")
        app = App(root)
        root.mainloop()
    except Exception as e:
        messagebox.showerror("Startup Error", f"Failed to start application: {e}")
        logging.error(f"Application startup failed: {e}")