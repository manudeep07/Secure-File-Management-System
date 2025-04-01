import os
import hashlib
import re
import secrets
from cryptography.fernet import Fernet
import pyotp
from tkinter import messagebox
import logging
from database import get_db_connection  # Dependency on database module

# Logging is already set up in database.py, so we just use it
logging.getLogger(__name__)

def sanitize_input(value):
    """Sanitize input to prevent injection attacks."""
    return re.sub(r'[^a-zA-Z0-9_.-]', '', value)[:50]

def scan_for_malware(filepath=None, data=None):
    """Scan for malware using ClamAV or hash-based fallback."""
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
class Authentication:
    def hash_password(self, password, salt=None):
        """Hash a password with an optional salt."""
        if not salt:
            salt = secrets.token_hex(16)
        return hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000).hex(), salt
