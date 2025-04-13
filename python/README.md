# Secure File Management System

A secure file management system with encryption, user authentication, and file sharing capabilities. Built with Python, MySQL, and Tkinter.

## Features

- **Secure User Authentication**
  - Password hashing using PBKDF2HMAC
  - Two-factor authentication (TOTP)
  - Session management
  - Secure login system

- **File Management**
  - File upload and download
  - File encryption using Fernet
  - File sharing between users
  - File metadata tracking
  - Support for various file types (including images)

- **Security Features**
  - End-to-end encryption
  - Malware scanning
  - Input sanitization
  - Secure session handling
  - Activity logging

## Prerequisites

- Python 3.6 or higher
- MySQL Server (XAMPP recommended)
- Required Python packages (install using `pip install -r requirements.txt`):
  ```
  mysql-connector-python
  tkinter
  ttkthemes
  cryptography
  pyotp
  ```

## Installation

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd secure-file-management
   ```

2. Install required packages:
   ```bash
   pip install -r requirements.txt
   ```

3. Set up MySQL:
   - Install XAMPP or MySQL Server
   - Start MySQL service
   - The application will automatically create the required database and tables

## Configuration

1. Database Configuration:
   - Default configuration uses XAMPP MySQL settings
   - Modify `DB_CONFIG` in `o.py` if using different MySQL settings:
     ```python
     DB_CONFIG = {
         "host": "localhost",
         "user": "root",
         "password": "",  # Update if set
         "database": "file_system_db"
     }
     ```

## Usage

1. Start the application:
   ```bash
   python o.py
   ```

2. User Registration:
   - Click "Register"
   - Enter username and password
   - Save the TOTP secret and use it in an authenticator app (e.g., Google Authenticator)

3. User Login:
   - Enter username and password
   - Enter TOTP code from authenticator app

4. File Operations:
   - Upload files using "Upload File"
   - Write new files using "Write File"
   - View files in the file list
   - Share files with other users
   - View file metadata
   - Delete files (own files or shared files)

## Security Features

- **Password Security**
  - Passwords are hashed using PBKDF2HMAC
  - Salt is stored separately for each user
  - Minimum password length requirement

- **File Security**
  - Files are encrypted before storage
  - Each user has a unique encryption key
  - Malware scanning for uploaded files
  - File size limits (10MB)

- **Session Security**
  - Session tokens for authenticated users
  - Secure session management
  - Automatic logout

## File Sharing

- Share files with other users
- Shared files can be viewed by recipients
- Shared files can be removed from recipient's view
- Original file owner maintains control

## Logging

- Security events are logged to `security.log`
- Includes:
  - User authentication attempts
  - File operations
  - Security incidents
  - System errors

## Error Handling

- Comprehensive error handling
- User-friendly error messages
- Detailed logging of errors
- Graceful failure handling

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a new Pull Request

## Acknowledgments

- Built with Python and Tkinter
- Uses MySQL for data storage
- Implements industry-standard security practices 