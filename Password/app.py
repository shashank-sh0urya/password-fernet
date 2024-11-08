from flask import Flask, render_template, request, redirect, url_for, session, flash
from functools import wraps
import os
import json
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import logging
from cryptography.fernet import Fernet

USERS_FILE = 'users.json'
PASSWORDS_FILE = 'passwords.json'
KEY_FILE = 'secret.key'

# Generate and save a key (only run once to generate the key)
# key = Fernet.generate_key()
# with open(KEY_FILE, 'wb') as key_file:
#     key_file.write(key)

# Load encryption key
def load_key():
    return open(KEY_FILE, 'rb').read()

# Initialize Fernet
key = load_key()
cipher_suite = Fernet(key)

# Load users from a JSON file
def load_users():
    if os.path.exists(USERS_FILE) and os.path.getsize(USERS_FILE) > 0:
        with open(USERS_FILE, 'r') as file:
            return json.load(file)
    return {}

# Save users to a JSON file
def save_users(users):
    with open(USERS_FILE, 'w') as file:
        json.dump(users, file, indent=4)

# Load passwords from a JSON file
def load_passwords():
    if os.path.exists(PASSWORDS_FILE) and os.path.getsize(PASSWORDS_FILE) > 0:
        with open(PASSWORDS_FILE, 'r') as file:
            return json.load(file)
    return {}

# Save passwords to a JSON file
def save_passwords(passwords):
    with open(PASSWORDS_FILE, 'w') as file:
        json.dump(passwords, file, indent=4)

# Encrypt a password
def encrypt_password(password):
    return cipher_suite.encrypt(password.encode()).decode()

# Decrypt a password
def decrypt_password(encrypted_password):
    return cipher_suite.decrypt(encrypted_password.encode()).decode()

# Initialize Flask app
app = Flask(__name__)
app.secret_key = 'your_secret_key_here'

# Setup logging for audit logs
logging.basicConfig(filename="audit.log", level=logging.INFO, format="%(asctime)s - %(message)s")

# Role-based access control decorator
def role_required(required_roles):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if 'role' not in session or session['role'] not in required_roles:
                flash("Access Denied: Insufficient permissions.")
                return redirect(url_for('login'))
            return f(*args, **kwargs)
        return wrapped
    return decorator

@app.route('/')
def home():
    return redirect(url_for('login'))

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        users = load_users()
        if username in users and users[username]['password'] == password:
            session['username'] = username
            session['role'] = users[username]['role']
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password. Please try again.', 'danger')
            return redirect(url_for('login'))
    
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        flash('Please login first.')
        return redirect(url_for('login'))
    
    return render_template('dashboard.html', username=session['username'], role=session['role'])

@app.route('/create_user', methods=['GET', 'POST'])
@role_required(['admin'])
def create_user():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']

        users = load_users()
        if username in users:
            flash('User already exists.', 'danger')
        else:
            users[username] = {'password': password, 'role': role}
            save_users(users)
            flash('User created successfully!', 'success')
        
        return redirect(url_for('admin_dashboard'))

    return render_template('create_user.html')

@app.route('/edit_user', methods=['GET', 'POST'])
@role_required(['admin'])
def edit_user():
    if request.method == 'POST':
        username = request.form['username']
        users = load_users()
        if username in users:
            users[username]['role'] = request.form['role']
            save_users(users)
            flash(f'User {username} updated successfully!', 'success')
        else:
            flash(f'User {username} does not exist.', 'danger')
        return redirect(url_for('admin_dashboard'))
    return render_template('edit_user.html')

@app.route('/delete_user', methods=['GET', 'POST'])
@role_required(['admin'])
def delete_user():
    if request.method == 'POST':
        username = request.form['username']
        users = load_users()
        if username in users:
            del users[username]
            save_users(users)
            flash(f'User {username} deleted successfully!', 'success')
        else:
            flash(f'User {username} does not exist.', 'danger')
        return redirect(url_for('admin_dashboard'))
    return render_template('delete_user.html')

@app.route('/view_users')
@role_required(['admin'])
def view_users():
    users = load_users()
    return render_template('view_users.html', users=users)

@app.route('/add_password', methods=['GET', 'POST'])
@role_required(['admin', 'manager'])
def add_password():
    if request.method == 'POST':
        service = request.form['service']
        username = request.form['username']
        password = request.form['password']

        encrypted_password = encrypt_password(password)
        passwords = load_passwords()
        passwords[service] = {'username': username, 'password': encrypted_password}
        save_passwords(passwords)

        flash(f'Password for {service} added successfully!', 'success')
        return redirect(url_for('admin_dashboard'))

    return render_template('add_password.html')

@app.route('/edit_password', methods=['GET', 'POST'])
@role_required(['admin', 'manager'])
def edit_password():
    if request.method == 'POST':
        service = request.form['service']
        passwords = load_passwords()
        if service in passwords:
            passwords[service]['username'] = request.form['username']
            passwords[service]['password'] = encrypt_password(request.form['password'])
            save_passwords(passwords)
            flash(f'Password for {service} updated successfully!', 'success')
        else:
            flash(f'Service {service} does not exist.', 'danger')
        return redirect(url_for('admin_dashboard'))
    return render_template('edit_password.html')

@app.route('/delete_password', methods=['GET', 'POST'])
@role_required(['admin', 'manager'])
def delete_password():
    if request.method == 'POST':
        service = request.form['service']
        passwords = load_passwords()
        if service in passwords:
            del passwords[service]
            save_passwords(passwords)
            flash(f'Password for {service} deleted successfully!', 'success')
        else:
            flash(f'Service {service} does not exist.', 'danger')
        return redirect(url_for('admin_dashboard'))
    return render_template('delete_password.html')

@app.route('/view_all_passwords')
@role_required(['admin', 'manager'])
def view_all_passwords():
    passwords = load_passwords()
    # If the user is a manager, do not decrypt the passwords
    if session.get('role') == 'manager':
        # Pass passwords as-is (encrypted)
        return render_template('view_all_passwords.html', passwords=passwords, show_encrypted=True)
    else:
        # For admin, decrypt the passwords for display
        for service, details in passwords.items():
            details['password'] = decrypt_password(details['password'])
        return render_template('view_all_passwords.html', passwords=passwords, show_encrypted=False)


@app.route('/view_audit_logs')
@role_required(['admin'])
def view_audit_logs():
    # Replace with logic to fetch audit logs
    logs = []  # Example placeholder for log data
    return render_template('view_audit_logs.html', logs=logs)

@app.route('/generate_report', methods=['GET'])
@role_required(['admin'])
def generate_report():
    report = "This is a placeholder for the compliance report."
    return render_template('generate_report.html', report=report)

@app.route('/configure_mfa')
@role_required(['admin'])
def configure_mfa():
    return render_template('configure_mfa.html')

@app.route('/configure_ldap')
@role_required(['admin'])
def configure_ldap():
    return render_template('configure_ldap.html')

@app.route('/admin')
@role_required(['admin'])
def admin_dashboard():
    return render_template('admin.html')


# user dashboard
@app.route('/view_personal_passwords')
@role_required(['user'])
def view_personal_passwords():
    # Replace with logic to fetch passwords related to the logged-in user
    username = session['username']
    passwords = load_passwords()
    user_passwords = {service: details for service, details in passwords.items() if details['username'] == username}
    return render_template('view_personal_passwords.html', passwords=user_passwords)

@app.route('/update_personal_info', methods=['GET', 'POST'])
@role_required(['user'])
def update_personal_info():
    if request.method == 'POST':
        # Add logic to update personal information
        flash('Your information has been updated successfully.', 'success')
        return redirect(url_for('dashboard'))
    return render_template('update_personal_info.html')

# Logout route
@app.route('/logout')
def logout():
    session.clear()  # Clear all session data to log the user out
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
