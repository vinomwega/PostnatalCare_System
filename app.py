from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
import mysql.connector
from functools import wraps
import os

app = Flask(__name__)


app.secret_key = '145944'  # My secret key

# Database configuration
db_config = {
    'host': '127.0.0.1',
    'user': 'root',
    'password': '',
    'database': 'postnatalcare_system'
}

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Routes for registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Prevent admin registration through regular registration
        user_type = request.form['user_type']
        if user_type == 'admin':
            flash('Admin registration not allowed through this form', 'error')
            return redirect(url_for('register'))
            
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        
        # Hash the password
        password_hash = generate_password_hash(password)
        
        try:
            conn = mysql.connector.connect(**db_config)
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO users (username, password_hash, email, user_type)
                VALUES (%s, %s, %s, %s)
            """, (username, password_hash, email, user_type))
            
            conn.commit()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
            
        except mysql.connector.Error as err:
            flash(f'Registration failed: {err}', 'error')
        finally:
            cursor.close()
            conn.close()
            
    return render_template('register.html')

# Route for login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        try:
            conn = mysql.connector.connect(**db_config)
            cursor = conn.cursor(dictionary=True)
            
            cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
            user = cursor.fetchone()
            
            if user and check_password_hash(user['password_hash'], password):
                session['user_id'] = user['id']
                session['user_type'] = user['user_type']
                
                # Redirect to appropriate dashboard
                if user['user_type'] == 'mother':
                    return redirect(url_for('mother_dashboard'))
                elif user['user_type'] == 'chw':
                    return redirect(url_for('chw_dashboard'))
                else:
                    return redirect(url_for('admin_dashboard'))
            
            flash('Invalid username or password', 'error')
            
        except mysql.connector.Error as err:
            flash(f'Login failed: {err}', 'error')
        finally:
            cursor.close()
            conn.close()
            
    return render_template('login.html')

# Dashboard routes
@app.route('/mother/dashboard')
@login_required
def mother_dashboard():
    if session['user_type'] != 'mother':
        return redirect(url_for('login'))
    return render_template('mother_dashboard.html')

@app.route('/chw/dashboard')
@login_required
def chw_dashboard():
    if session['user_type'] != 'chw':
        return redirect(url_for('login'))
    return render_template('chw_dashboard.html')

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if session['user_type'] != 'admin':
        return redirect(url_for('login'))
    return render_template('admin_dashboard.html')

# Logout route
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# Home route
@app.route('/')
def home():
    return redirect(url_for('login'))

# Admin Registration Configuration settings
ADMIN_AUTH_CODE = '145944'  # a secure code

# Check admin authentication
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('user_type') == 'admin':
            flash('Admin access required', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Admin registration route
@app.route('/admin/register', methods=['GET', 'POST'])
@admin_required  # This ensures only logged-in admins can access this route
def admin_register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        user_type = 'admin'
        
        # Hash the password
        password_hash = generate_password_hash(password)
        
        try:
            conn = mysql.connector.connect(**db_config)
            cursor = conn.cursor()
            
            # Check if username already exists
            cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
            if cursor.fetchone():
                flash('Username already exists', 'error')
                return redirect(url_for('admin_register'))
            
            # Insert new admin user
            cursor.execute("""
                INSERT INTO users (username, password_hash, email, user_type)
                VALUES (%s, %s, %s, %s)
            """, (username, password_hash, email, user_type))
            
            conn.commit()
            flash('New admin registered successfully!', 'success')
            return redirect(url_for('admin_dashboard'))
            
        except mysql.connector.Error as err:
            flash(f'Registration failed: {err}', 'error')
        finally:
            cursor.close()
            conn.close()
            
    return render_template('admin_register.html')

if __name__ == '__main__':
    app.run(debug=True)