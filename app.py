from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
import mysql.connector
from functools import wraps
import os
import pickle #for loading the model
import pandas as pd #for data manipulation
from werkzeug.utils import secure_filename #for secure file uploads
from io import BytesIO #for pdf generation
from reportlab.pdfgen import canvas #for pdf generation
from datetime import datetime #for date and time
from xlsxwriter import Workbook #for excel generation



app = Flask(__name__)


app.secret_key = '145944'  # My secret key

# Configure Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'  # Replace with your SMTP server
app.config['MAIL_PORT'] = 587  # Use 465 for SSL, 587 for TLS
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'omwegavincent2@gmail.com'  # Replace with your email
app.config['MAIL_PASSWORD'] = 'dtzs okyy heqc bpvf '           # Replace with your password
app.config['MAIL_DEFAULT_SENDER'] = 'omwegavincent2@gmail.com'  # Optional: set a default sender

mail = Mail(app)

# Database configuration
db_config = {
    'host': '127.0.0.1',
    'user': 'root',
    'password': '',
    'database': 'postnatalcare_system'
}

def get_db_connection():
    return mysql.connector.connect(**db_config)

# Load the model using pickle
with open(r'F:\IS project 2\PostnatalCare_System\models\RF_model.pkl', 'rb') as f:
    model = pickle.load(f)

# Configuration for file uploads
UPLOAD_FOLDER = 'static/uploads/profile_pictures'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def save_profile_picture(file, user_id, user_type):
    if file and allowed_file(file.filename):
        filename = secure_filename(f"{user_type}_{user_id}_{file.filename}")
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        connection = get_db_connection()
        cursor = connection.cursor()
        try:
            cursor.execute("""
                INSERT INTO profile_pictures (user_id, user_type, filename)
                VALUES (%s, %s, %s)
            """, (user_id, user_type, filename))
            connection.commit()
            return filename
        except mysql.connector.Error as err:
            print(f"Error: {err}")
            return None
        finally:
            cursor.close()
            connection.close()
    return None

@app.route('/predict', methods=['POST'])
def predict():
    # Retrieve form data (symptoms and user's name) from the request
    age = request.form.get('Age', type=int)
    systolic_bp = request.form.get('SystolicBP', type=int)
    diastolic_bp = request.form.get('DiastolicBP', type=int)
    bs = request.form.get('BS', type=float)
    body_temp = request.form.get('BodyTemp', type=float)
    heart_rate = request.form.get('HeartRate', type=int)
    
    # Assuming 'name' is passed from the form or stored in the session
    user_name = request.form.get('name') or session.get('username', 'the patient')

    # Create a DataFrame with the input data
    input_data = pd.DataFrame([[age, systolic_bp, diastolic_bp, bs, body_temp, heart_rate]],
                              columns=['Age', 'SystolicBP', 'DiastolicBP', 'BS', 'BodyTemp', 'HeartRate'])

    # Make a prediction
    prediction = model.predict(input_data)

    # Translate the prediction to a risk level
    risk_mapping = {0: 'High Risk', 1: 'Low Risk', 2: 'Medium Risk'}
    risk_level = risk_mapping[int(prediction[0])]

    # Send an email if the risk level is High Risk
    if risk_level == 'High Risk':
        try:
            msg = Message("High-Risk Postnatal Health Alert",
                          recipients=["vincent.gitenya@strathmore.edu"])
            msg.body = f"Alert: {user_name} has been classified as High Risk.\n\nDetails:\n" \
                       f"Age: {age}\nSystolic BP: {systolic_bp}\nDiastolic BP: {diastolic_bp}\n" \
                       f"Blood Sugar: {bs}\nBody Temperature: {body_temp}\nHeart Rate: {heart_rate}\n\n" \
                       f"Risk Level: {risk_level}"
            mail.send(msg)
            print("Email sent successfully.")
        except Exception as e:
            print("Error sending email:", e)

    # Pass the result to the 'mother_dashboard.html' template
    return render_template('Mother/mother_dashboard.html', risk_level=risk_level)

# Landing page route (this should be the first route)
@app.route('/')
def index():
    return render_template('index.html')

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in first.', 'error')
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
#mother dashboard
@app.route('/mother/dashboard')
@login_required
def mother_dashboard():
    if session['user_type'] != 'mother':
        return redirect(url_for('login'))
    return render_template('Mother/mother_dashboard.html')

#chw dashboard
@app.route('/chw/dashboard')
@login_required
def chw_dashboard():
    if session.get('user_type') != 'chw':
        flash('Unauthorized access', 'error')
        return redirect(url_for('login'))
    
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)
    
    try:
        # Get assigned mothers
        cursor.execute("""
            SELECT u.* FROM users u
            JOIN mother_chw mc ON u.id = mc.mother_id
            WHERE mc.chw_id = %s AND u.user_type = 'mother'
        """, (session['user_id'],))
        
        assigned_mothers = cursor.fetchall()
        
        return render_template('CHW/chw_dashboard.html', 
                             username=session.get('username'),
                             assigned_mothers=assigned_mothers)

    except mysql.connector.Error as err:
        print(f"Database Error: {err}")
        flash('Error fetching dashboard data', 'error')
        return render_template('CHW/chw_dashboard.html', 
                             username=session.get('username'),
                             assigned_mothers=[])

    finally:
        cursor.close()
        connection.close()

#chw meal plan
@app.route('/chw/chw_meal_plan')
@login_required
def chw_meal_plan():
    if session.get('user_type') != 'chw':
        flash('Unauthorized access', 'error')
        return redirect(url_for('login'))
    
    connection = None
    cursor = None
    try:
        connection = mysql.connector.connect(
            host='localhost',
            user='root',
            password='',
            database='postnatalcare_system'
        )
        cursor = connection.cursor(dictionary=True)

        # Debug print
        print(f"CHW ID from session: {session.get('user_id')}")

        # First, check if the CHW has any assigned mothers
        cursor.execute("""
            SELECT COUNT(*) as mother_count
            FROM mother_chw
            WHERE chw_id = %s
        """, (session['user_id'],))
        
        mother_count = cursor.fetchone()['mother_count']
        print(f"Assigned mothers count: {mother_count}")

        if mother_count == 0:
            flash('No mothers assigned to you yet.', 'info')
            return render_template('CHW/chw_meal_plan.html', 
                                 meal_plans=[],
                                 mothers=[])

        # Get meal plans for assigned mothers
        cursor.execute("""
            SELECT 
                mp.id,
                mp.meal_type,
                mp.description,
                mp.start_date,
                mp.end_date,
                u.username as mother_name,
                u.id as mother_id
            FROM users u
            JOIN mother_chw mc ON u.id = mc.mother_id
            LEFT JOIN meal_plans mp ON u.id = mp.mother_id
            WHERE mc.chw_id = %s AND u.user_type = 'mother'
            ORDER BY mp.created_at DESC
        """, (session['user_id'],))
        
        meal_plans = cursor.fetchall()
        print(f"Fetched meal plans: {meal_plans}")

        # Get list of mothers for the dropdown
        cursor.execute("""
            SELECT u.id, u.username 
            FROM users u
            JOIN mother_chw mc ON u.id = mc.mother_id
            WHERE mc.chw_id = %s AND u.user_type = 'mother'
        """, (session['user_id'],))
        
        mothers = cursor.fetchall()
        print(f"Fetched mothers: {mothers}")
        
        return render_template('CHW/chw_meal_plan.html', 
                             meal_plans=meal_plans,
                             mothers=mothers)

    except mysql.connector.Error as err:
        print(f"Database Error: {err}")
        flash(f'Database error: {str(err)}', 'error')
        return render_template('CHW/meal_plan.html', 
                             meal_plans=[],
                             mothers=[])

    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()

#chw workout plan
@app.route('/chw/chw_workout_plan')
@login_required
def chw_workout_plan():
    if session.get('user_type') != 'chw':
        flash('Unauthorized access', 'error')
        return redirect(url_for('login'))
    
    
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)
    
    try:
        # Get workout plans for assigned mothers
        cursor.execute("""
            SELECT wp.*, u.username as mother_name 
            FROM workout_plans wp
            JOIN users u ON wp.mother_id = u.id
            JOIN mother_chw mc ON u.id = mc.mother_id
            WHERE mc.chw_id = %s
        """, (session['user_id'],))
        
        workout_plans = cursor.fetchall()
        
        return render_template('CHW/chw_workout_plan.html', 
                             workout_plans=workout_plans)

    except mysql.connector.Error as err:
        print(f"Database Error: {err}")
        flash('Error fetching workout plans', 'error')
        return render_template('CHW/chw_workout_plan.html', 
                             workout_plans=[])

    finally:
        cursor.close()
        connection.close()

#add workout plan
@app.route('/chw/add_workout_plan', methods=['POST'])
@login_required
def add_workout_plan():
    if session.get('user_type') != 'chw':
        flash('Unauthorized access', 'error')
        return redirect(url_for('login'))
    
    connection = None
    cursor = None
    try:
        mother_id = request.form.get('mother_id')
        exercise_type = request.form.get('exercise_type')
        duration = request.form.get('duration')
        frequency = request.form.get('frequency')
        start_date = request.form.get('start_date')
        end_date = request.form.get('end_date')

        connection = mysql.connector.connect(
            host='localhost',
            user='root',
            password='',
            database='postnatalcare_system'
        )
        cursor = connection.cursor(dictionary=True)

        cursor.execute("""
            INSERT INTO workout_plans 
            (mother_id, exercise_type, duration, frequency, start_date, end_date)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (mother_id, exercise_type, duration, frequency, start_date, end_date))

        connection.commit()
        flash('Workout plan added successfully!', 'success')

    except mysql.connector.Error as err:
        print(f"Database Error: {err}")
        flash('Error adding workout plan', 'error')

    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()

    return redirect(url_for('chw_workout_plan'))

#chw visits
@app.route('/chw/chw_visits')
@login_required

def chw_visits():
    if session.get('user_type') != 'chw':
        flash('Unauthorized access', 'error')
        return redirect(url_for('login'))
    
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)
    
    try:
        # Get visits for assigned mothers
        cursor.execute("""
            SELECT v.*, u.username as mother_name 
            FROM visits v
            JOIN users u ON v.mother_id = u.id
            JOIN mother_chw mc ON u.id = mc.mother_id
            WHERE mc.chw_id = %s
            ORDER BY v.visit_date DESC
        """, (session['user_id'],))
        
        visits = cursor.fetchall()
        
        return render_template('CHW/chw_visits.html', 
                             visits=visits)

    except mysql.connector.Error as err:
        print(f"Database Error: {err}")
        flash('Error fetching visits', 'error')
        return render_template('CHW/chw_visits.html', 
                             visits=[])

    finally:
        cursor.close()
        connection.close()

# add visits
@app.route('/chw/add_visit', methods=['POST'])
@login_required
def add_visit():
    if session.get('user_type') != 'chw':
        flash('Unauthorized access', 'error')
        return redirect(url_for('login'))
    
    connection = None
    cursor = None
    try:
        mother_id = request.form.get('mother_id')
        visit_date = request.form.get('visit_date')
        visit_time = request.form.get('visit_time')
        visit_type = request.form.get('visit_type')
        notes = request.form.get('notes')
        status = 'Scheduled'  # Default status for new visits

        connection = mysql.connector.connect(
            host='localhost',
            user='root',
            password='',
            database='postnatalcare_system'
        )
        cursor = connection.cursor(dictionary=True)

        cursor.execute("""
            INSERT INTO visits 
            (mother_id, chw_id, visit_date, visit_time, visit_type, notes, status)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (mother_id, session['user_id'], visit_date, visit_time, 
              visit_type, notes, status))

        connection.commit()
        flash('Visit scheduled successfully!', 'success')

    except mysql.connector.Error as err:
        print(f"Database Error: {err}")
        flash('Error scheduling visit', 'error')

    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()

    return redirect(url_for('chw_visits'))

#admin dashboard
@app.route('/admin/admin_dashboard')
@login_required
def admin_dashboard():
    if session['user_type'] != 'admin':
        return redirect(url_for('login'))
    
    connection = None
    cursor = None
    try:
        connection = mysql.connector.connect(
            host='localhost',
            user='root',
            password='',
            database='postnatalcare_system'
        )
        cursor = connection.cursor(dictionary=True)

        # Get user counts
        cursor.execute("""
            SELECT 
                SUM(CASE WHEN user_type = 'mother' THEN 1 ELSE 0 END) as mother_count,
                SUM(CASE WHEN user_type = 'chw' THEN 1 ELSE 0 END) as chw_count,
                COUNT(*) as total_users
            FROM users
        """)
        stats = cursor.fetchone()

        return render_template('Admin/admin_dashboard.html', stats=stats)

    except mysql.connector.Error as err:
        print(f"Database Error: {err}")
        flash('Error loading dashboard data', 'error')
        return render_template('Admin/admin_dashboard.html', 
                             stats={'mother_count': 0, 'chw_count': 0, 'total_users': 0})

    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()

# Logout route
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# # Home route
# @app.route('/')
# def home():
#     return redirect(url_for('login'))



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
            
    return render_template('Admin/admin_register.html')

#mother dashboard
#mother meal plan
@app.route('/mother/meal_plan')
@login_required
def meal_plan():
    return render_template('Mother/meal_plan.html')

#mother workout plan
@app.route('/mother/workout_plan')
@login_required
def workout_plan():
    return render_template('Mother/workout_plan.html')

#mother visits
@app.route('/mother/visits')
@login_required
def visits():
    connection = None
    cursor = None
    try:
        # Get the mother's ID from session
        mother_id = session.get('user_id')
        
        connection = mysql.connector.connect(
            host='localhost',
            user='root',
            password='',
            database='postnatalcare_system'
        )
        cursor = connection.cursor(dictionary=True)

        # First, get the CHW information from the users table
        cursor.execute("""
            SELECT id, username as name, email, user_type 
            FROM users 
            WHERE user_type = 'chw'
            LIMIT 1
        """)
        chw = cursor.fetchone()

        # Initialize visits as an empty list
        visits = []
        
        # Only fetch visits if we have a CHW
        if chw:
            cursor.execute("""
                SELECT * FROM visits 
                WHERE mother_id = %s 
                ORDER BY visit_date DESC, visit_time DESC
            """, (mother_id,))
            visits = cursor.fetchall()

        return render_template('Mother/visits.html', 
                             chw=chw, 
                             visits=visits)

    except mysql.connector.Error as err:
        print(f"Database Error: {err}")
        flash('An error occurred while fetching visits data.', 'error')
        return render_template('Mother/visits.html', chw=None, visits=[])

    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()

#mother my chw
@app.route('/mother/my_chw')
@login_required
def my_chw():
    connection = None
    cursor = None
    try:
        connection = mysql.connector.connect(
            host='localhost',
            user='root',
            password='',
            database='postnatalcare_system'
        )
        cursor = connection.cursor(dictionary=True)

        # Get CHW information from users table
        cursor.execute("""
            SELECT id, username as name, email, user_type 
            FROM users 
            WHERE user_type = 'chw'
            LIMIT 1
        """)
        chw = cursor.fetchone()

        # Get any messages (if they exist)
        messages = []
        if chw:
            cursor.execute("""
                SELECT * FROM messages 
                WHERE (sender_id = %s AND receiver_id = %s)
                   OR (sender_id = %s AND receiver_id = %s)
                ORDER BY created_at DESC
            """, (session['user_id'], chw['id'], chw['id'], session['user_id']))
            messages = cursor.fetchall()

        return render_template('Mother/my_chw.html', 
                             chw=chw, 
                             messages=messages)

    except mysql.connector.Error as err:
        print(f"Database Error: {err}")
        flash('An error occurred while fetching CHW data.', 'error')
        return render_template('Mother/my_chw.html', chw=None, messages=[])

    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()

#mother profile
@app.route('/mother/profile')
@login_required
def profile():
    connection = None
    cursor = None
    try:
        connection = mysql.connector.connect(
            host='localhost',
            user='root',
            password='',
            database='postnatalcare_system'
        )
        cursor = connection.cursor(dictionary=True)

        # Get user information from users table
        cursor.execute("""
            SELECT id, username, email, user_type, created_at 
            FROM users 
            WHERE id = %s
        """, (session['user_id'],))
        
        user = cursor.fetchone()
        
        return render_template('Mother/profile.html', user=user)

    except mysql.connector.Error as err:
        print(f"Database Error: {err}")
        flash('An error occurred while fetching profile data.', 'error')
        return render_template('Mother/profile.html', user=None)

    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()

#update profile
@app.route('/update_profile', methods=['GET', 'POST'])
@login_required
def update_profile():
    if request.method == 'POST':
        connection = None
        cursor = None
        try:
            connection = mysql.connector.connect(
                host='localhost',
                user='root',
                password='',
                database='postnatalcare_system'
            )
            cursor = connection.cursor()

            # Handle profile picture upload
            if 'profile_picture' in request.files:
                file = request.files['profile_picture']
                if file and allowed_file(file.filename):
                    filename = secure_filename(f"user_{session['user_id']}_{file.filename}")
                    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    
                    # Create directory if it doesn't exist
                    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
                    
                    file.save(filepath)
                    
                    # Update profile picture path in database if you have a column for it
                    # cursor.execute("UPDATE users SET profile_picture = %s WHERE id = %s", 
                    #               (filename, session['user_id']))

            # Handle other form data
            if 'username' in request.form:
                username = request.form['username']
                email = request.form['email']
                
                cursor.execute("""
                    UPDATE users 
                    SET username = %s, email = %s 
                    WHERE id = %s
                """, (username, email, session['user_id']))

            connection.commit()
            flash('Profile updated successfully!', 'success')

        except mysql.connector.Error as err:
            print(f"Database Error: {err}")
            flash('An error occurred while updating profile.', 'error')

        finally:
            if cursor:
                cursor.close()
            if connection and connection.is_connected():
                connection.close()

        return redirect(url_for('profile'))

    return redirect(url_for('profile'))

#update medical info
@app.route('/update_medical_info', methods=['POST'])
@login_required
def update_medical_info():
    # Handle medical info update logic
    return redirect(url_for('profile'))

#change password
@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    connection = None
    cursor = None
    try:
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        
        # Validate password requirements
        if len(new_password) < 8:
            flash('Password must be at least 8 characters long', 'error')
            return redirect(url_for('profile'))
            
        if new_password != confirm_password:
            flash('New passwords do not match', 'error')
            return redirect(url_for('profile'))
            
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        
        # Get user's current password
        table_name = 'mothers' if session['user_type'] == 'mother' else 'chw'
        cursor.execute(f"SELECT password FROM {table_name} WHERE id = %s", 
                      (session['user_id'],))
        user = cursor.fetchone()
        
        if not check_password_hash(user['password'], current_password):
            flash('Current password is incorrect', 'error')
            return redirect(url_for('profile'))
            
        # Update password
        hashed_password = generate_password_hash(new_password)
        cursor.execute(f"UPDATE {table_name} SET password = %s WHERE id = %s",
                      (hashed_password, session['user_id']))
        
        connection.commit()
        flash('Password updated successfully!', 'success')
        
    except mysql.connector.Error as err:
        print(f"Error: {err}")
        flash('An error occurred. Please try again.', 'error')
        
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()
            
    return redirect(url_for('profile'))

#send message
@app.route('/send_message', methods=['POST'])
@login_required
def send_message():
    connection = None
    cursor = None
    try:
        message_text = request.form['message']
        receiver_id = request.form['receiver_id']
        sender_id = session['user_id']
        sender_type = session['user_type']

        connection = get_db_connection()
        cursor = connection.cursor()
        
        cursor.execute("""
            INSERT INTO messages (sender_id, receiver_id, sender_type, message_text)
            VALUES (%s, %s, %s, %s)
        """, (sender_id, receiver_id, sender_type, message_text))
        
        connection.commit()
        flash('Message sent successfully!', 'success')
        
    except mysql.connector.Error as err:
        print(f"Error: {err}")
        flash('Failed to send message. Please try again.', 'error')
        
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()
            
    return redirect(url_for('my_chw'))

#flash errors
def flash_errors(form):
    """Flash all errors from a form."""
    for field, errors in form.errors.items():
        for error in errors:
            flash(f'{getattr(form, field).label.text}: {error}', 'error')

#admin management dashboard
# User Management Routes
@app.route('/admin/manage_users')
@login_required
def manage_users():
    if session['user_type'] != 'admin':
        return redirect(url_for('login'))
    
    connection = None
    cursor = None
    try:
        connection = mysql.connector.connect(
            host='localhost',
            user='root',
            password='',
            database='postnatalcare_system'
        )
        cursor = connection.cursor(dictionary=True)
        
        # Fetch all users
        cursor.execute("""
            SELECT u.id, u.username, u.email, u.user_type, u.created_at,
                   COUNT(DISTINCT mc_mother.id) as assigned_mothers,
                   COUNT(DISTINCT mc_chw.id) as assigned_chws
            FROM users u
            LEFT JOIN mother_chw mc_mother ON u.id = mc_mother.mother_id
            LEFT JOIN mother_chw mc_chw ON u.id = mc_chw.chw_id
            GROUP BY u.id
            ORDER BY u.created_at DESC
        """)
        users = cursor.fetchall()
        
        return render_template('Admin/manage_users.html', users=users)

    except mysql.connector.Error as err:
        print(f"Database Error: {err}")
        flash('Error fetching users', 'error')
        return render_template('Admin/manage_users.html', users=[])

    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()

@app.route('/admin/user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if session['user_type'] != 'admin':
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        connection = None
        cursor = None
        try:
            connection = mysql.connector.connect(
                host='localhost',
                user='root',
                password='',
                database='postnatalcare_system'
            )
            cursor = connection.cursor(dictionary=True)
            
            # Update user information
            cursor.execute("""
                UPDATE users 
                SET username = %s, email = %s, user_type = %s
                WHERE id = %s
            """, (
                request.form['username'],
                request.form['email'],
                request.form['user_type'],
                user_id
            ))
            
            connection.commit()
            flash('User updated successfully', 'success')
            
        except mysql.connector.Error as err:
            print(f"Database Error: {err}")
            flash('Error updating user', 'error')
            
        finally:
            if cursor:
                cursor.close()
            if connection and connection.is_connected():
                connection.close()
                
        return redirect(url_for('manage_users'))
    
    # GET request - show edit form
    connection = None
    cursor = None
    try:
        connection = mysql.connector.connect(
            host='localhost',
            user='root',
            password='your_password',
            database='postnatalcare_system'
        )
        cursor = connection.cursor(dictionary=True)
        
        cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()
        
        if user:
            return render_template('Admin/edit_user.html', user=user)
        else:
            flash('User not found', 'error')
            return redirect(url_for('manage_users'))
            
    except mysql.connector.Error as err:
        print(f"Database Error: {err}")
        flash('Error fetching user details', 'error')
        return redirect(url_for('manage_users'))
        
    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()

# Reports Routes
@app.route('/admin/reports')
@login_required
def reports():
    if session['user_type'] != 'admin':
        return redirect(url_for('login'))
    
    connection = None
    cursor = None
    try:
        connection = mysql.connector.connect(
            host='localhost',
            user='root',
            password='',
            database='postnatalcare_system'
        )
        cursor = connection.cursor(dictionary=True)
        
        # Get user registration statistics
        cursor.execute("""
            SELECT 
                DATE_FORMAT(created_at, '%Y-%m') as month,
                COUNT(*) as total,
                SUM(CASE WHEN user_type = 'mother' THEN 1 ELSE 0 END) as mothers,
                SUM(CASE WHEN user_type = 'chw' THEN 1 ELSE 0 END) as chws
            FROM users
            WHERE created_at >= DATE_SUB(NOW(), INTERVAL 6 MONTH)
            GROUP BY DATE_FORMAT(created_at, '%Y-%m')
            ORDER BY month
        """)
        registration_stats = cursor.fetchall()
        
        # Get visit statistics
        cursor.execute("""
            SELECT 
                visit_type,
                COUNT(*) as total,
                COUNT(DISTINCT mother_id) as unique_mothers
            FROM visits
            GROUP BY visit_type
        """)
        visit_stats = cursor.fetchall()

        # Get exported files
        files = []
        for filename in os.listdir(EXPORT_DIR):
            file_path = os.path.join(EXPORT_DIR, filename)
            files.append({
                'name': filename,
                'date': datetime.fromtimestamp(os.path.getctime(file_path)).strftime('%Y-%m-%d %H:%M:%S'),
                'size': f"{os.path.getsize(file_path) / 1024:.1f} KB"
            })
        
        return render_template('Admin/reports.html', 
                             registration_stats=registration_stats,
                             visit_stats=visit_stats,
                             files=files)
                             
    except mysql.connector.Error as err:
        print(f"Database Error: {err}")
        flash('Error generating reports', 'error')
        return render_template('Admin/reports.html', 
                             registration_stats=[],
                             visit_stats=[],
                             files=[])
        
    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()

#export reports routes
#export excel
# Create a constant for the export directory
EXPORT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'exports')

# Create the directory if it doesn't exist
os.makedirs(EXPORT_DIR, exist_ok=True)

@app.route('/admin/export/excel')
@login_required
def export_excel():
    if session['user_type'] != 'admin':
        return redirect(url_for('login'))
    
    try:
        connection = mysql.connector.connect(
            host='localhost',
            user='root',
            password='',
            database='postnatalcare_system'
        )
        
        # Get user data
        df_users = pd.read_sql("""
            SELECT username, email, user_type, created_at
            FROM users
            ORDER BY created_at DESC
        """, connection)
        
        # Generate filename with timestamp
        filename = f'maternal_care_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.xlsx'
        file_path = os.path.join(EXPORT_DIR, filename)
        
        print(f"Saving Excel file to: {file_path}")  # Debug print
        
        # Save to server
        df_users.to_excel(file_path, index=False)
        
        # Send file to user
        return send_file(
            file_path,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            as_attachment=True,
            download_name=filename
        )
        
    except Exception as e:
        print(f"Export Error: {e}")  # Debug print
        flash('Error exporting data', 'error')
        return redirect(url_for('reports'))

#export pdf
@app.route('/admin/export/pdf')
@login_required
def export_pdf():
    if session['user_type'] != 'admin':
        return redirect(url_for('login'))
    
    try:
        # Generate filename with timestamp
        filename = f'maternal_care_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf'
        file_path = os.path.join(EXPORT_DIR, filename)
        
        print(f"Saving PDF file to: {file_path}")  # Debug print
        
        # Create PDF
        p = canvas.Canvas(file_path)
        
        # Add content to PDF
        p.drawString(100, 750, "Maternal Care System Report")
        p.drawString(100, 700, f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Add statistics
        connection = mysql.connector.connect(
            host='localhost',
            user='root',
            password='',
            database='postnatalcare_system'
        )
        cursor = connection.cursor(dictionary=True)
        
        cursor.execute("""
            SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN user_type = 'mother' THEN 1 ELSE 0 END) as mothers,
                SUM(CASE WHEN user_type = 'chw' THEN 1 ELSE 0 END) as chws
            FROM users
        """)
        stats = cursor.fetchone()
        
        p.drawString(100, 650, f"Total Users: {stats['total']}")
        p.drawString(100, 630, f"Total Mothers: {stats['mothers']}")
        p.drawString(100, 610, f"Total CHWs: {stats['chws']}")
        
        p.save()
        
        # Send file to user
        return send_file(
            file_path,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=filename
        )
        
    except Exception as e:
        print(f"Export Error: {e}")  # Debug print
        flash('Error exporting data', 'error')
        return redirect(url_for('reports'))

# Optional: Add a route to view all exports
@app.route('/admin/exports')
@login_required
def view_exports():
    if session['user_type'] != 'admin':
        return redirect(url_for('login'))
        
    files = []
    for filename in os.listdir(EXPORT_DIR):
        file_path = os.path.join(EXPORT_DIR, filename)
        files.append({
            'name': filename,
            'date': datetime.fromtimestamp(os.path.getctime(file_path)).strftime('%Y-%m-%d %H:%M:%S'),
            'size': f"{os.path.getsize(file_path) / 1024:.1f} KB"
        })
    
    return render_template('Admin/exports.html', files=files)

if __name__ == '__main__':
    app.run(debug=True)