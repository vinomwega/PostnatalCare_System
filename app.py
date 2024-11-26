from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_file, send_from_directory
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
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle



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
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # SQL query to insert the data
        insert_query = """
        INSERT INTO risk_assessments 
            (mother_id, age, systolic_bp, diastolic_bp, blood_sugar, 
             body_temp, heart_rate, risk_level)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """
        cursor.execute(insert_query, (session['user_id'], age, systolic_bp, diastolic_bp, bs, body_temp, heart_rate, risk_level))

        # Commit the transaction
        conn.commit()

        # Close the connection
        cursor.close()
        conn.close()

        print("Data inserted successfully into the database.")

    except mysql.connector.Error as err:
        print("Error: ", err)
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
@app.route('/mother/dashboard', methods=['GET', 'POST'])
@login_required
def mother_dashboard():
    if session.get('user_type') != 'mother':
        flash('Unauthorized access', 'error')
        return redirect(url_for('login'))
    
    connection = None
    cursor = None
    try:
        mother_id = session['user_id']
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)

        # Initialize variables with default values
        next_visit = None
        chw = None

        # Fetch mother details
        cursor.execute("""
            SELECT username, email 
            FROM users 
            WHERE id = %s
        """, (session['user_id'],))
        mother_details = cursor.fetchone()

        # First, check if mother has an assigned CHW
        cursor.execute("""
            SELECT 
                u.id as chw_id,
                u.username as chw_name,
                u.email as chw_email,
                u.available_hours,
                mc.created_at as assignment_date
            FROM mother_chw mc
            JOIN users u ON mc.chw_id = u.id
            WHERE mc.mother_id = %s 
            AND u.user_type = 'chw'
        """, (mother_id,))
        chw = cursor.fetchone()

        # Only fetch visits if there's an assigned CHW
        if chw:
            cursor.execute("""
                SELECT 
                    v.*,
                    DATE_FORMAT(v.visit_date, '%d-%m-%Y') as formatted_date,
                    TIME_FORMAT(v.visit_time, '%H:%i') as formatted_time
                FROM visits v
                WHERE v.mother_id = %s 
                    AND v.visit_date >= CURDATE()
                    AND v.chw_id = %s
                ORDER BY v.visit_date ASC, v.visit_time ASC
                LIMIT 1
            """, (mother_id, chw['chw_id']))
            next_visit = cursor.fetchone()

        # Render template with the fetched data
        return render_template('Mother/mother_dashboard.html',
                             mother_name=mother_details['username'],
                             next_visit=next_visit,
                             chw=chw)

    except mysql.connector.Error as err:
        print(f"Database Error: {err}")
        flash(f'Error loading dashboard data: {str(err)}', 'error')
        return render_template('Mother/mother_dashboard.html',
                             mother_name="Mother",
                             next_visit=None,
                             chw=None)

    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()

# New route for handling check-ins
@app.route('/mother/checkin', methods=['POST'])
@login_required
def mother_checkin():
    if session.get('user_type') != 'mother':
        return jsonify({'error': 'Unauthorized'}), 403

    try:
        data = request.form
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()

        cursor.execute("""
            INSERT INTO checkin_responses 
            (mother_id, mood, physical_health, emotional_health, support_needed)
            VALUES (%s, %s, %s, %s, %s)
        """, (session['user_id'], 
              data.get('mood'),
              data.get('physical_health'),
              data.get('emotional_health'),
              data.get('support_needed')))

        connection.commit()
        flash('Check-in submitted successfully', 'success')

    except mysql.connector.Error as err:
        print(f"Database Error: {err}")
        flash('Error submitting check-in', 'error')

    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()

    return redirect(url_for('mother_dashboard'))

#chw dashboard
@app.route('/chw/dashboard')
@login_required
def chw_dashboard():
    if session['user_type'] != 'chw':
        return redirect(url_for('login'))
    
    connection = None
    cursor = None
    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)
        
        # First get the CHW's details
        cursor.execute("""
            SELECT username, email 
            FROM users 
            WHERE id = %s
        """, (session['user_id'],))
        chw_details = cursor.fetchone()
        
        # Get assigned mothers with their next visits
        cursor.execute("""
            SELECT 
                u.id, u.username, u.email,
                mc.created_at as assignment_date,
                (SELECT visit_date FROM visits 
                 WHERE mother_id = u.id 
                 AND visit_date > NOW() 
                 ORDER BY visit_date ASC 
                 LIMIT 1) as next_visit
            FROM users u
            JOIN mother_chw mc ON u.id = mc.mother_id
            WHERE mc.chw_id = %s
            ORDER BY mc.created_at DESC
        """, (session['user_id'],))
        
        assigned_mothers = cursor.fetchall()

         # Get assigned mothers with unread message counts
        cursor.execute("""
            SELECT 
                u.id,
                u.username,
                u.email,
                mc.created_at as assignment_date,
                (SELECT COUNT(*) 
                 FROM messages m 
                 WHERE m.sender_id = u.id 
                 AND m.receiver_id = %s 
                 AND m.is_read = FALSE) as unread_count
            FROM users u
            JOIN mother_chw mc ON u.id = mc.mother_id
            WHERE mc.chw_id = %s AND u.user_type = 'mother'
            ORDER BY u.username
        """, (session['user_id'], session['user_id']))
        assigned_mothers = cursor.fetchall()
        
        return render_template('CHW/chw_dashboard.html',
                             chw_name=chw_details['username'],
                             assigned_mothers=assigned_mothers)
                             
    except mysql.connector.Error as err:
        print(f"Database Error: {err}")
        flash('Error loading dashboard', 'error')
        return render_template('CHW/chw_dashboard.html',
                             chw_name="CHW",
                             assigned_mothers=[])

    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()

#chw meal plan
@app.route('/chw/chw_meal_plan', methods=['GET', 'POST'])
@login_required
def chw_meal_plan():
    if session.get('user_type') != 'chw':
        flash('Unauthorized access', 'error')
        return redirect(url_for('login'))
    
    connection = None
    cursor = None
    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)

        if request.method == 'POST':
            # Get form data
            meal_id = request.form.get('meal_id')
            mother_id = request.form.get('mother_id')
            meal_type = request.form.get('meal_type')
            description = request.form.get('description')
            start_date = request.form.get('start_date')
            end_date = request.form.get('end_date')

            if meal_id:  # Update existing meal plan
                cursor.execute("""
                    UPDATE meal_plans 
                    SET meal_type = %s, description = %s, 
                        start_date = %s, end_date = %s 
                    WHERE id = %s
                """, ( meal_type, description, start_date, end_date, meal_id))
                flash('Meal plan updated successfully', 'success')
            else:  # Create new meal plan
                cursor.execute("""
                    INSERT INTO meal_plans 
                    (mother_id, meal_type, description, start_date, end_date, created_at)
                    VALUES (%s, %s, %s, %s, %s, NOW())
                """, (mother_id, meal_type, description, start_date, end_date))
                flash('Meal plan created successfully', 'success')
            
            connection.commit()

        # Get all assigned mothers
        cursor.execute("""
            SELECT u.id, u.username 
            FROM users u
            JOIN mother_chw mc ON u.id = mc.mother_id
            WHERE mc.chw_id = %s AND u.user_type = 'mother'
        """, (session['user_id'],))
        mothers = cursor.fetchall()

        # Get meal plans for assigned mothers
        cursor.execute("""
            SELECT 
                mp.id,
                mp.meal_type,
                mp.description,
                mp.start_date,
                mp.end_date,
                mp.mother_id,
                u.username as mother_name
            FROM meal_plans mp
            JOIN users u ON mp.mother_id = u.id
            JOIN mother_chw mc ON u.id = mc.mother_id
            WHERE mc.chw_id = %s
            ORDER BY mp.created_at DESC
        """, (session['user_id'],))
        meal_plans = cursor.fetchall()

        return render_template('CHW/chw_meal_plan.html', 
                             meal_plans=meal_plans,
                             mothers=mothers)

    except mysql.connector.Error as err:
        print(f"Database Error: {err}")
        flash('Error managing meal plans', 'error')
        return redirect(url_for('chw_dashboard'))

    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()


#chw workout plan
@app.route('/chw/chw_workout_plan', methods=['GET', 'POST'])
@login_required
def chw_workout_plan():
    if session.get('user_type') != 'chw':
        return redirect(url_for('login'))
    
    connection = None
    cursor = None
    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)

        if request.method == 'POST':
            workout_id = request.form.get('workout_id')
            mother_id = request.form.get('mother_id')
            exercise_type = request.form.get('exercise_type')
            duration = request.form.get('duration')
            frequency = request.form.get('frequency')
            start_date = request.form.get('start_date')
            end_date = request.form.get('end_date')

            if workout_id:  # Update existing workout plan
                cursor.execute("""
                    UPDATE workout_plans 
                    SET exercise_type = %s, duration = %s, frequency = %s,
                        start_date = %s, end_date = %s 
                    WHERE id = %s
                """, (exercise_type, duration, frequency, start_date, end_date, workout_id))
                flash('Workout plan updated successfully', 'success')
            else:  # Create new workout plan
                cursor.execute("""
                    INSERT INTO workout_plans 
                    (mother_id, exercise_type, duration, frequency, start_date, end_date, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s, NOW())
                """, (mother_id, exercise_type, duration, frequency, start_date, end_date))
                flash('Workout plan created successfully', 'success')
            
            connection.commit()

        # Get all assigned mothers
        cursor.execute("""
            SELECT u.id, u.username 
            FROM users u
            JOIN mother_chw mc ON u.id = mc.mother_id
            WHERE mc.chw_id = %s AND u.user_type = 'mother'
        """, (session['user_id'],))
        mothers = cursor.fetchall()

        # Get workout plans for assigned mothers
        cursor.execute("""
            SELECT 
                wp.*,
                u.username as mother_name
            FROM workout_plans wp
            JOIN users u ON wp.mother_id = u.id
            JOIN mother_chw mc ON u.id = mc.mother_id
            WHERE mc.chw_id = %s
            ORDER BY wp.created_at DESC
        """, (session['user_id'],))
        workout_plans = cursor.fetchall()

        return render_template('CHW/chw_workout_plan.html', 
                             workout_plans=workout_plans,
                             mothers=mothers)

    except mysql.connector.Error as err:
        print(f"Database Error: {err}")
        flash('Error managing workout plans', 'error')
        return redirect(url_for('chw_dashboard'))

    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()

#delete workout plan
@app.route('/chw/workout_plan/delete/<int:plan_id>', methods=['POST'])
@login_required
def delete_workout_plan(plan_id):
    if session.get('user_type') != 'chw':
        return jsonify({'error': 'Unauthorized'}), 403
        
    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()
        
        # Verify the CHW has access to this workout plan
        cursor.execute("""
            SELECT wp.id
            FROM workout_plans wp
            JOIN mother_chw mc ON wp.mother_id = mc.mother_id
            WHERE wp.id = %s AND mc.chw_id = %s
        """, (plan_id, session['user_id']))
        
        if not cursor.fetchone():
            flash('Unauthorized access to this workout plan', 'error')
            return redirect(url_for('chw_workout_plan'))
            
        # Delete the workout plan
        cursor.execute("DELETE FROM workout_plans WHERE id = %s", (plan_id,))
        connection.commit()
        
        flash('Workout plan deleted successfully', 'success')
        
    except mysql.connector.Error as err:
        print(f"Database Error: {err}")
        flash('Error deleting workout plan', 'error')
    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()
            
    return redirect(url_for('chw_workout_plan'))

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
@app.route('/chw/chw_visits', methods=['GET', 'POST'])
@login_required
def chw_visits():
    if session.get('user_type') != 'chw':
        flash('Unauthorized access', 'error')
        return redirect(url_for('login'))
    
    connection = None
    cursor = None
    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)

        if request.method == 'POST':
            visit_id = request.form.get('visit_id')
            mother_id = request.form.get('mother_id')
            visit_date = request.form.get('visit_date')
            visit_time = request.form.get('visit_time')
            visit_type = request.form.get('visit_type')
            purpose = request.form.get('purpose')
            status = request.form.get('status', 'Scheduled')
            notes = request.form.get('notes')

            if visit_id:  # Update existing visit
                cursor.execute("""
                    UPDATE visits 
                    SET mother_id = %s, visit_date = %s, visit_time = %s,
                        visit_type = %s, purpose = %s, status = %s, notes = %s,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = %s AND chw_id = %s
                """, (mother_id, visit_date, visit_time, visit_type, purpose, 
                      status, notes, visit_id, session['user_id']))
                flash('Visit updated successfully', 'success')
            else:  # Schedule new visit
                cursor.execute("""
                    INSERT INTO visits 
                    (mother_id, chw_id, visit_date, visit_time, visit_type, 
                     purpose, status, notes, created_at, updated_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 
                           CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                """, (mother_id, session['user_id'], visit_date, visit_time,
                      visit_type, purpose, status, notes))
                flash('Visit scheduled successfully', 'success')
            
            connection.commit()

        # Get all assigned mothers
        cursor.execute("""
            SELECT u.id, u.username 
            FROM users u
            JOIN mother_chw mc ON u.id = mc.mother_id
            WHERE mc.chw_id = %s AND u.user_type = 'mother'
        """, (session['user_id'],))
        mothers = cursor.fetchall()

        # Get upcoming visits
        cursor.execute("""
            SELECT 
                v.id,
                v.mother_id,
                u.username as mother_name,
                DATE_FORMAT(v.visit_date, '%d-%m-%Y') as visit_date,
                TIME_FORMAT(v.visit_time, '%H:%i') as visit_time,
                v.visit_type,
                v.purpose,
                v.status,
                v.notes,
                v.created_at,
                v.updated_at
            FROM visits v
            JOIN users u ON v.mother_id = u.id
            WHERE v.chw_id = %s 
            AND v.visit_date >= CURDATE()
            ORDER BY v.visit_date ASC, v.visit_time ASC
        """, (session['user_id'],))
        upcoming_visits = cursor.fetchall()

        # Get past visits
        cursor.execute("""
            SELECT 
                v.id,
                v.mother_id,
                u.username as mother_name,
                DATE_FORMAT(v.visit_date, '%d-%m-%Y') as visit_date,
                TIME_FORMAT(v.visit_time, '%H:%i') as visit_time,
                v.visit_type,
                v.purpose,
                v.status,
                v.notes,
                v.created_at,
                v.updated_at
            FROM visits v
            JOIN users u ON v.mother_id = u.id
            WHERE v.chw_id = %s 
            AND v.visit_date < CURDATE()
            ORDER BY v.visit_date DESC, v.visit_time DESC
        """, (session['user_id'],))
        past_visits = cursor.fetchall()

        return render_template('CHW/chw_visits.html',
                             mothers=mothers,
                             upcoming_visits=upcoming_visits,
                             past_visits=past_visits)

    except mysql.connector.Error as err:
        print(f"Database Error: {err}")
        flash('Error managing visits', 'error')
        return redirect(url_for('chw_dashboard'))

    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()

#delete visit
@app.route('/chw/visit/delete/<int:visit_id>', methods=['POST'])
@login_required
def delete_visit(visit_id):
    if session.get('user_type') != 'chw':
        flash('Unauthorized access', 'error')
        return redirect(url_for('login'))
    
    connection = None
    cursor = None
    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()
        
        cursor.execute("DELETE FROM visits WHERE id = %s", (visit_id,))
        connection.commit()
        flash('Visit cancelled successfully', 'success')
    
    except mysql.connector.Error as err:
        print(f"Database Error: {err}")
        flash('Error cancelling visit', 'error')
    
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

        # Fetch admin details
        cursor.execute("""
            SELECT username, email 
            FROM users 
            WHERE id = %s
        """, (session['user_id'],))
        admin_details = cursor.fetchone()

        # Get user counts
        cursor.execute("""
            SELECT 
                COUNT(CASE WHEN user_type = 'mother' THEN 1 END) as total_mothers,
                COUNT(CASE WHEN user_type = 'chw' THEN 1 END) as total_chws
            FROM users
        """)
        stats = cursor.fetchone()  # Changed from user_stats to stats
        
        cursor.execute("SELECT COUNT(*) as total_visits FROM visits")
        visit_stats = cursor.fetchone()
        
        # New query for recent users
        cursor.execute("""
            SELECT username, email, user_type, created_at
            FROM users
            WHERE user_type IN ('mother', 'chw')
            ORDER BY created_at DESC
            LIMIT 5
        """)
        recent_users = cursor.fetchall()
        
        return render_template('Admin/admin_dashboard.html',
                             stats=stats,  # Changed from user_stats to stats
                             visit_stats=visit_stats,
                             recent_users=recent_users,
                             admin_name=admin_details['username'])
                             
    except mysql.connector.Error as err:
        print(f"Database Error: {err}")
        flash('Error loading dashboard data', 'error')
        return render_template('Admin/admin_dashboard.html', 
                             stats={'total_mothers': 0, 'total_chws': 0},  # Match the structure
                             visit_stats={'total_visits': 0},
                             recent_users=[],
                             admin_details=None)

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
    if session.get('user_type') != 'mother':
        flash('Unauthorized access', 'error')
        return redirect(url_for('login'))
    
    connection = None
    cursor = None
    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)

        # Get mother's meal plans with CHW information
        cursor.execute("""
            SELECT 
                mp.*,
                u.username as chw_name,
                DATE_FORMAT(mp.start_date, '%d-%m-%Y') as formatted_start_date,
                DATE_FORMAT(mp.end_date, '%d-%m-%Y') as formatted_end_date
            FROM meal_plans mp
            JOIN mother_chw mc ON mp.mother_id = mc.mother_id
            JOIN users u ON mc.chw_id = u.id
            WHERE mp.mother_id = %s
            ORDER BY mp.start_date DESC
        """, (session['user_id'],))
        meal_plans = cursor.fetchall()

        return render_template('Mother/meal_plan.html', meal_plans=meal_plans)

    except mysql.connector.Error as err:
        print(f"Database Error: {err}")
        flash('Error fetching meal plans', 'error')
        return render_template('Mother/meal_plan.html', meal_plans=[])

    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()

#mother workout plan
@app.route('/mother/workout_plan')
@login_required
def workout_plan():
    if session.get('user_type') != 'mother':
        flash('Unauthorized access', 'error')
        return redirect(url_for('login'))
    
    connection = None
    cursor = None
    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)

        # Get mother's workout plans with CHW information
        cursor.execute("""
            SELECT 
                wp.*,
                u.username as chw_name,
                DATE_FORMAT(wp.start_date, '%d-%m-%Y') as formatted_start_date,
                DATE_FORMAT(wp.end_date, '%d-%m-%Y') as formatted_end_date
            FROM workout_plans wp
            JOIN mother_chw mc ON wp.mother_id = mc.mother_id
            JOIN users u ON mc.chw_id = u.id
            WHERE wp.mother_id = %s
            ORDER BY wp.start_date DESC
        """, (session['user_id'],))
        workout_plans = cursor.fetchall()

        return render_template('Mother/workout_plan.html', workout_plans=workout_plans)

    except mysql.connector.Error as err:
        print(f"Database Error: {err}")
        flash('Error fetching workout plans', 'error')
        return render_template('Mother/workout_plan.html', workout_plans=[])

    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()

#mother visits
@app.route('/mother/visits')
@login_required
def visits():
    if session.get('user_type') != 'mother':
        flash('Unauthorized access', 'error')
        return redirect(url_for('login'))
    
    connection = None
    cursor = None
    try:
        mother_id = session.get('user_id')
        
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)

        # Get CHW information
        cursor.execute("""
            SELECT 
                u.id, 
                u.username as name, 
                u.email
            FROM users u
            JOIN mother_chw mc ON u.id = mc.chw_id
            WHERE mc.mother_id = %s AND u.user_type = 'chw'
        """, (mother_id,))
        chw = cursor.fetchone()
        #removed phone number

        # Get upcoming visits
        cursor.execute("""
            SELECT 
                v.*,
                DATE_FORMAT(v.visit_date, '%d-%m-%Y') as formatted_date,
                TIME_FORMAT(v.visit_time, '%H:%i') as formatted_time,
                u.username as chw_name
            FROM visits v
            JOIN users u ON v.chw_id = u.id
            WHERE v.mother_id = %s 
            AND v.visit_date >= CURDATE()
            ORDER BY v.visit_date ASC, v.visit_time ASC
        """, (mother_id,))
        upcoming_visits = cursor.fetchall()

        # Get past visits
        cursor.execute("""
            SELECT 
                v.*,
                DATE_FORMAT(v.visit_date, '%d-%m-%Y') as formatted_date,
                TIME_FORMAT(v.visit_time, '%H:%i') as formatted_time,
                u.username as chw_name
            FROM visits v
            JOIN users u ON v.chw_id = u.id
            WHERE v.mother_id = %s 
            AND v.visit_date < CURDATE()
            ORDER BY v.visit_date DESC, v.visit_time DESC
        """, (mother_id,))
        past_visits = cursor.fetchall()

        return render_template('Mother/visits.html',
                             chw=chw,
                             upcoming_visits=upcoming_visits,
                             past_visits=past_visits)

    except mysql.connector.Error as err:
        print(f"Database Error: {err}")
        flash('Error fetching visits data', 'error')
        return render_template('Mother/visits.html',
                             chw=None,
                             upcoming_visits=[],
                             past_visits=[])
    
    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()

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

        # Fetch the assigned CHW for the logged-in mother
        cursor.execute("""
            SELECT 
                u.id, 
                u.username AS name, 
                u.email
            FROM users u
            JOIN mother_chw mc ON u.id = mc.chw_id
            WHERE mc.mother_id = %s AND u.user_type = 'chw'
        """, (session['user_id'],))
        chw = cursor.fetchone()
        #removed phone number

        # Get messages exchanged between the mother and the assigned CHW
        messages = []
        if chw:
            cursor.execute("""
                SELECT * 
                FROM messages 
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
                DATE_FORMAT(created_at, '%m-%Y') as month,
                COUNT(*) as total,
                SUM(CASE WHEN user_type = 'mother' THEN 1 ELSE 0 END) as mothers,
                SUM(CASE WHEN user_type = 'chw' THEN 1 ELSE 0 END) as chws
            FROM users
            WHERE created_at >= DATE_SUB(NOW(), INTERVAL 6 MONTH)
            GROUP BY DATE_FORMAT(created_at, '%m-%Y')
            ORDER BY month
        """)
        registration_stats = cursor.fetchall()
        
        # Get visit statistics
        cursor.execute("""
            SELECT 
                visit_type,
                COUNT(*) as total_visits,
                COUNT(DISTINCT mother_id) as unique_mothers,
                SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as completed_visits
            FROM visits
            WHERE visit_date >= DATE_SUB(NOW(), INTERVAL 6 MONTH)
            GROUP BY visit_type
        """)
        visit_stats = cursor.fetchall()
        
        # Get CHW performance metrics
        cursor.execute("""
            SELECT 
                u.username as chw_name,
                COUNT(v.id) as total_visits,
                COUNT(DISTINCT v.mother_id) as mothers_attended,
                COUNT(DISTINCT mp.mother_id) as meal_plans_created,
                COUNT(DISTINCT wp.mother_id) as workout_plans_created
            FROM users u
            LEFT JOIN visits v ON u.id = v.chw_id
            LEFT JOIN meal_plans mp ON u.id = mp.mother_id
            LEFT JOIN workout_plans wp ON u.id = wp.mother_id
            WHERE u.user_type = 'chw'
            GROUP BY u.id, u.username
        """)
        chw_performance = cursor.fetchall()
        
        # Get mother-CHW assignment stats
        cursor.execute("""
            SELECT 
                COUNT(*) as total_assignments,
                COUNT(DISTINCT mother_id) as unique_mothers,
                COUNT(DISTINCT chw_id) as unique_chws
            FROM mother_chw
        """)
        assignment_stats = cursor.fetchone()
        
        return render_template('Admin/reports.html',
                             registration_stats=registration_stats,
                             visit_stats=visit_stats,
                             chw_performance=chw_performance,
                             assignment_stats=assignment_stats)
                             
    except mysql.connector.Error as err:
        print(f"Database Error: {err}")
        flash('Error generating reports', 'error')
        return render_template('Admin/reports.html')
        
    finally:
        if cursor:
            cursor.close()
        if connection:
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
        connection = mysql.connector.connect(**db_config)
        
        # Create a new Excel writer object
        filename = f'maternal_care_report_{datetime.now().strftime("%d%m%Y_%H%M%S")}.xlsx'
        filepath = os.path.join(EXPORT_DIR, filename)
        
        writer = pd.ExcelWriter(filepath, engine='xlsxwriter')
        
        # User Registration Data
        df_users = pd.read_sql("""
            SELECT username, email, user_type, created_at
            FROM users
            ORDER BY created_at DESC
        """, connection)
        df_users.to_excel(writer, sheet_name='Users', index=False)
        
        # Visit Statistics
        df_visits = pd.read_sql("""
            SELECT 
                v.visit_type,
                v.visit_date,
                v.status,
                u_m.username as mother_name,
                u_c.username as chw_name
            FROM visits v
            JOIN users u_m ON v.mother_id = u_m.id
            JOIN users u_c ON v.chw_id = u_c.id
            ORDER BY v.visit_date DESC
        """, connection)
        df_visits.to_excel(writer, sheet_name='Visits', index=False)
        
        # CHW Performance
        df_chw = pd.read_sql("""
            SELECT 
                u.username as chw_name,
                COUNT(v.id) as total_visits,
                COUNT(DISTINCT v.mother_id) as mothers_attended,
                COUNT(DISTINCT mp.mother_id) as meal_plans_created,
                COUNT(DISTINCT wp.mother_id) as workout_plans_created
            FROM users u
            LEFT JOIN visits v ON u.id = v.chw_id
            LEFT JOIN meal_plans mp ON u.id = mp.mother_id
            LEFT JOIN workout_plans wp ON u.id = wp.mother_id
            WHERE u.user_type = 'chw'
            GROUP BY u.id, u.username
        """, connection)
        df_chw.to_excel(writer, sheet_name='CHW Performance', index=False)
        
        writer.close()
        
        # Send file to user
        return send_file(
            filepath,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            as_attachment=True,
            download_name=filename
        )
        
    except Exception as e:
        print(f"Export Error: {e}")  # Debug print
        flash('Error exporting data', 'error')
        return redirect(url_for('reports'))
    
    finally:
        if connection:
            connection.close()

#export pdf
@app.route('/admin/export/pdf')
@login_required
def export_pdf():
    if session['user_type'] != 'admin':
        return redirect(url_for('login'))
    
    connection = None
    cursor = None
    try:
        # Generate filename with timestamp
        filename = f'maternal_care_report_{datetime.now().strftime("%d%m%Y_%H%M%S")}.pdf'
        filepath = os.path.join(EXPORT_DIR, filename)
        
        # Ensure exports directory exists
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        
        # Create the PDF document using filename
        doc = SimpleDocTemplate(
            filepath,  # Using filepath instead of buffer
            pagesize=letter,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=72
        )
        
        # Container for the 'Flowable' objects
        elements = []
        
        # Get styles
        styles = getSampleStyleSheet()
        
        # Add title and date
        elements.append(Paragraph("Maternal Care System Report", styles['Heading1']))
        elements.append(Spacer(1, 12))
        elements.append(Paragraph(f"Generated on: {datetime.now().strftime('%d-%m-%Y %H:%M:%S')}", styles['Normal']))
        elements.append(Spacer(1, 20))
        
        # Get database connection
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)
        
        # User Statistics
        elements.append(Paragraph("User Statistics", styles['Heading2']))
        cursor.execute("""
            SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN user_type = 'mother' THEN 1 ELSE 0 END) as mothers,
                SUM(CASE WHEN user_type = 'chw' THEN 1 ELSE 0 END) as chws
            FROM users
        """)
        stats = cursor.fetchone()
        
        # Create user statistics table
        user_data = [
            ['Category', 'Count'],
            ['Total Users', stats['total']],
            ['Total Mothers', stats['mothers']],
            ['Total CHWs', stats['chws']]
        ]
        user_table = Table(user_data, colWidths=[200, 100])
        user_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        elements.append(user_table)
        elements.append(Spacer(1, 20))
        
        # Visit Statistics
        elements.append(Paragraph("Visit Statistics", styles['Heading2']))
        cursor.execute("""
            SELECT 
                visit_type,
                COUNT(*) as total,
                COUNT(DISTINCT mother_id) as unique_mothers
            FROM visits
            GROUP BY visit_type
        """)
        visit_stats = cursor.fetchall()
        
        if visit_stats:
            visit_data = [['Visit Type', 'Total Visits', 'Unique Mothers']]
            for stat in visit_stats:
                visit_data.append([
                    stat['visit_type'],
                    stat['total'],
                    stat['unique_mothers']
                ])
            
            visit_table = Table(visit_data, colWidths=[150, 100, 100])
            visit_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            elements.append(visit_table)
        else:
            elements.append(Paragraph("No visit data available", styles['Normal']))
        
        # Build PDF
        doc.build(elements)
        
        # Return the file
        return send_file(
            filepath,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=filename
        )
        
    except Exception as e:
        print(f"Export Error: {e}")  # Debug print
        flash('Error exporting data', 'error')
        return redirect(url_for('reports'))
        
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()

# Optional: Add a route to view all exports
@app.route('/admin/exports')
@login_required
def view_exports():
    if session['user_type'] != 'admin':
        return redirect(url_for('login'))
        
    files = []
    try:
        # Ensure export directory exists
        if not os.path.exists(EXPORT_DIR):
            os.makedirs(EXPORT_DIR)
            
        # Get list of files
        for filename in os.listdir(EXPORT_DIR):
            file_path = os.path.join(EXPORT_DIR, filename)
            if os.path.isfile(file_path):
                files.append({
                    'name': filename,
                    'date': datetime.fromtimestamp(os.path.getctime(file_path)).strftime('%d-%m-%Y %H:%M:%S'),
                    'size': f"{os.path.getsize(file_path) / 1024:.1f} KB"
                })
        
        # Sort files by date (newest first)
        files.sort(key=lambda x: x['date'], reverse=True)
        
    except Exception as e:
        print(f"Error listing exports: {e}")
        flash('Error accessing export files', 'error')
        
    return render_template('Admin/exports.html', files=files)

@app.route('/admin/exports/download/<filename>')
@login_required
def download_export(filename):
    if session['user_type'] != 'admin':
        return redirect(url_for('login'))
    
    try:
        return send_from_directory(
            EXPORT_DIR,
            filename,
            as_attachment=True
        )
    except Exception as e:
        flash('Error downloading file', 'error')
        return redirect(url_for('view_exports'))

@app.route('/admin/exports/delete/<filename>', methods=['POST'])
@login_required
def delete_export(filename):
    if session['user_type'] != 'admin':
        return redirect(url_for('login'))
    
    try:
        file_path = os.path.join(EXPORT_DIR, secure_filename(filename))
        if os.path.exists(file_path):
            os.remove(file_path)
            flash('File deleted successfully', 'success')
        else:
            flash('File not found', 'error')
    except Exception as e:
        flash('Error deleting file', 'error')
        
    return redirect(url_for('view_exports'))

@app.route('/admin/export_report/<report_type>')
@login_required
def export_report(report_type):
    if session['user_type'] != 'admin':
        return redirect(url_for('login'))
        
    try:
        connection = mysql.connector.connect(
            host='localhost',
            user='root',
            password='',
            database='postnatalcare_system'
        )
        cursor = connection.cursor(dictionary=True)
        
        if report_type == 'chw_performance':
            cursor.execute("""
                SELECT 
                    u.username as chw_name,
                    COUNT(v.id) as total_visits,
                    COUNT(DISTINCT v.mother_id) as mothers_attended,
                    COUNT(DISTINCT mp.mother_id) as meal_plans_created,
                    COUNT(DISTINCT wp.mother_id) as workout_plans_created
                FROM users u
                LEFT JOIN visits v ON u.id = v.chw_id
                LEFT JOIN meal_plans mp ON u.id = mp.mother_id
                LEFT JOIN workout_plans wp ON u.id = wp.mother_id
                WHERE u.user_type = 'chw'
                GROUP BY u.id, u.username
            """)
            data = cursor.fetchall()
            
            # Create DataFrame and export to Excel
            df = pd.DataFrame(data)
            filename = f'chw_performance_{datetime.now().strftime("%d%m%Y_%H%M%S")}.xlsx'
            filepath = os.path.join(app.static_folder, 'exports', filename)
            
            # Ensure exports directory exists
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            
            # Export to Excel
            df.to_excel(filepath, index=False)
            
            return send_file(filepath, as_attachment=True)
            
    except Exception as e:
        flash(f'Error exporting report: {str(e)}', 'error')
        return redirect(url_for('reports'))
        
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()

#assign chw routes
@app.route('/admin/assign-chw', methods=['GET', 'POST'])
@login_required
def assign_chw():
    if session['user_type'] != 'admin':
        return redirect(url_for('login'))
    
    connection = None
    cursor = None
    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)
        
        if request.method == 'POST':
            mother_id = request.form.get('mother_id')
            chw_id = request.form.get('chw_id')
            
            # Check if mother already has a CHW assigned
            cursor.execute("""
                SELECT * FROM mother_chw 
                WHERE mother_id = %s
            """, (mother_id,))
            
            existing = cursor.fetchone()
            if existing:
                flash('This mother already has a CHW assigned', 'warning')
            else:
                # Create new assignment
                cursor.execute("""
                    INSERT INTO mother_chw (mother_id, chw_id, created_at)
                    VALUES (%s, %s, NOW())
                """, (mother_id, chw_id))
                connection.commit()
                flash('CHW assigned successfully', 'success')
        
        # Get current assignments
        cursor.execute("""
            SELECT mc.id, mc.created_at,
                   m.username as mother_name,
                   c.username as chw_name
            FROM mother_chw mc
            JOIN users m ON mc.mother_id = m.id
            JOIN users c ON mc.chw_id = c.id
            ORDER BY mc.created_at DESC
        """)
        assignments = cursor.fetchall()
        
        # Get unassigned mothers
        cursor.execute("""
            SELECT id, username 
            FROM users 
            WHERE user_type = 'mother'
            AND id NOT IN (SELECT mother_id FROM mother_chw)
        """)
        unassigned_mothers = cursor.fetchall()
        
        # Get all CHWs
        cursor.execute("""
            SELECT id, username 
            FROM users 
            WHERE user_type = 'chw'
        """)
        chws = cursor.fetchall()
        
        return render_template('Admin/assign_chw.html',
                             assignments=assignments,
                             unassigned_mothers=unassigned_mothers,
                             chws=chws)
                             
    except Exception as e:
        print(f"Database Error: {e}")
        flash('Error processing request', 'error')
        return redirect(url_for('admin_dashboard'))
        
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()

# delete chwassignment
@app.route('/admin/assign-chw/delete/<int:assignment_id>', methods=['POST'])
@login_required
def delete_assignment(assignment_id):
    if session['user_type'] != 'admin':
        return redirect(url_for('login'))
    
    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()
        
        cursor.execute("DELETE FROM mother_chw WHERE id = %s", (assignment_id,))
        connection.commit()
        
        flash('Assignment removed successfully', 'success')
        
    except Exception as e:
        print(f"Database Error: {e}")
        flash('Error removing assignment', 'error')
        
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()
            
    return redirect(url_for('assign_chw'))
# delete meal plan
@app.route('/chw/meal_plan/delete/<int:meal_id>', methods=['POST'])
@login_required
def delete_meal_plan(meal_id):
    if session.get('user_type') != 'chw':
        flash('Unauthorized access', 'error')
        return redirect(url_for('login'))
    
    connection = None
    cursor = None
    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()
        
        # Verify the meal plan belongs to one of the CHW's assigned mothers
        cursor.execute("""
            SELECT mp.id 
            FROM meal_plans mp
            JOIN mother_chw mc ON mp.mother_id = mc.mother_id
            WHERE mp.id = %s AND mc.chw_id = %s
        """, (meal_id, session['user_id']))
        
        if cursor.fetchone():
            cursor.execute("DELETE FROM meal_plans WHERE id = %s", (meal_id,))
            connection.commit()
            flash('Meal plan deleted successfully', 'success')
        else:
            flash('Unauthorized to delete this meal plan', 'error')
            
    except mysql.connector.Error as err:
        print(f"Database Error: {err}")
        flash('Error deleting meal plan', 'error')
        
    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()
            
    return redirect(url_for('chw_meal_plan'))

# add visits
@app.route('/chw/visit/add', methods=['POST'])
@login_required
def add_visit():
    if session.get('user_type') != 'chw':
        flash('Unauthorized access', 'error')
        return redirect(url_for('login'))
    
    connection = None
    cursor = None
    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()

        mother_id = request.form.get('mother_id')
        visit_date = request.form.get('visit_date')
        visit_time = request.form.get('visit_time')
        purpose = request.form.get('purpose')
        visit_type = request.form.get('visit_type', 'Routine')
        
        cursor.execute("""
            INSERT INTO visits 
            (mother_id, chw_id, visit_date, visit_time, purpose, visit_type, status)
            VALUES (%s, %s, %s, %s, %s, %s, 'Scheduled')
        """, (mother_id, session['user_id'], visit_date, visit_time, purpose, visit_type))
        
        connection.commit()
        flash('Visit scheduled successfully', 'success')
        
    except mysql.connector.Error as err:
        print(f"Database Error: {err}")
        flash('Error scheduling visit', 'error')
    
    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()
    
    return redirect(url_for('chw_visits'))

# Individual mother's meal plan
@app.route('/chw/meal-plan/<int:mother_id>', methods=['GET', 'POST'])
@login_required
def create_mother_meal_plan(mother_id):
    if session.get('user_type') != 'chw':
        flash('Unauthorized access', 'error')
        return redirect(url_for('login'))
    
    connection = None
    cursor = None
    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)
        
        # Get mother's details
        cursor.execute("""
            SELECT username 
            FROM users 
            WHERE id = %s AND user_type = 'mother'
        """, (mother_id,))
        mother = cursor.fetchone()
        
        if not mother:
            flash('Mother not found', 'error')
            return redirect(url_for('chw_dashboard'))
            
        return render_template('CHW/meal_plan.html', mother=mother)
        
    except mysql.connector.Error as err:
        print(f"Database Error: {err}")
        flash('Error accessing meal plan', 'error')
        return redirect(url_for('chw_dashboard'))
        
    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()

# CHW Profile Routes
@app.route('/chw/profile')
@login_required
def chw_profile():
    if session.get('user_type') != 'chw':
        return redirect(url_for('login'))
    
    connection = None
    cursor = None
    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)
        
        cursor.execute("""
            SELECT 
                u.id,
                u.username,
                u.email,
                u.user_type,
                u.created_at,
                u.experience,
                u.available_hours,
                (SELECT COUNT(*) FROM mother_chw WHERE chw_id = u.id) as mother_count,
                (SELECT COUNT(*) 
                 FROM meal_plans mp
                 JOIN mother_chw mc ON mp.mother_id = mc.mother_id
                 WHERE mc.chw_id = u.id AND mp.end_date >= CURDATE()) as meal_plan_count,
                (SELECT COUNT(*) 
                 FROM workout_plans wp
                 JOIN mother_chw mc ON wp.mother_id = mc.mother_id
                 WHERE mc.chw_id = u.id AND wp.end_date >= CURDATE()) as workout_plan_count,
                (SELECT COUNT(*) 
                 FROM visits v
                 WHERE v.chw_id = u.id 
                 AND v.visit_date >= CURDATE()
                 AND v.status = 'Scheduled') as upcoming_visits
            FROM users u
            WHERE u.id = %s AND u.user_type = 'chw'
        """, (session['user_id'],))
        
        chw = cursor.fetchone()
        
        if not chw:
            flash('CHW profile not found', 'error')
            return redirect(url_for('login'))
            
        # Create stats dictionary for template compatibility
        stats = {
            'mother_count': chw['mother_count'],
            'meal_plan_count': chw['meal_plan_count'],
            'workout_plan_count': chw['workout_plan_count'],
            'upcoming_visits': chw['upcoming_visits']
        }
        
        return render_template('CHW/chw_profile.html', chw=chw, stats=stats)
        
    except mysql.connector.Error as err:
        flash(f'Error accessing profile: {err}', 'error')
        return redirect(url_for('chw_dashboard'))
    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()

@app.route('/chw/profile/update', methods=['POST'])
@login_required
def chw_update_profile():
    if session.get('user_type') != 'chw':
        return redirect(url_for('login'))
    
    connection = None
    cursor = None
    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()
        
        # Update user details
        cursor.execute("""
            UPDATE users 
            SET username = %s,
                email = %s,
                phone = %s,
                location = %s
            WHERE id = %s AND user_type = 'chw'
        """, (
            request.form['username'],
            request.form['email'],
            request.form['phone'],
            request.form['location'],
            session['user_id']
        ))
        
        connection.commit()
        flash('Profile updated successfully', 'success')
        
    except mysql.connector.Error as err:
        flash(f'Error updating profile: {err}', 'error')
    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()
            
    return redirect(url_for('chw_profile'))

@app.route('/chw/change-password', methods=['POST'])
@login_required
def chw_change_password():
    if session.get('user_type') != 'chw':
        return redirect(url_for('login'))
    
    if request.form['new_password'] != request.form['confirm_password']:
        flash('New passwords do not match', 'error')
        return redirect(url_for('chw_profile'))
    
    connection = None
    cursor = None
    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()
        
        # Verify current password
        cursor.execute("""
            SELECT password_hash FROM users WHERE id = %s
        """, (session['user_id'],))
        current_hash = cursor.fetchone()[0]
        
        if not check_password_hash(current_hash, request.form['current_password']):
            flash('Current password is incorrect', 'error')
            return redirect(url_for('chw_profile'))
        
        # Update password
        new_password_hash = generate_password_hash(request.form['new_password'])
        cursor.execute("""
            UPDATE users 
            SET password_hash = %s
            WHERE id = %s
        """, (new_password_hash, session['user_id']))
        
        connection.commit()
        flash('Password changed successfully', 'success')
        
    except mysql.connector.Error as err:
        flash(f'Error changing password: {err}', 'error')
    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()
            
    return redirect(url_for('chw_profile'))

@app.route('/chw/get-meal-plan/<int:plan_id>', methods=['GET'])
@login_required
def get_meal_plan_details(plan_id):
    if session.get('user_type') != 'chw':
        return jsonify({'error': 'Unauthorized'}), 403
        
    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)
        
        cursor.execute("""
            SELECT 
                mp.id,
                mp.meal_type,
                mp.description,
                DATE_FORMAT(mp.start_date, '%d-%m-%Y') as start_date,
                DATE_FORMAT(mp.end_date, '%d-%m-%Y') as end_date,
                mp.mother_id,
                u.username as mother_name
            FROM meal_plans mp
            JOIN users u ON mp.mother_id = u.id
            JOIN mother_chw mc ON u.id = mc.mother_id
            WHERE mp.id = %s AND mc.chw_id = %s
        """, (plan_id, session['user_id']))
        
        meal_plan = cursor.fetchone()
        
        if meal_plan:
            return jsonify(meal_plan)
        return jsonify({'error': 'Meal plan not found'}), 404
        
    except mysql.connector.Error as err:
        return jsonify({'error': str(err)}), 500
    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()
            
# update meal plan
@app.route('/chw/meal-plan/update/<int:plan_id>', methods=['POST'])
@login_required
def update_meal_plan(plan_id):
    if session.get('user_type') != 'chw':
        return jsonify({'error': 'Unauthorized'}), 403
        
    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)
        
        # Verify CHW has access to this meal plan
        cursor.execute("""
            SELECT 1 FROM meal_plans mp
            JOIN mother_chw mc ON mp.mother_id = mc.mother_id
            WHERE mp.id = %s AND mc.chw_id = %s
        """, (plan_id, session['user_id']))
        
        if not cursor.fetchone():
            flash('Unauthorized access to meal plan', 'error')
            return redirect(url_for('chw_meal_plan'))
        
        # Update meal plan
        cursor.execute("""
            UPDATE meal_plans 
            SET meal_type = %s,
                description = %s,
                start_date = %s,
                end_date = %s
            WHERE id = %s
        """, (
            request.form['meal_type'],
            request.form['description'],
            request.form['start_date'],
            request.form['end_date'],
            plan_id
        ))
        
        connection.commit()
        flash('Meal plan updated successfully', 'success')
        
    except mysql.connector.Error as err:
        flash(f'Error updating meal plan: {err}', 'error')
    finally:
        cursor.close()
        connection.close()
        
    return redirect(url_for('chw_meal_plan'))

# get workout plan details
@app.route('/chw/get-workout-plan/<int:plan_id>', methods=['GET'])
@login_required
def get_workout_plan_details(plan_id):
    if session.get('user_type') != 'chw':
        return jsonify({'error': 'Unauthorized'}), 403
        
    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)
        
        cursor.execute("""
            SELECT 
                wp.id,
                wp.exercise_type,
                wp.duration,
                wp.frequency,
                DATE_FORMAT(wp.start_date, '%d-%m-%Y') as start_date,
                DATE_FORMAT(wp.end_date, '%d-%m-%Y') as end_date,
                wp.mother_id,
                u.username as mother_name
            FROM workout_plans wp
            JOIN users u ON wp.mother_id = u.id
            JOIN mother_chw mc ON u.id = mc.mother_id
            WHERE wp.id = %s AND mc.chw_id = %s
        """, (plan_id, session['user_id']))
        
        workout_plan = cursor.fetchone()
        
        if workout_plan:
            return jsonify(workout_plan)
        return jsonify({'error': 'Workout plan not found'}), 404
        
    except mysql.connector.Error as err:
        return jsonify({'error': str(err)}), 500
    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()

# get visit details 
@app.route('/chw/get-visit/<int:visit_id>', methods=['GET'])
@login_required
def get_visit_details(visit_id):
    if session.get('user_type') != 'chw':
        return jsonify({'error': 'Unauthorized'}), 403
        
    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)
        
        cursor.execute("""
            SELECT 
                v.*,
                u.username as mother_name,
                DATE_FORMAT(v.visit_date, '%d-%m-%Y') as visit_date,
                TIME_FORMAT(v.visit_time, '%H:%i') as visit_time
            FROM visits v
            JOIN users u ON v.mother_id = u.id
            JOIN mother_chw mc ON u.id = mc.mother_id
            WHERE v.id = %s AND mc.chw_id = %s
        """, (visit_id, session['user_id']))
        
        visit = cursor.fetchone()
        
        if visit:
            return jsonify(visit)
        return jsonify({'error': 'Visit not found'}), 404
        
    except mysql.connector.Error as err:
        return jsonify({'error': str(err)}), 500
    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()
# meal plan tracking
@app.route('/mother/meal-plan-tracking/<int:plan_id>', methods=['GET', 'POST'])
@login_required
def mother_meal_tracking(plan_id):
    if session.get('user_type') != 'mother':
        flash('Unauthorized access', 'error')
        return redirect(url_for('login'))
    
    connection = None
    cursor = None
    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)
        
        # Handle form submission
        if request.method == 'POST':
            date = request.form.get('date')
            is_completed = request.form.get('is_completed') == 'true'
            notes = request.form.get('notes')
            
            cursor.execute("""
                INSERT INTO meal_plan_tracking 
                (mother_id, meal_plan_id, meal_date, is_completed, notes)
                VALUES (%s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE 
                is_completed = VALUES(is_completed),
                notes = VALUES(notes)
            """, (session['user_id'], plan_id, date, is_completed, notes))
            connection.commit()
            flash('Tracking updated successfully', 'success')
            
        # Get meal plan details
        cursor.execute("""
            SELECT mp.*, u.username as chw_name
            FROM meal_plans mp
            JOIN mother_chw mc ON mp.mother_id = mc.mother_id
            JOIN users u ON mc.chw_id = u.id
            WHERE mp.id = %s AND mp.mother_id = %s
        """, (plan_id, session['user_id']))
        meal_plan = cursor.fetchone()
        
        if not meal_plan:
            flash('Meal plan not found', 'error')
            return redirect(url_for('meal_plan'))
            
        # Get tracking data
        cursor.execute("""
            SELECT * 
            FROM meal_plan_tracking
            WHERE meal_plan_id = %s AND mother_id = %s
            ORDER BY meal_date DESC
        """, (plan_id, session['user_id']))
        tracking_data = cursor.fetchall()
        
        return render_template('Mother/meal_plan_tracking.html',
                             meal_plan=meal_plan,
                             tracking_data=tracking_data)
                             
    except mysql.connector.Error as err:
        print(f"Database Error: {err}")
        flash('Error accessing meal plan tracking', 'error')
        return redirect(url_for('meal_plan'))
        
    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()
            
# meal plan report  
@app.route('/chw/meal-plan-report')
@login_required
def chw_meal_plan_reports():
    if session.get('user_type') != 'chw':
        flash('Unauthorized access', 'error')
        return redirect(url_for('login'))
    
    connection = None
    cursor = None
    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)
        
        cursor.execute("""
            SELECT 
                u.username as mother_name,
                mp.meal_type,
                mp.start_date,
                mp.end_date,
                COUNT(mpt.id) as total_days,
                SUM(mpt.is_completed) as completed_days,
                (SUM(mpt.is_completed) / COUNT(mpt.id) * 100) as completion_rate
            FROM meal_plans mp
            JOIN users u ON mp.mother_id = u.id
            JOIN mother_chw mc ON u.id = mc.mother_id
            LEFT JOIN meal_plan_tracking mpt ON mp.id = mpt.meal_plan_id
            WHERE mc.chw_id = %s
            GROUP BY mp.id
            ORDER BY mp.start_date DESC
        """, (session['user_id'],))
        reports = cursor.fetchall()
        
        return render_template('CHW/meal_plan_reports.html', reports=reports)
        
    except mysql.connector.Error as err:
        print(f"Database Error: {err}")
        flash('Error generating report', 'error')
        return redirect(url_for('chw_dashboard'))
        
    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()

# workout tracking
@app.route('/mother/workout-tracking/<int:plan_id>', methods=['GET', 'POST'])
@login_required
def mother_workout_tracking(plan_id):
    if session.get('user_type') != 'mother':
        flash('Unauthorized access', 'error')
        return redirect(url_for('login'))
    
    connection = None
    cursor = None
    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)
        
        # Handle form submission
        if request.method == 'POST':
            date = request.form.get('date')
            is_completed = request.form.get('is_completed') == 'true'
            duration = request.form.get('duration_minutes')
            difficulty = request.form.get('difficulty_level')
            notes = request.form.get('notes')
            
            cursor.execute("""
                INSERT INTO workout_plan_tracking 
                (mother_id, workout_plan_id, workout_date, is_completed, 
                 duration_minutes, difficulty_level, notes)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE 
                is_completed = VALUES(is_completed),
                duration_minutes = VALUES(duration_minutes),
                difficulty_level = VALUES(difficulty_level),
                notes = VALUES(notes)
            """, (session['user_id'], plan_id, date, is_completed, 
                  duration, difficulty, notes))
            connection.commit()
            flash('Workout tracking updated successfully', 'success')
            
        # Get workout plan details
        cursor.execute("""
            SELECT wp.*, u.username as chw_name
            FROM workout_plans wp
            JOIN mother_chw mc ON wp.mother_id = mc.mother_id
            JOIN users u ON mc.chw_id = u.id
            WHERE wp.id = %s AND wp.mother_id = %s
        """, (plan_id, session['user_id']))
        workout_plan = cursor.fetchone()
        
        if not workout_plan:
            flash('Workout plan not found', 'error')
            return redirect(url_for('workout_plan'))
            
        # Get tracking data
        cursor.execute("""
            SELECT * 
            FROM workout_plan_tracking
            WHERE workout_plan_id = %s AND mother_id = %s
            ORDER BY workout_date DESC
        """, (plan_id, session['user_id']))
        tracking_data = cursor.fetchall()
        
        return render_template('Mother/workout_tracking.html',
                             workout_plan=workout_plan,
                             tracking_data=tracking_data)
                             
    except mysql.connector.Error as err:
        print(f"Database Error: {err}")
        flash('Error accessing workout tracking', 'error')
        return redirect(url_for('workout_plan'))
        
    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()

# workout report
@app.route('/chw/workout-reports')
@login_required
def chw_workout_reports():
    if session.get('user_type') != 'chw':
        flash('Unauthorized access', 'error')
        return redirect(url_for('login'))
    
    connection = None
    cursor = None
    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)
        
        # Get overall summary for all mothers
        cursor.execute("""
            SELECT 
                u.id as mother_id,
                u.username as mother_name,
                wp.id as plan_id,
                wp.exercise_type,
                wp.frequency,
                DATE_FORMAT(wp.start_date, '%Y-%m-%d') as start_date,
                DATE_FORMAT(wp.end_date, '%Y-%m-%d') as end_date,
                COUNT(wpt.id) as total_tracked_days,
                SUM(wpt.is_completed) as completed_days,
                ROUND(AVG(wpt.duration_minutes), 0) as avg_duration,
                ROUND((SUM(wpt.is_completed) / COUNT(wpt.id) * 100), 2) as completion_rate
            FROM users u
            JOIN mother_chw mc ON u.id = mc.mother_id
            JOIN workout_plans wp ON u.id = wp.mother_id
            LEFT JOIN workout_plan_tracking wpt ON wp.id = wpt.workout_plan_id
            WHERE mc.chw_id = %s AND u.user_type = 'mother'
            GROUP BY wp.id
            ORDER BY wp.start_date DESC
        """, (session['user_id'],))
        summary_data = cursor.fetchall()
        
        # Get detailed tracking data
        cursor.execute("""
            SELECT 
                u.username as mother_name,
                wp.exercise_type,
                DATE_FORMAT(wpt.workout_date, '%Y-%m-%d') as tracked_date,
                wpt.is_completed,
                wpt.duration_minutes,
                wpt.difficulty_level,
                wpt.notes
            FROM users u
            JOIN mother_chw mc ON u.id = mc.mother_id
            JOIN workout_plans wp ON u.id = wp.mother_id
            JOIN workout_plan_tracking wpt ON wp.id = wpt.workout_plan_id
            WHERE mc.chw_id = %s AND u.user_type = 'mother'
            ORDER BY wpt.workout_date DESC
        """, (session['user_id'],))
        detailed_data = cursor.fetchall()
        
        return render_template('CHW/workout_reports.html',
                             summary_data=summary_data,
                             detailed_data=detailed_data)
                             
    except mysql.connector.Error as err:
        print(f"Database Error: {err}")
        flash('Error generating workout reports', 'error')
        return redirect(url_for('chw_dashboard'))
        
    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()

# get messages
@app.route('/api/messages/<int:other_user_id>')
@login_required
def get_messages(other_user_id):
    connection = None
    cursor = None
    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)
        
        # Verify relationship exists (CHW-Mother)
        if session['user_type'] == 'chw':
            cursor.execute("""
                SELECT 1 FROM mother_chw 
                WHERE chw_id = %s AND mother_id = %s
            """, (session['user_id'], other_user_id))
        else:
            cursor.execute("""
                SELECT 1 FROM mother_chw 
                WHERE mother_id = %s AND chw_id = %s
            """, (session['user_id'], other_user_id))
            
        if not cursor.fetchone():
            return jsonify({'error': 'Unauthorized'}), 403
        
        # Get messages
        cursor.execute("""
            SELECT 
                m.*,
                u.username as sender_name,
                u.user_type as sender_type
            FROM messages m
            JOIN users u ON m.sender_id = u.id
            WHERE (m.sender_id = %s AND m.receiver_id = %s)
            OR (m.sender_id = %s AND m.receiver_id = %s)
            ORDER BY m.created_at ASC
        """, (session['user_id'], other_user_id, 
              other_user_id, session['user_id']))
        
        messages = cursor.fetchall()
        
        # Mark messages as read
        cursor.execute("""
            UPDATE messages 
            SET is_read = TRUE
            WHERE receiver_id = %s AND sender_id = %s
        """, (session['user_id'], other_user_id))
        connection.commit()
        
        return jsonify({'messages': messages})
        
    except mysql.connector.Error as err:
        print(f"Database Error: {err}")
        return jsonify({'error': 'Database error'}), 500
        
    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()

# get unread messages
@app.route('/api/messages/unread')
@login_required
def get_unread_messages():
    connection = None
    cursor = None
    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)
        
        cursor.execute("""
            SELECT 
                COUNT(*) as count,
                sender_id,
                u.username as sender_name
            FROM messages m
            JOIN users u ON m.sender_id = u.id
            WHERE receiver_id = %s AND is_read = FALSE
            GROUP BY sender_id
        """, (session['user_id'],))
        
        unread = cursor.fetchall()
        return jsonify({'unread': unread})
        
    except mysql.connector.Error as err:
        print(f"Database Error: {err}")
        return jsonify({'error': 'Database error'}), 500
        
    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()

# chw messages
@app.route('/chw/messages/<int:mother_id>', methods=['GET', 'POST'])
@login_required
def chw_messages(mother_id):
    if session.get('user_type') != 'chw':
        flash('Unauthorized access', 'error')
        return redirect(url_for('login'))
    
    connection = None
    cursor = None
    try:
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)
        
        # Verify CHW is assigned to this mother
        cursor.execute("""
            SELECT u.id, u.username, u.email
            FROM users u
            JOIN mother_chw mc ON u.id = mc.mother_id
            WHERE mc.chw_id = %s AND u.id = %s AND u.user_type = 'mother'
        """, (session['user_id'], mother_id))
        mother = cursor.fetchone()
        
        if not mother:
            flash('Unauthorized: Mother not assigned to you', 'error')
            return redirect(url_for('chw_dashboard'))
            
        # Handle message sending
        if request.method == 'POST':
            message_text = request.form.get('message')
            if message_text:
                cursor.execute("""
                    INSERT INTO messages 
                    (sender_id, receiver_id, message_text)
                    VALUES (%s, %s, %s)
                """, (session['user_id'], mother_id, message_text))
                connection.commit()
                flash('Message sent successfully', 'success')
        
        # Get conversation history
        cursor.execute("""
            SELECT 
                m.*,
                u.username as sender_name,
                u.user_type as sender_type
            FROM messages m
            JOIN users u ON m.sender_id = u.id
            WHERE (m.sender_id = %s AND m.receiver_id = %s)
               OR (m.sender_id = %s AND m.receiver_id = %s)
            ORDER BY m.created_at DESC
        """, (session['user_id'], mother_id, mother_id, session['user_id']))
        messages = cursor.fetchall()
        
        # Mark messages as read
        cursor.execute("""
            UPDATE messages 
            SET is_read = TRUE
            WHERE receiver_id = %s AND sender_id = %s
        """, (session['user_id'], mother_id))
        connection.commit()
        
        return render_template('CHW/messages.html',
                             mother=mother,
                             messages=messages)
                             
    except mysql.connector.Error as err:
        print(f"Database Error: {err}")
        flash('Error accessing messages', 'error')
        return redirect(url_for('chw_dashboard'))
        
    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()

# run the app
if __name__ == '__main__':
    app.run(debug=True)