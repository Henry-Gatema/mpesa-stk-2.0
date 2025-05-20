from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf.csrf import CSRFProtect
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired
import json
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from mpesa import lipa_na_mpesa
from functools import wraps
import jwt
import os

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your-secret-key-here')  # Use environment variable
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)  # Increased session time
app.config['SESSION_COOKIE_SECURE'] = True  # Enable secure cookies
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'your-jwt-secret-key')
app.config['WTF_CSRF_ENABLED'] = True  # Enable CSRF protection

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Login form
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.session_protection = 'strong'

class User(UserMixin):
    def __init__(self, id, username, password_hash):
        self.id = id
        self.username = username
        self.password_hash = password_hash

@login_manager.user_loader
def load_user(user_id):
    try:
        with open('users.json', 'r') as f:
            users = json.load(f)
            user_data = next((u for u in users if u['id'] == user_id), None)
            if user_data:
                return User(user_data['id'], user_data['username'], user_data['password_hash'])
    except FileNotFoundError:
        return None
    return None

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    form = LoginForm()
    
    if request.method == 'POST':
        if form.validate_on_submit():
            username = form.username.data
            password = form.password.data
            
            try:
                with open('users.json', 'r') as f:
                    users = json.load(f)
                    user_data = next((u for u in users if u['username'] == username), None)
                    
                    if user_data and check_password_hash(user_data['password_hash'], password):
                        user = User(user_data['id'], user_data['username'], user_data['password_hash'])
                        login_user(user, remember=True)
                        session.permanent = True
                        next_page = request.args.get('next')
                        
                        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                            return jsonify({'redirect': url_for('index')})
                        return redirect(next_page or url_for('index'))
                    else:
                        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                            return jsonify({'error': 'Invalid username or password'}), 401
                        flash('Invalid username or password')
            except FileNotFoundError:
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return jsonify({'error': 'No users found'}), 500
                flash('No users found')
        else:
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'error': 'Please provide both username and password'}), 400
            flash('Please provide both username and password')
    
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    session.clear()  # Clear the session
    logout_user()    # Log out the user
    flash('You have been logged out successfully.')
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/stk_push', methods=['POST'])
@login_required
def stk_push():
    name = request.form['name']
    phone = request.form['phone']
    amount = request.form['amount']
    time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # Format phone number (remove +254 if present and ensure it starts with 254)
    phone = phone.replace('+254', '')
    if not phone.startswith('254'):
        phone = '254' + phone.lstrip('0')

    try:
        # Initiate M-Pesa STK Push
        response = lipa_na_mpesa(phone, amount)
        
        if 'CheckoutRequestID' in response:
            new_log = {
                'name': name,
                'phone': phone,
                'amount': amount,
                'time': time,
                'status': 'pending',
                'checkout_request_id': response['CheckoutRequestID']
            }

            try:
                with open('logs.json', 'r') as f:
                    logs = json.load(f)
            except FileNotFoundError:
                logs = []

            logs.append(new_log)

            with open('logs.json', 'w') as f:
                json.dump(logs, f, indent=4)

            flash('STK Push initiated successfully! Please check your phone.')
        else:
            flash('Failed to initiate STK Push. Please try again.')
            
    except Exception as e:
        flash(f'Error: {str(e)}')

    return redirect(url_for('index'))

@app.route('/logs')
@login_required
def view_logs():
    try:
        with open('logs.json', 'r') as f:
            logs = json.load(f)
    except FileNotFoundError:
        logs = []

    total_payments = sum(int(log['amount']) for log in logs)
    num_transactions = len(logs)

    return render_template('logs.html', logs=logs,
                         total_payments=total_payments,
                         num_transactions=num_transactions)

@app.route('/check_session')
@login_required
def check_session():
    if not current_user.is_authenticated:
        return jsonify({'active': False}), 401
    return jsonify({'active': True})

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        try:
            token = token.split(' ')[1]  # Remove 'Bearer ' prefix
            data = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=["HS256"])
            current_user = User(data['id'], data['username'], None)
        except:
            return jsonify({'message': 'Token is invalid!'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    try:
        with open('users.json', 'r') as f:
            users = json.load(f)
            user_data = next((u for u in users if u['username'] == username), None)
            
            if user_data and check_password_hash(user_data['password_hash'], password):
                token = jwt.encode({
                    'id': user_data['id'],
                    'username': user_data['username'],
                    'exp': datetime.utcnow() + timedelta(hours=24)
                }, app.config['JWT_SECRET_KEY'])
                return jsonify({
                    'token': token,
                    'message': 'Login successful'
                })
    except Exception as e:
        return jsonify({'message': str(e)}), 500
    
    return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/api/stk_push', methods=['POST'])
@token_required
def api_stk_push(current_user):
    data = request.get_json()
    name = data.get('name')
    phone = data.get('phone')
    amount = data.get('amount')
    time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # Format phone number
    phone = phone.replace('+254', '')
    if not phone.startswith('254'):
        phone = '254' + phone.lstrip('0')

    try:
        response = lipa_na_mpesa(phone, amount)
        
        if 'CheckoutRequestID' in response:
            new_log = {
                'name': name,
                'phone': phone,
                'amount': amount,
                'time': time,
                'status': 'pending',
                'checkout_request_id': response['CheckoutRequestID']
            }

            try:
                with open('logs.json', 'r') as f:
                    logs = json.load(f)
            except FileNotFoundError:
                logs = []

            logs.append(new_log)

            with open('logs.json', 'w') as f:
                json.dump(logs, f, indent=4)

            return jsonify({
                'message': 'STK Push initiated successfully',
                'checkout_request_id': response['CheckoutRequestID']
            })
        else:
            return jsonify({'message': 'Failed to initiate STK Push'}), 400
            
    except Exception as e:
        return jsonify({'message': str(e)}), 500

@app.route('/api/logs', methods=['GET'])
@token_required
def api_logs(current_user):
    try:
        with open('logs.json', 'r') as f:
            logs = json.load(f)
    except FileNotFoundError:
        logs = []

    total_payments = sum(int(log['amount']) for log in logs)
    num_transactions = len(logs)

    return jsonify({
        'logs': logs,
        'total_payments': total_payments,
        'num_transactions': num_transactions
    })

@app.errorhandler(500)
def internal_error(error):
    app.logger.error(f'Server Error: {error}')
    return render_template('error.html', error="An internal server error occurred. Please try again later."), 500

@app.errorhandler(404)
def not_found_error(error):
    return render_template('error.html', error="The requested page was not found."), 404

if __name__ == '__main__':
    app.run(debug=True) 