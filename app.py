from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import json
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-this-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Store logs
logs = []

# User Model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Logging function
def log_event(action, status, endpoint, user=None):
    log_entry = {
        'timestamp': datetime.now().isoformat(),
        'ip': request.remote_addr,
        'user': user if user else 'anonymous',
        'action': action,
        'status': status,
        'endpoint': endpoint,
        'user_agent': request.headers.get('User-Agent', 'Unknown')
    }
    logs.append(log_entry)
    print(f"[LOG] {log_entry}")
    return log_entry

# Routes
@app.route('/')
def home():
    log_event('page_view', 'success', '/', user=current_user.username if current_user.is_authenticated else None)
    return render_template('home.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        # Check if user exists
        if User.query.filter_by(username=username).first():
            log_event('signup', 'failed', '/signup', user=username)
            flash('Username already exists!', 'danger')
            return redirect(url_for('signup'))
        
        if User.query.filter_by(email=email).first():
            log_event('signup', 'failed', '/signup', user=email)
            flash('Email already registered!', 'danger')
            return redirect(url_for('signup'))
        
        # Create new user
        new_user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password, method='pbkdf2:sha256')
        )
        db.session.add(new_user)
        db.session.commit()
        
        log_event('signup', 'success', '/signup', user=username)
        flash('Account created successfully! Please login.', 'success')
        return redirect(url_for('login'))
    
    log_event('page_view', 'success', '/signup')
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            log_event('login', 'success', '/login', user=username)
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            log_event('login', 'failed', '/login', user=username)
            flash('Invalid username or password!', 'danger')
            return redirect(url_for('login'))
    
    log_event('page_view', 'success', '/login')
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    log_event('page_view', 'success', '/dashboard', user=current_user.username)
    return render_template('dashboard.html', user=current_user)

@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        log_event('unauthorized_access', 'failed', '/admin', user=current_user.username)
        flash('Unauthorized access!', 'danger')
        return redirect(url_for('dashboard'))
    
    log_event('page_view', 'success', '/admin', user=current_user.username)
    users = User.query.all()
    return render_template('admin.html', users=users)

@app.route('/profile')
@login_required
def profile():
    log_event('page_view', 'success', '/profile', user=current_user.username)
    return render_template('profile.html', user=current_user)

@app.route('/logout')
@login_required
def logout():
    log_event('logout', 'success', '/logout', user=current_user.username)
    logout_user()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('home'))

@app.route('/api/logs')
def get_logs():
    return jsonify(logs)

# Initialize database
with app.app_context():
    db.create_all()
    # Create default admin user if not exists
    if not User.query.filter_by(username='admin').first():
        admin = User(
            username='admin',
            email='admin@securecloud.com',
            password_hash=generate_password_hash('admin123', method='pbkdf2:sha256'),
            is_admin=True
        )
        db.session.add(admin)
        db.session.commit()
        print("[SYSTEM] Default admin user created: admin / admin123")

if __name__ == '__main__':
    print("=" * 50)
    print("SecureCloud Corp - Web Application")
    print("=" * 50)
    print("Visit: http://127.0.0.1:5000")
    print("Default Admin: admin / admin123")
    print("=" * 50)
    app.run(debug=True, port=5000)
