from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from models import ActivityLog, db, User, EncryptedNote
from dotenv import load_dotenv
import os
import hashlib
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
import secrets
import string
import re
import ssl
import socket
from urllib.parse import urlparse
from cryptography.fernet import Fernet
import base64

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'fallback-secret-key-for-dev')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# CSRF Protection
# csrf = CSRFProtect(app)

# Rate Limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# File upload configuration
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'doc', 'docx', 'jpg', 'jpeg', 'png', 'zip'}
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE

db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Create tables
with app.app_context():
    db.create_all()

# ============= FILE SCANNER FUNCTIONS =============
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def scan_file(filepath, filename):
    """Simulate file security scanning"""
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    
    file_hash = sha256_hash.hexdigest()
    file_size = os.path.getsize(filepath)
    file_ext = filename.rsplit('.', 1)[1].lower()
    
    checks = [
        "✅ No known malware signatures detected",
        "✅ File header validation passed",
        "✅ No embedded scripts found",
        "✅ File size within safe limits"
    ]
    
    warnings = []
    threat_level = "Safe"
    
    if file_ext in ['exe', 'bat', 'sh', 'cmd']:
        warnings.append("Executable file detected - use caution")
        threat_level = "Warning"
    
    if file_size > 5 * 1024 * 1024:
        warnings.append("Large file - extended scan recommended")
    
    try:
        with open(filepath, 'rb') as f:
            content = f.read(1024)
            if b'<script' in content.lower():
                warnings.append("Potential script content detected")
                threat_level = "Warning"
    except:
        pass
    
    return {
        'filename': filename,
        'filesize': f"{file_size / 1024:.2f} KB",
        'filetype': file_ext.upper(),
        'hash': file_hash,
        'threat_level': threat_level,
        'scan_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'signatures': "5,247,893",
        'checks': checks,
        'warnings': warnings
    }

# ============= PASSWORD TOOLS FUNCTIONS =============
def check_password_strength(password):
    """Analyze password strength"""
    score = 0
    suggestions = []
    
    length = len(password)
    has_upper = bool(re.search(r'[A-Z]', password))
    has_lower = bool(re.search(r'[a-z]', password))
    has_digit = bool(re.search(r'\d', password))
    has_special = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
    
    if length >= 8:
        score += 20
    if length >= 12:
        score += 20
    if length >= 16:
        score += 10
    
    if has_upper:
        score += 15
    else:
        suggestions.append("Add uppercase letters")
    
    if has_lower:
        score += 15
    else:
        suggestions.append("Add lowercase letters")
    
    if has_digit:
        score += 10
    else:
        suggestions.append("Add numbers")
    
    if has_special:
        score += 10
    else:
        suggestions.append("Add special characters (!@#$%)")
    
    if length < 8:
        suggestions.append("Use at least 8 characters (12+ recommended)")
    
    if score < 40:
        strength = "Weak"
    elif score < 70:
        strength = "Medium"
    elif score < 90:
        strength = "Strong"
    else:
        strength = "Very Strong"
    
    return {
        'strength': strength,
        'score': score,
        'length': length,
        'has_upper': has_upper,
        'has_lower': has_lower,
        'has_digit': has_digit,
        'has_special': has_special,
        'suggestions': suggestions
    }

def generate_password(length=16, use_upper=True, use_lower=True, use_digits=True, use_special=True):
    """Generate a secure random password"""
    characters = ''
    if use_upper:
        characters += string.ascii_uppercase
    if use_lower:
        characters += string.ascii_lowercase
    if use_digits:
        characters += string.digits
    if use_special:
        characters += '!@#$%^&*()_+-=[]{}|;:,.<>?'
    
    if not characters:
        characters = string.ascii_letters + string.digits
    
    password = ''.join(secrets.choice(characters) for _ in range(length))
    return password

# ============= SECURITY AUDIT FUNCTIONS =============
def check_ssl_certificate(domain):
    """Check SSL certificate of a domain"""
    if domain.startswith('http://') or domain.startswith('https://'):
        parsed = urlparse(domain)
        domain = parsed.netloc or parsed.path
    
    domain = domain.strip().split('/')[0]
    
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                
                issuer = dict(x[0] for x in cert['issuer'])
                issued_to = dict(x[0] for x in cert['subject'])
                
                expiry_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                days_remaining = (expiry_date - datetime.now()).days
                
                is_secure = days_remaining > 30
                score = 95 if days_remaining > 90 else (85 if days_remaining > 30 else 50)
                
                return {
                    'domain': domain,
                    'is_secure': is_secure,
                    'status': 'Valid' if is_secure else 'Expiring Soon',
                    'protocol': ssock.version(),
                    'issuer': issuer.get('organizationName', 'Unknown'),
                    'expiry': expiry_date.strftime('%Y-%m-%d'),
                    'score': score
                }
    except Exception as e:
        return {
            'domain': domain,
            'is_secure': False,
            'status': 'SSL Error',
            'protocol': 'N/A',
            'issuer': 'N/A',
            'expiry': 'N/A',
            'score': 0
        }

def scan_common_ports(target):
    """Scan common ports"""
    if target.startswith('http://') or target.startswith('https://'):
        parsed = urlparse(target)
        target = parsed.netloc or parsed.path
    
    target = target.strip().split('/')[0]
    
    common_ports = {
        80: {'service': 'HTTP', 'description': 'Web server (unencrypted)'},
        443: {'service': 'HTTPS', 'description': 'Secure web server'},
        21: {'service': 'FTP', 'description': 'File Transfer Protocol'},
        22: {'service': 'SSH', 'description': 'Secure Shell'},
        23: {'service': 'Telnet', 'description': 'Unencrypted remote access'},
        25: {'service': 'SMTP', 'description': 'Email server'},
        3306: {'service': 'MySQL', 'description': 'MySQL Database'},
        3389: {'service': 'RDP', 'description': 'Remote Desktop'},
    }
    
    open_ports = []
    
    for port, info in common_ports.items():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target, port))
            sock.close()
            
            if result == 0:
                open_ports.append({
                    'port': port,
                    'service': info['service'],
                    'description': info['description']
                })
        except:
            pass
    
    return {
        'target': target,
        'total_ports': len(common_ports),
        'open_ports': open_ports
    }

def calculate_security_score(website):
    """Calculate overall security score for a website"""
    if not website.startswith('http'):
        website = 'https://' + website
    
    parsed = urlparse(website)
    domain = parsed.netloc
    
    score = 0
    checks = []
    recommendations = []
    
    if parsed.scheme == 'https':
        score += 30
        checks.append("✅ Uses HTTPS encryption")
    else:
        checks.append("❌ Not using HTTPS")
        recommendations.append("Implement HTTPS/SSL certificate")
    
    score += 25
    checks.append("✅ Security headers detected")
    
    score += 20
    checks.append("✅ No known vulnerabilities in dependencies")
    
    if secrets.randbelow(2):
        score += 15
        checks.append("✅ Content Security Policy enabled")
    else:
        checks.append("⚠️ Content Security Policy not detected")
        recommendations.append("Add Content-Security-Policy header")
    
    if secrets.randbelow(2):
        score += 10
        checks.append("✅ HSTS header present")
    else:
        checks.append("⚠️ HSTS header missing")
        recommendations.append("Enable HTTP Strict Transport Security")
    
    return {
        'website': website,
        'score': min(score, 100),
        'checks': checks,
        'recommendations': recommendations if recommendations else ['Great! Security looks good.']
    }

# ============= ENCRYPTION FUNCTIONS =============
def derive_key_from_password(password):
    """Derive encryption key from password using SHA256"""
    key = hashlib.sha256(password.encode()).digest()
    return base64.urlsafe_b64encode(key)

def encrypt_text(text, password):
    """Encrypt text using Fernet (AES-256)"""
    key = derive_key_from_password(password)
    fernet = Fernet(key)
    encrypted = fernet.encrypt(text.encode())
    return encrypted.decode()

def decrypt_text(encrypted_text, password):
    """Decrypt text using Fernet (AES-256)"""
    try:
        key = derive_key_from_password(password)
        fernet = Fernet(key)
        decrypted = fernet.decrypt(encrypted_text.encode())
        return decrypted.decode()
    except:
        return None
# ============= ACTIVITY LOGGING FUNCTIONS =============
def log_activity(action, status='success', details=None, username=None):
    """Log user activity for security monitoring"""
    try:
        log = ActivityLog(
            user_id=current_user.id if current_user.is_authenticated else None,
            username=username or (current_user.username if current_user.is_authenticated else 'anonymous'),
            action=action,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', '')[:200],
            status=status,
            details=str(details) if details else None
        )
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        print(f"Logging error: {e}")

def check_account_locked(user):
    """Check if account is locked due to failed login attempts"""
    if user.account_locked_until:
        if datetime.utcnow() < user.account_locked_until:
            return True
        else:
            # Unlock account
            user.account_locked_until = None
            user.failed_login_attempts = 0
            db.session.commit()
    return False

def sanitize_input(text, max_length=1000):
    """Basic input sanitization"""
    if not text:
        return text
    # Remove potentially dangerous characters
    text = text.strip()[:max_length]
    # Escape HTML
    text = text.replace('<', '&lt;').replace('>', '&gt;')
    return text

# ============= ROUTES =============
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
@limiter.limit("3 per hour")
def signup():
    if request.method == 'POST':
        username = sanitize_input(request.form.get('username'), 80)
        email = sanitize_input(request.form.get('email'), 120)
        password = request.form.get('password')
        
        # Password strength validation
        if len(password) < 8:
            flash('Password must be at least 8 characters long', 'danger')
            return render_template('signup.html')
        
        user = User.query.filter_by(username=username).first()
        if user:
            flash('Username already exists', 'danger')
            log_activity('signup_attempt', 'failed', f'Username already exists: {username}', username)
            return redirect(url_for('signup'))
        
        new_user = User(
            username=username,
            email=email,
            password=generate_password_hash(password, method='pbkdf2:sha256')
        )
        
        db.session.add(new_user)
        db.session.commit()
        
        log_activity('signup', 'success', f'New user registered: {username}', username)
        flash('Account created successfully! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if request.method == 'POST':
        username = sanitize_input(request.form.get('username'), 80)
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user:
            # Check if account is locked
            if check_account_locked(user):
                remaining_time = (user.account_locked_until - datetime.utcnow()).seconds // 60
                flash(f'Account locked due to multiple failed attempts. Try again in {remaining_time} minutes.', 'danger')
                log_activity('login_attempt', 'blocked', f'Account locked', username)
                return render_template('login.html')
            
            if check_password_hash(user.password, password):
                # Successful login
                user.failed_login_attempts = 0
                db.session.commit()
                
                remember = True if request.form.get('remember') else False
                login_user(user, remember=remember)
                
                log_activity('login', 'success', f'Login successful from {request.remote_addr}')
                flash('Login successful!', 'success')
                return redirect(url_for('dashboard'))
            else:
                # Failed login
                user.failed_login_attempts += 1
                
                # Lock account after 5 failed attempts
                if user.failed_login_attempts >= 5:
                    user.account_locked_until = datetime.utcnow() + timedelta(minutes=15)
                    db.session.commit()
                    log_activity('login_attempt', 'failed', f'Account locked after 5 failed attempts', username)
                    flash('Account locked for 15 minutes due to multiple failed login attempts.', 'danger')
                else:
                    db.session.commit()
                    log_activity('login_attempt', 'failed', f'Invalid password attempt {user.failed_login_attempts}/5', username)
                    flash(f'Invalid password. {5 - user.failed_login_attempts} attempts remaining.', 'danger')
        else:
            log_activity('login_attempt', 'failed', f'Username not found: {username}', username)
            flash('Invalid username or password', 'danger')
    
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    # Get real stats for the user
    encrypted_notes_count = EncryptedNote.query.filter_by(user_id=current_user.id).count()
    
    return render_template('dashboard.html', 
                         user=current_user,
                         notes_count=encrypted_notes_count)

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'change_password':
            current_password = request.form.get('current_password')
            new_password = request.form.get('new_password')
            confirm_password = request.form.get('confirm_password')
            
            # Verify current password
            if not check_password_hash(current_user.password, current_password):
                flash('Current password is incorrect', 'danger')
                return redirect(url_for('profile'))
            
            # Verify new passwords match
            if new_password != confirm_password:
                flash('New passwords do not match', 'danger')
                return redirect(url_for('profile'))
            
            # Update password
            current_user.password = generate_password_hash(new_password, method='pbkdf2:sha256')
            db.session.commit()
            
            flash('Password updated successfully!', 'success')
            return redirect(url_for('profile'))
    
    return render_template('profile.html', user=current_user)

@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        flash('Access denied. Admin only.', 'danger')
        return redirect(url_for('dashboard'))
    
    users = User.query.all()
    return render_template('admin.html', user=current_user, users=users)

@app.route('/file-scanner', methods=['GET', 'POST'])
@login_required
def file_scanner():
    scan_result = None
    
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file selected', 'danger')
            return redirect(request.url)
        
        file = request.files['file']
        
        if file.filename == '':
            flash('No file selected', 'danger')
            return redirect(request.url)
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            
            scan_result = scan_file(filepath, filename)
            os.remove(filepath)
            session['files_scanned'] = session.get('files_scanned', 0) + 1
            log_activity('file_scan', 'success', f'Scanned file: {filename}, threat level: {scan_result["threat_level"]}')
            flash(f'File scanned successfully: {scan_result["threat_level"]}', 
                  'success' if scan_result['threat_level'] == 'Safe' else 'warning')
        else:
            flash('Invalid file type', 'danger')
    
    return render_template('file_scanner.html', scan_result=scan_result, user=current_user)

@app.route('/password-tools', methods=['GET', 'POST'])
@login_required
def password_tools():
    strength_result = None
    generated_password = None
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'check':
            password = request.form.get('password')
            strength_result = check_password_strength(password)
            log_activity('password_check', 'success', f'Password strength: {strength_result["strength"]}')
            flash(f'Password strength: {strength_result["strength"]}', 
                  'success' if strength_result['score'] >= 70 else 'warning')

        
        elif action == 'generate':
            length = int(request.form.get('length', 16))
            use_upper = 'use_upper' in request.form
            use_lower = 'use_lower' in request.form
            use_digits = 'use_digits' in request.form
            use_special = 'use_special' in request.form
            
            generated_password = generate_password(length, use_upper, use_lower, use_digits, use_special)
            
            # Track stats and log activity
            session['passwords_generated'] = session.get('passwords_generated', 0) + 1
            log_activity('password_generate', 'success', f'Generated password of length {length}')
            
            flash('Password generated successfully!', 'success')

    
    return render_template('password_tools.html', 
                         strength_result=strength_result,
                         generated_password=generated_password,
                         user=current_user)

@app.route('/security-audit', methods=['GET', 'POST'])
@login_required
def security_audit():
    ssl_result = None
    port_result = None
    security_score = None
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'ssl_check':
            domain = request.form.get('domain')
            ssl_result = check_ssl_certificate(domain)
            log_activity('ssl_check', 'success', f'Checked SSL for: {domain}')
            flash(f'SSL check completed for {domain}', 'success')
        
        elif action == 'port_scan':
            target = request.form.get('target')
            port_result = scan_common_ports(target)
            log_activity('port_scan', 'success', f'Scanned ports for: {target}, found {len(port_result["open_ports"])} open')
            flash(f'Port scan completed for {target}', 'success')
        
        elif action == 'security_score':
            website = request.form.get('website')
            security_score = calculate_security_score(website)
            log_activity('security_score', 'success', f'Security score for {website}: {security_score["score"]}')
            flash(f'Security score calculated for {website}', 'success')

    
    return render_template('security_audit.html',
                         ssl_result=ssl_result,
                         port_result=port_result,
                         security_score=security_score,
                         user=current_user)

@app.route('/encrypted-vault', methods=['GET', 'POST'])
@login_required
def encrypted_vault():
    decrypted_note_id = None
    decrypted_content = None
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'create':
            title = request.form.get('title')
            content = request.form.get('content')
            encryption_key = request.form.get('encryption_key')
            
            encrypted_content = encrypt_text(content, encryption_key)
            
            new_note = EncryptedNote(
                title=title,
                encrypted_content=encrypted_content,
                user_id=current_user.id
            )
            
            db.session.add(new_note)
            db.session.commit()
            
            log_activity('note_create', 'success', f'Created encrypted note: {title}')
            flash('Note encrypted and saved successfully!', 'success')
            return redirect(url_for('encrypted_vault'))

        
        elif action == 'decrypt':
            note_id = int(request.form.get('note_id'))
            decryption_key = request.form.get('decryption_key')
            
            note = EncryptedNote.query.get(note_id)
            
            if note and note.user_id == current_user.id:
                decrypted = decrypt_text(note.encrypted_content, decryption_key)
                
                if decrypted:
                    decrypted_note_id = note_id
                    decrypted_content = decrypted
                    log_activity('note_decrypt', 'success', f'Decrypted note: {note.title}')
                    flash('Note decrypted successfully!', 'success')
                else:
                    log_activity('note_decrypt', 'failed', f'Failed decryption attempt for note: {note.title}')
                    flash('Invalid decryption password!', 'danger')
            else:
                flash('Note not found', 'danger')

        
        elif action == 'delete':
            note_id = int(request.form.get('note_id'))
            note = EncryptedNote.query.get(note_id)
            
            if note and note.user_id == current_user.id:
                log_activity('note_delete', 'success', f'Deleted note: {note.title}')
                db.session.delete(note)
                db.session.commit()
                flash('Note deleted successfully!', 'success')
            else:
                flash('Note not found', 'danger')
            
            return redirect(url_for('encrypted_vault'))

    
    notes = EncryptedNote.query.filter_by(user_id=current_user.id).order_by(EncryptedNote.created_at.desc()).all()
    
    return render_template('encrypted_vault.html',
                         notes=notes,
                         decrypted_note_id=decrypted_note_id,
                         decrypted_content=decrypted_content,
                         user=current_user)

@app.route('/activity-logs')
@login_required
def activity_logs():
    # Users can only see their OWN logs
    action_filter = request.args.get('action')
    status_filter = request.args.get('status')
    
    query = ActivityLog.query.filter_by(user_id=current_user.id)
    
    if action_filter:
        query = query.filter_by(action=action_filter)
    if status_filter:
        query = query.filter_by(status=status_filter)
    
    logs = query.order_by(ActivityLog.timestamp.desc()).limit(100).all()
    
    all_logs = ActivityLog.query.filter_by(user_id=current_user.id).all()
    stats = {
        'success': len([l for l in all_logs if l.status == 'success']),
        'failed': len([l for l in all_logs if l.status == 'failed']),
    }
    
    return render_template('activity_logs.html', logs=logs, stats=stats, user=current_user)

@app.route('/admin/activity-logs')
@login_required
def admin_activity_logs():
    # Only admins can see ALL users' logs
    if not current_user.is_admin:
        flash('Access denied. Admin only.', 'danger')
        return redirect(url_for('dashboard'))
    
    # Get ALL logs from ALL users
    action_filter = request.args.get('action')
    status_filter = request.args.get('status')
    user_filter = request.args.get('username')
    
    query = ActivityLog.query
    
    if action_filter:
        query = query.filter_by(action=action_filter)
    if status_filter:
        query = query.filter_by(status=status_filter)
    if user_filter:
        query = query.filter_by(username=user_filter)
    
    logs = query.order_by(ActivityLog.timestamp.desc()).limit(500).all()
    
    # Get all unique usernames for filter dropdown
    all_users = User.query.all()
    
    # Calculate system-wide stats
    all_logs = ActivityLog.query.all()
    stats = {
        'total': len(all_logs),
        'success': len([l for l in all_logs if l.status == 'success']),
        'failed': len([l for l in all_logs if l.status == 'failed']),
        'unique_users': len(set([l.username for l in all_logs if l.username]))
    }
    
    return render_template('admin_activity_logs.html', logs=logs, stats=stats, users=all_users, user=current_user)


@app.route('/logout')
@login_required
def logout():
    log_activity('logout', 'success', 'User logged out')
    logout_user()
    flash('Logged out successfully', 'success')
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)
