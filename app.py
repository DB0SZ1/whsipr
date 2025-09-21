import os
import json
import uuid
import hashlib
import logging
import threading
import requests
import time
from datetime import datetime
from functools import wraps
from urllib.parse import urlparse

from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
from werkzeug.middleware.proxy_fix import ProxyFix

# Initialize Flask app
app = Flask(__name__)

# Production Configuration
class Config:
    # Security
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-key-change-in-production'
    
    # Database files
    DATA_DIR = os.environ.get('DATA_DIR', 'data')
    MESSAGES_FILE = os.path.join(DATA_DIR, 'messages.json')
    USERS_FILE = os.path.join(DATA_DIR, 'users.json')
    ACCOUNTS_FILE = os.path.join(DATA_DIR, 'accounts.json')
    
    # App settings
    MAX_MESSAGE_LENGTH = int(os.environ.get('MAX_MESSAGE_LENGTH', '1000'))
    MAX_NAME_LENGTH = int(os.environ.get('MAX_NAME_LENGTH', '50'))
    MIN_PASSWORD_LENGTH = int(os.environ.get('MIN_PASSWORD_LENGTH', '8'))
    
    # URL settings
    CUSTOM_DOMAIN = os.environ.get('CUSTOM_DOMAIN')  # e.g., 'anonymsg.com'
    FORCE_HTTPS = os.environ.get('FORCE_HTTPS', 'false').lower() == 'true'
    
    # Keep-alive settings
    ENABLE_KEEP_ALIVE = os.environ.get('ENABLE_KEEP_ALIVE', 'true').lower() == 'true'
    KEEP_ALIVE_INTERVAL = int(os.environ.get('KEEP_ALIVE_INTERVAL', '840'))  # 14 minutes

app.config.from_object(Config)

# Production middleware for handling reverse proxy headers
if not app.debug:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

# Setup logging for production
if not app.debug:
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)
else:
    logger = app.logger

# Ensure data directory exists
os.makedirs(app.config['DATA_DIR'], exist_ok=True)

# Keep-alive functionality
class AppKeepAlive:
    """Keep the Flask app alive by pinging itself periodically"""
    
    def __init__(self, ping_interval=840):  # 14 minutes (before 15-min timeout)
        self.ping_interval = ping_interval
        self.running = False
        self.thread = None
        self.app_url = None
        self.start_time = time.time()
        self.ping_count = 0
        self.last_ping_time = None
        self.failed_pings = 0
        
    def get_app_url(self):
        """Determine the app URL from environment variables"""
        # Check common hosting platform environment variables
        app_url = (
            os.environ.get('RENDER_EXTERNAL_URL') or      # Render
            os.environ.get('RAILWAY_STATIC_URL') or       # Railway  
            os.environ.get('CUSTOM_DOMAIN') or            # Custom domain
            os.environ.get('HEROKU_APP_NAME')             # Heroku
        )
        
        if app_url:
            # Format Heroku URL properly
            if 'heroku' in str(app_url).lower() and not app_url.startswith('http'):
                app_url = f"https://{app_url}.herokuapp.com"
            # Ensure URL has protocol
            elif not app_url.startswith('http'):
                app_url = f"https://{app_url}"
            
            return app_url.rstrip('/')
        
        # Fallback - will be set when first request comes in
        return None
    
    def set_url_from_request(self, request_obj):
        """Set app URL from the first incoming request"""
        if not self.app_url:
            self.app_url = f"{request_obj.scheme}://{request_obj.host}"
            if not self.running and app.config['ENABLE_KEEP_ALIVE'] and not app.debug:
                self.start()
    
    def start(self):
        """Start the keep-alive pinger"""
        if not self.running and app.config['ENABLE_KEEP_ALIVE'] and not app.debug:
            self.app_url = self.get_app_url()
            if self.app_url:
                self.running = True
                self.thread = threading.Thread(target=self._ping_loop, daemon=True)
                self.thread.start()
                logger.info(f"Keep-alive started: pinging {self.app_url}/health every {self.ping_interval}s")
            else:
                logger.info("Keep-alive waiting for app URL...")
    
    def stop(self):
        """Stop the keep-alive pinger"""
        self.running = False
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=5)
        logger.info("Keep-alive stopped")
    
    def _ping_loop(self):
        """Internal ping loop"""
        # Wait a bit before starting to ping (let app fully start)
        time.sleep(120)  # Wait 2 minutes before first ping
        
        while self.running:
            try:
                if self.app_url:
                    response = requests.get(
                        f"{self.app_url}/health",
                        timeout=30,
                        headers={
                            'User-Agent': 'KeepAlive-Bot/1.0',
                            'X-Keep-Alive': 'internal'
                        }
                    )
                    if response.status_code == 200:
                        self.ping_count += 1
                        self.last_ping_time = time.time()
                        self.failed_pings = 0
                        logger.debug(f"Keep-alive ping #{self.ping_count} successful")
                    else:
                        self.failed_pings += 1
                        logger.warning(f"Keep-alive ping failed with status: {response.status_code}")
                else:
                    logger.warning("Keep-alive: No app URL available")
            except requests.exceptions.RequestException as e:
                self.failed_pings += 1
                logger.warning(f"Keep-alive ping failed: {e}")
            except Exception as e:
                self.failed_pings += 1
                logger.error(f"Keep-alive unexpected error: {e}")
            
            # If too many failed pings, try to restart
            if self.failed_pings > 5:
                logger.error("Too many failed pings, attempting to restart keep-alive...")
                time.sleep(300)  # Wait 5 minutes before retrying
                self.failed_pings = 0
            else:
                time.sleep(self.ping_interval)
    
    def get_status(self):
        """Get keep-alive status"""
        return {
            'running': self.running,
            'app_url': self.app_url,
            'uptime': time.time() - self.start_time,
            'ping_count': self.ping_count,
            'last_ping': self.last_ping_time,
            'failed_pings': self.failed_pings,
            'interval': self.ping_interval
        }

# Global keep-alive instance
keep_alive = AppKeepAlive(app.config['KEEP_ALIVE_INTERVAL'])

# Helper functions
def get_base_url():
    """Get the base URL for the application"""
    if app.config['CUSTOM_DOMAIN']:
        protocol = 'https' if app.config['FORCE_HTTPS'] else 'http'
        return f"{protocol}://{app.config['CUSTOM_DOMAIN']}"
    else:
        # Fallback to request host
        return request.host_url.rstrip('/')

def load_json_file(filepath):
    """Generic function to load JSON files with error handling"""
    try:
        if os.path.exists(filepath):
            with open(filepath, 'r', encoding='utf-8') as f:
                return json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        logger.error(f"Error loading {filepath}: {e}")
    return []

def save_json_file(filepath, data):
    """Generic function to save JSON files with error handling"""
    try:
        # Create backup
        if os.path.exists(filepath):
            backup_path = f"{filepath}.backup"
            os.rename(filepath, backup_path)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
        # Remove backup on success
        backup_path = f"{filepath}.backup"
        if os.path.exists(backup_path):
            os.remove(backup_path)
            
    except IOError as e:
        logger.error(f"Error saving {filepath}: {e}")
        # Restore backup if save failed
        backup_path = f"{filepath}.backup"
        if os.path.exists(backup_path):
            os.rename(backup_path, filepath)
        raise

def load_messages():
    """Load messages from JSON file"""
    return load_json_file(app.config['MESSAGES_FILE'])

def save_messages(messages):
    """Save messages to JSON file"""
    save_json_file(app.config['MESSAGES_FILE'], messages)

def load_users():
    """Load users from JSON file"""
    return load_json_file(app.config['USERS_FILE'])

def save_users(users):
    """Save users to JSON file"""
    save_json_file(app.config['USERS_FILE'], users)

def load_accounts():
    """Load accounts from JSON file"""
    return load_json_file(app.config['ACCOUNTS_FILE'])

def save_accounts(accounts):
    """Save accounts to JSON file"""
    save_json_file(app.config['ACCOUNTS_FILE'], accounts)

def hash_password(password):
    """Hash password with salt using PBKDF2"""
    salt = os.urandom(32)
    pwdhash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return (salt + pwdhash).hex()

def verify_password(stored_password, provided_password):
    """Verify a password against its hash"""
    try:
        stored_bytes = bytes.fromhex(stored_password)
        salt = stored_bytes[:32]
        stored_pwdhash = stored_bytes[32:]
        pwdhash = hashlib.pbkdf2_hmac('sha256', provided_password.encode('utf-8'), salt, 100000)
        return pwdhash == stored_pwdhash
    except (ValueError, TypeError):
        return False

def login_required(f):
    """Decorator to require login for certain routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def generate_user_id():
    """Generate a unique user ID"""
    return str(uuid.uuid4()).replace('-', '')[:12]

def sanitize_input(text, max_length=None):
    """Sanitize user input"""
    if not text:
        return ""
    text = text.strip()
    if max_length:
        text = text[:max_length]
    return text

def validate_email(email):
    """Basic email validation"""
    import re
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

# Middleware to capture app URL from first request and start keep-alive
@app.before_request
def before_request():
    global keep_alive
    if keep_alive and not keep_alive.app_url:
        keep_alive.set_url_from_request(request)

# Security headers
@app.after_request
def add_security_headers(response):
    """Add security headers to all responses"""
    if not app.debug:
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        if app.config['FORCE_HTTPS']:
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal error: {error}")
    return render_template('500.html'), 500

@app.errorhandler(403)
def forbidden(error):
    return render_template('403.html'), 403

# Health check and monitoring endpoints
@app.route('/health')
def health_check():
    """Health check endpoint for keep-alive and monitoring"""
    is_keep_alive_request = request.headers.get('X-Keep-Alive') == 'internal'
    
    status = {
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'uptime': time.time() - keep_alive.start_time,
    }
    
    # Add detailed info for non-keep-alive requests
    if not is_keep_alive_request:
        status.update({
            'keep_alive': keep_alive.get_status(),
            'app_info': {
                'debug': app.debug,
                'config': {
                    'enable_keep_alive': app.config['ENABLE_KEEP_ALIVE'],
                    'keep_alive_interval': app.config['KEEP_ALIVE_INTERVAL'],
                    'custom_domain': app.config['CUSTOM_DOMAIN'],
                }
            }
        })
    
    return jsonify(status)

@app.route('/ping')
def ping_endpoint():
    """Simple ping endpoint for external keep-alive services"""
    return jsonify({
        'status': 'pong',
        'timestamp': datetime.now().isoformat(),
        'uptime': time.time() - keep_alive.start_time,
        'version': '1.0'
    })

@app.route('/keep-alive/status')
def keep_alive_status():
    """Detailed keep-alive status endpoint"""
    return jsonify(keep_alive.get_status())

# Authentication Routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page and handler"""
    if request.method == 'POST':
        try:
            data = request.get_json()
            if not data:
                return jsonify({'success': False, 'error': 'Invalid request data'})
            
            email = sanitize_input(data.get('email', '')).lower()
            password = data.get('password', '')
            
            if not email or not password:
                return jsonify({'success': False, 'error': 'Email and password are required'})
            
            if not validate_email(email):
                return jsonify({'success': False, 'error': 'Invalid email format'})
            
            accounts = load_accounts()
            account = next((acc for acc in accounts if acc['email'] == email), None)
            
            if not account or not verify_password(account['password'], password):
                return jsonify({'success': False, 'error': 'Invalid email or password'})
            
            # Set session
            session.permanent = True
            session['user_id'] = account['user_id']
            session['email'] = account['email']
            session['name'] = account['name']
            
            return jsonify({'success': True, 'redirect': url_for('dashboard')})
            
        except Exception as e:
            logger.error(f"Login error: {e}")
            return jsonify({'success': False, 'error': 'An error occurred during login'})
    
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """Signup page and handler"""
    if request.method == 'POST':
        try:
            data = request.get_json()
            if not data:
                return jsonify({'success': False, 'error': 'Invalid request data'})
            
            name = sanitize_input(data.get('name', ''), app.config['MAX_NAME_LENGTH'])
            email = sanitize_input(data.get('email', '')).lower()
            password = data.get('password', '')
            
            # Validation
            if not name or not email or not password:
                return jsonify({'success': False, 'error': 'All fields are required'})
            
            if not validate_email(email):
                return jsonify({'success': False, 'error': 'Invalid email format'})
            
            if len(password) < app.config['MIN_PASSWORD_LENGTH']:
                return jsonify({'success': False, 'error': f'Password must be at least {app.config["MIN_PASSWORD_LENGTH"]} characters'})
            
            if len(name) > app.config['MAX_NAME_LENGTH']:
                return jsonify({'success': False, 'error': f'Name too long (max {app.config["MAX_NAME_LENGTH"]} characters)'})
            
            # Check if email already exists
            accounts = load_accounts()
            if any(acc['email'] == email for acc in accounts):
                return jsonify({'success': False, 'error': 'Email already registered'})
            
            # Generate unique user ID
            user_id = generate_user_id()
            existing_ids = [acc['user_id'] for acc in accounts]
            while user_id in existing_ids:
                user_id = generate_user_id()
            
            # Create account
            new_account = {
                'user_id': user_id,
                'name': name,
                'email': email,
                'password': hash_password(password),
                'created_at': datetime.now().isoformat()
            }
            
            accounts.append(new_account)
            save_accounts(accounts)
            
            # Create user profile
            users = load_users()
            new_user = {
                'user_id': user_id,
                'name': name,
                'created_at': datetime.now().isoformat(),
                'message_count': 0
            }
            users.append(new_user)
            save_users(users)
            
            # Set session
            session.permanent = True
            session['user_id'] = user_id
            session['email'] = email
            session['name'] = name
            
            return jsonify({'success': True, 'redirect': url_for('dashboard')})
            
        except Exception as e:
            logger.error(f"Signup error: {e}")
            return jsonify({'success': False, 'error': 'An error occurred during signup'})
    
    return render_template('signup.html')

@app.route('/logout')
def logout():
    """Logout handler"""
    session.clear()
    return redirect(url_for('landing'))

@app.route('/dashboard')
@login_required
def dashboard():
    """Dashboard - redirect to admin page for logged in user"""
    user_id = session.get('user_id')
    return redirect(url_for('admin', user_id=user_id))

# Main Routes
@app.route('/')
def landing():
    """Landing page - redirect to login if not authenticated"""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/home')
def home():
    """Original landing page for creating anonymous message links"""
    return render_template('landing.html')

@app.route('/create', methods=['POST'])
def create_user():
    """Create a new user and generate their message link"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'Invalid request data'})
        
        name = sanitize_input(data.get('name', ''), app.config['MAX_NAME_LENGTH'])
        
        if not name:
            return jsonify({'success': False, 'error': 'Name is required'})
        
        if len(name) > app.config['MAX_NAME_LENGTH']:
            return jsonify({'success': False, 'error': f'Name too long (max {app.config["MAX_NAME_LENGTH"]} characters)'})
        
        # Generate unique user ID
        user_id = generate_user_id()
        users = load_users()
        
        # Ensure user_id is unique
        existing_ids = [user['user_id'] for user in users]
        while user_id in existing_ids:
            user_id = generate_user_id()
        
        # Create new user
        new_user = {
            'user_id': user_id,
            'name': name,
            'created_at': datetime.now().isoformat(),
            'message_count': 0
        }
        
        users.append(new_user)
        save_users(users)
        
        base_url = get_base_url()
        message_url = f"{base_url}/anonymous/{name.replace(' ', '-').lower()}/{user_id}"
        admin_url = f"{base_url}/admin/{user_id}"
        
        return jsonify({
            'success': True,
            'user_id': user_id,
            'message_url': message_url,
            'admin_url': admin_url,
            'name': name
        })
        
    except Exception as e:
        logger.error(f"Create user error: {e}")
        return jsonify({'success': False, 'error': 'An error occurred while creating user'})

@app.route('/anonymous/<name>/<user_id>')
@app.route('/m/<user_id>')  # Keep old route for backward compatibility
def message_form(user_id, name=None):
    """Message form for a specific user"""
    try:
        users = load_users()
        user = next((u for u in users if u['user_id'] == user_id), None)
        
        if not user:
            return render_template('404.html'), 404
        
        # If accessed via old route, redirect to new pretty URL
        if name is None:
            formatted_name = user['name'].replace(' ', '-').lower()
            return redirect(url_for('message_form', name=formatted_name, user_id=user_id), code=301)
        
        return render_template('message.html', user=user)
        
    except Exception as e:
        logger.error(f"Message form error: {e}")
        return render_template('500.html'), 500

@app.route('/send/<user_id>', methods=['POST'])
def send_message(user_id):
    """Handle sending anonymous messages to a specific user"""
    try:
        users = load_users()
        user = next((u for u in users if u['user_id'] == user_id), None)
        
        if not user:
            return jsonify({'success': False, 'error': 'User not found'})
        
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'Invalid request data'})
        
        message = sanitize_input(data.get('message', ''), app.config['MAX_MESSAGE_LENGTH'])
        
        if not message:
            return jsonify({'success': False, 'error': 'Message cannot be empty'})
        
        if len(message) > app.config['MAX_MESSAGE_LENGTH']:
            return jsonify({'success': False, 'error': f'Message too long (max {app.config["MAX_MESSAGE_LENGTH"]} characters)'})
        
        # Load existing messages
        messages = load_messages()
        
        # Generate message ID
        message_id = max([msg.get('id', 0) for msg in messages], default=0) + 1
        
        # Add new message
        new_message = {
            'id': message_id,
            'user_id': user_id,
            'message': message,
            'timestamp': datetime.now().isoformat(),
            'read': False,
            'ip_hash': hashlib.sha256(request.remote_addr.encode()).hexdigest()[:8]  # For basic spam prevention
        }
        
        messages.append(new_message)
        save_messages(messages)
        
        # Update user message count
        for u in users:
            if u['user_id'] == user_id:
                u['message_count'] = u.get('message_count', 0) + 1
                break
        save_users(users)
        
        return jsonify({'success': True, 'message': f'Your anonymous message has been sent to {user["name"]}!'})
        
    except Exception as e:
        logger.error(f"Send message error: {e}")
        return jsonify({'success': False, 'error': 'An error occurred while sending the message'})

@app.route('/admin/<user_id>')
@login_required
def admin(user_id):
    """Admin page to view messages for a specific user"""
    try:
        # Check if user is accessing their own admin page
        if session.get('user_id') != user_id:
            return render_template('403.html'), 403
        
        users = load_users()
        user = next((u for u in users if u['user_id'] == user_id), None)
        
        if not user:
            return render_template('404.html'), 404
        
        messages = load_messages()
        user_messages = [msg for msg in messages if msg['user_id'] == user_id]
        # Sort by newest first
        user_messages.sort(key=lambda x: x['timestamp'], reverse=True)
        
        # Generate the pretty message URL
        base_url = get_base_url()
        formatted_name = user['name'].replace(' ', '-').lower()
        pretty_message_url = f"{base_url}/anonymous/{formatted_name}/{user_id}"
        
        return render_template('admin.html', 
                             messages=user_messages, 
                             user=user, 
                             message_url=pretty_message_url)
        
    except Exception as e:
        logger.error(f"Admin page error: {e}")
        return render_template('500.html'), 500

@app.route('/mark_read/<user_id>/<int:message_id>')
@login_required
def mark_read(user_id, message_id):
    """Mark a message as read"""
    try:
        # Check if user is accessing their own messages
        if session.get('user_id') != user_id:
            return render_template('403.html'), 403
        
        messages = load_messages()
        for msg in messages:
            if msg['id'] == message_id and msg['user_id'] == user_id:
                msg['read'] = True
                break
        save_messages(messages)
        
        return redirect(url_for('admin', user_id=user_id))
        
    except Exception as e:
        logger.error(f"Mark read error: {e}")
        return render_template('500.html'), 500

@app.route('/delete/<user_id>/<int:message_id>')
@login_required
def delete_message(user_id, message_id):
    """Delete a message"""
    try:
        # Check if user is accessing their own messages
        if session.get('user_id') != user_id:
            return render_template('403.html'), 403
        
        messages = load_messages()
        original_count = len(messages)
        messages = [msg for msg in messages if not (msg['id'] == message_id and msg['user_id'] == user_id)]
        
        if len(messages) < original_count:
            save_messages(messages)
            
            # Update user message count
            users = load_users()
            for user in users:
                if user['user_id'] == user_id:
                    user['message_count'] = max(0, user.get('message_count', 0) - 1)
                    break
            save_users(users)
        
        return redirect(url_for('admin', user_id=user_id))
        
    except Exception as e:
        logger.error(f"Delete message error: {e}")
        return render_template('500.html'), 500

# Initialize keep-alive on startup
def initialize_keep_alive():
    """Initialize keep-alive after app startup"""
    if app.config['ENABLE_KEEP_ALIVE'] and not app.debug:
        # Try to start keep-alive immediately if URL is available
        keep_alive.start()

if __name__ == '__main__':
    # Development mode
    port = int(os.environ.get('PORT', 5001))
    host = os.environ.get('HOST', '127.0.0.1')
    debug = os.environ.get('FLASK_DEBUG', 'True').lower() == 'true'
    
    # Create templates directory if it doesn't exist
    if not os.path.exists('templates'):
        os.makedirs('templates')
    
    # Initialize keep-alive after a short delay in production
    if not debug:
        def delayed_start():
            time.sleep(10)  # Wait for app to be fully ready
            initialize_keep_alive()
        
        threading.Thread(target=delayed_start, daemon=True).start()
    
    try:
        app.run(debug=debug, host=host, port=port)
    except KeyboardInterrupt:
        logger.info("Application stopped by user")
        keep_alive.stop()
    except Exception as e:
        logger.error(f"Application error: {e}")
        keep_alive.stop()
        raise