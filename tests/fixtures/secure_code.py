"""
Test fixtures - Secure code examples

These demonstrate proper security practices that should NOT trigger findings.
"""

import hashlib
import secrets
import hmac
from urllib.parse import urlparse

# Secure SQL queries using parameterized statements
def get_user_by_id_secure(user_id):
    """Secure parameterized query"""
    query = "SELECT * FROM users WHERE id = %s"
    return execute_query(query, (user_id,))  # SECURE

def login_secure(username, password):
    """Secure authentication with parameterized query"""
    query = "SELECT * FROM users WHERE username = %s"
    user = execute_query(query, (username,))
    
    if user and verify_password(password, user.password_hash):
        return user
    return None

# Secure XSS prevention with HTML escaping
from html import escape

def display_user_comment_secure(comment):
    """XSS prevention through escaping"""
    return f"<div>{escape(comment)}</div>"  # SECURE

# Secure command execution
import subprocess

def ping_host_secure(hostname):
    """Secure command execution"""
    # Validate hostname
    if not hostname.replace('.', '').replace('-', '').isalnum():
        raise ValueError("Invalid hostname")
    
    # Use list form (no shell=True)
    result = subprocess.run(['ping', '-c', '4', hostname], 
                          capture_output=True, check=True)  # SECURE
    return result.stdout

# Secure file access with path validation
import os
from pathlib import Path

def read_file_secure(filename):
    """Secure file reading with path traversal prevention"""
    # Validate filename
    if '..' in filename or filename.startswith('/'):
        raise ValueError("Invalid filename")
    
    upload_dir = Path("uploads").resolve()
    file_path = (upload_dir / filename).resolve()
    
    # Ensure file is within upload directory
    if not str(file_path).startswith(str(upload_dir)):
        raise ValueError("Path traversal attempt detected")
    
    with open(file_path) as f:  # SECURE
        return f.read()

# Secure secret management
import os

API_KEY = os.environ.get('API_KEY')  # SECURE - from environment
DATABASE_PASSWORD = os.environ.get('DB_PASSWORD')  # SECURE
AWS_ACCESS_KEY = os.environ.get('AWS_ACCESS_KEY_ID')  # SECURE

# Secure password hashing
import bcrypt

def hash_password_secure(password):
    """Secure password hashing with bcrypt"""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt)  # SECURE

def verify_password(password, hashed):
    """Secure password verification"""
    return bcrypt.checkpw(password.encode(), hashed)  # SECURE

# Secure deserialization
import json

def load_user_data_secure(data):
    """Secure JSON deserialization"""
    return json.loads(data)  # SECURE - JSON is safe

# Proper authentication decorator
from functools import wraps

def login_required(f):
    """Authentication decorator"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            abort(401)
        return f(*args, **kwargs)
    return decorated_function

@login_required
def admin_delete_user_secure(user_id):
    """With authentication check"""
    User.objects.get(id=user_id).delete()  # SECURE

# Secure IDOR prevention
@login_required
def get_user_profile_secure(request, user_id):
    """With ownership check"""
    user = User.objects.get(id=user_id)
    
    # Verify ownership
    if user.id != request.user.id and not request.user.is_admin:
        abort(403)  # Forbidden
    
    return user.profile  # SECURE

# Secure SSRF prevention
import requests
from urllib.parse import urlparse

ALLOWED_HOSTS = ['api.example.com', 'data.example.com']

def fetch_url_secure(url):
    """SSRF prevention with URL validation"""
    parsed = urlparse(url)
    
    # Block private IPs and metadata endpoints
    if parsed.hostname in ['localhost', '127.0.0.1', '169.254.169.254']:
        raise ValueError("Access to internal URLs is forbidden")
    
    # Whitelist allowed hosts
    if parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError("Host not in allowlist")
    
    return requests.get(url, timeout=5).text  # SECURE

# Secure XML parsing (XXE prevention)
import xml.etree.ElementTree as ET

def parse_xml_secure(xml_string):
    """XXE prevention"""
    parser = ET.XMLParser()
    parser.entity = {}  # Disable entity processing
    return ET.fromstring(xml_string, parser=parser)  # SECURE

# Proper configuration
DEBUG = False  # SECURE - debug disabled in production

# Secure CORS configuration
CORS_ALLOWED_ORIGINS = [
    'https://app.example.com',
    'https://www.example.com'
]  # SECURE

# Cryptographically secure session token
def generate_session_token_secure(user_id):
    """Cryptographically secure random token"""
    return secrets.token_urlsafe(32)  # SECURE

# Rate limiting decorator
from time import time
from functools import wraps

rate_limit_store = {}

def rate_limit(max_requests=5, window=60):
    """Rate limiting decorator"""
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            now = time()
            key = f"{request.remote_addr}:{f.__name__}"
            
            if key in rate_limit_store:
                requests_list = rate_limit_store[key]
                # Remove old requests outside window
                requests_list = [r for r in requests_list if now - r < window]
                
                if len(requests_list) >= max_requests:
                    abort(429)  # Too Many Requests
                
                requests_list.append(now)
                rate_limit_store[key] = requests_list
            else:
                rate_limit_store[key] = [now]
            
            return f(*args, **kwargs)
        return wrapped
    return decorator

@rate_limit(max_requests=5, window=60)
def api_login_secure(username, password):
    """With rate limiting"""
    return authenticate(username, password)  # SECURE

# Secure error handling
def handle_error_secure(error):
    """Generic error messages"""
    log_error(error)  # Log detailed error server-side
    return "An error occurred. Please try again."  # SECURE - generic message

# Cryptographically secure random
def generate_password_reset_token_secure():
    """Secure random token generation"""
    return secrets.token_urlsafe(32)  # SECURE

# Secure MongoDB query (NoSQL injection prevention)
def find_user_secure(username):
    """Secure MongoDB query"""
    # Sanitize input
    if not isinstance(username, str):
        raise ValueError("Username must be string")
    
    return db.users.find_one({"username": username})  # SECURE

# CSRF protection
from django.views.decorators.csrf import csrf_protect

@csrf_protect
def update_email_secure(request):
    """With CSRF protection"""
    user = request.user
    user.email = request.POST.get('email')
    user.save()  # SECURE

# Secure redirect with URL validation
ALLOWED_REDIRECT_HOSTS = ['www.example.com', 'app.example.com']

def redirect_after_login_secure(request):
    """Secure redirect with validation"""
    next_url = request.GET.get('next', '/')
    
    # Validate redirect URL
    parsed = urlparse(next_url)
    if parsed.hostname and parsed.hostname not in ALLOWED_REDIRECT_HOSTS:
        next_url = '/'
    
    return redirect(next_url)  # SECURE

# Security headers
SECURE_HEADERS = {
    'X-Frame-Options': 'DENY',
    'X-Content-Type-Options': 'nosniff',
    'X-XSS-Protection': '1; mode=block',
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains'
}  # SECURE

# HTTPS enforcement
SESSION_COOKIE_SECURE = True  # SECURE
CSRF_COOKIE_SECURE = True  # SECURE
SESSION_COOKIE_HTTPONLY = True  # SECURE

# Constant-time comparison (timing attack prevention)
def compare_tokens_secure(token1, token2):
    """Timing-attack resistant comparison"""
    return hmac.compare_digest(token1, token2)  # SECURE

