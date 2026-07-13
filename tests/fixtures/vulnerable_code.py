"""
Test fixtures - Intentionally vulnerable code samples for testing

⚠️ WARNING: This file contains intentionally vulnerable code for testing purposes.
DO NOT use these patterns in production code!
"""

# SQL Injection vulnerability
def get_user_by_id(user_id):
    """Vulnerable to SQL injection"""
    query = f"SELECT * FROM users WHERE id = {user_id}"  # VULNERABLE
    return execute_query(query)

def login(username, password):
    """Vulnerable to SQL injection"""
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"  # VULNERABLE
    return execute_query(query)

# XSS vulnerability
def display_user_comment(comment):
    """Vulnerable to XSS"""
    return f"<div>{comment}</div>"  # VULNERABLE - no escaping

# Command Injection
import os

def ping_host(hostname):
    """Vulnerable to command injection"""
    os.system(f"ping -c 4 {hostname}")  # VULNERABLE

# Path Traversal
def read_file(filename):
    """Vulnerable to path traversal"""
    with open(f"uploads/{filename}") as f:  # VULNERABLE
        return f.read()

# Hardcoded Secrets
API_KEY = "sk-1234567890abcdefghijklmnop"  # VULNERABLE
DATABASE_PASSWORD = "super_secret_password"  # VULNERABLE
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"  # VULNERABLE

# Weak Cryptography
import hashlib

def hash_password(password):
    """Weak password hashing"""
    return hashlib.md5(password.encode()).hexdigest()  # VULNERABLE

# Insecure Deserialization
import pickle

def load_user_data(data):
    """Vulnerable to deserialization attacks"""
    return pickle.loads(data)  # VULNERABLE

# Missing Authentication
def admin_delete_user(user_id):
    """No authentication check"""
    # Missing @login_required or authentication check
    User.objects.get(id=user_id).delete()  # VULNERABLE

# IDOR (Insecure Direct Object Reference)
def get_user_profile(request, user_id):
    """No ownership check"""
    user = User.objects.get(id=user_id)  # VULNERABLE - no ownership verification
    return user.profile

# SSRF (Server-Side Request Forgery)
import requests

def fetch_url(url):
    """Vulnerable to SSRF"""
    return requests.get(url).text  # VULNERABLE - no URL validation

# XXE (XML External Entity)
import xml.etree.ElementTree as ET

def parse_xml(xml_string):
    """Vulnerable to XXE"""
    return ET.fromstring(xml_string)  # VULNERABLE - external entities enabled

# Debug Mode Enabled
DEBUG = True  # VULNERABLE in production

# CORS Misconfiguration
CORS_ALLOW_ALL = "*"  # VULNERABLE

# Weak Session Token
import time
import random

def generate_session_token(user_id):
    """Predictable session token"""
    return f"{user_id}_{int(time.time())}_{random.randint(1000, 9999)}"  # VULNERABLE

# Missing Rate Limiting
def api_login(username, password):
    """No rate limiting"""
    # No rate limiting or brute force protection
    return authenticate(username, password)

# Information Disclosure
def handle_error(error):
    """Verbose error messages"""
    return f"Error: {error} at line {error.__traceback__.tb_lineno}"  # VULNERABLE

# Insecure Random
import random

def generate_password_reset_token():
    """Weak randomness"""
    return str(random.randint(100000, 999999))  # VULNERABLE - use secrets module

# NoSQL Injection
def find_user(username):
    """Vulnerable to NoSQL injection"""
    return db.users.find({"username": username})  # VULNERABLE if username from user input

# CSRF Missing Protection
def update_email(request):
    """No CSRF protection"""
    # Missing CSRF token validation
    user = request.user
    user.email = request.POST.get('email')
    user.save()

# Open Redirect
def redirect_after_login(request):
    """Vulnerable to open redirect"""
    next_url = request.GET.get('next', '/')
    return redirect(next_url)  # VULNERABLE - no URL validation

# Clickjacking - Missing X-Frame-Options
# No X-Frame-Options header set

# Missing HTTPS Enforcement
SESSION_COOKIE_SECURE = False  # VULNERABLE
CSRF_COOKIE_SECURE = False  # VULNERABLE

# Timing Attack Vulnerability
def compare_tokens(token1, token2):
    """Vulnerable to timing attacks"""
    return token1 == token2  # VULNERABLE - should use constant-time comparison

