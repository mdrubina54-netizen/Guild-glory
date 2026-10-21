#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Guild Glory - Web Management System
Flask Backend with Anti-DDoS Protection
"""

import os
import json
import subprocess
import threading
import time
import hashlib
import hmac
from datetime import datetime, timedelta
from functools import wraps
from collections import defaultdict
from flask import Flask, render_template, request, jsonify, session, send_from_directory
from flask_cors import CORS
import logging

# ═══════════════════════════════════════════════════════
#  CONFIGURATION
# ═══════════════════════════════════════════════════════

app = Flask(__name__, static_folder='.', static_url_path='')
app.secret_key = os.environ.get('SECRET_KEY', 'guild-glory-secret-key-2026')
CORS(app)

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════
#  ANTI-DDoS & SECURITY
# ═══════════════════════════════════════════════════════

class RateLimiter:
    """Rate limiting to prevent DDoS attacks"""
    def __init__(self, max_requests=30, window_seconds=60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests = defaultdict(list)
        self.blocked_ips = {}

    def is_blocked(self, ip):
        """Check if IP is currently blocked"""
        if ip in self.blocked_ips:
            if datetime.now() < self.blocked_ips[ip]:
                return True
            else:
                del self.blocked_ips[ip]
        return False

    def check(self, ip):
        """Check if request is allowed"""
        if self.is_blocked(ip):
            return False, "IP temporarily blocked due to rate limit"

        now = datetime.now()
        cutoff = now - timedelta(seconds=self.window_seconds)

        # Clean old requests
        self.requests[ip] = [req_time for req_time in self.requests[ip] if req_time > cutoff]

        # Check limit
        if len(self.requests[ip]) >= self.max_requests:
            # Block for 5 minutes
            self.blocked_ips[ip] = now + timedelta(minutes=5)
            logger.warning(f"IP {ip} blocked for excessive requests")
            return False, "Rate limit exceeded. Try again later."

        self.requests[ip].append(now)
        return True, "OK"

    def get_stats(self):
        """Get rate limiter statistics"""
        return {
            'active_ips': len(self.requests),
            'blocked_ips': len(self.blocked_ips),
            'total_requests': sum(len(reqs) for reqs in self.requests.values())
        }

# Initialize rate limiter
rate_limiter = RateLimiter(max_requests=30, window_seconds=60)

def rate_limit(f):
    """Decorator for rate limiting"""
    @wraps(f)
    def decorated(*args, **kwargs):
        ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        allowed, message = rate_limiter.check(ip)

        if not allowed:
            logger.warning(f"Rate limit exceeded for IP: {ip}")
            return jsonify({'success': False, 'error': message}), 429

        return f(*args, **kwargs)
    return decorated

# ═══════════════════════════════════════════════════════
#  AUTHENTICATION
# ═══════════════════════════════════════════════════════

ADMIN_USERNAME = 'admin'
ADMIN_PASSWORD = 'admin123@#'

def hash_password(password):
    """Hash password for security"""
    return hashlib.sha256(password.encode()).hexdigest()

def verify_authentication(f):
    """Decorator to verify user is authenticated"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user' not in session or 'login_time' not in session:
            return jsonify({'success': False, 'error': 'Unauthorized'}), 401

        # Session timeout: 12 hours
        login_time = datetime.fromisoformat(session['login_time'])
        if datetime.now() - login_time > timedelta(hours=12):
            session.clear()
            return jsonify({'success': False, 'error': 'Session expired'}), 401

        return f(*args, **kwargs)
    return decorated

# ═══════════════════════════════════════════════════════
#  DATA MANAGEMENT
# ═══════════════════════════════════════════════════════

class DataManager:
    """Manage guilds and accounts data"""

    def __init__(self):
        self.data_file = 'guild_data.json'
        self.accounts_file = 'accounts.json'
        self.load_data()

    def load_data(self):
        """Load data from files"""
        try:
            if os.path.exists(self.data_file):
                with open(self.data_file, 'r', encoding='utf-8') as f:
                    self.data = json.load(f)
            else:
                self.data = {'guilds': []}

            if os.path.exists(self.accounts_file):
                with open(self.accounts_file, 'r', encoding='utf-8') as f:
                    self.accounts = json.load(f)
            else:
                self.accounts = []
        except Exception as e:
            logger.error(f"Error loading data: {e}")
            self.data = {'guilds': []}
            self.accounts = []

    def save_data(self):
        """Save data to files"""
        try:
            with open(self.data_file, 'w', encoding='utf-8') as f:
                json.dump(self.data, f, indent=2, ensure_ascii=False)

            with open(self.accounts_file, 'w', encoding='utf-8') as f:
                json.dump(self.accounts, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.error(f"Error saving data: {e}")

    def create_guild(self, guild_id, name, region, account_count):
        """Create a new guild"""
        if any(g['id'] == guild_id for g in self.data['guilds']):
            return False, "Guild already exists"

        guild = {
            'id': guild_id,
            'name': name,
            'region': region,
            'accountCount': min(account_count, len(self.accounts)),
            'accounts': self.accounts[:account_count],
            'status': 'active',
            'createdAt': datetime.now().isoformat(),
            'joinedAccounts': 0,
            'successCount': 0
        }

        self.data['guilds'].append(guild)
        self.save_data()
        logger.info(f"Guild created: {guild_id}")
        return True, guild

    def get_guild(self, guild_id):
        """Get guild by ID"""
        for g in self.data['guilds']:
            if g['id'] == guild_id:
                return g
        return None

    def delete_guild(self, guild_id):
        """Delete a guild"""
        self.data['guilds'] = [g for g in self.data['guilds'] if g['id'] != guild_id]
        self.save_data()
        logger.info(f"Guild deleted: {guild_id}")

    def get_all_guilds(self):
        """Get all guilds"""
        return self.data['guilds']

    def get_all_accounts(self):
        """Get all accounts"""
        return self.accounts

    def update_guild_status(self, guild_id, status, joined=None, success=None):
        """Update guild status"""
        guild = self.get_guild(guild_id)
        if guild:
            guild['status'] = status
            if joined is not None:
                guild['joinedAccounts'] = joined
            if success is not None:
                guild['successCount'] = success
            self.save_data()

data_manager = DataManager()

# ═══════════════════════════════════════════════════════
#  SCRIPT EXECUTION
# ═══════════════════════════════════════════════════════

class ScriptExecutor:
    """Execute Python scripts safely"""

    def __init__(self):
        self.running_processes = {}
        self.max_concurrent = 5

    def run_guild_script(self, guild_id, accounts):
        """Run guild.py with specified guild ID and accounts"""
        if len(self.running_processes) >= self.max_concurrent:
            return False, "Max concurrent processes reached"

        try:
            # Create temporary accounts file for this execution
            temp_accounts_file = f'accounts_{guild_id}.json'
            with open(temp_accounts_file, 'w', encoding='utf-8') as f:
                json.dump(accounts, f, indent=2)

            # Run guild.py
            cmd = [
                'python3', 'guild.py',
                '--guild-id', guild_id,
                '--accounts-file', temp_accounts_file
            ]

            logger.info(f"Running guild.py for guild {guild_id}")

            # Non-blocking execution
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            self.running_processes[guild_id] = {
                'process': process,
                'started': datetime.now(),
                'type': 'guild'
            }

            # Wait for completion in background
            def wait_and_cleanup():
                try:
                    stdout, stderr = process.communicate(timeout=300)  # 5 minute timeout
                    data_manager.update_guild_status(guild_id, 'completed')
                    logger.info(f"guild.py completed for {guild_id}")
                finally:
                    if guild_id in self.running_processes:
                        del self.running_processes[guild_id]
                    if os.path.exists(temp_accounts_file):
                        os.remove(temp_accounts_file)

            thread = threading.Thread(target=wait_and_cleanup, daemon=True)
            thread.start()

            return True, f"Guild script started for {guild_id}"

        except Exception as e:
            logger.error(f"Error running guild script: {e}")
            return False, str(e)

    def run_main_script(self, guild_id, accounts):
        """Run main.py with specified accounts"""
        if len(self.running_processes) >= self.max_concurrent:
            return False, "Max concurrent processes reached"

        try:
            # Create temporary accounts file
            temp_accounts_file = f'accounts_main_{guild_id}.json'
            with open(temp_accounts_file, 'w', encoding='utf-8') as f:
                json.dump(accounts, f, indent=2)

            # Run main.py
            cmd = [
                'python3', 'main.py',
                '--accounts-file', temp_accounts_file,
                '--guild-id', guild_id
            ]

            logger.info(f"Running main.py for guild {guild_id}")

            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            self.running_processes[guild_id] = {
                'process': process,
                'started': datetime.now(),
                'type': 'main'
            }

            # Wait for completion in background
            def wait_and_cleanup():
                try:
                    stdout, stderr = process.communicate(timeout=3600)  # 1 hour timeout
                    logger.info(f"main.py completed for {guild_id}")
                finally:
                    if guild_id in self.running_processes:
                        del self.running_processes[guild_id]
                    if os.path.exists(temp_accounts_file):
                        os.remove(temp_accounts_file)

            thread = threading.Thread(target=wait_and_cleanup, daemon=True)
            thread.start()

            return True, f"Main script started for {guild_id}"

        except Exception as e:
            logger.error(f"Error running main script: {e}")
            return False, str(e)

    def get_process_status(self, guild_id):
        """Get status of a running process"""
        if guild_id in self.running_processes:
            proc_info = self.running_processes[guild_id]
            return {
                'running': True,
                'type': proc_info['type'],
                'elapsed': (datetime.now() - proc_info['started']).total_seconds()
            }
        return {'running': False}

executor = ScriptExecutor()

# ═══════════════════════════════════════════════════════
#  ROUTES
# ═══════════════════════════════════════════════════════

@app.route('/')
def index():
    """Serve main page"""
    return send_from_directory('.', 'index.html')

@app.route('/api/login', methods=['POST'])
@rate_limit
def login():
    """Authenticate user"""
    data = request.get_json() or {}
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()

    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        session['user'] = username
        session['login_time'] = datetime.now().isoformat()
        logger.info(f"User logged in: {username}")
        return jsonify({'success': True, 'message': 'Login successful'})

    logger.warning(f"Failed login attempt with username: {username}")
    return jsonify({'success': False, 'error': 'Invalid credentials'}), 401

@app.route('/api/logout', methods=['POST'])
def logout():
    """Logout user"""
    session.clear()
    logger.info("User logged out")
    return jsonify({'success': True})

@app.route('/api/guilds', methods=['GET'])
@verify_authentication
@rate_limit
def get_guilds():
    """Get all guilds"""
    return jsonify({'success': True, 'guilds': data_manager.get_all_guilds()})

@app.route('/api/guilds', methods=['POST'])
@verify_authentication
@rate_limit
def create_guild():
    """Create a new guild"""
    data = request.get_json() or {}

    guild_id = data.get('guildId', '').strip()
    guild_name = data.get('guildName', '').strip()
    region = data.get('region', 'IND').strip()
    account_count = int(data.get('accountCount', 4))

    if not guild_id:
        return jsonify({'success': False, 'error': 'Guild ID is required'}), 400

    success, result = data_manager.create_guild(guild_id, guild_name or f'Guild {guild_id}', region, account_count)

    if success:
        return jsonify({'success': True, 'guild': result})
    else:
        return jsonify({'success': False, 'error': result}), 400

@app.route('/api/guilds/<guild_id>', methods=['DELETE'])
@verify_authentication
@rate_limit
def delete_guild_route(guild_id):
    """Delete a guild"""
    data_manager.delete_guild(guild_id)
    return jsonify({'success': True})

@app.route('/api/accounts', methods=['GET'])
@verify_authentication
@rate_limit
def get_accounts():
    """Get all accounts"""
    return jsonify({'success': True, 'accounts': data_manager.get_all_accounts()})

@app.route('/api/run-guild', methods=['POST'])
@verify_authentication
@rate_limit
def run_guild_endpoint():
    """Execute guild.py"""
    data = request.get_json() or {}
    guild_id = data.get('guildId', '').strip()

    if not guild_id:
        return jsonify({'success': False, 'error': 'Guild ID is required'}), 400

    guild = data_manager.get_guild(guild_id)
    if not guild:
        return jsonify({'success': False, 'error': 'Guild not found'}), 404

    data_manager.update_guild_status(guild_id, 'running')
    success, message = executor.run_guild_script(guild_id, guild['accounts'])

    if success:
        return jsonify({'success': True, 'message': message})
    else:
        return jsonify({'success': False, 'error': message}), 500

@app.route('/api/run-main', methods=['POST'])
@verify_authentication
@rate_limit
def run_main_endpoint():
    """Execute main.py"""
    data = request.get_json() or {}
    guild_id = data.get('guildId', '').strip()

    if not guild_id:
        return jsonify({'success': False, 'error': 'Guild ID is required'}), 400

    guild = data_manager.get_guild(guild_id)
    if not guild:
        return jsonify({'success': False, 'error': 'Guild not found'}), 404

    data_manager.update_guild_status(guild_id, 'running')
    success, message = executor.run_main_script(guild_id, guild['accounts'])

    if success:
        return jsonify({'success': True, 'message': message})
    else:
        return jsonify({'success': False, 'error': message}), 500

@app.route('/api/status/<guild_id>', methods=['GET'])
@verify_authentication
@rate_limit
def get_status(guild_id):
    """Get execution status"""
    status = executor.get_process_status(guild_id)
    return jsonify({'success': True, 'status': status})

@app.route('/api/stats', methods=['GET'])
@verify_authentication
@rate_limit
def get_stats():
    """Get system statistics"""
    guilds = data_manager.get_all_guilds()
    accounts = data_manager.get_all_accounts()
    regions = len(set(a.get('region', 'IND') for a in accounts))

    return jsonify({
        'success': True,
        'stats': {
            'totalGuilds': len(guilds),
            'totalAccounts': len(accounts),
            'totalRegions': regions,
            'activeGuilds': len([g for g in guilds if g['status'] == 'active']),
            'runningGuilds': len([g for g in guilds if g['status'] == 'running']),
            'rateLimiterStats': rate_limiter.get_stats()
        }
    })

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint for monitoring"""
    return jsonify({'status': 'healthy', 'timestamp': datetime.now().isoformat()})

# ═══════════════════════════════════════════════════════
#  ERROR HANDLERS
# ═══════════════════════════════════════════════════════

@app.errorhandler(404)
def not_found(e):
    return jsonify({'success': False, 'error': 'Not found'}), 404

@app.errorhandler(500)
def server_error(e):
    logger.error(f"Server error: {e}")
    return jsonify({'success': False, 'error': 'Internal server error'}), 500

# ═══════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('DEBUG', 'False').lower() == 'true'

    logger.info(f"Starting Guild Glory server on port {port}")
    app.run(
        host='0.0.0.0',
        port=port,
        debug=debug,
        use_reloader=False,
        threaded=True
    )
