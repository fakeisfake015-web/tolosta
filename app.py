#!/usr/bin/env python3
"""
CTF Challenge: SQL Injection - The Ultimate WAF Bypass
Category: Web Exploitation / SQL Injection
Difficulty: Expert ⚠️⚠️⚠️
Points: 750

Description:
A modern web application with an advanced WAF (Web Application Firewall).
Can you bypass all protections and extract the flag?

Protection Layers:
- WAF with keyword blacklist
- Prepared statement simulation
- Input length limits
- SQL comment filtering
- Union/select filtering
- Special character filtering

Flag: JCOECTF{sql_1nj3ct10n_w4f_byp4ss_2024}
"""

import sqlite3
import re
import hashlib
from flask import Flask, request, jsonify

app = Flask(__name__)

# Initialize database
def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    
    # Create tables
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE,
        password TEXT,
        role TEXT
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS secrets (
        id INTEGER PRIMARY KEY,
        user_id INTEGER,
        secret TEXT,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )''')
    
    # Insert data
    users = [
        ('admin', hashlib.md5(b'sup3r_s3cur3_p4ssw0rd!@#').hexdigest(), 'admin'),
        ('guest', hashlib.md5(b'guest123').hexdigest(), 'user'),
        ('test', hashlib.md5(b'test123').hexdigest(), 'user'),
    ]
    
    for user in users:
        try:
            c.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', user)
        except:
            pass
    
    # Insert secrets
    secrets = [
        (1, 'Admin secret key: admin_key_123'),
        (1, 'JCOECTF{sql_1nj3ct10n_w4f_byp4ss_2024}'),  # FLAG!
        (2, 'Guest has no secrets'),
        (3, 'Test secret'),
    ]
    
    for secret in secrets:
        try:
            c.execute('INSERT INTO secrets (user_id, secret) VALUES (?, ?)', secret)
        except:
            pass
    
    conn.commit()
    conn.close()

# Advanced WAF
class AdvancedWAF:
    BLACKLIST = [
        'union', 'select', 'from', 'where', 'or', 'and', '=', '--', '#', '/*',
        '*/', 'drop', 'insert', 'update', 'delete', 'exec', 'execute',
        'script', 'javascript', 'onerror', 'onload', 'alert', 'prompt',
        'concat', 'char', 'ascii', 'substring', 'substr', 'mid', 'sleep',
        'benchmark', 'waitfor', 'pg_sleep', 'information_schema', 'sysobjects',
        'syscolumns', 'table_name', 'column_name', '0x', 'x\'', 'chr', 'char'
    ]
    
    @staticmethod
    def check(input_str):
        """Multi-layer WAF checking"""
        if not input_str:
            return True, "Empty input"
        
        # Length check
        if len(input_str) > 50:
            return False, "Input too long"
        
        # Convert to lowercase for checking
        lower_input = input_str.lower()
        
        # Blacklist check
        for keyword in AdvancedWAF.BLACKLIST:
            if keyword in lower_input:
                return False, f"Forbidden keyword detected: {keyword}"
        
        # Pattern matching
        dangerous_patterns = [
            r'\/\*.*\*\/',  # Comments
            r'--.*',  # SQL comments
            r'#.*',  # MySQL comments
            r';.*',  # Multiple queries
            r'\bunion\b',  # Union keyword
            r'\bselect\b',  # Select keyword
            r'[\'"]+',  # Quote injection
            r'<script',  # XSS
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, lower_input, re.IGNORECASE):
                return False, f"Dangerous pattern detected"
        
        return True, "OK"

@app.route('/')
def index():
    return '''
    <html>
    <head><title>SQL Injection Challenge</title></head>
    <body style="font-family: monospace; padding: 40px;">
        <h1>🔒 Ultra Secure Login System v3.0</h1>
        <p>Protected by Advanced WAF Technology</p>
        
        <h2>Login</h2>
        <form action="/login" method="POST">
            <input type="text" name="username" placeholder="Username" maxlength="50"><br><br>
            <input type="password" name="password" placeholder="Password" maxlength="50"><br><br>
            <button type="submit">Login</button>
        </form>
        
        <h2>Search Users</h2>
        <form action="/search" method="GET">
            <input type="text" name="q" placeholder="Search username" maxlength="50"><br><br>
            <button type="submit">Search</button>
        </form>
        
        <hr>
        <p>Protection Status:</p>
        <ul>
            <li>✅ WAF Enabled</li>
            <li>✅ Input Validation</li>
            <li>✅ SQL Comment Filtering</li>
            <li>✅ Keyword Blacklist</li>
            <li>✅ Length Restrictions</li>
        </ul>
        
        <p><i>Hint: Sometimes the best attack is the most creative one...</i></p>
    </body>
    </html>
    '''

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    
    # WAF check
    allowed, msg = AdvancedWAF.check(username)
    if not allowed:
        return jsonify({'error': f'WAF blocked: {msg}'}), 403
    
    allowed, msg = AdvancedWAF.check(password)
    if not allowed:
        return jsonify({'error': f'WAF blocked: {msg}'}), 403
    
    # Hash password
    pwd_hash = hashlib.md5(password.encode()).hexdigest()
    
    # Vulnerable query (but with WAF)
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    
    # Intentionally vulnerable to SQL injection
    query = f"SELECT id, username, role FROM users WHERE username='{username}' AND password='{pwd_hash}'"
    
    try:
        c.execute(query)
        result = c.fetchone()
        conn.close()
        
        if result:
            user_id, username, role = result
            
            # Get user secrets
            conn = sqlite3.connect('database.db')
            c = conn.cursor()
            c.execute('SELECT secret FROM secrets WHERE user_id=?', (user_id,))
            secrets = [row[0] for row in c.fetchall()]
            conn.close()
            
            return jsonify({
                'success': True,
                'username': username,
                'role': role,
                'secrets': secrets
            })
        else:
            return jsonify({'error': 'Invalid credentials'}), 401
            
    except sqlite3.Error as e:
        conn.close()
        return jsonify({'error': f'Database error: {str(e)}'}), 500

@app.route('/search', methods=['GET'])
def search():
    query = request.args.get('q', '')
    
    # WAF check
    allowed, msg = AdvancedWAF.check(query)
    if not allowed:
        return jsonify({'error': f'WAF blocked: {msg}'}), 403
    
    # Vulnerable search query
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    
    sql = f"SELECT username, role FROM users WHERE username LIKE '%{query}%'"
    
    try:
        c.execute(sql)
        results = c.fetchall()
        conn.close()
        
        return jsonify({
            'results': [{'username': r[0], 'role': r[1]} for r in results]
        })
    except sqlite3.Error as e:
        conn.close()
        return jsonify({'error': f'Database error: {str(e)}'}), 500

@app.route('/debug')
def debug():
    """Hidden debug endpoint (players need to find this)"""
    if request.args.get('key') == 'debug_mode_enabled':
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = c.fetchall()
        conn.close()
        return jsonify({'tables': [t[0] for t in tables]})
    return jsonify({'error': 'Access denied'}), 403

if __name__ == '__main__':
    init_db()
    print("="*60)
    print("     SQL INJECTION CHALLENGE - WAF BYPASS")
    print("="*60)
    print("\n[*] Starting server on http://localhost:9011")
    print("[*] WAF Protection: ENABLED")
    print("[*] Objective: Extract the flag from the database")
    print("[*] Hint: The WAF can't catch everything...")
    print("\n" + "="*60 + "\n")
    
    app.run(host='0.0.0.0', port=9011, debug=False)
