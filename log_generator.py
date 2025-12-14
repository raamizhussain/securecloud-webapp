from flask import Flask, request, jsonify
import json
import random
import time
from datetime import datetime

app = Flask(__name__)

# Store logs in memory
logs = []

# Sample data for generating realistic logs
usernames = ['alice', 'bob', 'charlie', 'admin', 'user123']
endpoints = ['/home', '/dashboard', '/api/data', '/admin/users', '/api/payments']
ips = ['192.168.1.10', '192.168.1.20', '10.0.0.5', '203.0.113.45', '198.51.100.78']

@app.route('/')
def home():
    return "Log Generator App is Running!"

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    username = data.get('username', random.choice(usernames))
    ip = request.remote_addr
    
    # Simulate success or failure
    success = random.choice([True, True, True, False])  # 75% success rate
    
    log_entry = {
        'timestamp': datetime.now().isoformat(),
        'ip': ip,
        'user': username,
        'action': 'login',
        'status': 'success' if success else 'failed',
        'endpoint': '/login'
    }
    
    logs.append(log_entry)
    print(f"[LOG] {log_entry}")
    
    return jsonify(log_entry)

@app.route('/access', methods=['GET'])
def access():
    endpoint = random.choice(endpoints)
    user = random.choice(usernames)
    ip = request.remote_addr
    
    log_entry = {
        'timestamp': datetime.now().isoformat(),
        'ip': ip,
        'user': user,
        'action': 'access',
        'status': 'success',
        'endpoint': endpoint
    }
    
    logs.append(log_entry)
    print(f"[LOG] {log_entry}")
    
    return jsonify(log_entry)

@app.route('/logs', methods=['GET'])
def get_logs():
    return jsonify(logs)

if __name__ == '__main__':
    print("Starting Log Generator App...")
    print("Visit: http://127.0.0.1:5000")
    app.run(debug=True, port=5000)
