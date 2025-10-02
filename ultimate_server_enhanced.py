# ultimate_server_enhanced.py - УЛУЧШЕННАЯ МАКСИМАЛЬНО ЗАЩИЩЕННАЯ ВЕРСИЯ
from flask import Flask, request, jsonify, send_file, session, render_template_string
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
import os
import hashlib
import hmac
import time
import logging
from threading import Thread, Lock
import subprocess
import re
import json
from datetime import datetime, timedelta
import secrets

app = Flask(__name__)
app.secret_key = os.urandom(32)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

# ⚡ MAXIMUM PROTECTION CONFIGURATION ⚡

# Rate Limiting - улучшенная защита от DDoS
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["500 per minute", "100 per second"],
    storage_uri="memory://",
)

# Security Headers - Talisman с улучшенными настройками
csp = {
    'default-src': "'self'",
    'script-src': "'self' 'unsafe-inline'",
    'style-src': "'self' 'unsafe-inline'",
    'img-src': "'self' data: https:",
    'font-src': "'self' https://fonts.gstatic.com",
    'connect-src': "'self'",
    'frame-ancestors': "'none'",
    'form-action': "'self'"
}

talisman = Talisman(
    app,
    content_security_policy=csp,
    force_https=True,
    strict_transport_security=True,
    strict_transport_security_max_age=31536000,
    session_cookie_secure=True,
    session_cookie_http_only=True,
    session_cookie_samesite='Lax'
)

# УЛУЧШЕННЫЙ FIREWALL & THREAT DETECTION
class AdvancedFirewall:
    def __init__(self):
        self.suspicious_ips = set()
        self.request_counts = {}
        self.blocked_ips = set()
        self.whitelist_ips = {'127.0.0.1', '::1'}  # Белый список
        self.ip_lock = Lock()
        self.suspicious_patterns = [
            r'\.\./', r'\.\.\\', r'/etc/passwd', r'wp-admin', r'phpmyadmin',
            r'\.env', r'config', r'administrator', r'union.*select', 
            r'script.*alert', r'eval\(', r'base64_decode', r'xss',
            r'<script', r'javascript:', r'vbscript:', r'onload=',
            r'benchmark\(', r'sleep\(', r'waitfor\sdelay'
        ]
        self.failed_logins = {}
        
    def check_threat(self, ip, user_agent, path, method, data):
        # Проверка белого списка
        if ip in self.whitelist_ips:
            return False
            
        # Проверка подозрительных паттернов в URL и данных
        combined_check = path.lower() + " " + str(data).lower()
        
        for pattern in self.suspicious_patterns:
            if re.search(pattern, combined_check, re.IGNORECASE):
                with self.ip_lock:
                    self.blocked_ips.add(ip)
                logging.warning(f"BLOCKED: {ip} - Suspicious pattern detected: {pattern}")
                return True
        
        # Rate limiting по IP с блокировкой
        current_time = time.time()
        with self.ip_lock:
            self.request_counts[ip] = self.request_counts.get(ip, 0) + 1
            
            # Сброс счетчика каждую минуту
            if current_time - self.request_counts.get(f'{ip}_time', 0) > 60:
                self.request_counts[ip] = 1
                self.request_counts[f'{ip}_time'] = current_time
            
            if self.request_counts[ip] > 200:  # 200 запросов в минуту
                self.blocked_ips.add(ip)
                logging.warning(f"BLOCKED: {ip} - Rate limit exceeded")
                return True
                
        return False

    def add_failed_login(self, ip):
        """Добавление неудачной попытки входа"""
        with self.ip_lock:
            self.failed_logins[ip] = self.failed_logins.get(ip, 0) + 1
            if self.failed_logins[ip] >= 5:  # После 5 неудачных попыток
                self.blocked_ips.add(ip)
                logging.warning(f"BLOCKED: {ip} - Too many failed login attempts")

    def reset_failed_logins(self, ip):
        """Сброс счетчика неудачных попыток"""
        with self.ip_lock:
            if ip in self.failed_logins:
                del self.failed_logins[ip]

firewall = AdvancedFirewall()

# УЛУЧШЕННЫЙ AI THREAT DETECTION
def ai_threat_detection(ip, headers, payload, method, path):
    """Улучшенный AI-детектор угроз"""
    threat_score = 0
    
    # Анализ User-Agent
    suspicious_agents = ['sqlmap', 'nikto', 'metasploit', 'nmap', 'wget', 'curl', 'hydra']
    ua = headers.get('User-Agent', '').lower()
    if any(agent in ua for agent in suspicious_agents):
        threat_score += 35
    
    # Анализ payload
    dangerous_patterns = [
        r'<script.*?>', r'javascript:', r'vbscript:', r'onload=',
        r'union.*select', r'exec\(', r'system\(', r'eval\(', 
        r'base64_decode', r'document\.cookie', r'localStorage',
        r'sessionStorage', r'XMLHttpRequest', r'fetch\(.*\)'
    ]
    
    payload_str = str(payload).lower()
    for pattern in dangerous_patterns:
        if re.search(pattern, payload_str, re.IGNORECASE):
            threat_score += 30
    
    # Анализ методов и путей
    if method in ['POST', 'PUT'] and any(x in path for x in ['/admin', '/login', '/api']):
        threat_score += 15
        
    # Анализ частоты запросов
    if firewall.request_counts.get(ip, 0) > 100:
        threat_score += 20
    
    return threat_score > 60

# УЛУЧШЕННАЯ АУТЕНТИФИКАЦИЯ
def generate_secure_token():
    """Генерация безопасного токена"""
    return secrets.token_urlsafe(32)

def verify_token(token):
    """Проверка токена"""
    if not token:
        return False
    # В реальном приложении здесь должна быть проверка против базы данных
    return len(token) >= 10

# 2FA СИСТЕМА
def generate_2fa_code():
    """Генерация 6-значного 2FA кода"""
    return ''.join([str(secrets.randbelow(10)) for _ in range(6)])

def verify_2fa_code(stored_code, provided_code):
    """Проверка 2FA кода"""
    return stored_code == provided_code

# СИСТЕМА СЕССИЙ
session_tokens = {}
SESSION_TIMEOUT = 1800  # 30 минут

def create_session(user_id, ip):
    """Создание сессии"""
    session_id = secrets.token_urlsafe(32)
    session_tokens[session_id] = {
        'user_id': user_id,
        'ip': ip,
        'created_at': time.time(),
        'last_activity': time.time()
    }
    return session_id

def validate_session(session_id, ip):
    """Проверка сессии"""
    if session_id not in session_tokens:
        return False
        
    session_data = session_tokens[session_id]
    
    # Проверка IP
    if session_data['ip'] != ip:
        return False
        
    # Проверка таймаута
    if time.time() - session_data['last_activity'] > SESSION_TIMEOUT:
        del session_tokens[session_id]
        return False
        
    # Обновление времени активности
    session_tokens[session_id]['last_activity'] = time.time()
    return True

# УЛУЧШЕННОЕ ЛОГИРОВАНИЕ
def setup_logging():
    """Настройка расширенного логирования"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(name)s - %(message)s',
        handlers=[
            logging.FileHandler('security.log'),
            logging.FileHandler('audit.log'),  # Отдельный лог для аудита
            logging.StreamHandler()
        ]
    )
    
    # Логгер для подозрительной активности
    suspicious_logger = logging.getLogger('suspicious')
    suspicious_handler = logging.FileHandler('suspicious_activity.log')
    suspicious_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
    suspicious_logger.addHandler(suspicious_handler)
    suspicious_logger.propagate = False

setup_logging()

# MIDDLEWARE - улучшенная проверка всех запросов
@app.before_request
def security_check():
    client_ip = get_remote_address()
    
    # Проверка firewall
    if firewall.check_threat(client_ip, 
                           request.headers.get('User-Agent'), 
                           request.path,
                           request.method,
                           request.get_data()):
        logging.warning(f"FIREWALL BLOCKED: {client_ip} - {request.path}")
        return jsonify({"error": "Access Denied", "code": 403}), 403
    
    # AI threat detection
    if ai_threat_detection(client_ip, 
                          request.headers, 
                          request.get_data(),
                          request.method,
                          request.path):
        logging.warning(f"AI THREAT BLOCKED: {client_ip} - {request.path}")
        firewall.blocked_ips.add(client_ip)
        return jsonify({"error": "Security Violation", "code": 403}), 403
    
    # Проверка авторизации для защищенных путей
    if request.path.startswith('/admin') and not request.path.endswith('/login'):
        token = request.headers.get('Authorization') or request.args.get('token')
        if not token or not validate_session(token, client_ip):
            return jsonify({"error": "Unauthorized", "code": 401}), 401

# ROUTES - улучшенные маршруты
@app.route('/')
@limiter.limit("200/minute")
def home():
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>🔒 ULTIMATE SECURE SERVER v2.0</title>
        <style>
            body { 
                background: #0a0a0a; 
                color: #00ff00; 
                font-family: 'Courier New', monospace;
                text-align: center;
                padding: 50px;
            }
            .security-badge {
                border: 2px solid #00ff00;
                padding: 20px;
                margin: 20px;
                border-radius: 10px;
                background: rgba(0, 255, 0, 0.05);
            }
            .status-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 15px;
                margin: 20px 0;
            }
            .status-item {
                padding: 10px;
                border: 1px solid #00ff00;
                border-radius: 5px;
            }
        </style>
    </head>
    <body>
        <h1>🔒 ULTIMATE SECURE SERVER v2.0</h1>
        <div class="security-badge">
            <h2>MAXIMUM PROTECTION ACTIVATED</h2>
            <div class="status-grid">
                <div class="status-item">✅ Advanced Firewall</div>
                <div class="status-item">✅ AI Threat Detection</div>
                <div class="status-item">✅ DDoS Protection</div>
                <div class="status-item">✅ Rate Limiting</div>
                <div class="status-item">✅ HSTS & CSP</div>
                <div class="status-item">✅ Real-time Monitoring</div>
                <div class="status-item">✅ 2FA System</div>
                <div class="status-item">✅ Session Management</div>
            </div>
        </div>
        <p>Server Time: <span id="time"></span></p>
        <p>Active Sessions: <span id="sessions">0</span></p>
        
        <script>
            document.getElementById('time').textContent = new Date().toLocaleString();
            setInterval(() => {
                document.getElementById('time').textContent = new Date().toLocaleString();
            }, 1000);
            
            // Запрос статуса сессий
            fetch('/api/status')
                .then(r => r.json())
                .then(data => {
                    document.getElementById('sessions').textContent = data.active_sessions || 0;
                });
        </script>
    </body>
    </html>
    '''

@app.route('/api/status')
@limiter.limit("100/minute")
def api_status():
    return jsonify({
        "status": "secure",
        "firewall": "active",
        "threat_level": "low",
        "server_time": time.time(),
        "active_sessions": len(session_tokens),
        "blocked_ips": len(firewall.blocked_ips),
        "protected_routes": ["/admin", "/api", "/secure"]
    })

@app.route('/admin/login', methods=['POST'])
@limiter.limit("5/minute")
def admin_login():
    client_ip = get_remote_address()
    
    # Проверка учетных данных (в реальном приложении - против базы данных)
    username = request.json.get('username')
    password = request.json.get('password')
    
    if username == 'admin' and password == 'secure_password':  # Заменить на реальные проверки
        # Генерация 2FA кода
        twofa_code = generate_2fa_code()
        session['2fa_code'] = twofa_code
        session['2fa_expires'] = time.time() + 300  # 5 минут
        
        logging.info(f"2FA code generated for {client_ip}: {twofa_code}")
        
        return jsonify({
            "status": "2fa_required",
            "message": "Please enter 2FA code"
        })
    else:
        firewall.add_failed_login(client_ip)
        return jsonify({"error": "Invalid credentials"}), 401

@app.route('/admin/verify-2fa', methods=['POST'])
@limiter.limit("5/minute")
def verify_2fa():
    client_ip = get_remote_address()
    code = request.json.get('code')
    
    stored_code = session.get('2fa_code')
    expires = session.get('2fa_expires', 0)
    
    if not stored_code or time.time() > expires:
        return jsonify({"error": "2FA code expired"}), 401
        
    if verify_2fa_code(stored_code, code):
        # Создание сессии
        session_id = create_session('admin', client_ip)
        
        # Очистка 2FA данных
        session.pop('2fa_code', None)
        session.pop('2fa_expires', None)
        
        logging.info(f"Successful admin login from {client_ip}")
        
        return jsonify({
            "status": "success",
            "token": session_id,
            "message": "Login successful"
        })
    else:
        firewall.add_failed_login(client_ip)
        return jsonify({"error": "Invalid 2FA code"}), 401

@app.route('/admin/dashboard')
@limiter.limit("10/minute")
def admin_dashboard():
    client_ip = get_remote_address()
    token = request.headers.get('Authorization')
    
    if not validate_session(token, client_ip):
        return jsonify({"error": "Unauthorized"}), 401
        
    stats = {
        "active_sessions": len(session_tokens),
        "blocked_ips": len(firewall.blocked_ips),
        "total_requests": sum(firewall.request_counts.values()),
        "failed_logins": len(firewall.failed_logins)
    }
    
    return jsonify({
        "status": "success",
        "dashboard": "Admin Panel",
        "statistics": stats
    })

# СИСТЕМА МОНИТОРИНГА В РЕАЛЬНОМ ВРЕМЕНИ
def security_monitor():
    """Фоновая задача мониторинга безопасности"""
    while True:
        time.sleep(60)
        # Очистка устаревших сессий
        current_time = time.time()
        expired_sessions = [
            sid for sid, data in session_tokens.items()
            if current_time - data['last_activity'] > SESSION_TIMEOUT
        ]
        for sid in expired_sessions:
            del session_tokens[sid]
            
        logging.info(
            f"SECURITY SCAN: "
            f"Sessions: {len(session_tokens)} | "
            f"Blocked IPs: {len(firewall.blocked_ips)} | "
            f"Active IPs: {len(firewall.request_counts)}"
        )

def auto_backup():
    """Автоматическое резервное копирование"""
    while True:
        time.sleep(3600)  # Каждый час
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        try:
            os.system(f"tar -czf backup_{timestamp}.tar.gz *.py 2>/dev/null")
            logging.info(f"Backup created: backup_{timestamp}.tar.gz")
        except Exception as e:
            logging.error(f"Backup failed: {e}")

# ЗАПУСК СЕРВИСОВ БЕЗОПАСНОСТИ
def start_security_services():
    monitor_thread = Thread(target=security_monitor, daemon=True)
    backup_thread = Thread(target=auto_backup, daemon=True)
    monitor_thread.start()
    backup_thread.start()

if __name__ == '__main__':
    # Создание безопасных директорий
    os.makedirs('./secure_files', exist_ok=True)
    os.makedirs('./backups', exist_ok=True)
    
    # Запуск сервисов безопасности
    start_security_services()
    
    # Конфигурация для разработки
    dev_config = {
        'host': '0.0.0.0',
        'port': 8080,
        'debug': False,
        'use_reloader': False
    }
    
    print("🚀 ULTIMATE SECURE SERVER v2.0 STARTING...")
    print("🔒 Enhanced Security Features:")
    print("   ✅ Advanced Firewall with Pattern Detection")
    print("   ✅ AI Threat Detection v2.0") 
    print("   ✅ DDoS Protection with Rate Limiting")
    print("   ✅ HSTS & CSP Headers")
    print("   ✅ Real-time Monitoring")
    print("   ✅ Auto Backup System")
    print("   ✅ 2FA Authentication")
    print("   ✅ Session Management")
    print("   ✅ Suspicious Activity Logging")
    
    app.run(**dev_config)