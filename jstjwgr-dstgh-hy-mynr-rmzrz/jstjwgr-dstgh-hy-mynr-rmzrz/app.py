#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
سیستم جامع شناسایی و نظارت بر ماینرهای رمزارز
نرم‌افزار حرفه‌ای چندکاربره با رابط وب �� بانک اطلاعاتی
"""

from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import socket
import threading
import subprocess
import psutil
import requests
import json
import time
import hashlib
import ipaddress
import nmap
import sqlite3
import os
import logging
from concurrent.futures import ThreadPoolExecutor
import uuid
import secrets

# تنظیمات لاگ
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///miner_detection.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# مدل‌های دیتابیس
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), default='user')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)

class DetectedMiner(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), nullable=False)
    mac_address = db.Column(db.String(17))
    hostname = db.Column(db.String(255))
    location = db.Column(db.String(255))
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    device_type = db.Column(db.String(100))
    detection_method = db.Column(db.String(255))
    confidence_score = db.Column(db.Integer)
    threat_level = db.Column(db.String(20))
    open_ports = db.Column(db.Text)
    power_consumption = db.Column(db.Float)
    hash_rate = db.Column(db.String(100))
    detection_time = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    notes = db.Column(db.Text)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class ScanSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.String(36), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    scan_type = db.Column(db.String(50), nullable=False)
    target_range = db.Column(db.String(100))
    start_time = db.Column(db.DateTime, default=datetime.utcnow)
    end_time = db.Column(db.DateTime)
    status = db.Column(db.String(20), default='running')
    total_hosts = db.Column(db.Integer, default=0)
    scanned_hosts = db.Column(db.Integer, default=0)
    detected_miners = db.Column(db.Integer, default=0)
    progress = db.Column(db.Integer, default=0)
    results = db.Column(db.Text)

class NetworkActivity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), nullable=False)
    port = db.Column(db.Integer, nullable=False)
    protocol = db.Column(db.String(10), nullable=False)
    service = db.Column(db.String(100))
    activity_type = db.Column(db.String(50))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    data_size = db.Column(db.BigInteger)
    is_suspicious = db.Column(db.Boolean, default=False)

class SystemMetrics(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    cpu_usage = db.Column(db.Float)
    memory_usage = db.Column(db.Float)
    network_io = db.Column(db.BigInteger)
    disk_io = db.Column(db.BigInteger)
    active_connections = db.Column(db.Integer)
    suspicious_processes = db.Column(db.Integer)

# کلاس اصلی شناسایی ماینر
class MinerDetectionEngine:
    def __init__(self):
        self.miner_ports = {
            4028: "CGMiner API", 4029: "SGMiner API", 4030: "BFGMiner API",
            3333: "Stratum Pool", 4444: "Stratum Pool Alt", 5555: "Stratum Pool",
            7777: "Stratum Pool", 8080: "Web Interface", 8888: "Web Interface Alt",
            9999: "Stratum SSL", 14444: "Stratum SSL Alt", 1080: "SOCKS Proxy",
            3128: "HTTP Proxy", 8118: "Privoxy", 9050: "Tor SOCKS",
            8332: "Bitcoin RPC", 8333: "Bitcoin P2P", 9332: "Litecoin RPC",
            25: "SMTP", 587: "SMTP TLS", 465: "SMTP SSL"
        }
        
        self.miner_processes = [
            'cgminer', 'bfgminer', 'sgminer', 'cpuminer', 'xmrig', 'xmr-stak',
            'claymore', 'phoenixminer', 't-rex', 'gminer', 'nbminer', 'teamredminer',
            'lolminer', 'miniZ', 'bminer', 'z-enemy', 'ccminer', 'ethminer',
            'nanominer', 'srbminer', 'wildrig'
        ]
        
        self.suspicious_domains = [
            'stratum+tcp', 'mining.pool', 'pool.mining', 'btc.pool', 'eth.pool',
            'xmr.pool', 'nicehash.com', 'f2pool.com', 'antpool.com',
            'slushpool.com', 'poolin.com', 'viabtc.com'
        ]

    def ping_host(self, ip):
        """بررسی دسترسی به IP"""
        try:
            result = subprocess.run(['ping', '-c', '1', '-W', '1', ip], 
                                  capture_output=True, text=True)
            return result.returncode == 0
        except:
            return False

    def scan_port(self, ip, port, timeout=2):
        """اسکن تک پورت"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except:
            return False

    def get_mac_address(self, ip):
        """دریافت آدرس MAC"""
        try:
            arp_result = subprocess.run(['arp', '-n', ip], 
                                      capture_output=True, text=True)
            if arp_result.returncode == 0:
                lines = arp_result.stdout.split('\n')
                for line in lines:
                    if ip in line:
                        parts = line.split()
                        for part in parts:
                            if ':' in part and len(part) == 17:
                                return part
        except:
            pass
        return None

    def get_hostname(self, ip):
        """دریافت نام میزبان"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:
            return None

    def geolocate_ip(self, ip):
        """مکان‌یابی IP"""
        try:
            response = requests.get(f'http://ip-api.com/json/{ip}', timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data['status'] == 'success':
                    return {
                        'country': data.get('country', ''),
                        'city': data.get('city', ''),
                        'region': data.get('regionName', ''),
                        'lat': data.get('lat', 0),
                        'lon': data.get('lon', 0),
                        'isp': data.get('isp', ''),
                        'org': data.get('org', '')
                    }
        except:
            pass
        return None

    def detect_miner_processes(self):
        """تشخیص فرآیندهای ماینر"""
        suspicious_processes = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info']):
            try:
                proc_info = proc.info
                process_name = proc_info['name'].lower()
                
                if any(miner in process_name for miner in self.miner_processes):
                    suspicious_processes.append({
                        'pid': proc_info['pid'],
                        'name': proc_info['name'],
                        'cpu_percent': proc_info['cpu_percent'],
                        'memory_mb': proc_info['memory_info'].rss / 1024 / 1024,
                        'suspicion_level': 'high'
                    })
            except:
                continue
        
        return suspicious_processes

    def advanced_port_scan(self, ip, ports=None):
        """اسکن پیشرفته پورت"""
        if ports is None:
            ports = list(self.miner_ports.keys())
        
        open_ports = []
        for port in ports:
            if self.scan_port(ip, port):
                open_ports.append(port)
        
        return open_ports

    def analyze_network_traffic(self, ip):
        """تحلیل ترافیک شبکه"""
        try:
            connections = psutil.net_connections()
            suspicious_connections = []
            
            for conn in connections:
                if conn.raddr and conn.raddr.ip == ip:
                    if conn.raddr.port in self.miner_ports:
                        suspicious_connections.append({
                            'local_port': conn.laddr.port,
                            'remote_port': conn.raddr.port,
                            'status': conn.status,
                            'service': self.miner_ports[conn.raddr.port]
                        })
            
            return suspicious_connections
        except:
            return []

    def scan_network_range(self, network_range, progress_callback=None):
        """اسکن رنج شبکه"""
        results = []
        
        try:
            network = ipaddress.ip_network(network_range, strict=False)
            total_hosts = network.num_addresses
            scanned_hosts = 0
            
            for ip in network.hosts():
                ip_str = str(ip)
                
                if self.ping_host(ip_str):
                    device_info = self.analyze_device(ip_str)
                    if device_info:
                        results.append(device_info)
                
                scanned_hosts += 1
                if progress_callback:
                    progress = int((scanned_hosts / total_hosts) * 100)
                    progress_callback(progress, scanned_hosts, total_hosts)
        
        except Exception as e:
            logger.error(f"خطا در اسکن شبکه: {e}")
        
        return results

    def analyze_device(self, ip):
        """تحلیل جامع دستگاه"""
        device_info = {
            'ip': ip,
            'timestamp': datetime.utcnow().isoformat(),
            'open_ports': [],
            'services': {},
            'mac_address': self.get_mac_address(ip),
            'hostname': self.get_hostname(ip),
            'geolocation': self.geolocate_ip(ip),
            'suspicion_score': 0,
            'detection_methods': [],
            'threat_level': 'low'
        }
        
        # اسکن پورت‌ها
        open_ports = self.advanced_port_scan(ip)
        device_info['open_ports'] = open_ports
        
        for port in open_ports:
            service = self.miner_ports.get(port, "Unknown Service")
            device_info['services'][port] = service
            device_info['suspicion_score'] += 20
            device_info['detection_methods'].append(f'port_{port}')
        
        # تحلیل hostname
        if device_info['hostname']:
            hostname = device_info['hostname'].lower()
            if any(keyword in hostname for keyword in 
                  ['miner', 'mining', 'asic', 'antminer', 'whatsminer']):
                device_info['suspicion_score'] += 30
                device_info['detection_methods'].append('hostname')
        
        # تحلیل ترافیک شبکه
        network_analysis = self.analyze_network_traffic(ip)
        if network_analysis:
            device_info['network_connections'] = network_analysis
            device_info['suspicion_score'] += 25
            device_info['detection_methods'].append('network_traffic')
        
        # تعیین سطح تهدید
        if device_info['suspicion_score'] >= 70:
            device_info['threat_level'] = 'critical'
        elif device_info['suspicion_score'] >= 50:
            device_info['threat_level'] = 'high'
        elif device_info['suspicion_score'] >= 30:
            device_info['threat_level'] = 'medium'
        else:
            device_info['threat_level'] = 'low'
        
        return device_info if device_info['suspicion_score'] > 15 else None

# نمونه detection engine
detection_engine = MinerDetectionEngine()

# Helper function for auto-login
def ensure_logged_in():
    if 'user_id' not in session:
        admin = User.query.filter_by(username='admin').first()
        if admin:
            session['user_id'] = admin.id
            session['username'] = admin.username
            session['role'] = admin.role
            admin.last_login = datetime.utcnow()
            db.session.commit()

# Routes
@app.route('/')
def index():
    # Show loading screen first
    return render_template('loading.html')

@app.route('/login_form')
def login_form():
    # Show login form after loading
    return render_template('login_classic.html')

@app.route('/dashboard')
def dashboard():
    ensure_logged_in()
    
    # آمار کلی
    total_miners = DetectedMiner.query.filter_by(user_id=session['user_id']).count()
    active_miners = DetectedMiner.query.filter_by(user_id=session['user_id'], is_active=True).count()
    recent_scans = ScanSession.query.filter_by(user_id=session['user_id']).order_by(ScanSession.start_time.desc()).limit(5).all()
    
    # آمار تهدیدات
    threat_stats = db.session.query(
        DetectedMiner.threat_level,
        db.func.count(DetectedMiner.id).label('count')
    ).filter_by(user_id=session['user_id']).group_by(DetectedMiner.threat_level).all()
    
        return render_template('dashboard_win98.html', 
                         total_miners=total_miners,
                         active_miners=active_miners,
                         recent_scans=recent_scans,
                         threat_stats=threat_stats)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            return redirect(url_for('index'))
        else:
            flash('نام کاربری یا رمز عبور اشتباه است', 'error')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        if User.query.filter_by(username=username).first():
            flash('نام کاربری قبلاً استفاده شده است', 'error')
            return render_template('register.html')
        
        if User.query.filter_by(email=email).first():
            flash('ایمیل قبلاً استفاده شده است', 'error')
            return render_template('register.html')
        
        user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password)
        )
        
        db.session.add(user)
        db.session.commit()
        
        flash('ثبت نام با موفقیت انجام شد', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/scan', methods=['GET', 'POST'])
def scan():
    ensure_logged_in()
    
    if request.method == 'POST':
        scan_type = request.form['scan_type']
        target_range = request.form['target_range']
        
        # ایجاد session جدید اسکن
        session_id = str(uuid.uuid4())
        scan_session = ScanSession(
            session_id=session_id,
            user_id=session['user_id'],
            scan_type=scan_type,
            target_range=target_range
        )
        
        db.session.add(scan_session)
        db.session.commit()
        
        # شروع اسکن در پس‌زمینه
        threading.Thread(target=run_scan, args=(session_id,)).start()
        
        return redirect(url_for('scan_progress', session_id=session_id))
    
    return render_template('scan.html')

def run_scan(session_id):
    """اجرای اسکن در پس‌زمینه"""
    scan_session = ScanSession.query.filter_by(session_id=session_id).first()
    if not scan_session:
        return
    
    try:
        def progress_callback(progress, scanned, total):
            scan_session.progress = progress
            scan_session.scanned_hosts = scanned
            scan_session.total_hosts = total
            db.session.commit()
        
        results = detection_engine.scan_network_range(
            scan_session.target_range, 
            progress_callback
        )
        
        # ذخیره نتایج
        for result in results:
            miner = DetectedMiner(
                ip_address=result['ip'],
                mac_address=result.get('mac_address'),
                hostname=result.get('hostname'),
                device_type='cryptocurrency_miner',
                detection_method=','.join(result['detection_methods']),
                confidence_score=result['suspicion_score'],
                threat_level=result['threat_level'],
                open_ports=json.dumps(result['open_ports']),
                latitude=result.get('geolocation', {}).get('lat'),
                longitude=result.get('geolocation', {}).get('lon'),
                location=result.get('geolocation', {}).get('city'),
                user_id=scan_session.user_id
            )
            db.session.add(miner)
        
        scan_session.status = 'completed'
        scan_session.end_time = datetime.utcnow()
        scan_session.detected_miners = len(results)
        scan_session.results = json.dumps(results)
        
        db.session.commit()
        
    except Exception as e:
        logger.error(f"خطا در اجرای اسکن: {e}")
        scan_session.status = 'failed'
        scan_session.end_time = datetime.utcnow()
        db.session.commit()

@app.route('/scan_progress/<session_id>')
def scan_progress(session_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    scan_session = ScanSession.query.filter_by(session_id=session_id, user_id=session['user_id']).first()
    if not scan_session:
        return redirect(url_for('scan'))
    
    return render_template('scan_progress.html', scan_session=scan_session)

@app.route('/api/scan_status/<session_id>')
def scan_status(session_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    scan_session = ScanSession.query.filter_by(session_id=session_id, user_id=session['user_id']).first()
    if not scan_session:
        return jsonify({'error': 'Session not found'}), 404
    
    return jsonify({
        'status': scan_session.status,
        'progress': scan_session.progress,
        'scanned_hosts': scan_session.scanned_hosts,
        'total_hosts': scan_session.total_hosts,
        'detected_miners': scan_session.detected_miners
    })

@app.route('/miners')
def miners():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    page = request.args.get('page', 1, type=int)
    per_page = 20
    
    miners = DetectedMiner.query.filter_by(user_id=session['user_id']).order_by(
        DetectedMiner.detection_time.desc()
    ).paginate(page=page, per_page=per_page, error_out=False)
    
    return render_template('miners.html', miners=miners)

@app.route('/miner/<int:miner_id>')
def miner_detail(miner_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    miner = DetectedMiner.query.filter_by(id=miner_id, user_id=session['user_id']).first_or_404()
    return render_template('miner_detail.html', miner=miner)

@app.route('/reports')
def reports():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # آمار کلی
    total_miners = DetectedMiner.query.filter_by(user_id=session['user_id']).count()
    
    # آمار بر اساس سطح تهدید
    threat_stats = db.session.query(
        DetectedMiner.threat_level,
        db.func.count(DetectedMiner.id).label('count')
    ).filter_by(user_id=session['user_id']).group_by(DetectedMiner.threat_level).all()
    
    # آمار روزانه
    daily_stats = db.session.query(
        db.func.date(DetectedMiner.detection_time).label('date'),
        db.func.count(DetectedMiner.id).label('count')
    ).filter_by(user_id=session['user_id']).group_by(
        db.func.date(DetectedMiner.detection_time)
    ).order_by(db.func.date(DetectedMiner.detection_time).desc()).limit(30).all()
    
    # آمار پورت‌ها
    port_stats = {}
    miners_with_ports = DetectedMiner.query.filter_by(user_id=session['user_id']).all()
    for miner in miners_with_ports:
        if miner.open_ports:
            try:
                ports = json.loads(miner.open_ports)
                for port in ports:
                    port_stats[port] = port_stats.get(port, 0) + 1
            except:
                pass
    
    return render_template('reports.html',
                         total_miners=total_miners,
                         threat_stats=threat_stats,
                         daily_stats=daily_stats,
                         port_stats=port_stats)

@app.route('/api/system_metrics')
def system_metrics():
    ensure_logged_in()
    
    # جمع‌آوری معیارهای سیستم
    cpu_usage = psutil.cpu_percent()
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    network = psutil.net_io_counters()
    
    # ذخیره در دیتابیس
    metrics = SystemMetrics(
        cpu_usage=cpu_usage,
        memory_usage=memory.percent,
        network_io=network.bytes_sent + network.bytes_recv,
        disk_io=disk.used,
        active_connections=len(psutil.net_connections())
    )
    
    db.session.add(metrics)
    db.session.commit()
    
    return jsonify({
        'cpu_usage': cpu_usage,
        'memory_usage': memory.percent,
        'disk_usage': (disk.used / disk.total) * 100,
        'network_io': network.bytes_sent + network.bytes_recv,
        'active_connections': len(psutil.net_connections())
    })

@app.route('/api/live_monitor')
def live_monitor():
    ensure_logged_in()
    
    # نظارت زنده بر فرآیندها
    suspicious_processes = detection_engine.detect_miner_processes()
    
    # نظارت بر اتصالات شبکه
    network_connections = []
    for conn in psutil.net_connections():
        if conn.raddr and conn.raddr.port in detection_engine.miner_ports:
            network_connections.append({
                'local_addr': f"{conn.laddr.ip}:{conn.laddr.port}",
                'remote_addr': f"{conn.raddr.ip}:{conn.raddr.port}",
                'status': conn.status,
                'service': detection_engine.miner_ports[conn.raddr.port]
            })
    
    return jsonify({
        'suspicious_processes': suspicious_processes,
        'network_connections': network_connections,
        'timestamp': datetime.utcnow().isoformat()
    })

# ایجاد جداول دیتابیس
with app.app_context():
    db.create_all()
    
    # ایجاد کاربر ادمین پیش‌فرض
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        admin = User(
            username='admin',
            email='admin@example.com',
            password_hash=generate_password_hash('admin123'),
            role='admin'
        )
        db.session.add(admin)
        db.session.commit()

@app.route('/about')
def about():
    ensure_logged_in()
    return render_template('about.html')

@app.route('/scan_history')
def scan_history():
    ensure_logged_in()
    return render_template('scan_history.html')

@app.route('/api/scan_sessions')
def api_scan_sessions():
    ensure_logged_in()
    sessions = ScanSession.query.filter_by(user_id=session['user_id']).order_by(ScanSession.start_time.desc()).all()

    sessions_data = []
    for s in sessions:
        sessions_data.append({
            'id': s.session_id,
            'scan_type': s.scan_type,
            'target_range': s.target_range,
            'status': s.status,
            'progress': s.progress,
            'detected_miners': s.detected_miners,
            'start_time': s.start_time.strftime('%Y-%m-%d %H:%M:%S') if s.start_time else '',
            'end_time': s.end_time.strftime('%Y-%m-%d %H:%M:%S') if s.end_time else '',
            'total_hosts': s.total_hosts,
            'scanned_hosts': s.scanned_hosts
        })

    return jsonify(sessions_data)

@app.route('/api/pause_scan/<session_id>', methods=['POST'])
def api_pause_scan(session_id):
    ensure_logged_in()
    scan_session = ScanSession.query.filter_by(session_id=session_id, user_id=session['user_id']).first()
    if scan_session:
        scan_session.status = 'paused'
        db.session.commit()
        return jsonify({'success': True, 'message': 'اسکن متوقف شد'})
    return jsonify({'success': False, 'message': 'اسکن یافت نشد'})

@app.route('/api/retry_scan/<session_id>', methods=['POST'])
def api_retry_scan(session_id):
    ensure_logged_in()
    scan_session = ScanSession.query.filter_by(session_id=session_id, user_id=session['user_id']).first()
    if scan_session:
        scan_session.status = 'running'
        scan_session.progress = 0
        scan_session.start_time = datetime.utcnow()
        db.session.commit()

        # Restart scan in background
        threading.Thread(target=run_scan, args=(session_id,)).start()

        return jsonify({'success': True, 'message': 'اسکن مجدد شروع شد'})
    return jsonify({'success': False, 'message': 'اسکن یافت نشد'})

@app.route('/api/download_report/<session_id>')
def api_download_report(session_id):
    ensure_logged_in()
    scan_session = ScanSession.query.filter_by(session_id=session_id, user_id=session['user_id']).first()
    if scan_session:
        # Generate report content
        report_content = f"""
گزارش اسکن {session_id}
===================
نوع اسکن: {scan_session.scan_type}
محدوده: {scan_session.target_range}
وضعیت: {scan_session.status}
زمان شروع: {scan_session.start_time}
زمان پایان: {scan_session.end_time}
ماینرهای یافت شده: {scan_session.detected_miners}
میزبان‌های اسکن شده: {scan_session.scanned_hosts}
        """

        from flask import make_response
        response = make_response(report_content)
        response.headers['Content-Disposition'] = f'attachment; filename=scan_report_{session_id}.txt'
        response.headers['Content-Type'] = 'text/plain; charset=utf-8'
        return response

    return jsonify({'error': 'گزارش یافت نشد'}), 404

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
