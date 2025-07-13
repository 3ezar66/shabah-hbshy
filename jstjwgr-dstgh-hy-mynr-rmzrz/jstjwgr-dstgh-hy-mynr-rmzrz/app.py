#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
��یستم ��امع شناسایی و نظارت بر ماینرهای رمزارز
نرم‌افزار حرفه‌ای چندکاربره با رابط وب و بانک اطلاعاتی
"""

from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import secrets
import uuid

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
    return render_template('loading_glitch.html')

@app.route('/login_form')
def login_form():
    return render_template('login_modern.html')

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
            
            return redirect(url_for('dashboard'))
        else:
            return render_template('login_modern.html', error_message='نام کاربری یا رمز عبور اشتباه است')
    
    return render_template('login_modern.html')

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
        
        return redirect(url_for('scan_progress', session_id=session_id))
    
    return render_template('scan.html')

@app.route('/scan_progress/<session_id>')
def scan_progress(session_id):
    ensure_logged_in()
    
    scan_session = ScanSession.query.filter_by(session_id=session_id, user_id=session['user_id']).first()
    if not scan_session:
        return redirect(url_for('scan'))
    
    return render_template('scan_progress.html', scan_session=scan_session)

@app.route('/scan_history')
def scan_history():
    ensure_logged_in()
    return render_template('scan_history.html')

@app.route('/miners')
def miners():
    ensure_logged_in()
    
    page = request.args.get('page', 1, type=int)
    per_page = 20
    
    miners = DetectedMiner.query.filter_by(user_id=session['user_id']).order_by(
        DetectedMiner.detection_time.desc()
    ).paginate(page=page, per_page=per_page, error_out=False)
    
    return render_template('miners.html', miners=miners)

@app.route('/reports')
def reports():
    ensure_logged_in()
    
    # آمار کلی
    total_miners = DetectedMiner.query.filter_by(user_id=session['user_id']).count()
    
    # آمار بر اساس سطح تهدید
    threat_stats = db.session.query(
        DetectedMiner.threat_level,
        db.func.count(DetectedMiner.id).label('count')
    ).filter_by(user_id=session['user_id']).group_by(DetectedMiner.threat_level).all()
    
    return render_template('reports.html',
                         total_miners=total_miners,
                         threat_stats=threat_stats,
                         daily_stats=[],
                         port_stats={})

@app.route('/about')
def about():
    ensure_logged_in()
    return render_template('about.html')

@app.route('/scanner')
def real_time_scanner():
    """صفحه اسکن زنده و واقعی"""
    ensure_logged_in()
    return render_template('real_time_scanner.html')

@app.route('/map')
def dynamic_map():
    """صفحه نقشه پویا و مکان‌یابی"""
    ensure_logged_in()
    return render_template('dynamic_map.html')

@app.route('/api/scan/start', methods=['POST'])
def start_scan():
    """API شروع اسکن واقعی"""
    ensure_logged_in()

    try:
        data = request.json or {}
        target = data.get('target', '192.168.1.0/24')
        ports = data.get('ports', [22, 80, 443, 3333, 4444])
        scan_type = data.get('scan_type', 'network')

        # ایجاد session اسکن
        session_id = str(uuid.uuid4())
        scan_session = ScanSession(
            session_id=session_id,
            user_id=session['user_id'],
            scan_type=scan_type,
            target_range=target,
            status='running'
        )

        db.session.add(scan_session)
        db.session.commit()

        # اجرای اسکن واقعی
        try:
            import sys
            import os
            sys.path.append(os.path.dirname(__file__))

            from modules.network.scanner import NetworkScanner
            scanner = NetworkScanner()
            results = scanner.comprehensive_scan(target)

            # به‌روزرسانی session
            scan_session.status = 'completed'
            scan_session.end_time = datetime.utcnow()
            scan_session.total_hosts = results.get('total_hosts', 0)
            scan_session.detected_miners = results.get('summary', {}).get('confirmed_miners', 0)
            scan_session.results = str(results)
            scan_session.progress = 100

            db.session.commit()

            # ذخیره ماینرهای شناسایی شده
            for ip, host_data in results.get('scanned_hosts', {}).items():
                if host_data.get('risk_level') in ['confirmed', 'potential']:
                    miner = DetectedMiner(
                        ip_address=ip,
                        mac_address=host_data.get('mac_address'),
                        hostname=host_data.get('hostname'),
                        device_type='Unknown',
                        detection_method='Network Scan',
                        confidence_score=host_data.get('confidence', 0),
                        threat_level=host_data.get('risk_level'),
                        open_ports=','.join([str(p) for p, status in host_data.get('open_ports', {}).items() if status]),
                        user_id=session['user_id']
                    )
                    db.session.add(miner)

            db.session.commit()

            return jsonify({
                'status': 'success',
                'scan_id': session_id,
                'message': 'اسکن با موفقیت کامل شد',
                'results': results
                        })

        except ImportError as e:
            # اعلام خطا در صورت عدم دسترسی به ماژول
            scan_session.status = 'failed'
            scan_session.end_time = datetime.utcnow()
            db.session.commit()

            return jsonify({
                'status': 'error',
                'message': f'ماژول اسکن در دسترس نیست: {str(e)}'
            }), 500

    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'خطا در شروع اسکن: {str(e)}'
        }), 500

@app.route('/api/scan/results/<scan_id>')
def get_scan_results(scan_id):
    """دریافت نتایج اسکن"""
    ensure_logged_in()

    try:
        scan_session = ScanSession.query.filter_by(
            session_id=scan_id,
            user_id=session['user_id']
        ).first()

        if scan_session:
            return jsonify({
                'session_id': scan_session.session_id,
                'status': scan_session.status,
                'progress': scan_session.progress,
                'total_hosts': scan_session.total_hosts,
                'detected_miners': scan_session.detected_miners,
                'start_time': scan_session.start_time.isoformat(),
                'end_time': scan_session.end_time.isoformat() if scan_session.end_time else None,
                'results': scan_session.results
            })
        else:
            return jsonify({'error': 'اسکن یافت نشد'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/geoip/lookup/<ip>')
def geoip_lookup(ip):
    """مکان‌یابی آدرس IP"""
    ensure_logged_in()

        try:
        import sys
        import os
        sys.path.append(os.path.dirname(__file__))

        from modules.geolocation.iran_geoip import IranGeoIP
        geoip = IranGeoIP()
        location = geoip.lookup_ip(ip)

        return jsonify(location)
    except ImportError:
        return jsonify({'error': 'ماژول مکان‌یابی در دسترس نیست'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/rf/scan/start', methods=['POST'])
def start_rf_scan():
    """شروع اسکن RF و مغناطیسی"""
    ensure_logged_in()

    try:
        import sys
        import os
        sys.path.append(os.path.dirname(__file__))

        data = request.json or {}
        area = data.get('area', 'local')
        duration = data.get('duration', 300)

        from modules.detection.rf_detector import RFDetector
        detector = RFDetector()
        detector.start_rf_monitoring(area, duration)

        return jsonify({
            'status': 'success',
            'message': 'اسکن RF شروع شد',
            'duration': duration
        })
        except ImportError:
        return jsonify({
            'status': 'error',
            'message': 'ماژول اسکن RF در دسترس نیست'
        }), 500
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'خطا در شروع اسکن RF: {str(e)}'
        }), 500

@app.route('/api/ai/analyze', methods=['POST'])
def ai_analyze():
    """تحلیل هوش مصنوعی"""
    ensure_logged_in()

    try:
        import sys
        import os
        sys.path.append(os.path.dirname(__file__))

        data = request.json or {}
        network_data = data.get('network_data', {})

        from modules.ai.free_ai_models import FreeAIAnalyzer
        analyzer = FreeAIAnalyzer()
        analysis = analyzer.analyze_network_pattern(network_data)

        return jsonify(analysis)
        except ImportError:
        return jsonify({'error': 'ماژول تحلیل هوش مصنوعی در دسترس نیست'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/provinces')
def get_provinces():
    """دریافت لیست استان‌های ایران"""
    ensure_logged_in()

    provinces = [
        {'code': 'ilam', 'name': 'ایلام', 'capital': 'ایلام'},
        {'code': 'tehran', 'name': 'تهران', 'capital': 'تهران'},
        {'code': 'isfahan', 'name': 'اصفهان', 'capital': 'اصفهان'},
        {'code': 'shiraz', 'name': 'فارس', 'capital': 'شی��از'},
        {'code': 'tabriz', 'name': 'آذربایجان شرقی', 'capital': 'تبریز'},
        {'code': 'mashhad', 'name': 'خراسان رضوی', 'capital': 'مشهد'}
    ]

    return jsonify(provinces)

@app.route('/api/cities/<province_code>')
def get_cities(province_code):
    """دریافت شهرهای یک استان"""
    ensure_logged_in()

    cities_data = {
        'ilam': ['ایلام', 'ایوان', 'دره‌شهر', 'دهلران', 'آبدانان', 'مهران', 'ملکشاهی', 'سرابله', 'چرداول'],
        'tehran': ['تهران', 'کرج', 'ری', 'شهریار', 'ورامین'],
        'isfahan': ['اصفهان', 'کاشان', 'نجف‌آباد', 'خمینی‌شهر', 'شاهین‌شهر'],
        'shiraz': ['شیراز', 'کازرون', 'مرودشت', 'جهرم', 'لار'],
        'tabriz': ['تبریز', 'مراغه', 'اهر', 'بناب', 'میانه'],
        'mashhad': ['مشهد', 'نیشابور', 'سبزوار', 'کاشمر', 'گناباد']
    }

    cities = cities_data.get(province_code, [])
    return jsonify(cities)

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

@app.route('/api/system_metrics')
def system_metrics():
    ensure_logged_in()
    
    # Mock data for now
    return jsonify({
        'cpu_usage': 45.2,
        'memory_usage': 62.1,
        'disk_usage': 78.5,
        'network_io': 1024000,
        'active_connections': 15
    })

@app.route('/api/live_monitor')
def live_monitor():
    ensure_logged_in()
    
    # Mock data for now
    return jsonify({
        'suspicious_processes': [],
        'network_connections': [],
        'timestamp': datetime.utcnow().isoformat()
    })

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

# ایجاد جداول دی��ابیس
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

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
