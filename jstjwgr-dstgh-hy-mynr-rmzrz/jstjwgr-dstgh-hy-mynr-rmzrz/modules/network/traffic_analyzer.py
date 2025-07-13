#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ماژول تحلیل ترافیک شبکه برای تشخیص الگوهای ماینینگ
توسط: عرفان رجبی (Erfan Rajabi)
"""

import time
import threading
import json
from datetime import datetime, timedelta
from collections import defaultdict, deque
from typing import Dict, List, Optional, Tuple
import socket
import struct

class TrafficAnalyzer:
    """تحلیلگر ترافیک برای شناسایی الگوهای ماینینگ"""
    
    def __init__(self, monitoring_duration: int = 300):
        self.monitoring_duration = monitoring_duration  # 5 دقیقه
        self.traffic_data = defaultdict(lambda: {
            'bytes_sent': deque(maxlen=100),
            'bytes_received': deque(maxlen=100),
            'connections': deque(maxlen=50),
            'timestamps': deque(maxlen=100),
            'patterns': {}
        })
        
        self.mining_signatures = {
            'stratum_subscribe': b'mining.subscribe',
            'stratum_authorize': b'mining.authorize',
            'stratum_submit': b'mining.submit',
            'getwork': b'getwork',
            'eth_submitWork': b'eth_submitWork',
            'eth_getWork': b'eth_getWork'
        }
        
        self.pool_domains = [
            'nanopool.org', 'ethermine.org', 'f2pool.com',
            'antpool.com', 'slushpool.com', 'minergate.com',
            'supportxmr.com', 'miningpoolhub.com'
        ]
        
        self.suspicious_patterns = {}
        self.is_monitoring = False
        
    def start_monitoring(self, target_network: str = None):
        """شروع مانیتورینگ ترافیک"""
        self.is_monitoring = True
        print(f"🔍 شروع مانیتورینگ ترافیک...")
        
        # شروع thread مانیتورینگ
        monitor_thread = threading.Thread(
            target=self._monitor_traffic, 
            args=(target_network,)
        )
        monitor_thread.daemon = True
        monitor_thread.start()
        
        # شروع thread تحلیل الگوها
        analysis_thread = threading.Thread(target=self._analyze_patterns)
        analysis_thread.daemon = True
        analysis_thread.start()
        
    def stop_monitoring(self):
        """توقف مانیتورینگ"""
        self.is_monitoring = False
        print("⏹️ مانیتورینگ ترافیک متو��ف شد")
        
    def _monitor_traffic(self, target_network: str = None):
        """مانیتورینگ فعال ترافیک (شبیه‌سازی)"""
        while self.is_monitoring:
            try:
                # شبیه‌سازی جمع‌آوری داده‌های ترافیک
                # در عمل باید از ابزارهایی مثل tcpdump یا WinPcap استفاده شود
                current_connections = self._get_active_connections()
                
                for connection in current_connections:
                    self._process_connection(connection)
                
                time.sleep(1)  # چک هر ثانیه
                
            except Exception as e:
                print(f"❌ خطا در مانیتورینگ: {e}")
                time.sleep(5)
    
    def _get_active_connections(self) -> List[Dict]:
        """دریافت اتصالات فعال سیستم"""
        connections = []
        
        try:
            import subprocess
            result = subprocess.run(
                ['netstat', '-tn'], 
                capture_output=True, 
                text=True
            )
            
            for line in result.stdout.split('\n'):
                if 'ESTABLISHED' in line:
                    parts = line.split()
                    if len(parts) >= 5:
                        local_addr = parts[3]
                        remote_addr = parts[4]
                        
                        # پارس کردن IP و Port
                        try:
                            local_ip, local_port = local_addr.rsplit(':', 1)
                            remote_ip, remote_port = remote_addr.rsplit(':', 1)
                            
                            connections.append({
                                'local_ip': local_ip,
                                'local_port': int(local_port),
                                'remote_ip': remote_ip,
                                'remote_port': int(remote_port),
                                'timestamp': time.time()
                            })
                        except:
                            continue
                            
        except Exception as e:
            pass
            
        return connections
    
    def _process_connection(self, connection: Dict):
        """پردازش یک اتصال"""
        local_ip = connection['local_ip']
        remote_ip = connection['remote_ip']
        remote_port = connection['remote_port']
        timestamp = connection['timestamp']
        
        # ثبت اتصال
        self.traffic_data[local_ip]['connections'].append(connection)
        self.traffic_data[local_ip]['timestamps'].append(timestamp)
        
        # بررسی پورت‌های مشکوک
        suspicious_ports = [3333, 4444, 5555, 7777, 8080, 8333, 9332, 14444]
        if remote_port in suspicious_ports:
            self._flag_suspicious_activity(local_ip, 'suspicious_port', {
                'remote_ip': remote_ip,
                'remote_port': remote_port,
                'timestamp': timestamp
            })
        
        # بررسی DNS برای دامنه‌های استخر
        self._check_pool_domain(local_ip, remote_ip)
        
    def _check_pool_domain(self, local_ip: str, remote_ip: str):
        """بررسی آیا IP مقصد متعلق به استخر ماینینگ است"""
        try:
            hostname = socket.gethostbyaddr(remote_ip)[0]
            
            for pool_domain in self.pool_domains:
                if pool_domain in hostname.lower():
                    self._flag_suspicious_activity(local_ip, 'pool_connection', {
                        'pool_domain': hostname,
                        'pool_ip': remote_ip,
                        'timestamp': time.time()
                    })
                    break
                    
        except:
            pass
    
    def _flag_suspicious_activity(self, ip: str, activity_type: str, details: Dict):
        """علامت‌گذاری فعالیت مشکوک"""
        if ip not in self.suspicious_patterns:
            self.suspicious_patterns[ip] = []
        
        self.suspicious_patterns[ip].append({
            'type': activity_type,
            'details': details,
            'flagged_at': time.time()
        })
        
        print(f"⚠️  فعالیت مشکوک: {ip} - {activity_type}")
    
    def _analyze_patterns(self):
        """تحلیل الگوهای ترافیک"""
        while self.is_monitoring:
            try:
                current_time = time.time()
                
                for ip, data in self.traffic_data.items():
                    if len(data['timestamps']) >= 10:
                        patterns = self._detect_mining_patterns(ip, data)
                        self.traffic_data[ip]['patterns'] = patterns
                        
                        if patterns['is_mining_likely']:
                            self._flag_suspicious_activity(ip, 'mining_pattern', patterns)
                
                time.sleep(30)  # تحلیل هر 30 ثانیه
                
            except Exception as e:
                print(f"❌ خطا در تحلیل الگوها: {e}")
                time.sleep(60)
    
    def _detect_mining_patterns(self, ip: str, data: Dict) -> Dict:
        """تشخیص الگوهای ماینینگ در ترافیک"""
        patterns = {
            'is_mining_likely': False,
            'confidence': 0,
            'indicators': [],
            'connection_frequency': 0,
            'constant_activity': False,
            'suspicious_ports': [],
            'pool_connections': []
        }
        
        # تحلیل فرکانس اتصالات
        if len(data['connections']) > 0:
            recent_connections = [
                conn for conn in data['connections'] 
                if time.time() - conn['timestamp'] < 300  # 5 دقیقه اخیر
            ]
            
            patterns['connection_frequency'] = len(recent_connections)
            
            # بررسی اتصال مداوم
            if len(recent_connections) > 20:  # بیش از 20 اتصال در 5 دقیقه
                patterns['constant_activity'] = True
                patterns['indicators'].append('فعالیت مداوم شبکه')
                patterns['confidence'] += 25
        
        # بررسی پورت‌های مشکوک
        suspicious_ports = set()
        for conn in data['connections']:
            if conn['remote_port'] in [3333, 4444, 5555, 7777]:
                suspicious_ports.add(conn['remote_port'])
        
        patterns['suspicious_ports'] = list(suspicious_ports)
        if suspicious_ports:
            patterns['indicators'].append(f'اتصال به پورت‌های ماینینگ: {suspicious_ports}')
            patterns['confidence'] += 30
        
        # بررسی اتصالات استخر
        if ip in self.suspicious_patterns:
            pool_connections = [
                activity for activity in self.suspicious_patterns[ip]
                if activity['type'] == 'pool_connection'
            ]
            if pool_connections:
                patterns['pool_connections'] = pool_connections
                patterns['indicators'].append(f'اتصال به {len(pool_connections)} استخر')
                patterns['confidence'] += 40
        
        # تعیین احتمال ماینینگ
        if patterns['confidence'] >= 60:
            patterns['is_mining_likely'] = True
        
        return patterns
    
    def get_traffic_analysis(self, ip: str = None) -> Dict:
        """دریافت تحلیل ترافیک"""
        if ip:
            return {
                'ip': ip,
                'traffic_data': dict(self.traffic_data[ip]) if ip in self.traffic_data else {},
                'suspicious_activities': self.suspicious_patterns.get(ip, [])
            }
        
        # گزارش کلی
        summary = {
            'total_monitored_ips': len(self.traffic_data),
            'suspicious_ips': len(self.suspicious_patterns),
            'mining_likely_ips': [],
            'analysis_timestamp': datetime.now().isoformat()
        }
        
        # شناسایی IP های احتمالی ماینر
        for ip, data in self.traffic_data.items():
            if 'patterns' in data and data['patterns'].get('is_mining_likely', False):
                summary['mining_likely_ips'].append({
                    'ip': ip,
                    'confidence': data['patterns']['confidence'],
                    'indicators': data['patterns']['indicators']
                })
        
        return summary
    
    def generate_report(self, format: str = 'json') -> str:
        """تولید گزارش تحلیل ترافیک"""
        analysis = self.get_traffic_analysis()
        
        if format == 'json':
            return json.dumps(analysis, ensure_ascii=False, indent=2)
        
        elif format == 'text':
            report = f"""
🔍 گزارش تحلیل ترافیک شبکه
{'='*50}
زمان تحلیل: {analysis['analysis_timestamp']}
تعداد IP های مانیتور شده: {analysis['total_monitored_ips']}
تعداد IP های مشکوک: {analysis['suspicious_ips']}

🚨 IP های احتمالی ماینر:
{'-'*30}
"""
            for ip_data in analysis['mining_likely_ips']:
                report += f"""
IP: {ip_data['ip']}
اطمینان: {ip_data['confidence']}%
شاخص‌ها: {', '.join(ip_data['indicators'])}
{'-'*30}
"""
            return report
        
        return str(analysis)

# مثال استفاده
if __name__ == "__main__":
    analyzer = TrafficAnalyzer()
    
    print("🚀 شروع تحلیل ترافیک...")
    analyzer.start_monitoring()
    
    try:
        # مانیتورینگ به مدت 2 دقیقه
        time.sleep(120)
        
        # دریافت گزارش
        report = analyzer.generate_report('text')
        print(report)
        
    finally:
        analyzer.stop_monitoring()
