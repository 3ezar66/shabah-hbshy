#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ماژول اسکن شبکه پیشرفته برای تشخیص ماینرهای رمزارز
توسط: عرفان رجبی (Erfan Rajabi)
"""

import socket
import struct
import time
import json
import threading
from datetime import datetime
from typing import List, Dict, Optional, Tuple
import subprocess
import ipaddress
import re

class NetworkScanner:
    """کلاس اصلی برای اسکن شبکه و تشخیص ماینرها"""
    
    def __init__(self):
        self.mining_ports = [3333, 4444, 5555, 7777, 8080, 8333, 9332, 14444]
        self.common_pools = [
            'pool.supportxmr.com', 'xmr-usa-east1.nanopool.org',
            'eth-us-east1.nanopool.org', 'btc.antpool.com',
            'stratum+tcp://pool.minergate.com', 'eu1.ethermine.org'
        ]
        self.scan_results = {}
        self.active_threads = []
        
    def ping_sweep(self, network: str) -> List[str]:
        """پینگ تمام آی‌پی‌های یک شبکه برای پیدا کردن هاست‌های فعال"""
        active_hosts = []
        
        try:
            network_obj = ipaddress.ip_network(network, strict=False)
            
            for ip in network_obj.hosts():
                if self._ping_host(str(ip)):
                    active_hosts.append(str(ip))
                    print(f"✅ هاست فعال: {ip}")
                    
        except Exception as e:
            print(f"❌ خطا در ping sweep: {e}")
            
        return active_hosts
    
    def _ping_host(self, ip: str, timeout: int = 1) -> bool:
        """پینگ یک IP برای بررسی فعال بودن"""
        try:
            result = subprocess.run(
                ['ping', '-c', '1', '-W', str(timeout), ip],
                capture_output=True, text=True, timeout=timeout+1
            )
            return result.returncode == 0
        except:
            return False
    
    def port_scan(self, ip: str, ports: List[int] = None) -> Dict[int, bool]:
        """اسکن پورت‌های مشکوک در یک IP"""
        if ports is None:
            ports = self.mining_ports
            
        open_ports = {}
        
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            
            try:
                result = sock.connect_ex((ip, port))
                if result == 0:
                    open_ports[port] = True
                    print(f"🔓 پورت باز: {ip}:{port}")
                else:
                    open_ports[port] = False
            except:
                open_ports[port] = False
            finally:
                sock.close()
                
        return open_ports
    
    def detect_stratum_protocol(self, ip: str, port: int) -> Dict:
        """تشخیص پروتکل Stratum در یک IP:Port"""
        result = {
            'is_stratum': False,
            'method': None,
            'response': None,
            'mining_software': None
        }
        
        stratum_requests = [
            '{"id": 1, "method": "mining.subscribe", "params": []}\n',
            '{"id": 1, "method": "mining.authorize", "params": ["test", "test"]}\n'
        ]
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((ip, port))
            
            for request in stratum_requests:
                sock.send(request.encode())
                response = sock.recv(1024).decode()
                
                if any(keyword in response.lower() for keyword in 
                      ['mining', 'subscribe', 'authorize', 'difficulty', 'target']):
                    result['is_stratum'] = True
                    result['method'] = 'stratum'
                    result['response'] = response
                    
                    # تشخیص نرم‌افزار ماینینگ
                    if 'xmrig' in response.lower():
                        result['mining_software'] = 'XMRig'
                    elif 'claymore' in response.lower():
                        result['mining_software'] = 'Claymore'
                    elif 'phoenixminer' in response.lower():
                        result['mining_software'] = 'PhoenixMiner'
                    
                    break
                    
            sock.close()
            
        except Exception as e:
            pass
            
        return result
    
    def get_mac_address(self, ip: str) -> Optional[str]:
        """دریافت MAC Address از جدول ARP"""
        try:
            # Linux/Unix
            result = subprocess.run(['arp', '-n', ip], 
                                  capture_output=True, text=True)
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    if ip in line:
                        parts = line.split()
                        for part in parts:
                            if re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', part):
                                return part.upper()
        except:
            pass
            
        return None
    
    def analyze_traffic_pattern(self, ip: str, duration: int = 60) -> Dict:
        """تحلیل الگوی ترافیک برای تشخیص رفتار ماینر"""
        pattern_data = {
            'constant_traffic': False,
            'suspicious_connections': [],
            'upload_download_ratio': 0,
            'connection_frequency': 0
        }
        
        # شبیه‌سازی تحلیل ترافیک (در واقعیت باید از ابزارهای مانیتورینگ استفاده شود)
        try:
            # بررسی اتصالات فعال
            netstat_result = subprocess.run(
                ['netstat', '-tn'], capture_output=True, text=True
            )
            
            connections = []
            for line in netstat_result.stdout.split('\n'):
                if ip in line and 'ESTABLISHED' in line:
                    connections.append(line.strip())
            
            pattern_data['connection_frequency'] = len(connections)
            
            # بررسی اتصال به پورت‌های معروف استخرها
            for connection in connections:
                for port in self.mining_ports:
                    if f':{port}' in connection:
                        pattern_data['suspicious_connections'].append(connection)
                        
        except:
            pass
            
        return pattern_data
    
    def comprehensive_scan(self, target: str) -> Dict:
        """اسکن جامع یک هدف (IP یا شبکه)"""
        scan_id = f"scan_{int(time.time())}"
        start_time = datetime.now()
        
        print(f"🔍 شروع اسکن جامع: {target}")
        
        # تشخیص نوع هدف (IP منفرد یا شبکه)
        if '/' in target:
            # اسکن شبکه
            active_hosts = self.ping_sweep(target)
        else:
            # اسکن IP منفرد
            active_hosts = [target] if self._ping_host(target) else []
        
        results = {
            'scan_id': scan_id,
            'target': target,
            'start_time': start_time.isoformat(),
            'total_hosts': len(active_hosts),
            'scanned_hosts': {},
            'summary': {
                'potential_miners': 0,
                'confirmed_miners': 0,
                'suspicious_hosts': 0
            }
        }
        
        # اسکن تک تک هاست‌ها
        for host in active_hosts:
            host_result = self._scan_single_host(host)
            results['scanned_hosts'][host] = host_result
            
            # به‌روزرسانی خلاصه
            if host_result['risk_level'] == 'confirmed':
                results['summary']['confirmed_miners'] += 1
            elif host_result['risk_level'] == 'potential':
                results['summary']['potential_miners'] += 1
            elif host_result['risk_level'] == 'suspicious':
                results['summary']['suspicious_hosts'] += 1
        
        end_time = datetime.now()
        results['end_time'] = end_time.isoformat()
        results['duration'] = str(end_time - start_time)
        
        # ذخیره نتایج
        self.scan_results[scan_id] = results
        
        print(f"✅ اسکن کامل شد. ماینرهای تایید شده: {results['summary']['confirmed_miners']}")
        
        return results
    
    def _scan_single_host(self, ip: str) -> Dict:
        """اسکن کامل یک هاست"""
        print(f"🔎 اسکن هاست: {ip}")
        
        host_data = {
            'ip': ip,
            'mac_address': self.get_mac_address(ip),
            'hostname': self._get_hostname(ip),
            'open_ports': self.port_scan(ip),
            'stratum_detection': {},
            'traffic_analysis': {},
            'risk_level': 'safe',
            'confidence': 0,
            'indicators': []
        }
        
        # بررسی پورت‌های باز برای Stratum
        confidence_score = 0
        
        for port, is_open in host_data['open_ports'].items():
            if is_open:
                stratum_result = self.detect_stratum_protocol(ip, port)
                host_data['stratum_detection'][port] = stratum_result
                
                if stratum_result['is_stratum']:
                    confidence_score += 40
                    host_data['indicators'].append(f"پروتکل Stratum در پورت {port}")
                    
                    if stratum_result['mining_software']:
                        confidence_score += 30
                        host_data['indicators'].append(f"نرم‌افزار ماینینگ: {stratum_result['mining_software']}")
        
        # تحلیل ترافیک
        traffic_data = self.analyze_traffic_pattern(ip)
        host_data['traffic_analysis'] = traffic_data
        
        if traffic_data['suspicious_connections']:
            confidence_score += 20
            host_data['indicators'].append(f"اتصالات مشکوک: {len(traffic_data['suspicious_connections'])}")
        
        # تعیین سطح خطر
        if confidence_score >= 70:
            host_data['risk_level'] = 'confirmed'
        elif confidence_score >= 40:
            host_data['risk_level'] = 'potential'
        elif confidence_score >= 20:
            host_data['risk_level'] = 'suspicious'
        else:
            host_data['risk_level'] = 'safe'
        
        host_data['confidence'] = min(confidence_score, 100)
        
        return host_data
    
    def _get_hostname(self, ip: str) -> Optional[str]:
        """دریافت hostname از IP"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:
            return None
    
    def get_scan_results(self, scan_id: str = None) -> Dict:
        """دریافت نتایج اسکن"""
        if scan_id:
            return self.scan_results.get(scan_id, {})
        return self.scan_results
    
    def export_results(self, scan_id: str, format: str = 'json') -> str:
        """خروجی ��یری نتایج به فرمت‌های مختلف"""
        if scan_id not in self.scan_results:
            return "اسکن پیدا نشد"
        
        data = self.scan_results[scan_id]
        
        if format == 'json':
            return json.dumps(data, ensure_ascii=False, indent=2)
        elif format == 'csv':
            # تبدیل به CSV
            csv_lines = ['IP,MAC,Hostname,Risk Level,Confidence,Indicators']
            for ip, host_data in data['scanned_hosts'].items():
                indicators = '; '.join(host_data['indicators'])
                csv_lines.append(f"{ip},{host_data['mac_address']},{host_data['hostname']},{host_data['risk_level']},{host_data['confidence']},\"{indicators}\"")
            return '\n'.join(csv_lines)
        
        return str(data)

# تست سریع
if __name__ == "__main__":
    scanner = NetworkScanner()
    
    # تست روی شبکه محلی
    results = scanner.comprehensive_scan("192.168.1.0/24")
    print("\n" + "="*50)
    print("خلاصه نتایج:")
    print(f"تعداد هاست‌های فعال: {results['total_hosts']}")
    print(f"ماینرهای تایید شده: {results['summary']['confirmed_miners']}")
    print(f"ماینرهای احتمالی: {results['summary']['potential_miners']}")
    print(f"هاست‌های مشکوک: {results['summary']['suspicious_hosts']}")
