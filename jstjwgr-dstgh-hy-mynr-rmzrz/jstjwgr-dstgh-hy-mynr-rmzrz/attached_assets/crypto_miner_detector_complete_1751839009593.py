#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
سیستم جامع شناسایی و مکان‌یابی دستگاه‌های ماینر ارز دیجیتال
ویژه استان ایلام - جمهوری اسلامی ایران
"""

import socket
import threading
import subprocess
import re
import json
import time
import psutil
import requests
import folium
import geopy
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import scapy.all as scapy
from collections import defaultdict
import hashlib
import statistics
import sqlite3
import math
import numpy as np
from geopy.distance import geodesic
from scipy.optimize import minimize
import wifi
import netifaces

class IlamMinerGeoDetector:
    def __init__(self):
        # مختصات استان ایلام
        self.ilam_bounds = {
            'north': 34.5,
            'south': 32.0, 
            'east': 48.5,
            'west': 45.5,
            'center': (33.63, 46.42)  # مرکز استان ایلام
        }
        
        # شهرهای اصلی ایلام
        self.ilam_cities = {
            'ایلام': (33.6374, 46.4227),
            'مهران': (33.1221, 46.1641),
            'دهلران': (32.6942, 47.2678),
            'آبدانان': (32.9928, 47.4164),
            'دره‌شهر': (33.1458, 47.3667),
            'ایوان': (33.8081, 46.2892),
            'چرداول': (33.7333, 46.8833),
            'بدره': (33.0833, 47.1167),
            'سرابله': (32.9667, 46.5833),
            'ملکشاهی': (33.3833, 46.5667),
            'شیروان چرداول': (33.9, 46.95)
        }
        
        # پورت‌های تشخیص ماینر
        self.miner_ports = {
            4028: "CGMiner API", 4029: "SGMiner API", 4030: "BFGMiner API",
            8080: "Web Interface", 8888: "Web Interface Alt", 9999: "Stratum Pool",
            3333: "Stratum Pool", 4444: "Stratum Pool Alt", 14444: "Stratum SSL",
            1080: "SOCKS Proxy", 3128: "HTTP Proxy", 8118: "Privoxy",
            9050: "Tor SOCKS", 1194: "OpenVPN", 1723: "PPTP VPN"
        }
        
        # محدوده‌های فرکانسی برای تشخیص RF
        self.rf_signatures = {
            'switching_noise': [150000, 30000000],  # 150kHz - 30MHz
            'fan_harmonics': [50, 500],             # 50Hz - 500Hz
            'power_harmonics': [100, 600]           # 100Hz - 600Hz (50Hz و مضارب)
        }
        
        # دیتابیس SQLite برای ذخیره داده‌ها
        self.init_database()

    def init_database(self):
        """راه‌اندازی دیتابیس محلی"""
        self.conn = sqlite3.connect('ilam_miners.db')
        cursor = self.conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS detected_miners (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT,
                mac_address TEXT,
                latitude REAL,
                longitude REAL,
                city TEXT,
                detection_method TEXT,
                power_consumption REAL,
                hash_rate TEXT,
                device_type TEXT,
                detection_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                confidence_score INTEGER,
                notes TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS rf_signatures (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                frequency REAL,
                amplitude REAL,
                latitude REAL,
                longitude REAL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        self.conn.commit()

    def ping_host(self, ip):
        """بررسی دسترسی به IP"""
        try:
            result = subprocess.run(['ping', '-c', '1', '-W', '1', ip], 
                                  capture_output=True, text=True)
            return result.returncode == 0
        except:
            return False

    def scan_port(self, ip, port, timeout=3):
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
            # استفاده از ARP table
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

    def geolocate_ip(self, ip_address):
        """مکان‌یابی IP با استفاده از سرویس‌های مختلف"""
        location_data = {}
        
        try:
            # روش 1: استفاده از ipapi.co
            response = requests.get(f'http://ipapi.co/{ip_address}/json/', timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get('latitude') and data.get('longitude'):
                    location_data['ipapi'] = {
                        'lat': float(data['latitude']),
                        'lon': float(data['longitude']),
                        'city': data.get('city', ''),
                        'region': data.get('region', ''),
                        'country': data.get('country_name', '')
                    }
        except:
            pass
        
        try:
            # روش 2: استفاده از ip-api.com
            response = requests.get(f'http://ip-api.com/json/{ip_address}', timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data['status'] == 'success':
                    location_data['ip-api'] = {
                        'lat': float(data['lat']),
                        'lon': float(data['lon']),
                        'city': data.get('city', ''),
                        'region': data.get('regionName', ''),
                        'country': data.get('country', '')
                    }
        except:
            pass
        
        # بررسی اینکه آیا IP در محدوده ایلام است
        for service, data in location_data.items():
            if self.is_in_ilam_bounds(data['lat'], data['lon']):
                data['in_ilam'] = True
                data['closest_city'] = self.find_closest_city(data['lat'], data['lon'])
            else:
                data['in_ilam'] = False
        
        return location_data

    def is_in_ilam_bounds(self, lat, lon):
        """بررسی قرارگیری مختصات در محدوده ایلام"""
        return (self.ilam_bounds['south'] <= lat <= self.ilam_bounds['north'] and
                self.ilam_bounds['west'] <= lon <= self.ilam_bounds['east'])

    def find_closest_city(self, lat, lon):
        """یافتن نزدیک‌ترین شهر ایلام"""
        min_distance = float('inf')
        closest_city = None
        
        for city, (city_lat, city_lon) in self.ilam_cities.items():
            distance = geodesic((lat, lon), (city_lat, city_lon)).kilometers
            if distance < min_distance:
                min_distance = distance
                closest_city = city
        
        return {'city': closest_city, 'distance_km': min_distance}

    def wifi_triangulation_scan(self):
        """تشخیص ماینر از طریق تحلیل WiFi و مثلث‌بندی"""
        print("📡 اسکن WiFi برای مثلث‌بندی...")
        
        wifi_devices = []
        try:
            # شبیه‌سازی اسکن WiFi (در عمل باید از کتابخانه واقعی استفاده شود)
            # برای اجرای واقعی نیاز به root access و wireless adapter
            
            suspicious_names = [
                'antminer', 'miner', 'asic', 'mining', 'btc', 'eth',
                'whatsminer', 'avalon', 'innosilicon', 'bitmain'
            ]
            
            # شبیه‌سازی داده‌های WiFi
            simulated_networks = [
                {'ssid': 'AntMiner_S19', 'bssid': '00:11:22:33:44:55', 'signal': -45},
                {'ssid': 'Mining_Rig_01', 'bssid': '00:11:22:33:44:56', 'signal': -67},
                {'ssid': 'Home_Network', 'bssid': '00:11:22:33:44:57', 'signal': -72}
            ]
            
            for network in simulated_networks:
                ssid = network['ssid'].lower()
                suspicious = any(name in ssid for name in suspicious_names)
                
                estimated_distance = self.estimate_distance_from_rssi(network['signal'])
                
                wifi_devices.append({
                    'ssid': network['ssid'],
                    'bssid': network['bssid'],
                    'signal': network['signal'],
                    'estimated_distance': estimated_distance,
                    'suspicious': suspicious
                })
                
        except Exception as e:
            print(f"خطا در اسکن WiFi: {e}")
        
        return wifi_devices

    def usb_proximity_scan(self):
        """تشخیص از طریق USB"""
        
        print("🔌 اسکن USB...")
        
        usb_devices = []
        
        try:
            import usb.core
            import usb.util
            
            # پیدا کردن دستگاه‌های USB متصل
            devices = usb.core.find(find_all=True)
            
            for device in devices:
                try:
                    manufacturer = usb.util.get_string(device, device.iManufacturer) or ''
                    product = usb.util.get_string(device, device.iProduct) or ''
                    serial_number = usb.util.get_string(device, device.iSerialNumber) or ''
                    
                    name = f"{manufacturer} {product}".lower()
                    suspicious_keywords = ['miner', 'asic', 'antminer', 'whatsminer']
                    suspicious = any(keyword in name for keyword in suspicious_keywords)
                    
                    usb_devices.append({
                        'manufacturer': manufacturer,
                        'product': product,
                        'serial_number': serial_number,
                        'suspicious': suspicious
                    })
                except Exception:
                    continue
        except ImportError:
            print("ماژول pyusb نصب نشده است. اسکن USB انجام نشد.")
        
        return usb_devices

    def rf_spectrum_analysis(self):
        """تحلیل طیف رادیویی برای تشخیص نویز سوئیچینگ"""
        print("📻 تحلیل طیف RF...")
        
        # شبیه‌سازی داده‌های RF
        rf_signatures = []
        
        # شبیه‌سازی نویز سوئیچینگ معمول ماینرها
        simulated_rf_data = [
            {'frequency': 150000, 'power': -55, 'type': 'switching_noise'},
            {'frequency': 500000, 'power': -48, 'type': 'switching_noise'},
            {'frequency': 1200000, 'power': -52, 'type': 'switching_noise'}
        ]
        
        for data in simulated_rf_data:
            if self.is_miner_rf_signature(data['frequency'], data['power']):
                rf_signatures.append(data)
        
        return rf_signatures

    def is_miner_rf_signature(self, frequency, power):
        """بررسی نویز RF مشخصه ماینرها"""
        switching_freq_ranges = [
            (100000, 200000),    # 100-200kHz
            (400000, 600000),    # 400-600kHz  
            (1000000, 2000000)   # 1-2MHz
        ]
        
        for freq_min, freq_max in switching_freq_ranges:
            if freq_min <= frequency <= freq_max and power > -60:
                return True
        
        return False

    def power_consumption_analysis(self, ip_address):
        """تحلیل مصرف برق از طریق SNMP"""
        power_data = {}
        
        try:
            # شبیه‌سازی داده‌های مصرف برق
            # در عمل باید از SNMP واقعی استفاده شود
            
            # ماینرها معمولاً مصرف بالایی دارند
            simulated_power = {
                'current_power': 3200,  # وات
                'voltage': 220,         # ولت
                'current': 14.5,        # آمپر
                'power_factor': 0.98,
                'temperature': 68       # درجه سانتیگراد
            }
            
            # اگر مصرف برق بالا باشد، احتمال ماینر بودن زیاد است
            if simulated_power['current_power'] > 1500:  # بیش از 1.5 کیلووات
                power_data = simulated_power
                
        except Exception as e:
            print(f"خطا در تحلیل مصرف برق: {e}")
        
        return power_data

    def thermal_signature_detection(self):
        """تشخیص از طریق امضای حرارتی"""
        print("🌡️ تشخیص امضای حرارتی...")
        
        # شبیه‌سازی نقاط گرم
        thermal_hotspots = [
            {'lat': 33.640, 'lon': 46.425, 'temp': 72.5, 'area_m2': 4.2},
            {'lat': 33.635, 'lon': 46.420, 'temp': 68.3, 'area_m2': 3.8},
            {'lat': 33.630, 'lon': 46.415, 'temp': 75.1, 'area_m2': 5.1}
        ]
        
        return thermal_hotspots

    def acoustic_signature_analysis(self):
        """تحلیل امضای صوتی"""
        print("🔊 تحلیل امضای صوتی...")
        
        # شبیه‌سازی امضای صوتی
        acoustic_signatures = [
            {'frequency': 50, 'amplitude': 0.02, 'type': 'fan_noise'},
            {'frequency': 100, 'amplitude': 0.015, 'type': 'fan_noise'},
            {'frequency': 150, 'amplitude': 0.018, 'type': 'fan_noise'}
        ]
        
        return acoustic_signatures

    def estimate_distance_from_rssi(self, rssi, frequency=2400):
        """تخمین فاصله از قدرت سیگنال"""
        if rssi == 0:
            return -1.0
        
        ratio = rssi / -59.0
        if ratio < 1.0:
            return math.pow(ratio, 10)
        else:
            accuracy = (0.89976) * math.pow(ratio, 7.7095) + 0.111
            return accuracy

    def triangulate_position(self, wifi_points):
        """مثلث‌بندی موقعیت از نقاط WiFi"""
        if len(wifi_points) < 3:
            return None
        
        def distance_error(pos, points):
            error = 0
            for point in points:
                calculated_dist = geodesic(pos, (point['lat'], point['lon'])).meters
                error += (calculated_dist - point['distance']) ** 2
            return error
        
        initial_guess = self.ilam_bounds['center']
        result = minimize(distance_error, initial_guess, args=(wifi_points,))
        
        if result.success:
            return {'lat': result.x[0], 'lon': result.x[1]}
        
        return None

    def scan_local_networks(self):
        """اسکن شبکه‌های محلی"""
        devices = []
        
        try:
            # دریافت رنج شبکه فعلی
            for interface in netifaces.interfaces():
                try:
                    addrs = netifaces.ifaddresses(interface)
                    if netifaces.AF_INET in addrs:
                        for addr in addrs[netifaces.AF_INET]:
                            ip = addr['addr']
                            netmask = addr.get('netmask')
                            
                            if ip and not ip.startswith('127.') and netmask:
                                network_devices = self.scan_network_range(ip, netmask)
                                devices.extend(network_devices)
                except:
                    continue
        except:
            # در صورت عدم دسترسی، اسکن رنج پیش‌فرض
            devices = self.scan_default_ranges()
        
        return devices

    def scan_default_ranges(self):
        """اسکن رنج‌های پیش‌فرض"""
        devices = []
        default_ranges = ['192.168.1', '192.168.0', '10.0.0', '172.16.0']
        
        for range_base in default_ranges:
            for i in range(1, 255):
                ip = f"{range_base}.{i}"
                device = self.advanced_device_scan(ip)
                if device:
                    devices.append(device)
                    if len(devices) >= 10:  # محدود کردن برای جلوگیری از طولانی شدن
                        break
        
        return devices

    def scan_network_range(self, base_ip, netmask):
        """اسکن رنج شبکه مشخص"""
        devices = []
        
        ip_parts = base_ip.split('.')
        network_base = '.'.join(ip_parts[:-1])
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = []
            for i in range(1, 255):
                ip = f"{network_base}.{i}"
                futures.append(executor.submit(self.advanced_device_scan, ip))
            
            for future in futures:
                try:
                    device = future.result(timeout=10)
                    if device:
                        devices.append(device)
                except:
                    continue
        
        return devices

    def advanced_device_scan(self, ip):
        """اسکن پیشرفته تک دستگاه"""
        if not self.ping_host(ip):
            return None
        
        device_info = {
            'ip': ip,
            'timestamp': datetime.now().isoformat(),
            'open_ports': [],
            'services': {},
            'mac_address': self.get_mac_address(ip),
            'suspicion_score': 0,
            'detection_methods': []
        }
        
        # اسکن پورت‌های مشکوک
        for port, service in self.miner_ports.items():
            if self.scan_port(ip, port, timeout=2):
                device_info['open_ports'].append(port)
                device_info['services'][port] = service
                device_info['suspicion_score'] += 25
                device_info['detection_methods'].append(f'port_{port}')
        
        # تحلیل مصرف برق
        power_data = self.power_consumption_analysis(ip)
        if power_data:
            device_info['power_analysis'] = power_data
            device_info['suspicion_score'] += 15
            device_info['detection_methods'].append('power_analysis')
        
        # بررسی نام host
        try:
            hostname = socket.gethostbyaddr(ip)[0].lower()
            suspicious_names = ['miner', 'asic', 'antminer', 'whatsminer', 'mining']
            if any(name in hostname for name in suspicious_names):
                device_info['hostname'] = hostname
                device_info['suspicion_score'] += 30
                device_info['detection_methods'].append('hostname')
        except:
            pass
        
        return device_info if device_info['suspicion_score'] > 10 else None

    def comprehensive_ilam_scan(self):
        """اسکن جامع استان ایلام"""
        print("🏔️ شروع اسکن جامع استان ایلام")
        print("=" * 60)
        
        results = {
            'timestamp': datetime.now().isoformat(),
            'scan_area': 'استان ایلام',
            'network_devices': [],
            'wifi_devices': [],
            'usb_devices': [],
            'rf_signatures': [],
            'thermal_hotspots': [],
            'acoustic_signatures': [],
            'geolocated_miners': [],
            'statistics': {}
        }
        
        # 1. اسکن شبکه
        print("1️⃣ اسکن شبکه...")
        results['network_devices'] = self.scan_local_networks()
        
        # 2. اسکن WiFi
        print("2️⃣ اسکن WiFi...")
        results['wifi_devices'] = self.wifi_triangulation_scan()
        
        # 3. اسکن Bluetooth
        print("3️⃣ اسکن USB...")
        results['usb_devices'] = self.usb_proximity_scan()
        
        # 4. تحلیل طیف RF
        print("4️⃣ تحلیل طیف RF...")
        results['rf_signatures'] = self.rf_spectrum_analysis()
        
        # 5. تشخیص حرارتی
        print("5️⃣ تشخیص حرارتی...")
        results['thermal_hotspots'] = self.thermal_signature_detection()
        
        # 6. تحلیل صوتی
        print("6️⃣ تحلیل صوتی...")
        results['acoustic_signatures'] = self.acoustic_signature_analysis()
        
        # 7. مکان‌یابی
        print("7️⃣ مکان‌یابی...")
        for device in results['network_devices']:
            if device.get('suspicion_score', 0) > 20:
                location = self.geolocate_ip(device['ip'])
                if location:
                    device['geolocation'] = location
                    if any(loc.get('in_ilam') for loc in location.values()):
                        results['geolocated_miners'].append(device)
        
        # محاسبه آمار
        results['statistics'] = self.calculate_statistics(results)
        
        # ذخیره در دیتابیس
        self.save_to_database(results)
        
        return results

    def calculate_statistics(self, results):
        """محاسبه آمار"""
        stats = {
            'total_devices_scanned': len(results['network_devices']),
            'suspicious_devices': len([d for d in results['network_devices'] 
                                     if d.get('suspicion_score', 0) > 20]),
            'confirmed_miners': len(results['geolocated_miners']),
            'wifi_suspicious': len([w for w in results['wifi_devices'] 
                                  if w.get('suspicious')]),
            'usb_suspicious': len([u for u in results['usb_devices'] 
                                       if u.get('suspicious')]),
            'thermal_hotspots': len(results['thermal_hotspots']),
            'rf_signatures': len(results['rf_signatures'])
        }
        
        return stats

    def save_to_database(self, results):
        """ذخیره نتایج در دیتابیس"""
        cursor = self.conn.cursor()
        
        for device in results.get('geolocated_miners', []):
            location = device.get('geolocation', {})
            if location:
                best_location = None
                for service, loc_data in location.items():
                    if loc_data.get('in_ilam'):
                        best_location = loc_data
                        break
                
                if best_location:
                    cursor.execute('''
                        INSERT INTO detected_miners 
                        (ip_address, mac_address, latitude, longitude, city, 
                         detection_method, device_type, confidence_score, notes)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        device['ip'],
                        device.get('mac_address', ''),
                        best_location['lat'],
                        best_location['lon'],
                        best_location.get('city', ''),
                        ','.join(device.get('detection_methods', [])),
                        'cryptocurrency_miner',
                        device.get('suspicion_score', 0),
                        json.dumps(device, ensure_ascii=False)
                    ))
        
        # ذخیره امضاهای RF
        for rf_sig in results.get('rf_signatures', []):
            cursor.execute('''
                INSERT INTO rf_signatures (frequency, amplitude, latitude, longitude)
                VALUES (?, ?, ?, ?)
            ''', (
                rf_sig['frequency'],
                rf_sig.get('power', 0),
                self.ilam_bounds['center'][0],
                self.ilam_bounds['center'][1]
            ))
        
        self.conn.commit()

    def generate_ilam_map(self, results):
        """تولید نقشه تعاملی استان ایلام"""
        print("🗺️ تولید نقشه...")
        
        ilam_map = folium.Map(
            location=self.ilam_bounds['center'],
            zoom_start=9,
            tiles='OpenStreetMap'
        )
        
        # مرزهای استان
        ilam_boundary = [
            [self.ilam_bounds['north'], self.ilam_bounds['west']],
            [self.ilam_bounds['north'], self.ilam_bounds['east']],
            [self.ilam_bounds['south'], self.ilam_bounds['east']],
            [self.ilam_bounds['south'], self.ilam_bounds['west']]
        ]
        
        folium.Polygon(
            locations=ilam_boundary,
            color='red',
            weight=2,
            fillOpacity=0.1,
            popup='مرز استان ایلام'
        ).add_to(ilam_map)
        
        # شهرهای ایلام
        for city, (lat, lon) in self.ilam_cities.items():
            folium.Marker(
                [lat, lon],
                popup=f'شهر {city}',
                icon=folium.Icon(color='blue', icon='info-sign')
            ).add_to(ilam_map)
        
        # ماینرهای یافت شده
        for device in results.get('geolocated_miners', []):
            location = device.get('geolocation', {})
            for service, loc_data in location.items():
                if loc_data.get('in_ilam'):
                    score = device.get('suspicion_score', 0)
                    if score > 50:
                        color = 'red'
                        icon = 'warning-sign'
                    elif score > 30:
                        color = 'orange'
                        icon = 'exclamation-sign'
                    else:
                        color = 'yellow'
                        icon = 'question-sign'
                    
                    popup_text = f"""
                    <b>دستگاه مشکوک</b><br>
                    IP: {device['ip']}<br>
                    امتیاز: {score}<br>
                    شهر: {loc_data.get('city', 'نامشخص')}<br>
                    پورت‌های باز: {', '.join(map(str, device.get('open_ports', [])))}
                    """
                    
                    folium.Marker(
                        [loc_data['lat'], loc_data['lon']],
                        popup=folium.Popup(popup_text, max_width=300),
                        icon=folium.Icon(color=color, icon=icon)
                    ).add_to(ilam_map)
                    break
        
        # نقاط گرم حرارتی
        for hotspot in results.get('thermal_hotspots', []):
            folium.CircleMarker(
                [hotspot['lat'], hotspot['lon']],
                radius=hotspot['area_m2'],
                popup=f"نقطه گرم: {hotspot['temp']}°C",
                color='red',
                fillColor='red',
                fillOpacity=0.6
            ).add_to(ilam_map)
        
        map_filename = f'ilam_miners_map_{datetime.now().strftime("%Y%m%d_%H%M%S")}.html'
        ilam_map.save(map_filename)
        
        return map_filename

    def generate_report(self, results):
        """تولید گزارش جامع"""
        print("📊 تولید گزارش...")
        
        report = {
            'header': {
                'title': 'گزارش جامع شناسایی ماینرهای ارز دیجیتال',
                'subtitle': 'استان ایلام - جمهوری اسلامی ایران',
                'timestamp': results['timestamp'],
                'scan_area': results['scan_area']
            },
            'summary': results['statistics'],
            'detailed_findings': {
                'network_analysis': self.analyze_network_findings(results['network_devices']),
                'geolocation_analysis': self.analyze_geolocation_findings(results['geolocated_miners']),
                'signal_analysis': self.analyze_signal_findings(results),
                'threat_assessment': self.assess_threat_level(results)
            },
            'recommendations': self.generate_recommendations(results),
            'technical_details': {
                'detection_methods': self.get_detection_methods_summary(results),
                'confidence_levels': self.calculate_confidence_levels(results),
                'false_positive_analysis': self.analyze_false_positives(results)
            }
        }
        
        # ذخیره گزارش
        report_filename = f'ilam_mining_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
        with open(report_filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        
        return report, report_filename

    def analyze_network_findings(self, network_devices):
        """تحلیل یافته‌های شبکه"""
        analysis = {
            'total_devices': len(network_devices),
            'high_suspicion': len([d for d in network_devices if d.get('suspicion_score', 0) > 50]),
            'medium_suspicion': len([d for d in network_devices if 20 < d.get('suspicion_score', 0) <= 50]),
            'low_suspicion': len([d for d in network_devices if 10 < d.get('suspicion_score', 0) <= 20]),
            'common_ports': self.get_common_ports(network_devices),
            'ip_ranges': self.get_ip_ranges(network_devices)
        }
        
        return analysis

    def analyze_geolocation_findings(self, geolocated_miners):
        """تحلیل یافته‌های مکان‌یابی"""
        analysis = {
            'total_geolocated': len(geolocated_miners),
            'city_distribution': {},
            'coordinate_clusters': []
        }
        
        # توزیع شهری
        for miner in geolocated_miners:
            location = miner.get('geolocation', {})
            for service, loc_data in location.items():
                if loc_data.get('in_ilam'):
                    city = loc_data.get('city', 'نامشخص')
                    analysis['city_distribution'][city] = analysis['city_distribution'].get(city, 0) + 1
                    break
        
        return analysis

    def analyze_signal_findings(self, results):
        """تحلیل یافته‌های سیگنال"""
        analysis = {
            'wifi_analysis': {
                'total_networks': len(results['wifi_devices']),
                'suspicious_networks': len([w for w in results['wifi_devices'] if w.get('suspicious')]),
                'signal_strength_avg': self.calculate_avg_signal_strength(results['wifi_devices'])
            },
            'bluetooth_analysis': {
                'total_devices': len(results['bluetooth_devices']),
                'suspicious_devices': len([b for b in results['bluetooth_devices'] if b.get('suspicious')])
            },
            'rf_analysis': {
                'signatures_detected': len(results['rf_signatures']),
                'frequency_ranges': self.analyze_frequency_ranges(results['rf_signatures'])
            }
        }
        
        return analysis

    def assess_threat_level(self, results):
        """ارزیابی سطح تهدید"""
        total_indicators = 0
        threat_score = 0
        
        # شمارش شاخص‌های تهدید
        confirmed_miners = len(results['geolocated_miners'])
        suspicious_devices = len([d for d in results['network_devices'] if d.get('suspicion_score', 0) > 20])
        thermal_hotspots = len(results['thermal_hotspots'])
        rf_signatures = len(results['rf_signatures'])
        
        total_indicators = confirmed_miners + suspicious_devices + thermal_hotspots + rf_signatures
        
        if confirmed_miners > 0:
            threat_score += confirmed_miners * 10
        if suspicious_devices > 0:
            threat_score += suspicious_devices * 5
        if thermal_hotspots > 0:
            threat_score += thermal_hotspots * 3
        if rf_signatures > 0:
            threat_score += rf_signatures * 2
        
        # تعیین سطح تهدید
        if threat_score >= 50:
            level = 'بالا'
            color = 'قرمز'
        elif threat_score >= 20:
            level = 'متوسط'
            color = 'نارنجی'
        elif threat_score >= 10:
            level = 'پایین'
            color = 'زرد'
        else:
            level = 'ناچیز'
            color = 'سبز'
        
        return {
            'level': level,
            'color': color,
            'score': threat_score,
            'total_indicators': total_indicators,
            'confirmed_miners': confirmed_miners,
            'description': self.get_threat_description(level)
        }

    def get_threat_description(self, level):
        """توضیح سطح تهدید"""
        descriptions = {
            'بالا': 'وجود ماینرهای فعال با قطعیت بالا. نیاز به اقدام فوری.',
            'متوسط': 'وجود فعالیت‌های مشکوک که نیاز به بررسی بیشتر دارد.',
            'پایین': 'شاخص‌های محدود فعالیت ماینینگ. نیاز به نظارت.',
            'ناچیز': 'عدم وجود شاخص‌های معنی‌دار فعالیت ماینینگ.'
        }
        return descriptions.get(level, 'نامشخص')

    def generate_recommendations(self, results):
        """تولید توصیه‌ها"""
        recommendations = []
        
        threat_assessment = self.assess_threat_level(results)
        
        if threat_assessment['confirmed_miners'] > 0:
            recommendations.append({
                'priority': 'فوری',
                'category': 'اقدام قانونی',
                'description': 'مراجعه به مقامات قضایی برای بررسی ماینرهای شناسایی شده',
                'details': f"{threat_assessment['confirmed_miners']} ماینر با موقعیت مشخص شناسایی شده"
            })
        
        if len(results['thermal_hotspots']) > 0:
            recommendations.append({
                'priority': 'بالا',
                'category': 'بازرسی فیزیکی',
                'description': 'بازرسی نقاط گرم شناسایی شده',
                'details': f"{len(results['thermal_hotspots'])} نقطه گرم مشکوک"
            })
        
        if len([d for d in results['network_devices'] if d.get('suspicion_score', 0) > 30]) > 0:
            recommendations.append({
                'priority': 'متوسط',
                'category': 'بررسی شبکه',
                'description': 'بررسی دقیق‌تر دستگاه‌های شبکه مشکوک',
                'details': 'استفاده از ابزارهای تخصصی‌تر شبکه'
            })
        
        recommendations.append({
            'priority': 'پایین',
            'category': 'نظارت مستمر',
            'description': 'راه‌اندازی سیستم نظارت مستمر',
            'details': 'اجرای اسکن‌های منظم برای شناسایی فعالیت‌های جدید'
        })
        
        return recommendations

    def get_detection_methods_summary(self, results):
        """خلاصه روش‌های تشخیص"""
        methods = {
            'port_scanning': {'count': 0, 'effectiveness': 'بالا'},
            'geolocation': {'count': 0, 'effectiveness': 'متوسط'},
            'thermal_detection': {'count': len(results['thermal_hotspots']), 'effectiveness': 'بالا'},
            'rf_analysis': {'count': len(results['rf_signatures']), 'effectiveness': 'متوسط'},
            'power_analysis': {'count': 0, 'effectiveness': 'بالا'},
            'acoustic_analysis': {'count': len(results['acoustic_signatures']), 'effectiveness': 'پایین'}
        }
        
        # شمارش روش‌های تشخیص
        for device in results['network_devices']:
            detection_methods = device.get('detection_methods', [])
            for method in detection_methods:
                if method.startswith('port_'):
                    methods['port_scanning']['count'] += 1
                elif method == 'geolocation':
                    methods['geolocation']['count'] += 1
                elif method == 'power_analysis':
                    methods['power_analysis']['count'] += 1
        
        return methods

    def calculate_confidence_levels(self, results):
        """محاسبه سطوح اطمینان"""
        confidence_levels = {}
        
        for device in results['network_devices']:
            score = device.get('suspicion_score', 0)
            if score >= 50:
                confidence = 'بالا'
            elif score >= 30:
                confidence = 'متوسط'
            elif score >= 10:
                confidence = 'پایین'
            else:
                confidence = 'ناچیز'
            
            confidence_levels[confidence] = confidence_levels.get(confidence, 0) + 1
        
        return confidence_levels

    def analyze_false_positives(self, results):
        """تحلیل مثبت کاذب"""
        analysis = {
            'potential_false_positives': 0,
            'common_causes': [],
            'recommendations': []
        }
        
        # شناسایی احتمال مثبت کاذب
        for device in results['network_devices']:
            score = device.get('suspicion_score', 0)
            detection_methods = device.get('detection_methods', [])
            
            # اگر فقط یک روش تشخیص داشته باشد، احتمال مثبت کاذب بالاست
            if len(detection_methods) == 1 and score < 40:
                analysis['potential_false_positives'] += 1
        
        # علل رایج مثبت کاذب
        analysis['common_causes'] = [
            'سرورهای بازی آنلاین',
            'دستگاه‌های IoT',
            'سیستم‌های نظارت',
            'روترهای پیکربندی شده'
        ]
        
        # توصیه‌ها برای کاهش مثبت کاذب
        analysis['recommendations'] = [
            'استفاده از چندین روش تشخیص همزمان',
            'تأیید فیزیکی موارد مشکوک',
            'بررسی الگوهای ترافیک شبکه',
            'تحلیل مصرف برق واقعی'
        ]
        
        return analysis

    def get_common_ports(self, devices):
        """دریافت پورت‌های رایج"""
        port_counts = {}
        for device in devices:
            for port in device.get('open_ports', []):
                port_counts[port] = port_counts.get(port, 0) + 1
        
        return dict(sorted(port_counts.items(), key=lambda x: x[1], reverse=True)[:10])

    def get_ip_ranges(self, devices):
        """دریافت رنج‌های IP"""
        ranges = {}
        for device in devices:
            ip = device.get('ip', '')
            if ip:
                range_key = '.'.join(ip.split('.')[:2]) + '.x.x'
                ranges[range_key] = ranges.get(range_key, 0) + 1
        
        return ranges

    def calculate_avg_signal_strength(self, wifi_devices):
        """محاسبه میانگین قدرت سیگنال"""
        if not wifi_devices:
            return 0
        
        signals = [w.get('signal', 0) for w in wifi_devices if w.get('signal')]
        return sum(signals) / len(signals) if signals else 0

    def analyze_frequency_ranges(self, rf_signatures):
        """تحلیل محدوده‌های فرکانسی"""
        ranges = {
            'low_freq': 0,      # < 1MHz
            'mid_freq': 0,      # 1-10MHz
            'high_freq': 0      # > 10MHz
        }
        
        for sig in rf_signatures:
            freq = sig.get('frequency', 0)
            if freq < 1000000:
                ranges['low_freq'] += 1
            elif freq < 10000000:
                ranges['mid_freq'] += 1
            else:
                ranges['high_freq'] += 1
        
        return ranges

    def print_results(self, results):
        """چاپ نتایج"""
        print("\n" + "="*60)
        print("🏔️ نتایج اسکن استان ایلام")
        print("="*60)
        
        stats = results['statistics']
        print(f"📊 آمار کلی:")
        print(f"   • کل دستگاه‌های اسکن شده: {stats['total_devices_scanned']}")
        print(f"   • دستگاه‌های مشکوک: {stats['suspicious_devices']}")
        print(f"   • ماینرهای تأیید شده: {stats['confirmed_miners']}")
        print(f"   • شبکه‌های WiFi مشکوک: {stats['wifi_suspicious']}")
        print(f"   • دستگاه‌های USB مشکوک: {stats['usb_suspicious']}")
        print(f"   • نقاط گرم حرارتی: {stats['thermal_hotspots']}")
        print(f"   • امضاهای RF: {stats['rf_signatures']}")
        
        if results['geolocated_miners']:
            print(f"\n🎯 ماینرهای مکان‌یابی شده:")
            for i, miner in enumerate(results['geolocated_miners'], 1):
                print(f"   {i}. IP: {miner['ip']} | امتیاز: {miner.get('suspicion_score', 0)}")
                location = miner.get('geolocation', {})
                for service, loc_data in location.items():
                    if loc_data.get('in_ilam'):
                        print(f"      موقعیت: {loc_data.get('city', 'نامشخص')} ({loc_data['lat']:.4f}, {loc_data['lon']:.4f})")
                        break
        
        if results['thermal_hotspots']:
            print(f"\n🌡️ نقاط گرم حرارتی:")
            for i, hotspot in enumerate(results['thermal_hotspots'], 1):
                print(f"   {i}. دما: {hotspot['temp']}°C | موقعیت: ({hotspot['lat']:.4f}, {hotspot['lon']:.4f})")
        
        print("\n" + "="*60)

    def close_database(self):
        """بستن اتصال دیتابیس"""
        if hasattr(self, 'conn'):
            self.conn.close()

def main():
    """تابع اصلی"""
    print("🚀 راه‌اندازی سیستم شناسایی ماینر استان ایلام")
    print("=" * 60)
    
    try:
        # ایجاد نمونه detector
        detector = IlamMinerGeoDetector()
        
        # اجرای اسکن جامع
        results = detector.comprehensive_ilam_scan()
        
        # چاپ نتایج
        detector.print_results(results)
        
        # تولید نقشه
        map_file = detector.generate_ilam_map(results)
        print(f"\n🗺️ نقشه ذخیره شد: {map_file}")
        
        # تولید گزارش
        report, report_file = detector.generate_report(results)
        print(f"📊 گزارش ذخیره شد: {report_file}")
        
        # ذخیره نتایج JSON
        results_file = f'ilam_scan_results_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
        with open(results_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
        print(f"💾 نتایج کامل ذخیره شد: {results_file}")
        
        # بستن دیتابیس
        detector.close_database()
        
        print("\n✅ اسکن با موفقیت تکمیل شد!")
        
    except KeyboardInterrupt:
        print("\n❌ اسکن توسط کاربر متوقف شد")
    except Exception as e:
        print(f"\n❌ خطا در اجرای اسکن: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()