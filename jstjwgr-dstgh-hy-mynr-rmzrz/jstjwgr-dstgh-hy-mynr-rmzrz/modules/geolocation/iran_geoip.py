#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ماژول مکان‌یابی و تقسیمات کشوری ایران
توسط: عرفان رجبی (Erfan Rajabi)

این ماژول شامل:
1. اطلاعات کامل تقسیمات کشوری ایران
2. تشخیص محدوده IP برای هر استان/شهر
3. مکان‌یابی دقیق آدرس‌های IP ایرانی
4. اطلاعات ISP و اپراتورها
"""

import json
import ipaddress
import os
from typing import Dict, List, Optional, Tuple
from datetime import datetime

class IranGeoIP:
    """کلاس اصلی برای مکان‌یابی IP های ایرانی"""
    
    def __init__(self, data_file: str = None):
        self.data_file = data_file or os.path.join(os.path.dirname(__file__), '../../data/iran_locations.json')
        self.iran_data = self._load_iran_data()
        self.ip_cache = {}
        
    def _load_iran_data(self) -> Dict:
        """بارگذاری اطلاعات تقسیمات کشوری"""
        try:
            with open(self.data_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"⚠️ فایل داده‌ها یافت نشد: {self.data_file}")
            return self._get_default_data()
    
    def _get_default_data(self) -> Dict:
        """داده‌های پیش‌فرض در صورت نبود فایل"""
        return {
            "provinces": {
                "ilam": {
                    "name": "ایلام",
                    "capital": "ایلام",
                    "ip_ranges": ["213.207.0.0/16", "185.74.0.0/15"],
                    "cities": ["ایلام", "ایوان", "دره‌شهر", "دهلران", "آبدانان", "مهران", "ملکشاهی", "سرابله", "چرداول"]
                }
            }
        }
    
    def lookup_ip(self, ip_address: str) -> Dict:
        """جستجوی مکان یک آدرس IP"""
        # بررسی کش
        if ip_address in self.ip_cache:
            return self.ip_cache[ip_address]
        
        try:
            ip_obj = ipaddress.ip_address(ip_address)
            
            # بررسی اینکه IP ایرانی است یا نه
            if not self._is_iranian_ip(ip_obj):
                result = {
                    'ip': ip_address,
                    'country': 'غیر ایرانی',
                    'province': None,
                    'city': None,
                    'isp': None,
                    'confidence': 0
                }
                self.ip_cache[ip_address] = result
                return result
            
            # جستجو در استان‌ها
            location_info = self._find_location_by_ip(ip_obj)
            
            # ذخیره در کش
            self.ip_cache[ip_address] = location_info
            
            return location_info
            
        except Exception as e:
            return {
                'ip': ip_address,
                'error': f'خطا در پردازش IP: {str(e)}',
                'country': 'نامشخص',
                'province': None,
                'city': None
            }
    
    def _is_iranian_ip(self, ip_obj) -> bool:
        """بررسی اینکه IP ایرانی است یا نه"""
        # محدوده‌های اصلی IP ایران
        iranian_ranges = [
            '5.0.0.0/8',      # محدوده اصلی ایران
            '31.0.0.0/8',     # محدوده دوم
            '37.0.0.0/8',     # محدوده سوم
            '46.0.0.0/8',     # محدوده چهارم
            '78.0.0.0/8',     # محدوده پنجم
            '91.0.0.0/8',     # محدوده ششم
            '185.0.0.0/8',    # محدوده هفتم
            '188.0.0.0/8',    # محدوده هشتم
            '212.0.0.0/8',    # محدوده نهم
            '213.0.0.0/8',    # محدوده دهم
            '217.0.0.0/8'     # محدوده یازدهم
        ]
        
        for range_str in iranian_ranges:
            if ip_obj in ipaddress.ip_network(range_str):
                return True
        
        return False
    
    def _find_location_by_ip(self, ip_obj) -> Dict:
        """پیدا کردن مکان بر اساس IP"""
        best_match = {
            'ip': str(ip_obj),
            'country': 'ایران',
            'province': 'نامشخص',
            'city': 'نامشخص',
            'isp': 'نامشخص',
            'confidence': 0
        }
        
        # جستجو در استان‌ها
        for province_code, province_data in self.iran_data['provinces'].items():
            ip_ranges = province_data.get('ip_ranges', [])
            
            for ip_range in ip_ranges:
                try:
                    network = ipaddress.ip_network(ip_range)
                    if ip_obj in network:
                        confidence = self._calculate_confidence(network, province_data)
                        
                        if confidence > best_match['confidence']:
                            best_match.update({
                                'province': province_data['name'],
                                'province_code': province_code,
                                'capital': province_data['capital'],
                                'confidence': confidence,
                                'ip_range': ip_range
                            })
                            
                            # تشخیص شهر دقیق‌تر (اگر موجود باشد)
                            city_info = self._find_city_by_ip(ip_obj, province_data)
                            if city_info:
                                best_match.update(city_info)
                
                except Exception as e:
                    continue
        
        # تشخیص ISP
        isp_info = self._identify_isp(ip_obj)
        best_match.update(isp_info)
        
        return best_match
    
    def _find_city_by_ip(self, ip_obj, province_data: Dict) -> Optional[Dict]:
        """تشخیص شهر دقیق در یک استان"""
        detailed_info = province_data.get('detailed_info', {})
        
        for city_code, city_data in detailed_info.items():
            city_ranges = city_data.get('ip_ranges', [])
            
            for ip_range in city_ranges:
                try:
                    network = ipaddress.ip_network(ip_range)
                    if ip_obj in network:
                        return {
                            'city': city_data['name'],
                            'city_code': city_code,
                            'districts': city_data.get('districts', []),
                            'city_ip_range': ip_range
                        }
                except:
                    continue
        
        return None
    
    def _identify_isp(self, ip_obj) -> Dict:
        """تشخیص ISP و اپراتور"""
        isp_info = {'isp': 'نامش��ص', 'isp_type': 'نامشخص'}
        
        isp_data = self.iran_data.get('ip_allocation_info', {}).get('main_isps', {})
        
        for isp_code, isp_details in isp_data.items():
            isp_ranges = isp_details.get('ip_ranges', [])
            
            for ip_range in isp_ranges:
                try:
                    network = ipaddress.ip_network(ip_range)
                    if ip_obj in network:
                        isp_info = {
                            'isp': isp_details['name'],
                            'isp_code': isp_code,
                            'isp_type': 'ثابت' if isp_code == 'tci' else 'همراه',
                            'coverage': isp_details['coverage']
                        }
                        break
                except:
                    continue
        
        return isp_info
    
    def _calculate_confidence(self, network, province_data: Dict) -> float:
        """محاسبه اطمینان مکان‌یابی"""
        base_confidence = 0.7
        
        # اگر شهرهای جزئی‌تر موجود باشد
        if 'detailed_info' in province_data:
            base_confidence += 0.2
        
        # بر اساس اندازه شبکه (کوچک‌تر = دقیق‌تر)
        network_size = network.num_addresses
        if network_size < 1024:
            base_confidence += 0.1
        elif network_size > 65536:
            base_confidence -= 0.1
        
        return min(base_confidence, 1.0)
    
    def get_province_list(self) -> List[Dict]:
        """دریافت لیست استان‌ها"""
        provinces = []
        
        for code, data in self.iran_data['provinces'].items():
            provinces.append({
                'code': code,
                'name': data['name'],
                'capital': data['capital'],
                'cities_count': len(data.get('cities', [])),
                'ip_ranges_count': len(data.get('ip_ranges', []))
            })
        
        return sorted(provinces, key=lambda x: x['name'])
    
    def get_cities_by_province(self, province_code: str) -> List[str]:
        """دریافت شهرهای یک استان"""
        province_data = self.iran_data['provinces'].get(province_code, {})
        return province_data.get('cities', [])
    
    def get_ip_ranges_by_location(self, province_code: str, city_name: str = None) -> List[str]:
        """دریافت محدوده‌های IP برای مکان مشخص"""
        province_data = self.iran_data['provinces'].get(province_code, {})
        
        if not city_name:
            # محدوده‌های کل استان
            return province_data.get('ip_ranges', [])
        
        # جستجوی شهر خاص
        detailed_info = province_data.get('detailed_info', {})
        
        for city_data in detailed_info.values():
            if city_data['name'] == city_name:
                return city_data.get('ip_ranges', [])
        
        return []
    
    def scan_ip_range_for_province(self, province_code: str) -> List[str]:
        """تولید لیست IP های قابل اسکن برای یک استان"""
        ip_ranges = self.get_ip_ranges_by_location(province_code)
        scannable_ips = []
        
        for ip_range in ip_ranges:
            try:
                network = ipaddress.ip_network(ip_range)
                
                # برای شبکه‌های بزرگ، نمونه‌برداری انجام می‌دهیم
                if network.num_addresses > 1024:
                    # نمونه‌برداری هر 64 آدرس
                    sample_ips = list(network.hosts())[::64]
                    scannable_ips.extend([str(ip) for ip in sample_ips[:100]])
                else:
                    # شبکه‌های کوچک را کاملاً اسکن می‌کنیم
                    scannable_ips.extend([str(ip) for ip in network.hosts()])
                    
            except Exception as e:
                print(f"❌ خطا در پردازش محدوده {ip_range}: {e}")
                continue
        
        return scannable_ips[:1000]  # محدود به 1000 IP
    
    def get_ilam_detailed_scan_ranges(self) -> Dict:
        """دریافت محدوده‌های اسکن دقیق برای استان ایلام"""
        ilam_data = self.iran_data['provinces'].get('ilam', {})
        detailed_info = ilam_data.get('detailed_info', {})
        
        scan_plan = {
            'province_name': 'ایلام',
            'total_cities': len(detailed_info),
            'scan_targets': {}
        }
        
        for city_code, city_data in detailed_info.items():
            city_ranges = city_data.get('ip_ranges', [])
            scannable_ips = []
            
            for ip_range in city_ranges:
                try:
                    network = ipaddress.ip_network(ip_range)
                    # برای هر شهر حداکثر 200 IP
                    sample_ips = list(network.hosts())[::max(1, network.num_addresses // 200)]
                    scannable_ips.extend([str(ip) for ip in sample_ips[:200]])
                except:
                    continue
            
            scan_plan['scan_targets'][city_code] = {
                'city_name': city_data['name'],
                'ip_ranges': city_ranges,
                'scannable_ips': scannable_ips,
                'total_ips': len(scannable_ips)
            }
        
        return scan_plan
    
    def reverse_lookup(self, province_name: str, city_name: str = None) -> Dict:
        """جستجوی معکوس: دریافت اطلاعات IP از روی نام مکان"""
        result = {
            'province': province_name,
            'city': city_name,
            'ip_ranges': [],
            'estimated_hosts': 0,
            'scannable_sample': []
        }
        
        # پیدا کردن کد استان
        province_code = None
        for code, data in self.iran_data['provinces'].items():
            if data['name'] == province_name:
                province_code = code
                break
        
        if not province_code:
            result['error'] = 'استان یافت نشد'
            return result
        
        # دریافت محدوده‌های IP
        ip_ranges = self.get_ip_ranges_by_location(province_code, city_name)
        result['ip_ranges'] = ip_ranges
        
        # محاسبه تعداد هاست‌ها
        total_hosts = 0
        sample_ips = []
        
        for ip_range in ip_ranges:
            try:
                network = ipaddress.ip_network(ip_range)
                total_hosts += network.num_addresses
                
                # نمونه IP ها
                sample_hosts = list(network.hosts())[:10]
                sample_ips.extend([str(ip) for ip in sample_hosts])
                
            except:
                continue
        
        result['estimated_hosts'] = total_hosts
        result['scannable_sample'] = sample_ips
        
        return result
    
    def export_scan_config(self, province_code: str, format: str = 'json') -> str:
        """خروجی پیکربندی اسکن برای یک استان"""
        scan_config = {
            'scan_config': {
                'target_province': self.iran_data['provinces'][province_code]['name'],
                'target_code': province_code,
                'timestamp': datetime.now().isoformat(),
                'ip_ranges': self.get_ip_ranges_by_location(province_code),
                'cities': self.get_cities_by_province(province_code),
                'scan_methodology': 'تشخیص ماینر رمزارز',
                'estimated_scan_time': '30-60 دقیقه'
            }
        }
        
        if province_code == 'ilam':
            scan_config['detailed_city_scan'] = self.get_ilam_detailed_scan_ranges()
        
        if format == 'json':
            return json.dumps(scan_config, ensure_ascii=False, indent=2)
        elif format == 'nmap':
            # تولید کامند nmap
            ip_ranges = ' '.join(scan_config['scan_config']['ip_ranges'])
            return f"nmap -sS -p 3333,4444,5555,7777 {ip_ranges}"
        
        return str(scan_config)

# تست و مثال استفاده
if __name__ == "__main__":
    geoip = IranGeoIP()
    
    print("🌍 تست سیستم مکان‌یابی ایران")
    
    # تست IP های نمونه
    test_ips = [
        "213.207.128.1",  # ایلام
        "5.200.1.1",      # تهران
        "37.156.1.1",     # آذربایجان شرقی
        "8.8.8.8"         # خارجی
    ]
    
    for ip in test_ips:
        result = geoip.lookup_ip(ip)
        print(f"\n📍 IP: {ip}")
        print(f"   استان: {result.get('province', 'نامشخص')}")
        print(f"   شهر: {result.get('city', 'نامشخص')}")
        print(f"   ISP: {result.get('isp', 'نامشخص')}")
        print(f"   اطمینان: {result.get('confidence', 0):.1%}")
    
    # تست محدوده‌های اسکن ایلام
    print(f"\n🎯 محدوده‌های اسکن ایلام:")
    ilam_scan = geoip.get_ilam_detailed_scan_ranges()
    for city_code, city_info in ilam_scan['scan_targets'].items():
        print(f"   {city_info['city_name']}: {city_info['total_ips']} IP قابل اسکن")
