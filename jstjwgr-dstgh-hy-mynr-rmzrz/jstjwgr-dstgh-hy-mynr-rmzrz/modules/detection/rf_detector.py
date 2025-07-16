#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ماژول تشخیص امواج رادیو و مغناطیسی ماینرهای رمزارز
توسط: عرفان رجبی (Erfan Rajabi)

این ماژول برای تشخیص ماینرها از طریق:
1. تحلیل امواج الکترومغناطیسی (EMI)
2. تشخیص فرکانس‌های خاص ASIC و GPU
3. مانیتورینگ گرمای تولیدی
4. تحلیل نویز صوتی
"""

import numpy as np
import time
import threading
import json
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional
import math
import random
from collections import deque, defaultdict

class RFDetector:
    """کلاس اصلی برای تشخیص امواج رادیو و مغناطیسی ماینرها"""
    
    def __init__(self):
        # فرکانس‌های مشخصه ماینرها (MHz)
        self.miner_frequencies = {
            'asic_bitcoin': [13.56, 27.12, 40.68, 433.92],  # فرکانس‌های معمول ASIC Bitcoin
            'asic_ethereum': [12.5, 25.0, 50.0, 868.0],    # فرکانس‌های ASIC Ethereum
            'gpu_mining': [24.0, 48.0, 96.0, 144.0],       # فرکانس‌های GPU Mining
            'cpu_mining': [16.0, 32.0, 64.0, 128.0],       # فرکانس‌های CPU Mining
            'fpga_mining': [100.0, 200.0, 400.0, 800.0]    # فرکانس‌های FPGA Mining
        }
        
        # الگوهای نویز الکترومغناطیسی
        self.emi_patterns = {
            'switching_power': {'freq_range': (20, 200), 'harmonic_spacing': 50},
            'clock_signals': {'freq_range': (1, 1000), 'harmonic_spacing': 25},
            'data_buses': {'freq_range': (100, 500), 'harmonic_spacing': 133}
        }
        
        # آستانه‌های تشخیص
        self.detection_thresholds = {
            'rf_intensity': -60,      # dBm
            'magnetic_field': 50,     # nT (nanotesla)
            'temperature': 60,        # درجه سانتیگراد
            'power_consumption': 500, # وات
            'noise_level': 40         # dB
        }
        
        # داده‌های مانیتورینگ
        self.monitoring_data = defaultdict(lambda: {
            'rf_readings': deque(maxlen=1000),
            'magnetic_readings': deque(maxlen=1000),
            'temperature_readings': deque(maxlen=1000),
            'noise_readings': deque(maxlen=1000),
            'timestamps': deque(maxlen=1000)
        })
        
        self.detected_miners = {}
        self.is_monitoring = False
        self.scan_results = {}
        
    def start_rf_monitoring(self, scan_area: str = "local", duration: int = 300):
        """شروع مانیتورینگ امواج رادیو"""
        self.is_monitoring = True
        print(f"🔍 شروع مانیتورینگ RF در محدوده: {scan_area}")
        
        # شروع thread مانیتورینگ
        rf_thread = threading.Thread(
            target=self._continuous_rf_scan,
            args=(scan_area, duration)
        )
        rf_thread.daemon = True
        rf_thread.start()
        
        # شروع thread تحلیل امواج مغناطیسی
        magnetic_thread = threading.Thread(
            target=self._magnetic_field_analysis,
            args=(duration,)
        )
        magnetic_thread.daemon = True
        magnetic_thread.start()
        
        # شروع thread تحلیل حرارتی
        thermal_thread = threading.Thread(
            target=self._thermal_analysis,
            args=(duration,)
        )
        thermal_thread.daemon = True
        thermal_thread.start()
        
    def stop_rf_monitoring(self):
        """توقف مانیتورینگ"""
        self.is_monitoring = False
        print("⏹️ مانیتورینگ RF متوقف شد")
        
    def _continuous_rf_scan(self, scan_area: str, duration: int):
        """اسکن مداوم امواج رادیو"""
        start_time = time.time()
        
        while self.is_monitoring and (time.time() - start_time) < duration:
            try:
                # شبیه‌سازی اسکن RF واقعی
                rf_data = self._simulate_rf_scan()
                timestamp = time.time()
                
                # تحلیل داده‌های RF
                for location, readings in rf_data.items():
                    self.monitoring_data[location]['rf_readings'].append(readings)
                    self.monitoring_data[location]['timestamps'].append(timestamp)
                    
                    # تشخیص الگوهای مشکوک
                    if self._detect_miner_signature(readings):
                        self._flag_potential_miner(location, readings, timestamp)
                
                time.sleep(1)  # اسکن هر ثانیه
                
            except Exception as e:
                print(f"❌ خطا در اسکن RF: {e}")
                time.sleep(5)
    
    def _simulate_rf_scan(self) -> Dict:
        """شبیه‌سازی اسکن RF واقعی"""
        # در واقعیت از SDR (Software Defined Radio) استفاده می‌شود
        rf_data = {}
        
        # شبیه‌سازی مختصات مختلف
        locations = [
            f"lat_{33.637 + random.uniform(-0.01, 0.01):.6f}_lon_{46.423 + random.uniform(-0.01, 0.01):.6f}",
            f"lat_{33.640 + random.uniform(-0.01, 0.01):.6f}_lon_{46.425 + random.uniform(-0.01, 0.01):.6f}",
            f"lat_{33.635 + random.uniform(-0.01, 0.01):.6f}_lon_{46.420 + random.uniform(-0.01, 0.01):.6f}"
        ]
        
        for location in locations:
            rf_data[location] = self._generate_rf_spectrum()
            
        return rf_data
    
    def _generate_rf_spectrum(self) -> Dict:
        """تولید طیف RF شبیه‌سازی شده"""
        spectrum = {}
        
        # اسکن فرکانس‌های مختلف
        frequencies = np.linspace(1, 1000, 100)  # 1 MHz تا 1 GHz
        
        for freq in frequencies:
            # نویز پس‌زمینه
            base_noise = -80 + random.normalvariate(0, 5)
            
            # احتمال وجود سیگنال ماینر
            miner_signal = 0
            if random.random() < 0.1:  # 10% احتمال
                # شناسایی فرکانس‌های مشخصه ماینر
                for miner_type, freqs in self.miner_frequencies.items():
                    for miner_freq in freqs:
                        if abs(freq - miner_freq) < 0.5:  # تلرانس 0.5 MHz
                            miner_signal = random.uniform(-50, -30)  # سیگنال قوی
                            break
            
            # ترکیب نویز و سیگنال
            spectrum[freq] = max(base_noise, miner_signal)
            
        return {
            'spectrum': spectrum,
            'peak_frequency': max(spectrum.keys(), key=lambda k: spectrum[k]),
            'peak_power': max(spectrum.values()),
            'total_power': sum(spectrum.values()),
            'timestamp': time.time()
        }
    
    def _detect_miner_signature(self, rf_readings: Dict) -> bool:
        """تشخیص امضای ماینر در داده‌های RF"""
        spectrum = rf_readings['spectrum']
        peak_power = rf_readings['peak_power']
        peak_freq = rf_readings['peak_frequency']
        
        # بررسی قدرت سیگنال
        if peak_power < self.detection_thresholds['rf_intensity']:
            return False
        
        # بررسی فرکانس‌های مشخصه
        for miner_type, freqs in self.miner_frequencies.items():
            for freq in freqs:
                if abs(peak_freq - freq) < 1.0:  # تلرانس 1 MHz
                    # بررسی الگوی هارمونیک
                    if self._check_harmonic_pattern(spectrum, freq):
                        return True
        
        return False
    
    def _check_harmonic_pattern(self, spectrum: Dict, fundamental_freq: float) -> bool:
        """بررسی الگوی هارمونیک مشخصه ماینرها"""
        harmonics_found = 0
        
        # بررسی 5 هارمونیک اول
        for n in range(2, 7):
            harmonic_freq = fundamental_freq * n
            
            # جستجو در نزدیکی فرکانس هارمونیک
            for freq, power in spectrum.items():
                if abs(freq - harmonic_freq) < 2.0:  # تلرانس 2 MHz
                    if power > self.detection_thresholds['rf_intensity'] + 20:
                        harmonics_found += 1
                        break
        
        # اگر حداقل 2 هارمونیک پیدا شود
        return harmonics_found >= 2
    
    def _magnetic_field_analysis(self, duration: int):
        """تحلیل میدان‌های مغناطیسی"""
        start_time = time.time()
        
        while self.is_monitoring and (time.time() - start_time) < duration:
            try:
                # شبیه‌سازی سنسور مغناطیسی
                magnetic_data = self._simulate_magnetometer()
                timestamp = time.time()
                
                for location, reading in magnetic_data.items():
                    self.monitoring_data[location]['magnetic_readings'].append(reading)
                    
                    # تشخیص تغییرات میدان مغناطیسی
                    if self._detect_magnetic_anomaly(reading):
                        print(f"⚠️ تغییرات مغناطیسی مشکوک در {location}")
                
                time.sleep(2)  # خواندن هر 2 ثانیه
                
            except Exception as e:
                print(f"❌ خطا در تحلیل مغناطیسی: {e}")
                time.sleep(5)
    
    def _simulate_magnetometer(self) -> Dict:
        """شبیه‌سازی سنسور مغناطیسی"""
        # میدان مغناطیسی زمین در ایران: ~50000 nT
        earth_field = 50000
        
        magnetic_data = {}
        
        # نقاط مختلف اندازه‌گیری
        for i in range(3):
            location = f"point_{i+1}"
            
            # نوسانات طبیعی
            natural_variation = random.normalvariate(0, 50)
            
            # اثر احتمالی ماینر
            miner_effect = 0
            if random.random() < 0.15:  # 15% احتمال
                # ماینرها معمولاً میدان مغناطیسی کمتری تولید می‌کنند
                miner_effect = random.uniform(100, 500)
            
            total_field = earth_field + natural_variation + miner_effect
            
            magnetic_data[location] = {
                'total_field': total_field,
                'anomaly': miner_effect,
                'gradient': random.uniform(-10, 10),  # گرادیان میدان
                'timestamp': time.time()
            }
            
        return magnetic_data
    
    def _detect_magnetic_anomaly(self, reading: Dict) -> bool:
        """تشخیص ناهنجاری مغناطیسی"""
        return reading['anomaly'] > self.detection_thresholds['magnetic_field']
    
    def _thermal_analysis(self, duration: int):
        """تحلیل حرارتی محیط"""
        start_time = time.time()
        
        while self.is_monitoring and (time.time() - start_time) < duration:
            try:
                # شبیه‌سازی سنسور حرارتی
                thermal_data = self._simulate_thermal_camera()
                timestamp = time.time()
                
                for location, temp_data in thermal_data.items():
                    self.monitoring_data[location]['temperature_readings'].append(temp_data)
                    
                    # تشخیص نقاط داغ مشکوک
                    if self._detect_thermal_anomaly(temp_data):
                        print(f"🌡️ نقطه داغ مشکوک در {location}: {temp_data['max_temp']:.1f}°C")
                
                time.sleep(3)  # اسکن حرارتی هر 3 ثانیه
                
            except Exception as e:
                print(f"❌ خطا در تحلیل حرارتی: {e}")
                time.sleep(5)
    
    def _simulate_thermal_camera(self) -> Dict:
        """شبیه‌سازی دوربین حرارتی"""
        thermal_data = {}
        
        for i in range(3):
            location = f"area_{i+1}"
            
            # دمای محیط (بین 20-35 درجه)
            ambient_temp = random.uniform(20, 35)
            
            # گرمای اضافی احتمالی ماینر
            miner_heat = 0
            if random.random() < 0.2:  # 20% احتمال
                miner_heat = random.uniform(30, 80)  # ماینرها گرمای زیادی تولید می‌کنند
            
            max_temp = ambient_temp + miner_heat
            
            thermal_data[location] = {
                'max_temp': max_temp,
                'min_temp': ambient_temp,
                'avg_temp': (max_temp + ambient_temp) / 2,
                'temp_variance': abs(max_temp - ambient_temp),
                'hot_spots': 1 if miner_heat > 20 else 0,
                'timestamp': time.time()
            }
            
        return thermal_data
    
    def _detect_thermal_anomaly(self, temp_data: Dict) -> bool:
        """تشخیص ناهنجاری حرارتی"""
        return (temp_data['max_temp'] > self.detection_thresholds['temperature'] or
                temp_data['temp_variance'] > 40)
    
    def _flag_potential_miner(self, location: str, rf_data: Dict, timestamp: float):
        """علامت‌گذاری ماینر احتمالی"""
        if location not in self.detected_miners:
            self.detected_miners[location] = {
                'first_detected': timestamp,
                'detection_count': 0,
                'confidence_score': 0,
                'evidence': []
            }
        
        miner_data = self.detected_miners[location]
        miner_data['detection_count'] += 1
        miner_data['last_detected'] = timestamp
        
        # محاسبه امتیاز اطمینان
        confidence = 0
        evidence = []
        
        # بررسی قدرت سیگنال RF
        if rf_data['peak_power'] > self.detection_thresholds['rf_intensity']:
            confidence += 30
            evidence.append(f"سیگنال RF قوی: {rf_data['peak_power']:.1f} dBm")
        
        # بررسی فرکانس مشخصه
        peak_freq = rf_data['peak_frequency']
        for miner_type, freqs in self.miner_frequencies.items():
            if any(abs(peak_freq - f) < 1.0 for f in freqs):
                confidence += 40
                evidence.append(f"فرکانس مشخصه {miner_type}: {peak_freq:.1f} MHz")
                break
        
        # بررسی تکرار تشخیص
        if miner_data['detection_count'] > 5:
            confidence += 20
            evidence.append(f"تشخیص مکرر: {miner_data['detection_count']} بار")
        
        miner_data['confidence_score'] = min(confidence, 100)
        miner_data['evidence'] = evidence
        
        print(f"🚨 ماینر احتمالی: {location} (اطمینان: {confidence}%)")
    
    def acoustic_analysis(self, location: str = "unknown") -> Dict:
        """تحلیل صوتی برای تشخیص ماینرها"""
        print(f"🎵 شروع تحلیل صوتی در {location}")
        
        # شبیه‌سازی آنالیز صوتی
        acoustic_data = {
            'location': location,
            'ambient_noise': random.uniform(30, 50),  # dB
            'peak_noise': random.uniform(40, 80),
            'frequency_analysis': {},
            'fan_signatures': [],
            'miner_probability': 0
        }
        
        # تحلیل فرکانس‌های صوتی
        audio_freqs = np.linspace(20, 20000, 100)  # 20 Hz تا 20 kHz
        
        for freq in audio_freqs:
            # نویز پس‌زمینه
            noise_level = random.uniform(20, 40)
            
            # صدای مشخصه فن ماینر (معمولاً 50-200 Hz و 1-5 kHz)
            if (50 <= freq <= 200) or (1000 <= freq <= 5000):
                if random.random() < 0.3:  # 30% احتمال وجود ماینر
                    noise_level += random.uniform(20, 40)
                    acoustic_data['fan_signatures'].append(freq)
            
            acoustic_data['frequency_analysis'][freq] = noise_level
        
        # محاسبه احتمال وجود ماینر بر اساس صدا
        if len(acoustic_data['fan_signatures']) > 3:
            acoustic_data['miner_probability'] = min(len(acoustic_data['fan_signatures']) * 15, 90)
        
        return acoustic_data
    
    def power_consumption_analysis(self, area: str = "building") -> Dict:
        """تحلیل مصرف برق برای تشخیص ماینرها"""
        print(f"⚡ تحلیل مصرف برق در {area}")
        
        # شبیه‌سازی داده‌های مصرف برق
        power_data = {
            'area': area,
            'baseline_consumption': random.uniform(500, 2000),  # وات
            'current_consumption': 0,
            'consumption_pattern': [],
            'anomaly_detected': False,
            'miner_signature': False
        }
        
        # الگوی مصرف طی 24 ساعت گذشته
        for hour in range(24):
            # مصرف پایه
            base = power_data['baseline_consumption']
            
            # تغییرات عادی روزانه
            daily_variation = base * 0.2 * math.sin(2 * math.pi * hour / 24)
            
            # مصرف احتمالی ماینر (ثابت 24/7)
            miner_consumption = 0
            if random.random() < 0.4:  # 40% احتمال وجود ماینر
                miner_consumption = random.uniform(1000, 5000)  # ماینرها مصرف بالایی دارند
                power_data['miner_signature'] = True
            
            total_consumption = base + daily_variation + miner_consumption
            power_data['consumption_pattern'].append(total_consumption)
        
        power_data['current_consumption'] = power_data['consumption_pattern'][-1]
        
        # تشخیص ناهنجاری در مصرف
        avg_consumption = sum(power_data['consumption_pattern']) / 24
        if avg_consumption > power_data['baseline_consumption'] * 2:
            power_data['anomaly_detected'] = True
        
        return power_data
    
    def generate_comprehensive_report(self) -> Dict:
        """تولید گزارش جامع تشخیص"""
        report = {
            'scan_summary': {
                'start_time': datetime.now().isoformat(),
                'monitored_locations': len(self.monitoring_data),
                'total_detections': len(self.detected_miners),
                'high_confidence_miners': 0,
                'medium_confidence_miners': 0,
                'low_confidence_miners': 0
            },
            'detection_results': {},
            'methodology': {
                'rf_analysis': 'تحلیل طیف امواج رادیو 1MHz-1GHz',
                'magnetic_analysis': 'اندازه‌گیری میدان مغناطیسی',
                'thermal_analysis': 'تصویربرداری حرارتی',
                'acoustic_analysis': 'تحلیل طیف صوتی 20Hz-20kHz',
                'power_analysis': 'مانیتورینگ مصرف برق'
            },
            'detected_signatures': {
                'asic_miners': [],
                'gpu_miners': [],
                'cpu_miners': [],
                'unknown_miners': []
            }
        }
        
        # تحلیل نتایج تشخیص
        for location, data in self.detected_miners.items():
            confidence = data['confidence_score']
            
            if confidence >= 80:
                report['scan_summary']['high_confidence_miners'] += 1
                confidence_level = 'بالا'
            elif confidence >= 50:
                report['scan_summary']['medium_confidence_miners'] += 1
                confidence_level = 'متوسط'
            else:
                report['scan_summary']['low_confidence_miners'] += 1
                confidence_level = 'پایین'
            
            report['detection_results'][location] = {
                'confidence_score': confidence,
                'confidence_level': confidence_level,
                'evidence': data['evidence'],
                'detection_count': data['detection_count'],
                'first_detected': datetime.fromtimestamp(data['first_detected']).isoformat(),
                'coordinates': self._extract_coordinates(location)
            }
        
        return report
    
    def _extract_coordinates(self, location: str) -> Dict:
        """استخراج مختصات از نام مکان"""
        try:
            if 'lat_' in location and 'lon_' in location:
                parts = location.split('_')
                lat = float(parts[1])
                lon = float(parts[3])
                return {'latitude': lat, 'longitude': lon}
        except:
            pass
        
        return {'latitude': 33.637, 'longitude': 46.423}  # مختصات پیش‌فرض ایلام
    
    def export_detection_data(self, format: str = 'json') -> str:
        """خروجی گیری داده‌های تشخیص"""
        report = self.generate_comprehensive_report()
        
        if format == 'json':
            return json.dumps(report, ensure_ascii=False, indent=2)
        
        elif format == 'csv':
            csv_lines = ['Location,Latitude,Longitude,Confidence,Evidence,Detection_Count']
            
            for location, data in report['detection_results'].items():
                coords = data['coordinates']
                evidence = '; '.join(data['evidence'])
                csv_lines.append(
                    f"{location},{coords['latitude']},{coords['longitude']},"
                    f"{data['confidence_score']},\"{evidence}\",{data['detection_count']}"
                )
            
            return '\n'.join(csv_lines)
        
        return str(report)

# تست و مثال استفاده
if __name__ == "__main__":
    detector = RFDetector()
    
    print("🚀 شروع سیستم تشخیص RF/مغناطیسی")
    
    # شروع مانیتورینگ
    detector.start_rf_monitoring("ایلام - منطقه شهری", duration=60)
    
    # تحلیل‌های اضافی
    acoustic_result = detector.acoustic_analysis("ساختمان اداری")
    power_result = detector.power_consumption_analysis("مجتمع مسکونی")
    
    try:
        # مانیتورینگ به مدت 1 دقیقه
        time.sleep(60)
        
        # تولید گزارش نهایی
        report = detector.generate_comprehensive_report()
        
        print("\n" + "="*60)
        print("📊 گزارش نهایی تشخیص:")
        print(f"تعداد مکان‌های مانیتور شده: {report['scan_summary']['monitored_locations']}")
        print(f"تعداد ماینرهای تشخیص داده شده: {report['scan_summary']['total_detections']}")
        print(f"اطمینان بالا: {report['scan_summary']['high_confidence_miners']}")
        print(f"اطمینان متوسط: {report['scan_summary']['medium_confidence_miners']}")
        print(f"اطمینان پایین: {report['scan_summary']['low_confidence_miners']}")
        
    finally:
        detector.stop_rf_monitoring()
