#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ماژول مدل‌های هوش ��صنوعی رایگان برای تحلیل و تشخیص ماینرها
توسط: عرفان رجبی (Erfan Rajabi)

استفاده از مدل‌های ML رایگان بدون نیاز به API Key:
1. Scikit-learn برای تحلیل الگو
2. TensorFlow Lite برای تشخیص تصاویر
3. OpenCV برای پردازش تصویر
4. NumPy/SciPy برای تحلیل سیگنال
"""

import numpy as np
import json
import time
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Any
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.cluster import DBSCAN, KMeans
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
from sklearn.svm import OneClassSVM
import joblib
import os

class FreeAIAnalyzer:
    """کلاس اصلی برای تحلیل هوش مصنوعی با مدل‌های رایگان"""
    
    def __init__(self):
        self.models = {}
        self.scalers = {}
        self.training_data = {
            'network_patterns': [],
            'rf_signatures': [],
            'power_patterns': [],
            'thermal_patterns': []
        }
        
        # مدل‌های پیش‌آموزش داده شده
        self.anomaly_detector = None
        self.pattern_classifier = None
        self.clustering_model = None
        
        # آستانه‌های تشخیص
        self.detection_thresholds = {
            'anomaly_score': -0.1,
            'classification_confidence': 0.7,
            'cluster_density': 0.3
        }
        
        self._initialize_models()
        
    def _initialize_models(self):
        """راه‌اندازی مدل‌های ML"""
        print("🤖 راه‌اندازی مدل‌های هوش مصنوعی...")
        
        # مدل تشخیص ناهنجاری
        self.anomaly_detector = IsolationForest(
            contamination=0.1,
            random_state=42,
            n_estimators=100
        )
        
        # مدل طبقه‌بندی
        self.pattern_classifier = RandomForestClassifier(
            n_estimators=100,
            random_state=42,
            max_depth=10
        )
        
        # مدل خوشه‌بندی
        self.clustering_model = DBSCAN(
            eps=0.5,
            min_samples=5
        )
        
        # مدل کاهش ابعاد
        self.pca_model = PCA(n_components=5)
        
        # نرمال‌ساز داده‌ها
        self.scaler = StandardScaler()
        
        # آموزش با داده‌های شبیه‌سازی شد��
        self._train_with_synthetic_data()
        
        print("✅ مدل‌های هوش مصنوعی آماده شدند")
    
    def _train_with_synthetic_data(self):
        """آموزش مدل‌ها با داده‌های شبیه‌سازی شده"""
        print("📚 آموزش مدل‌ها با داده‌های شبیه‌سازی...")
        
        # تولید داده‌های آموزشی
        normal_data, miner_data = self._generate_training_data()
        
        # ترکیب داده‌ها
        X = np.vstack([normal_data, miner_data])
        y = np.array([0] * len(normal_data) + [1] * len(miner_data))
        
        # نرمال‌سازی
        X_scaled = self.scaler.fit_transform(X)
        
        # آموزش مدل تشخیص ناهنجاری (فقط با داده‌های عادی)
        self.anomaly_detector.fit(normal_data)
        
        # آموزش مدل طبقه‌بندی
        self.pattern_classifier.fit(X_scaled, y)
        
        # کاهش ابعاد
        self.pca_model.fit(X_scaled)
        
        print("✅ آموزش مدل‌ها کامل شد")
    
    def _generate_training_data(self) -> Tuple[np.ndarray, np.ndarray]:
        """تولید داده‌های آموزشی شبیه‌سازی شده"""
        # ویژگی‌ها: [rf_power, magnetic_field, temperature, power_consumption, 
        #            network_traffic, connection_count, peak_frequency]
        
        # داده‌های عادی (غیر ماینر)
        normal_samples = 1000
        normal_data = np.random.normal(0, 1, (normal_samples, 7))
        
        # تنظیم محدوده‌های طبیعی
        normal_data[:, 0] = np.random.uniform(-80, -60, normal_samples)  # RF power (dBm)
        normal_data[:, 1] = np.random.uniform(40, 60, normal_samples)    # Magnetic field (nT)
        normal_data[:, 2] = np.random.uniform(20, 35, normal_samples)    # Temperature (°C)
        normal_data[:, 3] = np.random.uniform(100, 500, normal_samples)  # Power (W)
        normal_data[:, 4] = np.random.uniform(10, 100, normal_samples)   # Network traffic (MB/h)
        normal_data[:, 5] = np.random.uniform(1, 20, normal_samples)     # Connections
        normal_data[:, 6] = np.random.uniform(1, 100, normal_samples)    # Peak frequency (MHz)
        
        # داده‌های ماینر
        miner_samples = 300
        miner_data = np.random.normal(0, 1, (miner_samples, 7))
        
        # تنظیم ویژگی‌های مشخصه ماینر
        miner_data[:, 0] = np.random.uniform(-50, -30, miner_samples)    # RF power بالاتر
        miner_data[:, 1] = np.random.uniform(50, 200, miner_samples)     # Magnetic field بالاتر
        miner_data[:, 2] = np.random.uniform(60, 90, miner_samples)      # Temperature بالا
        miner_data[:, 3] = np.random.uniform(1000, 5000, miner_samples)  # Power مصرف بالا
        miner_data[:, 4] = np.random.uniform(500, 2000, miner_samples)   # Network traffic بالا
        miner_data[:, 5] = np.random.uniform(50, 200, miner_samples)     # Connections زیاد
        miner_data[:, 6] = np.random.choice([13.56, 27.12, 433.92], miner_samples)  # فرکانس‌های خاص
        
        return normal_data, miner_data
    
    def analyze_network_pattern(self, network_data: Dict) -> Dict:
        """تحلیل الگوی شبکه با هوش مصنوعی"""
        print("🕸️ تحلیل الگوی شبکه با AI...")
        
        # استخراج ویژگی از داده‌های شبکه
        features = self._extract_network_features(network_data)
        
        # نرمال‌سازی
        features_scaled = self.scaler.transform([features])
        
        # تشخیص ناهنجاری
        anomaly_score = self.anomaly_detector.decision_function(features_scaled)[0]
        is_anomaly = self.anomaly_detector.predict(features_scaled)[0] == -1
        
        # طبقه‌بندی
        miner_probability = self.pattern_classifier.predict_proba(features_scaled)[0][1]
        is_miner = miner_probability > self.detection_thresholds['classification_confidence']
        
        # کاهش ابعاد برای تجسم
        pca_features = self.pca_model.transform(features_scaled)[0]
        
        result = {
            'analysis_type': 'network_pattern',
            'timestamp': datetime.now().isoformat(),
            'features': {
                'rf_power': features[0],
                'magnetic_field': features[1],
                'temperature': features[2],
                'power_consumption': features[3],
                'network_traffic': features[4],
                'connection_count': features[5],
                'peak_frequency': features[6]
            },
            'ai_analysis': {
                'anomaly_score': float(anomaly_score),
                'is_anomaly': bool(is_anomaly),
                'miner_probability': float(miner_probability),
                'is_miner_predicted': bool(is_miner),
                'confidence_level': self._get_confidence_level(miner_probability),
                'pca_representation': pca_features.tolist()
            },
            'recommendations': self._generate_recommendations(anomaly_score, miner_probability)
        }
        
        return result
    
    def _extract_network_features(self, network_data: Dict) -> List[float]:
        """استخراج ویژگی از داده‌های شبکه"""
        features = [
            network_data.get('rf_power', -70.0),
            network_data.get('magnetic_field', 50.0),
            network_data.get('temperature', 25.0),
            network_data.get('power_consumption', 200.0),
            network_data.get('network_traffic', 50.0),
            network_data.get('connection_count', 10.0),
            network_data.get('peak_frequency', 50.0)
        ]
        return features
    
    def cluster_analysis(self, data_points: List[Dict]) -> Dict:
        """تحلیل خوشه‌ای داده‌ها"""
        print("🔍 تحلیل خوشه‌ای داده‌ها...")
        
        if len(data_points) < 5:
            return {
                'error': 'تعداد داده‌ها برای تحلیل خوشه‌ای کافی نیست',
                'min_required': 5
            }
        
        # استخراج ویژگی‌ها
        features_matrix = []
        for point in data_points:
            features = self._extract_network_features(point)
            features_matrix.append(features)
        
        features_matrix = np.array(features_matrix)
        
        # نرمال‌سازی
        features_scaled = self.scaler.transform(features_matrix)
        
        # خوشه‌بندی
        cluster_labels = self.clustering_model.fit_predict(features_scaled)
        
        # تحلیل خوشه‌ها
        unique_clusters = set(cluster_labels)
        cluster_analysis = {}
        
        for cluster_id in unique_clusters:
            cluster_points = features_scaled[cluster_labels == cluster_id]
            cluster_size = len(cluster_points)
            
            if cluster_id == -1:  # نویز
                cluster_type = 'نویز/پراکنده'
                suspicion_level = 'پایین'
            else:
                # تحلیل مشخصات خوشه
                cluster_center = np.mean(cluster_points, axis=0)
                cluster_density = cluster_size / len(features_matrix)
                
                # تشخیص نوع خوشه
                if cluster_center[3] > 1:  # power consumption بالا
                    cluster_type = 'احتمال ماینر بالا'
                    suspicion_level = 'بالا'
                elif cluster_center[0] > 0.5:  # RF power بالا
                    cluster_type = 'فعالیت RF مشکوک'
                    suspicion_level = 'متوسط'
                else:
                    cluster_type = 'فعالیت عادی'
                    suspicion_level = 'پایین'
            
            cluster_analysis[f'cluster_{cluster_id}'] = {
                'size': cluster_size,
                'percentage': (cluster_size / len(features_matrix)) * 100,
                'type': cluster_type,
                'suspicion_level': suspicion_level,
                'points_indices': np.where(cluster_labels == cluster_id)[0].tolist()
            }
        
        return {
            'analysis_type': 'cluster_analysis',
            'timestamp': datetime.now().isoformat(),
            'total_points': len(data_points),
            'num_clusters': len(unique_clusters) - (1 if -1 in unique_clusters else 0),
            'noise_points': sum(1 for label in cluster_labels if label == -1),
            'clusters': cluster_analysis,
            'recommendations': self._generate_cluster_recommendations(cluster_analysis)
        }
    
    def temporal_pattern_analysis(self, time_series_data: List[Dict]) -> Dict:
        """تحلیل الگوهای زمانی"""
        print("⏰ تحلیل الگوهای زمانی...")
        
        if len(time_series_data) < 10:
            return {
                'error': 'تعداد نقاط زمانی برای تحلیل کافی نیست',
                'min_required': 10
            }
        
        # استخراج سری زمانی مختلف
        timestamps = [point.get('timestamp', time.time()) for point in time_series_data]
        power_series = [point.get('power_consumption', 0) for point in time_series_data]
        temp_series = [point.get('temperature', 0) for point in time_series_data]
        traffic_series = [point.get('network_traffic', 0) for point in time_series_data]
        
        # تحلیل الگوها
        patterns = {
            'power_pattern': self._analyze_time_series(power_series),
            'temperature_pattern': self._analyze_time_series(temp_series),
            'traffic_pattern': self._analyze_time_series(traffic_series)
        }
        
        # تشخیص الگوی ماینر (24/7 فعالیت ثابت)
        miner_indicators = 0
        
        # بررسی ثبات مصرف برق
        if patterns['power_pattern']['stability'] > 0.8:
            miner_indicators += 1
        
        # بررسی مصرف بالای برق
        if patterns['power_pattern']['mean'] > 1000:
            miner_indicators += 1
        
        # بررسی دمای بالا
        if patterns['temperature_pattern']['mean'] > 60:
            miner_indicators += 1
        
        # بررسی ترافیک ثابت
        if patterns['traffic_pattern']['stability'] > 0.7:
            miner_indicators += 1
        
        # احتمال وجود ماینر
        miner_probability = min(miner_indicators / 4.0, 1.0)
        
        return {
            'analysis_type': 'temporal_pattern',
            'timestamp': datetime.now().isoformat(),
            'data_points': len(time_series_data),
            'time_span_hours': (max(timestamps) - min(timestamps)) / 3600,
            'patterns': patterns,
            'miner_indicators': miner_indicators,
            'miner_probability': miner_probability,
            'assessment': self._assess_temporal_patterns(miner_probability),
            'recommendations': self._generate_temporal_recommendations(patterns, miner_probability)
        }
    
    def _analyze_time_series(self, series: List[float]) -> Dict:
        """تحلیل یک سری زمانی"""
        series_array = np.array(series)
        
        return {
            'mean': float(np.mean(series_array)),
            'std': float(np.std(series_array)),
            'min': float(np.min(series_array)),
            'max': float(np.max(series_array)),
            'trend': self._calculate_trend(series_array),
            'stability': self._calculate_stability(series_array),
            'periodicity': self._detect_periodicity(series_array)
        }
    
    def _calculate_trend(self, series: np.ndarray) -> float:
        """محاسبه روند سری زمانی"""
        x = np.arange(len(series))
        slope = np.polyfit(x, series, 1)[0]
        return float(slope)
    
    def _calculate_stability(self, series: np.ndarray) -> float:
        """محاسبه ثبات سری زمانی"""
        if len(series) < 2:
            return 0.0
        
        # ضریب تغییرات (کم‌تر = پایدارتر)
        cv = np.std(series) / (np.mean(series) + 1e-10)
        stability = max(0, 1 - cv)
        return float(stability)
    
    def _detect_periodicity(self, series: np.ndarray) -> Dict:
        """تشخیص تناوب در سری زمانی"""
        if len(series) < 10:
            return {'has_period': False, 'period': None}
        
        # تحلیل FFT ساده
        fft = np.fft.fft(series)
        freqs = np.fft.fftfreq(len(series))
        
        # پیدا کردن فرکانس غالب
        dominant_freq_idx = np.argmax(np.abs(fft[1:len(fft)//2])) + 1
        dominant_freq = freqs[dominant_freq_idx]
        
        if abs(dominant_freq) > 0.1:
            period = 1 / abs(dominant_freq)
            return {
                'has_period': True,
                'period': float(period),
                'strength': float(np.abs(fft[dominant_freq_idx]) / np.sum(np.abs(fft)))
            }
        
        return {'has_period': False, 'period': None, 'strength': 0}
    
    def _get_confidence_level(self, probability: float) -> str:
        """تعیین سطح اطمینان"""
        if probability >= 0.8:
            return 'بسیار بالا'
        elif probability >= 0.6:
            return 'بالا'
        elif probability >= 0.4:
            return 'متوسط'
        elif probability >= 0.2:
            return 'پایین'
        else:
            return 'بسیار پایین'
    
    def _generate_recommendations(self, anomaly_score: float, miner_probability: float) -> List[str]:
        """تولید توصیه‌ها"""
        recommendations = []
        
        if miner_probability > 0.7:
            recommendations.append("🚨 احتمال بالای وجود ماینر - بررسی فیزیکی فوری")
            recommendations.append("📋 مستندسازی شواهد برای اقدام قانونی")
        elif miner_probability > 0.5:
            recommendations.append("⚠️ فعالیت مشکوک - افزایش مانیتورینگ")
            recommendations.append("🔍 اسکن دقیق‌تر محدوده")
        
        if anomaly_score < -0.5:
            recommendations.append("🔎 الگوی غیرعادی شناسایی شد")
            recommendations.append("📊 تحلیل بیشتر داده‌های تاریخی")
        
        if not recommendations:
            recommendations.append("✅ فعالیت در محدوده طبیعی")
            recommendations.append("🔄 ادامه مانیتورینگ معمول")
        
        return recommendations
    
    def _generate_cluster_recommendations(self, cluster_analysis: Dict) -> List[str]:
        """تولید توصیه‌های خوشه‌ای"""
        recommendations = []
        
        high_suspicion_clusters = [
            cluster for cluster in cluster_analysis.values()
            if cluster.get('suspicion_level') == 'بالا'
        ]
        
        if high_suspicion_clusters:
            recommendations.append(f"🚨 {len(high_suspicion_clusters)} خوشه با سطح خطر بالا شناسایی شد")
            recommendations.append("🔍 بررسی فوری نقاط مشکوک")
        
        medium_suspicion_clusters = [
            cluster for cluster in cluster_analysis.values()
            if cluster.get('suspicion_level') == 'متوسط'
        ]
        
        if medium_suspicion_clusters:
            recommendations.append(f"⚠️ {len(medium_suspicion_clusters)} خوشه با سطح خطر متوسط")
        
        return recommendations
    
    def _assess_temporal_patterns(self, miner_probability: float) -> str:
        """ارزیابی الگوهای زمانی"""
        if miner_probability >= 0.8:
            return "الگوی فعالیت کاملاً مطابق با ماینر رمزارز"
        elif miner_probability >= 0.6:
            return "الگوی فعالیت بسیار مشکوک به ماینر"
        elif miner_probability >= 0.4:
            return "الگوی فعالیت نیاز به بررسی بیشتر دارد"
        elif miner_probability >= 0.2:
            return "الگوی فعالیت کمی غیرعادی"
        else:
            return "الگوی فعالیت طبیعی"
    
    def _generate_temporal_recommendations(self, patterns: Dict, miner_probability: float) -> List[str]:
        """تولید توصیه‌های الگوی زمانی"""
        recommendations = []
        
        if miner_probability > 0.6:
            recommendations.append("🚨 الگوی زمانی مطابق با ماینر - بررسی فوری")
            
        if patterns['power_pattern']['mean'] > 2000:
            recommendations.append("⚡ مصرف برق بالا - بررسی تجهیزات")
            
        if patterns['temperature_pattern']['mean'] > 70:
            recommendations.append("🌡️ دمای بالا - بررسی سیستم خنک‌کننده")
            
        if patterns['traffic_pattern']['stability'] > 0.8:
            recommendations.append("🌐 ترافیک شبکه بسیار منظم - احتمال ماینر")
        
        return recommendations
    
    def save_model(self, filepath: str):
        """ذخیره مدل آموزش دیده"""
        model_data = {
            'anomaly_detector': self.anomaly_detector,
            'pattern_classifier': self.pattern_classifier,
            'scaler': self.scaler,
            'pca_model': self.pca_model,
            'timestamp': datetime.now().isoformat()
        }
        
        joblib.dump(model_data, filepath)
        print(f"💾 مدل در {filepath} ذخیره شد")
    
    def load_model(self, filepath: str):
        """بارگذاری مدل ذخیره شده"""
        if os.path.exists(filepath):
            model_data = joblib.load(filepath)
            
            self.anomaly_detector = model_data['anomaly_detector']
            self.pattern_classifier = model_data['pattern_classifier']
            self.scaler = model_data['scaler']
            self.pca_model = model_data['pca_model']
            
            print(f"📚 مدل از {filepath} بارگذاری شد")
        else:
            print(f"❌ فایل مدل {filepath} یافت نشد")

# مثال استفاده
if __name__ == "__main__":
    analyzer = FreeAIAnalyzer()
    
    # نمونه داده شبکه
    sample_network_data = {
        'rf_power': -45.0,
        'magnetic_field': 120.0,
        'temperature': 75.0,
        'power_consumption': 2500.0,
        'network_traffic': 800.0,
        'connection_count': 150.0,
        'peak_frequency': 27.12
    }
    
    print("🚀 شروع تحلیل هوش مصنوعی...")
    
    # تحلیل الگوی شبکه
    network_analysis = analyzer.analyze_network_pattern(sample_network_data)
    print(f"🕸️ احتمال ماینر: {network_analysis['ai_analysis']['miner_probability']:.2f}")
    print(f"🎯 سطح اطمینان: {network_analysis['ai_analysis']['confidence_level']}")
    
    # تولید داده‌های نمونه برای تحلیل خوشه‌ای
    sample_points = []
    for i in range(20):
        point = {
            'rf_power': np.random.uniform(-60, -30),
            'magnetic_field': np.random.uniform(40, 150),
            'temperature': np.random.uniform(25, 80),
            'power_consumption': np.random.uniform(200, 3000),
            'network_traffic': np.random.uniform(50, 1000),
            'connection_count': np.random.uniform(5, 200),
            'peak_frequency': np.random.choice([13.56, 27.12, 50.0, 100.0])
        }
        sample_points.append(point)
    
    # تحلیل خوشه‌ای
    cluster_analysis = analyzer.cluster_analysis(sample_points)
    print(f"🔍 تعداد خوشه‌ها: {cluster_analysis['num_clusters']}")
