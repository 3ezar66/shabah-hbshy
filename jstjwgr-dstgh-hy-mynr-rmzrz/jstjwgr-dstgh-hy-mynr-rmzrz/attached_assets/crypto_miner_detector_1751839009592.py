#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Advanced Cryptocurrency Miner Detection System
Optimized for Windows 10/11 64-bit
"""

import os
import sys
import socket
import threading
import subprocess
import re
import json
import time
import sqlite3
import math
import psutil
import wmi
import requests
import platform  # Added for system information
from datetime import datetime, timedelta
from collections import defaultdict
import hashlib
import statistics
import concurrent.futures
from pathlib import Path
import winreg
import ctypes
from ctypes import wintypes
import win32api
import win32con
import win32security
import win32net
import win32netcon

class AdvancedMinerDetector:
    def __init__(self):
        # Ilam province boundaries (more precise)
        self.ilam_bounds = {
            'north': 34.5,
            'south': 32.0, 
            'east': 48.5,
            'west': 45.5,
            'center': (33.63, 46.42)
        }
        
        # Enhanced cities database for Ilam
        self.ilam_cities = {
            'Ilam': (33.6374, 46.4227),
            'Mehran': (33.1221, 46.1641),
            'Dehloran': (32.6942, 47.2678),
            'Abdanan': (32.9928, 47.4164),
            'Darreh Shahr': (33.1458, 47.3667),
            'Ivan': (33.8081, 46.2892),
            'Chardavol': (33.7333, 46.8833),
            'Badreh': (33.0833, 47.1167),
            'Sarableh': (32.9667, 46.5833),
            'Malekshahi': (33.3833, 46.5667),
            'Shirvan Chardavol': (33.9, 46.95),
            'Eyvan': (33.8081, 46.2892),
            'Arkavaz': (33.4167, 46.6833),
            'Zarneh': (33.2833, 46.8167)
        }
        
        # Comprehensive miner detection ports
        self.miner_ports = {
            # Mining APIs
            4028: "CGMiner API", 4029: "SGMiner API", 4030: "BFGMiner API",
            4031: "CPUMiner API", 4032: "XMRig API", 4033: "T-Rex API",
            4034: "PhoenixMiner API", 4035: "Claymore API", 4036: "Gminer API",
            
            # Web Interfaces
            8080: "Web Interface", 8888: "Web Interface Alt", 8081: "Miner Web UI",
            3000: "Miner Dashboard", 3001: "Mining Pool UI", 8000: "HTTP Server",
            
            # Stratum Pools
            3333: "Stratum Pool", 4444: "Stratum Pool Alt", 9999: "Stratum SSL",
            14444: "Stratum SSL Alt", 5555: "Stratum Pool", 7777: "Stratum Pool",
            
            # Proxy and VPN
            1080: "SOCKS Proxy", 3128: "HTTP Proxy", 8118: "Privoxy",
            9050: "Tor SOCKS", 1194: "OpenVPN", 1723: "PPTP VPN",
            
            # Cryptocurrency specific
            8332: "Bitcoin RPC", 8333: "Bitcoin P2P", 9332: "Litecoin RPC",
            19332: "Bitcoin Testnet", 18332: "Bitcoin Regtest",
            
            # Mining Pool Connections
            4001: "Mining Pool", 4002: "Mining Pool Alt", 6666: "Mining Pool",
            25: "SMTP (suspicious)", 587: "SMTP TLS", 465: "SMTP SSL"
        }
        
        # Known miner process signatures
        self.miner_processes = {
            'cgminer.exe', 'bfgminer.exe', 'sgminer.exe', 'cpuminer.exe',
            'xmrig.exe', 'xmr-stak.exe', 'claymore.exe', 'phoenixminer.exe',
            't-rex.exe', 'gminer.exe', 'nbminer.exe', 'teamredminer.exe',
            'lolminer.exe', 'miniZ.exe', 'bminer.exe', 'z-enemy.exe',
            'ccminer.exe', 'ethminer.exe', 'nanominer.exe', 'srbminer.exe',
            'wildrig.exe', 'xmrig-nvidia.exe', 'xmrig-amd.exe'
        }
        
        # Suspicious registry keys
        self.suspicious_registry_keys = [
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
            r"SYSTEM\CurrentControlSet\Services"
        ]
        
        # Initialize WMI connection
        try:
            self.wmi_conn = wmi.WMI()
        except Exception as e:
            print(f"WMI initialization failed: {e}")
            self.wmi_conn = None
        
        # Initialize database
        self.init_database()

    def init_database(self):
        """Initialize enhanced SQLite database"""
        self.conn = sqlite3.connect('advanced_miners.db')
        cursor = self.conn.cursor()
        
        # Main miners table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS detected_miners (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT,
                mac_address TEXT,
                hostname TEXT,
                latitude REAL,
                longitude REAL,
                city TEXT,
                detection_method TEXT,
                power_consumption REAL,
                hash_rate TEXT,
                device_type TEXT,
                process_name TEXT,
                cpu_usage REAL,
                memory_usage REAL,
                network_usage REAL,
                gpu_usage REAL,
                detection_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                confidence_score INTEGER,
                threat_level TEXT,
                notes TEXT
            )
        ''')
        
        # Process monitoring table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS process_monitoring (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                process_name TEXT,
                pid INTEGER,
                cpu_percent REAL,
                memory_mb REAL,
                network_connections TEXT,
                command_line TEXT,
                parent_process TEXT,
                detection_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                suspicious_score INTEGER
            )
        ''')
        
        # Network monitoring table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS network_monitoring (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                local_address TEXT,
                local_port INTEGER,
                remote_address TEXT,
                remote_port INTEGER,
                protocol TEXT,
                status TEXT,
                process_name TEXT,
                detection_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Registry monitoring table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS registry_monitoring (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                registry_key TEXT,
                value_name TEXT,
                value_data TEXT,
                suspicious_score INTEGER,
                detection_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        self.conn.commit()

    def get_system_info(self):
        """Get comprehensive system information"""
        system_info = {
            'os': f"{platform.system()} {platform.platform()}",  # Modified to use platform module
            'cpu_count': psutil.cpu_count(),
            'cpu_freq': psutil.cpu_freq()._asdict() if psutil.cpu_freq() else None,
            'memory': psutil.virtual_memory()._asdict(),
            'disk': [disk._asdict() for disk in psutil.disk_partitions()],
            'network_interfaces': [],
            'gpu_info': []
        }
        
        # Network interfaces
        for interface, addrs in psutil.net_if_addrs().items():
            interface_info = {'name': interface, 'addresses': []}
            for addr in addrs:
                interface_info['addresses'].append({
                    'family': str(addr.family),
                    'address': addr.address,
                    'netmask': addr.netmask,
                    'broadcast': addr.broadcast
                })
            system_info['network_interfaces'].append(interface_info)
        
        # GPU information using WMI
        if self.wmi_conn:
            try:
                for gpu in self.wmi_conn.Win32_VideoController():
                    if gpu.Name:
                        system_info['gpu_info'].append({
                            'name': gpu.Name,
                            'driver_version': gpu.DriverVersion,
                            'memory': gpu.AdapterRAM
                        })
            except Exception as e:
                print(f"GPU info error: {e}")
        
        return system_info

    def monitor_processes(self):
        """Advanced process monitoring"""
        suspicious_processes = []
        
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info', 
                                       'cmdline', 'connections', 'ppid']):
            try:
                proc_info = proc.info
                process_name = proc_info['name'].lower()
                
                # Check against known miner processes
                suspicion_score = 0
                detection_reasons = []
                
                if process_name in [p.lower() for p in self.miner_processes]:
                    suspicion_score += 50
                    detection_reasons.append('known_miner_process')
                
                # Check for suspicious keywords in process name
                suspicious_keywords = ['miner', 'mining', 'crypto', 'bitcoin', 'ethereum', 
                                     'monero', 'xmr', 'btc', 'eth', 'hash', 'pool']
                if any(keyword in process_name for keyword in suspicious_keywords):
                    suspicion_score += 30
                    detection_reasons.append('suspicious_name')
                
                # Check CPU usage
                cpu_percent = proc_info['cpu_percent'] or 0
                if cpu_percent > 80:
                    suspicion_score += 20
                    detection_reasons.append('high_cpu_usage')
                
                # Check memory usage
                memory_mb = proc_info['memory_info'].rss / 1024 / 1024 if proc_info['memory_info'] else 0
                if memory_mb > 500:  # More than 500MB
                    suspicion_score += 10
                    detection_reasons.append('high_memory_usage')
                
                # Check network connections
                connections = proc_info['connections'] or []
                mining_ports = set(self.miner_ports.keys())
                for conn in connections:
                    if hasattr(conn, 'raddr') and conn.raddr:
                        if conn.raddr.port in mining_ports:
                            suspicion_score += 25
                            detection_reasons.append('mining_port_connection')
                
                # Check command line arguments
                cmdline = ' '.join(proc_info['cmdline'] or []).lower()
                mining_args = ['--algo', '--pool', '--user', '--pass', '--worker', 
                             'stratum+tcp', '--cuda', '--opencl', '--intensity']
                if any(arg in cmdline for arg in mining_args):
                    suspicion_score += 35
                    detection_reasons.append('mining_arguments')
                
                # Debug log
                print(f"Checking process: {proc_info['name']}, Suspicion Score: {suspicion_score}, Reasons: {detection_reasons}")
                
                if suspicion_score > 10:  # Reduced threshold from 20 to 10
                    suspicious_processes.append({
                        'pid': proc_info['pid'],
                        'name': proc_info['name'],
                        'cpu_percent': cpu_percent,
                        'memory_mb': memory_mb,
                        'cmdline': cmdline,
                        'connections': len(connections),
                        'suspicion_score': suspicion_score,
                        'detection_reasons': detection_reasons,
                        'parent_pid': proc_info['ppid']
                    })
                    
                    # Save to database
                    self.save_process_to_db(proc_info, suspicion_score)
                    
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        
        return suspicious_processes

    def monitor_network_connections(self):
        """Monitor network connections for mining activity"""
        suspicious_connections = []
        
        for conn in psutil.net_connections(kind='inet'):
            try:
                if conn.raddr and conn.raddr.port in self.miner_ports:
                    # Get process info
                    try:
                        proc = psutil.Process(conn.pid) if conn.pid else None
                        process_name = proc.name() if proc else 'Unknown'
                    except:
                        process_name = 'Unknown'
                    
                    connection_info = {
                        'local_address': f"{conn.laddr.ip}:{conn.laddr.port}",
                        'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}",
                        'protocol': 'TCP' if conn.type == socket.SOCK_STREAM else 'UDP',
                        'status': conn.status,
                        'process_name': process_name,
                        'service': self.miner_ports.get(conn.raddr.port, 'Unknown'),
                        'suspicion_score': 40
                    }
                    
                    # Debug log
                    print(f"Suspicious connection: {connection_info['remote_address']}, Service: {connection_info['service']}")
                    
                    suspicious_connections.append(connection_info)
                    
                    # Save to database
                    self.save_connection_to_db(connection_info)
                    
            except Exception as e:
                continue
        
        return suspicious_connections

    def scan_registry_for_miners(self):
        """Scan Windows registry for miner-related entries"""
        suspicious_entries = []
        
        for key_path in self.suspicious_registry_keys:
            try:
                # Try both HKEY_LOCAL_MACHINE and HKEY_CURRENT_USER
                for hive in [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]:
                    try:
                        key = winreg.OpenKey(hive, key_path)
                        
                        # Enumerate values
                        i = 0
                        while True:
                            try:
                                value_name, value_data, value_type = winreg.EnumValue(key, i)
                                
                                # Check for suspicious patterns
                                suspicion_score = 0
                                detection_reasons = []
                                
                                # Check value name
                                if any(keyword in value_name.lower() for keyword in 
                                      ['miner', 'mining', 'crypto', 'bitcoin', 'ethereum']):
                                    suspicion_score += 30
                                    detection_reasons.append('suspicious_value_name')
                                
                                # Check value data
                                if isinstance(value_data, str):
                                    if any(keyword in value_data.lower() for keyword in 
                                          ['miner', 'mining', 'crypto', 'pool', 'stratum']):
                                        suspicion_score += 25
                                        detection_reasons.append('suspicious_value_data')
                                    
                                    # Check for executable paths
                                    if value_data.endswith('.exe') and any(proc in value_data.lower() 
                                                                          for proc in self.miner_processes):
                                        suspicion_score += 40
                                        detection_reasons.append('miner_executable')
                                
                                # Debug log
                                print(f"Registry check: {key_path}\\{value_name}, Suspicion Score: {suspicion_score}, Reasons: {detection_reasons}")
                                
                                if suspicion_score > 10:  # Reduced threshold from 20 to 10
                                    entry = {
                                        'hive': 'HKLM' if hive == winreg.HKEY_LOCAL_MACHINE else 'HKCU',
                                        'key_path': key_path,
                                        'value_name': value_name,
                                        'value_data': str(value_data),
                                        'suspicion_score': suspicion_score,
                                        'detection_reasons': detection_reasons
                                    }
                                    suspicious_entries.append(entry)
                                    
                                    # Save to database
                                    self.save_registry_to_db(entry)
                                
                                i += 1
                            except WindowsError:
                                break
                        
                        winreg.CloseKey(key)
                    except WindowsError:
                        continue
            except Exception as e:
                continue
        
        return suspicious_entries

    def advanced_port_scan(self, ip, ports=None, timeout=1):
        """Advanced port scanning with threading"""
        if ports is None:
            ports = list(self.miner_ports.keys())
        
        open_ports = []
        
        def scan_single_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((ip, port))
                sock.close()
                if result == 0:
                    return port
            except:
                pass
            return None
        
        # Use ThreadPoolExecutor for concurrent scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            future_to_port = {executor.submit(scan_single_port, port): port for port in ports}
            for future in concurrent.futures.as_completed(future_to_port):
                result = future.result()
                if result:
                    open_ports.append(result)
        
        return open_ports

    def get_network_ranges(self):
        """Get all network ranges to scan"""
        ranges = []
        
        for interface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET and not addr.address.startswith('127.'):
                    # Calculate network range
                    ip_parts = addr.address.split('.')
                    if addr.netmask:
                        # Simple /24 network assumption for common cases
                        if addr.netmask == '255.255.255.0':
                            network_base = '.'.join(ip_parts[:-1])
                            ranges.append(network_base)
        
        # Add common ranges if none found
        if not ranges:
            ranges = ['192.168.1', '192.168.0', '10.0.0', '172.16.0']
        
        return ranges

    def geolocate_ip_sync(self, ip_address):
        """Synchronous IP geolocation using requests"""
        try:
            url = f'http://ip-api.com/json/{ip_address}'
            response = requests.get(url, timeout=5)
            data = response.json()
            
            if data['status'] == 'success':
                location_data = {
                    'lat': float(data['lat']),
                    'lon': float(data['lon']),
                    'city': data.get('city', ''),
                    'region': data.get('regionName', ''),
                    'country': data.get('country', ''),
                    'isp': data.get('isp', ''),
                    'org': data.get('org', '')
                }
                
                # Check if in Ilam bounds
                if self.is_in_ilam_bounds(location_data['lat'], location_data['lon']):
                    location_data['in_ilam'] = True
                    location_data['closest_city'] = self.find_closest_city(
                        location_data['lat'], location_data['lon'])
                else:
                    location_data['in_ilam'] = False
                
                return location_data
        except Exception as e:
            print(f"Geolocation error for {ip_address}: {e}")
        
        return None

    def comprehensive_network_scan(self, progress_callback=None):
        """Comprehensive synchronous network scan"""
        devices = []
        ranges = self.get_network_ranges()
        
        def update_progress(message):
            if progress_callback:
                progress_callback(message)
            else:
                print(message)
    
        update_progress("Starting network discovery...")
    
        # Discover active IPs first
        active_ips = []
        for range_base in ranges:
            update_progress(f"Scanning range {range_base}.x...")
        
            def ping_ip(i):
                ip = f"{range_base}.{i}"
                if self.ping_host(ip):
                    return ip
                return None
        
            # Concurrent ping scanning
            with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
                futures = [executor.submit(ping_ip, i) for i in range(1, 255)]
                for future in concurrent.futures.as_completed(futures):
                    result = future.result()
                    if result:
                        active_ips.append(result)
    
        update_progress(f"Found {len(active_ips)} active IPs. Performing detailed scan...")
    
        # Detailed scan of active IPs
        for ip in active_ips:
            update_progress(f"Scanning {ip}...")
        
            device_info = {
                'ip': ip,
                'timestamp': datetime.now().isoformat(),
                'open_ports': [],
                'services': {},
                'mac_address': self.get_mac_address_advanced(ip),
                'hostname': self.get_hostname(ip),
                'os_fingerprint': self.get_os_fingerprint(ip),
                'suspicion_score': 0,
                'detection_methods': [],
                'geolocation': None
            }
        
            # Port scan
            open_ports = self.advanced_port_scan(ip)
            device_info['open_ports'] = open_ports
        
            for port in open_ports:
                service = self.miner_ports.get(port, "Unknown Service")
                device_info['services'][port] = service
                device_info['suspicion_score'] += 25
                device_info['detection_methods'].append(f'port_{port}')
        
            # Banner grabbing
            device_info['banners'] = self.grab_banners(ip, open_ports[:5])  # Limit to first 5 ports
        
            # Check for mining-specific banners
            for port, banner in device_info['banners'].items():
                if any(keyword in banner.lower() for keyword in 
                      ['miner', 'mining', 'stratum', 'cgminer', 'bfgminer']):
                    device_info['suspicion_score'] += 30
                    device_info['detection_methods'].append('mining_banner')
        
            # Hostname analysis
            if device_info['hostname']:
                hostname = device_info['hostname'].lower()
                if any(keyword in hostname for keyword in 
                      ['miner', 'mining', 'asic', 'antminer', 'whatsminer']):
                    device_info['suspicion_score'] += 35
                    device_info['detection_methods'].append('suspicious_hostname')
        
            # Geolocation (only for suspicious devices)
            if device_info['suspicion_score'] > 10:  # Reduced threshold from 20 to 10
                device_info['geolocation'] = self.geolocate_ip_sync(ip)
        
            if device_info['suspicion_score'] > 5:  # Reduced threshold from 10 to 5
                devices.append(device_info)
                print(f"Suspicious device detected: {ip}, Score: {device_info['suspicion_score']}, Methods: {device_info['detection_methods']}")
    
        return devices

    def get_mac_address_advanced(self, ip):
        """Advanced MAC address retrieval using multiple methods"""
        # Method 1: ARP table
        try:
            result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if ip in line:
                        parts = line.split()
                        for part in parts:
                            if re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', part):
                                return part.replace('-', ':')
        except:
            pass
        
        # Method 2: PowerShell
        try:
            ps_cmd = f'Get-NetNeighbor -IPAddress {ip} | Select-Object LinkLayerAddress'
            result = subprocess.run(['powershell', '-Command', ps_cmd], 
                                  capture_output=True, text=True)
            if result.returncode == 0 and result.stdout:
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    if re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', line.strip()):
                        return line.strip()
        except:
            pass
        
        return None

    def get_hostname(self, ip):
        """Get hostname for IP address"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:
            return None

    def get_os_fingerprint(self, ip):
        """Basic OS fingerprinting"""
        try:
            # Try to determine OS based on TTL and other characteristics
            result = subprocess.run(['ping', '-n', '1', ip], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                output = result.stdout
                if 'TTL=64' in output:
                    return 'Linux/Unix'
                elif 'TTL=128' in output:
                    return 'Windows'
                elif 'TTL=255' in output:
                    return 'Network Device'
        except:
            pass
        
        return 'Unknown'

    def grab_banners(self, ip, ports):
        """Grab service banners from open ports"""
        banners = {}
        
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                sock.connect((ip, port))
                
                # Send HTTP request for web services
                if port in [80, 8080, 8888, 3000, 3001, 8000]:
                    sock.send(b'GET / HTTP/1.1\r\nHost: ' + ip.encode() + b'\r\n\r\n')
                
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                if banner.strip():
                    banners[port] = banner.strip()
                
                sock.close()
            except:
                continue
        
        return banners

    def monitor_gpu_usage(self):
        """Monitor GPU usage for mining detection"""
        gpu_info = []
        
        if self.wmi_conn:
            try:
                # Get GPU utilization using WMI
                for gpu in self.wmi_conn.Win32_PerfRawData_GPUPerformanceCounters_GPUEngine():
                    if gpu.UtilizationPercentage:
                        gpu_info.append({
                            'name': gpu.Name,
                            'utilization': float(gpu.UtilizationPercentage),
                            'suspicious': float(gpu.UtilizationPercentage) > 80
                        })
            except Exception as e:
                print(f"GPU monitoring error: {e}")
        
        # Alternative method using nvidia-smi if available
        try:
            result = subprocess.run(['nvidia-smi', '--query-gpu=name,utilization.gpu,temperature.gpu', 
                                   '--format=csv,noheader,nounits'], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    parts = line.split(', ')
                    if len(parts) >= 3:
                        name, utilization, temperature = parts[0], parts[1], parts[2]
                        gpu_info.append({
                            'name': name,
                            'utilization': float(utilization),
                            'temperature': float(temperature),
                            'suspicious': float(utilization) > 80 or float(temperature) > 80
                        })
        except:
            pass
        
        return gpu_info

    def analyze_power_consumption(self):
        """Analyze system power consumption patterns"""
        power_info = {
            'cpu_usage': psutil.cpu_percent(interval=1),
            'memory_usage': psutil.virtual_memory().percent,
            'disk_usage': psutil.disk_usage('/').percent if os.name != 'nt' else psutil.disk_usage('C:').percent,
            'network_io': psutil.net_io_counters()._asdict(),
            'suspicious_power_pattern': False
        }
        
        # Check for suspicious power patterns
        if power_info['cpu_usage'] > 80:
            power_info['suspicious_power_pattern'] = True
            power_info['reason'] = 'High CPU usage'
        
        # Get battery info if available
        try:
            battery = psutil.sensors_battery()
            if battery:
                power_info['battery'] = {
                    'percent': battery.percent,
                    'power_plugged': battery.power_plugged,
                    'secsleft': battery.secsleft
                }
        except:
            pass
        
        return power_info

    def comprehensive_scan(self, progress_callback=None):
        """Main comprehensive scanning function"""
        def update_progress(message):
            if progress_callback:
                progress_callback(message)
            else:
                print(message)
    
        update_progress("Starting comprehensive miner detection scan...")
    
        results = {
            'timestamp': datetime.now().isoformat(),
            'scan_area': 'Ilam Province',
            'system_info': self.get_system_info(),
            'network_devices': [],
            'suspicious_processes': [],
            'suspicious_connections': [],
            'suspicious_registry': [],
            'gpu_usage': [],
            'power_analysis': {},
            'geolocated_miners': [],
            'statistics': {}
        }
    
        # System analysis
        update_progress("Analyzing system information...")
        results['system_info'] = self.get_system_info()
    
        # Process monitoring
        update_progress("Monitoring processes...")
        results['suspicious_processes'] = self.monitor_processes()
    
        # Network connection monitoring
        update_progress("Monitoring network connections...")
        results['suspicious_connections'] = self.monitor_network_connections()
    
        # Registry scanning
        update_progress("Scanning registry...")
        results['suspicious_registry'] = self.scan_registry_for_miners()
    
        # GPU monitoring
        update_progress("Monitoring GPU usage...")
        results['gpu_usage'] = self.monitor_gpu_usage()
    
        # Power analysis
        update_progress("Analyzing power consumption...")
        results['power_analysis'] = self.analyze_power_consumption()
    
        # Network scanning
        update_progress("Scanning network...")
        results['network_devices'] = self.comprehensive_network_scan(update_progress)
    
        # Identify geolocated miners
        for device in results['network_devices']:
            if device.get('suspicion_score', 0) > 30 and device.get('geolocation'):
                if device['geolocation'].get('in_ilam'):
                    results['geolocated_miners'].append(device)
    
        # Calculate statistics
        results['statistics'] = self.calculate_comprehensive_statistics(results)
    
        # Save to database
        update_progress("Saving results to database...")
        self.save_comprehensive_results(results)
    
        update_progress("Scan completed successfully!")
        return results

    def calculate_comprehensive_statistics(self, results):
        """Calculate comprehensive statistics"""
        stats = {
            'total_devices_scanned': len(results['network_devices']),
            'suspicious_devices': len([d for d in results['network_devices'] 
                                     if d.get('suspicion_score', 0) > 30]),
            'confirmed_miners': len(results['geolocated_miners']),
            'suspicious_processes': len(results['suspicious_processes']),
            'suspicious_connections': len(results['suspicious_connections']),
            'suspicious_registry_entries': len(results['suspicious_registry']),
            'high_gpu_usage': len([g for g in results['gpu_usage'] if g.get('suspicious')]),
            'threat_level': 'Low',
            'overall_risk_score': 0
        }
        
        # Calculate overall risk score
        risk_score = 0
        risk_score += stats['confirmed_miners'] * 50
        risk_score += stats['suspicious_devices'] * 20
        risk_score += stats['suspicious_processes'] * 15
        risk_score += stats['suspicious_connections'] * 10
        risk_score += stats['suspicious_registry_entries'] * 5
        risk_score += stats['high_gpu_usage'] * 10
        
        stats['overall_risk_score'] = risk_score
        
        # Determine threat level
        if risk_score >= 100:
            stats['threat_level'] = 'Critical'
        elif risk_score >= 50:
            stats['threat_level'] = 'High'
        elif risk_score >= 20:
            stats['threat_level'] = 'Medium'
        else:
            stats['threat_level'] = 'Low'
        
        return stats

    def generate_advanced_html_report(self, results):
        """Generate advanced HTML report with charts and maps"""
        html = f'''
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Advanced Miner Detection Report</title>
            <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
            <script src="https://unpkg.com/leaflet@1.7.1/dist/leaflet.js"></script>
            <link rel="stylesheet" href="https://unpkg.com/leaflet@1.7.1/dist/leaflet.css" />
            <style>
                body {{
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    margin: 0;
                    padding: 0;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: #333;
                }}
                .container {{
                    max-width: 1200px;
                    margin: 0 auto;
                    padding: 20px;
                }}
                .header {{
                    background: rgba(255, 255, 255, 0.95);
                    padding: 30px;
                    border-radius: 15px;
                    box-shadow: 0 10px 30px rgba(0,0,0,0.2);
                    margin-bottom: 30px;
                    text-align: center;
                }}
                .header h1 {{
                    color: #2c3e50;
                    margin: 0;
                    font-size: 2.5em;
                }}
                .header p {{
                    color: #7f8c8d;
                    margin: 10px 0;
                }}
                .stats-grid {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                    gap: 20px;
                    margin-bottom: 30px;
                }}
                .stat-card {{
                    background: rgba(255, 255, 255, 0.95);
                    padding: 25px;
                    border-radius: 15px;
                    box-shadow: 0 5px 15px rgba(0,0,0,0.1);
                    text-align: center;
                }}
                .stat-number {{
                    font-size: 2.5em;
                    font-weight: bold;
                    margin-bottom: 10px;
                }}
                .critical {{ color: #e74c3c; }}
                .high {{ color: #f39c12; }}
                .medium {{ color: #f1c40f; }}
                .low {{ color: #27ae60; }}
                .section {{
                    background: rgba(255, 255, 255, 0.95);
                    margin-bottom: 30px;
                    border-radius: 15px;
                    box-shadow: 0 5px 15px rgba(0,0,0,0.1);
                    overflow: hidden;
                }}
                .section-header {{
                    background: #34495e;
                    color: white;
                    padding: 20px;
                    font-size: 1.3em;
                    font-weight: bold;
                }}
                .section-content {{
                    padding: 25px;
                }}
                .device-card {{
                    border: 1px solid #ecf0f1;
                    border-radius: 10px;
                    padding: 20px;
                    margin-bottom: 15px;
                    border-left: 5px solid #3498db;
                }}
                .device-card.critical {{ border-left-color: #e74c3c; }}
                .device-card.high {{ border-left-color: #f39c12; }}
                .device-card.medium {{ border-left-color: #f1c40f; }}
                .chart-container {{
                    width: 100%;
                    height: 400px;
                    margin: 20px 0;
                }}
                #map {{
                    height: 500px;
                    width: 100%;
                    border-radius: 10px;
                }}
                .process-table {{
                    width: 100%;
                    border-collapse: collapse;
                    margin-top: 20px;
                }}
                .process-table th, .process-table td {{
                    padding: 12px;
                    text-align: left;
                    border-bottom: 1px solid #ddd;
                }}
                .process-table th {{
                    background-color: #f8f9fa;
                    font-weight: bold;
                }}
                .badge {{
                    padding: 5px 10px;
                    border-radius: 15px;
                    font-size: 0.8em;
                    font-weight: bold;
                }}
                .badge-critical {{ background: #e74c3c; color: white; }}
                .badge-high {{ background: #f39c12; color: white; }}
                .badge-medium {{ background: #f1c40f; color: black; }}
                .badge-low {{ background: #27ae60; color: white; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Advanced Cryptocurrency Miner Detection Report</h1>
                    <p><strong>Scan Date:</strong> {results['timestamp']}</p>
                    <p><strong>Target Area:</strong> {results['scan_area']}</p>
                    <p><strong>Threat Level:</strong> 
                        <span class="{results['statistics']['threat_level'].lower()}">
                            {results['statistics']['threat_level'].upper()}
                        </span>
                    </p>
                </div>
                
                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-number critical">{results['statistics']['confirmed_miners']}</div>
                        <div>Confirmed Miners</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number high">{results['statistics']['suspicious_devices']}</div>
                        <div>Suspicious Devices</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number medium">{results['statistics']['suspicious_processes']}</div>
                        <div>Suspicious Processes</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number low">{results['statistics']['total_devices_scanned']}</div>
                        <div>Total Devices Scanned</div>
                    </div>
                </div>
        '''
        
        # Add map section
        html += '''
                <div class="section">
                    <div class="section-header">Geographic Distribution</div>
                    <div class="section-content">
                        <div id="map"></div>
                    </div>
                </div>
        '''
        
        # Add charts section
        html += '''
                <div class="section">
                    <div class="section-header">Detection Statistics</div>
                    <div class="section-content">
                        <div class="chart-container">
                            <canvas id="detectionChart"></canvas>
                        </div>
                    </div>
                </div>
        '''
        
        # Add detected devices section
        if results['network_devices']:
            html += '''
                <div class="section">
                    <div class="section-header">Detected Network Devices</div>
                    <div class="section-content">
            '''
            
            for device in results['network_devices']:
                score = device.get('suspicion_score', 0)
                if score >= 70:
                    risk_class = 'critical'
                    risk_label = 'CRITICAL'
                elif score >= 50:
                    risk_class = 'high'
                    risk_label = 'HIGH'
                elif score >= 30:
                    risk_class = 'medium'
                    risk_label = 'MEDIUM'
                else:
                    risk_class = 'low'
                    risk_label = 'LOW'
                
                location_info = ""
                if device.get('geolocation'):
                    geo = device['geolocation']
                    location_info = f"<p><strong>Location:</strong> {geo.get('city', 'Unknown')}, {geo.get('region', '')} ({geo.get('lat', 0):.4f}, {geo.get('lon', 0):.4f})</p>"
                
                html += f'''
                    <div class="device-card {risk_class}">
                        <h3>{risk_label} RISK - IP: {device['ip']} <span class="badge badge-{risk_class}">Score: {score}</span></h3>
                        <p><strong>Hostname:</strong> {device.get('hostname', 'Unknown')}</p>
                        <p><strong>MAC Address:</strong> {device.get('mac_address', 'Unknown')}</p>
                        <p><strong>Open Ports:</strong> {', '.join(map(str, device.get('open_ports', [])))}</p>
                        <p><strong>Detection Methods:</strong> {', '.join(device.get('detection_methods', []))}</p>
                        <p><strong>OS Fingerprint:</strong> {device.get('os_fingerprint', 'Unknown')}</p>
                        {location_info}
                    </div>
                '''
            
            html += '''
                    </div>
                </div>
            '''
        
        # Add suspicious processes section
        if results['suspicious_processes']:
            html += '''
                <div class="section">
                    <div class="section-header">Suspicious Processes</div>
                    <div class="section-content">
                        <table class="process-table">
                            <thead>
                                <tr>
                                    <th>Process Name</th>
                                    <th>PID</th>
                                    <th>CPU %</th>
                                    <th>Memory (MB)</th>
                                    <th>Suspicion Score</th>
                                    <th>Detection Reasons</th>
                                </tr>
                            </thead>
                            <tbody>
            '''
            
            for proc in results['suspicious_processes']:
                score = proc.get('suspicion_score', 0)
                if score >= 70:
                    badge_class = 'badge-critical'
                elif score >= 50:
                    badge_class = 'badge-high'
                elif score >= 30:
                    badge_class = 'badge-medium'
                else:
                    badge_class = 'badge-low'
                
                html += f'''
                    <tr>
                        <td><strong>{proc.get('name', 'Unknown')}</strong></td>
                        <td>{proc.get('pid', 'N/A')}</td>
                        <td>{proc.get('cpu_percent', 0):.1f}%</td>
                        <td>{proc.get('memory_mb', 0):.1f}</td>
                        <td><span class="badge {badge_class}">{score}</span></td>
                        <td>{', '.join(proc.get('detection_reasons', []))}</td>
                    </tr>
                '''
            
            html += '''
                            </tbody>
                        </table>
                    </div>
                </div>
            '''
        
        # Add JavaScript for charts and map
        html += f'''
                <script>
                    // Initialize map
                    var map = L.map('map').setView([33.63, 46.42], 10);
                    L.tileLayer('https://{{s}}.tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png', {{
                        attribution: '© OpenStreetMap contributors'
                    }}).addTo(map);
                    
                    // Add markers for detected miners
        '''
        
        for device in results.get('geolocated_miners', []):
            if device.get('geolocation'):
                geo = device['geolocation']
                score = device.get('suspicion_score', 0)
                color = 'red' if score >= 70 else 'orange' if score >= 50 else 'yellow'
                
                html += f'''
                    L.marker([{geo['lat']}, {geo['lon']}])
                        .addTo(map)
                        .bindPopup('<b>Suspicious Device</b><br>IP: {device["ip"]}<br>Score: {score}<br>Location: {geo.get("city", "Unknown")}');
                '''
        
        # Add chart
        html += f'''
                    // Detection statistics chart
                    var ctx = document.getElementById('detectionChart').getContext('2d');
                    var chart = new Chart(ctx, {{
                        type: 'doughnut',
                        data: {{
                            labels: ['Confirmed Miners', 'Suspicious Devices', 'Suspicious Processes', 'Clean Devices'],
                            datasets: [{{
                                data: [
                                    {results['statistics']['confirmed_miners']},
                                    {results['statistics']['suspicious_devices']},
                                    {results['statistics']['suspicious_processes']},
                                    {results['statistics']['total_devices_scanned'] - results['statistics']['suspicious_devices']}
                                ],
                                backgroundColor: ['#e74c3c', '#f39c12', '#f1c40f', '#27ae60']
                            }}]
                        }},
                        options: {{
                            responsive: true,
                            maintainAspectRatio: false,
                            plugins: {{
                                legend: {{
                                    position: 'bottom'
                                }}
                            }}
                        }}
                    }});
                </script>
            </div>
        </body>
        </html>
        '''
        
        # Save HTML file
        report_filename = f'advanced_miner_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.html'
        with open(report_filename, 'w', encoding='utf-8') as f:
            f.write(html)
        
        return report_filename

    # Database helper methods
    def save_process_to_db(self, proc_info, suspicion_score):
        """Save process information to database"""
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                INSERT INTO process_monitoring 
                (process_name, pid, cpu_percent, memory_mb, command_line, 
                 parent_process, suspicious_score)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                proc_info.get('name', ''),
                proc_info.get('pid', 0),
                proc_info.get('cpu_percent', 0),
                proc_info.get('memory_info', {}).get('rss', 0) / 1024 / 1024 if proc_info.get('memory_info') else 0,
                ' '.join(proc_info.get('cmdline', [])),
                proc_info.get('ppid', 0),
                suspicion_score
            ))
            self.conn.commit()
        except Exception as e:
            print(f"Database save error: {e}")

    def save_connection_to_db(self, conn_info):
        """Save network connection to database"""
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                INSERT INTO network_monitoring 
                (local_address, remote_address, protocol, status, process_name)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                conn_info.get('local_address', ''),
                conn_info.get('remote_address', ''),
                conn_info.get('protocol', ''),
                conn_info.get('status', ''),
                conn_info.get('process_name', '')
            ))
            self.conn.commit()
        except Exception as e:
            print(f"Database save error: {e}")

    def save_registry_to_db(self, entry):
        """Save registry entry to database"""
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                INSERT INTO registry_monitoring 
                (registry_key, value_name, value_data, suspicious_score)
                VALUES (?, ?, ?, ?)
            ''', (
                f"{entry['hive']}\\{entry['key_path']}",
                entry['value_name'],
                entry['value_data'],
                entry['suspicion_score']
            ))
            self.conn.commit()
        except Exception as e:
            print(f"Database save error: {e}")

    def save_comprehensive_results(self, results):
        """Save comprehensive results to database"""
        try:
            cursor = self.conn.cursor()
            
            # Save detected miners
            for device in results.get('geolocated_miners', []):
                if device.get('geolocation'):
                    geo = device['geolocation']
                    cursor.execute('''
                        INSERT INTO detected_miners 
                        (ip_address, mac_address, hostname, latitude, longitude, city, 
                         detection_method, device_type, confidence_score, threat_level, notes)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        device['ip'],
                        device.get('mac_address', ''),
                        device.get('hostname', ''),
                        geo.get('lat', 0),
                        geo.get('lon', 0),
                        geo.get('city', ''),
                        ','.join(device.get('detection_methods', [])),
                        'cryptocurrency_miner',
                        device.get('suspicion_score', 0),
                        results['statistics']['threat_level'],
                        json.dumps(device, ensure_ascii=False)
                    ))
            
            self.conn.commit()
        except Exception as e:
            print(f"Database save error: {e}")

    # Utility methods
    def ping_host(self, ip):
        """Ping host - Windows 10/11 optimized"""
        try:
            result = subprocess.run(['ping', '-n', '1', '-w', '1000', ip], 
                                  capture_output=True, text=True)
            return result.returncode == 0
        except:
            return False

    def is_in_ilam_bounds(self, lat, lon):
        """Check if coordinates are within Ilam boundaries"""
        return (self.ilam_bounds['south'] <= lat <= self.ilam_bounds['north'] and
                self.ilam_bounds['west'] <= lon <= self.ilam_bounds['east'])

    def find_closest_city(self, lat, lon):
        """Find the closest city in Ilam"""
        min_distance = float('inf')
        closest_city = None
        
        for city, (city_lat, city_lon) in self.ilam_cities.items():
            distance = self.haversine(lat, lon, city_lat, city_lon)
            if distance < min_distance:
                min_distance = distance
                closest_city = city
        
        return {'city': closest_city, 'distance_km': min_distance}
    
    def haversine(self, lat1, lon1, lat2, lon2):
        """Calculate distance between two points"""
        lat1, lon1, lat2, lon2 = map(math.radians, [lat1, lon1, lat2, lon2])
        dlon = lon2 - lon1
        dlat = lat2 - lat1
        a = math.sin(dlat/2)**2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon/2)**2
        c = 2 * math.asin(math.sqrt(a))
        r = 6371  # Earth radius in kilometers
        return c * r

    def close_database(self):
        """Close database connection"""
        if hasattr(self, 'conn'):
            self.conn.close()

if __name__ == "__main__":
    detector = AdvancedMinerDetector()
    try:
        results = detector.comprehensive_scan()
        report_file = detector.generate_advanced_html_report(results)
        print(f"Report generated: {report_file}")
    finally:
        detector.close_database()