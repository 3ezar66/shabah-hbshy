import socket
import requests
import ipaddress

# API Keys (جایگزین کن با کلیدهای خودت)
ABUSEIPDB_API_KEY = "11e9cbd8c7b5b2bf17a689c6ba61236287f62f7ca19c64d05a7bd420f5affe68"
PROXYCHECK_API_KEY = "g4h996-3u1579-40s3e7-f18k55"
SHODAN_API_KEY = "wgH9c7KfZkbXhfi4McSpivgFfsCqFAJm"
IPINFO_API_KEY = "df7861fa741dbf"

# پورت‌های ماینینگ معمول
MINER_PORTS = [22, 3333, 3389, 4444, 5555, 7777, 8888, 9999, 18081, 18082, 18083, 3000, 4000, 5000]

def check_port(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            result = s.connect_ex((ip, port))
            return result == 0
    except:
        return False

def abuseipdb_check(ip):
    url = f"https://api.abuseipdb.com/api/v2/check"
    headers = {
        'Accept': 'application/json',
        'Key': ABUSEIPDB_API_KEY
    }
    params = {
        'ipAddress': ip,
        'maxAgeInDays': 90
    }
    try:
        response = requests.get(url, headers=headers, params=params, timeout=5)
        if response.status_code == 200:
            return response.json()
        else:
            return None
    except:
        return None

def proxycheck_check(ip):
    url = f"https://proxycheck.io/v2/{ip}"
    params = {
        'key': PROXYCHECK_API_KEY,
        'vpn': 1,
        'asn': 1
    }
    try:
        response = requests.get(url, params=params, timeout=5)
        if response.status_code == 200:
            return response.json()
        else:
            return None
    except:
        return None

def shodan_check(ip):
    url = f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}"
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            return response.json()
        else:
            return None
    except:
        return None

def ipinfo_check(ip):
    url = f"https://ipinfo.io/{ip}/json?token={IPINFO_API_KEY}"
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            return response.json()
        else:
            return None
    except:
        return None

def is_suspect(ip, proxycheck_res, abuseipdb_res):
    if not proxycheck_res or not abuseipdb_res:
        return False
    proxy = proxycheck_res.get(ip, {}).get("proxy", "no") if ip in proxycheck_res else "no"
    abuse_score = abuseipdb_res.get("data", {}).get("abuseConfidenceScore", 0)
    return proxy == "yes" or abuse_score > 50

def main():
    ip_range_input = input("رنج IP را به صورت start-end وارد کنید (مثال: 192.168.1.1-192.168.1.255): ").strip()
    try:
        start_ip_str, end_ip_str = ip_range_input.split('-')
        start_ip = ipaddress.IPv4Address(start_ip_str)
        end_ip = ipaddress.IPv4Address(end_ip_str)
    except Exception as e:
        print("فرمت IP نادرست است.")
        return

    current_ip = start_ip
    while current_ip <= end_ip:
        ip = str(current_ip)
        print(f"\n🔎 در حال بررسی {ip} ...")

        abuseipdb_res = abuseipdb_check(ip)
        proxycheck_res = proxycheck_check(ip)

        if is_suspect(ip, proxycheck_res, abuseipdb_res):
            print(f"[⚠️] IP مشکوک به فعالیت ماینری یافت شد: {ip}")

            # چک پورت‌های ماینینگ
            for port in MINER_PORTS:
                if check_port(ip, port):
                    print(f"[✅] پورت باز و فعال برای ماینینگ یافت شد: {port}")
                else:
                    print(f"[❌] پورت {port} بسته است.")

        else:
            print("[ℹ️] IP مشکوک به ماینر نیست.")

        if current_ip == end_ip:
            break
        current_ip += 1

if __name__ == "__main__":
    main()
