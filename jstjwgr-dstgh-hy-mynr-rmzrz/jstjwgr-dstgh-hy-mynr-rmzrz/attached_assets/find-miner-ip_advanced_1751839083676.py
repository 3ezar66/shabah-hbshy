import requests
import ipaddress
import socket
import sqlite3
import time
from datetime import datetime

# کلیدهای API (با کلیدهای خودت جایگزین کن)
ABUSEIPDB_KEY = "11e9cbd8c7b5b2bf17a689c6ba61236287f62f7ca19c64d05a7bd420f5affe68"
PROXYCHECK_KEY = "g4h996-3u1579-40s3e7-f18k55"
SHODAN_KEY = "wgH9c7KfZkbXhfi4McSpivgFfsCqFAJm"
IPINFO_KEY = "df7861fa741dbf"

# پورت‌های مهم ماینینگ برای چک کردن
PORTS = [22, 3333, 3389, 4444, 5555, 7777, 8888, 9999, 18081, 18082, 18083, 3000, 4000, 5000]

# دیتابیس sqlite برای ذخیره اطلاعات
conn = sqlite3.connect("ip_mining_scan.db")
cursor = conn.cursor()
cursor.execute('''
CREATE TABLE IF NOT EXISTS scan_results (
    ip TEXT PRIMARY KEY,
    proxycheck TEXT,
    abuseipdb TEXT,
    shodan TEXT,
    ipinfo TEXT,
    open_ports TEXT,
    timestamp TEXT
)
''')
conn.commit()

def scan_ports(ip):
    open_ports = []
    for port in PORTS:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                if s.connect_ex((ip, port)) == 0:
                    open_ports.append(port)
        except:
            pass
    return open_ports

def call_proxycheck(ip):
    url = f"https://proxycheck.io/v2/{ip}?key={PROXYCHECK_KEY}&vpn=1&asn=1"
    try:
        res = requests.get(url, timeout=5).json()
        return res
    except:
        return None

def call_abuseipdb(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": ABUSEIPDB_KEY,
        "Accept": "application/json"
    }
    params = {"ipAddress": ip, "maxAgeInDays": "90"}
    try:
        res = requests.get(url, headers=headers, params=params, timeout=5).json()
        return res
    except:
        return None

def call_shodan(ip):
    url = f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_KEY}"
    try:
        res = requests.get(url, timeout=5).json()
        return res
    except:
        return None

def call_ipinfo(ip):
    url = f"https://ipinfo.io/{ip}?token={IPINFO_KEY}"
    try:
        res = requests.get(url, timeout=5).json()
        return res
    except:
        return None

def is_suspect(proxycheck_res, abuseipdb_res):
    # شرط ساده برای شناسایی IP مشکوک: VPN یا proxy فعال یا گزارش بالا
    if not proxycheck_res or not abuseipdb_res:
        return False
    proxy = proxycheck_res.get(ip, {}).get("proxy", "no") if ip in proxycheck_res else "no"
    abuse_score = abuseipdb_res.get("data", {}).get("abuseConfidenceScore", 0)
    return proxy == "yes" or abuse_score > 50

def save_result(ip, proxycheck_res, abuseipdb_res, shodan_res, ipinfo_res, open_ports):
    cursor.execute('''
    INSERT OR REPLACE INTO scan_results 
    (ip, proxycheck, abuseipdb, shodan, ipinfo, open_ports, timestamp)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (
        ip,
        str(proxycheck_res),
        str(abuseipdb_res),
        str(shodan_res),
        str(ipinfo_res),
        ",".join(map(str, open_ports)),
        datetime.utcnow().isoformat()
    ))
    conn.commit()

def generate_html_report():
    cursor.execute("SELECT * FROM scan_results")
    rows = cursor.fetchall()
    with open("report.html", "w", encoding="utf-8") as f:
        f.write("<html><head><meta charset='utf-8'><title>گزارش اسکن ماینر</title></head><body>")
        f.write("<h1>گزارش اسکن IP ماینر</h1><table border=1><tr><th>IP</th><th>ProxyCheck</th><th>AbuseIPDB</th><th>Shodan</th><th>IPInfo</th><th>Open Ports</th><th>Timestamp</th></tr>")
        for row in rows:
            f.write("<tr>")
            for col in row:
                f.write(f"<td><pre>{col}</pre></td>")
            f.write("</tr>")
        f.write("</table></body></html>")

def main():
    ip_range = input("رنج IP را به صورت start-end وارد کنید (مثال: 192.168.1.1-192.168.1.255): ").strip()
    try:
        start_ip_str, end_ip_str = ip_range.split("-")
        start_ip = ipaddress.IPv4Address(start_ip_str)
        end_ip = ipaddress.IPv4Address(end_ip_str)
        if start_ip > end_ip:
            print("خطا: IP شروع بزرگتر از IP پایان است.")
            return
    except Exception as e:
        print("ورودی نامعتبر است:", e)
        return

    current_ip = start_ip
    while current_ip <= end_ip:
        ip = str(current_ip)
        print(f"\n🔎 در حال بررسی {ip} ...")
        proxycheck_res = call_proxycheck(ip)
        abuseipdb_res = call_abuseipdb(ip)
        shodan_res = call_shodan(ip)
        ipinfo_res = call_ipinfo(ip)

        # اگر IP مشکوک بود، پورت‌ها رو بررسی کن
        open_ports = []
        if proxycheck_res and abuseipdb_res:
            if is_suspect(proxycheck_res, abuseipdb_res):
                print(f"⚠️ {ip} مشکوک به ماینینگ، بررسی پورت‌ها...")
                open_ports = scan_ports(ip)
                print(f"پورت‌های باز: {open_ports if open_ports else 'هیچ'}")
            else:
                print(f"{ip} مشکوک نیست.")

        # ذخیره در دیتابیس
        save_result(ip, proxycheck_res, abuseipdb_res, shodan_res, ipinfo_res, open_ports)

        # تاخیر جهت جلوگیری از بلاک شدن API ها
        time.sleep(1)

        current_ip += 1

    print("\nکار اسکن تمام شد. گزارش در فایل report.html ذخیره شد.")
    generate_html_report()

if __name__ == "__main__":
    main()
