import socket

# پورت‌هایی که معمولاً برای ماینینگ استفاده می‌شن
ports = [22, 3333, 3389, 4444, 5555, 7777, 8888, 9999, 18081, 18082, 18083, 3000, 4000, 5000]

# آدرس آی‌پی هدف (جایگزین کن با آی‌پی موردنظر)
target_ip = "192.168.1.100"  # 👈 آی‌پی رو اینجا بذار

print(f"🔍 در حال بررسی پورت‌های ماینری روی {target_ip}...\n")

for port in ports:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)  # تایم‌اوت یک ثانیه‌ای
            result = s.connect_ex((target_ip, port))
            if result == 0:
                print(f"[✅] پورت باز است: {port}")
            else:
                print(f"[❌] پورت بسته است: {port}")
    except Exception as e:
        print(f"[⚠️] خطا هنگام بررسی پورت {port}: {e}")
