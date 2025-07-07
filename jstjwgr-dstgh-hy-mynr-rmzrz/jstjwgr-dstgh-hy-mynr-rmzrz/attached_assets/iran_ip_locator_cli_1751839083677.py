import json

# Load provinces and cities from JSON file
with open("iran_states_cities.json", "r", encoding="utf-8") as f:
    data = json.load(f)

# Step 1: Let user choose a province
print("\n📍 لیست استان‌های ایران:")
provinces = list(data.keys())
for i, province in enumerate(provinces, 1):
    print(f"{i}. {province}")

province_choice = int(input("\nاستان مورد نظر را انتخاب کنید (شماره وارد کنید): "))
selected_province = provinces[province_choice - 1]

# Step 2: Let user choose a city
cities = data[selected_province]
print(f"\n🏙️ لیست شهرهای استان {selected_province}:")
for i, city in enumerate(cities, 1):
    print(f"{i}. {city}")

city_choice = int(input("\nشهر مورد نظر را انتخاب کنید (شماره وارد کنید): "))
selected_city = cities[city_choice - 1]

# Step 3: Simulate IP range detection
print("\n🛰️ در حال دریافت اطلاعات IP برای منطقه انتخاب‌شده...")
# Placeholder: Replace with actual IP mapping logic or API call
sample_ip_range = "192.168.100.0/24"

print(f"\n✅ محدوده IP برای {selected_city} در {selected_province}: {sample_ip_range}")

# Step 4: Save to local DB or config (mocked here)
db = {"province": selected_province, "city": selected_city, "ip_range": sample_ip_range}

with open("target_location.json", "w", encoding="utf-8") as f:
    json.dump(db, f, indent=4, ensure_ascii=False)

print("\n💾 اطلاعات در فایل target_location.json ذخیره شد.")
