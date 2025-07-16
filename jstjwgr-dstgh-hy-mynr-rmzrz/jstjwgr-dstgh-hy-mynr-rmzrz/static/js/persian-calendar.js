// Persian (Jalali) Calendar Conversion Functions
// Accurate Persian calendar implementation

class PersianCalendar {
  constructor() {
    this.persianMonths = [
      "فروردین",
      "اردیبهشت",
      "خرداد",
      "تیر",
      "مرداد",
      "شهریور",
      "مهر",
      "آبان",
      "آذر",
      "دی",
      "بهمن",
      "اسفند",
    ];

    this.persianDays = [
      "یکشنبه",
      "دوشنبه",
      "سه‌شنبه",
      "چهارشنبه",
      "پنج‌شنبه",
      "جمعه",
      "شنبه",
    ];
  }

  // Convert Gregorian to Persian date
  gregorianToPersian(gYear, gMonth, gDay) {
    const g_d_m = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];

    let gy = gYear;
    let gm = gMonth;
    let gd = gDay;

    let jy, jm, jd;

    if (gy <= 1600) {
      jy = 0;
      gy -= 621;
    } else {
      jy = 979;
      gy -= 1600;
    }

    let gy2 = gm > 2 ? gy + 1 : gy;
    let days =
      365 * gy +
      Math.floor((gy2 + 3) / 4) +
      Math.floor((gy2 + 99) / 100) -
      Math.floor((gy2 + 399) / 400) -
      80 +
      gd +
      g_d_m[gm - 1];

    jy += 33 * Math.floor(days / 12053);
    days %= 12053;

    jy += 4 * Math.floor(days / 1461);
    days %= 1461;

    if (days > 365) {
      jy += Math.floor((days - 1) / 365);
      days = (days - 1) % 365;
    }

    if (days < 186) {
      jm = 1 + Math.floor(days / 31);
      jd = 1 + (days % 31);
    } else {
      jm = 7 + Math.floor((days - 186) / 30);
      jd = 1 + ((days - 186) % 30);
    }

    return { year: jy, month: jm, day: jd };
  }

  // Get current Persian date
  getCurrentPersianDate() {
    const now = new Date();
    const gregorianDate = {
      year: now.getFullYear(),
      month: now.getMonth() + 1,
      day: now.getDate(),
    };

    const persianDate = this.gregorianToPersian(
      gregorianDate.year,
      gregorianDate.month,
      gregorianDate.day,
    );

    const dayOfWeek = this.persianDays[now.getDay()];

    return {
      year: persianDate.year,
      month: persianDate.month,
      day: persianDate.day,
      monthName: this.persianMonths[persianDate.month - 1],
      dayOfWeek: dayOfWeek,
      formatted: `${dayOfWeek}، ${persianDate.day} ${this.persianMonths[persianDate.month - 1]} ${persianDate.year}`,
    };
  }

  // Get formatted time
  getCurrentTime() {
    const now = new Date();
    return now.toLocaleTimeString("fa-IR", {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  }
}

// Export for use
window.PersianCalendar = PersianCalendar;
