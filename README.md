

# 🚀 LML PANEL

### پنل مدیریت و ساخت کانفیگ

**رابط کاربری مدرن • مدیریت آسان • راه‌اندازی روی Cloudflare**

به مخزن رسمی LML PANEL خوش آمدید.

در این پروژه می‌توانید سورس پنل را مشاهده کنید و با دنبال کردن راهنمای زیر، نسخه خودتان را راه‌اندازی کنید.

[📦 مشاهده سورس کد](https://github.com/nukesamp-crypto/LML-PANEL)　·　[💬 کانال تلگرام](https://t.me/LML_panel)　·　[🐛 گزارش مشکل](https://github.com/nukesamp-crypto/LML-PANEL/issues/new)



---

## 📌 معرفی پروژه

LML PANEL یک پنل وب فارسی برای مدیریت کاربران و ساخت کانفیگ‌های اتصال است.

این پروژه بر پایه Cloudflare Workers و پایگاه داده D1 طراحی شده و بخش‌های اصلی برنامه در قالب یک Worker اجرا می‌شوند.

---

## ✨ امکانات پنل

* مدیریت کاربران و تنظیمات آن‌ها
* ساخت کانفیگ و مدیریت اطلاعات مربوط به کاربران
* داشبورد مدیریتی و نمایش اطلاعات
* مدیریت محدودیت‌ها و تاریخ انقضای کاربران
* پشتیبان‌گیری و بازیابی اطلاعات
* تنظیمات مختلف پنل
* رابط کاربری فارسی
* قابلیت به‌روزرسانی پنل

---

## 🧰 پیش‌نیازهای نصب

برای راه‌اندازی پنل به موارد زیر نیاز دارید:

* یک حساب کاربری Cloudflare
* دسترسی به بخش Workers در داشبورد Cloudflare
* امکان ایجاد پایگاه داده D1
* سورس کد پروژه از مخزن رسمی LML PANEL

---

## 🚀 آموزش نصب و راه‌اندازی

### مرحله اول: دریافت سورس کد

وارد مخزن رسمی پروژه شوید:

[دریافت سورس کد LML PANEL](https://github.com/nukesamp-crypto/LML-PANEL)

فایل برنامه را از مخزن دریافت کنید.

### مرحله دوم: ساخت Worker

۱. وارد داشبورد Cloudflare شوید.

۲. از بخش Workers & Pages، یک Worker جدید ایجاد کنید.

۳. نام دلخواه خود را برای Worker انتخاب کنید.

۴. پس از ایجاد Worker، وارد بخش ویرایش کد شوید.

۵. محتوای فایل برنامه را در ویرایشگر قرار دهید.

۶. تغییرات را ذخیره و Worker را Deploy کنید.

### مرحله سوم: ایجاد پایگاه داده D1

۱. در داشبورد Cloudflare وارد بخش D1 شوید.

۲. یک پایگاه داده جدید ایجاد کنید.

۳. به تنظیمات Worker برگردید.

۴. وارد بخش Settings و سپس Bindings شوید.

۵. یک اتصال D1 Database اضافه کنید.

۶. پایگاه داده‌ای را که ساخته‌اید انتخاب کنید.

۷. نام متغیر اتصال را دقیقاً برابر با DB قرار دهید.

**توجه:** نام متغیر اتصال باید دقیقاً DB باشد تا برنامه بتواند به پایگاه داده دسترسی پیدا کند.

### مرحله چهارم: استقرار نهایی

پس از تنظیم اتصال پایگاه داده:

۱. تغییرات Worker را ذخیره کنید.

۲. یک بار دیگر Deploy را انجام دهید.

۳. آدرس Worker خود را باز کنید.

۴. در انتهای آدرس، مسیر /panel را قرار دهید.

۵. صفحه مدیریت پنل را باز کنید و رمز عبور مدیر را تنظیم کنید.

### مرحله پنجم: بررسی عملکرد

پس از ورود به پنل، بخش‌های مختلف را بررسی کنید تا مطمئن شوید برنامه و پایگاه داده به‌درستی کار می‌کنند.

جداول موردنیاز پایگاه داده در اولین اجرا به‌صورت خودکار ایجاد می‌شوند و نیازی به ساخت دستی آن‌ها نیست.

---

## 🔄 به‌روزرسانی پنل

برای به‌روزرسانی، ابتدا تغییرات نسخه جدید را در مخزن رسمی بررسی کنید.

سپس می‌توانید از قابلیت به‌روزرسانی پنل یا روش دستی معرفی‌شده در مستندات پروژه استفاده کنید.

پیش از انجام تغییرات مهم، از اطلاعات پایگاه داده خود نسخه پشتیبان تهیه کنید.

---

## 🔐 نکات امنیتی

* رمز عبور مدیریت پنل را در اختیار افراد غیرمجاز قرار ندهید.
* اطلاعات محرمانه و توکن‌های دسترسی را در مخزن عمومی منتشر نکنید.
* تنظیمات دسترسی پایگاه داده را با دقت انجام دهید.
* پیش از به‌روزرسانی، از اطلاعات مهم خود نسخه پشتیبان تهیه کنید.

---

## 🐛 گزارش مشکل و باگ

اگر هنگام نصب، راه‌اندازی یا استفاده از پنل با مشکلی مواجه شدید، لطفاً گزارش خود را از طریق بخش Issues گیت‌هاب ثبت کنید.

در گزارش خود، مشکل را واضح توضیح دهید و مشخص کنید در کدام مرحله با آن مواجه شده‌اید.

### 📩 ثبت گزارش جدید

[**برای ثبت گزارش مشکل یا باگ کلیک کنید**](https://github.com/nukesamp-crypto/LML-PANEL/issues/new)

---

## 💬 ارتباط با ما

برای دریافت اطلاعیه‌ها و دنبال کردن اخبار پروژه، به کانال تلگرام LML PANEL بپیوندید.

[**ورود به کانال تلگرام LML PANEL**](https://t.me/LML_panel)

---



### LML PANEL

**مدیریت آسان‌تر، تجربه‌ای مدرن‌تر.**

⭐ اگر پروژه برای شما مفید است، می‌توانید با دادن Star از آن حمایت کنید.

</div>


---

## 📝 v1.0.0 (Custom Build) — Update Notes

**Why this update?** This build fixes the long-standing issue where admin-entered IPs never appeared in generated configs, removes the Cloudflare-range restriction entirely, and makes updates come from this GitHub repository only — always with admin confirmation.

### 🐛 Fixed
- **User IPs never appeared in configs** — Auto IP-rotation (enabled by default) was *replacing* the admin's own clean IPs with random ones in all three config generators (subscription `/sub/`, panel "Copy Configs", status page). Own IPs now always come **first**; rotation and live-repo IPs are only appended.
- **"Copy Configs" copied the subscription link instead of the configs** — an undeclared variable assignment under `"use strict"` threw a `ReferenceError` inside the config builder; the error was silently swallowed by the copy fallback. Fixed.
- **Multi-IP users got no IP configs in the panel** — a newline-escaping bug (`split` on a literal backslash-n instead of real newlines) emptied `ips_valid` whenever a user had more than one IP. Fixed.
- **Edit form pollution** — the users API returned rotated random IPs in the `ips` field, so editing a user displayed (and then permanently saved) IPs the admin never entered. The form now shows the stored IPs.

### 🔓 Changed
- **Cloudflare-range restriction removed** — every IP the admin enters is accepted: no range validation, no rejections, no error messages (in the IP filter, `/api/scan-ips`, and the panel button, which is now a local "tidy IPs" action).
- **New config family: IP + TLS** — for every user IP the panel now emits TLS links on 443/2053/… with `sni=<panel domain>` and `allowInsecure=1`, so clients never hit SSL/CCL certificate errors, even with non-Cloudflare IPs. Domain+TLS and IP+plain-HTTP families are kept.
- **Updates: GitHub-only + confirmation** — the update source is this repository (`worker.js`); the old external fallback was removed, and updates are never applied silently: the admin is always asked first.
- **Login page redesigned** to match the in-panel design system (glassmorphism card, Vazirmatn font, aurora background, accent gradients).

### ✨ Added
- **Live IP repository (`live-ips.json`)** — edit this file right here on GitHub:
  ```json
  { "enabled": true, "ips": ["1.2.3.4", "5.6.7.8"] }
  ```
  Those IPs are appended to **every user's configs within ~5 minutes — no redeploy needed**. Network failures never throw; results are cached and refreshed in the background.

### ⚡ Performance
- Removed a blocking Cloudflare-ranges fetch from **every subscription request**.
- Proxy country lookups are cached for 24 h (previously a network round-trip per proxy, per request).
- Live-IP refresh runs in the background after the first fetch; "Restart core" clears all new caches.
