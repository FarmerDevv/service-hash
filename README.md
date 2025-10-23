# 🔒 Service Hash  
### USB Token Tabanlı Kurumsal Güvenlik Sistemi

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python)](https://python.org)  
[![License](https://img.shields.io/badge/Lisans-GPLv3-red?logo=gnu)](https://www.gnu.org/licenses/gpl-3.0)  
[![Platform](https://img.shields.io/badge/Platform-Windows%207%2F10%2F11-orange)](https://microsoft.com/windows)  
[![PyQt5](https://img.shields.io/badge/Arayüz-PyQt5-purple)](https://www.riverbankcomputing.com/software/pyqt/)

Yetkili bir USB token çıkarıldığında Windows sistemini anında kilitleyen, klavye/fare girdilerini ve kritik sistem araçlarını devre dışı bırakan, tüm yönetim işlemlerini şifreyle koruyan gerçek zamanlı bir güvenlik çözümü.

---

## ✨ Özellikler

- **Anında Kilit**: Yetkili USB çıkarıldığında sistem tamamen kilitlenir; yeniden takıldığında otomatik açılır.  
- **Giriş Engelleme**:  
  - `Ctrl+Alt+Del`, `Win` tuşları, `Alt+Tab`, `F1–F12`  
  - Tüm klavye ve fare girdileri  
- **Sistem Koruması**:  
  - Görev Yöneticisi, Komut İstemi, Kayıt Defteri, Win+X menüsü devre dışı  
- **Şifreli Yönetim**: Token değiştirme, sıfırlama, yapılandırma gibi tüm işlemler şifre gerektirir.  
- **Olay Günlüğü**: Tüm eylemler zaman damgalı ve JSON formatında kaydedilir.  
- **Sistem Tepsisi**: Minimal arayüzle durum takibi ve hızlı erişim.  
- **Otomatik Başlatma**: Windows ile birlikte yönetici olarak arka planda çalışır.

---

## 🛠️ Gereksinimler

| Bileşen        | Gereksinim                     |
|----------------|--------------------------------|
| İşletim Sistemi | Windows 7 / 10 / 11 (64-bit önerilir) |
| RAM            | ≥ 2 GB                         |
| Disk Alanı     | ≥ 100 MB                       |
| Yetki          | Yönetici hakları **zorunlu**   |

---

## ▶️ Kurulum & Kullanım

### İlk Başlatma
1. **Yönetim şifresi** belirleyin (en az 4 karakter).  
2. Yetkili **USB cihazını takın** ve listeden seçin.  
3. Sistem otomatik olarak USB kimliğini **SHA-256 hash** ile kaydeder.  
4. Uygulama sistem tepsisinde çalışmaya başlar.

> 💡 **Normal Kullanım**:  
> - USB takılı → Sistem açık  
> - USB çıkarıldı → Sistem anında kilitlenir

---

## 📂 Dosya Konumları

- **Yapılandırma**:  
  `%APPDATA%\ServiceHash\config.json`  
- **Günlükler**:  
  `%APPDATA%\ServiceHash\logs\log.json`

---

## 🔐 Güvenlik Mimarisi

- **USB Kimlik Doğrulaması**:  
  ```python
  hash = SHA256(sürücü_harfi + seri_numarası + birim_adı)
  Veri Koruma:
Şifreler ve token hash’leri düz metin olarak saklanmaz.
Tüm hassas veriler şifrelenmiş veya hashlenmiş biçimde tutulur.
Sistem Seviyesi Koruma:
Kayıt defteri politikaları ile kritik sistem bileşenleri engellenir.
⚠️ Uyarı
Şifreyi unutursanız kurtarma yolu yoktur.
Yazılım tamamen kullanıcı sorumluluğunda ve yasal kullanım amacıyla tasarlanmıştır.
