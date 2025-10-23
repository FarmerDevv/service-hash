🔒 Service Hash – USB Token Tabanlı Kurumsal Güvenlik Sistemi
Python

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python)](https://python.org     )
[![License](https://img.shields.io/badge/Lisans-GPLv3-red?logo=gnu)](https://www.gnu.org/licenses/gpl-3.0     )
[![Platform](https://img.shields.io/badge/Platform-Windows%207%2F10%2F11-orange     )](https://microsoft.com/windows     )
[![PyQt5](https://img.shields.io/badge/Arayüz-PyQt5-purple)](https://www.riverbankcomputing.com/software/pyqt/     )

Yetkili USB çıkarıldığında sistemi anında kilitleyen, klavye/fare girdilerini ve sistem araçlarını engelleyen, şifre korumalı yönetim sunan gerçek zamanlı bir güvenlik çözümü.

✨ Temel Özellikler
Anında kilit: USB çıkarılınca sistem tamamen kilitlenir.
Giriş engelleme: Ctrl+Alt+Del, Win tuşları, fare/klavye vs. devre dışı.
Sistem koruma: Görev Yöneticisi, CMD, Kayıt Defteri vb. engellenir.
Şifreli yönetim: Token değiştirme, sıfırlama gibi işlemler şifre gerektirir.
Olay günlüğü: Tüm eylemler JSON formatında kaydedilir.
Sistem tepsisi: Minimal arayüzle kolay erişim.
Otomatik başlatma: Windows ile birlikte yönetici olarak başlar.
🛠️ Gereksinimler
OS: Windows 7/10/11 (64-bit önerilir)
RAM: ≥2 GB
Disk: ≥100 MB
Yetki: Yönetici hakları zorunlu
▶️ Başlangıç
İlk çalıştırmada:

Yönetim şifresi belirleyin (≥4 karakter).
Yetkili USB’yi seçin (SHA-256 hash’i otomatik oluşturulur).
Uygulama sistem tepsisinde çalışmaya başlar.
USB takılıysa sistem açık, çıkarılırsa anında kilitlenir. 

📂 Dosya Yolları
Yapılandırma: %APPDATA%\ServiceHash\config.json
Günlükler: %APPDATA%\ServiceHash\logs\log.json
🔐 Güvenlik
USB kimliği: SHA256(sürücü + seri no + birim adı)
Şifreler ve hash’ler düz metin olarak saklanmaz.
Kayıt defteri politikaları ile sistem korunur.
⚠️ Uyarı: Şifreyi unutursanız kurtarma yolu yoktur. Tamamen kullanıcı sorumluluğundadır. Yasal kullanım için tasarlanmıştır.
