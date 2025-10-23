🔒 Service Hash – USB Token Tabanlı Kurumsal Güvenlik Sistemi
[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python)](   https://python.org   )
[![License](https://img.shields.io/badge/Lisans-GPLv3-red?logo=gnu)](   https://www.gnu.org/licenses/gpl-3.0   )
[![Platform](https://img.shields.io/badge/Platform-Windows%207%2F10%2F11-orange   )](https://microsoft.com/windows   )
[![PyQt5](https://img.shields.io/badge/Arayüz-PyQt5-purple)](https://www.riverbankcomputing.com/software/pyqt/   )

Yetkili USB çıkarıldığı anda Windows iş istasyonunuzu kilitleyen, çekirdek seviyesinde klavye/fare engellemesi, kayıt defteri koruması ve şifre ile korunan yönetim sunan gerçek zamanlı bir USB token kimlik doğrulama sistemidir.


📑 İçindekiler

Özellikler
Gereksinimler
Kurulum
Nasıl Çalıştırılır
Kullanım Kılavuzu
Güvenlik Modeli
Teknik Detaylar
Proje Yapısı



✨ Özellikler
🔒 Gerçek Zamanlı USB İzleme
Yetkili USB token çıkarıldığı anda sistem anında kilitlenir. Cihaz tekrar takıldığında otomatik olarak açılır.
⚙️ Çekirdek Seviyesi Giriş Engelleme
Sistem kilitliyken şu girişler tamamen engellenir:

Ctrl+Alt+Del kombinasyonu
Windows tuşları (Win, Win+X, Win+R vb.)
Alt+Tab görev değiştirme
F1–F12 fonksiyon tuşları
Tüm klavye ve fare girdileri

📁 Kayıt Defteri ve Sistem Koruması
Güvenlik için şu sistem bileşenleri devre dışı bırakılır:

Görev Yöneticisi (Task Manager)
Kayıt Defteri Düzenleyicisi (Registry Editor)
Komut İstemi (Command Prompt)
Win+X hızlı erişim menüsü
Diğer sistem araçları

🔐 Şifre ile Korunan Yönetim Paneli
Tüm kritik işlemler şifre doğrulaması gerektirir:

Token değiştirme
Sistem sıfırlama
Yönetim şifresi güncelleme
Yapılandırma değişiklikleri

📊 Olay Günlüğü
Tüm kritik eylemler detaylı şekilde kaydedilir:

Sistem kilitlenme/açılma zamanları
Token değişiklikleri
Şifre güncellemeleri
Kurulum ve yapılandırma işlemleri
Hata ve uyarı mesajları

🖥️ Sistem Tepsisi Entegrasyonu
Minimal ve kullanıcı dostu arayüz:

Sistem tepsisinde gizli simge
Sağ tık menüsü ile hızlı erişim
Durum bildirimleri
Kolay yönetim paneli

🔄 Otomatik Başlatma
Windows başlangıcında yönetici hakları ile otomatik olarak çalışır ve arka planda sessizce izleme yapar.
🧪 Kurumsal Güvenlik
Fiziksel token'a dayalı erişim gerektiren ortamlar için özel olarak tasarlanmıştır:

Banka ve finans kurumları
Devlet kurumları
Ar-Ge laboratuvarları
Veri merkezleri
Yüksek güvenlik gerektiren ofisler


🛠️ Gereksinimler
Sistem Gereksinimleri

İşletim Sistemi: Windows 7 / 10 / 11 (64-bit önerilir)
RAM: Minimum 2 GB
Disk Alanı: 50 MB serbest alan
Yönetici Hakları: Zorunlu

Yazılım Gereksinimleri

Python: 3.8 veya üstü
pip: Python paket yöneticisi

Gerekli Python Paketleri
bashpip install pyqt5 pywin32
veya requirements.txt dosyası ile:
bashpip install -r requirements.txt
requirements.txt içeriği:
txtpyqt5>=5.15.0
pywin32>=300

📥 Kurulum
Adım 1: Python'u Yükleyin
Python resmi web sitesinden Python 3.8 veya üstünü indirin ve yükleyin.
Önemli: Kurulum sırasında "Add Python to PATH" seçeneğini işaretleyin.
Adım 2: Projeyi İndirin
bashgit clone https://github.com/kullaniciadi/servicehash.git
cd servicehash
veya ZIP olarak indirip çıkarın.
Adım 3: Bağımlılıkları Yükleyin
bashpip install -r requirements.txt
Adım 4: Lisans Dosyasını Ekleyin
Proje dizinine LICENSE dosyası ekleyin:
bashcurl https://www.gnu.org/licenses/gpl-3.0.txt -o LICENSE

▶️ Nasıl Çalıştırılır
Temel Çalıştırma
Yönetici olarak çalıştırmalısınız (sistem hook'ları ve kayıt defteri erişimi için gerekli):
bashpython servicehash.py
veya Windows'ta:

servicehash.py dosyasına sağ tıklayın
"Yönetici olarak çalıştır" seçeneğini seçin

İlk Kurulum Sihirbazı
İlk çalıştırmada kurulum sihirbazı açılır:

Yönetim Şifresi Belirleme

En az 4 karakter uzunluğunda güçlü bir şifre oluşturun
Bu şifre tüm yönetim işlemleri için kullanılacaktır
Şifreyi unutmayın!


USB Token Seçimi

Kullanmak istediğiniz USB cihazını bilgisayara takın
Listeden USB'nizi seçin
Sistem otomatik olarak SHA-256 hash oluşturur


Tamamlama

Yapılandırma otomatik olarak kaydedilir
Uygulama sistem tepsisinde çalışmaya başlar



Normal Kullanım
Kurulumdan sonra:

USB Takılı: Sistem normal şekilde çalışır
USB Çıkarıldı: Sistem anında tamamen kilitlenir
USB Tekrar Takıldı: Sistem otomatik olarak açılır

EXE Dosyası Oluşturma
Taşınabilir tek dosya çalıştırılabilir oluşturmak için:
bashpip install pyinstaller
pyinstaller --onefile --windowed --icon=icon.ico --uac-admin servicehash.py
```

**Parametreler:**
- `--onefile`: Tek EXE dosyası oluşturur
- `--windowed`: Konsol penceresi göstermez
- `--icon=icon.ico`: Özel simge ekler (isteğe bağlı)
- `--uac-admin`: Yönetici izni ister

Oluşturulan EXE dosyası `dist/` klasöründe bulunur.

---

## 📖 Kullanım Kılavuzu

### Sistem Tepsisi Menüsü

Sistem tepsisindeki simgeye sağ tıklayarak:

- **Yönetim Paneli**: Yapılandırma ayarlarını açar
- **Mevcut Token**: Şu an kayıtlı USB token bilgisini gösterir
- **Durumu Kontrol Et**: USB bağlantı durumunu kontrol eder
- **Çıkış**: Uygulamayı kapatır (şifre gerektirir)

### Yönetim Paneli İşlemleri

#### Token Değiştirme
1. "Token Değiştir" butonuna tıklayın
2. Yönetim şifrenizi girin
3. Yeni USB'yi takın
4. Listeden seçin ve kaydedin

#### Yönetim Şifresini Değiştirme
1. "Şifre Değiştir" butonuna tıklayın
2. Mevcut şifrenizi girin
3. Yeni şifrenizi iki kez girin
4. Kaydedin

#### Sistemi Sıfırlama
1. "Sistemi Sıfırla" butonuna tıklayın
2. Yönetim şifrenizi girin
3. Onaylayın
4. Tüm yapılandırma silinir ve kurulum başa döner

### Olay Günlüklerini İnceleme

Günlük dosyası konumu:
```
%APPDATA%\ServiceHash\logs\log.json
```

Windows'ta tam yol:
```
C:\Users\KullaniciAdi\AppData\Roaming\ServiceHash\logs\log.json
Günlük formatı (JSON):
json[
  {
    "timestamp": "2025-10-23 14:30:15",
    "event": "system_locked",
    "details": "USB token removed"
  },
  {
    "timestamp": "2025-10-23 14:35:22",
    "event": "system_unlocked",
    "details": "Authorized USB detected"
  }
]

🔐 Güvenlik Modeli
Hash Algoritması
USB kimlik doğrulaması için SHA-256 hash algoritması kullanılır:
pythonhash = SHA256(sürücü_harfi + seri_numarası + birim_adı)
```

**Örnek:**
```
USB Bilgileri:
- Sürücü: E:\
- Seri No: 1234567890
- Birim Adı: MYUSB

Hash = SHA256("E1234567890MYUSB")
     = "a7b3c9d2e1f4a5b6c7d8e9f0a1b2c3d4..."
```

### Veri Depolama

Tüm hassas veriler güvenli şekilde saklanır:

- **Şifreler**: Hashlenmiş olarak saklanır (düz metin asla)
- **Token Hash'leri**: SHA-256 ile şifrelenmiş
- **Yapılandırma**: JSON formatında `%APPDATA%` klasöründe
- **Günlükler**: Zaman damgalı, şifreli olarak

**Yapılandırma dosyası konumu:**
```
%APPDATA%\ServiceHash\config.json
```

### Sistem Korumaları

#### Düşük Seviye Hook'lar
Windows API kullanılarak şunlar engellenir:
- `WH_KEYBOARD_LL`: Tüm klavye girdileri
- `WH_MOUSE_LL`: Tüm fare girdileri

#### Kayıt Defteri Politikaları
Şu kayıt defteri anahtarları değiştirilir:
```
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\
├── System
│   └── DisableTaskMgr = 1
├── Explorer
│   └── NoWinKeys = 1
└── System
    └── DisableCMD = 1
```

#### Güvenlik Katmanları
1. **Fiziksel Katman**: USB token gereksinimi
2. **Şifreleme Katmani**: SHA-256 hash doğrulama
3. **Yönetimsel Katman**: Şifre korumalı işlemler
4. **Sistem Katmanı**: Kayıt defteri ve API korumaları

---

⚠️son uyarılar⚠️
programda yedek veya 2. şifre yoktur şfirelrini unutmayın dikkatli olun tamamen yasal kullanım sorumluluk herşey kullanıcıya aittir iyi kullanımlar
